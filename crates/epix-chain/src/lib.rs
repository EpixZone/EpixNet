//! `epix-chain` - the Epix chain layer.
//!
//! Resolves `.epix` names to their on-chain records, **chain-verified**: every
//! answer is checked with a Merkle inclusion proof against a state digest that
//! has been finalized by 2/3+ validators. A malicious or buggy RPC cannot forge
//! a resolution - a tampered proof is rejected.

mod attestation;
mod merkle;
mod resolver;
mod types;
mod vrf;

pub use attestation::{ChainAttestation, StateDigest};
pub use resolver::{XidResolver, DEFAULT_RPC_URL};
pub use types::{DomainSnapshot, Identity};
pub use vrf::{combine_beacons, derive_random, Beacon, Vrf};

use thiserror::Error;

/// The SOCKS proxy every chain RPC routes through, if set - the node's Arti
/// listener in Tor-always mode (`socks5h://127.0.0.1:43111`). Process-global so
/// resolvers created anywhere pick it up. `None` = direct (enable/disable modes).
static CHAIN_SOCKS: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

/// Route all chain RPC through `socks` (e.g. `socks5h://127.0.0.1:43111`), or
/// `None` for direct. Set by the node in Tor-always mode so the chain server
/// never sees the node's real IP or which `.epix` names it resolves (`socks5h`
/// resolves the hostname through Tor too, so DNS doesn't leak). Clients built
/// after this call use the new setting.
pub fn set_chain_socks(socks: Option<String>) {
    if let Ok(mut w) = CHAIN_SOCKS.write() {
        *w = socks.filter(|s| !s.is_empty());
    }
}

/// Whether chain RPC is currently routed through a proxy.
pub fn chain_socks() -> Option<String> {
    CHAIN_SOCKS.read().ok().and_then(|r| r.clone())
}

/// Build the HTTP client every chain RPC uses, honoring [`set_chain_socks`].
pub(crate) fn http_client(timeout: std::time::Duration) -> reqwest::Client {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if let Some(socks) = chain_socks() {
        if let Ok(proxy) = reqwest::Proxy::all(&socks) {
            builder = builder.proxy(proxy);
        }
    }
    builder.build().expect("reqwest client")
}

#[derive(Error, Debug)]
pub enum ChainError {
    #[error("rpc request failed: {0}")]
    Rpc(String),
    #[error("name not found: {0}")]
    NotFound(String),
    #[error("Merkle proof verification failed")]
    MerkleInvalid,
    #[error("proof root does not match the attested state digest")]
    DigestMismatch,
    #[error("state digest not finalized by validators")]
    NotFinalized,
    #[error("malformed chain response: {0}")]
    Malformed(String),
}

pub type Result<T> = std::result::Result<T, ChainError>;

/// Cached resolution of an xID name to its linked identity addresses (the
/// content signers for that user), mirroring EpixNet's XidResolver plugin:
/// check the in-memory cache first, else resolve on-chain (Merkle-verified)
/// and cache the result. A rarely-changing mapping that would otherwise cost
/// one RPC per user per resync cycle.
pub mod xid_signers {
    use super::XidResolver;
    use std::collections::HashMap;
    use std::sync::RwLock;
    use std::time::{Duration, Instant};

    /// How long a positive resolution stays cached.
    const TTL: Duration = Duration::from_secs(30 * 60);

    struct Entry {
        signers: Vec<String>,
        at: Instant,
    }

    static CACHE: RwLock<Option<HashMap<String, Entry>>> = RwLock::new(None);

    fn cached(key: &str) -> Option<Vec<String>> {
        let guard = CACHE.read().ok()?;
        let map = guard.as_ref()?;
        let entry = map.get(key)?;
        (entry.at.elapsed() < TTL).then(|| entry.signers.clone())
    }

    fn store(key: String, signers: Vec<String>) {
        if let Ok(mut guard) = CACHE.write() {
            guard.get_or_insert_with(HashMap::new).insert(key, Entry { signers, at: Instant::now() });
        }
    }

    /// The addresses that may sign for `name.tld`'s user content: its linked
    /// identity addresses (all of them - a signature matching any is valid,
    /// EpixNet's `resolveUserSigners`). Empty if the name doesn't resolve.
    pub async fn resolve(name: &str, tld: &str) -> Vec<String> {
        let key = format!("{name}.{tld}");
        if let Some(hit) = cached(&key) {
            return hit;
        }
        let resolver = XidResolver::new(super::DEFAULT_RPC_URL);
        let Ok(domain) = resolver.resolve(name, tld).await else {
            return Vec::new();
        };
        let signers: Vec<String> =
            domain.identities.iter().map(|i| i.address.clone()).collect();
        store(key, signers.clone());
        signers
    }
}

/// Cached xID identity lookups, mirroring EpixNet's XidResolver plugin
/// (`resolve_identity_xid` / `_resolve_xid_name_profile`): reverse-resolve a
/// linked identity address to its xID name, or forward-resolve a `name.tld`
/// to its profile. The reverse endpoint only NAMES the domain; the answer is
/// then confirmed through the Merkle-verified forward resolve, so a rogue RPC
/// can't attach an address to someone else's name. Negative answers cache
/// briefly (transient failures don't cache at all), positives cache long -
/// this is what stops sites from hammering the chain once per render.
pub mod xid_identity {
    use super::{XidResolver, DEFAULT_RPC_URL};
    use std::collections::HashMap;
    use std::sync::RwLock;
    use std::time::{Duration, Instant};

    /// Positive results are near-permanent on-chain; revocation is carried in
    /// the record itself.
    const POSITIVE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
    /// Negatives are usually "not linked (yet)" - recover fast.
    const NEGATIVE_TTL: Duration = Duration::from_secs(30);

    /// A resolved xID identity, the shape EpixNet's plugin returns.
    #[derive(Clone, Debug)]
    pub struct XidInfo {
        pub name: String,
        pub tld: String,
        pub owner: String,
        pub active: bool,
        pub revoked_at: u64,
        pub revoked_at_time: u64,
        pub avatar: String,
        pub bio: String,
    }

    static CACHE: RwLock<Option<HashMap<String, (Option<XidInfo>, Instant)>>> =
        RwLock::new(None);

    fn cached(key: &str) -> Option<Option<XidInfo>> {
        let guard = CACHE.read().ok()?;
        let (info, at) = guard.as_ref()?.get(key)?;
        let ttl = if info.is_some() { POSITIVE_TTL } else { NEGATIVE_TTL };
        (at.elapsed() < ttl).then(|| info.clone())
    }

    fn store(key: String, info: Option<XidInfo>) {
        if let Ok(mut guard) = CACHE.write() {
            guard
                .get_or_insert_with(HashMap::new)
                .insert(key, (info, Instant::now()));
        }
    }

    /// Reverse-resolve a linked identity address to its xID, or `None` if the
    /// address isn't linked to any name.
    pub async fn resolve_identity(address: &str) -> Option<XidInfo> {
        if let Some(hit) = cached(address) {
            return hit;
        }
        // Step 1: unverified reverse lookup - names the candidate domain.
        let client = super::http_client(Duration::from_secs(15));
        let url = format!("{DEFAULT_RPC_URL}/xid/v1/reverse_identity/{address}");
        // Transient fetch errors return without caching so the next call retries.
        let data: serde_json::Value = client.get(&url).send().await.ok()?.json().await.ok()?;
        let record = match data.get("name_record").filter(|r| !r.is_null()) {
            Some(r) => r,
            None => {
                store(address.to_string(), None);
                return None;
            }
        };
        let name = record.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let tld = record.get("tld").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() || tld.is_empty() {
            store(address.to_string(), None);
            return None;
        }
        // Step 2: confirm through the Merkle-verified forward resolve.
        let resolver = XidResolver::new(DEFAULT_RPC_URL);
        let domain = resolver.resolve(name, tld).await.ok()?;
        let Some(ident) = domain.identities.iter().find(|i| i.address == address) else {
            // Verified domain doesn't actually contain this identity.
            store(address.to_string(), None);
            return None;
        };
        let info = XidInfo {
            name: domain.name.clone(),
            tld: domain.tld.clone(),
            owner: domain.owner.clone(),
            active: ident.active,
            revoked_at: ident.revoked_at,
            revoked_at_time: ident.revoked_at_time,
            avatar: domain.avatar.clone(),
            bio: domain.bio.clone(),
        };
        store(address.to_string(), Some(info.clone()));
        store(domain.fqdn(), Some(info.clone()));
        Some(info)
    }

    /// Forward-resolve `name.tld` to its profile, or `None` if unregistered.
    pub async fn resolve_name(fqdn: &str) -> Option<XidInfo> {
        let (name, tld) = fqdn.rsplit_once('.')?;
        if name.is_empty() || tld.is_empty() {
            return None;
        }
        if let Some(hit) = cached(fqdn) {
            return hit;
        }
        let resolver = XidResolver::new(DEFAULT_RPC_URL);
        let domain = match resolver.resolve(name, tld).await {
            Ok(d) => d,
            Err(super::ChainError::NotFound(_)) => {
                store(fqdn.to_string(), None);
                return None;
            }
            // Transient failure - don't cache, let the next call retry.
            Err(_) => return None,
        };
        let info = XidInfo {
            name: domain.name.clone(),
            tld: domain.tld.clone(),
            owner: domain.owner.clone(),
            active: true,
            revoked_at: 0,
            revoked_at_time: 0,
            avatar: domain.avatar.clone(),
            bio: domain.bio.clone(),
        };
        store(fqdn.to_string(), Some(info.clone()));
        Some(info)
    }
}
