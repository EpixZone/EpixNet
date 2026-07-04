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
