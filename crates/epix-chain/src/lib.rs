//! `epix-chain` - the Epix chain layer.
//!
//! Resolves `.epix` names to their on-chain records, **chain-verified**: every
//! answer is checked with a Merkle inclusion proof against a state digest that
//! has been finalized by 2/3+ validators. A malicious or buggy RPC cannot forge
//! a resolution - a tampered proof is rejected.

mod attestation;
mod finality;
mod leaf;
mod merkle;
mod resolver;
mod types;
mod vrf;

pub use attestation::{ChainAttestation, StateDigest};
pub use leaf::verify_and_parse_leaf;
pub use finality::{
    canonical_vote_ext_bytes, parse_bundle, verify_finality, AttestationEntry, FinalityBundle,
    FinalityError, PinnedSet, PinnedValidator, VerifyParams, DEFAULT_MIN_POWER_BPS,
};
pub use resolver::{XidResolver, DEFAULT_RPC_URL};
pub use types::{DomainSnapshot, Identity};
pub use vrf::{combine_beacons, derive_random, Beacon, Vrf};

use std::sync::Arc;
use std::sync::OnceLock;

/// One process-wide `XidResolver` against the default RPC, so every resolve
/// reuses its HTTP connection pool (one TLS handshake instead of one per call)
/// and its short-lived digest cache (one digest fetch per burst, not per
/// name). Built lazily on first use so it captures the chain-socks setting the
/// node configured at boot.
pub fn shared_resolver() -> Arc<XidResolver> {
    static SHARED: OnceLock<Arc<XidResolver>> = OnceLock::new();
    SHARED.get_or_init(|| Arc::new(XidResolver::new(&resolver_rpc_url()))).clone()
}

/// The chain REST base the xID resolver targets. This is the single chain RPC
/// URL — the resolver appends the `/xid/v1/...` paths itself, so there is no
/// separate xID endpoint. Defaults to [`DEFAULT_RPC_URL`] (mainnet); set
/// `EPIX_XID_RPC_URL` to override it for a local devnet or an alternate chain
/// (e.g. `EPIX_XID_RPC_URL=http://127.0.0.1:1317`) without rebuilding.
pub fn resolver_rpc_url() -> String {
    std::env::var("EPIX_XID_RPC_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_RPC_URL.to_string())
}

/// Drop every in-memory xID cache in this process - the shared resolver's
/// verified snapshots, the signer cache, and the identity cache - so the next
/// resolve of any name is a fresh, chain-verified lookup. Backs the node's
/// "Clear xID cache" action; the node clears its own on-disk resolve cache and
/// display-name bindings alongside this.
pub async fn clear_xid_caches() {
    shared_resolver().clear().await;
    xid_signers::clear();
    xid_identity::clear();
}

use thiserror::Error;

/// The SOCKS proxy every chain RPC routes through, if set - the node's Arti
/// listener in Tor-always mode (`socks5h://127.0.0.1:43111`). Process-global so
/// resolvers created anywhere pick it up. `None` = direct (enable/disable modes).
static CHAIN_SOCKS: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

/// Whether chain RPC MUST route through Tor (set in Tor-always mode). While set
/// and no SOCKS proxy is configured yet, a chain call is refused rather than
/// sent direct - so the chain server never sees the node's real IP or which
/// `.epix` name it resolves during the ~10-40s Tor bootstrap window.
static CHAIN_REQUIRE_TOR: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Bumped whenever [`set_chain_socks`] changes the proxy, so a cached HTTP
/// client built for the old setting is rebuilt instead of sending over the
/// wrong route (a client built direct before the proxy was set would otherwise
/// stay direct forever).
static SOCKS_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Route all chain RPC through `socks` (e.g. `socks5h://127.0.0.1:43111`), or
/// `None` for direct. Set by the node in Tor-always mode so the chain server
/// never sees the node's real IP or which `.epix` names it resolves (`socks5h`
/// resolves the hostname through Tor too, so DNS doesn't leak). Clients rebuild
/// to pick up the new setting.
pub fn set_chain_socks(socks: Option<String>) {
    if let Ok(mut w) = CHAIN_SOCKS.write() {
        *w = socks.filter(|s| !s.is_empty());
    }
    SOCKS_GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Whether chain RPC is currently routed through a proxy.
pub fn chain_socks() -> Option<String> {
    CHAIN_SOCKS.read().ok().and_then(|r| r.clone())
}

/// Require chain RPC to route through Tor (Tor-always mode). Set once at
/// startup; until the SOCKS proxy is wired, [`chain_egress_ok`] refuses calls.
pub fn set_chain_require_tor(required: bool) {
    CHAIN_REQUIRE_TOR.store(required, std::sync::atomic::Ordering::Relaxed);
}

/// The current SOCKS generation - cached HTTP clients rebuild when it changes.
pub(crate) fn socks_generation() -> u64 {
    SOCKS_GEN.load(std::sync::atomic::Ordering::Relaxed)
}

/// Whether a chain request may egress right now. In Tor-always mode a request
/// before the SOCKS proxy is set would go direct over clearnet, leaking the
/// real IP and the queried name, so it is refused; the caller retries once Tor
/// is up. A no-op in enable/disable modes.
pub(crate) fn chain_egress_ok() -> Result<()> {
    if CHAIN_REQUIRE_TOR.load(std::sync::atomic::Ordering::Relaxed) && chain_socks().is_none() {
        return Err(ChainError::Rpc(
            "Tor-always mode: chain RPC blocked until Tor is ready".into(),
        ));
    }
    Ok(())
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

// ---------------------------------------------------------------------------
// Client-side finality verification config (see finality.rs, leaf.rs and
// docs/xid-lightclient-finality.md). All process-global so a resolver created
// anywhere picks them up; the node sets them at boot.
// ---------------------------------------------------------------------------

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};

/// The pinned validator set — the client's root of trust for finality. `None`
/// until the node installs it; while `None` and [`XID_VERIFY_FINALITY`] is on,
/// finality fails closed.
static PINNED_VALIDATORS: std::sync::RwLock<Option<finality::PinnedSet>> =
    std::sync::RwLock::new(None);

/// Whether to cryptographically verify digest finality against the pinned set
/// (and require leaf-binding). Default OFF — the node enables it once a pin is
/// installed and the chain serves signed attestations. OFF = legacy RPC-boolean.
static XID_VERIFY_FINALITY: AtomicBool = AtomicBool::new(false);

/// Highest finalized-bundle height accepted so far — the monotonic anti-replay
/// floor. The node persists this across restarts (a reinstall must not reset it
/// to 0), via [`set_xid_max_height`] / [`xid_max_height`].
static XID_MAX_HEIGHT: AtomicU64 = AtomicU64::new(0);

/// Max `|now − block_time|` (seconds) accepted for a finality bundle.
static XID_SKEW_SECS: AtomicI64 = AtomicI64::new(120);
/// Max pin age (seconds) before finality fails closed (weak subjectivity).
/// Default 7 days — must be < the chain's unbonding period.
static XID_WS_PERIOD_SECS: AtomicI64 = AtomicI64::new(7 * 24 * 3600);
/// Required fraction of pinned voting power, in basis points (default 80%).
static XID_MIN_POWER_BPS: AtomicU32 = AtomicU32::new(finality::DEFAULT_MIN_POWER_BPS);

/// Install (or clear) the pinned validator set the client verifies finality
/// against. Shipped from a signed app release and re-pinned within the WS window.
pub fn set_pinned_validators(set: Option<finality::PinnedSet>) {
    if let Ok(mut w) = PINNED_VALIDATORS.write() {
        *w = set;
    }
}

/// A clone of the current pinned set, if installed.
pub fn pinned_validators() -> Option<finality::PinnedSet> {
    PINNED_VALIDATORS.read().ok().and_then(|r| r.clone())
}

/// Enable/disable client-side finality verification (and leaf-binding enforcement).
pub fn set_verify_finality(on: bool) {
    XID_VERIFY_FINALITY.store(on, Ordering::Relaxed);
}

/// Whether client-side finality verification is enabled.
pub fn verify_finality_enabled() -> bool {
    XID_VERIFY_FINALITY.load(Ordering::Relaxed)
}

/// Install a pinned validator set from a JSON pin file and turn ON client-side
/// xID finality verification. After this, xID resolution REQUIRES a digest signed
/// by more than two thirds of the pinned voting power and fails closed otherwise
/// (see [`XidResolver`]).
///
/// The pin is captured from a trusted mainnet height AFTER the v0.7.2 attestation
/// upgrade is live (before then there are no signed attestations to pin). Shape:
///
/// ```json
/// { "chain_id": "epix_1917-1", "pinned_at_height": 5360001,
///   "pinned_at_unix": 1790000000,
///   "validators": [ { "valcons": "epixvalcons1...", "pubkey": "<64 hex>",
///                     "voting_power": 1000000 } ] }
/// ```
///
/// Returns the number of validators pinned.
pub fn install_finality_pin(json: &[u8]) -> std::result::Result<usize, String> {
    let pinned = parse_finality_pin(json)?;
    let n = pinned.validators.len();
    set_pinned_validators(Some(pinned));
    set_verify_finality(true);
    Ok(n)
}

/// Parse a pin file into a [`finality::PinnedSet`] without touching global state.
pub fn parse_finality_pin(json: &[u8]) -> std::result::Result<finality::PinnedSet, String> {
    let v: serde_json::Value =
        serde_json::from_slice(json).map_err(|e| format!("pin JSON: {e}"))?;
    let miss = |f: &str| format!("pin: missing {f}");
    let chain_id = v.get("chain_id").and_then(|x| x.as_str()).ok_or_else(|| miss("chain_id"))?;
    let height = v
        .get("pinned_at_height")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| miss("pinned_at_height"))?;
    let unix =
        v.get("pinned_at_unix").and_then(|x| x.as_i64()).ok_or_else(|| miss("pinned_at_unix"))?;
    let arr = v.get("validators").and_then(|x| x.as_array()).ok_or_else(|| miss("validators"))?;

    let mut validators = std::collections::HashMap::new();
    for e in arr {
        let valcons = e
            .get("valcons")
            .and_then(|x| x.as_str())
            .ok_or_else(|| "pin: validator missing valcons".to_string())?;
        let pk_hex = e
            .get("pubkey")
            .and_then(|x| x.as_str())
            .ok_or_else(|| "pin: validator missing pubkey".to_string())?;
        let power = e
            .get("voting_power")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| "pin: validator missing voting_power".to_string())?;
        let pk = hex::decode(pk_hex).map_err(|_| "pin: pubkey not hex".to_string())?;
        let pubkey: [u8; 32] =
            pk.try_into().map_err(|_| "pin: pubkey not 32 bytes".to_string())?;
        validators.insert(
            valcons.to_string(),
            finality::PinnedValidator { pubkey, voting_power: power },
        );
    }
    if validators.is_empty() {
        return Err("pin: no validators".into());
    }
    Ok(finality::PinnedSet::new(validators, chain_id, unix, height))
}

#[cfg(test)]
mod pin_tests {
    use super::*;

    #[test]
    fn parses_a_valid_pin() {
        let json = br#"{ "chain_id": "epix_1917-1", "pinned_at_height": 5360001,
            "pinned_at_unix": 1790000000, "validators": [
              { "valcons": "epixvalcons1aa", "pubkey": "aa00000000000000000000000000000000000000000000000000000000000011", "voting_power": 700000 },
              { "valcons": "epixvalcons1bb", "pubkey": "bb00000000000000000000000000000000000000000000000000000000000022", "voting_power": 300000 } ] }"#;
        let pin = parse_finality_pin(json).unwrap();
        assert_eq!(pin.validators.len(), 2);
        assert_eq!(pin.total_power, 1_000_000);
        assert_eq!(pin.chain_id, "epix_1917-1");
        assert_eq!(pin.pinned_at_height, 5360001);
    }

    #[test]
    fn rejects_malformed_pins() {
        assert!(parse_finality_pin(b"not json").is_err());
        assert!(parse_finality_pin(br#"{"chain_id":"x","pinned_at_height":1,"pinned_at_unix":1,"validators":[]}"#).is_err());
        // bad pubkey length
        assert!(parse_finality_pin(br#"{"chain_id":"x","pinned_at_height":1,"pinned_at_unix":1,"validators":[{"valcons":"v","pubkey":"aa","voting_power":1}]}"#).is_err());
    }
}

/// Set the finality policy knobs (seconds / basis points).
pub fn set_finality_policy(skew_secs: i64, ws_period_secs: i64, min_power_bps: u32) {
    XID_SKEW_SECS.store(skew_secs, Ordering::Relaxed);
    XID_WS_PERIOD_SECS.store(ws_period_secs, Ordering::Relaxed);
    XID_MIN_POWER_BPS.store(min_power_bps, Ordering::Relaxed);
}

/// The monotonic anti-replay floor (persist across restarts).
pub fn xid_max_height() -> u64 {
    XID_MAX_HEIGHT.load(Ordering::Relaxed)
}

/// Set the anti-replay floor (only ever raise it; the node loads the persisted
/// value at boot and saves it after a successful verify).
pub fn set_xid_max_height(h: u64) {
    XID_MAX_HEIGHT.fetch_max(h, Ordering::Relaxed);
}

/// Build [`finality::VerifyParams`] from the configured policy + a `now` unix time.
pub(crate) fn finality_params(now_unix: i64) -> finality::VerifyParams {
    finality::VerifyParams {
        now_unix,
        skew_secs: XID_SKEW_SECS.load(Ordering::Relaxed),
        ws_period_secs: XID_WS_PERIOD_SECS.load(Ordering::Relaxed),
        min_power_bps: XID_MIN_POWER_BPS.load(Ordering::Relaxed),
        max_height_seen: XID_MAX_HEIGHT.load(Ordering::Relaxed),
    }
}

/// Current unix time in seconds (for finality freshness).
pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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
    /// The returned domain data does not hash to the proven leaf, or is for a
    /// different name — a hostile RPC swapping data behind a genuine proof.
    #[error("leaf binding failed: {0}")]
    LeafBindingFailed(String),
    /// Client-side finality verification rejected the attestation bundle
    /// (bad signatures, <required power, stale, expired pin, …).
    #[error("finality not verified: {0}")]
    FinalityUnverified(String),
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

    /// Drop every cached signer resolution (see [`super::clear_xid_caches`]).
    pub fn clear() {
        if let Ok(mut guard) = CACHE.write() {
            *guard = None;
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
        let Ok(domain) = super::shared_resolver().resolve(name, tld).await else {
            return Vec::new();
        };
        // Only ACTIVE, non-revoked linked identities may sign the domain's
        // content. A revoked key (lost/stolen device) must not remain a valid
        // signer — otherwise it can keep re-publishing/replacing signed files.
        let signers: Vec<String> = domain
            .identities
            .iter()
            .filter(|i| i.active && i.revoked_at == 0)
            .map(|i| i.address.clone())
            .collect();
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
/// this is what stops xites from hammering the chain once per render.
pub mod xid_identity {
    use super::DEFAULT_RPC_URL;
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

    /// Drop every cached identity lookup (see [`super::clear_xid_caches`]).
    pub fn clear() {
        if let Ok(mut guard) = CACHE.write() {
            *guard = None;
        }
    }

    /// Reverse-resolve a linked identity address to its xID, or `None` if the
    /// address isn't linked to any name.
    pub async fn resolve_identity(address: &str) -> Option<XidInfo> {
        if let Some(hit) = cached(address) {
            return hit;
        }
        // Refuse to egress over clearnet before Tor is ready in Always mode
        // (returns without caching, so the next call retries once Tor is up).
        if super::chain_egress_ok().is_err() {
            return None;
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
        let domain = super::shared_resolver().resolve(name, tld).await.ok()?;
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
        let domain = match super::shared_resolver().resolve(name, tld).await {
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

    /// Whether `fqdn` currently has at least one ACTIVE, non-revoked linked
    /// identity, Merkle-verified. `Some(true)` = a valid identity exists;
    /// `Some(false)` = the name is registered but EVERY linked key is
    /// revoked/inactive; `None` = indeterminate (not registered, chain
    /// unreachable, or Tor-not-ready). Callers enforcing revocation should
    /// **fail OPEN on `None`** so channel mail keeps working when the chain is
    /// unavailable — a definite `Some(false)` is what cuts a revoked key off.
    /// (`resolve_name` can't answer this: it hard-codes `active: true`.)
    pub async fn name_has_active_identity(fqdn: &str) -> Option<bool> {
        let (name, tld) = fqdn.rsplit_once('.')?;
        if name.is_empty() || tld.is_empty() {
            return None;
        }
        let ck = format!("active?:{fqdn}");
        if let Some(hit) = cached(&ck) {
            return hit.map(|info| info.active);
        }
        match super::shared_resolver().resolve(name, tld).await {
            Ok(domain) => {
                let active = domain.identities.iter().any(|i| i.active && i.revoked_at == 0);
                // Reuse XidInfo.active as the cached bool carrier.
                store(
                    ck,
                    Some(XidInfo {
                        name: name.to_string(),
                        tld: tld.to_string(),
                        owner: String::new(),
                        active,
                        revoked_at: 0,
                        revoked_at_time: 0,
                        avatar: String::new(),
                        bio: String::new(),
                    }),
                );
                Some(active)
            }
            // Not registered: cache a short negative; indeterminate to the caller.
            Err(super::ChainError::NotFound(_)) => {
                store(ck, None);
                None
            }
            // Transient/unreachable: don't cache; indeterminate → caller fails open.
            Err(_) => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn info(active: bool) -> XidInfo {
            XidInfo {
                name: "x".into(),
                tld: "epix".into(),
                owner: String::new(),
                active,
                revoked_at: 0,
                revoked_at_time: 0,
                avatar: String::new(),
                bio: String::new(),
            }
        }

        // Pre-seed the resolver cache so no network is touched: the active flag
        // maps through to the three-valued answer the channel gate relies on.
        #[tokio::test]
        async fn name_active_maps_cached_flag_without_network() {
            clear();
            store("active?:alice.epix".into(), Some(info(true)));
            assert_eq!(name_has_active_identity("alice.epix").await, Some(true), "active → keep");
            store("active?:bob.epix".into(), Some(info(false)));
            assert_eq!(name_has_active_identity("bob.epix").await, Some(false), "revoked → cut off");
            store("active?:ghost.epix".into(), None);
            assert_eq!(name_has_active_identity("ghost.epix").await, None, "unknown → fail open");
            clear();
        }
    }
}

#[cfg(test)]
mod egress_gate_tests {
    use super::*;

    /// The Tor-always egress gate blocks chain RPC until the SOCKS proxy is
    /// wired, and advancing the proxy setting bumps the client-rebuild
    /// generation. Global state is reset at the end so it doesn't leak to other
    /// tests (no other test touches these globals).
    #[test]
    fn egress_gate_blocks_until_socks_then_allows() {
        // Not required (enable/disable modes): always allowed.
        set_chain_require_tor(false);
        set_chain_socks(None);
        assert!(chain_egress_ok().is_ok());

        // Always mode, proxy not wired yet: refused (a direct call would leak).
        set_chain_require_tor(true);
        set_chain_socks(None);
        assert!(chain_egress_ok().is_err());

        // Proxy wired: allowed, and the generation advanced so a cached direct
        // client rebuilds to route through Tor.
        let before = socks_generation();
        set_chain_socks(Some("socks5h://127.0.0.1:43111".into()));
        assert!(chain_egress_ok().is_ok());
        assert!(socks_generation() > before);

        // Reset to defaults for any other test in this binary.
        set_chain_require_tor(false);
        set_chain_socks(None);
    }
}
