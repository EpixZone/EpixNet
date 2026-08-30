//! `epix-chain` - the Epix chain layer.
//!
//! Resolves `.epix` names to their on-chain records, **chain-verified**: every
//! answer is checked with a Merkle inclusion proof against a state digest that
//! has been finalized by 2/3+ validators. A malicious or buggy RPC cannot forge
//! a resolution - a tampered proof is rejected.

mod attestation;
mod checkpoint;
mod finality;
mod identity_snapshot;
mod leaf;
mod lightclient;
mod merkle;
mod resolver;
mod types;
mod vrf;

pub use attestation::{ChainAttestation, StateDigest};
pub use checkpoint::FinalityCheckpoint;
pub use finality::{
    canonical_vote_ext_bytes, parse_bundle, verify_finality, AttestationEntry, FinalityBundle,
    FinalityError, PinnedSet, PinnedValidator, VerifyParams, DEFAULT_MIN_POWER_BPS,
};
pub use identity_snapshot::{
    resolve_xid_identity_snapshot, XidFinalityBinding, XidIdentityAuth, XidIdentitySnapshot,
    XidIdentityStatus,
};
pub use leaf::verify_and_parse_leaf;
pub use lightclient::{
    advance_trusted_set, Advance, LightClientConfig, DEFAULT_BOOTSTRAP_QUORUM,
    DEFAULT_BOOTSTRAP_SOURCES, DEFAULT_CHAIN_ID, DEFAULT_CMT_RPC_URL,
    DEFAULT_TRUSTING_PERIOD_SECS,
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
    SHARED
        .get_or_init(|| Arc::new(XidResolver::new(resolver_rpc_url())))
        .clone()
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

#[derive(Clone, Debug)]
struct ChainRoute {
    socks: Option<String>,
    require_tor: bool,
    generation: u64,
    error: Option<String>,
}

impl ChainRoute {
    const fn direct() -> Self {
        Self {
            socks: None,
            require_tor: false,
            generation: 0,
            error: None,
        }
    }

    fn ensure_egress(&self) -> Result<()> {
        if let Some(error) = &self.error {
            return Err(ChainError::Rpc(error.clone()));
        }
        if self.require_tor && self.socks.is_none() {
            return Err(ChainError::Rpc(
                "Tor-always mode: chain RPC blocked until Tor is ready".into(),
            ));
        }
        Ok(())
    }
}

/// Proxy URL, Tor requirement, validation state, and cached-client generation
/// share one lock. A reader can never observe a new proxy with the old
/// generation and reuse a direct client for a Tor-routed request.
static CHAIN_ROUTE: OnceLock<std::sync::RwLock<ChainRoute>> = OnceLock::new();

fn chain_route() -> &'static std::sync::RwLock<ChainRoute> {
    CHAIN_ROUTE.get_or_init(|| std::sync::RwLock::new(ChainRoute::direct()))
}

fn chain_route_snapshot() -> Result<ChainRoute> {
    let route = chain_route()
        .read()
        .map_err(|_| ChainError::Rpc("chain proxy configuration lock poisoned".into()))?
        .clone();
    route.ensure_egress()?;
    Ok(route)
}

fn build_http_client(socks: Option<&str>, timeout: std::time::Duration) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if let Some(socks) = socks {
        let proxy = reqwest::Proxy::all(socks)
            .map_err(|error| ChainError::Rpc(format!("invalid chain SOCKS proxy: {error}")))?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|error| ChainError::Rpc(format!("cannot build chain HTTP client: {error}")))
}

fn normalized_chain_socks(
    socks: Option<String>,
) -> (Option<String>, std::result::Result<(), String>) {
    let socks = socks
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string());
    // Validate both proxy parsing and client construction before the route can
    // be observed as ready. An invalid candidate is published as an error with
    // no proxy, which makes every request fail closed instead of going direct.
    let validation = build_http_client(socks.as_deref(), std::time::Duration::from_secs(15))
        .map(|_| ())
        .map_err(|error| error.to_string());
    (socks, validation)
}

fn set_chain_socks_inner(socks: Option<String>, before_commit: impl FnOnce()) {
    let (socks, validation) = normalized_chain_socks(socks);
    let Ok(mut route) = chain_route().write() else {
        return;
    };
    before_commit();
    route.generation = route.generation.wrapping_add(1);
    match validation {
        Ok(()) => {
            route.socks = socks;
            route.error = None;
        }
        Err(error) => {
            route.socks = None;
            route.error = Some(error);
        }
    }
}

/// Atomically publish the complete chain egress route. Proxy validation happens
/// before the write lock is taken. Readers then observe the proxy, validation
/// result, Tor requirement, and client generation as one state transition.
pub fn set_chain_route(socks: Option<String>, require_tor: bool) {
    let (socks, validation) = normalized_chain_socks(socks);
    let Ok(mut route) = chain_route().write() else {
        return;
    };
    route.generation = route.generation.wrapping_add(1);
    route.require_tor = require_tor;
    match validation {
        Ok(()) => {
            route.socks = socks;
            route.error = None;
        }
        Err(error) => {
            route.socks = None;
            route.error = Some(error);
        }
    }
}

/// Route all chain RPC through `socks` (e.g. `socks5h://127.0.0.1:43111`), or
/// `None` for direct. Set by the node in Tor-always mode so the chain server
/// never sees the node's real IP or which `.epix` names it resolves (`socks5h`
/// resolves the hostname through Tor too, so DNS doesn't leak). Clients rebuild
/// to pick up the new setting.
pub fn set_chain_socks(socks: Option<String>) {
    set_chain_socks_inner(socks, || {});
    }

#[cfg(test)]
fn set_chain_socks_with_hook(socks: Option<String>, before_commit: impl FnOnce()) {
    set_chain_socks_inner(socks, before_commit);
}

/// Whether chain RPC is currently routed through a proxy.
pub fn chain_socks() -> Option<String> {
    chain_route().read().ok().and_then(|route| {
        if route.error.is_none() {
            route.socks.clone()
        } else {
            None
        }
    })
}

/// Require chain RPC to route through Tor (Tor-always mode). Set once at
/// startup; until the SOCKS proxy is wired, [`chain_egress_ok`] refuses calls.
pub fn set_chain_require_tor(required: bool) {
    if let Ok(mut route) = chain_route().write() {
        route.require_tor = required;
        route.generation = route.generation.wrapping_add(1);
    }
}

/// The current SOCKS generation - cached HTTP clients rebuild when it changes.
#[cfg(test)]
pub(crate) fn socks_generation() -> u64 {
    chain_route()
        .read()
        .map(|route| route.generation)
        .unwrap_or(u64::MAX)
}

/// Whether a chain request may egress right now. In Tor-always mode a request
/// before the SOCKS proxy is set would go direct over clearnet, leaking the
/// real IP and the queried name, so it is refused; the caller retries once Tor
/// is up. A no-op in enable/disable modes.
pub(crate) fn chain_egress_ok() -> Result<()> {
    chain_route_snapshot().map(|_| ())
}

/// Build an HTTP client and return the exact atomic route generation it uses.
/// Proxy parse/build failures are errors and never fall back to a direct client.
pub(crate) fn http_client(timeout: std::time::Duration) -> Result<(u64, reqwest::Client)> {
    let route = chain_route_snapshot()?;
    let client = build_http_client(route.socks.as_deref(), timeout)?;
    Ok((route.generation, client))
        }

#[cfg(test)]
static CHAIN_ROUTE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
static FINALITY_STATE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
pub(crate) async fn chain_route_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    CHAIN_ROUTE_TEST_LOCK.lock().await
    }

#[cfg(test)]
pub(crate) async fn finality_state_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    FINALITY_STATE_TEST_LOCK.lock().await
}

// ---------------------------------------------------------------------------
// Client-side finality verification config (see finality.rs, leaf.rs and
// docs/xid-lightclient-finality.md). All process-global so a resolver created
// anywhere picks them up; the node sets them at boot.
// ---------------------------------------------------------------------------

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};

/// The pinned validator set — the client's root of trust for finality. `None`
/// until the node installs it; while `None` and [`XID_VERIFY_FINALITY`] is on,
/// finality fails closed.
static PINNED_VALIDATORS: std::sync::RwLock<Option<finality::PinnedSet>> =
    std::sync::RwLock::new(None);

/// Whether to cryptographically verify digest finality against the pinned set
/// (and require leaf-binding). Default OFF — the node enables it once a pin is
/// installed and the chain serves signed attestations. OFF = legacy RPC-boolean.
static XID_VERIFY_FINALITY: AtomicBool = AtomicBool::new(false);

/// Max `|now − block_time|` and future pin clock skew, in seconds.
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

/// Replace the active pin with a light-client-verified NEWER set (see
/// [`lightclient`]). Monotonic and fail-closed: the new pin must be for the
/// same chain and a strictly higher height than the current one, and the
/// durable checkpoint must accept the rebind (its supersede rules) BEFORE the
/// in-memory set swaps — so a failure at any step leaves the previous trust
/// root fully in force. A same-height call is an idempotent no-op.
pub fn advance_finality_pin(new_pin: finality::PinnedSet) -> std::result::Result<(), String> {
    let current = pinned_validators()
        .ok_or_else(|| "cannot advance the finality pin: none installed".to_string())?;
    if new_pin.chain_id != current.chain_id {
        return Err(format!(
            "cannot advance the finality pin across chains ({} -> {})",
            current.chain_id, new_pin.chain_id
        ));
    }
    if new_pin.pinned_at_height < current.pinned_at_height {
        return Err(format!(
            "refusing to roll the finality pin back ({} -> {})",
            current.pinned_at_height, new_pin.pinned_at_height
        ));
    }
    if new_pin.pinned_at_height == current.pinned_at_height {
        return Ok(());
    }
    checkpoint::rebind(&new_pin)?;
    set_pinned_validators(Some(new_pin));
    Ok(())
}

/// Configure and restore the durable anti-rollback checkpoint used by every
/// finality-verifying resolver in this process. Call this after
/// [`install_finality_pin`] and before resolving any xID name. A malformed,
/// unreadable, or wrong-chain checkpoint fails closed.
pub fn configure_finality_checkpoint(
    path: impl Into<std::path::PathBuf>,
) -> std::result::Result<Option<FinalityCheckpoint>, String> {
    let pinned = pinned_validators().ok_or_else(|| {
        "install the xID finality pin before configuring its checkpoint".to_string()
    })?;
    checkpoint::configure(path, &pinned)
}

/// Return whether an exact finality height and digest still identify the
/// process's durable checkpoint under a pin that remains inside its weak-
/// subjectivity window. Disk caches use this to reject legacy, superseded, or
/// pin-expired entries once client-side finality is enabled.
pub fn finality_checkpoint_matches(height: u64, digest_hex: &str) -> bool {
    verify_finality_enabled() && xid_verified_binding_current(height, digest_hex)
}

/// Run a synchronous cache publication only while `height` and `digest_hex`
/// are the exact durable finality checkpoint and the installed pin remains
/// inside its weak-subjectivity window. The pin read guard and checkpoint mutex
/// stay held until `publish` returns, so neither a repin nor another resolver
/// can change the trust decision between the check and publication itself.
///
/// `publish` must not call another finality checkpoint or pin-configuration API.
pub fn publish_if_finality_checkpoint_current<T>(
    height: u64,
    digest_hex: &str,
    publish: impl FnOnce() -> T,
) -> Option<T> {
    if !verify_finality_enabled() {
        return None;
    }
    // Retain the pin read guard through publication. A repin cannot race the
    // age check and publish a cache entry under a different trust root.
    let pinned_guard = PINNED_VALIDATORS.read().ok()?;
    let pinned = pinned_guard.as_ref()?;
    let pin_current = pin_within_weak_subjectivity(
        pinned.pinned_at_unix,
        now_unix(),
        XID_WS_PERIOD_SECS.load(Ordering::Relaxed),
        XID_SKEW_SECS.load(Ordering::Relaxed),
    );
    if !pin_current || height < pinned.pinned_at_height {
        return None;
    }
    let result = checkpoint::publish_if_current(height, digest_hex, publish);
    drop(pinned_guard);
    result
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
        let pubkey: [u8; 32] = pk
            .try_into()
            .map_err(|_| "pin: pubkey not 32 bytes".to_string())?;
        if validators
            .insert(
                valcons.to_string(),
                finality::PinnedValidator {
                    pubkey,
                    voting_power: power,
                },
            )
            .is_some()
        {
            return Err(format!("pin: duplicate valcons {valcons}"));
    }
    }
    finality::PinnedSet::new(validators, chain_id, unix, height)
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

    #[test]
    fn rejects_ambiguous_or_overflowing_validator_pins() {
        let key_a = "11".repeat(32);
        let key_b = "22".repeat(32);
        let pin = |chain: &str, height: u64, unix: i64, validators: serde_json::Value| {
            serde_json::to_vec(&serde_json::json!({
                "chain_id": chain,
                "pinned_at_height": height,
                "pinned_at_unix": unix,
                "validators": validators,
            }))
            .unwrap()
        };
        let validator = |valcons: &str, pubkey: &str, power: u64| {
            serde_json::json!({
                "valcons": valcons,
                "pubkey": pubkey,
                "voting_power": power,
            })
        };

        assert!(parse_finality_pin(&pin(
            "",
            1,
            1,
            serde_json::json!([validator("v1", &key_a, 1)])
        ))
        .is_err());
        assert!(parse_finality_pin(&pin(
            "chain",
            0,
            1,
            serde_json::json!([validator("v1", &key_a, 1)])
        ))
        .is_err());
        assert!(parse_finality_pin(&pin(
            "chain",
            1,
            0,
            serde_json::json!([validator("v1", &key_a, 1)])
        ))
        .is_err());
        assert!(parse_finality_pin(&pin(
            "chain",
            1,
            1,
            serde_json::json!([validator("v1", &key_a, 0)])
        ))
        .is_err());
        assert!(parse_finality_pin(&pin(
            "chain",
            1,
            1,
            serde_json::json!([validator("v1", &key_a, 1), validator("v1", &key_b, 1)])
        ))
        .is_err());
        assert!(parse_finality_pin(&pin(
            "chain",
            1,
            1,
            serde_json::json!([validator("v1", &key_a, 1), validator("v2", &key_a, 1)])
        ))
        .is_err());
        assert!(parse_finality_pin(&pin(
            "chain",
            1,
            1,
            serde_json::json!([
                validator("v1", &key_a, u64::MAX),
                validator("v2", &key_b, 1)
            ])
        ))
        .is_err());
}

    #[test]
    fn weak_subjectivity_boundary_invalidates_every_verified_cache_binding() {
        let pinned_at = 1_000_000;
        let period = 7 * 24 * 3600;
        assert!(pin_within_weak_subjectivity(
            pinned_at,
            pinned_at + period,
            period,
            120,
        ));
        assert!(!pin_within_weak_subjectivity(
            pinned_at,
            pinned_at + period + 1,
            period,
            120,
        ));

        let now = pinned_at;
        assert!(pin_within_weak_subjectivity(now + 120, now, period, 120,));
        assert!(!pin_within_weak_subjectivity(now + 121, now, period, 120,));
        assert!(!pin_within_weak_subjectivity(now, now, period, -1));
        assert!(!pin_within_weak_subjectivity(now, now, -1, 120));

        let binding = (42, "11".repeat(32));
        assert!(xid_cache_binding_current_with(
            Some(&binding),
            true,
            Some(42),
            |height, digest| height == 42 && digest == "11".repeat(32),
        ));
        assert!(
            !xid_cache_binding_current_with(Some(&binding), true, None, |_height, _digest| true),
            "an expired pin must invalidate snapshot, digest, identity, and signer caches"
        );
        assert!(
            xid_cache_binding_current_with(None, false, None, |_height, _digest| false),
            "explicit legacy mode does not require a pin or binding"
        );
        assert!(
            !xid_cache_binding_current_with(Some(&binding), true, Some(43), |_height, _digest| {
                true
            },),
            "a cache below a newly installed pin height must not survive a repin"
        );
    }
}

/// Set the finality policy knobs. `skew_secs` bounds both signed block-time
/// drift and how far a pin capture timestamp may be ahead of the local clock.
pub fn set_finality_policy(skew_secs: i64, ws_period_secs: i64, min_power_bps: u32) {
    XID_SKEW_SECS.store(skew_secs, Ordering::Relaxed);
    XID_WS_PERIOD_SECS.store(ws_period_secs, Ordering::Relaxed);
    XID_MIN_POWER_BPS.store(min_power_bps, Ordering::Relaxed);
}

/// The monotonic anti-replay floor (persist across restarts).
pub fn xid_max_height() -> u64 {
    checkpoint::height()
}

pub(crate) fn xid_cache_binding_current(
    binding: Option<&(u64, String)>,
    verification_enabled: bool,
) -> bool {
    xid_cache_binding_current_with(
        binding,
        verification_enabled,
        finality_pin_floor_at(now_unix()),
        checkpoint::matches,
    )
}

pub(crate) fn xid_verified_binding_current(height: u64, digest: &str) -> bool {
    finality_pin_floor_at(now_unix()).is_some_and(|pinned_at_height| height >= pinned_at_height)
        && checkpoint::matches(height, digest)
}

fn xid_cache_binding_current_with(
    binding: Option<&(u64, String)>,
    verification_enabled: bool,
    pin_floor: Option<u64>,
    checkpoint_current: impl Fn(u64, &str) -> bool,
) -> bool {
    !verification_enabled
        || binding.is_some_and(|(height, digest)| {
            pin_floor.is_some_and(|pinned_at_height| *height >= pinned_at_height)
                && checkpoint_current(*height, digest)
        })
}

fn finality_pin_floor_at(now_unix: i64) -> Option<u64> {
    let Ok(pinned) = PINNED_VALIDATORS.read() else {
        return None;
    };
    let pinned = pinned.as_ref()?;
    pin_within_weak_subjectivity(
        pinned.pinned_at_unix,
        now_unix,
        XID_WS_PERIOD_SECS.load(Ordering::Relaxed),
        XID_SKEW_SECS.load(Ordering::Relaxed),
    )
    .then_some(pinned.pinned_at_height)
}

fn pin_within_weak_subjectivity(
    pinned_at_unix: i64,
    now_unix: i64,
    ws_period_secs: i64,
    skew_secs: i64,
) -> bool {
    ws_period_secs >= 0
        && skew_secs >= 0
        && pinned_at_unix <= now_unix.saturating_add(skew_secs)
        && now_unix.saturating_sub(pinned_at_unix) <= ws_period_secs
}

/// Build [`finality::VerifyParams`] from the configured policy + a `now` unix time.
pub(crate) fn finality_params(now_unix: i64, max_height_seen: u64) -> finality::VerifyParams {
    finality::VerifyParams {
        now_unix,
        skew_secs: XID_SKEW_SECS.load(Ordering::Relaxed),
        ws_period_secs: XID_WS_PERIOD_SECS.load(Ordering::Relaxed),
        min_power_bps: XID_MIN_POWER_BPS.load(Ordering::Relaxed),
        max_height_seen,
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
    /// A newer valid checkpoint won a concurrent race before this snapshot
    /// could be published. The resolver catches this internally and retries.
    #[error("finality advanced while publishing the resolved snapshot")]
    FinalityAdvanced,
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
    use crate::Identity;
    use std::collections::HashMap;
    use std::future::Future;
    use std::sync::RwLock;
    use std::time::{Duration, Instant};

    /// Authorization data must follow revocation quickly. The underlying
    /// resolver's profile cache is bypassed when this expires.
    const TTL: Duration = Duration::from_secs(3);

    struct Entry {
        identities: Vec<Identity>,
        at: Instant,
        finality_binding: Option<(u64, String)>,
    }

    static CACHE: RwLock<Option<HashMap<String, Entry>>> = RwLock::new(None);

    fn cached(key: &str) -> Option<Vec<Identity>> {
        let guard = CACHE.read().ok()?;
        let map = guard.as_ref()?;
        let entry = map.get(key)?;
        let checkpoint_current = super::xid_cache_binding_current(
            entry.finality_binding.as_ref(),
            super::verify_finality_enabled(),
        );
        (entry.at.elapsed() < TTL && checkpoint_current).then(|| entry.identities.clone())
    }

    fn store(key: String, identities: Vec<Identity>, finality_binding: Option<(u64, String)>) {
        if let Ok(mut guard) = CACHE.write() {
            guard.get_or_insert_with(HashMap::new).insert(
                key,
                Entry {
                    identities,
                    at: Instant::now(),
                    finality_binding,
                },
            );
        }
    }

    /// Drop every cached signer resolution (see [`super::clear_xid_caches`]).
    pub fn clear() {
        if let Ok(mut guard) = CACHE.write() {
            *guard = None;
        }
    }

    async fn resolve_identities_checked_with<F, Fut>(
        name: &str,
        tld: &str,
        fetch: F,
    ) -> super::Result<Vec<Identity>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = super::Result<(Vec<Identity>, Option<(u64, String)>)>>,
    {
        let key = format!("{name}.{tld}");
        if let Some(hit) = cached(&key) {
            return Ok(hit);
        }
        let (identities, binding) = fetch().await?;
        store(key, identities.clone(), binding);
        Ok(identities)
    }

    /// Resolve `name.tld` to its full linked identity records - address plus
    /// active/revocation state. Chain-delegated cert verification needs the
    /// revocation data, not just the address list.
    ///
    /// The checked form preserves chain lookup failures so callers can
    /// distinguish an authoritative empty identity list from an RPC, proof,
    /// malformed-response, or not-found error. Only successful resolutions
    /// enter the cache.
    ///
    /// Resolution is fresh and finality-bound: authorization data must not
    /// ride the resolver's 30-minute profile cache past a revocation, and the
    /// cache entry stores the exact checkpoint it was proven against so a
    /// checkpoint advance invalidates it (see `cached`).
    pub async fn resolve_identities_checked(
        name: &str,
        tld: &str,
    ) -> super::Result<Vec<Identity>> {
        resolve_identities_checked_with(name, tld, || async {
            let (domain, binding) = super::shared_resolver()
                .resolve_fresh_bound(name, tld)
                .await?;
            Ok((domain.identities, binding))
        })
        .await
    }

    /// Resolve every identity address allowed to sign `name.tld` user content.
    ///
    /// Unlike [`resolve`], this checked form preserves chain lookup failures
    /// (see [`resolve_identities_checked`]).
    pub async fn resolve_checked(name: &str, tld: &str) -> super::Result<Vec<String>> {
        // Revoked identities stay in the list on purpose: content signed
        // before the revocation (plus grace) must keep verifying, and the
        // per-content cutoff lives in epix-content's verify path, not here.
        Ok(resolve_identities_checked(name, tld)
            .await?
            .into_iter()
            .map(|identity| identity.address)
            .collect())
    }

    /// The addresses that may sign for `name.tld`'s user content: its linked
    /// identity addresses (all of them - a signature matching any is valid,
    /// EpixNet's `resolveUserSigners`). Empty if the name doesn't resolve or
    /// the checked chain lookup fails.
    pub async fn resolve(name: &str, tld: &str) -> Vec<String> {
        resolve_checked(name, tld).await.unwrap_or_default()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::ChainError;
        use std::sync::atomic::{AtomicUsize, Ordering};

        fn identity(address: &str) -> Identity {
            Identity {
                address: address.to_string(),
                label: String::new(),
                active: true,
                revoked_at: 0,
                revoked_at_time: 0,
            }
        }

        #[tokio::test]
        async fn checked_resolution_does_not_cache_failures() {
            clear();
            let attempts = AtomicUsize::new(0);

            let error = resolve_identities_checked_with("retryable", "test", || async {
                attempts.fetch_add(1, Ordering::Relaxed);
                Err(ChainError::Rpc("offline".into()))
            })
            .await;
            assert!(matches!(error, Err(ChainError::Rpc(message)) if message == "offline"));

            let identities = resolve_identities_checked_with("retryable", "test", || async {
                attempts.fetch_add(1, Ordering::Relaxed);
                Ok((vec![identity("epix1signer")], None))
            })
            .await
            .unwrap();
            assert_eq!(identities, [identity("epix1signer")]);
            assert_eq!(attempts.load(Ordering::Relaxed), 2);

            let cached = resolve_identities_checked_with("retryable", "test", || async {
                attempts.fetch_add(1, Ordering::Relaxed);
                Err(ChainError::Malformed("must not run".into()))
            })
            .await
            .unwrap();
            assert_eq!(cached, identities);
            assert_eq!(attempts.load(Ordering::Relaxed), 2);
            clear();
        }

        #[tokio::test]
        async fn checked_resolution_preserves_chain_error_kinds() {
            let rpc = resolve_identities_checked_with("rpc", "test", || async {
                Err(ChainError::Rpc("down".into()))
            })
            .await;
            assert!(matches!(rpc, Err(ChainError::Rpc(_))));

            let proof = resolve_identities_checked_with("proof", "test", || async {
                Err(ChainError::MerkleInvalid)
            })
            .await;
            assert!(matches!(proof, Err(ChainError::MerkleInvalid)));

            let malformed = resolve_identities_checked_with("malformed", "test", || async {
                Err(ChainError::Malformed("bad response".into()))
            })
            .await;
            assert!(matches!(malformed, Err(ChainError::Malformed(_))));

            let missing = resolve_identities_checked_with("missing", "test", || async {
                Err(ChainError::NotFound("missing.test".into()))
            })
            .await;
            assert!(matches!(missing, Err(ChainError::NotFound(_))));
        }
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

    /// Profile results are cheap to cache briefly, but they also carry device
    /// status and must not retain a revoked identity for a day.
    const POSITIVE_TTL: Duration = Duration::from_secs(30);
    /// Channel authorization gets the shortest TTL and bypasses the resolver's
    /// general snapshot cache when it expires.
    const ACTIVE_STATUS_TTL: Duration = Duration::from_secs(3);
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

    struct Entry {
        info: Option<XidInfo>,
        at: Instant,
        finality_binding: Option<(u64, String)>,
    }

    static CACHE: RwLock<Option<HashMap<String, Entry>>> = RwLock::new(None);

    fn ttl_for(key: &str, info: &Option<XidInfo>) -> Duration {
        if key.starts_with("active?:") {
            ACTIVE_STATUS_TTL
        } else if info.is_some() {
            POSITIVE_TTL
        } else {
            NEGATIVE_TTL
        }
    }

    fn cached(key: &str) -> Option<Option<XidInfo>> {
        let guard = CACHE.read().ok()?;
        let entry = guard.as_ref()?.get(key)?;
        // A POSITIVE answer must stay bound to a finalized checkpoint, so it is
        // dropped the moment its binding is no longer current. A NEGATIVE answer
        // ("address not linked" / "not in the verified domain") carries no
        // binding by construction; gating it on `checkpoint_current` (which is
        // false for a `None` binding under verification) would store it but never
        // serve it, re-issuing the RPC on every call. Serve negatives on their
        // TTL alone so they dedup under verification exactly as in legacy mode -
        // a stale negative can never forge a positive, and NEGATIVE_TTL already
        // bounds how long a freshly-linked identity stays hidden.
        let binding_ok = entry.info.is_none()
            || super::xid_cache_binding_current(
                entry.finality_binding.as_ref(),
                super::verify_finality_enabled(),
            );
        (entry.at.elapsed() < ttl_for(key, &entry.info) && binding_ok).then(|| entry.info.clone())
    }

    fn store(key: String, info: Option<XidInfo>, finality_binding: Option<(u64, String)>) {
        if let Ok(mut guard) = CACHE.write() {
            guard.get_or_insert_with(HashMap::new).insert(
                key,
                Entry {
                    info,
                    at: Instant::now(),
                    finality_binding,
                },
            );
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
        let (_, client) = super::http_client(Duration::from_secs(15)).ok()?;
        let url = format!("{DEFAULT_RPC_URL}/xid/v1/reverse_identity/{address}");
        // Transient fetch errors return without caching so the next call retries.
        let data: serde_json::Value = client.get(&url).send().await.ok()?.json().await.ok()?;
        let record = match data.get("name_record").filter(|r| !r.is_null()) {
            Some(r) => r,
            None => {
                store(address.to_string(), None, None);
                return None;
            }
        };
        let name = record.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let tld = record.get("tld").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() || tld.is_empty() {
            store(address.to_string(), None, None);
            return None;
        }
        // Step 2: confirm through the Merkle-verified forward resolve.
        let (domain, binding) = super::shared_resolver()
            .resolve_fresh_bound(name, tld)
            .await
            .ok()?;
        let Some(ident) = domain.identities.iter().find(|i| i.address == address) else {
            // Verified domain doesn't actually contain this identity.
            store(address.to_string(), None, binding);
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
        store(address.to_string(), Some(info.clone()), binding.clone());
        store(domain.fqdn(), Some(info.clone()), binding);
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
        let (domain, binding) = match super::shared_resolver()
            .resolve_fresh_bound(name, tld)
            .await
        {
            Ok(resolved) => resolved,
            Err(super::ChainError::NotFound(_)) => {
                store(fqdn.to_string(), None, None);
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
        store(fqdn.to_string(), Some(info.clone()), binding);
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
        match super::shared_resolver()
            .resolve_fresh_bound(name, tld)
            .await
        {
            Ok((domain, binding)) => {
                let active = domain
                    .identities
                    .iter()
                    .any(|i| i.active && i.revoked_at == 0);
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
                    binding,
                );
                Some(active)
            }
            // Not registered: cache a short negative; indeterminate to the caller.
            Err(super::ChainError::NotFound(_)) => {
                store(ck, None, None);
                None
            }
            // Transient/unreachable: don't cache; indeterminate → caller fails open.
            Err(_) => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        static CACHE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

        struct VerifyFinalityReset(bool);

        impl Drop for VerifyFinalityReset {
            fn drop(&mut self) {
                crate::set_verify_finality(self.0);
            }
        }

        struct CacheReset;

        impl Drop for CacheReset {
            fn drop(&mut self) {
                clear();
            }
        }

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

        #[test]
        fn authorization_cache_is_short_lived() {
            assert_eq!(
                ttl_for("active?:alice.epix", &Some(info(true))),
                Duration::from_secs(3)
            );
            assert_eq!(
                ttl_for("alice.epix", &Some(info(true))),
                Duration::from_secs(30)
            );
            assert_eq!(ttl_for("alice.epix", &None), Duration::from_secs(30));
        }

        // Pre-seed the resolver cache so no network is touched: the active flag
        // maps through to the three-valued answer the channel gate relies on.
        #[tokio::test]
        async fn name_active_maps_cached_flag_without_network() {
            let _finality_guard = crate::finality_state_test_guard().await;
            let _cache_guard = CACHE_TEST_LOCK.lock().await;
            let _verify_reset = VerifyFinalityReset(crate::verify_finality_enabled());
            let _cache_reset = CacheReset;
            crate::set_verify_finality(false);
            clear();
            store("active?:alice.epix".into(), Some(info(true)), None);
            assert_eq!(
                name_has_active_identity("alice.epix").await,
                Some(true),
                "active → keep"
            );
            store("active?:bob.epix".into(), Some(info(false)), None);
            assert_eq!(
                name_has_active_identity("bob.epix").await,
                Some(false),
                "revoked → cut off"
            );
            store("active?:ghost.epix".into(), None, None);
            assert_eq!(
                name_has_active_identity("ghost.epix").await,
                None,
                "unknown → fail open"
            );
        }

        #[tokio::test]
        async fn verified_mode_serves_negative_cache_and_expires_it() {
            let _finality_guard = crate::finality_state_test_guard().await;
            let _cache_guard = CACHE_TEST_LOCK.lock().await;
            let _verify_reset = VerifyFinalityReset(crate::verify_finality_enabled());
            let _cache_reset = CacheReset;
            crate::set_verify_finality(true);
            clear();

            let missing = "epix1missing";
            store(missing.into(), None, None);
            assert!(
                matches!(cached(missing), Some(None)),
                "a verified-mode negative must be served from cache"
            );

            let unbound = "unbound.epix";
            store(unbound.into(), Some(info(true)), None);
            assert!(
                cached(unbound).is_none(),
                "verified-mode positives must still require a current finality binding"
            );

            let mut guard = CACHE.write().unwrap();
            guard
                .as_mut()
                .unwrap()
                .get_mut(missing)
                .unwrap()
                .at = Instant::now() - NEGATIVE_TTL - Duration::from_millis(1);
            drop(guard);
            assert!(
                cached(missing).is_none(),
                "a negative must stop being served after its short TTL"
            );
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
    #[tokio::test]
    async fn egress_gate_blocks_until_socks_then_allows() {
        let _route_guard = chain_route_test_guard().await;
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

    #[tokio::test]
    async fn invalid_proxy_configuration_never_falls_back_to_direct() {
        let _route_guard = chain_route_test_guard().await;
        set_chain_require_tor(true);
        set_chain_socks(Some("socks5h://[::1".into()));

        assert_eq!(chain_socks(), None);
        let error = chain_egress_ok().unwrap_err().to_string();
        assert!(error.contains("invalid chain SOCKS proxy"), "{error}");
        assert!(http_client(std::time::Duration::from_secs(15)).is_err());

        set_chain_socks(None);
        set_chain_require_tor(false);
    }
}
