//! Self-advancing validator-set tracking: a CometBFT light client that keeps
//! the xID finality pin current so nodes never need a shipped re-pin.
//!
//! The static pin (`xid_pin.json`) remains the COLD-START ANCHOR — the root of
//! trust a fresh install starts from. From there, this module advances trust
//! forward using CometBFT's own consensus: each new signed header is accepted
//! only if validators holding at least 1/3 of an already-trusted set signed it
//! (skipping verification, audited `tendermint-light-client-verifier`), exactly
//! how IBC light clients follow a chain. Each accepted header carries the
//! `validators_hash` of the set at that height; the set fetched for that height
//! must hash to it, and that set becomes the new [`crate::PinnedSet`] the xID
//! vote-extension verifier checks attestations against.
//!
//! Consequences:
//! - The trusted set is always ≈ the live set, so no drift buffer is needed on
//!   top of the >2/3 attestation threshold, and validator churn/maintenance
//!   does not strand resolution.
//! - A continuously-running client (or one that connects at least once per
//!   trusting period, 2/3 × unbonding ≈ 14 days) NEVER re-pins manually — a
//!   year-old binary keeps working.
//! - Verification cost is a handful of ed25519 verifies per advance: fine for
//!   mobile.
//!
//! Fail-closed: any verification failure leaves the current pin untouched.
//! The light client can only ever be a liveness upgrade, not a safety
//! downgrade — a hostile RPC that serves garbage stalls advancement (until the
//! weak-subjectivity window lapses, as before), it cannot rotate the set.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tendermint::block::signed_header::SignedHeader;
use tendermint::validator::{Info as TmValidatorInfo, Set as TmValidatorSet};
use tendermint_light_client_verifier::options::Options;
use tendermint_light_client_verifier::types::{TrustedBlockState, UntrustedBlockState};
use tendermint_light_client_verifier::{ProdVerifier, Verdict, Verifier};

use crate::finality::{PinnedSet, PinnedValidator};

/// Default CometBFT RPC the light client follows. Overridable per-node; routed
/// through the same chain egress (socks/Tor) as every other chain fetch, so
/// Tor-Always mode covers it and no new clearnet path is introduced.
pub const DEFAULT_CMT_RPC_URL: &str = "https://rpc.epix.zone";

/// Trusting period: how stale a trusted header may be and still serve as a
/// verification base. 2/3 of the chain's unbonding period (21 d), the standard
/// light-client margin: within it, >1/3 of any trusted set is still bonded and
/// slashable, so signatures from it cannot be costlessly forged.
pub const DEFAULT_TRUSTING_PERIOD_SECS: u64 = 14 * 24 * 3600;

/// Max bisection steps before giving up on one advance attempt. 2^40 blocks is
/// far beyond any real gap inside a trusting period.
const MAX_BISECTION_STEPS: usize = 40;

/// The consensus-address bech32 prefix attestations key validators by.
const VALCONS_HRP: bech32::Hrp = bech32::Hrp::parse_unchecked("epixvalcons");

/// Configuration for one advance cycle.
#[derive(Clone, Debug)]
pub struct LightClientConfig {
    /// CometBFT RPC base URL (`/commit`, `/validators`, `/status`).
    pub rpc_url: String,
    /// Where the trusted state persists (beside the finality checkpoint).
    pub state_path: PathBuf,
    pub trusting_period_secs: u64,
    pub clock_drift_secs: u64,
}

impl LightClientConfig {
    pub fn new(state_path: PathBuf) -> Self {
        Self {
            rpc_url: std::env::var("EPIX_CMT_RPC_URL")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_CMT_RPC_URL.to_string()),
            state_path,
            trusting_period_secs: DEFAULT_TRUSTING_PERIOD_SECS,
            clock_drift_secs: 30,
        }
    }
}

/// Outcome of one [`advance_trusted_set`] cycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Advance {
    /// Verified up to `height`; the pinned set was refreshed from it.
    Advanced { height: u64, validators: usize },
    /// Already at (or within one block of) the chain head; nothing to do.
    UpToDate { height: u64 },
    /// The persisted trusted state (or the pin) is older than the trusting
    /// period; advancing is impossible without a fresh anchor. The current pin
    /// is left untouched (it fails closed on its own weak-subjectivity clock).
    AnchorExpired { trusted_unix: i64 },
}

/// The durable trusted state: the last light-client-verified signed header and
/// the NEXT validator set it committed to (`next_validators_hash`), which is
/// exactly what verifying the following untrusted header requires. Stored as
/// the CometBFT RPC JSON shapes so (de)serialization is tendermint-rs's own.
#[derive(serde::Serialize, serde::Deserialize)]
struct TrustedStateFile {
    version: u32,
    chain_id: String,
    signed_header: SignedHeader,
    next_validators: Vec<TmValidatorInfo>,
}

const TRUSTED_STATE_VERSION: u32 = 1;

fn read_trusted_state(path: &Path) -> Result<Option<TrustedStateFile>, String> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("light client: cannot read {}: {e}", path.display())),
    };
    let state: TrustedStateFile = serde_json::from_slice(&bytes).map_err(|e| {
        format!(
            "light client: corrupt trusted state {}: {e}",
            path.display()
        )
    })?;
    if state.version != TRUSTED_STATE_VERSION {
        return Err(format!(
            "light client: trusted state version {} unsupported",
            state.version
        ));
    }
    Ok(Some(state))
}

/// Atomic write + fsync, same durability contract as the finality checkpoint:
/// a crash mid-write must never leave a torn or missing trust anchor.
fn write_trusted_state(path: &Path, state: &TrustedStateFile) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "light client: state path has no parent".to_string())?;
    let json = serde_json::to_vec(state)
        .map_err(|e| format!("light client: serialize trusted state: {e}"))?;
    let tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("light client: temp file: {e}"))?;
    use std::io::Write as _;
    let mut file = tmp;
    file.write_all(&json)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.as_file().sync_all())
        .map_err(|e| format!("light client: write trusted state: {e}"))?;
    let persisted = file
        .persist(path)
        .map_err(|e| format!("light client: persist trusted state: {e}"))?;
    persisted
        .sync_all()
        .map_err(|e| format!("light client: sync trusted state: {e}"))?;
    #[cfg(unix)]
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

// ---- RPC fetch (reuses the crate's egress: socks/Tor route, fail-closed) ----

async fn rpc_json(base: &str, path: &str) -> Result<serde_json::Value, String> {
    crate::chain_egress_ok().map_err(|e| e.to_string())?;
    let (_, client) = crate::http_client(Duration::from_secs(20)).map_err(|e| e.to_string())?;
    let url = format!("{base}{path}");
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("light client: fetch {url}: {e}"))?;
    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("light client: parse {url}: {e}"))
}

async fn fetch_signed_header(base: &str, height: u64) -> Result<SignedHeader, String> {
    let v = rpc_json(base, &format!("/commit?height={height}")).await?;
    serde_json::from_value(v["result"]["signed_header"].clone())
        .map_err(|e| format!("light client: signed header at {height}: {e}"))
}

async fn fetch_validators(base: &str, height: u64) -> Result<Vec<TmValidatorInfo>, String> {
    // One page is enough for this chain (19 validators, cap 100); page anyway
    // so a larger future set cannot silently truncate (truncation = wrong
    // validators_hash = fail closed, but loop to be correct, not just safe).
    let mut infos: Vec<TmValidatorInfo> = Vec::new();
    let mut page = 1u32;
    loop {
        let v = rpc_json(
            base,
            &format!("/validators?height={height}&per_page=100&page={page}"),
        )
        .await?;
        let total: u64 = v["result"]["total"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("light client: validators total missing at {height}"))?;
        let batch = v["result"]["validators"]
            .as_array()
            .cloned()
            .ok_or_else(|| format!("light client: validators missing at {height}"))?;
        for entry in batch {
            infos.push(
                serde_json::from_value(entry)
                    .map_err(|e| format!("light client: validator at {height}: {e}"))?,
            );
        }
        if infos.len() as u64 >= total || page > 64 {
            break;
        }
        page += 1;
    }
    Ok(infos)
}

async fn fetch_latest_height(base: &str) -> Result<u64, String> {
    let v = rpc_json(base, "/status").await?;
    v["result"]["sync_info"]["latest_block_height"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "light client: latest height missing".to_string())
}

// ---- validator-set mapping ----

/// The bech32 consensus address (`epixvalcons1…`) attestations key this
/// validator by. CometBFT's validator `address` IS `sha256(pubkey)[..20]`
/// (verified against all live validators), so encode it directly.
fn valcons_of(info: &TmValidatorInfo) -> Result<String, String> {
    bech32::encode::<bech32::Bech32>(VALCONS_HRP, info.address.as_bytes())
        .map_err(|e| format!("light client: valcons encode: {e}"))
}

/// Map a light-client-verified validator set into the `PinnedSet` the xID
/// vote-extension verifier consumes, stamped with the verified header's
/// height/time so the weak-subjectivity clock restarts at every advance.
fn pinned_set_from(
    set: &[TmValidatorInfo],
    chain_id: &str,
    header_time_unix: i64,
    height: u64,
) -> Result<PinnedSet, String> {
    let mut validators: HashMap<String, PinnedValidator> = HashMap::new();
    for info in set {
        let valcons = valcons_of(info)?;
        let pubkey: [u8; 32] = info
            .pub_key
            .ed25519()
            .ok_or_else(|| format!("light client: {valcons} has a non-ed25519 consensus key"))?
            .as_bytes()
            .try_into()
            .map_err(|_| format!("light client: {valcons} pubkey is not 32 bytes"))?;
        let voting_power = info.power.value();
        if validators
            .insert(
                valcons.clone(),
                PinnedValidator {
                    pubkey,
                    voting_power,
                },
            )
            .is_some()
        {
            return Err(format!("light client: duplicate validator {valcons}"));
        }
    }
    PinnedSet::new(validators, chain_id, header_time_unix, height)
}

/// True when the header's validator set equals the given pin: same valcons
/// keys, same consensus pubkeys, same voting power, nothing extra or missing.
/// This is the trust splice — it proves the signed header chain and the shipped
/// pin describe the SAME set, so trust rooted in the pin may continue along the
/// header chain.
fn set_matches_pin(set: &[TmValidatorInfo], pin: &PinnedSet) -> Result<bool, String> {
    if set.len() != pin.validators.len() {
        return Ok(false);
    }
    for info in set {
        let valcons = valcons_of(info)?;
        let Some(pinned) = pin.validators.get(&valcons) else {
            return Ok(false);
        };
        let pk = info.pub_key.ed25519().map(|k| k.as_bytes().to_vec());
        if pk.as_deref() != Some(&pinned.pubkey[..]) || info.power.value() != pinned.voting_power {
            return Ok(false);
        }
    }
    Ok(true)
}

fn header_time_unix(sh: &SignedHeader) -> i64 {
    sh.header.time.unix_timestamp()
}

fn now_tm() -> Result<tendermint::Time, String> {
    tendermint::Time::from_unix_timestamp(crate::now_unix(), 0)
        .map_err(|e| format!("light client: clock: {e}"))
}

fn lc_options(cfg: &LightClientConfig) -> Options {
    Options {
        trust_threshold: Default::default(), // 1/3, the standard skipping bound
        trusting_period: Duration::from_secs(cfg.trusting_period_secs),
        clock_drift: Duration::from_secs(cfg.clock_drift_secs),
    }
}

/// Verify `target` against `trusted` (skipping verification). On
/// `NotEnoughTrust`, bisect: verify a midpoint first, adopt it as the new
/// trusted base, and continue toward the target.
async fn verify_forward(
    cfg: &LightClientConfig,
    mut trusted_sh: SignedHeader,
    mut trusted_next_vals: Vec<TmValidatorInfo>,
    target: u64,
) -> Result<(SignedHeader, Vec<TmValidatorInfo>), String> {
    let verifier = ProdVerifier::default();
    let opts = lc_options(cfg);
    let chain_id = trusted_sh.header.chain_id.clone();
    let mut goal = target;
    for _ in 0..MAX_BISECTION_STEPS {
        let trusted_height = trusted_sh.header.height.value();
        if trusted_height >= target {
            return Ok((trusted_sh, trusted_next_vals));
        }
        let untrusted_sh = fetch_signed_header(&cfg.rpc_url, goal).await?;
        let untrusted_vals = fetch_validators(&cfg.rpc_url, goal).await?;
        let untrusted_next_vals = fetch_validators(&cfg.rpc_url, goal + 1).await?;
        let untrusted_set = TmValidatorSet::without_proposer(untrusted_vals.clone());
        let untrusted_next_set = TmValidatorSet::without_proposer(untrusted_next_vals.clone());
        let trusted_next_set = TmValidatorSet::without_proposer(trusted_next_vals.clone());

        let trusted_state = TrustedBlockState {
            chain_id: &chain_id,
            header_time: trusted_sh.header.time,
            height: trusted_sh.header.height,
            next_validators: &trusted_next_set,
            next_validators_hash: trusted_sh.header.next_validators_hash,
        };
        let untrusted_state = UntrustedBlockState {
            signed_header: &untrusted_sh,
            validators: &untrusted_set,
            next_validators: Some(&untrusted_next_set),
        };
        match verifier.verify_update_header(untrusted_state, trusted_state, &opts, now_tm()?) {
            Verdict::Success => {
                trusted_sh = untrusted_sh;
                trusted_next_vals = untrusted_next_vals;
                goal = target;
            }
            Verdict::NotEnoughTrust(_) => {
                // The set changed too much across the gap: verify a midpoint
                // first. Strictly between trusted and goal, else give up.
                let mid = trusted_height + (goal - trusted_height) / 2;
                if mid <= trusted_height || mid >= goal {
                    return Err(format!(
                        "light client: cannot bridge trust from {trusted_height} to {goal}"
                    ));
                }
                goal = mid;
            }
            Verdict::Invalid(detail) => {
                return Err(format!(
                    "light client: header {goal} REJECTED: {detail} (leaving current pin untouched)"
                ));
            }
        }
    }
    Err("light client: bisection exceeded step budget".to_string())
}

/// Run one advance cycle:
///
/// 1. Load the persisted trusted state; if none, BOOTSTRAP from the installed
///    pin — fetch the signed header + set at the pin height and require the
///    set to EQUAL the pinned set (the trust splice).
/// 2. Skip-verify from the trusted header to (near) the chain head.
/// 3. Persist the new trusted state, then republish the pin:
///    [`crate::advance_finality_pin`] swaps `PINNED_VALIDATORS` and rebinds
///    the finality checkpoint, all fail-closed.
///
/// Any error leaves both the persisted state and the active pin untouched.
pub async fn advance_trusted_set(cfg: &LightClientConfig) -> Result<Advance, String> {
    let (trusted_sh, trusted_next_vals) = match read_trusted_state(&cfg.state_path)? {
        Some(state) => (state.signed_header, state.next_validators),
        None => bootstrap_from_pin(cfg).await?,
    };

    // A trusted header older than the trusting period cannot anchor skipping
    // verification; report it rather than silently doing nothing. The pin's
    // own weak-subjectivity check keeps failing closed as before.
    let trusted_unix = header_time_unix(&trusted_sh);
    let age = crate::now_unix().saturating_sub(trusted_unix);
    if age > cfg.trusting_period_secs as i64 {
        return Ok(Advance::AnchorExpired { trusted_unix });
    }

    let head = fetch_latest_height(&cfg.rpc_url).await?;
    // Verify to head-2 so /validators at target+1 always exists.
    let target = head.saturating_sub(2);
    let trusted_height = trusted_sh.header.height.value();
    if target <= trusted_height {
        return Ok(Advance::UpToDate {
            height: trusted_height,
        });
    }

    let (new_sh, new_next_vals) =
        verify_forward(cfg, trusted_sh, trusted_next_vals, target).await?;
    let height = new_sh.header.height.value();
    let chain_id = new_sh.header.chain_id.to_string();

    // The set that signs vote extensions AT `height` is the set of `height`
    // itself; fetch and bind it to the verified header's validators_hash.
    let vals = fetch_validators(&cfg.rpc_url, height).await?;
    let set = TmValidatorSet::without_proposer(vals.clone());
    if set.hash() != new_sh.header.validators_hash {
        return Err(format!(
            "light client: validator set at {height} does not hash to the verified header"
        ));
    }
    let new_pin = pinned_set_from(&vals, &chain_id, header_time_unix(&new_sh), height)?;
    let validators = new_pin.validators.len();

    // Persist trust BEFORE publishing, so a crash between the two re-derives
    // the same pin on restart instead of resurrecting an older set.
    write_trusted_state(
        &cfg.state_path,
        &TrustedStateFile {
            version: TRUSTED_STATE_VERSION,
            chain_id,
            signed_header: new_sh,
            next_validators: new_next_vals,
        },
    )?;
    crate::advance_finality_pin(new_pin)?;
    Ok(Advance::Advanced { height, validators })
}

/// First run: splice light-client trust onto the shipped pin. The header at
/// the pin height must carry a validator set EQUAL to the pinned one (same
/// valcons, pubkeys, powers) and hash-match its `validators_hash`; that header
/// then becomes the initial trusted state.
async fn bootstrap_from_pin(
    cfg: &LightClientConfig,
) -> Result<(SignedHeader, Vec<TmValidatorInfo>), String> {
    let pin = crate::pinned_validators()
        .ok_or_else(|| "light client: no finality pin installed to bootstrap from".to_string())?;
    let height = pin.pinned_at_height;
    let sh = fetch_signed_header(&cfg.rpc_url, height).await?;
    if sh.header.chain_id.as_str() != pin.chain_id {
        return Err(format!(
            "light client: pin chain_id {} != header chain_id {}",
            pin.chain_id, sh.header.chain_id
        ));
    }
    let vals = fetch_validators(&cfg.rpc_url, height).await?;
    let set = TmValidatorSet::without_proposer(vals.clone());
    if set.hash() != sh.header.validators_hash {
        return Err(format!(
            "light client: bootstrap set at {height} does not hash to the header"
        ));
    }
    if !set_matches_pin(&vals, &pin)? {
        return Err(format!(
            "light client: validator set at pin height {height} does not match the shipped pin; \
             refusing to bootstrap from an unverifiable anchor"
        ));
    }
    let next_vals = fetch_validators(&cfg.rpc_url, height + 1).await?;
    let next_set = TmValidatorSet::without_proposer(next_vals.clone());
    if next_set.hash() != sh.header.next_validators_hash {
        return Err(format!(
            "light client: bootstrap next-set at {height} does not hash to the header"
        ));
    }
    Ok((sh, next_vals))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tm_validator(pubkey_seed: u8, power: u64) -> TmValidatorInfo {
        let sk = tendermint::PrivateKey::Ed25519(
            tendermint::crypto::ed25519::SigningKey::try_from(&[pubkey_seed; 32][..]).unwrap(),
        );
        TmValidatorInfo::new(
            sk.public_key(),
            tendermint::vote::Power::try_from(power).unwrap(),
        )
    }

    #[test]
    fn valcons_matches_cometbft_address_derivation() {
        // CometBFT: address = sha256(pubkey)[..20]; tendermint-rs computes the
        // same in Info::new. Our valcons must bech32-encode exactly that.
        let info = tm_validator(7, 10);
        let pk = info.pub_key.ed25519().unwrap();
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(pk.as_bytes());
        assert_eq!(info.address.as_bytes(), &digest[..20]);
        let valcons = valcons_of(&info).unwrap();
        assert!(valcons.starts_with("epixvalcons1"), "{valcons}");
        let (hrp, data) = bech32::decode(&valcons).unwrap();
        assert_eq!(hrp.as_str(), "epixvalcons");
        assert_eq!(data, digest[..20]);
    }

    #[test]
    fn pinned_set_from_maps_all_fields() {
        let vals = vec![tm_validator(1, 700), tm_validator(2, 300)];
        let pin = pinned_set_from(&vals, "epix_1916-1", 1_700_000_000, 42).unwrap();
        assert_eq!(pin.total_power, 1000);
        assert_eq!(pin.chain_id, "epix_1916-1");
        assert_eq!(pin.pinned_at_unix, 1_700_000_000);
        assert_eq!(pin.pinned_at_height, 42);
        assert_eq!(pin.validators.len(), 2);
        for info in &vals {
            let valcons = valcons_of(info).unwrap();
            let pinned = pin.validators.get(&valcons).expect("mapped");
            assert_eq!(pinned.pubkey, info.pub_key.ed25519().unwrap().as_bytes());
            assert_eq!(pinned.voting_power, info.power.value());
        }
    }

    #[test]
    fn set_matches_pin_detects_all_divergence() {
        let vals = vec![tm_validator(1, 700), tm_validator(2, 300)];
        let pin = pinned_set_from(&vals, "epix_1916-1", 1, 1).unwrap();
        assert!(set_matches_pin(&vals, &pin).unwrap());
        // extra validator
        let mut extra = vals.clone();
        extra.push(tm_validator(3, 5));
        assert!(!set_matches_pin(&extra, &pin).unwrap());
        // power change
        let changed = vec![tm_validator(1, 701), tm_validator(2, 300)];
        assert!(!set_matches_pin(&changed, &pin).unwrap());
        // different key entirely
        let swapped = vec![tm_validator(1, 700), tm_validator(9, 300)];
        assert!(!set_matches_pin(&swapped, &pin).unwrap());
    }

    #[test]
    fn trusted_state_roundtrip_and_corruption_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xid_lc_state.json");
        assert!(read_trusted_state(&path).unwrap().is_none());

        // A real signed header requires consensus data; exercise the file
        // contract with raw JSON instead: corrupt content must error, not
        // silently reset trust.
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(read_trusted_state(&path).is_err());

        std::fs::write(
            &path,
            br#"{"version":99,"chain_id":"x","signed_header":{},"next_validators":[]}"#,
        )
        .unwrap();
        assert!(read_trusted_state(&path).is_err());
    }
}
