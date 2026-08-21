//! `ChainAttestation` - trust whole-state chain-attested content.
//!
//! Some `content.json` files opt out of per-name Merkle proofs and instead
//! carry a `state_digest`. Such content is trusted **iff** that digest equals
//! the chain's *current* state digest **and** that digest is finalized by 2/3+
//! validators. There are no signatures to check - validator consensus *is* the
//! proof. (Contrast [`XidResolver`](crate::XidResolver), which proves a single
//! name with a Merkle path.)
//!
//! In legacy mode, two short-lived caches keep this cheap: the current digest
//! (15s) and per-digest finality (30s). Name lookups are cached against the
//! digest they were seen under. Verified mode instead shares the proof-bound
//! resolver's signed-finality and durable-checkpoint path.

use crate::{ChainError, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const DIGEST_TTL: Duration = Duration::from_secs(15);
const ATTESTATION_TTL: Duration = Duration::from_secs(30);
type NameCache = HashMap<(String, String), (Option<Value>, String)>;

/// The chain's current committed state.
#[derive(Clone, Debug)]
pub struct StateDigest {
    pub digest: String,
    pub height: u64,
    pub num_names: u64,
}

/// Verifies chain-attested content against the Epix chain's finalized state.
pub struct ChainAttestation {
    /// HTTP client + the SOCKS generation it was built for (rebuilt on change,
    /// so a direct client from before Tor came up doesn't keep sending direct).
    client: RwLock<Option<(u64, reqwest::Client)>>,
    rpc_url: String,
    /// Proof-bound resolver used whenever pinned-validator verification is on.
    /// Keeping one resolver here preserves its verified snapshot and digest
    /// caches without ever falling back to the unproved legacy `/resolve` API.
    resolver: crate::XidResolver,
    digest: RwLock<Option<(StateDigest, Instant)>>,
    finalized: RwLock<HashMap<String, (bool, Instant)>>,
    names: RwLock<NameCache>,
}

impl ChainAttestation {
    pub fn new(rpc_url: impl Into<String>) -> Self {
        let rpc_url = rpc_url.into().trim_end_matches('/').to_string();
        let client = crate::http_client(Duration::from_secs(15)).ok();
        Self {
            client: RwLock::new(client),
            resolver: crate::XidResolver::new(&rpc_url),
            rpc_url,
            digest: RwLock::new(None),
            finalized: RwLock::new(HashMap::new()),
            names: RwLock::new(HashMap::new()),
        }
    }

    /// The HTTP client for the current SOCKS setting, rebuilding on change.
    async fn client(&self) -> Result<reqwest::Client> {
        let generation = crate::chain_route_snapshot()?.generation;
        {
            let cur = self.client.read().await;
            if let Some((cached_generation, client)) = cur.as_ref() {
                if *cached_generation == generation {
                    return Ok(client.clone());
            }
        }
        }
        let (generation, client) = crate::http_client(Duration::from_secs(15))?;
        *self.client.write().await = Some((generation, client.clone()));
        Ok(client)
    }

    /// The chain's current state digest (cached for [`DIGEST_TTL`]).
    pub async fn state_digest(&self) -> Result<StateDigest> {
        if let Some((sd, at)) = &*self.digest.read().await {
            if at.elapsed() < DIGEST_TTL {
                return Ok(sd.clone());
            }
        }
        let data = self
            .get_json(&format!("{}/xid/v1/state_digest", self.rpc_url))
            .await?;
        let sd = StateDigest {
            digest: str_field(&data, "digest")?.to_string(),
            height: num_field(&data, "height"),
            num_names: num_field(&data, "num_names"),
        };
        *self.digest.write().await = Some((sd.clone(), Instant::now()));
        Ok(sd)
    }

    /// Whether `digest` has been finalized by 2/3+ validators. Verified mode
    /// requires pinned signatures and a durable checkpoint. Legacy mode caches
    /// the RPC boolean for [`ATTESTATION_TTL`].
    pub async fn is_finalized(&self, digest: &str) -> Result<bool> {
        if crate::verify_finality_enabled() {
            return self
                .resolver
                .verify_signed_digest(digest)
                .await
                .map(|_| true);
        }
        if let Some((f, at)) = self.finalized.read().await.get(digest) {
            if at.elapsed() < ATTESTATION_TTL && !crate::verify_finality_enabled() {
                return Ok(*f);
            }
        }
        let data = self
            .get_json(&format!("{}/xid/v1/attestations?digest={digest}", self.rpc_url))
            .await?;
        let finalized = data
            .get("finalized")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        // Enabling verification while the legacy request was in flight must not
        // let this caller publish or consume an RPC boolean after the policy
        // transition. Re-run through the signed path instead.
        if crate::verify_finality_enabled() {
            return self
                .resolver
                .verify_signed_digest(digest)
                .await
                .map(|_| true);
        }
        self.finalized
            .write()
            .await
            .insert(digest.to_string(), (finalized, Instant::now()));
        Ok(finalized)
    }

    /// Verify chain-attested content: its `state_digest` must equal the chain's
    /// current digest, and that digest must be finalized. Fails closed.
    pub async fn verify_digest(&self, content_state_digest: &str) -> Result<StateDigest> {
        if content_state_digest.is_empty() {
            return Err(ChainError::Malformed("content missing state_digest".into()));
        }
        let mut chain = self.state_digest().await?;
        if content_state_digest != chain.digest {
            return Err(ChainError::DigestMismatch);
        }
        if crate::verify_finality_enabled() {
            // The height from `/state_digest` is informational until validator
            // signatures bind it. Return the signed bundle height to callers.
            chain.height = self.resolver.verify_signed_digest(&chain.digest).await?;
            return Ok(chain);
        }
        if !self.is_finalized(&chain.digest).await? {
            return Err(ChainError::NotFinalized);
        }
        Ok(chain)
    }

    /// Resolve a name from the chain. Verified mode requires a proof-bound leaf
    /// plus pinned-validator finality. Legacy mode retains the unproved
    /// `/resolve` behavior and caches it against the current digest.
    pub async fn resolve_name(&self, tld: &str, name: &str) -> Result<Option<Value>> {
        if crate::verify_finality_enabled() {
            return self.resolve_name_verified(tld, name).await;
        }
        let current = self
            .state_digest()
            .await
            .map(|d| d.digest)
            .unwrap_or_default();
        let key = (tld.to_string(), name.to_string());
        if let Some((record, seen)) = self.names.read().await.get(&key) {
            if *seen == current && !crate::verify_finality_enabled() {
                return Ok(record.clone());
            }
        }
        let data = self
            .get_json(&format!("{}/xid/v1/resolve/{tld}/{name}", self.rpc_url))
            .await?;
        let record = data.get("record").filter(|r| !r.is_null()).cloned();
        // As with finality booleans, a policy transition during the request
        // invalidates this unproved response. Resolve again with inclusion and
        // signed-finality verification rather than caching legacy data.
        if crate::verify_finality_enabled() {
            return self.resolve_name_verified(tld, name).await;
        }
        self.names
            .write()
            .await
            .insert(key, (record.clone(), current));
        Ok(record)
    }

    /// Verified-mode name resolution must return only data reconstructed from
    /// the leaf preimage proven by [`crate::XidResolver`]. The legacy endpoint's
    /// record is never fetched or mixed with the verified snapshot.
    async fn resolve_name_verified(&self, tld: &str, name: &str) -> Result<Option<Value>> {
        match self.resolver.resolve_fresh(name, tld).await {
            Ok(snapshot) => Ok(Some(proof_bound_name_record(&snapshot))),
            Err(ChainError::NotFound(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn get_json(&self, url: &str) -> Result<Value> {
        // Refuse to egress over clearnet before Tor is ready in Always mode.
        crate::chain_egress_ok()?;
        self.client()
            .await?
            .get(url)
            .send()
            .await
            .map_err(|e| ChainError::Rpc(e.to_string()))?
            .json::<Value>()
            .await
            .map_err(|e| ChainError::Rpc(e.to_string()))
    }
}

/// Reconstruct the proof-bound subset of the legacy `NameRecord` JSON schema.
/// Profile, DNS, identity, and content-root data live outside `record` in the
/// chain API, so returning them here would change this method's public shape.
/// `registered_at` is part of `NameRecord`, but not the signed leaf preimage, so
/// verified mode must omit it instead of copying an unauthenticated RPC value.
fn proof_bound_name_record(snapshot: &crate::DomainSnapshot) -> Value {
    serde_json::json!({
        "name": snapshot.name,
        "tld": snapshot.tld,
        "owner": snapshot.owner,
    })
}

fn str_field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| ChainError::Malformed(format!("missing `{key}`")))
}

/// Parse a u64 that the chain may encode as a JSON number or a string.
fn num_field(v: &Value, key: &str) -> u64 {
    v.get(key)
        .map(|f| f.as_u64().or_else(|| f.as_str().and_then(|s| s.parse().ok())).unwrap_or(0))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use sha2::{Digest as _, Sha256};
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    const CHAIN: &str = "epix_1917-1";
    const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    struct FinalityGlobals {
        verify: bool,
        pinned: Option<crate::PinnedSet>,
    }

    impl FinalityGlobals {
        fn install(verify: bool, pinned: Option<crate::PinnedSet>) -> Self {
            let old = Self {
                verify: crate::verify_finality_enabled(),
                pinned: crate::pinned_validators(),
            };
            crate::set_verify_finality(false);
            crate::checkpoint::reset_for_test();
            crate::set_pinned_validators(pinned);
            crate::set_verify_finality(verify);
            old
        }
    }

    impl Drop for FinalityGlobals {
        fn drop(&mut self) {
            crate::set_verify_finality(false);
            crate::checkpoint::reset_for_test();
            crate::set_pinned_validators(self.pinned.take());
            crate::set_verify_finality(self.verify);
        }
    }

    struct MockServer {
        url: String,
        worker: std::thread::JoinHandle<Vec<String>>,
    }

    impl MockServer {
        fn spawn(
            expected_requests: usize,
            response: impl Fn(&str) -> Value + Send + 'static,
        ) -> Self {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let worker = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut paths = Vec::new();
                while paths.len() < expected_requests && Instant::now() < deadline {
                    let (mut stream, _) = match listener.accept() {
                        Ok(accepted) => accepted,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(error) => panic!("mock server accept failed: {error}"),
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 2048];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        let read = stream.read(&mut chunk).unwrap();
                        if read == 0 {
                            break;
                        }
                        request.extend_from_slice(&chunk[..read]);
                    }
                    let request = String::from_utf8(request).unwrap();
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap()
                        .to_string();
                    let body = serde_json::to_vec(&response(&path)).unwrap();
                    paths.push(path);
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .unwrap();
                    stream.write_all(&body).unwrap();
                }
                paths
            });
            Self { url, worker }
        }

        fn finish(self) -> Vec<String> {
            self.worker.join().unwrap()
        }
    }

    fn pinned_set(key: &SigningKey, now: i64) -> crate::PinnedSet {
        crate::PinnedSet::new(
            std::collections::HashMap::from([(
                "epixvalcons1test".to_string(),
                crate::PinnedValidator {
                    pubkey: key.verifying_key().to_bytes(),
                    voting_power: 1,
                },
            )]),
            CHAIN,
            now,
            1,
        )
        .unwrap()
    }

    fn put_uvarint(mut value: u64, output: &mut Vec<u8>) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            output.push(byte);
            if value == 0 {
                return;
            }
        }
    }

    fn signed_attestations(key: &SigningKey, digest: &str, height: u64, block_time: i64) -> Value {
        let mut extension = vec![0x08];
        put_uvarint(height, &mut extension);
        extension.push(0x10);
        put_uvarint(block_time as u64, &mut extension);
        extension.push(0x1a);
        put_uvarint(digest.len() as u64, &mut extension);
        extension.extend_from_slice(digest.as_bytes());
        let sign_bytes = crate::canonical_vote_ext_bytes(&extension, height as i64, 0, CHAIN);
        let signature = key.sign(&sign_bytes);
        serde_json::json!({
            "height": height.to_string(),
            "block_time": block_time.to_string(),
            "finalized": false,
            "attestations": [{
                "validator_cons_addr": "epixvalcons1test",
                "signature": hex::encode(signature.to_bytes()),
                "vote_extension": base64::engine::general_purpose::STANDARD.encode(extension),
                "round": "0",
            }],
        })
    }

    async fn prepare_route() -> tokio::sync::MutexGuard<'static, ()> {
        let guard = crate::chain_route_test_guard().await;
        crate::set_chain_route(None, false);
        guard
    }

    #[tokio::test]
    async fn verified_digest_and_finality_reject_rpc_boolean_without_signatures() {
        let _finality_guard = crate::finality_state_test_guard().await;
        let _route_guard = prepare_route().await;
        let now = crate::now_unix();
        let key = SigningKey::from_bytes(&[7; 32]);
        let pin = pinned_set(&key, now);
        let _globals = FinalityGlobals::install(true, Some(pin.clone()));
        let dir = tempfile::tempdir().unwrap();
        crate::checkpoint::configure(dir.path().join("checkpoint.json"), &pin).unwrap();

        let server = MockServer::spawn(3, |path| {
            if path == "/xid/v1/state_digest" {
                serde_json::json!({ "digest": DIGEST, "height": 999, "num_names": 1 })
            } else {
                serde_json::json!({ "finalized": true })
            }
        });
        let attestation = ChainAttestation::new(&server.url);
        let result = attestation.verify_digest(DIGEST).await;
        let finalized = attestation.is_finalized(DIGEST).await;
        let paths = server.finish();

        assert!(matches!(result, Err(ChainError::Malformed(_))));
        assert!(matches!(finalized, Err(ChainError::Malformed(_))));
        assert_eq!(paths.len(), 3);
        assert!(paths[1].starts_with("/xid/v1/attestations?digest="));
        assert!(paths[2].starts_with("/xid/v1/attestations?digest="));
        assert!(!crate::finality_checkpoint_matches(1, DIGEST));
    }

    #[tokio::test]
    async fn verified_digest_uses_signed_height_and_durable_checkpoint() {
        let _finality_guard = crate::finality_state_test_guard().await;
        let _route_guard = prepare_route().await;
        let now = crate::now_unix();
        let height = 12;
        let key = SigningKey::from_bytes(&[8; 32]);
        let pin = pinned_set(&key, now);
        let signed = signed_attestations(&key, DIGEST, height, now);
        let _globals = FinalityGlobals::install(true, Some(pin.clone()));
        let dir = tempfile::tempdir().unwrap();
        crate::checkpoint::configure(dir.path().join("checkpoint.json"), &pin).unwrap();

        let server = MockServer::spawn(2, move |path| {
            if path == "/xid/v1/state_digest" {
                serde_json::json!({ "digest": DIGEST, "height": 999, "num_names": 1 })
            } else {
                signed.clone()
            }
        });
        let attestation = ChainAttestation::new(&server.url);
        let state = attestation.verify_digest(DIGEST).await;
        let finalized = attestation.is_finalized(DIGEST).await;
        let paths = server.finish();

        let state = state.unwrap();
        assert_eq!(state.height, height, "untrusted RPC height must not escape");
        assert!(matches!(finalized, Ok(true)));
        assert!(crate::finality_checkpoint_matches(height, DIGEST));
        assert_eq!(paths.len(), 2);
    }

    #[tokio::test]
    async fn legacy_digest_still_accepts_rpc_finalized_boolean() {
        let _finality_guard = crate::finality_state_test_guard().await;
        let _route_guard = prepare_route().await;
        let _globals = FinalityGlobals::install(false, None);
        let server = MockServer::spawn(2, |path| {
            if path == "/xid/v1/state_digest" {
                serde_json::json!({ "digest": DIGEST, "height": 999, "num_names": 1 })
            } else {
                serde_json::json!({ "finalized": true })
            }
        });
        let attestation = ChainAttestation::new(&server.url);
        let state = attestation.verify_digest(DIGEST).await;
        let paths = server.finish();

        assert_eq!(state.unwrap().height, 999);
        assert_eq!(paths.len(), 2);
    }

    #[tokio::test]
    async fn verified_name_preserves_name_record_shape_using_only_proof_bound_data() {
        let _finality_guard = crate::finality_state_test_guard().await;
        let _route_guard = prepare_route().await;
        let now = crate::now_unix();
        let height = 12;
        let key = SigningKey::from_bytes(&[9; 32]);
        let leaf = serde_json::to_vec(&serde_json::json!({
            "name": "talk",
            "tld": "epix",
            "owner": "epix1proven",
            "profile": {
                "avatar": "ipfs://avatar",
                "bio": "proof bound",
            },
            "dns": [{
                "record_type": 65280,
                "value": "epix1xite",
            }],
            "identities": [
                {
                    "address": "epix1active",
                    "label": "epixnet",
                    "active": true,
                },
                {
                    "address": "epix1revoked",
                    "label": "epixnet",
                    "revoked_at": 44,
                    "revoked_at_time": 55,
                }
            ],
            "content_root": "deadbeef",
        }))
        .unwrap();
        let digest = hex::encode(Sha256::digest(&leaf));
        let pin = pinned_set(&key, now);
        let signed = signed_attestations(&key, &digest, height, now);
        let proof_digest = digest.clone();
        let proof_leaf = hex::encode(&leaf);
        let _globals = FinalityGlobals::install(true, Some(pin.clone()));
        let dir = tempfile::tempdir().unwrap();
        crate::checkpoint::configure(dir.path().join("checkpoint.json"), &pin).unwrap();

        let server = MockServer::spawn(2, move |path| {
            if path == "/xid/v1/resolve_with_proof/epix/talk" {
                serde_json::json!({
                    "proof": {
                        "leaf_hash": proof_digest,
                        "leaf_index": 0,
                        "root": proof_digest,
                        "siblings": [],
                    },
                    "leaf_preimage": proof_leaf,
                    "domain": { "record": { "owner": "epix1forged" } },
                })
            } else if path.starts_with("/xid/v1/attestations?digest=") {
                signed.clone()
            } else if path == "/xid/v1/state_digest" {
                serde_json::json!({ "digest": proof_digest, "height": 999 })
            } else {
                serde_json::json!({ "record": { "owner": "epix1forged" } })
            }
        });
        let attestation = ChainAttestation::new(&server.url);
        let record = attestation.resolve_name("epix", "talk").await;
        let paths = server.finish();

        let record = record.unwrap().unwrap();
        assert_eq!(
            record,
            serde_json::json!({
                "name": "talk",
                "tld": "epix",
                "owner": "epix1proven",
            })
        );
        assert!(record.get("registered_at").is_none());
        assert!(record.get("profile").is_none());
        assert!(record.get("dns").is_none());
        assert!(record.get("identities").is_none());
        assert!(record.get("content_root").is_none());
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], "/xid/v1/resolve_with_proof/epix/talk");
        assert!(paths.iter().all(|path| path != "/xid/v1/resolve/epix/talk"));
    }

    #[tokio::test]
    async fn legacy_name_keeps_raw_resolve_behavior() {
        let _finality_guard = crate::finality_state_test_guard().await;
        let _route_guard = prepare_route().await;
        let _globals = FinalityGlobals::install(false, None);
        let server = MockServer::spawn(2, |path| {
            if path == "/xid/v1/state_digest" {
                serde_json::json!({ "digest": DIGEST, "height": 1 })
            } else {
                serde_json::json!({ "record": { "owner": "epix1legacy", "custom": 7 } })
            }
        });
        let attestation = ChainAttestation::new(&server.url);
        let record = attestation.resolve_name("epix", "talk").await;
        let paths = server.finish();

        let record = record.unwrap().unwrap();
        assert_eq!(record["owner"], "epix1legacy");
        assert_eq!(record["custom"], 7);
        assert_eq!(
            paths,
            vec![
                "/xid/v1/state_digest".to_string(),
                "/xid/v1/resolve/epix/talk".to_string(),
            ]
        );
    }
}
