//! `XidResolver` - chain-verified `.epix` name resolution.

use crate::merkle::verify_proof;
use crate::types::{DnsRecord, DomainSnapshot, Identity};
use crate::{ChainError, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub const DEFAULT_RPC_URL: &str = "https://api.epix.zone";
type SnapshotCacheEntry = (DomainSnapshot, Instant, Option<(u64, String)>);
type SnapshotCache = HashMap<String, SnapshotCacheEntry>;

/// Resolves `.epix` names against the Epix chain, verifying every answer with a
/// Merkle proof against a finalized state digest.
pub struct XidResolver {
    /// The HTTP client plus the SOCKS generation it was built for. Rebuilt when
    /// the proxy setting changes, so a client built direct before Tor came up
    /// (Always mode) does not keep sending over clearnet afterwards.
    client: RwLock<Option<(u64, reqwest::Client)>>,
    /// Endpoint fallbacks, in preference order. Every request starts at
    /// `preferred` and rotates to the next on failure (see
    /// [`crate::rotate_endpoints`]).
    rpc_urls: Vec<String>,
    preferred: std::sync::atomic::AtomicUsize,
    /// Re-read the node-configured endpoint list per request instead of
    /// `rpc_urls` (the shared resolver: it may be built before config loads,
    /// and a Config change must apply without a rebuild).
    follow_configured: bool,
    /// Cached snapshot plus the accepted finality height it came from. A newer
    /// checkpoint invalidates older snapshots immediately, independent of TTL.
    /// `Some((height, digest))` exists only for pinned-validator verification.
    /// Legacy cache entries use `None`, so enabling finality at height zero can
    /// never reinterpret an old legacy snapshot as cryptographically verified.
    cache: RwLock<SnapshotCache>,
    ttl: Duration,
    /// The last digest confirmed finalized, cached briefly. Every resolve
    /// checks its proof against the current attested + finalized digest; that
    /// digest is global chain state, identical for every name resolved in the
    /// same moment. Caching it turns a burst of N resolves from 3N HTTP calls
    /// (proof + digest + attestations, each) into N + 2.
    /// `(digest, cached_at, verified_height)`. `Some(height)` records a digest
    /// proven by pinned-validator signatures and durably checkpointed. `None`
    /// records a legacy RPC boolean result. The cryptographic fast path also
    /// confirms that the tuple still matches the process-wide checkpoint.
    digest: RwLock<Option<(String, Instant, Option<u64>)>>,
}

/// How long a confirmed-finalized digest is reused. Short: the digest advances
/// each block, so a proof for a just-changed name must still be verifiable, but
/// long enough that one burst of resolves shares a single digest fetch.
const DIGEST_TTL: Duration = Duration::from_secs(3);

#[derive(Clone, Debug)]
struct FinalityBinding {
    digest: String,
    /// `Some` only when pinned-validator signatures were verified and the exact
    /// height and digest were durably checkpointed.
    height: Option<u64>,
}

impl XidResolver {
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self::new_multi(vec![rpc_url.into()])
    }

    /// A resolver with endpoint FALLBACKS: requests start at the preferred
    /// (initially first) URL and rotate to the next on failure, remembering
    /// whichever answered.
    pub fn new_multi(rpc_urls: Vec<String>) -> Self {
        let client = crate::http_client(Duration::from_secs(15)).ok();
        let rpc_urls: Vec<String> = rpc_urls
            .into_iter()
            .map(|url| url.trim().trim_end_matches('/').to_string())
            .filter(|url| !url.is_empty())
            .collect();
        Self {
            client: RwLock::new(client),
            rpc_urls,
            preferred: std::sync::atomic::AtomicUsize::new(0),
            follow_configured: false,
            cache: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(30 * 60),
            digest: RwLock::new(None),
        }
    }

    /// Follow the node-configured endpoint list live (see the field note).
    pub(crate) fn following_configured_endpoints(mut self) -> Self {
        self.follow_configured = true;
        self
    }

    /// The endpoints this request should try, in order of preference.
    fn endpoints(&self) -> Vec<String> {
        if self.follow_configured {
            let configured = crate::configured_chain_rpc_urls();
            if !configured.is_empty() {
                return configured;
            }
        }
        self.rpc_urls.clone()
    }

    /// The endpoint most recently confirmed working (or the most preferred
    /// one before any traffic has flowed). What a xite asking for "the"
    /// chain RPC should be handed.
    pub fn preferred_endpoint(&self) -> String {
        let endpoints = self.endpoints();
        if endpoints.is_empty() {
            return crate::DEFAULT_RPC_URL.to_string();
        }
        let index = self.preferred.load(std::sync::atomic::Ordering::Relaxed) % endpoints.len();
        endpoints[index].clone()
    }

    /// The HTTP client for the current SOCKS setting, rebuilding it if the proxy
    /// changed since it was last built.
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

    /// Override the positive-cache TTL (default 30 minutes).
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Drop every cached snapshot (and the finalized-digest memo), so the next
    /// resolve of any name fetches and re-verifies from the chain.
    pub async fn clear(&self) {
        self.cache.write().await.clear();
        *self.digest.write().await = None;
    }

    /// Resolve `name.tld`, returning a **chain-verified** snapshot.
    ///
    /// Pipeline: fetch the record + Merkle proof, recompute the root, require it
    /// to equal the current attested state digest, and require that digest to be
    /// finalized by validators. Any failure is an error (fail closed).
    pub async fn resolve(&self, name: &str, tld: &str) -> Result<DomainSnapshot> {
        self.resolve_inner(name, tld, true)
            .await
            .map(|(snapshot, _)| snapshot)
    }

    /// Resolve without reusing a cached domain snapshot. Security-sensitive
    /// revocation checks use this path so the general 30-minute profile cache
    /// cannot extend a revoked identity's authorization.
    pub async fn resolve_fresh(&self, name: &str, tld: &str) -> Result<DomainSnapshot> {
        self.resolve_inner(name, tld, false)
            .await
            .map(|(snapshot, _)| snapshot)
    }

    /// Fresh security-sensitive resolution together with its exact finality
    /// height and digest binding. Derived authorization caches use this instead
    /// of sampling global state after the fact. Legacy mode returns `None`.
    pub async fn resolve_fresh_bound(
        &self,
        name: &str,
        tld: &str,
    ) -> Result<(DomainSnapshot, Option<(u64, String)>)> {
        self.resolve_inner(name, tld, false).await
    }

    async fn resolve_inner(
        &self,
        name: &str,
        tld: &str,
        use_snapshot_cache: bool,
    ) -> Result<(DomainSnapshot, Option<(u64, String)>)> {
        // A concurrent resolution can advance the checkpoint between our RPC
        // fetch and snapshot publication. Retry once against the newer state
        // instead of returning or caching the now-stale snapshot.
        for _ in 0..2 {
            match self.resolve_once(name, tld, use_snapshot_cache).await {
                Err(ChainError::FinalityAdvanced) => continue,
                result => return result,
            }
        }
        Err(ChainError::FinalityUnverified(
            "xID finality advanced repeatedly while publishing the resolved snapshot".into(),
        ))
    }

    async fn resolve_once(
        &self,
        name: &str,
        tld: &str,
        use_snapshot_cache: bool,
    ) -> Result<(DomainSnapshot, Option<(u64, String)>)> {
        let key = format!("{name}.{tld}");
        if let Some(cached) = self.cached_snapshot(&key, use_snapshot_cache).await {
            return Ok(cached);
        }

        let data = self
            .get_json(&format!("/xid/v1/resolve_with_proof/{tld}/{name}"))
            .await?;

        // An unregistered name comes back as a gRPC-gateway error body (no proof
        // and no domain). Report it as NotFound — a definite, negatively-cacheable
        // answer — rather than Malformed, which reads as a transient chain fault
        // (re-hit every lookup) and blurs "name available" with "chain broken".
        if data.get("proof").is_none() && data.get("domain").is_none() {
            let code = data.get("code").and_then(|v| v.as_i64());
            let msg = data.get("message").and_then(|v| v.as_str()).unwrap_or("");
            if code == Some(5) || msg.to_lowercase().contains("not found") {
                return Err(ChainError::NotFound(key.clone()));
            }
        }

        let proof = data
            .get("proof")
            .ok_or_else(|| ChainError::Malformed("missing proof".into()))?;

        let leaf_hash = str_field(proof, "leaf_hash")?;
        let leaf_index = u64_field(proof, "leaf_index").unwrap_or(0);
        let proof_root = proof
            .get("root")
            .and_then(|v| v.as_str())
            .or_else(|| data.get("root").and_then(|v| v.as_str()))
            .ok_or_else(|| ChainError::Malformed("missing proof root".into()))?;
        let siblings: Vec<String> = proof
            .get("siblings")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let verify = crate::verify_finality_enabled();

        // Step 1 - LEAF BINDING. The Merkle proof only proves *a* leaf is in the
        // tree; the returned data must actually BE that leaf. The chain serves the
        // canonical `leaf_preimage` (hex); we hash it (== leaf_hash), bind the name,
        // and parse the snapshot FROM it. When verification is on, the preimage is
        // REQUIRED (an RPC can't downgrade by omitting it). Pre-upgrade chains omit
        // it, so with verification off we fall back to the (unbound) domain payload.
        let leaf_preimage: Option<Vec<u8>> = data
            .get("leaf_preimage")
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s.trim()).ok());
        let snapshot = match &leaf_preimage {
            Some(pre) => crate::verify_and_parse_leaf(pre, leaf_hash, name, tld)?,
            None if verify => {
                return Err(ChainError::LeafBindingFailed(
                    "leaf_preimage required when finality verification is enabled".into(),
                ))
            }
            None => {
                let domain = data
                    .get("domain")
                    .filter(|d| !d.is_null())
                    .ok_or_else(|| ChainError::NotFound(key.clone()))?;
                parse_domain(name, tld, domain)?
            }
        };

        // Step 2 - Merkle inclusion proof over the (now name-bound) leaf.
        if !verify_proof(leaf_hash, leaf_index, &siblings, proof_root)? {
            return Err(ChainError::MerkleInvalid);
        }

        // Step 3 - the proof root must be a state digest validators finalized.
        let binding = self.finality_binding(proof_root, verify).await?;

        let binding = self
            .publish_snapshot(key, snapshot.clone(), &binding)
            .await?;
        Ok((snapshot, binding))
    }

    async fn cached_snapshot(
        &self,
        key: &str,
        use_snapshot_cache: bool,
    ) -> Option<(DomainSnapshot, Option<(u64, String)>)> {
        if !use_snapshot_cache {
            return None;
        }
        let cache = self.cache.read().await;
        let (snapshot, cached_at, binding) = cache.get(key)?;
        let checkpoint_current =
            snapshot_binding_current(binding.as_ref(), crate::verify_finality_enabled());
        (cached_at.elapsed() < self.ttl && checkpoint_current)
            .then(|| (snapshot.clone(), binding.clone()))
    }

    async fn finality_binding(&self, proof_root: &str, verify: bool) -> Result<FinalityBinding> {
        if verify {
            // Cryptographic: verify signed validator power over `proof_root`
            // against the pinned set (no trust in any RPC boolean).
            return self.verify_finality_gated(proof_root).await;
        }

        // Legacy: the digest is confirmed finalized via the RPC boolean,
        // cached briefly (global chain state). A proof that doesn't match the
        // cached digest forces a fresh fetch before we reject it.
        match self.digest_matches(proof_root, false).await? {
            Some(binding) => Ok(binding),
            None => self
                .digest_matches(proof_root, true)
                .await?
                .ok_or(ChainError::DigestMismatch),
        }
    }

    async fn publish_snapshot(
        &self,
        key: String,
        snapshot: DomainSnapshot,
        binding: &FinalityBinding,
    ) -> Result<Option<(u64, String)>> {
        let mut cache = self.cache.write().await;
        if let Some(height) = binding.height {
            if !crate::xid_verified_binding_current(height, &binding.digest) {
                return Err(ChainError::FinalityAdvanced);
            }
        }
        // Store the height and digest that verified THIS snapshot. Reading newer
        // global state here would mislabel a lower snapshot during a race.
        let stored_binding = binding
            .height
            .map(|height| (height, binding.digest.clone()));
        cache.insert(key, (snapshot, Instant::now(), stored_binding.clone()));
        Ok(stored_binding)
    }

    /// Cryptographically verify that `digest` was signed by the required share of
    /// PINNED validator voting power (replaces the RPC `finalized` boolean). The
    /// last verified digest is memoized for [`DIGEST_TTL`] since it is global chain
    /// state. Fails closed if no pin is installed.
    async fn verify_finality_gated(&self, digest: &str) -> Result<FinalityBinding> {
        if let Some((d, at, Some(height))) = self.digest.read().await.as_ref() {
            // Only reuse a memo that is still the durable process-wide
            // checkpoint. This prevents a lower-height result from being
            // republished by a concurrent request after a higher result wins.
            if d == digest
                && at.elapsed() < DIGEST_TTL
                && crate::xid_verified_binding_current(*height, d)
            {
                return Ok(FinalityBinding {
                    digest: d.clone(),
                    height: Some(*height),
                });
            }
        }
        let pinned = crate::pinned_validators()
            .ok_or_else(|| ChainError::FinalityUnverified("no pinned validator set installed".into()))?;
        let att = self
            .get_json(&format!("/xid/v1/attestations?digest={digest}"))
            .await?;
        let bundle = crate::parse_bundle(digest, &att)
            .ok_or_else(|| ChainError::Malformed("attestation bundle malformed".into()))?;
        let height = crate::checkpoint::verify_and_commit(&bundle, &pinned, crate::now_unix())
            .map_err(ChainError::FinalityUnverified)?;
        // A higher concurrent result may have advanced the global checkpoint
        // after our commit. Never publish this memo unless it remains current.
        if !crate::xid_verified_binding_current(height, digest) {
            return Err(ChainError::FinalityAdvanced);
        }
        *self.digest.write().await = Some((digest.to_string(), Instant::now(), Some(height)));
        Ok(FinalityBinding {
            digest: digest.to_string(),
            height: Some(height),
        })
    }

    /// Verify and durably checkpoint one digest through the same pinned-
    /// validator path used by proof-bound name resolution.
    pub(crate) async fn verify_signed_digest(&self, digest: &str) -> Result<u64> {
        self.verify_finality_gated(digest)
            .await?
            .height
            .ok_or_else(|| {
                ChainError::FinalityUnverified(
                    "signed finality verification returned no checkpoint height".into(),
                )
            })
    }

    /// Whether `proof_root` equals the current attested + finalized state
    /// digest. `force_fresh` bypasses the short-lived digest cache and fetches
    /// (and re-verifies finalization of) a fresh digest.
    async fn digest_matches(
        &self,
        proof_root: &str,
        force_fresh: bool,
    ) -> Result<Option<FinalityBinding>> {
        if !force_fresh {
            if let Some((digest, at, height)) = self.digest.read().await.as_ref() {
                // The legacy path needs only RPC-level trust, so either memo kind
                // (crypto- or RPC-verified) is acceptable here.
                if at.elapsed() < DIGEST_TTL {
                    return Ok((digest == proof_root).then(|| FinalityBinding {
                        digest: digest.clone(),
                        height: *height,
                    }));
                }
            }
        }
        // Fetch the current digest and confirm validators finalized it.
        let digest_info =
            self.get_json("/xid/v1/state_digest").await?;
        let attested = str_field(&digest_info, "digest")?.to_string();
        let att = self
            .get_json(&format!("/xid/v1/attestations?digest={attested}"))
            .await?;
        if !att.get("finalized").and_then(|v| v.as_bool()).unwrap_or(false) {
            return Err(ChainError::NotFinalized);
        }
        let matches = attested == proof_root;
        *self.digest.write().await = Some((attested.clone(), Instant::now(), None));
        Ok(matches.then_some(FinalityBinding {
            digest: attested,
            height: None,
        }))
    }

    /// GET `path` (endpoint-relative, starting with `/`) as JSON, rotating
    /// across the configured endpoints on failure.
    async fn get_json(&self, path: &str) -> Result<Value> {
        // Refuse to egress over clearnet before Tor is ready in Always mode.
        // Checked ONCE, outside the rotation: this failure is local policy,
        // not an endpoint's fault, so trying the others would be noise.
        crate::chain_egress_ok()?;
        let client = self.client().await?;
        crate::rotate_endpoints(&self.endpoints(), &self.preferred, |base| {
            let client = client.clone();
            let url = format!("{base}{path}");
            async move {
                client
                    .get(url)
                    .send()
                    .await
                    .map_err(|e| ChainError::Rpc(e.to_string()))?
                    .json::<Value>()
                    .await
                    .map_err(|e| ChainError::Rpc(e.to_string()))
            }
        })
        .await
    }
}

fn snapshot_binding_current(binding: Option<&(u64, String)>, verification_enabled: bool) -> bool {
    crate::xid_cache_binding_current(binding, verification_enabled)
}

fn parse_domain(name: &str, tld: &str, domain: &Value) -> Result<DomainSnapshot> {
    let record = domain.get("record");
    let owner = record
        .and_then(|r| r.get("owner"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let content_root = domain
        .get("content_root")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let identities = domain
        .get("identities")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|id| {
                    Some(Identity {
                        address: id.get("address")?.as_str()?.to_string(),
                        label: id.get("label").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        active: id.get("active").and_then(|v| v.as_bool()).unwrap_or(false),
                        revoked_at: id.get("revoked_at").and_then(u64_value).unwrap_or(0),
                        revoked_at_time: id
                            .get("revoked_at_time")
                            .and_then(u64_value)
                            .unwrap_or(0),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let dns_records = domain
        .get("dns_records")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    Some(DnsRecord {
                        record_type: r.get("record_type").and_then(as_u32)?,
                        value: r.get("value")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let profile = domain.get("profile");
    let avatar = profile
        .and_then(|p| p.get("avatar"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let bio = profile
        .and_then(|p| p.get("bio"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(DomainSnapshot {
        name: name.to_string(),
        tld: tld.to_string(),
        owner,
        content_root,
        identities,
        dns_records,
        avatar,
        bio,
    })
}

fn u64_value(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

fn as_u32(v: &Value) -> Option<u32> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .map(|n| n as u32)
}

fn str_field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| ChainError::Malformed(format!("missing `{key}`")))
}

fn u64_field(v: &Value, key: &str) -> Option<u64> {
    let f = v.get(key)?;
    f.as_u64().or_else(|| f.as_str().and_then(|s| s.parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const CHAIN: &str = "epix_1917-1";
    const D1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const D2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn snapshot() -> DomainSnapshot {
        DomainSnapshot {
            name: "alice".into(),
            tld: "epix".into(),
            owner: "epix1alice".into(),
            content_root: String::new(),
            identities: Vec::new(),
            dns_records: Vec::new(),
            avatar: String::new(),
            bio: String::new(),
        }
    }

    fn pinned_set() -> crate::finality::PinnedSet {
        let validators = std::collections::HashMap::from([(
            "epixvalcons1test".to_string(),
            crate::finality::PinnedValidator {
                pubkey: [1; 32],
                voting_power: 1,
            },
        )]);
        crate::finality::PinnedSet::new(validators, CHAIN, 1, 1).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_higher_checkpoint_never_relabels_lower_snapshot() {
        let _finality_guard = crate::finality_state_test_guard().await;
        crate::checkpoint::reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        crate::checkpoint::configure(dir.path().join("checkpoint.json"), &pinned_set()).unwrap();
        crate::checkpoint::record_for_test(100, D1).unwrap();

        let resolver = Arc::new(XidResolver::new("http://127.0.0.1:1"));
        let barrier = Arc::new(tokio::sync::Barrier::new(2));

        // The lower request has already verified height 100. Race its cache
        // publication against a second resolver accepting height 200.
        let lower = {
            let resolver = Arc::clone(&resolver);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                resolver
                    .publish_snapshot(
                        "alice.epix".into(),
                        snapshot(),
                        &FinalityBinding {
                            digest: D1.into(),
                            height: Some(100),
                        },
                    )
                    .await
            })
        };
        let higher = {
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                crate::checkpoint::record_for_test(200, D2).unwrap();
            })
        };
        higher.await.unwrap();
        let lower_result = lower.await.unwrap();
        assert_eq!(crate::xid_max_height(), 200);

        let cache = resolver.cache.read().await;
        match cache.get("alice.epix") {
            Some((_, _, Some((height, digest)))) => {
                // Publication linearized first. It retains its exact binding and
                // is already invalid against the newer global checkpoint.
                assert!(lower_result.is_ok());
                assert_eq!(*height, 100);
                assert_eq!(digest, D1);
                assert_ne!(*height, crate::xid_max_height());
            }
            Some((_, _, None)) => panic!("verified snapshot was stored as a legacy entry"),
            None => {
                // The higher checkpoint linearized first, so publication failed
                // and resolve_inner would retry the RPC fetch.
                assert!(matches!(lower_result, Err(ChainError::FinalityAdvanced)));
            }
        }
        drop(cache);
        crate::checkpoint::reset_for_test();
    }

    #[test]
    fn legacy_snapshot_never_becomes_verified_at_height_zero() {
        assert!(snapshot_binding_current(None, false));
        assert!(!snapshot_binding_current(None, true));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn proxy_publication_cannot_pair_new_route_with_cached_direct_generation() {
        let _route_guard = crate::chain_route_test_guard().await;
        crate::set_chain_require_tor(false);
        crate::set_chain_socks(None);
        let resolver = Arc::new(XidResolver::new("http://127.0.0.1:1"));
        let direct_generation = resolver.client.read().await.as_ref().unwrap().0;

        crate::set_chain_require_tor(true);
        let (setter_entered_tx, setter_entered_rx) = std::sync::mpsc::channel();
        let release_setter = Arc::new(std::sync::Barrier::new(2));
        let setter_release = Arc::clone(&release_setter);
        let setter = std::thread::spawn(move || {
            crate::set_chain_socks_with_hook(Some("socks5h://127.0.0.1:43111".into()), || {
                setter_entered_tx.send(()).unwrap();
                setter_release.wait();
            });
        });
        setter_entered_rx.recv().unwrap();

        let (getter_entered_tx, getter_entered_rx) = std::sync::mpsc::channel();
        let getter_resolver = Arc::clone(&resolver);
        let getter = tokio::spawn(async move {
            getter_entered_tx.send(()).unwrap();
            getter_resolver.client().await
        });
        getter_entered_rx.recv().unwrap();
        assert!(
            crate::chain_route().try_read().is_err(),
            "route readers must block while proxy and generation publish together"
        );
        release_setter.wait();
        setter.join().unwrap();
        getter.await.unwrap().unwrap();

        let current_generation = crate::socks_generation();
        let cached_generation = resolver.client.read().await.as_ref().unwrap().0;
        assert_ne!(current_generation, direct_generation);
        assert_eq!(cached_generation, current_generation);
        assert_eq!(
            crate::chain_socks().as_deref(),
            Some("socks5h://127.0.0.1:43111")
        );

        crate::set_chain_socks(None);
        crate::set_chain_require_tor(false);
    }
}
