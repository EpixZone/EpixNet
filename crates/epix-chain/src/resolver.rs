//! `XidResolver` - chain-verified `.epix` name resolution.

use crate::merkle::verify_proof;
use crate::types::{DnsRecord, DomainSnapshot, Identity};
use crate::{ChainError, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub const DEFAULT_RPC_URL: &str = "https://api.epix.zone";

/// Resolves `.epix` names against the Epix chain, verifying every answer with a
/// Merkle proof against a finalized state digest.
pub struct XidResolver {
    /// The HTTP client plus the SOCKS generation it was built for. Rebuilt when
    /// the proxy setting changes, so a client built direct before Tor came up
    /// (Always mode) does not keep sending over clearnet afterwards.
    client: RwLock<(u64, reqwest::Client)>,
    rpc_url: String,
    cache: RwLock<HashMap<String, (DomainSnapshot, Instant)>>,
    ttl: Duration,
    /// The last digest confirmed finalized, cached briefly. Every resolve
    /// checks its proof against the current attested + finalized digest; that
    /// digest is global chain state, identical for every name resolved in the
    /// same moment. Caching it turns a burst of N resolves from 3N HTTP calls
    /// (proof + digest + attestations, each) into N + 2.
    /// `(digest, cached_at, crypto_verified)`. `crypto_verified` records whether
    /// this digest was proven by pinned-validator signatures (true) or only by the
    /// RPC's `finalized` boolean (false), so the cryptographic path never reuses a
    /// digest the legacy path merely RPC-trusted.
    digest: RwLock<Option<(String, Instant, bool)>>,
}

/// How long a confirmed-finalized digest is reused. Short: the digest advances
/// each block, so a proof for a just-changed name must still be verifiable, but
/// long enough that one burst of resolves shares a single digest fetch.
const DIGEST_TTL: Duration = Duration::from_secs(3);

impl XidResolver {
    pub fn new(rpc_url: impl Into<String>) -> Self {
        let gen = crate::socks_generation();
        let client = crate::http_client(Duration::from_secs(15));
        Self {
            client: RwLock::new((gen, client)),
            rpc_url: rpc_url.into().trim_end_matches('/').to_string(),
            cache: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(30 * 60),
            digest: RwLock::new(None),
        }
    }

    /// The HTTP client for the current SOCKS setting, rebuilding it if the proxy
    /// changed since it was last built.
    async fn client(&self) -> reqwest::Client {
        let gen = crate::socks_generation();
        {
            let cur = self.client.read().await;
            if cur.0 == gen {
                return cur.1.clone();
            }
        }
        let client = crate::http_client(Duration::from_secs(15));
        *self.client.write().await = (gen, client.clone());
        client
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
        let key = format!("{name}.{tld}");
        if let Some((snap, at)) = self.cache.read().await.get(&key) {
            if at.elapsed() < self.ttl {
                return Ok(snap.clone());
            }
        }

        let data = self
            .get_json(&format!("{}/xid/v1/resolve_with_proof/{tld}/{name}", self.rpc_url))
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
        if verify {
            // Cryptographic: verify signed validator power over `proof_root`
            // against the pinned set (no trust in any RPC boolean).
            self.verify_finality_gated(proof_root).await?;
        } else {
            // Legacy: the digest is confirmed finalized via the RPC boolean,
            // cached briefly (global chain state). A proof that doesn't match the
            // cached digest forces a fresh fetch before we reject it.
            if !self.digest_matches(proof_root, false).await?
                && !self.digest_matches(proof_root, true).await?
            {
                return Err(ChainError::DigestMismatch);
            }
        }

        self.cache
            .write()
            .await
            .insert(key, (snapshot.clone(), Instant::now()));
        Ok(snapshot)
    }

    /// Cryptographically verify that `digest` was signed by the required share of
    /// PINNED validator voting power (replaces the RPC `finalized` boolean). The
    /// last verified digest is memoized for [`DIGEST_TTL`] since it is global chain
    /// state. Fails closed if no pin is installed.
    async fn verify_finality_gated(&self, digest: &str) -> Result<()> {
        if let Some((d, at, crypto_verified)) = self.digest.read().await.as_ref() {
            // Only reuse a memo that was CRYPTOGRAPHICALLY verified — a digest the
            // legacy RPC-boolean path cached must not satisfy this gate.
            if *crypto_verified && d == digest && at.elapsed() < DIGEST_TTL {
                return Ok(());
            }
        }
        let pinned = crate::pinned_validators()
            .ok_or_else(|| ChainError::FinalityUnverified("no pinned validator set installed".into()))?;
        let att = self
            .get_json(&format!("{}/xid/v1/attestations?digest={digest}", self.rpc_url))
            .await?;
        let bundle = crate::parse_bundle(digest, &att)
            .ok_or_else(|| ChainError::Malformed("attestation bundle malformed".into()))?;
        let height = crate::verify_finality(&bundle, &pinned, &crate::finality_params(crate::now_unix()))
            .map_err(|e| ChainError::FinalityUnverified(format!("{e:?}")))?;
        crate::set_xid_max_height(height);
        *self.digest.write().await = Some((digest.to_string(), Instant::now(), true));
        Ok(())
    }

    /// Whether `proof_root` equals the current attested + finalized state
    /// digest. `force_fresh` bypasses the short-lived digest cache and fetches
    /// (and re-verifies finalization of) a fresh digest.
    async fn digest_matches(&self, proof_root: &str, force_fresh: bool) -> Result<bool> {
        if !force_fresh {
            if let Some((digest, at, _)) = self.digest.read().await.as_ref() {
                // The legacy path needs only RPC-level trust, so either memo kind
                // (crypto- or RPC-verified) is acceptable here.
                if at.elapsed() < DIGEST_TTL {
                    return Ok(digest == proof_root);
                }
            }
        }
        // Fetch the current digest and confirm validators finalized it.
        let digest_info =
            self.get_json(&format!("{}/xid/v1/state_digest", self.rpc_url)).await?;
        let attested = str_field(&digest_info, "digest")?.to_string();
        let att = self
            .get_json(&format!("{}/xid/v1/attestations?digest={attested}", self.rpc_url))
            .await?;
        if !att.get("finalized").and_then(|v| v.as_bool()).unwrap_or(false) {
            return Err(ChainError::NotFinalized);
        }
        let matches = attested == proof_root;
        *self.digest.write().await = Some((attested, Instant::now(), false));
        Ok(matches)
    }

    async fn get_json(&self, url: &str) -> Result<Value> {
        // Refuse to egress over clearnet before Tor is ready in Always mode.
        crate::chain_egress_ok()?;
        self.client()
            .await
            .get(url)
            .send()
            .await
            .map_err(|e| ChainError::Rpc(e.to_string()))?
            .json::<Value>()
            .await
            .map_err(|e| ChainError::Rpc(e.to_string()))
    }
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
