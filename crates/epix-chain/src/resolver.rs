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
    client: reqwest::Client,
    rpc_url: String,
    cache: RwLock<HashMap<String, (DomainSnapshot, Instant)>>,
    ttl: Duration,
    /// The last digest confirmed finalized, cached briefly. Every resolve
    /// checks its proof against the current attested + finalized digest; that
    /// digest is global chain state, identical for every name resolved in the
    /// same moment. Caching it turns a burst of N resolves from 3N HTTP calls
    /// (proof + digest + attestations, each) into N + 2.
    digest: RwLock<Option<(String, Instant)>>,
}

/// How long a confirmed-finalized digest is reused. Short: the digest advances
/// each block, so a proof for a just-changed name must still be verifiable, but
/// long enough that one burst of resolves shares a single digest fetch.
const DIGEST_TTL: Duration = Duration::from_secs(3);

impl XidResolver {
    pub fn new(rpc_url: impl Into<String>) -> Self {
        let client = crate::http_client(Duration::from_secs(15));
        Self {
            client,
            rpc_url: rpc_url.into().trim_end_matches('/').to_string(),
            cache: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(30 * 60),
            digest: RwLock::new(None),
        }
    }

    /// Override the positive-cache TTL (default 30 minutes).
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
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

        let domain = data
            .get("domain")
            .filter(|d| !d.is_null())
            .ok_or_else(|| ChainError::NotFound(key.clone()))?;
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

        // Step 1 - Merkle proof.
        if !verify_proof(leaf_hash, leaf_index, &siblings, proof_root)? {
            return Err(ChainError::MerkleInvalid);
        }

        // Step 2+3 - the proof root must equal a state digest that validators
        // have finalized. The finalized digest is cached briefly (it is global
        // chain state), so a burst of resolves shares one digest fetch. A
        // proof that doesn't match the cached digest (its name changed since)
        // forces a fresh fetch before we reject it, so caching never yields a
        // false negative.
        if !self.digest_matches(proof_root, false).await?
            && !self.digest_matches(proof_root, true).await?
        {
            return Err(ChainError::DigestMismatch);
        }

        let snapshot = parse_domain(name, tld, domain)?;
        self.cache
            .write()
            .await
            .insert(key, (snapshot.clone(), Instant::now()));
        Ok(snapshot)
    }

    /// Whether `proof_root` equals the current attested + finalized state
    /// digest. `force_fresh` bypasses the short-lived digest cache and fetches
    /// (and re-verifies finalization of) a fresh digest.
    async fn digest_matches(&self, proof_root: &str, force_fresh: bool) -> Result<bool> {
        if !force_fresh {
            if let Some((digest, at)) = self.digest.read().await.as_ref() {
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
        *self.digest.write().await = Some((attested, Instant::now()));
        Ok(matches)
    }

    async fn get_json(&self, url: &str) -> Result<Value> {
        self.client
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
