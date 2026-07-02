//! `ChainAttestation` - trust whole-state chain-attested content.
//!
//! Some `content.json` files opt out of per-name Merkle proofs and instead
//! carry a `state_digest`. Such content is trusted **iff** that digest equals
//! the chain's *current* state digest **and** that digest is finalized by 2/3+
//! validators. There are no signatures to check - validator consensus *is* the
//! proof. (Contrast [`XidResolver`](crate::XidResolver), which proves a single
//! name with a Merkle path.)
//!
//! Two short-lived caches keep this cheap without trusting stale state: the
//! current digest (15s) and per-digest finality (30s). Name lookups are cached
//! against the digest they were seen under, so a digest change invalidates them.

use crate::{ChainError, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const DIGEST_TTL: Duration = Duration::from_secs(15);
const ATTESTATION_TTL: Duration = Duration::from_secs(30);

/// The chain's current committed state.
#[derive(Clone, Debug)]
pub struct StateDigest {
    pub digest: String,
    pub height: u64,
    pub num_names: u64,
}

/// Verifies chain-attested content against the Epix chain's finalized state.
pub struct ChainAttestation {
    client: reqwest::Client,
    rpc_url: String,
    digest: RwLock<Option<(StateDigest, Instant)>>,
    finalized: RwLock<HashMap<String, (bool, Instant)>>,
    names: RwLock<HashMap<(String, String), (Option<Value>, String)>>,
}

impl ChainAttestation {
    pub fn new(rpc_url: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("reqwest client");
        Self {
            client,
            rpc_url: rpc_url.into().trim_end_matches('/').to_string(),
            digest: RwLock::new(None),
            finalized: RwLock::new(HashMap::new()),
            names: RwLock::new(HashMap::new()),
        }
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

    /// Whether `digest` has been finalized by 2/3+ validators (cached for
    /// [`ATTESTATION_TTL`]).
    pub async fn is_finalized(&self, digest: &str) -> Result<bool> {
        if let Some((f, at)) = self.finalized.read().await.get(digest) {
            if at.elapsed() < ATTESTATION_TTL {
                return Ok(*f);
            }
        }
        let data = self
            .get_json(&format!("{}/xid/v1/attestations?digest={digest}", self.rpc_url))
            .await?;
        let finalized = data.get("finalized").and_then(|v| v.as_bool()).unwrap_or(false);
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
        let chain = self.state_digest().await?;
        if content_state_digest != chain.digest {
            return Err(ChainError::DigestMismatch);
        }
        if !self.is_finalized(&chain.digest).await? {
            return Err(ChainError::NotFinalized);
        }
        Ok(chain)
    }

    /// Resolve a name from the chain (attested-state trust, no Merkle proof).
    /// Returns `None` if the name has no record. Cached against the current
    /// digest, so a state change invalidates the entry.
    pub async fn resolve_name(&self, tld: &str, name: &str) -> Result<Option<Value>> {
        let current = self
            .state_digest()
            .await
            .map(|d| d.digest)
            .unwrap_or_default();
        let key = (tld.to_string(), name.to_string());
        if let Some((record, seen)) = self.names.read().await.get(&key) {
            if *seen == current {
                return Ok(record.clone());
            }
        }
        let data = self
            .get_json(&format!("{}/xid/v1/resolve/{tld}/{name}", self.rpc_url))
            .await?;
        let record = data.get("record").filter(|r| !r.is_null()).cloned();
        self.names
            .write()
            .await
            .insert(key, (record.clone(), current));
        Ok(record)
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
