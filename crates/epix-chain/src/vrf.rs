//! `Vrf` — verifiable randomness from the Epix chain's per-block random beacon.
//!
//! Every block carries a random beacon (produced during its `EndBlock`).
//! Applications get unbiasable randomness by deriving values from a beacon plus
//! an application seed:
//!
//! ```text
//! value[i] = SHA256(beacon_hex || seed || decimal(i))
//! ```
//!
//! Because the beacon is fixed once its block is produced, the derivation is
//! deterministic and publicly checkable: nobody can pick the seed after seeing
//! the beacon, and nobody can pick the beacon after seeing the seed. Combining N
//! consecutive blocks ([`combine_beacons`]) raises the bar for manipulation to
//! "every proposer across the whole range colludes".
//!
//! [`derive_random`] and [`combine_beacons`] are pure and match the Python
//! implementation byte-for-byte — the encoding (the beacon **hex string** is
//! hashed as UTF-8 bytes, not decoded; the index as its decimal ASCII) is the
//! easy-to-get-wrong part, so it is pinned by known-answer tests below.

use crate::{ChainError, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const BEACON_TTL: Duration = Duration::from_secs(300);
const LATEST_TTL: Duration = Duration::from_secs(6);

/// A block's random beacon.
#[derive(Clone, Debug)]
pub struct Beacon {
    pub height: u64,
    pub beacon: String,
    pub proposer: String,
    pub timestamp: u64,
}

/// Derive `count` deterministic 32-byte hex random values from a beacon + seed.
///
/// `value[i] = SHA256(beacon_hex_utf8 || seed_utf8 || decimal(i)_utf8)`. Pure
/// and publicly verifiable — this is the primitive dapps rely on.
pub fn derive_random(beacon_hex: &str, seed: &str, count: usize) -> Vec<String> {
    (0..count)
        .map(|i| {
            let mut h = Sha256::new();
            h.update(beacon_hex.as_bytes());
            h.update(seed.as_bytes());
            h.update(i.to_string().as_bytes());
            hex::encode(h.finalize())
        })
        .collect()
}

/// Combine several block beacons into one, by hashing their hex strings in
/// order: `SHA256(beacon0_hex || beacon1_hex || …)`.
pub fn combine_beacons<S: AsRef<str>>(beacons: &[S]) -> String {
    let mut h = Sha256::new();
    for b in beacons {
        h.update(b.as_ref().as_bytes());
    }
    hex::encode(h.finalize())
}

/// Fetches (and caches) random beacons from the chain's VRF REST API.
pub struct Vrf {
    client: reqwest::Client,
    rpc_url: String,
    beacons: RwLock<HashMap<u64, (Beacon, Instant)>>,
    latest: RwLock<Option<(Beacon, Instant)>>,
}

impl Vrf {
    pub fn new(rpc_url: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("reqwest client");
        Self {
            client,
            rpc_url: rpc_url.into().trim_end_matches('/').to_string(),
            beacons: RwLock::new(HashMap::new()),
            latest: RwLock::new(None),
        }
    }

    /// The random beacon at `height` (immutable once produced; cached 5 min).
    pub async fn beacon(&self, height: u64) -> Result<Beacon> {
        if let Some((b, at)) = self.beacons.read().await.get(&height) {
            if at.elapsed() < BEACON_TTL {
                return Ok(b.clone());
            }
        }
        let data = self
            .get_json(&format!("{}/vrf/v1/beacon/{height}", self.rpc_url))
            .await?;
        let bd = data
            .get("beacon")
            .filter(|b| !b.is_null())
            .ok_or_else(|| ChainError::NotFound(format!("beacon {height}")))?;
        let beacon = Beacon {
            height: num_field(bd, "height").unwrap_or(height),
            beacon: str_or_empty(bd, "beacon"),
            proposer: str_or_empty(bd, "proposer"),
            timestamp: num_field(bd, "timestamp").unwrap_or(0),
        };
        self.beacons
            .write()
            .await
            .insert(height, (beacon.clone(), Instant::now()));
        Ok(beacon)
    }

    /// The most recent usable beacon (cached 6s). Uses `latest height - 1`,
    /// since the current block's beacon isn't stored until its `EndBlock`.
    pub async fn latest_beacon(&self) -> Result<Beacon> {
        if let Some((b, at)) = &*self.latest.read().await {
            if at.elapsed() < LATEST_TTL {
                return Ok(b.clone());
            }
        }
        let block = self
            .get_json(&format!(
                "{}/cosmos/base/tendermint/v1beta1/blocks/latest",
                self.rpc_url
            ))
            .await?;
        let height = block
            .get("block")
            .and_then(|b| b.get("header"))
            .and_then(|h| h.get("height"))
            .and_then(value_u64)
            .ok_or_else(|| ChainError::Malformed("no latest block height".into()))?;
        if height < 2 {
            return Err(ChainError::NotFound("no beacon produced yet".into()));
        }
        let beacon = self.beacon(height - 1).await?;
        *self.latest.write().await = Some((beacon.clone(), Instant::now()));
        Ok(beacon)
    }

    /// A combined beacon over `blocks` consecutive blocks ending at
    /// `end_height` — every proposer in the range contributes entropy.
    pub async fn multi_block_beacon(&self, end_height: u64, blocks: u64) -> Result<String> {
        if !(1..=256).contains(&blocks) {
            return Err(ChainError::Malformed("blocks must be between 1 and 256".into()));
        }
        if end_height < blocks {
            return Err(ChainError::Malformed("end_height must be >= blocks".into()));
        }
        let start = end_height - blocks + 1;
        let mut hexes = Vec::with_capacity(blocks as usize);
        for height in start..=end_height {
            let b = self.beacon(height).await?;
            if b.beacon.is_empty() {
                return Err(ChainError::NotFound(format!("beacon {height}")));
            }
            hexes.push(b.beacon);
        }
        Ok(combine_beacons(&hexes))
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

fn str_or_empty(v: &Value, key: &str) -> String {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn num_field(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(value_u64)
}

/// A u64 the chain may encode as a JSON number or a string.
fn value_u64(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known answers computed from the Python VrfPlugin (`_derive_random_values`
    // and the multi-block SHA256), pinning byte-exact compatibility.
    #[test]
    fn derive_random_matches_python() {
        let vals = derive_random("abc123def456", "my-raffle-2026", 3);
        assert_eq!(
            vals,
            vec![
                "10940abe465529ed407372f606de7c703764ae2d530cad5143f4a923ce806980",
                "46498e3d688923ad3a308c9d32b8a63c16b4665d6b2ae1b22623ec22935b9c27",
                "6dd2f3919179d69eb448119eb33b6ca8ef43aa78010c119fe6df1a5a1856bb72",
            ]
        );
    }

    #[test]
    fn combine_beacons_matches_python() {
        assert_eq!(
            combine_beacons(&["aa11", "bb22", "cc33"]),
            "378d594d7bb48098fcf2c87a56e85e5f9f5b3b91b39e6898c1bbfff2b041a40d"
        );
    }
}
