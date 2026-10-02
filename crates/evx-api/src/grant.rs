//! Persistent per-xite execution grant as seen by the supervisor.
//!
//! The authority generation changes only when authority changes: enable,
//! revoke, capability or publisher changes. Limit adjustments live in a
//! separate `limits_generation` owned by the broker so a budget change never
//! cancels queued or in-flight work.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::broker::Capability;
use crate::Denied;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub xite: String,
    pub enabled: bool,
    /// Authority generation. Incremented on every authority change.
    pub generation: u64,
    pub capabilities: BTreeSet<Capability>,
    pub publisher: Option<String>,
    /// Raw Ed25519 public key bytes of the publisher, if bound.
    #[serde(default, with = "key_bytes")]
    pub publisher_public_key: Option<[u8; 32]>,
    pub runtime_profiles: BTreeSet<String>,
}

impl Grant {
    pub fn new(xite: impl Into<String>, enabled: bool) -> Result<Self, Denied> {
        let xite = xite.into();
        crate::validate_identifier(&xite)?;
        Ok(Grant {
            xite,
            enabled,
            generation: 1,
            capabilities: Capability::all().into_iter().collect(),
            publisher: None,
            publisher_public_key: None,
            runtime_profiles: ["evx-core-v1".to_string()].into_iter().collect(),
        })
    }

    pub fn with_capabilities(mut self, caps: impl IntoIterator<Item = Capability>) -> Self {
        self.capabilities = caps.into_iter().collect();
        self
    }

    /// Disable and advance the authority generation atomically from the
    /// caller's point of view. The supervisor holds its lock around this.
    pub fn revoke(&mut self) {
        self.enabled = false;
        self.generation += 1;
    }
}

/// Immutable context captured at activation and rechecked at every sensitive
/// boundary. A context that does not match the current grant means the
/// authority changed underneath the invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationContext {
    pub xite: String,
    pub generation: u64,
    pub publisher: String,
    #[serde(with = "key_bytes")]
    pub public_key: Option<[u8; 32]>,
    pub runtime_profile: String,
    pub capabilities: BTreeSet<Capability>,
}

impl ActivationContext {
    pub fn matches(&self, grant: &Grant) -> bool {
        self.xite == grant.xite
            && self.generation == grant.generation
            && grant.publisher.as_deref() == Some(self.publisher.as_str())
            && grant.publisher_public_key == self.public_key
            && grant.runtime_profiles.contains(&self.runtime_profile)
            && self.capabilities.is_subset(&grant.capabilities)
    }
}

mod key_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(value: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => {
                let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                Some(hex).serialize(s)
            }
            None => None::<String>.serialize(s),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let hex: Option<String> = Option::deserialize(d)?;
        match hex {
            None => Ok(None),
            Some(hex) => {
                if hex.len() != 64 {
                    return Err(serde::de::Error::custom(
                        "public key must be 64 hex characters",
                    ));
                }
                let mut out = [0u8; 32];
                for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
                    let s = std::str::from_utf8(chunk).map_err(serde::de::Error::custom)?;
                    out[i] = u8::from_str_radix(s, 16).map_err(serde::de::Error::custom)?;
                }
                Ok(Some(out))
            }
        }
    }
}
