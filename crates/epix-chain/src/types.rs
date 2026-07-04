//! Resolved `.epix` domain types.

use serde::{Deserialize, Serialize};

/// The DNS record type that carries an EpixNet xite address.
pub const EPIXNET_RECORD_TYPE: u32 = 65280;

/// A verified snapshot of a `.epix` domain record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainSnapshot {
    pub name: String,
    pub tld: String,
    /// The owner's Epix chain address.
    pub owner: String,
    /// Merkle root of the domain's content (hex).
    pub content_root: String,
    /// Identities this name maps to (the identity addresses).
    pub identities: Vec<Identity>,
    /// The domain's DNS records (carry the xite address + other pointers).
    pub dns_records: Vec<DnsRecord>,
    /// Profile avatar URL, empty if unset.
    #[serde(default)]
    pub avatar: String,
    /// Profile bio text, empty if unset.
    #[serde(default)]
    pub bio: String,
}

impl DomainSnapshot {
    /// `name.tld`.
    pub fn fqdn(&self) -> String {
        format!("{}.{}", self.name, self.tld)
    }

    /// The EpixNet **xite address** this name points to, from its `EPIXNET`
    /// DNS record - the address to clone and serve when visiting `name.tld`.
    pub fn xite_address(&self) -> Option<&str> {
        self.dns_records
            .iter()
            .find(|r| r.record_type == EPIXNET_RECORD_TYPE)
            .map(|r| r.value.trim())
    }

    /// The first active identity address, if any.
    pub fn active_identity(&self) -> Option<&str> {
        self.identities
            .iter()
            .find(|i| i.active)
            .map(|i| i.address.as_str())
    }
}

/// One DNS record on a domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: u32,
    pub value: String,
}

/// One identity bound to a domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub address: String,
    pub label: String,
    pub active: bool,
    /// Block height the identity was revoked at (0 = not revoked).
    #[serde(default)]
    pub revoked_at: u64,
    /// Unix time the identity was revoked at (0 = not revoked).
    #[serde(default)]
    pub revoked_at_time: u64,
}
