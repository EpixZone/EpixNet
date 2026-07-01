//! Resolved `.epix` domain types.

use serde::{Deserialize, Serialize};

/// A verified snapshot of a `.epix` domain record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainSnapshot {
    pub name: String,
    pub tld: String,
    /// The owner's Epix chain address.
    pub owner: String,
    /// Merkle root of the domain's content (hex).
    pub content_root: String,
    /// Identities this name maps to (the xite/identity addresses).
    pub identities: Vec<Identity>,
}

impl DomainSnapshot {
    /// `name.tld`.
    pub fn fqdn(&self) -> String {
        format!("{}.{}", self.name, self.tld)
    }

    /// The first active identity address, if any — the identity a visitor to
    /// `name.tld` resolves to.
    pub fn active_identity(&self) -> Option<&str> {
        self.identities
            .iter()
            .find(|i| i.active)
            .map(|i| i.address.as_str())
    }
}

/// One identity bound to a domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub address: String,
    pub label: String,
    pub active: bool,
}
