//! Site / identity addresses (`epix1…` bech32), validated via `epix-crypt`.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// A validated EpixNet address. Construction guarantees the value is a
/// well-formed `epix1…` bech32 address (20-byte payload).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Address(String);

impl Address {
    pub fn parse(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if epix_crypt::is_valid_address(&s) {
            Ok(Address(s))
        } else {
            Err(Error::InvalidAddress(s))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The 20-byte hash160 payload.
    pub fn hash160(&self) -> [u8; 20] {
        // Safe: an `Address` is only ever constructed from a validated string.
        epix_crypt::address_to_hash160(&self.0).expect("validated address")
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Address {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Address::parse(s)
    }
}

impl From<Address> for String {
    fn from(a: Address) -> String {
        a.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DASH: &str = "epix1dashuu6pvsut7aw9dx44f543mv7xt9zlydsj9t";

    #[test]
    fn parse_valid_and_invalid() {
        let a = Address::parse(DASH).unwrap();
        assert_eq!(a.as_str(), DASH);
        assert_eq!(a.hash160().len(), 20);
        assert!(Address::parse("not-an-address").is_err());
    }

    #[test]
    fn serde_roundtrip_and_rejects_bad() {
        let a = Address::parse(DASH).unwrap();
        let j = serde_json::to_string(&a).unwrap();
        assert_eq!(j, format!("\"{DASH}\""));
        let back: Address = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
        // Deserialization enforces validation.
        assert!(serde_json::from_str::<Address>("\"epix1bogus\"").is_err());
    }
}
