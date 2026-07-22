//! Xite / identity addresses (`epix1…` bech32), validated via `epix-crypt`.

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

/// The bech32 data charset (excludes `1`, `b`, `i`, `o`).
const BECH32_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// How a name label (e.g. the part before `.epix`) relates to the bech32
/// address space. One shared rule, so every resolver treats address-shaped
/// labels identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelClass {
    /// A checksum-valid `epix1…` address: the dotted alias. It resolves to
    /// itself and is never looked up as an xID name, so a registered
    /// same-string name can never take over an address.
    Address,
    /// Address-shaped - `epix1` plus 20 or more bech32-charset characters -
    /// but not checksum-valid: a mistyped or forged address. Never resolved
    /// as a name, so the typo-space around a real address cannot be
    /// registered and used to phish.
    AddressShaped,
    /// An ordinary xID name. Short or non-bech32 `epix1…` brandings
    /// (`epix1shop`, `epix1fans`) stay registrable and resolvable.
    Name,
}

/// Classify `label` against the address space (see [`LabelClass`]).
pub fn classify_label(label: &str) -> LabelClass {
    if epix_crypt::is_valid_address(label) {
        return LabelClass::Address;
    }
    let shaped = label
        .strip_prefix("epix1")
        .filter(|rest| rest.len() >= 20)
        .is_some_and(|rest| rest.chars().all(|c| BECH32_CHARSET.contains(c)));
    if shaped {
        LabelClass::AddressShaped
    } else {
        LabelClass::Name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DASH: &str = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";

    #[test]
    fn parse_valid_and_invalid() {
        let a = Address::parse(DASH).unwrap();
        assert_eq!(a.as_str(), DASH);
        assert_eq!(a.hash160().len(), 20);
        assert!(Address::parse("not-an-address").is_err());
    }

    #[test]
    fn classify_label_partitions_the_address_space() {
        // A checksum-valid address is the alias, never a name.
        assert_eq!(classify_label(DASH), LabelClass::Address);
        // One character off: address-shaped, refused as a name (typo-squat).
        let mut typo = DASH.to_string();
        typo.pop();
        typo.push('q');
        assert_ne!(typo, DASH);
        assert_eq!(classify_label(&typo), LabelClass::AddressShaped);
        // A truncated-but-still-long fake is refused too.
        assert_eq!(classify_label(&DASH[..30]), LabelClass::AddressShaped);
        // Short or non-charset epix1 brandings are ordinary names: under the
        // 20-char floor, or containing letters bech32 never uses (o, b, i).
        assert_eq!(classify_label("epix1fans"), LabelClass::Name);
        assert_eq!(classify_label("epix1shop"), LabelClass::Name);
        assert_eq!(classify_label("epix1bobsbigblog2026extra"), LabelClass::Name);
        // Non-epix1 labels are names regardless of shape.
        assert_eq!(classify_label("talk"), LabelClass::Name);
        assert_eq!(classify_label("dashboard"), LabelClass::Name);
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
