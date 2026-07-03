//! Optional-file availability index (`getHashfield`/`setHashfield`/
//! `findHashIds`). A hashfield is the set of *hash ids* of the optional files a
//! node holds, where a hash id is the first two bytes of a file's sha512 (the
//! first 4 hex chars). Peers exchange these so a downloader can find who holds a
//! rare optional file without asking for each file by name.
//!
//! Wire format matches EpixNet's `PeerHashfield`: a `array("H")` of `u16` hash
//! ids serialized native-endian (little-endian on the platforms we target).

use std::collections::BTreeSet;

/// A set of optional-file hash ids.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hashfield {
    ids: BTreeSet<u16>,
}

impl Hashfield {
    pub fn new() -> Self {
        Self::default()
    }

    /// The hash id of a sha512 hex digest: `int(sha512[0:4], 16)`. Returns None
    /// if the digest is too short or not hex.
    pub fn hash_id(sha512_hex: &str) -> Option<u16> {
        sha512_hex.get(0..4).and_then(|h| u16::from_str_radix(h, 16).ok())
    }

    /// Record that we hold the file with this sha512. Returns true if newly added.
    pub fn add_hash(&mut self, sha512_hex: &str) -> bool {
        match Self::hash_id(sha512_hex) {
            Some(id) => self.ids.insert(id),
            None => false,
        }
    }

    pub fn add_id(&mut self, id: u16) -> bool {
        self.ids.insert(id)
    }

    pub fn remove_hash(&mut self, sha512_hex: &str) -> bool {
        match Self::hash_id(sha512_hex) {
            Some(id) => self.ids.remove(&id),
            None => false,
        }
    }

    /// Do we hold a file whose sha512 maps to this hash id? (Hash ids collide -
    /// this is a "maybe", confirmed by an actual file request, exactly as
    /// EpixNet uses it.)
    pub fn has_hash(&self, sha512_hex: &str) -> bool {
        Self::hash_id(sha512_hex).is_some_and(|id| self.ids.contains(&id))
    }

    pub fn has_id(&self, id: u16) -> bool {
        self.ids.contains(&id)
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn ids(&self) -> impl Iterator<Item = u16> + '_ {
        self.ids.iter().copied()
    }

    /// Serialize to the wire form: little-endian `u16` per id.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.ids.len() * 2);
        for id in &self.ids {
            out.extend_from_slice(&id.to_le_bytes());
        }
        out
    }

    /// Parse the wire form (little-endian `u16` array); trailing odd byte is
    /// ignored, matching a truncated `array("H")`.
    pub fn from_bytes(raw: &[u8]) -> Self {
        let mut ids = BTreeSet::new();
        for chunk in raw.chunks_exact(2) {
            ids.insert(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        Self { ids }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_id_from_sha512_prefix() {
        assert_eq!(Hashfield::hash_id("abcd0000ff"), Some(0xabcd));
        assert_eq!(Hashfield::hash_id("0001rest"), Some(1));
        assert_eq!(Hashfield::hash_id("xy"), None); // too short
        assert_eq!(Hashfield::hash_id("zzzz"), None); // not hex
    }

    #[test]
    fn add_has_remove() {
        let mut hf = Hashfield::new();
        assert!(hf.add_hash("abcd1111"));
        assert!(!hf.add_hash("abcd2222")); // same hash id (abcd) - already present
        assert!(hf.has_hash("abcdffff"));
        assert!(!hf.has_hash("0000ffff"));
        assert!(hf.remove_hash("abcd0000"));
        assert!(hf.is_empty());
    }

    #[test]
    fn wire_roundtrip_little_endian() {
        let mut hf = Hashfield::new();
        hf.add_id(0x0001);
        hf.add_id(0xabcd);
        let bytes = hf.to_bytes();
        // 0x0001 little-endian = [1, 0]; 0xabcd = [0xcd, 0xab]
        assert_eq!(bytes, vec![0x01, 0x00, 0xcd, 0xab]);
        assert_eq!(Hashfield::from_bytes(&bytes), hf);
        // Odd trailing byte ignored.
        assert_eq!(Hashfield::from_bytes(&[0x01, 0x00, 0x99]).len(), 1);
    }
}
