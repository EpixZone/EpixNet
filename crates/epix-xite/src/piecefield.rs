//! Bigfile piecefields - a compact record of which pieces of a big file a peer
//! (or we) hold, exchanged so downloads only ask peers that actually have a
//! piece.
//!
//! Wire-compatible with EpixNet's `BigfilePiecefield`: the unpacked form is one
//! flag per piece (present / absent); the packed form is a little-endian `u16`
//! array of run lengths that alternate present, absent, present, … starting with
//! the count of leading present pieces (0 when the first piece is absent).

/// Safety cap on the total pieces an unpacked piecefield may describe, so a
/// malicious peer can't make us allocate an enormous vector.
const MAX_PIECES: usize = 8 * 1024 * 1024;

/// Which pieces of one big file are present.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Piecefield {
    bits: Vec<bool>,
}

impl Piecefield {
    pub fn new() -> Self {
        Self { bits: Vec::new() }
    }

    /// A piecefield with all `n` pieces present (a fully-downloaded file).
    pub fn all_present(n: usize) -> Self {
        Self { bits: vec![true; n] }
    }

    /// Build from a present/absent flag per piece.
    pub fn from_bits(bits: Vec<bool>) -> Self {
        Self { bits }
    }

    /// Whether piece `i` is present (absent past the end).
    pub fn get(&self, i: usize) -> bool {
        self.bits.get(i).copied().unwrap_or(false)
    }

    /// Mark piece `i` present/absent, extending with absent pieces as needed.
    pub fn set(&mut self, i: usize, present: bool) {
        if i >= self.bits.len() {
            self.bits.resize(i + 1, false);
        }
        self.bits[i] = present;
    }

    /// Number of pieces this field describes.
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    /// Number of present pieces.
    pub fn count_present(&self) -> usize {
        self.bits.iter().filter(|b| **b).count()
    }

    /// Pack to the wire form: a little-endian `u16` array of alternating run
    /// lengths (present, absent, present, …), first run = leading present count.
    pub fn pack(&self) -> Vec<u8> {
        if self.bits.is_empty() {
            return Vec::new();
        }
        let mut runs: Vec<u16> = Vec::new();
        let mut expected = true; // the first run counts present pieces
        let mut i = 0;
        while i < self.bits.len() {
            let mut count: u32 = 0;
            while i < self.bits.len() && self.bits[i] == expected {
                count += 1;
                i += 1;
            }
            // A single run can't exceed u16::MAX; split it with a zero-length
            // opposite run (which round-trips to nothing) to stay valid.
            while count > u16::MAX as u32 {
                runs.push(u16::MAX);
                runs.push(0);
                count -= u16::MAX as u32;
            }
            runs.push(count as u16);
            expected = !expected;
        }
        let mut out = Vec::with_capacity(runs.len() * 2);
        for r in runs {
            out.extend_from_slice(&r.to_le_bytes());
        }
        out
    }

    /// Unpack from the wire form. Returns an empty field on malformed input or if
    /// it would exceed [`MAX_PIECES`].
    pub fn unpack(packed: &[u8]) -> Self {
        let mut bits = Vec::new();
        let mut present = true; // the first run is present pieces
        for chunk in packed.chunks_exact(2) {
            let run = u16::from_le_bytes([chunk[0], chunk[1]]) as usize;
            if bits.len() + run > MAX_PIECES {
                return Self::new();
            }
            bits.extend(std::iter::repeat(present).take(run));
            present = !present;
        }
        Self { bits }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        for bits in [
            vec![],
            vec![true],
            vec![false],
            vec![true, true, false, true],
            vec![false, true, true],
            vec![false, false, false, true, false],
            vec![true; 100],
            (0..500).map(|i| i % 3 == 0).collect::<Vec<_>>(),
        ] {
            let pf = Piecefield::from_bits(bits.clone());
            let round = Piecefield::unpack(&pf.pack());
            assert_eq!(round, pf, "roundtrip failed for {bits:?}");
        }
    }

    #[test]
    fn packs_like_epixnet_run_lengths() {
        // data 1,1,0,1 -> runs [2,1,1]; data 0,1,1 -> runs [0,1,2].
        let a = Piecefield::from_bits(vec![true, true, false, true]).pack();
        assert_eq!(a, [2u16, 1, 1].iter().flat_map(|r| r.to_le_bytes()).collect::<Vec<u8>>());
        let b = Piecefield::from_bits(vec![false, true, true]).pack();
        assert_eq!(b, [0u16, 1, 2].iter().flat_map(|r| r.to_le_bytes()).collect::<Vec<u8>>());
    }

    #[test]
    fn get_set_and_count() {
        let mut pf = Piecefield::new();
        pf.set(5, true);
        assert!(pf.get(5));
        assert!(!pf.get(3));
        assert!(!pf.get(9));
        assert_eq!(pf.len(), 6);
        assert_eq!(pf.count_present(), 1);
        pf.set(5, false);
        assert_eq!(pf.count_present(), 0);
    }

    #[test]
    fn all_present_packs_to_a_single_run() {
        let pf = Piecefield::all_present(9);
        // A single present-run of 9 -> [9].
        assert_eq!(pf.pack(), 9u16.to_le_bytes().to_vec());
        assert_eq!(Piecefield::unpack(&pf.pack()).count_present(), 9);
    }

    #[test]
    fn oversized_run_is_rejected() {
        // A run claiming 60000 pieces repeated to exceed MAX_PIECES -> empty.
        let mut packed = Vec::new();
        for _ in 0..200 {
            packed.extend_from_slice(&60000u16.to_le_bytes());
            packed.extend_from_slice(&0u16.to_le_bytes());
        }
        assert!(Piecefield::unpack(&packed).is_empty());
    }
}
