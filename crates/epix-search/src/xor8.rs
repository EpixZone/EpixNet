//! Deterministic XOR8 term filter (Track 1 skip-filter).
//!
//! A binary fuse / xor filter is a compact set-membership structure with
//! NO false negatives — if a term is in the set the filter always says
//! "maybe present", and if it says "absent" the term is definitely not
//! there. That one-sidedness is exactly what a segment skip-filter needs:
//! walking the segment spine, we can safely SKIP any segment whose filter
//! rejects every query term, and only range-fetch the candidates.
//!
//! This is a clean-room implementation of the published xor-filter
//! construction (Graf & Lemire, "Xor Filters", 2020) — algorithm only.
//! It is fully DETERMINISTIC: the seed schedule is fixed, so any node
//! building a filter over the same term set produces byte-identical
//! bytes. That determinism is a Phase-G requirement (any node rebuilds
//! identical roots), so the filter is seeded from the term set itself,
//! never from a clock or RNG.
//!
//! 8-bit fingerprints → ~0.39% false-positive rate at ~9.84 bits/entry.

/// Fixed seed schedule: construction retries with these seeds in order
/// until it maps cleanly. Part of the frozen format — changing it changes
/// every filter's bytes. Values are arbitrary fixed 64-bit constants.
const SEEDS: [u64; 32] = [
    0x2545_F491_4F6C_DD1D, 0x9E37_79B9_7F4A_7C15, 0xD1B5_4A32_D192_ED03,
    0xA0761D6478BD642F, 0xE7037ED1A0B428DB, 0x8EBC6AF09C88C6E3,
    0x5897_1E0C_1D33_A6D1, 0x4CF5_AD43_2745_937F, 0xFF51_AFD7_ED55_8CCD,
    0xC4CE_B9FE_1A85_EC53, 0x1656_67B1_9E37_79F9, 0x27D4_EB2F_1656_67C5,
    0x1111_1111_1111_1111, 0x2222_2222_2222_2223, 0x3333_3333_3333_3335,
    0x4444_4444_4444_4447, 0x5555_5555_5555_5559, 0x6666_6666_6666_666B,
    0x7777_7777_7777_777D, 0x8888_8888_8888_888F, 0x9999_9999_9999_9991,
    0xAAAA_AAAA_AAAA_AAA3, 0xBBBB_BBBB_BBBB_BBB5, 0xCCCC_CCCC_CCCC_CCC7,
    0xDDDD_DDDD_DDDD_DDD9, 0xEEEE_EEEE_EEEE_EEEB, 0xFFFF_FFFF_FFFF_FFFD,
    0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210, 0x0F0F_0F0F_0F0F_0F0F,
    0xF0F0_F0F0_F0F0_F0F0, 0xACE1_ACE1_ACE1_ACE1,
];

/// A built XOR8 filter over a set of 64-bit term hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Xor8 {
    seed: u64,
    block_length: u32,
    fingerprints: Vec<u8>,
    /// True for the seed-exhaustion fallback: a filter that matches every
    /// key. No constant fingerprint fill can express "match everything"
    /// (contains() xors three slots), so it is an explicit state. Encoded
    /// in the frozen format as block_length == 0 with no fingerprints.
    match_all: bool,
}

fn mix(key: u64, seed: u64) -> u64 {
    let mut h = key.wrapping_add(seed);
    h = (h ^ (h >> 33)).wrapping_mul(0xff51afd7ed558ccd);
    h = (h ^ (h >> 33)).wrapping_mul(0xc4ceb9fe1a85ec53);
    h ^ (h >> 33)
}

/// Reduce `hash` into `[0, n)` without a modulo (Lemire's trick).
fn reduce(hash: u32, n: u32) -> u32 {
    (((hash as u64) * (n as u64)) >> 32) as u32
}

fn fingerprint(hash: u64) -> u8 {
    (hash ^ (hash >> 32)) as u8
}

struct Hashes {
    h0: u32,
    h1: u32,
    h2: u32,
}

impl Xor8 {
    fn subhashes(&self, hash: u64) -> Hashes {
        let r0 = hash as u32;
        let r1 = (hash >> 16) as u32;
        let r2 = (hash >> 32) as u32;
        Hashes {
            h0: reduce(r0, self.block_length),
            h1: reduce(r1, self.block_length) + self.block_length,
            h2: reduce(r2, self.block_length) + 2 * self.block_length,
        }
    }

    /// Build a filter over `keys` (64-bit term hashes). Duplicates are
    /// fine. Deterministic: the same key set always yields identical bytes.
    pub fn build(keys: &[u64]) -> Self {
        let mut dedup: Vec<u64> = keys.to_vec();
        dedup.sort_unstable();
        dedup.dedup();

        let size = dedup.len();
        let capacity = (32 + (1.23 * size as f64).ceil() as usize).max(3);
        let capacity = capacity + (3 - capacity % 3) % 3; // multiple of 3
        let block_length = (capacity / 3) as u32;

        for &seed in SEEDS.iter() {
            if let Some(fp) = Self::try_build(&dedup, seed, block_length, capacity) {
                return Self { seed, block_length, fingerprints: fp, match_all: false };
            }
        }
        // Astronomically unlikely with 32 seeds; fall back to a filter that
        // matches everything, preserving the no-false-negative guarantee.
        // This is an explicit state (see `match_all`): a constant
        // fingerprint fill would only match ~1/256 of keys.
        Self { seed: 0, block_length: 0, fingerprints: Vec::new(), match_all: true }
    }

    fn try_build(keys: &[u64], seed: u64, block_length: u32, capacity: usize) -> Option<Vec<u8>> {
        // Peeling: find an ordering where each key can be assigned to a
        // slot no other remaining key touches.
        let mut sets: Vec<(u64, u32)> = vec![(0, 0); capacity]; // (xor of hashes, count)
        let hashed: Vec<u64> = keys.iter().map(|k| mix(*k, seed)).collect();

        let temp = Self { seed, block_length, fingerprints: Vec::new(), match_all: false };
        for (i, &h) in hashed.iter().enumerate() {
            let hs = temp.subhashes(h);
            for slot in [hs.h0, hs.h1, hs.h2] {
                let e = &mut sets[slot as usize];
                e.0 ^= i as u64;
                e.1 += 1;
            }
        }

        // Queue of slots with exactly one key.
        let mut queue: Vec<u32> =
            (0..capacity as u32).filter(|&s| sets[s as usize].1 == 1).collect();
        let mut stack: Vec<(usize, u32)> = Vec::with_capacity(keys.len());

        while let Some(slot) = queue.pop() {
            if sets[slot as usize].1 != 1 {
                continue;
            }
            let key_idx = sets[slot as usize].0 as usize;
            stack.push((key_idx, slot));
            let hs = temp.subhashes(hashed[key_idx]);
            for s in [hs.h0, hs.h1, hs.h2] {
                let e = &mut sets[s as usize];
                e.0 ^= key_idx as u64;
                e.1 -= 1;
                if e.1 == 1 {
                    queue.push(s);
                }
            }
        }

        if stack.len() != keys.len() {
            return None; // did not fully peel; try the next seed
        }

        // Assign fingerprints in reverse peel order.
        let mut fp = vec![0u8; capacity];
        for &(key_idx, slot) in stack.iter().rev() {
            let h = hashed[key_idx];
            let hs = temp.subhashes(h);
            let f = fingerprint(h)
                ^ (if slot == hs.h0 { 0 } else { fp[hs.h0 as usize] })
                ^ (if slot == hs.h1 { 0 } else { fp[hs.h1 as usize] })
                ^ (if slot == hs.h2 { 0 } else { fp[hs.h2 as usize] });
            fp[slot as usize] = f;
        }
        Some(fp)
    }

    /// Membership query. Never a false NEGATIVE: if `key` was in the built
    /// set this always returns true. May rarely return true for an absent
    /// key (~0.39%).
    pub fn contains(&self, key: u64) -> bool {
        if self.match_all {
            return true;
        }
        let h = mix(key, self.seed);
        let hs = self.subhashes(h);
        let f = fingerprint(h);
        f == (self.fingerprints[hs.h0 as usize]
            ^ self.fingerprints[hs.h1 as usize]
            ^ self.fingerprints[hs.h2 as usize])
    }

    /// Frozen serialization: `seed(u64 LE) ‖ block_length(u32 LE) ‖
    /// len(u32 LE) ‖ fingerprints`. Deterministic → content-addressable.
    /// The match-all fallback is encoded canonically as all-zero header
    /// (seed 0, block_length 0, len 0) with no fingerprint bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.match_all {
            return vec![0u8; 16];
        }
        let mut out = Vec::with_capacity(16 + self.fingerprints.len());
        out.extend_from_slice(&self.seed.to_le_bytes());
        out.extend_from_slice(&self.block_length.to_le_bytes());
        out.extend_from_slice(&(self.fingerprints.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.fingerprints);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        let seed = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let block_length = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        let len = u32::from_le_bytes(bytes[12..16].try_into().ok()?) as usize;
        if bytes.len() != 16 + len {
            return None;
        }
        // block_length == 0 is the match-all sentinel: it carries no
        // fingerprints. A real filter always has block_length >= 1.
        if block_length == 0 {
            if len != 0 {
                return None;
            }
            return Some(Self { seed, block_length: 0, fingerprints: Vec::new(), match_all: true });
        }
        // A well-formed filter has exactly three sub-blocks of
        // block_length each. Reject anything else so contains() can index
        // the fingerprints without bounds-checking or panicking.
        if len != 3 * block_length as usize {
            return None;
        }
        Some(Self { seed, block_length, fingerprints: bytes[16..].to_vec(), match_all: false })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn term_hash(term: &str) -> u64 {
        let d = blake3::hash(term.as_bytes());
        u64::from_le_bytes(d.as_bytes()[..8].try_into().unwrap())
    }

    #[test]
    fn no_false_negatives() {
        let terms: Vec<u64> = (0..2000).map(|i| term_hash(&format!("term{i}"))).collect();
        let f = Xor8::build(&terms);
        for t in &terms {
            assert!(f.contains(*t), "a member must always be found (no false negatives)");
        }
    }

    #[test]
    fn false_positive_rate_is_low() {
        let terms: Vec<u64> = (0..5000).map(|i| term_hash(&format!("in{i}"))).collect();
        let f = Xor8::build(&terms);
        let mut fp = 0;
        let trials = 100_000;
        for i in 0..trials {
            if f.contains(term_hash(&format!("out{i}"))) {
                fp += 1;
            }
        }
        let rate = fp as f64 / trials as f64;
        assert!(rate < 0.01, "xor8 fp rate should be ~0.4%, got {rate}");
    }

    #[test]
    fn build_is_deterministic() {
        let terms: Vec<u64> = (0..1000).map(|i| term_hash(&format!("t{i}"))).collect();
        let a = Xor8::build(&terms);
        // Same terms, shuffled + duplicated -> identical bytes.
        let mut shuffled = terms.clone();
        shuffled.reverse();
        shuffled.extend_from_slice(&terms[..100]);
        let b = Xor8::build(&shuffled);
        assert_eq!(a.to_bytes(), b.to_bytes(), "any node builds identical filter bytes");
    }

    #[test]
    fn serialization_round_trips() {
        let terms: Vec<u64> = (0..500).map(|i| term_hash(&format!("s{i}"))).collect();
        let f = Xor8::build(&terms);
        let bytes = f.to_bytes();
        let g = Xor8::from_bytes(&bytes).unwrap();
        assert_eq!(f, g);
        for t in &terms {
            assert!(g.contains(*t));
        }
    }

    #[test]
    fn empty_and_tiny_sets() {
        let f = Xor8::build(&[]);
        assert!(!f.contains(term_hash("anything")));
        let one = vec![term_hash("solo")];
        let g = Xor8::build(&one);
        assert!(g.contains(term_hash("solo")));
    }

    #[test]
    fn match_all_fallback_never_false_negatives() {
        // The seed-exhaustion fallback must match EVERY key, otherwise the
        // no-false-negative guarantee inverts. Construct it directly.
        let f = Xor8 { seed: 0, block_length: 0, fingerprints: Vec::new(), match_all: true };
        for i in 0..1000u64 {
            assert!(f.contains(term_hash(&format!("k{i}"))), "match-all must accept every key");
            assert!(f.contains(i.wrapping_mul(0x9E37_79B9_7F4A_7C15)));
        }
    }

    #[test]
    fn match_all_fallback_round_trips() {
        let f = Xor8 { seed: 0, block_length: 0, fingerprints: Vec::new(), match_all: true };
        let bytes = f.to_bytes();
        assert_eq!(bytes, vec![0u8; 16], "canonical all-zero encoding");
        let g = Xor8::from_bytes(&bytes).unwrap();
        assert_eq!(f, g);
        assert!(g.contains(term_hash("anything")));
    }

    #[test]
    fn from_bytes_rejects_malformed_headers() {
        // block_length > 0 but no fingerprints: the old code parsed this and
        // then contains() indexed an empty vec and panicked. Must be None.
        let mut bad = vec![0u8; 16];
        bad[8] = 1; // block_length = 1, len = 0
        assert!(Xor8::from_bytes(&bad).is_none(), "inconsistent header must be rejected");

        // Truncated fingerprints: header self-consistent on length but
        // len != 3 * block_length.
        let mut trunc = vec![0u8; 16];
        trunc[8] = 2; // block_length = 2 -> needs len 6
        trunc[12] = 5; // len = 5
        trunc.extend_from_slice(&[0u8; 5]);
        assert!(Xor8::from_bytes(&trunc).is_none(), "wrong fingerprint count must be rejected");

        // Too short to hold a header.
        assert!(Xor8::from_bytes(&[0u8; 8]).is_none());
    }

    #[test]
    fn skip_decision_is_sound() {
        // The Track-1 use: a segment holding {apple, banana} must never
        // let us skip a query for "apple", and should skip "zebra".
        let seg_terms = vec![term_hash("apple"), term_hash("banana"), term_hash("cherry")];
        let f = Xor8::build(&seg_terms);
        assert!(f.contains(term_hash("apple")), "must not skip a segment that has the term");
        // "zebra" is absent; the filter almost certainly says skip.
        // (Not asserted as always-true since fp is possible, but the
        // soundness direction — never skip a real match — is the one that
        // matters and is guaranteed.)
    }
}
