//! The volunteer responsibility predicate: which encrypted shards a
//! disk-donating node is expected to hold, decided purely from its own
//! account and its byte quota.
//!
//! Pure and local by design (no network, no `epix_crypt` dependency - the
//! account arrives as raw 20 bytes) so it unit-tests here and stays the
//! single source of truth for both what a volunteer PULLs and, later, what
//! a `PushBlock` guard accepts. Multi-volunteer roster runs and DHT
//! discovery are deferred; this decides one node's share on its own.

use crate::ObjId;

/// Domain-separated cache identity for a volunteer, keyed by its 20-byte
/// account. `derive_key` gives a clean 32-byte KDF that takes the 20-byte
/// account directly (`keyed_hash` would need a 32-byte key), and the
/// context string pins it to this use so the same account can key other
/// derivations without colliding.
pub fn cache_id(account20: &[u8; 20]) -> [u8; 32] {
    blake3::derive_key("epix.cache.id.v1", account20)
}

/// A volunteer with `quota` bytes is responsible for `addr` when the top
/// 64 bits of the XOR distance between its `cache_id` and the shard
/// address fall under a threshold proportional to its quota share of the
/// shard universe.
///
/// Monotone in quota: quota 0 is responsible for nothing (matches "0 = not
/// volunteering"); quota >= `universe` is responsible for everything; a
/// larger quota accepts a superset of a smaller one (the threshold only
/// grows). With a uniformly distributed corpus the accepted fraction is
/// about `quota / universe`.
///
/// `universe` is an estimate of total network shard bytes. Nothing on
/// chain or in the DHT sources it in this foundation (discovery is
/// deferred), so callers pass a tuned constant; the predicate is correct
/// and monotone for any positive choice.
pub fn responsible(cache_id: &[u8; 32], addr: ObjId, quota: u64, universe: u64) -> bool {
    if quota == 0 {
        return false;
    }
    // quota >= universe (or a degenerate universe of 0): responsible for
    // everything. Handled explicitly so the "everything" case is exact
    // rather than the saturating-threshold approximation below.
    if universe == 0 || quota >= universe {
        return true;
    }
    let mut d = [0u8; 8];
    for i in 0..8 {
        d[i] = cache_id[i] ^ addr.0[i];
    }
    let dist = u64::from_be_bytes(d); // top 64 bits of the XOR distance
    let frac = quota as f64 / universe as f64; // in (0, 1) here
    // `as u64` saturates, so a frac near 1 maps to a near-full threshold.
    let threshold = (frac * 2f64.powi(64)) as u64;
    dist < threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed account maps to a stable, domain-separated cache id (frozen
    /// vector): if this changes, every volunteer's responsibility set moves.
    #[test]
    fn cache_id_is_stable_and_domain_separated() {
        let acct = [0x11u8; 20];
        let id = cache_id(&acct);
        // Frozen: recomputed by the documented construction.
        assert_eq!(id, blake3::derive_key("epix.cache.id.v1", &acct));
        // Domain separation: the same bytes under another context differ.
        assert_ne!(id, blake3::derive_key("some.other.context", &acct));
        // A different account gives a different id.
        assert_ne!(id, cache_id(&[0x22u8; 20]));
    }

    /// Quota 0 means "not volunteering": responsible for nothing.
    #[test]
    fn quota_zero_is_responsible_for_nothing() {
        let id = cache_id(&[7u8; 20]);
        for i in 0..64u8 {
            let addr = ObjId([i; 32]);
            assert!(!responsible(&id, addr, 0, 1_000_000));
        }
    }

    /// Quota >= universe means "hold everything".
    #[test]
    fn quota_at_or_above_universe_is_responsible_for_everything() {
        let id = cache_id(&[9u8; 20]);
        for i in 0..64u8 {
            let addr = ObjId([i.wrapping_mul(3); 32]);
            assert!(responsible(&id, addr, 1_000, 1_000));
            assert!(responsible(&id, addr, 5_000, 1_000));
        }
    }

    /// A larger quota is responsible for a superset of a smaller one (the
    /// threshold only grows), so raising a donation never drops a shard.
    #[test]
    fn responsibility_is_monotone_in_quota() {
        let id = cache_id(&[42u8; 20]);
        let universe = 1_000_000u64;
        let (small, large) = (100_000u64, 400_000u64);
        for i in 0..2_000u32 {
            let addr = ObjId(*blake3::hash(&i.to_le_bytes()).as_bytes());
            if responsible(&id, addr, small, universe) {
                assert!(
                    responsible(&id, addr, large, universe),
                    "a shard held at the smaller quota must stay held at the larger"
                );
            }
        }
    }

    /// On a uniform corpus the accepted fraction tracks quota/universe.
    #[test]
    fn accepted_fraction_approximates_quota_share() {
        let id = cache_id(&[3u8; 20]);
        let universe = 1_000_000u64;
        let quota = 250_000u64; // ~25%
        let n = 20_000u32;
        let hits = (0..n)
            .filter(|i| {
                let addr = ObjId(*blake3::hash(&i.to_le_bytes()).as_bytes());
                responsible(&id, addr, quota, universe)
            })
            .count();
        let frac = hits as f64 / n as f64;
        assert!((frac - 0.25).abs() < 0.03, "accepted fraction {frac} should be near 0.25");
    }
}
