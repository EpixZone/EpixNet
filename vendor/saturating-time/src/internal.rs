//! Internal parts used for sealing.
//!
//! This module primarily consists of the internal [`SaturatingTime`] trait, an
//! unstable abstraction used internally to implement the main logic behind
//! this.
//!
//! Normal users should not be using this.

use std::{
    cmp,
    sync::LazyLock,
    time::{Duration, Instant, SystemTime},
};

/// The maximum value of [`SystemTime`] for this platform.
static MAX_SYSTEM_TIME: LazyLock<SystemTime> = LazyLock::new(find_max);

/// The minimum value of [`SystemTime`] for this platform.
static MIN_SYSTEM_TIME: LazyLock<SystemTime> = LazyLock::new(find_min);

/// The maximum value of [`Instant`] for this platform.
static MAX_INSTANT: LazyLock<Instant> = LazyLock::new(find_max);

/// The minimum value of [`Instant`] for this platform.
static MIN_INSTANT: LazyLock<Instant> = LazyLock::new(find_min);

/// An internal trait implementing the actual magic behind this.
pub trait SaturatingTime: Sized + Copy + PartialEq {
    /// Anchor method to obtain an instance of this type.
    fn anchor() -> Self;

    /// Returns the maximum value of this type.
    fn max_value() -> Self;

    /// Returns the minimum value of this type.
    fn min_value() -> Self;

    /// Performs a checked addition on this type.
    fn checked_add(&self, duration: Duration) -> Option<Self>;

    /// Performs a checked subtraction on this type.
    fn checked_sub(&self, duration: Duration) -> Option<Self>;

    /// Performs a checked time delta on this type.
    fn checked_duration_since(&self, earlier: Self) -> Option<Duration>;
}

impl SaturatingTime for SystemTime {
    fn anchor() -> Self {
        Self::UNIX_EPOCH
    }

    fn max_value() -> Self {
        *MAX_SYSTEM_TIME
    }

    fn min_value() -> Self {
        *MIN_SYSTEM_TIME
    }

    fn checked_add(&self, duration: Duration) -> Option<Self> {
        Self::checked_add(self, duration)
    }

    fn checked_sub(&self, duration: Duration) -> Option<Self> {
        Self::checked_sub(self, duration)
    }

    fn checked_duration_since(&self, earlier: Self) -> Option<Duration> {
        Self::duration_since(self, earlier).ok()
    }
}

impl SaturatingTime for Instant {
    fn anchor() -> Self {
        use web_time_compat::InstantExt;
        Self::get()
    }

    fn max_value() -> Self {
        *MAX_INSTANT
    }

    fn min_value() -> Self {
        *MIN_INSTANT
    }

    fn checked_add(&self, duration: Duration) -> Option<Self> {
        Self::checked_add(self, duration)
    }

    fn checked_sub(&self, duration: Duration) -> Option<Self> {
        Self::checked_sub(self, duration)
    }

    /// DO NOT USE!
    ///
    /// Instead, override the top-level provided implementation with the already
    /// existing [`Instant::saturating_duration_since()`].
    fn checked_duration_since(&self, _earlier: Self) -> Option<Duration> {
        unreachable!()
    }
}

/// Finds the value for [`SaturatingTime::max_value()`].
fn find_max<T: SaturatingTime>() -> T {
    find_limit(T::checked_add)
}

/// Finds the value for [`SaturatingTime::min_value()`].
fn find_min<T: SaturatingTime>() -> T {
    find_limit(T::checked_sub)
}

/// Internal algorithm of [`find_max()`] and [`find_min()`].
///
/// It works by performing `f` with a very large [`Duration`] onto
/// [`SaturatingTime::anchor()`] until this call returns [`None`], in which case
/// this [`Duration`] gets halved. A successful operation that leaves the value
/// unchanged also halves the step, because clocks can round away small steps.
/// This process stops when a 1ns step cannot make progress.
///
/// # Algorithm
///
/// 1. Set `step` to `INITIAL_STEP` and `res` to [`SaturatingTime::anchor()`].
/// 2. Call `f(&res, step)`.
///     1. If [`Some`] with a different value, set `res` to it and continue.
///     2. Otherwise, if `step == 1ns`, return `res`.
///     3. Else, set `step` to `MAX{1ns, step / 2}` and continue.
///
/// Windows `SystemTime` has 100ns granularity. A smaller step returns
/// `Some(res)` unchanged, rather than overflowing. Without this progress check
/// the limit search never terminates on that platform.
fn find_limit<T, F>(f: F) -> T
where
    T: SaturatingTime,
    F: Fn(&T, Duration) -> Option<T>,
{
    const INITIAL_STEP: Duration = Duration::new(1_000_000_000_000_000_000, 0);
    const ONE_NS: Duration = Duration::new(0, 1);

    // (1) Set step to INITIAL_STEP and res to T::anchor().
    let mut step = INITIAL_STEP;
    let mut res = T::anchor();

    loop {
        // (2) Call f().
        match f(&res, step) {
            Some(next) if next != res => {
                // (2.1) The operation made progress.
                res = next;
            }
            _ => {
                if step == ONE_NS {
                    // (2.2) A 1ns step cannot make progress.
                    return res;
                } else {
                    // (2.3) Else, set step to MAX{1ns, step / 2}.
                    step = cmp::max(ONE_NS, step / 2);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use std::{
        cell::Cell,
        fmt::Debug,
        ops::{Add, Sub},
    };

    use super::*;

    /// A bounded clock with Windows FILETIME's 100ns granularity.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct CoarseTime(u64);

    impl SaturatingTime for CoarseTime {
        fn anchor() -> Self {
            Self(500_000)
        }

        fn max_value() -> Self {
            Self(1_000_000)
        }

        fn min_value() -> Self {
            Self(0)
        }

        fn checked_add(&self, duration: Duration) -> Option<Self> {
            let ticks = u64::try_from(duration.as_nanos() / 100).ok()?;
            let value = self.0.checked_add(ticks)?;
            (value <= Self::max_value().0).then_some(Self(value))
        }

        fn checked_sub(&self, duration: Duration) -> Option<Self> {
            let ticks = u64::try_from(duration.as_nanos() / 100).ok()?;
            self.0.checked_sub(ticks).map(Self)
        }

        fn checked_duration_since(&self, earlier: Self) -> Option<Duration> {
            self.0
                .checked_sub(earlier.0)
                .map(|ticks| Duration::from_nanos(ticks * 100))
        }
    }

    /// Exercise the production search, failing promptly if a no-op spins.
    fn assert_coarse_limit(
        operation: fn(&CoarseTime, Duration) -> Option<CoarseTime>,
        expected: CoarseTime,
    ) {
        let calls = Cell::new(0);
        let rounded_steps = Cell::new(0);
        let actual = find_limit(|current, step| {
            calls.set(calls.get() + 1);
            assert!(calls.get() <= 512, "limit search did not terminate");
            let next = operation(current, step);
            if next == Some(*current) {
                rounded_steps.set(rounded_steps.get() + 1);
            }
            next
        });
        assert!(rounded_steps.get() > 0, "fixture must exercise rounded steps");
        assert_eq!(actual, expected);
    }

    /// A sub-tick addition must converge to the exact maximum, not spin.
    #[test]
    fn coarse_clock_maximum_terminates() {
        assert_coarse_limit(CoarseTime::checked_add, CoarseTime::max_value());
    }

    /// A sub-tick subtraction must converge to the exact minimum, not spin.
    #[test]
    fn coarse_clock_minimum_terminates() {
        assert_coarse_limit(CoarseTime::checked_sub, CoarseTime::min_value());
    }

    /// Checks whether the minimum and maximum values are correct.
    fn min_max<T>()
    where
        T: SaturatingTime
            + PartialEq
            + Debug
            + Add<Duration, Output = T>
            + Sub<Duration, Output = T>,
    {
        assert_eq!(
            T::max_value().checked_add(Duration::ZERO),
            Some(T::max_value())
        );
        assert_eq!(T::max_value().checked_add(Duration::new(0, 1)), None);
        assert_eq!(
            T::max_value().checked_sub(Duration::ZERO),
            Some(T::max_value())
        );
        assert_eq!(
            T::max_value().checked_sub(Duration::new(0, 1)),
            Some(T::max_value() - Duration::new(0, 1))
        );

        assert_eq!(
            T::min_value().checked_sub(Duration::ZERO),
            Some(T::min_value())
        );
        assert_eq!(T::min_value().checked_sub(Duration::new(0, 1)), None);
        assert_eq!(
            T::min_value().checked_add(Duration::ZERO),
            Some(T::min_value())
        );
        assert_eq!(
            T::min_value().checked_add(Duration::new(0, 1)),
            Some(T::min_value() + Duration::new(0, 1))
        );
    }

    /// Verifies [`SystemTime::min_value()`] and [`SystemTime::max_value()`] are
    /// correct.
    ///
    /// These assertions require 1ns precision, unlike Windows FILETIME.
    #[cfg(target_family = "unix")]
    #[test]
    fn system_time_min_max() {
        min_max::<SystemTime>();
    }

    /// Verifies [`Instant::min_value()`] and [`Instant::max_value()`] are
    /// correct.
    #[test]
    fn instant_min_max() {
        min_max::<Instant>();
    }

    /// Verifies [`SystemTime::min_value()`] and [`SystemTime::max_value()`] are
    /// correct on Unix systems.
    #[cfg(target_family = "unix")]
    #[test]
    fn system_time_min_max_unix() {
        assert_eq!(
            SystemTime::max_value(),
            SystemTime::UNIX_EPOCH + Duration::new(i64::MAX as u64, 999_999_999)
        );
        assert_eq!(
            SystemTime::min_value(),
            SystemTime::UNIX_EPOCH - Duration::new(i64::MAX as u64 + 1, 0)
        );
    }

    /// Verifies that [`Instant::min_value()`] and [`Instant::max_value()`] are
    /// correct on Unix systems.
    #[test]
    #[cfg(target_family = "unix")]
    fn instant_min_max_unix() {
        // Using format is not nice but I cannot see a better way for now.
        assert_eq!(
            format!("{:?}", Instant::max_value()),
            format!(
                "Instant {{ tv_sec: {}, tv_nsec: {} }}",
                i64::MAX,
                999_999_999
            )
        );

        assert_eq!(
            format!("{:?}", Instant::min_value()),
            format!("Instant {{ tv_sec: {}, tv_nsec: {} }}", i64::MIN, 0)
        );
    }
}
