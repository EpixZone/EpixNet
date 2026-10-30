//! Distinguish a failed attempt from work suppressed before an attempt began.

use std::fmt;

/// A local reason for deferring work without making a new dial attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferredAttempt {
    NegativeDialCache,
    FailedDialFollower,
}

impl fmt::Display for DeferredAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NegativeDialCache => "recent dial failure (negative cache)",
            Self::FailedDialFollower => "dial in flight failed",
        })
    }
}

/// An actual failure, or a local decision not to make another attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptError<E> {
    Failed(E),
    Deferred(DeferredAttempt),
}

impl<E> AttemptError<E> {
    /// Convert a real failure while preserving the local deferral marker.
    pub fn map_failure<F>(self, map: impl FnOnce(E) -> F) -> AttemptError<F> {
        match self {
            Self::Failed(error) => AttemptError::Failed(map(error)),
            Self::Deferred(reason) => AttemptError::Deferred(reason),
        }
    }
}

impl<E: fmt::Display> fmt::Display for AttemptError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(error) => fmt::Display::fmt(error, f),
            Self::Deferred(reason) => fmt::Display::fmt(reason, f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_changes_only_real_failures() {
        assert_eq!(
            AttemptError::Failed(7).map_failure(|value| value.to_string()),
            AttemptError::Failed("7".to_string())
        );
        for reason in [
            DeferredAttempt::NegativeDialCache,
            DeferredAttempt::FailedDialFollower,
        ] {
            let deferred: AttemptError<u8> = AttemptError::Deferred(reason);
            let mapped: AttemptError<String> = deferred.map_failure(|_| panic!("not a failure"));
            assert_eq!(mapped, AttemptError::Deferred(reason));
        }
    }

    #[test]
    fn legacy_display_does_not_determine_attempt_kind() {
        for (reason, text) in [
            (
                DeferredAttempt::NegativeDialCache,
                "recent dial failure (negative cache)",
            ),
            (DeferredAttempt::FailedDialFollower, "dial in flight failed"),
        ] {
            let deferred: AttemptError<String> = AttemptError::Deferred(reason);
            let failed = AttemptError::Failed(text.to_string());
            assert_eq!(deferred.to_string(), text);
            assert_eq!(failed.to_string(), text);
            assert_ne!(deferred, failed);
        }
    }
}
