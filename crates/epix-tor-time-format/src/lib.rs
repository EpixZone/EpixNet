//! Time formats used in Arti configuration, guard state and onion service records.

mod duration;
pub mod serde;
mod timestamp;

pub use duration::{format_duration, parse_duration, FormattedDuration};
pub use timestamp::{format_rfc3339, format_rfc3339_seconds, parse_rfc3339, parse_rfc3339_weak};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseError(&'static str);

impl std::fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ParseError {}

pub type DurationError = ParseError;
