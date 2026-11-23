//! Serde adapters for the textual time fields in Arti configuration and state.
use super::{format_duration, format_rfc3339, parse_duration, parse_rfc3339_weak, ParseError};
use ::serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt,
    time::{Duration, SystemTime},
};

#[doc(hidden)]
pub trait TimeText: Copy {
    fn parse_text(input: &str) -> Result<Self, ParseError>;
    fn formatted(self) -> impl fmt::Display;
}

impl TimeText for Duration {
    fn parse_text(input: &str) -> Result<Self, ParseError> {
        parse_duration(input)
    }
    fn formatted(self) -> impl fmt::Display {
        format_duration(self)
    }
}

impl TimeText for SystemTime {
    fn parse_text(input: &str) -> Result<Self, ParseError> {
        parse_rfc3339_weak(input)
    }
    fn formatted(self) -> impl fmt::Display {
        format_rfc3339(self)
    }
}

pub fn serialize<S: Serializer, T: TimeText>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&value.formatted())
}

pub fn deserialize<'de, D: Deserializer<'de>, T: TimeText>(deserializer: D) -> Result<T, D::Error> {
    T::parse_text(&String::deserialize(deserializer)?).map_err(D::Error::custom)
}

/// A missing optional time is encoded as a null value. Present times use the same text as required fields.
pub mod option {
    use super::*;

    pub fn serialize<S: Serializer, T: TimeText>(
        value: &Option<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .map(|time| time.formatted().to_string())
            .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: TimeText>(
        deserializer: D,
    ) -> Result<Option<T>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .as_deref()
            .map(T::parse_text)
            .transpose()
            .map_err(D::Error::custom)
    }
}
