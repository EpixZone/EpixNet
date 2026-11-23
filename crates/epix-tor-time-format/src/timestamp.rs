use crate::ParseError;
use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const INVALID: ParseError = ParseError("expected a UTC timestamp");
const RANGE: ParseError = ParseError("timestamp is out of range");

/// Parse the UTC representation used in Tor state files.
pub fn parse_rfc3339(value: &str) -> Result<SystemTime, ParseError> {
    if value.as_bytes().get(10) != Some(&b'T')
        || !(value.ends_with('Z') || value.ends_with("+00:00"))
    {
        return Err(INVALID);
    }
    parse_rfc3339_weak(value)
}

/// Configuration also accepts a space between date and time and an implicit UTC offset.
pub fn parse_rfc3339_weak(value: &str) -> Result<SystemTime, ParseError> {
    let local = value
        .strip_suffix('Z')
        .or_else(|| value.strip_suffix("+00:00"))
        .unwrap_or(value);
    if !local.is_ascii() || local.len() < 19 || !matches!(local.as_bytes()[10], b' ' | b'T') {
        return Err(INVALID);
    }
    let mut normalized = String::with_capacity(30);
    normalized.push_str(&local[..10]);
    normalized.push('T');
    normalized.push_str(&local[11..17]);
    // Arti maps a leap second to second 59 on the POSIX clock.
    normalized.push_str(if &local[17..19] == "60" {
        "59"
    } else {
        &local[17..19]
    });
    if let Some(frac) = local[19..].strip_prefix('.') {
        if !frac.bytes().all(|c| c.is_ascii_digit()) {
            return Err(INVALID);
        }
        if !frac.is_empty() {
            normalized.push('.');
            normalized.push_str(&frac[..frac.len().min(9)]);
        }
    } else if local.len() != 19 {
        return Err(INVALID);
    }
    normalized.push('Z');
    let instant = OffsetDateTime::parse(&normalized, &Rfc3339).map_err(|_| INVALID)?;
    let seconds = u64::try_from(instant.unix_timestamp()).map_err(|_| RANGE)?;
    #[cfg(all(
        target_pointer_width = "32",
        not(target_os = "windows"),
        not(all(target_arch = "wasm32", not(target_os = "emscripten")))
    ))]
    if seconds > i32::MAX as u64 {
        return Err(RANGE);
    }
    UNIX_EPOCH
        .checked_add(Duration::new(seconds, instant.nanosecond()))
        .ok_or(RANGE)
}

struct Timestamp {
    value: SystemTime,
    seconds_only: bool,
}

/// Print nonzero subseconds with all nine digits, matching persisted Tor state.
pub fn format_rfc3339(value: SystemTime) -> impl fmt::Display {
    Timestamp {
        value,
        seconds_only: false,
    }
}

/// Print whole UTC seconds, as required by Tor protocol and state fields.
pub fn format_rfc3339_seconds(value: SystemTime) -> impl fmt::Display {
    Timestamp {
        value,
        seconds_only: true,
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let duration = self
            .value
            .duration_since(UNIX_EPOCH)
            .map_err(|_| fmt::Error)?;
        let secs = i64::try_from(duration.as_secs()).map_err(|_| fmt::Error)?;
        let utc = OffsetDateTime::from_unix_timestamp(secs).map_err(|_| fmt::Error)?;
        write!(
            out,
            "{}T{:02}:{:02}:{:02}",
            utc.date(),
            utc.hour(),
            utc.minute(),
            utc.second()
        )?;
        if !self.seconds_only && duration.subsec_nanos() != 0 {
            write!(out, ".{:09}", duration.subsec_nanos())?;
        }
        out.write_str("Z")
    }
}
