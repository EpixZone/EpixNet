use crate::ParseError;
use std::{fmt, time::Duration};
use winnow::{
    combinator::{opt, preceded},
    token::take_while,
    ModalResult, Parser,
};

const SECOND: u64 = 1_000_000_000;
const MINUTE: u64 = 60 * SECOND;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;
// Arti's text formats express months and years as fixed durations.
const MONTH: u64 = 2_630_016 * SECOND;
const YEAR: u64 = 31_557_600 * SECOND;
const RANGE: ParseError = ParseError("duration is out of range or loses precision");

fn unit_nanos(suffix: &str) -> Result<u64, ParseError> {
    match suffix {
        "ns" | "nsec" | "nanos" => Ok(1),
        "us" | "µs" | "usec" => Ok(1_000),
        "ms" | "msec" | "millis" => Ok(1_000_000),
        "s" | "sec" | "secs" | "second" | "seconds" => Ok(SECOND),
        "m" | "min" | "mins" | "minute" | "minutes" => Ok(MINUTE),
        "h" | "hr" | "hrs" | "hour" | "hours" => Ok(HOUR),
        "d" | "day" | "days" => Ok(DAY),
        "w" | "wk" | "wks" | "week" | "weeks" => Ok(7 * DAY),
        "M" | "month" | "months" => Ok(MONTH),
        "y" | "yr" | "yrs" | "year" | "years" => Ok(YEAR),
        _ => Err(ParseError("unknown duration unit")),
    }
}

fn digits<'a>(input: &mut &'a str) -> ModalResult<&'a str> {
    take_while(1.., |c: char| c.is_ascii_digit() || c.is_whitespace()).parse_next(input)
}

fn decimal(group: &str) -> Result<u64, ParseError> {
    group
        .chars()
        .filter(|c| !c.is_whitespace())
        .try_fold(0u64, |value, c| {
            value
                .checked_mul(10)?
                .checked_add(u64::from(c.to_digit(10)?))
        })
        .ok_or(RANGE)
}

fn whole_duration(digits: &str, nanos_per_unit: u64) -> Result<Duration, ParseError> {
    let value = decimal(digits)?;
    if nanos_per_unit < SECOND {
        Ok(Duration::from_nanos(
            value.checked_mul(nanos_per_unit).ok_or(RANGE)?,
        ))
    } else {
        Ok(Duration::from_secs(
            value.checked_mul(nanos_per_unit / SECOND).ok_or(RANGE)?,
        ))
    }
}

fn fraction_nanos(digits: &str, nanos_per_unit: u64) -> Result<u64, ParseError> {
    let places = digits.chars().filter(char::is_ascii_digit).count();
    if places == 0 || nanos_per_unit == 1 {
        return Err(RANGE);
    }
    let denominator = 10u64
        .checked_pow(places.try_into().map_err(|_| RANGE)?)
        .ok_or(RANGE)?;
    // The stored grammar permits fractions of hours and larger units only
    // when they denote whole seconds. Smaller units must resolve to whole ns.
    let resolution = if nanos_per_unit >= HOUR { SECOND } else { 1 };
    let numerator = decimal(digits)?
        .checked_mul(nanos_per_unit / resolution)
        .ok_or(RANGE)?;
    if numerator % denominator != 0 {
        return Err(RANGE);
    }
    Ok(numerator / denominator * resolution)
}

/// Read a sequence of nonnegative, unit-suffixed values from Arti configuration.
pub fn parse_duration(text: &str) -> Result<Duration, ParseError> {
    if text == "0" {
        return Ok(Duration::ZERO);
    }
    let mut input = text.trim();
    if input.is_empty() {
        return Err(ParseError("empty duration"));
    }
    let mut duration = Duration::ZERO;
    while !input.is_empty() {
        let integer = digits(&mut input).map_err(|_| ParseError("expected a duration value"))?;
        let fraction = opt(preceded('.', digits))
            .parse_next(&mut input)
            .map_err(|_| ParseError("expected a decimal fraction"))?;
        let suffix: &str = take_while::<_, _, winnow::error::ContextError>(1.., |c: char| {
            c.is_ascii_alphabetic() || c == 'µ'
        })
        .parse_next(&mut input)
        .map_err(|_| ParseError("expected a duration unit"))?;
        let unit = unit_nanos(suffix)?;
        duration = duration
            .checked_add(whole_duration(integer, unit)?)
            .ok_or(RANGE)?;
        if let Some(fraction) = fraction {
            let partial = Duration::from_nanos(fraction_nanos(fraction, unit)?);
            duration = duration.checked_add(partial).ok_or(RANGE)?;
        }
        input = input.trim_start();
    }
    Ok(duration)
}

pub struct FormattedDuration(Duration);

/// Print the duration using the spellings understood by older Arti releases.
pub fn format_duration(value: Duration) -> FormattedDuration {
    FormattedDuration(value)
}

impl fmt::Display for FormattedDuration {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut remaining = self.0.as_nanos();
        if remaining == 0 {
            return out.write_str("0s");
        }
        let mut separator = "";
        for (unit, label) in [
            (YEAR, "year"),
            (MONTH, "month"),
            (DAY, "day"),
            (HOUR, "h"),
            (MINUTE, "m"),
            (SECOND, "s"),
            (1_000_000, "ms"),
            (1_000, "us"),
            (1, "ns"),
        ] {
            let amount = remaining / u128::from(unit);
            if amount > 0 {
                let plural = if unit >= DAY && amount > 1 { "s" } else { "" };
                write!(out, "{separator}{amount}{label}{plural}")?;
                separator = " ";
                remaining %= u128::from(unit);
            }
        }
        Ok(())
    }
}
