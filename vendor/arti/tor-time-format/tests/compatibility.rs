//! The expected values were obtained from the published humantime 2.3.0 and
//! humantime-serde 1.1.1 crates in a separate executable. The corpus includes
//! literal inputs from the Arti 0.47 configuration and directory tests.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::{Duration, UNIX_EPOCH};
use tor_time_format::{
    format_duration, format_rfc3339, format_rfc3339_seconds, parse_duration, parse_rfc3339,
    parse_rfc3339_weak,
};

#[derive(Deserialize)]
struct DurationCase<'a>(
    String,
    Option<u64>,     // Whole seconds
    Option<u32>,     // Additional nanoseconds
    Option<&'a str>, // Canonical configuration string
);

#[test]
fn duration_configuration_and_display_match_published_values() {
    let cases: Vec<DurationCase> =
        serde_json::from_str(include_str!("data/durations.json")).unwrap();
    for DurationCase(input, secs, nanos, canonical) in cases {
        let expected = secs.zip(nanos).map(|(s, ns)| Duration::new(s, ns));
        assert_eq!(parse_duration(&input).ok(), expected, "{input:?}");
        let decoded: Result<Duration, _> = tor_time_format::serde::deserialize(json!(input));
        assert_eq!(decoded.ok(), expected, "serialized input {input:?}");
        if let Some(d) = expected {
            let formatted = format_duration(d).to_string();
            assert_eq!(Some(formatted.as_str()), canonical, "{input:?}");
            assert_eq!(parse_duration(&formatted).unwrap(), d, "{formatted}");
            let serialized =
                tor_time_format::serde::serialize(&d, serde_json::value::Serializer).unwrap();
            assert_eq!(serialized, json!(canonical), "{input:?}");
        }
    }
}

#[derive(Deserialize)]
struct TimestampCase<'a>(
    &'a str,
    bool,            // Accepted by the strict parser
    Option<u64>,     // Unix seconds
    Option<u32>,     // Additional nanoseconds
    Option<&'a str>, // Full UTC timestamp
    Option<&'a str>, // Seconds-only timestamp
);

#[test]
fn timestamp_configuration_and_display_match_published_values() {
    let cases: Vec<TimestampCase> =
        serde_json::from_str(include_str!("data/timestamps.json")).unwrap();
    for TimestampCase(input, strict, secs, nanos, full, seconds) in cases {
        let expected = secs
            .zip(nanos)
            .map(|(s, ns)| UNIX_EPOCH + Duration::new(s, ns));
        assert_eq!(parse_rfc3339_weak(input).ok(), expected, "{input}");
        assert_eq!(
            parse_rfc3339(input).ok(),
            expected.filter(|_| strict),
            "{input}"
        );
        let decoded = tor_time_format::serde::deserialize(json!(input));
        assert_eq!(decoded.ok(), expected, "serialized input {input}");
        if let Some(t) = expected {
            assert_eq!(
                Some(format_rfc3339(t).to_string().as_str()),
                full,
                "{input}"
            );
            assert_eq!(
                Some(format_rfc3339_seconds(t).to_string().as_str()),
                seconds,
                "{input}"
            );
            let serialized =
                tor_time_format::serde::serialize(&t, serde_json::value::Serializer).unwrap();
            assert_eq!(serialized, json!(full), "{input}");
        }
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct TimingConfig {
    #[serde(with = "tor_time_format::serde")]
    retry: Duration,
    #[serde(default, with = "tor_time_format::serde::option")]
    timeout: Option<Duration>,
    #[serde(default, with = "tor_time_format::serde::option")]
    valid_after: Option<std::time::SystemTime>,
}

#[test]
fn optional_configuration_preserves_missing_null_and_populated_fields() {
    let short = json!({"retry": "12 hours"});
    let empty = json!({"retry":"12h", "timeout":null, "valid_after":null});
    for input in [short, empty.clone()] {
        let config: TimingConfig = serde_json::from_value(input).unwrap();
        assert_eq!(config.retry, Duration::from_secs(43_200));
        assert_eq!(config.timeout, None);
        assert_eq!(config.valid_after, None);
        assert_eq!(serde_json::to_value(config).unwrap(), empty);
    }

    let input = json!({"retry":"1hr", "timeout":"1.5s", "valid_after":"2000-02-29 00:00:00"});
    let config: TimingConfig = serde_json::from_value(input).unwrap();
    assert_eq!(config.timeout, Some(Duration::from_millis(1_500)));
    assert_eq!(
        config.valid_after,
        Some(UNIX_EPOCH + Duration::from_secs(951_782_400))
    );
    assert_eq!(
        serde_json::to_value(config).unwrap(),
        json!({"retry":"1h", "timeout":"1s 500ms", "valid_after":"2000-02-29T00:00:00Z"})
    );
}

#[test]
fn serializers_reject_values_of_the_wrong_type() {
    for input in [Value::Null, json!(42), json!(false), json!({}), json!([])] {
        assert!(serde_json::from_value::<TimingConfig>(json!({"retry": input})).is_err());
    }
    for invalid in [
        json!(42),
        json!(false),
        json!({}),
        json!([]),
        json!("yesterday"),
    ] {
        assert!(
            serde_json::from_value::<TimingConfig>(json!({"retry":"0s","timeout":invalid}))
                .is_err()
        );
        assert!(serde_json::from_value::<TimingConfig>(
            json!({"retry":"0s","valid_after":invalid})
        )
        .is_err());
    }
}

#[test]
fn exceeding_max_duration_is_an_error() {
    assert_eq!(
        format_duration(Duration::MAX).to_string(),
        "584542046090years 7months 15days 17h 5m 3s 999ms 999us 999ns"
    );
    for input in [
        "18446744073709551615s1000000000ns",
        "18446744073709551615s999999999ns1ns",
    ] {
        assert!(parse_duration(input).is_err(), "{input}");
    }
}

#[test]
fn timestamps_reject_trailing_text_after_the_zone() {
    for input in [
        "2020-01-01T00:00:00Zjunk",
        "2020-01-01T00:00:00ZZ",
        "2020-01-01T00:00:00+00:00Z",
    ] {
        assert!(parse_rfc3339(input).is_err(), "{input}");
        assert!(parse_rfc3339_weak(input).is_err(), "{input}");
    }
}

#[test]
fn maximum_timestamp_respects_the_target_clock() {
    let last_32bit_second = UNIX_EPOCH + Duration::from_secs(i32::MAX as u64);
    assert_eq!(
        parse_rfc3339("2038-01-19T03:14:07Z").unwrap(),
        last_32bit_second
    );
    let last_utc_second = "9999-12-31T23:59:59Z";
    if cfg!(any(
        target_pointer_width = "64",
        target_os = "windows",
        all(target_arch = "wasm32", not(target_os = "emscripten")),
    )) {
        let timestamp = parse_rfc3339(last_utc_second).unwrap();
        assert_eq!(timestamp, UNIX_EPOCH + Duration::from_secs(253_402_300_799));
        assert_eq!(format_rfc3339(timestamp).to_string(), last_utc_second);
    } else {
        assert!(parse_rfc3339("2038-01-19T03:14:08Z").is_err());
        assert!(parse_rfc3339(last_utc_second).is_err());
    }
}
