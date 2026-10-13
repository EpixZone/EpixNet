use serde_json::{json, Value};

use crate::canonical::{canonical_bytes, python_float_repr};

fn canonical(value: &Value) -> String {
    String::from_utf8(canonical_bytes(value).unwrap()).unwrap()
}

/// The `\uXXXX` escape for one UTF-16 code unit, built at runtime so the
/// expectation text never contains the escape sequence itself.
fn esc(unit: u32) -> String {
    format!("\\u{unit:04x}")
}

#[test]
fn floats_match_python_repr() {
    for (value, expected) in [
        (1e16, "1e+16"),
        (1e15, "1000000000000000.0"),
        (0.0001, "0.0001"),
        (0.00001, "1e-05"),
        (-0.0, "-0.0"),
        (0.0, "0.0"),
        (1.0, "1.0"),
        (0.1, "0.1"),
        (0.1 + 0.2, "0.30000000000000004"),
        (5e-324, "5e-324"),
        (f64::MAX, "1.7976931348623157e+308"),
        (123_456_789.123_456_79, "123456789.12345679"),
        (1e22, "1e+22"),
        (1.5e300, "1.5e+300"),
        (2.5e-10, "2.5e-10"),
        (-1.5e-7, "-1.5e-07"),
        (12_345_678_901_234_567.0, "1.2345678901234568e+16"),
        (1_234_567_890_123_456.7, "1234567890123456.8"),
        (100_000.0, "100000.0"),
        (-100.5, "-100.5"),
    ] {
        assert_eq!(
            python_float_repr(value).as_deref(),
            Some(expected),
            "{value:?}"
        );
    }
    assert!(python_float_repr(f64::NAN).is_none());
    assert!(python_float_repr(f64::INFINITY).is_none());
    assert!(python_float_repr(f64::NEG_INFINITY).is_none());
}

#[test]
fn strings_escape_like_ensure_ascii() {
    let text = "h\u{e9}llo \u{1F600} \u{7f} \"q\" \\ \n\t\u{8}\u{c}\r ~ \u{0} \u{ffff} /";
    let expected = format!(
        "\"h{e9}llo {hi}{lo} {del} \\\"q\\\" \\\\ \\n\\t\\b\\f\\r ~ {nul} {max} /\"",
        e9 = esc(0xe9),
        hi = esc(0xd83d),
        lo = esc(0xde00),
        del = esc(0x7f),
        nul = esc(0),
        max = esc(0xffff),
    );
    assert_eq!(canonical(&json!(text)), expected);
    // Every printable ASCII character other than the quote and backslash is
    // written as itself.
    let printable: String = (0x20u8..=0x7e)
        .map(char::from)
        .filter(|c| *c != '"' && *c != '\\')
        .collect();
    assert_eq!(canonical(&json!(printable)), format!("\"{printable}\""));
    // The supplementary-plane boundary and the largest code point.
    assert_eq!(
        canonical(&json!("\u{10000}")),
        format!("\"{}{}\"", esc(0xd800), esc(0xdc00))
    );
    assert_eq!(
        canonical(&json!("\u{10FFFF}")),
        format!("\"{}{}\"", esc(0xdbff), esc(0xdfff))
    );
}

#[test]
fn keys_sort_by_code_point_without_whitespace() {
    let value =
        json!({"b": 1, "a": [1, 2, {"z": null, "y": true}], "\u{e4}": 2, "A": 3, "~": 4, "_": 5});
    assert_eq!(
        canonical(&value),
        format!(
            "{{\"A\":3,\"_\":5,\"a\":[1,2,{{\"y\":true,\"z\":null}}],\"b\":1,\"~\":4,\"{}\":2}}",
            esc(0xe4)
        )
    );
    assert_eq!(canonical(&json!({})), "{}");
    assert_eq!(canonical(&json!([])), "[]");
    assert_eq!(
        canonical(&json!([1.0, 1, -5, 10.0, true, false, null])),
        "[1.0,1,-5,10.0,true,false,null]"
    );
    assert_eq!(canonical(&json!(u64::MAX)), "18446744073709551615");
    assert_eq!(canonical(&json!(i64::MIN)), "-9223372036854775808");
}

#[test]
fn pathological_nesting_is_refused() {
    let mut value = json!([]);
    for _ in 0..300 {
        value = Value::Array(vec![value]);
    }
    assert!(canonical_bytes(&value).is_err());
    let mut value = json!([]);
    for _ in 0..100 {
        value = Value::Array(vec![value]);
    }
    assert!(canonical_bytes(&value).is_ok());
}
