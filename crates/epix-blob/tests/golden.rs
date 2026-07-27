//! Golden vectors for the frozen EDX slice format.
//!
//! `golden_vectors.json` pins the byte-level output of outboard creation
//! and verified-slice encoding. If any assertion here fails after a
//! dependency bump or refactor, the wire format changed — that is a spec
//! revision (docs/edx-slice-format.md), never a test update.
//!
//! Regenerate (deliberately!) with:
//!   cargo test -p epix-blob --test golden -- --ignored regenerate

use epix_blob::verified::{encode_slice, OutboardBytes};
use serde_json::{json, Value};
use std::ops::Range;
use std::path::PathBuf;

/// Deterministic test data shared with tests/verified.rs.
fn test_data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
}

/// (size, ranges) cases covering: empty, sub-chunk, chunk boundary ±1,
/// group boundary ±1, multi-group, and a large multi-range seek pattern.
fn cases() -> Vec<(usize, Vec<Range<u64>>)> {
    vec![
        (0, vec![]),
        (1, vec![0..1]),
        (1023, vec![0..1023]),
        (1024, vec![0..1024]),
        (1025, vec![0..1025]),
        (16384, vec![0..16384]),
        (16385, vec![0..16385]),
        (16385, vec![16384..16385]),
        (65536, vec![0..65536]),
        (65536, vec![20000..30000]),
        (262151, vec![0..262151]),
        (262151, vec![10..20000, 100000..100100, 250000..262151]),
    ]
}

fn compute() -> Value {
    let entries: Vec<Value> = cases()
        .into_iter()
        .map(|(size, ranges)| {
            let data = test_data(size);
            let ob = OutboardBytes::from_slice(&data);
            let mut slice = Vec::new();
            encode_slice(&data[..], &ob, &ranges, &mut slice).expect("encode");
            json!({
                "size": size,
                "ranges": ranges.iter().map(|r| json!([r.start, r.end])).collect::<Vec<_>>(),
                "root": ob.root.to_string(),
                "outboard_len": ob.data.len(),
                "outboard_b3": blake3::hash(&ob.data).to_hex().as_str(),
                "slice_len": slice.len(),
                "slice_b3": blake3::hash(&slice).to_hex().as_str(),
            })
        })
        .collect();
    json!({
        "format": "edx-slice-v1",
        "chunk_group_log": epix_blob::CHUNK_GROUP_LOG,
        "data_pattern": "byte[i] = (i * 31) % 251",
        "cases": entries,
    })
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden_vectors.json")
}

#[test]
fn golden_vectors_hold() {
    let committed: Value = serde_json::from_str(
        &std::fs::read_to_string(vectors_path()).expect(
            "tests/golden_vectors.json missing — run the ignored `regenerate` test once",
        ),
    )
    .expect("parse golden_vectors.json");
    let computed = compute();
    assert_eq!(
        committed, computed,
        "EDX slice format output changed — this is a frozen wire format; \
         see docs/edx-slice-format.md before touching anything"
    );
}

#[test]
#[ignore = "writes tests/golden_vectors.json; run only for a deliberate spec revision"]
fn regenerate() {
    let v = compute();
    std::fs::write(
        vectors_path(),
        serde_json::to_string_pretty(&v).unwrap() + "\n",
    )
    .expect("write golden_vectors.json");
}
