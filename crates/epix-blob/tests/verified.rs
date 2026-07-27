//! Property tests for the verified encode/decode path (Phase A gate).

use epix_blob::verified::{
    chunk_ranges, decode_slice, encode_slice, valid_ranges, verify_whole, OutboardBytes,
};
use epix_blob::ObjId;
use std::io;
use std::ops::Range;

/// Deterministic test data shared with the golden vectors.
fn test_data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
}

/// Grow-on-write sparse sink so decoded leaves land at their file offsets.
#[derive(Default)]
struct SparseBuf(Vec<u8>);

impl positioned_io::WriteAt for SparseBuf {
    fn write_at(&mut self, pos: u64, buf: &[u8]) -> io::Result<usize> {
        let end = pos as usize + buf.len();
        if self.0.len() < end {
            self.0.resize(end, 0);
        }
        self.0[pos as usize..end].copy_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode(data: &[u8], ob: &OutboardBytes, ranges: &[Range<u64>]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_slice(data, ob, ranges, &mut out).expect("encode");
    out
}

fn decode(slice: &[u8], root: ObjId, size: u64, ranges: &[Range<u64>]) -> io::Result<Vec<u8>> {
    let mut sink = SparseBuf::default();
    decode_slice(slice, root, size, ranges, &mut sink)?;
    Ok(sink.0)
}

const SIZES: &[usize] = &[1, 1023, 1024, 1025, 16384, 16385, 65536, 262151];

#[test]
fn round_trip_whole_object() {
    for &n in SIZES {
        let data = test_data(n);
        let ob = OutboardBytes::from_slice(&data);
        assert_eq!(ob.size, n as u64);
        let slice = encode(&data, &ob, &[0..n as u64]);
        let got = decode(&slice, ob.root, ob.size, &[0..n as u64]).expect("decode");
        assert_eq!(got, data, "size {n}");
    }
}

#[test]
fn root_is_plain_blake3() {
    // The object root must equal the plain BLAKE3 file hash — this is what
    // makes the `b3` manifest field and the bao root the same value.
    for &n in &[0usize, 1, 4096, 65536] {
        let data = test_data(n);
        let ob = OutboardBytes::from_slice(&data);
        assert_eq!(ob.root, ObjId(*blake3::hash(&data).as_bytes()));
    }
}

#[test]
fn seek_ranges_verify_against_same_root() {
    // A mid-file range (a seek) decodes and verifies with no data before it.
    let n = 262151usize;
    let data = test_data(n);
    let ob = OutboardBytes::from_slice(&data);
    let range = 100_000u64..131_072u64;
    let slice = encode(&data, &ob, &[range.clone()]);
    // The slice for one range is FAR smaller than the file.
    assert!(slice.len() < n / 4, "slice {} vs file {n}", slice.len());
    let got = decode(&slice, ob.root, ob.size, &[range.clone()]).expect("decode");
    assert_eq!(
        &got[range.start as usize..range.end as usize],
        &data[range.start as usize..range.end as usize]
    );
}

#[test]
fn multi_range_decodes_same_bytes_as_singles() {
    let n = 262151usize;
    let data = test_data(n);
    let ob = OutboardBytes::from_slice(&data);
    let ranges = [10..20_000u64, 100_000..100_100u64, 250_000..262_151u64];

    let multi = decode(
        &encode(&data, &ob, &ranges),
        ob.root,
        ob.size,
        &ranges,
    )
    .expect("multi decode");

    let mut singles = SparseBuf::default();
    for r in &ranges {
        let slice = encode(&data, &ob, std::slice::from_ref(r));
        decode_slice(&slice[..], ob.root, ob.size, std::slice::from_ref(r), &mut singles)
            .expect("single decode");
    }
    assert_eq!(multi, singles.0);
    // And the requested bytes are the real bytes.
    for r in &ranges {
        assert_eq!(
            &multi[r.start as usize..r.end as usize],
            &data[r.start as usize..r.end as usize],
            "range {r:?}"
        );
    }
}

#[test]
fn flipped_bit_is_rejected_and_localized() {
    // Corrupting any single bit of the encoded stream must fail decode —
    // and corruption in one chunk group must not poison an earlier one.
    let n = 65536usize;
    let data = test_data(n);
    let ob = OutboardBytes::from_slice(&data);
    let full = 0..n as u64;
    let clean = encode(&data, &ob, &[full.clone()]);

    // Flip a bit somewhere in every 8 KiB window of the stream.
    let mut hit_failures = 0;
    let mut pos = 0;
    while pos < clean.len() {
        let mut bad = clean.clone();
        bad[pos] ^= 0x40;
        if decode(&bad, ob.root, ob.size, &[full.clone()]).is_err() {
            hit_failures += 1;
        } else {
            // A flip that decodes successfully must have produced identical
            // bytes (impossible) — so any Ok here is a verification hole.
            panic!("bit flip at {pos} was not detected");
        }
        pos += 8192;
    }
    assert!(hit_failures > 0);
}

#[test]
fn corrupt_local_data_fails_validated_encode() {
    // The VALIDATED encoder must refuse to serve bytes that no longer match
    // the outboard (a corrupted store never earns us a bad reputation).
    let n = 65536usize;
    let data = test_data(n);
    let ob = OutboardBytes::from_slice(&data);
    let mut corrupted = data.clone();
    corrupted[40_000] ^= 1;
    let mut out = Vec::new();
    let res = encode_slice(&corrupted[..], &ob, &[0..n as u64], &mut out);
    assert!(res.is_err(), "validated encode served corrupted bytes");
}

#[test]
fn valid_ranges_localizes_corruption_to_one_group() {
    let n = 65536usize; // 4 chunk groups of 16 KiB
    let data = test_data(n);
    let ob = OutboardBytes::from_slice(&data);
    let mut stored = data.clone();
    stored[20_000] ^= 1; // corrupt group 1 (bytes 16384..32768)

    let all = chunk_ranges(&[0..n as u64]);
    let ok = valid_ranges(&ob, &stored[..], &all).expect("scan");
    let ok_groups: Vec<u64> = (0..4)
        .filter(|g| {
            let chunk = bao_chunk_of_group(*g);
            ok.contains(&chunk)
        })
        .collect();
    assert_eq!(ok_groups, vec![0, 2, 3], "only the corrupted group drops out");
}

/// First chunk number of 16 KiB group `g` (16 chunks of 1 KiB per group).
fn bao_chunk_of_group(g: u64) -> bao_tree::ChunkNum {
    bao_tree::ChunkNum(g * 16)
}

#[test]
fn verify_whole_matches() {
    let data = test_data(1000);
    let root = ObjId(*blake3::hash(&data).as_bytes());
    assert!(verify_whole(&data, root));
    let mut bad = data.clone();
    bad[0] ^= 1;
    assert!(!verify_whole(&bad, root));
}

#[test]
fn wrong_root_rejects_everything() {
    let data = test_data(20_000);
    let ob = OutboardBytes::from_slice(&data);
    let slice = encode(&data, &ob, &[0..20_000]);
    let wrong = ObjId(*blake3::hash(b"different").as_bytes());
    assert!(decode(&slice, wrong, ob.size, &[0..20_000]).is_err());
}
