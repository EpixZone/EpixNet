//! Benchmark - a diagnostics page that times the node's hot paths.
//!
//! Ports EpixNet's `Benchmark` plugin: it runs a fixed suite of micro-benchmarks
//! (HD key derivation, sign/verify, msgpack pack/unpack, gzip pack/unpack, the
//! hash functions, randomness) and reports each one's time against a baseline as
//! a multiplier with a fun title. Here the hot paths are the Rust ones, so the
//! page doubles as a demonstration of the rewrite's speed.
//!
//! Feature-gated behind `benchmark`; off by default.

use sha2::{Digest, Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use std::time::Instant;

/// One benchmark case.
struct Case {
    name: &'static str,
    num: u32,
    /// EpixNet's reference wall-clock for `num` iterations, so the multiplier is
    /// comparable to the Python client.
    standard: f64,
}

/// Run the whole suite and return a plain-text report.
pub fn run(filter: &str) -> String {
    let cases = [
        Case { name: "hd_privatekey", num: 50, standard: 0.57 },
        Case { name: "sign", num: 20, standard: 0.46 },
        Case { name: "verify", num: 200, standard: 0.30 },
        Case { name: "pack_msgpack", num: 100, standard: 0.35 },
        Case { name: "unpack_msgpack", num: 100, standard: 0.35 },
        Case { name: "pack_gz", num: 5, standard: 0.08 },
        Case { name: "unpack_gz", num: 20, standard: 0.28 },
        Case { name: "hash_sha256", num: 10, standard: 0.50 },
        Case { name: "hash_sha512", num: 10, standard: 0.33 },
        Case { name: "hash_sha3_256", num: 10, standard: 0.33 },
        Case { name: "hash_sha3_512", num: 10, standard: 0.65 },
        Case { name: "random", num: 100, standard: 0.08 },
    ];

    let mut out = String::from("\n== Epix benchmark ==\n\n");
    let started = Instant::now();
    let mut multipliers: Vec<f64> = Vec::new();
    for case in &cases {
        if !filter.is_empty() && !case.name.to_lowercase().contains(&filter.to_lowercase()) {
            continue;
        }
        out.push_str(&format!("* Running {} x {} ", case.name, case.num));
        let start = Instant::now();
        run_case(case.name, case.num);
        let taken = start.elapsed().as_secs_f64();
        let mult = case.standard / taken.max(0.001);
        multipliers.push(mult);
        out.push_str(&format!("Done in {taken:.3}s = {} ({mult:.2}x)\n", title(mult)));
    }
    let avg = if multipliers.is_empty() {
        0.0
    } else {
        multipliers.iter().sum::<f64>() / multipliers.len() as f64
    };
    out.push_str(&format!(
        "\n- Total time: {:.3}s\n- Average: {} ({:.2}x)\n",
        started.elapsed().as_secs_f64(),
        title(avg),
        avg,
    ));
    out
}

/// Run one case `num` times, using its work as a black box so it isn't
/// optimized away.
fn run_case(name: &str, num: u32) {
    // A 32-byte hex seed and its derived key/address, reused across crypto cases.
    let seed = "5f5e100000000000000000000000000000000000000000000000000000000001";
    let privatekey = epix_crypt::hd_privatekey(seed, 0).unwrap_or_default();
    let address = epix_crypt::privatekey_to_address(&privatekey).unwrap_or_default();
    let sig = epix_crypt::sign("benchmark", &privatekey).unwrap_or_default();
    // A 1 MiB buffer for the hash/compress cases.
    let blob: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    let gz = gzip(&blob);
    let packed = pack_msgpack(&blob);

    let mut sink: u64 = 0;
    for i in 0..num {
        match name {
            "hd_privatekey" => {
                let k = epix_crypt::hd_privatekey(seed, i as u64).unwrap_or_default();
                sink = sink.wrapping_add(k.len() as u64);
            }
            "sign" => {
                let s = epix_crypt::sign("benchmark", &privatekey).unwrap_or_default();
                sink = sink.wrapping_add(s.len() as u64);
            }
            "verify" => {
                if epix_crypt::verify("benchmark", &address, &sig) {
                    sink = sink.wrapping_add(1);
                }
            }
            "pack_msgpack" => sink = sink.wrapping_add(pack_msgpack(&blob).len() as u64),
            "unpack_msgpack" => sink = sink.wrapping_add(unpack_msgpack(&packed) as u64),
            "pack_gz" => sink = sink.wrapping_add(gzip(&blob).len() as u64),
            "unpack_gz" => sink = sink.wrapping_add(gunzip(&gz).len() as u64),
            "hash_sha256" => sink = sink.wrapping_add(Sha256::digest(&blob)[0] as u64),
            "hash_sha512" => sink = sink.wrapping_add(Sha512::digest(&blob)[0] as u64),
            "hash_sha3_256" => sink = sink.wrapping_add(Sha3_256::digest(&blob)[0] as u64),
            "hash_sha3_512" => sink = sink.wrapping_add(Sha3_512::digest(&blob)[0] as u64),
            "random" => {
                let mut buf = [0u8; 4096];
                let _ = getrandom::fill(&mut buf);
                sink = sink.wrapping_add(buf[0] as u64);
            }
            _ => {}
        }
    }
    // Keep the optimizer honest.
    std::hint::black_box(sink);
}

/// A speed grade for a multiplier, mirroring the reference plugin's titles.
fn title(m: f64) -> &'static str {
    match m {
        _ if m < 0.3 => "Sloooow",
        _ if m < 0.6 => "Ehh",
        _ if m < 0.8 => "Goodish",
        _ if m < 1.2 => "OK",
        _ if m < 1.7 => "Fine",
        _ if m < 2.5 => "Fast",
        _ if m < 3.5 => "WOW",
        _ => "Insane!!",
    }
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    let _ = e.write_all(data);
    e.finish().unwrap_or_default()
}

fn gunzip(data: &[u8]) -> Vec<u8> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut d = GzDecoder::new(data);
    let mut out = Vec::new();
    let _ = d.read_to_end(&mut out);
    out
}

fn pack_msgpack(data: &[u8]) -> Vec<u8> {
    let val = rmpv::Value::Binary(data.to_vec());
    let mut buf = Vec::new();
    let _ = rmpv::encode::write_value(&mut buf, &val);
    buf
}

fn unpack_msgpack(packed: &[u8]) -> usize {
    let mut cur = std::io::Cursor::new(packed);
    match rmpv::decode::read_value(&mut cur) {
        Ok(rmpv::Value::Binary(b)) => b.len(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_covers_filtered_case() {
        let report = run("sha256");
        assert!(report.contains("hash_sha256"));
        assert!(!report.contains("hd_privatekey"));
        assert!(report.contains("Total time"));
    }

    #[test]
    fn msgpack_roundtrips() {
        let data = b"hello benchmark";
        assert_eq!(unpack_msgpack(&pack_msgpack(data)), data.len());
    }

    #[test]
    fn gzip_roundtrips() {
        let data = vec![7u8; 4096];
        assert_eq!(gunzip(&gzip(&data)), data);
    }
}
