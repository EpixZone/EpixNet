//! Synthetic hostile IPC peer for the supervisor's adversarial tests.
//!
//! The IPC suite launches this binary in place of `evx-worker` and it speaks
//! the length-prefixed frame protocol wrongly on purpose: malformed JSON,
//! duplicate keys, non-finite numbers, truncated and oversized frames, floods,
//! forged measurements, control characters, and messages after a terminal
//! result. The supervisor must fail closed on every mode and must never trust
//! anything this peer reports about its own resource use.
//!
//! It is an example target so it is built for tests but is never part of the
//! supervisor library or any shipped binary. Only the trusted test harness
//! selects it, through `Config::worker_args`.
//!
//! Usage: `hostile_peer <mode> run` (the supervisor appends the mode name).

use std::io::{Read, Write};

fn raw(bytes: &[u8]) {
    let mut out = std::io::stdout().lock();
    out.write_all(bytes).expect("stdout");
    out.flush().expect("stdout");
}

fn frame(body: &[u8]) {
    let mut encoded = (body.len() as u32).to_be_bytes().to_vec();
    encoded.extend_from_slice(body);
    raw(&encoded);
}

fn result(extra: &str) {
    frame(format!(r#"{{"type":"result","status":"ok","value":42{extra}}}"#).as_bytes());
}

fn consume_init() {
    let mut stdin = std::io::stdin().lock();
    let mut len = [0u8; 4];
    if stdin.read_exact(&mut len).is_ok() {
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        let _ = stdin.read_exact(&mut body);
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    consume_init();
    match mode.as_str() {
        "bad_json" => frame(br#"{"type":"#),
        "duplicate_field" => frame(br#"{"type":"result","type":"call"}"#),
        "nonfinite" => frame(br#"{"type":"result","status":"ok","value":42,"elapsed_ms":1e999}"#),
        "truncated" => {
            let mut bytes = 40u32.to_be_bytes().to_vec();
            bytes.extend_from_slice(br#"{"type":"#);
            raw(&bytes);
        }
        "oversize" => {
            raw(&(300u32 * 1024).to_be_bytes());
            raw(&vec![b'x'; 300 * 1024]);
        }
        "stderr_flood" => {
            let mut err = std::io::stderr().lock();
            for _ in 0..128 {
                err.write_all(&[b'x'; 4096]).expect("stderr");
            }
            err.flush().expect("stderr");
            drop(err);
            result("");
        }
        "bad_type" => frame(br#"["result"]"#),
        "bad_value" => frame(br#"{"type":"result","status":"ok","value":true}"#),
        "missing_value" => frame(br#"{"type":"result","status":"ok"}"#),
        "extra_authority" => frame(br#"{"type":"call","request":"e30=","xite":"game-b"}"#),
        "invalid_base64" => frame(br#"{"type":"call","request":"$!"}"#),
        "after_result" => {
            result("");
            // base64 of {"op":"workspace.write","path":"must-not-exist","text":"no"}
            frame(
                br#"{"type":"call","request":"eyJvcCI6IndvcmtzcGFjZS53cml0ZSIsInBhdGgiOiJtdXN0LW5vdC1leGlzdCIsInRleHQiOiJubyJ9"}"#,
            );
        }
        "duplicate_result" => {
            result("");
            result("");
        }
        "failed_exit" => {
            result("");
            std::process::exit(7);
        }
        "false_cpu" => {
            result(r#","elapsed_ms":0"#);
            let mut counter = 0u64;
            loop {
                counter = std::hint::black_box(counter.wrapping_add(1));
            }
        }
        "false_rss" => {
            result(r#","memory_bytes":0"#);
            let mut blocks: Vec<Vec<u8>> = Vec::new();
            for _ in 0..64 {
                // Non-zero fill so every page is actually resident.
                blocks.push(std::hint::black_box(vec![1u8; 1024 * 1024]));
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            loop {
                std::thread::sleep(std::time::Duration::from_millis(100));
                std::hint::black_box(&blocks);
            }
        }
        "diagnostics" => {
            let mut err = std::io::stderr().lock();
            err.write_all("test\x1b[31m\0\u{202e}evil".as_bytes())
                .expect("stderr");
            err.flush().expect("stderr");
            drop(err);
            result("");
        }
        "environment" => {
            let leaked = i32::from(std::env::var_os("EVX_TEST_SECRET").is_some());
            frame(format!(r#"{{"type":"result","status":"ok","value":{leaked}}}"#).as_bytes());
        }
        "frame_flood" => {
            for _ in 0..200 {
                frame(br#"{"type":"call","request":"e30="}"#);
            }
        }
        _ => std::process::exit(2),
    }
}
