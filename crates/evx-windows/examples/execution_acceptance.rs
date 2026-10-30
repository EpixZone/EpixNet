//! Native Windows compile/run acceptance. Does not enable product admission.
#[cfg(windows)]
fn main() -> std::io::Result<()> {
    use evx_windows::{TrustedWorker, WindowsExecutor};
    use sha2::{Digest, Sha256};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let built_worker = std::env::current_exe()?
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("evx-windows-worker.exe");
    // Cargo hard-links top-level binaries to its dependency artifacts. Model
    // installation with an owned, single-link copy before pinning the worker.
    let installation = tempfile::tempdir()?;
    let path = installation.path().join("evx-windows-worker.exe");
    std::fs::copy(built_worker, &path)?;
    let hash = hex::encode(Sha256::digest(std::fs::read(&path)?));
    let linked = installation.path().join("linked-worker.exe");
    std::fs::hard_link(&path, &linked)?;
    assert!(
        TrustedWorker::open(&path, &hash).is_err(),
        "hard-linked workers must be rejected"
    );
    std::fs::remove_file(linked)?;
    assert!(TrustedWorker::open(&path, &"0".repeat(64)).is_err());
    let executor = WindowsExecutor::new(TrustedWorker::open(&path, &hash)?);
    let cancel = Arc::new(AtomicBool::new(false));
    let mut limits = evx_api::Limits {
        wall_seconds: 15.0,
        host_call_seconds: 2.0,
        process_cpu_seconds: 10.0,
        process_rss_bytes: 512 * 1024 * 1024,
        ..evx_api::Limits::default()
    };
    let module = evx_runtime::text_to_binary(
        r#"(module (memory (export "memory") 1)
        (func (export "run") (result i32) i32.const 42))"#,
    )
    .unwrap();
    let (compiled, compile_usage) = executor.compile(&module, &limits, &cancel)?;
    let (result, run_usage) = executor.run(&compiled, &limits, &cancel, |_| {
        panic!("unexpected host call")
    })?;
    assert_eq!(result.status, evx_api::frames::WorkerStatus::Ok);
    assert_eq!(result.value, Some(42));
    // Windows accounting can report zero for work shorter than a sampling
    // tick. Real output and memory evidence prove this compilation ran; the
    // native CPU-loop fixture independently checks CPU accounting and limits.
    assert!(compile_usage.peak_resident_bytes > 0);
    assert!(run_usage.peak_resident_bytes > 0);
    println!(
        "PASS real confined Wasm compile/run: compiler={compile_usage:?}, guest={run_usage:?}"
    );
    let request = br#"{"op":"game.score.get"}"#;
    let escaped: String = request.iter().map(|byte| format!("\\{byte:02x}")).collect();
    let module=evx_runtime::text_to_binary(&format!(r#"(module
        (import "evx" "call" (func $call (param i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1) (data (i32.const 0) "{escaped}")
        (func (export "run") (result i32) i32.const 0 i32.const {} i32.const 4096 i32.const 4096 call $call))"#,request.len())).unwrap();
    let (compiled, _) = executor.compile(&module, &limits, &cancel)?;
    let mut calls = 0;
    let (result, _) = executor.run(&compiled, &limits, &cancel, |bytes| {
        assert_eq!(
            evx_api::Request::decode(bytes).unwrap(),
            evx_api::Request::GameScoreGet
        );
        calls += 1;
        Ok(serde_json::to_vec(&evx_api::Response::Score { ok: true, score: 7 }).unwrap())
    })?;
    assert_eq!(calls, 1);
    assert_eq!(result.status, evx_api::frames::WorkerStatus::Ok);
    println!("PASS bounded evx.call roundtrip");
    let infinite = evx_runtime::text_to_binary(
        r#"(module (memory (export "memory") 1)
        (func (export "run") (result i32) (loop $again br $again) i32.const 0))"#,
    )
    .unwrap();
    let (compiled, _) = executor.compile(&infinite, &limits, &cancel)?;
    limits.fuel = 1_000_000_000_000;
    let signal = cancel.clone();
    let cancel_thread = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        signal.store(true, Ordering::Release);
    });
    assert!(executor
        .run(&compiled, &limits, &cancel, |_| panic!(
            "unexpected host call"
        ))
        .is_err());
    cancel_thread.join().unwrap();
    cancel.store(false, Ordering::Release);
    // A successful next invocation proves normal cancellation cleared only
    // after process and empty-job observations, without resetting quarantine.
    let (compiled, _) = executor.compile(&module, &limits, &cancel)?;
    let (result, _) = executor.run(&compiled, &limits, &cancel, |_| {
        Ok(br#"{"ok":true,"score":7}"#.to_vec())
    })?;
    assert_eq!(result.status, evx_api::frames::WorkerStatus::Ok);
    println!("PASS cancellation followed by fresh confined invocation");
    println!("PASS Windows real-runtime fixture; node and filesystem admission remain disabled");
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    panic!("native Windows acceptance requires Windows");
}
