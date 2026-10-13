//! Consumes private, freshly generated fixtures from the compiler build.
//! No publisher bytes are deserialized. The Python driver owns both builds.
#![cfg(all(feature = "pulley", not(feature = "compiler")))]

use evx_api::{frames::WorkerStatus, Limits};
use evx_runtime::{HostCalls, HostError, RunOptions};
use std::path::Path;

struct Score;
impl HostCalls for Score {
    fn call(&mut self, request: &[u8]) -> Result<Vec<u8>, HostError> {
        assert_eq!(request, br#"{"op":"game.score.get"}"#);
        Ok(br#"{"score":42}"#.to_vec())
    }
}

fn execute(dir: &Path, name: &str, limits: Limits) -> evx_runtime::ExecReport {
    let artifact = std::fs::read(dir.join(format!("{name}.artifact"))).unwrap();
    let options = RunOptions {
        limits,
        artifact_sha256: std::fs::read_to_string(dir.join(format!("{name}.sha256"))).unwrap(),
        engine_key: std::fs::read_to_string(dir.join(format!("{name}.engine"))).unwrap(),
    };
    // SAFETY: the dedicated test driver generated these exact bytes from fixed
    // Wasm using our compiler in its private directory. This is a local engine
    // compatibility test, not an admission path for downloaded artifacts.
    unsafe { evx_runtime::run(&artifact, &options, Box::new(Score)) }
}

#[test]
#[ignore = "requires scripts/test-evx-pulley-runtime.py to generate trusted local artifacts"]
fn compiler_free_pulley_preserves_execution_limits_and_broker_abi() {
    assert!(evx_runtime::new_engine().unwrap().is_pulley());
    let directory =
        std::env::var_os("EVX_TRUSTED_PULLEY_TEST_DIR").expect("private local fixtures");
    let dir = Path::new(&directory);
    let score = execute(dir, "score", Limits::default());
    assert_eq!(score.result.status, WorkerStatus::Ok, "{:?}", score.result);
    assert_eq!(score.result.value, Some(42));
    assert!(score.result.fuel_used > 0);
    let exhausted = execute(dir, "loop", Limits::default());
    assert_eq!(exhausted.result.status, WorkerStatus::Error);
    assert!(exhausted.result.error.unwrap().contains("fuel"));
    let limits = Limits {
        fuel: 1_000_000_000_000,
        wall_seconds: 0.1,
        ..Limits::default()
    };
    let deadline = execute(dir, "loop", limits);
    assert_eq!(deadline.result.status, WorkerStatus::Error);
    assert!(deadline.result.error.unwrap().contains("deadline"));
    let limits = Limits {
        memory_bytes: 65536,
        ..Limits::default()
    };
    let growth = execute(dir, "grow", limits);
    assert_eq!(growth.result.status, WorkerStatus::Ok);
    assert_eq!(growth.result.value, Some(-1));
    assert_eq!(growth.result.memory_bytes, 65536);
    let broker = execute(dir, "broker", Limits::default());
    assert_eq!(broker.result.status, WorkerStatus::Ok);
    assert_eq!(broker.result.value, Some(12));
    assert_eq!(broker.result.host_calls, 1);
}
