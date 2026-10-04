use evx_api::{
    frames::{FromWorker, WorkerResult, WorkerStatus},
    Limits,
};
use evx_runtime::{HostCalls, HostError};
use std::sync::{Arc, Mutex};

struct Host {
    calls: Arc<Mutex<Vec<Vec<u8>>>>,
    response: Vec<u8>,
}
impl HostCalls for Host {
    fn call(&mut self, request: &[u8]) -> Result<Vec<u8>, HostError> {
        self.calls.lock().unwrap().push(request.to_vec());
        Ok(self.response.clone())
    }
}
fn wasm(body: &str) -> Vec<u8> {
    wat::parse_str(format!(
        "(module (memory (export \"memory\") 1) (func (export \"run\") (result i32) {body}))"
    ))
    .unwrap()
}
fn call_wasm(request: &str, calls: usize) -> Vec<u8> {
    let data: String = request.bytes().map(|b| format!("\\{b:02x}")).collect();
    let call = format!(
        "i32.const 0 i32.const {} i32.const 4096 i32.const 4096 call $call",
        request.len()
    );
    let repeated = format!("{}{}", format!("{call} drop ").repeat(calls - 1), call);
    wat::parse_str(format!("(module (import \"evx\" \"call\" (func $call (param i32 i32 i32 i32) (result i32))) (memory (export \"memory\") 1) (data (i32.const 0) \"{data}\") (func (export \"run\") (result i32) {repeated}))")).unwrap()
}
fn execute(module: &[u8], limits: Limits, response: Vec<u8>) -> (WorkerResult, usize) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let host = Host {
        calls: calls.clone(),
        response,
    };
    let frame = evx_android::execute_module(
        module,
        &serde_json::to_vec(&limits).unwrap(),
        Box::new(host),
    )
    .unwrap();
    assert_eq!(
        u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
        frame.len() - 4
    );
    let FromWorker::Result(result) = evx_api::strict::parse_typed(&frame[4..]).unwrap() else {
        panic!("wrong frame");
    };
    let count = calls.lock().unwrap().len();
    (result, count)
}
#[test]
fn real_pulley_wasm_runs() {
    assert!(evx_runtime::new_engine().unwrap().is_pulley());
    let (result, count) = execute(&wasm("i32.const 42"), Limits::default(), Vec::new());
    assert_eq!(result.status, WorkerStatus::Ok);
    assert_eq!(result.value, Some(42));
    assert_eq!(count, 0);
}
#[test]
fn real_wasm_uses_existing_capability_protocol() {
    let response = br#"{"ok":true,"score":42}"#.to_vec();
    let (result, count) = execute(
        &call_wasm(r#"{"op":"game.score.get"}"#, 1),
        Limits::default(),
        response.clone(),
    );
    assert_eq!(result.status, WorkerStatus::Ok);
    assert_eq!(result.value, Some(response.len() as i32));
    assert_eq!(count, 1);
}
#[test]
fn authority_injection_never_reaches_callback() {
    for request in [
        r#"{"op":"http.get","url":"https://example.invalid"}"#,
        r#"{"op":"game.score.get","xite":"other"}"#,
        r#"{"op":"workspace.read","path":"../private"}"#,
        r#"{"op":"game.score.get","op":"game.score.get"}"#,
    ] {
        let (result, calls) = execute(&call_wasm(request, 1), Limits::default(), b"{}".to_vec());
        assert_eq!(result.status, WorkerStatus::Error);
        assert_eq!(calls, 0);
    }
}
#[test]
fn malformed_and_oversized_callback_results_trap() {
    for response in [
        vec![b'a'; evx_api::MAX_RESPONSE + 1],
        b"{\"ok\":true,\"ok\":false}".to_vec(),
        b"{}{}".to_vec(),
    ] {
        let (result, calls) = execute(
            &call_wasm(r#"{"op":"game.score.get"}"#, 1),
            Limits::default(),
            response,
        );
        assert_eq!(result.status, WorkerStatus::Error);
        assert_eq!(calls, 1);
    }
}
#[test]
fn fuel_and_host_call_budgets_hold() {
    let limits = Limits {
        fuel: 50,
        ..Limits::default()
    };
    let (result, _) = execute(&wasm("(loop br 0) i32.const 42"), limits, Vec::new());
    assert_eq!(result.status, WorkerStatus::Error);
    let limits = Limits {
        host_calls: 1,
        ..Limits::default()
    };
    let (result, calls) = execute(
        &call_wasm(r#"{"op":"game.score.get"}"#, 2),
        limits,
        b"{}".to_vec(),
    );
    assert_eq!(result.status, WorkerStatus::Error);
    assert_eq!(calls, 1);
}
#[test]
fn source_and_limits_cannot_select_artifact_or_expand_imports() {
    let no_host = || {
        Box::new(Host {
            calls: Arc::default(),
            response: Vec::new(),
        })
    };
    let limits = serde_json::to_vec(&Limits::default()).unwrap();
    for module in [b"\x7fELFcompiled".to_vec(), vec![0; evx_android::MAX_BINARY + 1], wat::parse_str("(module (import \"wasi_snapshot_preview1\" \"fd_write\" (func)) (memory (export \"memory\") 1) (func (export \"run\") (result i32) i32.const 42))").unwrap()] {
        assert!(evx_android::execute_module(&module, &limits, no_host()).is_err());
    }
    for invalid in [
        b"{}".to_vec(),
        vec![b' '; evx_android::MAX_LIMITS + 1],
        serde_json::to_vec(&Limits {
            fuel: 0,
            ..Limits::default()
        })
        .unwrap(),
    ] {
        assert!(evx_android::execute_module(&wasm("i32.const 42"), &invalid, no_host()).is_err());
    }
}
