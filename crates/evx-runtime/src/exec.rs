#![allow(clippy::field_reassign_with_default)]
//! Execution of a precompiled artifact under limits.
//!
//! The guest sees exactly one import, `evx.call(req_ptr, req_len, out_ptr,
//! out_cap) -> i32`. The host copies the request out of guest memory before
//! doing anything else, so the guest cannot change it during the call and
//! overlapping input and output buffers are safe. Return values: the response
//! length on success, `-1` for an invalid pointer, length or memory, `-2` when
//! the response does not fit.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wasmtime::{
    Caller, Engine, Extern, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Trap, TypedFunc,
};

use evx_api::frames::{WorkerResult, WorkerStatus};
use evx_api::{Limits, MAX_REQUEST, MAX_RESPONSE};

use crate::compile::sha256_hex;
use crate::engine::{engine_key, new_engine};
use crate::validate::{EXPORT_MEMORY, EXPORT_RUN, IMPORT_MODULE, IMPORT_NAME};

/// Minimum output buffer a guest must offer so any broker response fits.
const MIN_OUT_CAP: i32 = MAX_RESPONSE as i32;
/// Epoch tick period for the deadline thread.
const EPOCH_TICK: Duration = Duration::from_millis(10);

/// Errors a host callback can return. `Fatal` traps the guest.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostError {
    #[error("{0}")]
    Fatal(String),
}

/// Broker channel the worker supplies. The runtime never interprets requests.
pub trait HostCalls: Send {
    fn call(&mut self, request: &[u8]) -> Result<Vec<u8>, HostError>;
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub limits: Limits,
    /// Expected artifact digest; execution refuses a mismatch.
    pub artifact_sha256: String,
    /// Expected engine key; execution refuses a mismatch.
    pub engine_key: String,
}

/// Outcome of one execution. Measurements are diagnostic; budget decisions
/// belong to the supervisor's kernel observations.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecReport {
    pub result: WorkerResult,
    /// Set when a trap variant this crate does not classify was observed.
    /// Fails closed as an error; a test guards the classification table.
    pub unclassified_trap: bool,
}

struct State {
    limits: StoreLimits,
    host: Box<dyn HostCalls>,
    host_calls: u32,
    max_host_calls: u32,
    invalid_calls: u32,
}

/// Classification of an engine trap. Budget outcomes are distinct from guest
/// faults so the supervisor can report them separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapClass {
    OutOfFuel,
    Deadline,
    GuestFault,
    Unclassified,
}

pub fn classify_trap(trap: Trap) -> TrapClass {
    match trap {
        Trap::OutOfFuel => TrapClass::OutOfFuel,
        Trap::Interrupt => TrapClass::Deadline,
        Trap::StackOverflow
        | Trap::MemoryOutOfBounds
        | Trap::HeapMisaligned
        | Trap::TableOutOfBounds
        | Trap::IndirectCallToNull
        | Trap::BadSignature
        | Trap::IntegerOverflow
        | Trap::IntegerDivisionByZero
        | Trap::BadConversionToInteger
        | Trap::UnreachableCodeReached
        | Trap::AtomicWaitNonSharedMemory
        | Trap::NullReference
        | Trap::ArrayOutOfBounds
        | Trap::AllocationTooLarge
        | Trap::CastFailure
        | Trap::DisabledOpcode
        | Trap::UnhandledTag
        | Trap::UncaughtException => TrapClass::GuestFault,
        // Component-model, async, stack-switching and debug-assert traps
        // cannot occur under the EVX profile; fail closed if one ever does.
        _ => TrapClass::Unclassified,
    }
}

fn call_host(
    mut caller: Caller<'_, State>,
    req_ptr: i32,
    req_len: i32,
    out_ptr: i32,
    out_cap: i32,
) -> wasmtime::Result<i32> {
    let state = caller.data_mut();
    state.host_calls += 1;
    if state.host_calls > state.max_host_calls {
        wasmtime::bail!("host call budget exhausted");
    }
    let memory = match caller.get_export(EXPORT_MEMORY) {
        Some(Extern::Memory(m)) => m,
        _ => {
            caller.data_mut().invalid_calls += 1;
            return Ok(-1);
        }
    };
    let size = memory.data_size(&caller) as i64;
    let (rp, rl, op, oc) = (
        i64::from(req_ptr),
        i64::from(req_len),
        i64::from(out_ptr),
        i64::from(out_cap),
    );
    if rp < 0
        || rl < 0
        || rl > MAX_REQUEST as i64
        || op < 0
        || oc < i64::from(MIN_OUT_CAP)
        || oc > MAX_REQUEST as i64
        || rp + rl > size
        || op + oc > size
    {
        caller.data_mut().invalid_calls += 1;
        return Ok(-1);
    }
    // Own the bytes before suspension; overlap with the output is therefore safe.
    let request = memory.data(&caller)[rp as usize..(rp + rl) as usize].to_vec();
    let response = match caller.data_mut().host.call(&request) {
        Ok(bytes) => bytes,
        Err(HostError::Fatal(message)) => wasmtime::bail!("{message}"),
    };
    if response.len() > MAX_RESPONSE || response.len() as i64 > oc {
        return Ok(-2);
    }
    memory.data_mut(&mut caller)[op as usize..op as usize + response.len()]
        .copy_from_slice(&response);
    Ok(response.len() as i32)
}

/// Deserialize and run one artifact.
///
/// A digest supplied alongside bytes is not evidence of trusted compilation.
/// Calling this API requires an explicit artifact-provenance safety decision:
///
/// ```compile_fail,E0133
/// use evx_runtime::{run, HostCalls, RunOptions};
/// fn execute(bytes: &[u8], options: &RunOptions, host: Box<dyn HostCalls>) {
///     run(bytes, options, host);
/// }
/// ```
///
/// # Safety
///
/// `artifact` must be the unchanged output of this runtime's trusted compiler
/// using the EVX engine configuration. Its origin must be established outside
/// the supplied digest and engine key. Those fields only detect mismatches;
/// a publisher can compute both for malicious serialized code. A signed xite,
/// an artifact received from a peer, or a hash match does not establish this
/// contract. Raw Wasm must enter the confined compiler, never this function.
///
/// # Containment
///
/// Production callers must also provide the platform's process containment and
/// resource accounting. Fuel, epochs and guest memory limits do not isolate a native
/// engine failure or interrupt a blocked host callback.
pub unsafe fn run(artifact: &[u8], options: &RunOptions, host: Box<dyn HostCalls>) -> ExecReport {
    let started = Instant::now();
    let mut report = ExecReport {
        result: WorkerResult {
            status: WorkerStatus::Error,
            value: None,
            error: None,
            elapsed_ms: 0.0,
            fuel_used: 0,
            memory_bytes: 0,
            host_calls: 0,
            invalid_calls: 0,
        },
        unclassified_trap: false,
    };
    let finish = |report: &mut ExecReport,
                  store: Option<&mut Store<State>>,
                  memory: Option<wasmtime::Memory>| {
        report.result.elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        if let Some(store) = store {
            report.result.fuel_used = options
                .limits
                .fuel
                .saturating_sub(store.get_fuel().unwrap_or(0));
            report.result.host_calls = store.data().host_calls;
            report.result.invalid_calls = store.data().invalid_calls;
            if let Some(memory) = memory {
                report.result.memory_bytes = memory.data_size(&*store) as u64;
            }
        }
    };

    if options.engine_key != engine_key() {
        report.result.error = Some("artifact engine mismatch".into());
        finish(&mut report, None, None);
        return report;
    }
    if sha256_hex(artifact) != options.artifact_sha256 {
        report.result.error = Some("artifact digest mismatch".into());
        finish(&mut report, None, None);
        return report;
    }
    let engine: Engine = match new_engine() {
        Ok(e) => e,
        Err(e) => {
            report.result.error = Some(format!("engine: {e}"));
            finish(&mut report, None, None);
            return report;
        }
    };
    // SAFETY: the caller guarantees trusted compiler provenance and unchanged
    // bytes. The checks above detect transport/configuration mismatches, but
    // do not independently prove the serialized artifact is safe.
    let module = match unsafe { Module::deserialize(&engine, artifact) } {
        Ok(m) => m,
        Err(e) => {
            report.result.error = Some(format!("artifact rejected: {e}"));
            finish(&mut report, None, None);
            return report;
        }
    };
    // Defense in depth: the validator already enforced the ABI, but the
    // artifact is checked again before instantiation can run anything.
    for import in module.imports() {
        if import.module() != IMPORT_MODULE || import.name() != IMPORT_NAME {
            report.result.error = Some(format!(
                "unsupported import: {}.{}",
                import.module(),
                import.name()
            ));
            finish(&mut report, None, None);
            return report;
        }
    }
    let has_run = module
        .exports()
        .any(|e| e.name() == EXPORT_RUN && e.ty().func().is_some());
    let has_memory = module
        .exports()
        .any(|e| e.name() == EXPORT_MEMORY && e.ty().memory().is_some());
    if !has_run || !has_memory {
        report.result.error = Some("missing run or memory export".into());
        finish(&mut report, None, None);
        return report;
    }

    let limits = StoreLimitsBuilder::new()
        .memory_size(options.limits.memory_bytes as usize)
        .table_elements(256)
        .instances(1)
        .tables(1)
        .memories(1)
        .trap_on_grow_failure(false)
        .build();
    let mut store = Store::new(
        &engine,
        State {
            limits,
            host,
            host_calls: 0,
            max_host_calls: options.limits.host_calls,
            invalid_calls: 0,
        },
    );
    store.limiter(|s| &mut s.limits);
    if let Err(e) = store.set_fuel(options.limits.fuel) {
        report.result.error = Some(format!("fuel: {e}"));
        finish(&mut report, Some(&mut store), None);
        return report;
    }
    // Epoch deadline: a ticker thread advances the engine epoch every 10 ms
    // and the store traps once the wall budget elapses.
    let ticks = ((options.limits.wall_seconds / EPOCH_TICK.as_secs_f64()).ceil() as u64).max(1);
    store.set_epoch_deadline(ticks);
    store.epoch_deadline_trap();
    let stop = Arc::new(AtomicBool::new(false));
    let ticker = {
        let engine = engine.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(EPOCH_TICK);
                engine.increment_epoch();
            }
        })
    };

    let mut linker: Linker<State> = Linker::new(&engine);
    if let Err(e) = linker.func_wrap(IMPORT_MODULE, IMPORT_NAME, call_host) {
        report.result.error = Some(format!("linker: {e}"));
        stop.store(true, Ordering::Relaxed);
        let _ = ticker.join();
        finish(&mut report, Some(&mut store), None);
        return report;
    }
    let mut memory = None;
    let outcome: wasmtime::Result<i32> = (|| {
        let instance = linker.instantiate(&mut store, &module)?;
        memory = instance.get_memory(&mut store, EXPORT_MEMORY);
        let run: TypedFunc<(), i32> = instance.get_typed_func(&mut store, EXPORT_RUN)?;
        run.call(&mut store, ())
    })();
    stop.store(true, Ordering::Relaxed);
    let _ = ticker.join();
    match outcome {
        Ok(value) => {
            report.result.status = WorkerStatus::Ok;
            report.result.value = Some(value);
        }
        Err(error) => {
            report.result.status = WorkerStatus::Error;
            let message = match error.downcast_ref::<Trap>() {
                Some(trap) => match classify_trap(*trap) {
                    TrapClass::OutOfFuel => "fuel exhausted".to_string(),
                    TrapClass::Deadline => "epoch deadline reached".to_string(),
                    TrapClass::GuestFault => format!("guest trap: {trap:?}"),
                    TrapClass::Unclassified => {
                        report.unclassified_trap = true;
                        format!("unclassified trap: {trap:?}")
                    }
                },
                None => {
                    // Alternate formatting prints the cause chain, so a host
                    // callback failure is visible beneath Wasmtime's context.
                    let mut text = format!("{error:#}");
                    let end = text.floor_char_boundary(2048);
                    text.truncate(end);
                    text
                }
            };
            report.result.error = Some(message);
        }
    }
    finish(&mut report, Some(&mut store), memory);
    report
}

#[cfg(all(test, feature = "compiler"))]
mod tests {
    use super::*;
    use crate::compile::precompile;

    fn run(artifact: &[u8], options: &RunOptions, host: Box<dyn HostCalls>) -> ExecReport {
        // SAFETY: every test below executes unchanged bytes returned by the
        // local EVX compiler. Negative cases change only digest/key metadata.
        unsafe { super::run(artifact, options, host) }
    }

    struct Echo(Vec<Vec<u8>>);
    impl HostCalls for Echo {
        fn call(&mut self, request: &[u8]) -> Result<Vec<u8>, HostError> {
            self.0.push(request.to_vec());
            Ok(br#"{"ok":true,"score":42}"#.to_vec())
        }
    }

    fn options(artifact: &crate::Artifact, limits: Limits) -> RunOptions {
        RunOptions {
            limits,
            artifact_sha256: artifact.sha256.clone(),
            engine_key: artifact.engine_key.clone(),
        }
    }

    fn call_module(
        payload: &[u8],
        req_ptr: i32,
        req_len: i32,
        out_ptr: i32,
        out_cap: i32,
    ) -> Vec<u8> {
        let data: String = payload.iter().map(|b| format!("\\{b:02x}")).collect();
        let text = format!(
            r#"(module
              (import "evx" "call" (func $call (param i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (data (i32.const 0) "{data}")
              (func (export "run") (result i32)
                i32.const {req_ptr} i32.const {req_len} i32.const {out_ptr} i32.const {out_cap} call $call))"#
        );
        wat::parse_str(text).unwrap()
    }

    #[test]
    fn multibyte_function_name_does_not_panic_when_error_is_bounded() {
        let mut module = wat::parse_str(
            r#"(module
              (import "evx" "call" (func (param i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "run") (result i32)
                (loop
                  (drop (call 0 (i32.const 0) (i32.const 0)
                    (i32.const 4096) (i32.const 4096)))
                  (br 0))
                (i32.const 0)))"#,
        )
        .unwrap();
        fn leb(mut value: usize) -> Vec<u8> {
            let mut bytes = Vec::new();
            loop {
                let byte = (value & 127) as u8;
                value >>= 7;
                bytes.push(byte | if value == 0 { 0 } else { 128 });
                if value == 0 {
                    return bytes;
                }
            }
        }
        // The optional Wasm name section is guest-controlled UTF-8 and appears
        // in Wasmtime's error context for a host-call budget failure.
        let name = "é".repeat(1200);
        let mut names = vec![1, 1]; // One function name, for function index 1.
        names.extend(leb(name.len()));
        names.extend(name.as_bytes());
        let mut section = vec![4];
        section.extend(b"name");
        section.push(1); // Function names subsection.
        section.extend(leb(names.len()));
        section.extend(names);
        module.push(0); // Custom section.
        module.extend(leb(section.len()));
        module.extend(section);
        let artifact = precompile(&module).unwrap();
        let mut limits = Limits::default();
        limits.host_calls = 1;
        let report = run(
            &artifact.bytes,
            &options(&artifact, limits),
            Box::new(Echo(vec![])),
        );
        assert_eq!(report.result.status, WorkerStatus::Error);
        let error = report.result.error.unwrap();
        assert!(!error.is_empty());
        assert!(error.len() <= 2048);
        assert_eq!(report.result.host_calls, 2);
    }

    #[test]
    fn calc_runs_and_reports_fuel() {
        let module = wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "run") (result i32) i32.const 19 i32.const 23 i32.add))"#).unwrap();
        let artifact = precompile(&module).unwrap();
        let report = run(
            &artifact.bytes,
            &options(&artifact, Limits::default()),
            Box::new(Echo(vec![])),
        );
        assert_eq!(
            report.result.status,
            WorkerStatus::Ok,
            "{:?}",
            report.result
        );
        assert_eq!(report.result.value, Some(42));
        assert!(report.result.fuel_used > 0);
        assert_eq!(report.result.memory_bytes, 65536);
    }

    #[test]
    fn broker_call_copies_request_and_writes_response() {
        let payload = br#"{"op":"game.score.get"}"#;
        let module = call_module(payload, 0, payload.len() as i32, 4096, 4096);
        let artifact = precompile(&module).unwrap();
        let report = run(
            &artifact.bytes,
            &options(&artifact, Limits::default()),
            Box::new(Echo(vec![])),
        );
        assert_eq!(report.result.value, Some(22));
        assert_eq!(report.result.host_calls, 1);
        // Overlapping buffers: output at offset 0 over the input.
        let module = call_module(payload, 0, payload.len() as i32, 0, 4096);
        let artifact = precompile(&module).unwrap();
        let report = run(
            &artifact.bytes,
            &options(&artifact, Limits::default()),
            Box::new(Echo(vec![])),
        );
        assert_eq!(report.result.value, Some(22));
    }

    #[test]
    fn invalid_pointers_return_minus_one_without_calling_host() {
        let payload = br#"{"op":"game.score.get"}"#;
        for (rp, rl, op, oc) in [
            (65535, 23, 4096, 4096),
            (0, 65537, 4096, 4096),
            (-1, 23, 4096, 4096),
            (0, -1, 4096, 4096),
            (0, 23, 65535, 4096),
            (0, 23, 4096, -1),
            (0, 23, 4096, 1),
        ] {
            let module = call_module(payload, rp, rl, op, oc);
            let artifact = precompile(&module).unwrap();
            let report = run(
                &artifact.bytes,
                &options(&artifact, Limits::default()),
                Box::new(Echo(vec![])),
            );
            assert_eq!(report.result.value, Some(-1), "{rp} {rl} {op} {oc}");
            assert_eq!(report.result.invalid_calls, 1);
        }
    }

    #[test]
    fn fuel_deadline_and_memory_limits_apply() {
        let loop_module = wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "run") (result i32) (loop $f br $f) i32.const 0))"#).unwrap();
        let artifact = precompile(&loop_module).unwrap();
        let report = run(
            &artifact.bytes,
            &options(&artifact, Limits::default()),
            Box::new(Echo(vec![])),
        );
        assert_eq!(report.result.status, WorkerStatus::Error);
        assert!(
            report.result.error.as_deref().unwrap().contains("fuel"),
            "{:?}",
            report.result
        );
        assert_eq!(report.result.fuel_used, Limits::default().fuel);
        let mut limits = Limits::default();
        limits.fuel = 1_000_000_000_000;
        limits.wall_seconds = 0.3;
        let report = run(
            &artifact.bytes,
            &options(&artifact, limits),
            Box::new(Echo(vec![])),
        );
        assert!(
            report.result.error.as_deref().unwrap().contains("deadline"),
            "{:?}",
            report.result
        );
        let grow = wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "run") (result i32) i32.const 1 memory.grow))"#).unwrap();
        let artifact = precompile(&grow).unwrap();
        let mut limits = Limits::default();
        limits.memory_bytes = 65536;
        let report = run(
            &artifact.bytes,
            &options(&artifact, limits.clone()),
            Box::new(Echo(vec![])),
        );
        assert_eq!(report.result.value, Some(-1));
        assert_eq!(report.result.memory_bytes, 65536);
        limits.memory_bytes = 131072;
        let report = run(
            &artifact.bytes,
            &options(&artifact, limits),
            Box::new(Echo(vec![])),
        );
        assert_eq!(report.result.value, Some(1));
        assert_eq!(report.result.memory_bytes, 131072);
    }

    #[test]
    fn host_call_budget_and_digest_checks() {
        let payload = br#"{"op":"game.score.get"}"#;
        let text = format!(
            r#"(module
              (import "evx" "call" (func $call (param i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (data (i32.const 0) "{}")
              (func (export "run") (result i32) (local $n i32) (local $r i32)
                i32.const 17 local.set $n
                (loop $again
                  i32.const 0 i32.const {} i32.const 4096 i32.const 4096 call $call local.set $r
                  local.get $n i32.const 1 i32.sub local.tee $n br_if $again)
                local.get $r))"#,
            payload
                .iter()
                .map(|b| format!("\\{b:02x}"))
                .collect::<String>(),
            payload.len()
        );
        let module = wat::parse_str(text).unwrap();
        let artifact = precompile(&module).unwrap();
        let report = run(
            &artifact.bytes,
            &options(&artifact, Limits::default()),
            Box::new(Echo(vec![])),
        );
        assert!(
            report
                .result
                .error
                .as_deref()
                .unwrap()
                .contains("host call budget"),
            "{:?}",
            report.result
        );
        assert_eq!(report.result.host_calls, 17);
        let mut bad = options(&artifact, Limits::default());
        bad.artifact_sha256 = "0".repeat(64);
        let report = run(&artifact.bytes, &bad, Box::new(Echo(vec![])));
        assert!(report.result.error.as_deref().unwrap().contains("digest"));
        let mut bad = options(&artifact, Limits::default());
        bad.engine_key = "other".into();
        let report = run(&artifact.bytes, &bad, Box::new(Echo(vec![])));
        assert!(report.result.error.as_deref().unwrap().contains("engine"));
    }
}
