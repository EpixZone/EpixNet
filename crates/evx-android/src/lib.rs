//! Binary-Wasm runtime adapter for the isolated Android service.
//!
//! This library belongs only in that service. It must never be loaded into the
//! trusted node process. Production admission remains gated on Android host
//! broker, kernel accounting and lifecycle acceptance. Fuel and Wasm limits are
//! not a replacement for native process containment.
#![deny(unsafe_op_in_unsafe_fn)]

mod jni_bridge;

use evx_api::{frames::FromWorker, Limits, Request, MAX_RESPONSE};
use evx_runtime::{HostCalls, HostError, RunOptions};

/// Binder uses a smaller source ceiling than the generic EVX module parser.
pub const MAX_BINARY: usize = 65_536;
pub const MAX_LIMITS: usize = 4096;
pub const MAX_RESULT: usize = 4096;

struct CheckedHost(Box<dyn HostCalls>);
impl HostCalls for CheckedHost {
    fn call(&mut self, request: &[u8]) -> Result<Vec<u8>, HostError> {
        Request::decode(request)
            .map_err(|_| HostError::Fatal("invalid capability request".into()))?;
        let response = self.0.call(request)?;
        if response.len() > MAX_RESPONSE {
            return Err(HostError::Fatal("broker response limit".into()));
        }
        // The broker owns authorization and response semantics. This boundary
        // only accepts bounded strict JSON, with no duplicate keys/NaN/trailing data.
        evx_api::strict::parse(&response)
            .map_err(|_| HostError::Fatal("invalid broker response".into()))?;
        Ok(response)
    }
}

/// Compile raw Wasm and execute it in the already isolated service.
///
/// Serialized engine artifacts are never accepted by this API. Compilation is
/// not interruptible in process and can exhaust native memory. The Android host
/// must own independent limits, cancellation, death evidence and quarantine.
/// The returned worker frame is untrusted diagnostics until the host validates
/// its own accounting and confirms process death.
pub fn execute_module(
    module: &[u8],
    limits_json: &[u8],
    host: Box<dyn HostCalls>,
) -> Result<Vec<u8>, String> {
    if module.len() > MAX_BINARY || !module.starts_with(b"\0asm\x01\0\0\0") {
        return Err("bounded binary Wasm required".into());
    }
    if limits_json.len() > MAX_LIMITS {
        return Err("limit snapshot too large".into());
    }
    let limits: Limits = evx_api::strict::parse_typed(limits_json)
        .map_err(|_| "invalid limit snapshot".to_string())?;
    limits
        .validate()
        .map_err(|_| "unsupported limit snapshot".to_string())?;
    let artifact = evx_runtime::precompile(module)
        .map_err(|_| "Wasm validation or compilation failed".to_string())?;
    let options = RunOptions {
        limits,
        artifact_sha256: artifact.sha256,
        engine_key: artifact.engine_key,
    };
    // SAFETY: these exact artifact bytes were produced immediately above by the
    // bundled EVX compiler. Neither peer/publisher artifacts nor Java callbacks
    // can provide or replace this private byte vector.
    let report =
        unsafe { evx_runtime::run(&artifact.bytes, &options, Box::new(CheckedHost(host))) };
    let frame = evx_api::frames::encode(&FromWorker::Result(report.result))
        .map_err(|_| "result encoding failed".to_string())?;
    if frame.len() > MAX_RESULT {
        return Err("result frame limit".into());
    }
    Ok(frame)
}
