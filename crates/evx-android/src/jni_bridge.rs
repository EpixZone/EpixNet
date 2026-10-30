use evx_runtime::{HostCalls, HostError};
use jni::{
    objects::{GlobalRef, JByteArray, JClass, JObject, JValue},
    sys::jbyteArray,
    JNIEnv, JavaVM,
};
use std::sync::atomic::{AtomicBool, Ordering};

static ENTERED: AtomicBool = AtomicBool::new(false);

struct Callback {
    vm: JavaVM,
    object: GlobalRef,
}
impl HostCalls for Callback {
    fn call(&mut self, request: &[u8]) -> Result<Vec<u8>, HostError> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| HostError::Fatal("broker thread unavailable".into()))?;
        let response = env.with_local_frame(8, |env| -> jni::errors::Result<Vec<u8>> {
            let input = env.byte_array_from_slice(request)?;
            let response = env
                .call_method(
                    self.object.as_obj(),
                    "call",
                    "([B)[B",
                    &[JValue::Object(input.as_ref())],
                )?
                .l()?;
            let array = JByteArray::from(response);
            if env.get_array_length(&array)? as usize > evx_api::MAX_RESPONSE {
                return Err(jni::errors::Error::NullPtr("oversized broker response"));
            }
            env.convert_byte_array(array)
        });
        match response {
            Ok(response) => Ok(response),
            Err(_) => {
                // Java exceptions cannot propagate through the Wasm callback or
                // leak host error text. Native containment still belongs to OS.
                let _ = env.exception_clear();
                Err(HostError::Fatal("broker callback refused".into()))
            }
        }
    }
}

fn input(env: &JNIEnv<'_>, bytes: &JByteArray<'_>, max: usize) -> Result<Vec<u8>, String> {
    let length = env
        .get_array_length(bytes)
        .map_err(|_| "missing input".to_string())?;
    if length < 0 || length as usize > max {
        return Err("input limit".into());
    }
    env.convert_byte_array(bytes)
        .map_err(|_| "input copy failed".into())
}

#[no_mangle]
pub extern "system" fn Java_zone_epix_evx_NativeBridge_execute(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    module: JByteArray<'_>,
    limits: JByteArray<'_>,
    callback: JObject<'_>,
) -> jbyteArray {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<Vec<u8>, String> {
            // One invocation for the entire isolated process, including invalid
            // requests. Process reuse cannot inherit native or guest execution state.
            if ENTERED.swap(true, Ordering::AcqRel) {
                return Err("service invocation already consumed".into());
            }
            let module = input(&env, &module, crate::MAX_BINARY)?;
            let limits = input(&env, &limits, crate::MAX_LIMITS)?;
            if callback.is_null() {
                return Err("missing bound broker callback".into());
            }
            let vm = env
                .get_java_vm()
                .map_err(|_| "JVM unavailable".to_string())?;
            let object = env
                .new_global_ref(callback)
                .map_err(|_| "broker binding failed".to_string())?;
            crate::execute_module(&module, &limits, Box::new(Callback { vm, object }))
        },
    ));
    match result {
        Ok(Ok(frame)) => match env.byte_array_from_slice(&frame) {
            Ok(array) => array.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        failure => {
            let message = match failure {
                Ok(Err(message)) => message,
                _ => "isolated runtime panicked".into(),
            };
            let _ = env.exception_clear();
            let _ = env.throw_new("java/lang/IllegalStateException", message);
            std::ptr::null_mut()
        }
    }
}
