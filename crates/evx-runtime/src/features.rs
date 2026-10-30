//! The single WebAssembly feature set EVX accepts.
//!
//! Set explicitly in one place so an engine upgrade can never opt guests into
//! a proposal nobody reviewed. Every disabled feature below maps to at least
//! one Wasmtime advisory since 2022 or to a nondeterminism source.

use wasmparser::WasmFeatures;

/// Features enabled for validation and execution.
pub fn wasm_features() -> WasmFeatures {
    let mut f = WasmFeatures::empty();
    f |= WasmFeatures::MUTABLE_GLOBAL;
    f |= WasmFeatures::SATURATING_FLOAT_TO_INT;
    f |= WasmFeatures::SIGN_EXTENSION;
    f |= WasmFeatures::FLOATS;
    f |= WasmFeatures::MULTI_VALUE;
    f |= WasmFeatures::BULK_MEMORY;
    // Bulk memory without reference types is a Wasmtime-supported subset:
    // memory.copy/fill/init and data.drop, but no table instructions beyond
    // what the MVP allows.
    f
}

/// Apply the same choices to a Wasmtime configuration: clear every feature,
/// then enable exactly [`wasm_features`]. Proposals compiled out of this
/// build (threads, GC, reference types, exceptions, the component model) are
/// unavailable regardless; this keeps the two sources identical.
pub fn apply(config: &mut wasmtime::Config) {
    config.wasm_features(WasmFeatures::all(), false);
    config.wasm_features(wasm_features(), true);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_set_is_mvp_plus_four_proposals() {
        let f = wasm_features();
        assert!(f.contains(WasmFeatures::BULK_MEMORY));
        assert!(!f.contains(WasmFeatures::SIMD));
        assert!(!f.contains(WasmFeatures::REFERENCE_TYPES));
        assert!(!f.contains(WasmFeatures::THREADS));
        assert!(!f.contains(WasmFeatures::TAIL_CALL));
        assert!(!f.contains(WasmFeatures::EXCEPTIONS));
        assert!(!f.contains(WasmFeatures::MEMORY64));
        assert!(!f.contains(WasmFeatures::GC));
        assert!(!f.contains(WasmFeatures::COMPONENT_MODEL));
    }
}
