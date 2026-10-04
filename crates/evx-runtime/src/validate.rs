//! Structural validation before compilation.
//!
//! Runs a full `wasmparser` validation with the EVX feature set and then
//! enforces the caps below, which were chosen inside the range used by
//! CosmWasm, NEAR, Soroban and the Internet Computer. CosmWasm added its
//! parameter and local caps after a compiler memory blow-up advisory
//! (CWA-2023-004); the caps exist so a hostile module is refused before a
//! compiler allocates for it.

use std::collections::BTreeMap;

use wasmparser::{
    ExternalKind, FuncType, FuncValidatorAllocations, Operator, Parser, Payload, TypeRef, ValType,
    ValidPayload, Validator,
};

use evx_api::MAX_MODULE;

use crate::features::wasm_features;

/// Structural limits applied after feature validation.
#[derive(Debug, Clone)]
pub struct Caps {
    pub max_functions: u32,
    pub max_params: usize,
    pub max_results: usize,
    pub max_locals_per_function: u32,
    pub max_total_locals: u64,
    pub max_body_bytes: usize,
    pub max_weighted_complexity: u64,
    pub max_table_elements: u64,
    pub max_custom_sections: usize,
    pub max_custom_bytes: usize,
    pub max_data_segments: u32,
    pub max_globals: u32,
    pub max_exports: u32,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            max_functions: 10_000,
            max_params: 64,
            max_results: 1,
            max_locals_per_function: 1_000,
            max_total_locals: 10_000,
            max_body_bytes: 192 * 1024,
            max_weighted_complexity: 1_000_000,
            max_table_elements: 2_500,
            max_custom_sections: 16,
            max_custom_bytes: 1024 * 1024,
            max_data_segments: 1_024,
            max_globals: 1_000,
            max_exports: 1_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ValidationError(pub String);

impl ValidationError {
    pub fn new(message: impl Into<String>) -> Self {
        ValidationError(message.into())
    }
}

/// What the validator learned about an accepted module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleSummary {
    pub functions: u32,
    pub imports: Vec<(String, String)>,
    pub exports: Vec<String>,
    pub memory_min_pages: u64,
    pub weighted_complexity: u64,
}

/// The one import EVX provides: `evx.call(i32, i32, i32, i32) -> i32`.
pub const IMPORT_MODULE: &str = "evx";
pub const IMPORT_NAME: &str = "call";
/// Required exports.
pub const EXPORT_RUN: &str = "run";
pub const EXPORT_MEMORY: &str = "memory";
/// Export names a guest may not claim.
const RESERVED_EXPORT_PREFIX: &str = "evx";

fn is_call_signature(ty: &FuncType) -> bool {
    ty.params() == [ValType::I32, ValType::I32, ValType::I32, ValType::I32]
        && ty.results() == [ValType::I32]
}

fn is_run_signature(ty: &FuncType) -> bool {
    ty.params().is_empty() && ty.results() == [ValType::I32]
}

/// Validate `bytes` as a core module under the EVX profile.
pub fn validate_module(bytes: &[u8]) -> Result<ModuleSummary, ValidationError> {
    validate_with(bytes, &Caps::default())
}

pub fn validate_with(bytes: &[u8], caps: &Caps) -> Result<ModuleSummary, ValidationError> {
    if bytes.len() > MAX_MODULE {
        return Err(ValidationError::new("module size limit"));
    }
    if !bytes.starts_with(b"\0asm\x01\0\0\0") {
        return Err(ValidationError::new(
            "only core Wasm binaries are supported",
        ));
    }
    let mut validator = Validator::new_with_features(wasm_features());
    let mut allocs = FuncValidatorAllocations::default();
    let mut types: Vec<FuncType> = Vec::new();
    let mut func_type_indices: Vec<u32> = Vec::new();
    let mut imported_functions: u32 = 0;
    let mut imports: Vec<(String, String)> = Vec::new();
    let mut exports: BTreeMap<String, (ExternalKind, u32)> = BTreeMap::new();
    let mut memories: u32 = 0;
    let mut memory_min_pages: u64 = 0;
    let mut tables: u32 = 0;
    let mut custom_sections = 0usize;
    let mut custom_bytes = 0usize;
    let mut total_locals: u64 = 0;
    let mut weighted_complexity: u64 = 0;
    let mut saw_start = false;
    let mut data_segments: u32 = 0;
    let mut globals: u32 = 0;
    let mut defined_functions: u32 = 0;

    for payload in Parser::new(0).parse_all(bytes) {
        let payload =
            payload.map_err(|e| ValidationError::new(format!("malformed module: {e}")))?;
        match validator
            .payload(&payload)
            .map_err(|e| ValidationError::new(format!("invalid module: {e}")))?
        {
            ValidPayload::Func(func, body) => {
                let mut v = func.into_validator(std::mem::take(&mut allocs));
                v.validate(&body)
                    .map_err(|e| ValidationError::new(format!("invalid function: {e}")))?;
                allocs = v.into_allocations();
            }
            ValidPayload::Ok | ValidPayload::Parser(_) | ValidPayload::End(_) => {}
        }
        match &payload {
            Payload::TypeSection(reader) => {
                for group in reader.clone().into_iter() {
                    let group =
                        group.map_err(|e| ValidationError::new(format!("type section: {e}")))?;
                    for sub in group.into_types() {
                        match sub.composite_type.inner {
                            wasmparser::CompositeInnerType::Func(func) => {
                                if func.params().len() > caps.max_params {
                                    return Err(ValidationError::new("function parameter limit"));
                                }
                                if func.results().len() > caps.max_results {
                                    return Err(ValidationError::new("function result limit"));
                                }
                                types.push(func);
                            }
                            _ => return Err(ValidationError::new("unsupported type")),
                        }
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for group in reader.clone().into_iter() {
                    let group =
                        group.map_err(|e| ValidationError::new(format!("import section: {e}")))?;
                    let import = match group {
                        wasmparser::Imports::Single(_, import) => import,
                        _ => {
                            return Err(ValidationError::new(
                                "compact import sections are not supported",
                            ))
                        }
                    };
                    match import.ty {
                        TypeRef::Func(type_index) => {
                            let ty = types
                                .get(type_index as usize)
                                .ok_or_else(|| ValidationError::new("import type index"))?;
                            if import.module != IMPORT_MODULE
                                || import.name != IMPORT_NAME
                                || !is_call_signature(ty)
                            {
                                return Err(ValidationError::new(format!(
                                    "unsupported import: {}.{}",
                                    import.module, import.name
                                )));
                            }
                            imported_functions += 1;
                            func_type_indices.push(type_index);
                            imports.push((import.module.to_string(), import.name.to_string()));
                        }
                        _ => {
                            return Err(ValidationError::new(format!(
                                "unsupported import: {}.{}",
                                import.module, import.name
                            )))
                        }
                    }
                }
                if imported_functions > 1 {
                    return Err(ValidationError::new("duplicate broker import"));
                }
            }
            Payload::FunctionSection(reader) => {
                for index in reader.clone().into_iter() {
                    let index = index
                        .map_err(|e| ValidationError::new(format!("function section: {e}")))?;
                    func_type_indices.push(index);
                    defined_functions += 1;
                }
                if defined_functions > caps.max_functions {
                    return Err(ValidationError::new("function count limit"));
                }
            }
            Payload::TableSection(reader) => {
                for table in reader.clone().into_iter() {
                    let table =
                        table.map_err(|e| ValidationError::new(format!("table section: {e}")))?;
                    tables += 1;
                    if tables > 1 {
                        return Err(ValidationError::new("table count limit"));
                    }
                    match table.ty.maximum {
                        Some(max) if max <= caps.max_table_elements => {}
                        _ => {
                            return Err(ValidationError::new(
                                "table must declare a bounded maximum",
                            ))
                        }
                    }
                    if table.ty.initial > caps.max_table_elements {
                        return Err(ValidationError::new("table size limit"));
                    }
                }
            }
            Payload::MemorySection(reader) => {
                for memory in reader.clone().into_iter() {
                    let memory =
                        memory.map_err(|e| ValidationError::new(format!("memory section: {e}")))?;
                    memories += 1;
                    if memories > 1 {
                        return Err(ValidationError::new("memory count limit"));
                    }
                    if memory.maximum.is_some() {
                        return Err(ValidationError::new("memory maximum is set by the host"));
                    }
                    if memory.shared || memory.memory64 {
                        return Err(ValidationError::new("unsupported memory type"));
                    }
                    memory_min_pages = memory.initial;
                }
            }
            Payload::GlobalSection(reader) => {
                globals += reader.count();
                if globals > caps.max_globals {
                    return Err(ValidationError::new("global count limit"));
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader.clone().into_iter() {
                    let export =
                        export.map_err(|e| ValidationError::new(format!("export section: {e}")))?;
                    if export.name.starts_with(RESERVED_EXPORT_PREFIX) {
                        return Err(ValidationError::new("reserved export name"));
                    }
                    if exports
                        .insert(export.name.to_string(), (export.kind, export.index))
                        .is_some()
                    {
                        return Err(ValidationError::new("duplicate export"));
                    }
                    if exports.len() > caps.max_exports as usize {
                        return Err(ValidationError::new("export count limit"));
                    }
                }
            }
            Payload::StartSection { .. } => {
                saw_start = true;
            }
            Payload::DataSection(reader) => {
                data_segments += reader.count();
                if data_segments > caps.max_data_segments {
                    return Err(ValidationError::new("data segment limit"));
                }
            }
            Payload::TagSection(_) => return Err(ValidationError::new("unsupported section: tag")),
            Payload::CodeSectionEntry(body) => {
                let range = body.range();
                if range.end - range.start > caps.max_body_bytes {
                    return Err(ValidationError::new("function body size limit"));
                }
                let mut locals: u64 = 0;
                let locals_reader = body
                    .get_locals_reader()
                    .map_err(|e| ValidationError::new(format!("locals: {e}")))?;
                for local in locals_reader.into_iter() {
                    let (count, _) =
                        local.map_err(|e| ValidationError::new(format!("locals: {e}")))?;
                    locals = locals.saturating_add(u64::from(count));
                }
                if locals > u64::from(caps.max_locals_per_function) {
                    return Err(ValidationError::new("locals per function limit"));
                }
                total_locals = total_locals.saturating_add(locals);
                if total_locals > caps.max_total_locals {
                    return Err(ValidationError::new("total locals limit"));
                }
                let mut complexity: u64 = 0;
                let ops = body
                    .get_operators_reader()
                    .map_err(|e| ValidationError::new(format!("operators: {e}")))?;
                for op in ops.into_iter() {
                    let op = op.map_err(|e| ValidationError::new(format!("operators: {e}")))?;
                    let weight = match op {
                        Operator::Br { .. }
                        | Operator::BrIf { .. }
                        | Operator::BrTable { .. }
                        | Operator::Call { .. }
                        | Operator::CallIndirect { .. }
                        | Operator::Return
                        | Operator::Loop { .. } => 50,
                        Operator::TableGrow { .. } => {
                            return Err(ValidationError::new("table.grow is not permitted"))
                        }
                        _ => 1,
                    };
                    complexity = complexity.saturating_add(weight);
                    if complexity > caps.max_weighted_complexity {
                        return Err(ValidationError::new("function complexity limit"));
                    }
                }
                weighted_complexity = weighted_complexity.saturating_add(complexity);
            }
            Payload::CustomSection(section) => {
                custom_sections += 1;
                custom_bytes += section.data().len();
                if custom_sections > caps.max_custom_sections
                    || custom_bytes > caps.max_custom_bytes
                {
                    return Err(ValidationError::new("custom section limit"));
                }
            }
            // Component encodings are rejected by the core-module header
            // check and disabled validator feature before section processing.
            // Do not depend on optional wasmparser component payload variants.
            _ => {}
        }
    }

    if saw_start {
        return Err(ValidationError::new("start functions are not permitted"));
    }
    if memories != 1 {
        return Err(ValidationError::new("missing memory export"));
    }
    match exports.get(EXPORT_MEMORY) {
        Some((ExternalKind::Memory, _)) => {}
        _ => return Err(ValidationError::new("missing memory export")),
    }
    match exports.get(EXPORT_RUN) {
        Some((ExternalKind::Func, index)) => {
            let type_index = func_type_indices
                .get(*index as usize)
                .ok_or_else(|| ValidationError::new("run export index"))?;
            let ty = types
                .get(*type_index as usize)
                .ok_or_else(|| ValidationError::new("run export type"))?;
            if !is_run_signature(ty) {
                return Err(ValidationError::new("run must have signature () -> i32"));
            }
        }
        _ => return Err(ValidationError::new("missing run export")),
    }

    Ok(ModuleSummary {
        functions: imported_functions + defined_functions,
        imports,
        exports: exports.keys().cloned().collect(),
        memory_min_pages,
        weighted_complexity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wasm(text: &str) -> Vec<u8> {
        wat::parse_str(text).unwrap()
    }

    const CALC: &str = r#"(module (memory (export "memory") 1) (func (export "run") (result i32) i32.const 19 i32.const 23 i32.add))"#;

    #[test]
    fn accepts_calc_and_broker_call() {
        let summary = validate_module(&wasm(CALC)).unwrap();
        assert_eq!(summary.functions, 1);
        assert!(summary.imports.is_empty());
        let with_call = r#"(module
            (import "evx" "call" (func $call (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "run") (result i32) i32.const 0 i32.const 2 i32.const 4096 i32.const 4096 call $call))"#;
        let summary = validate_module(&wasm(with_call)).unwrap();
        assert_eq!(
            summary.imports,
            vec![("evx".to_string(), "call".to_string())]
        );
    }

    #[test]
    fn rejects_unsupported_imports_sections_and_abi() {
        let cases = [
            r#"(module (import "wasi_snapshot_preview1" "path_open" (func (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32))) (memory (export "memory") 1) (func (export "run") (result i32) i32.const 0))"#,
            r#"(module (import "evx" "call" (func (param i32) (result i32))) (memory (export "memory") 1) (func (export "run") (result i32) i32.const 0))"#,
            r#"(module (import "env" "memory" (memory 1)) (func (export "run") (result i32) i32.const 0))"#,
            r#"(module (memory (export "memory") 1 2) (func (export "run") (result i32) i32.const 0))"#,
            r#"(module (memory (export "memory") 1) (func (export "run") (result i32) i32.const 0) (func $s) (start $s))"#,
            r#"(module (memory (export "memory") 1) (func (export "run") (param i32) (result i32) local.get 0))"#,
            r#"(module (memory (export "memory") 1) (func (export "run")))"#,
            r#"(module (func (export "run") (result i32) i32.const 0))"#,
            r#"(module (memory (export "memory") 1) (func (export "evx_internal") (result i32) i32.const 0) (func (export "run") (result i32) i32.const 0))"#,
            r#"(module (memory (export "memory") 1) (table 1 funcref) (func (export "run") (result i32) i32.const 0))"#,
            r#"(module (memory (export "memory") 1) (func (export "run") (result i32) v128.const i32x4 0 0 0 0 i32x4.extract_lane 0))"#,
            r#"(module (memory (export "memory") 1) (memory 1) (func (export "run") (result i32) i32.const 0))"#,
        ];
        for case in cases {
            let bytes = match wat::parse_str(case) {
                Ok(b) => b,
                Err(_) => continue, // text-level rejection also counts
            };
            assert!(validate_module(&bytes).is_err(), "accepted {case}");
        }
        assert!(validate_module(b"\0asm\x01\0\0\0\x01\x01\xff").is_err());
        // The component header is refused even when wasmparser's optional
        // component-model parsing code is absent from the runtime-only build.
        assert!(validate_module(b"\0asm\x0d\0\x01\0").is_err());
        assert!(validate_module(b"not wasm").is_err());
        assert!(validate_module(&vec![0u8; MAX_MODULE + 1]).is_err());
    }

    #[test]
    fn structural_caps_apply() {
        let mut params = String::new();
        for _ in 0..65 {
            params.push_str("i32 ");
        }
        let many_params = format!(
            r#"(module (memory (export "memory") 1) (func (param {params})) (func (export "run") (result i32) i32.const 0))"#
        );
        assert!(validate_module(&wasm(&many_params)).is_err());
        let mut locals = String::new();
        for _ in 0..1001 {
            locals.push_str("(local i32) ");
        }
        let many_locals = format!(
            r#"(module (memory (export "memory") 1) (func {locals}) (func (export "run") (result i32) i32.const 0))"#
        );
        assert!(validate_module(&wasm(&many_locals)).is_err());
    }
}
