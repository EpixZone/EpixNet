//! Generate only these fixed local test programs for the compiler-free consumer.
//! Invoked by scripts/test-evx-pulley-runtime.py in a private temporary directory.

#[cfg(not(all(feature = "compiler", feature = "pulley")))]
fn main() {
    panic!("fixture generation requires compiler,pulley features");
}

#[cfg(all(feature = "compiler", feature = "pulley"))]
fn main() {
    use std::path::PathBuf;
    let dir = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("private fixture directory"),
    );
    assert!(dir.is_dir());
    assert!(evx_runtime::new_engine().unwrap().is_pulley());
    let fixtures = [
        (
            "score",
            r#"(module (memory (export "memory") 1)
          (func (export "run") (result i32) i32.const 42))"#,
        ),
        (
            "loop",
            r#"(module (memory (export "memory") 1)
          (func (export "run") (result i32) (loop $again br $again) i32.const 0))"#,
        ),
        (
            "grow",
            r#"(module (memory (export "memory") 1)
          (func (export "run") (result i32) i32.const 1 memory.grow))"#,
        ),
        (
            "broker",
            r#"(module
          (import "evx" "call" (func $call (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "{\22op\22:\22game.score.get\22}")
          (func (export "run") (result i32)
            i32.const 0 i32.const 23 i32.const 4096 i32.const 4096 call $call))"#,
        ),
    ];
    for (name, source) in fixtures {
        let wasm = wat::parse_str(source).unwrap();
        let artifact = evx_runtime::precompile(&wasm).unwrap();
        std::fs::write(dir.join(format!("{name}.artifact")), artifact.bytes).unwrap();
        std::fs::write(dir.join(format!("{name}.sha256")), artifact.sha256).unwrap();
        std::fs::write(dir.join(format!("{name}.engine")), artifact.engine_key).unwrap();
    }
}
