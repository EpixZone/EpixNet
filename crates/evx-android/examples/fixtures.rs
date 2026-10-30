fn main() {
    let dir = std::path::PathBuf::from(std::env::args_os().nth(1).expect("fixture directory"));
    std::fs::create_dir(&dir).expect("new fixture directory required");
    for (name, source) in [
        (
            "score",
            r#"(module (memory (export "memory") 1) (func (export "run") (result i32) i32.const 42))"#,
        ),
        (
            "call",
            r#"(module (import "evx" "call" (func $call (param i32 i32 i32 i32) (result i32))) (memory (export "memory") 1) (data (i32.const 0) "{\22op\22:\22game.score.get\22}") (func (export "run") (result i32) i32.const 0 i32.const 23 i32.const 4096 i32.const 4096 call $call))"#,
        ),
        (
            "loop",
            r#"(module (memory (export "memory") 1) (func (export "run") (result i32) (loop br 0) i32.const 0))"#,
        ),
    ] {
        std::fs::write(
            dir.join(format!("{name}.wasm")),
            wat::parse_str(source).unwrap(),
        )
        .unwrap();
    }
    std::fs::write(
        dir.join("limits.json"),
        serde_json::to_vec(&evx_api::Limits::default()).unwrap(),
    )
    .unwrap();
}
