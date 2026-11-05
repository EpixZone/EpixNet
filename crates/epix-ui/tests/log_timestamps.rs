//! Check the emitted text and the dashboard's numeric error tuple together.
use epix_ui::state::AppState;
use serde_json::Value;

const MESSAGE: &str = "timestamp regression marker";

#[test]
fn stdout_and_debug_log_use_the_same_utc_timestamp() {
    let root = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "log_timestamp_child", "--nocapture"])
        .env("EPIX_LOG_TIMESTAMP_TEST_ROOT", root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let file = std::fs::read_to_string(root.path().join("debug.log")).unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let line = stdout.lines().find(|line| line.contains(MESSAGE)).unwrap();
    assert_eq!(file.trim_end(), line);
    let timestamp = line.strip_prefix('[').unwrap().split_once(']').unwrap().0;
    assert_eq!(
        timestamp.len(),
        20,
        "must contain a full UTC date and time: {line}"
    );
    for (index, byte) in timestamp.bytes().enumerate() {
        match index {
            4 | 7 => assert_eq!(byte, b'-'),
            10 => assert_eq!(byte, b'T'),
            13 | 16 => assert_eq!(byte, b':'),
            19 => assert_eq!(byte, b'Z'),
            _ => assert!(byte.is_ascii_digit()),
        }
    }
    assert!(line.ends_with(&format!(" [ERROR] {MESSAGE}")));

    let errors: Value =
        serde_json::from_slice(&std::fs::read(root.path().join("errors.json")).unwrap()).unwrap();
    assert_eq!(errors.as_array().unwrap().len(), 1);
    assert!(
        errors[0][0].as_f64().unwrap() > 0.0,
        "wire timestamp remains numeric"
    );
    assert_eq!(errors[0][1], "ERROR");
    assert_eq!(errors[0][2], MESSAGE);
}

#[tokio::test]
async fn log_timestamp_child() {
    let Some(root) = std::env::var_os("EPIX_LOG_TIMESTAMP_TEST_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let state = AppState::new("timestamp-test");
    state.set_log_file(&root.join("debug.log"));
    state.log("ERROR", MESSAGE).await;
    std::fs::write(
        root.join("errors.json"),
        serde_json::to_vec(&state.server_errors().await).unwrap(),
    )
    .unwrap();
}
