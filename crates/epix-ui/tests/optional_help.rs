//! optionalHelp: opt into distributing a directory of optional files, remove
//! it, and toggle whole-site auto-download.

use epix_ui::command::{CommandRegistry, WsSession};
use epix_ui::state::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::{json, Value};

async fn session() -> (WsSession, CommandRegistry, String) {
    let state = AppState::new("opt-test");
    let dir = tempfile::tempdir().unwrap();
    let content = json!({
        "address": "1Opt",
        "files_optional": {
            "big/a.bin": { "size": 100, "sha512": "aa" },
            "big/b.bin": { "size": 250, "sha512": "bb" },
            "other/c.bin": { "size": 999, "sha512": "cc" },
        },
    });
    state
        .add_xite("1Opt", XiteEntry { storage: XiteStorage::new(dir.path()), content: Some(content) })
        .await;
    std::mem::forget(dir);
    (WsSession::new(state.clone(), Some("1Opt".to_string())), CommandRegistry::with_defaults(), "1Opt".to_string())
}

#[tokio::test]
async fn help_add_reports_count_and_size() {
    let (s, reg, _addr) = session().await;
    let res = reg
        .dispatch(&s, "optionalHelp", &json!({ "directory": "big/", "title": "Big set" }), 1)
        .await
        .unwrap();
    assert_eq!(res["num"], 2, "two files under big/: {res}");
    assert_eq!(res["size"], 350);
}

#[tokio::test]
async fn help_remove_and_help_all() {
    let (s, reg, _addr) = session().await;
    reg.dispatch(&s, "optionalHelp", &json!({ "directory": "big/", "title": "B" }), 1).await.unwrap();

    let ok = reg
        .dispatch(&s, "optionalHelpRemove", &json!({ "directory": "big/" }), 1)
        .await
        .unwrap();
    assert_eq!(ok, Value::from("ok"));
    let missing = reg
        .dispatch(&s, "optionalHelpRemove", &json!({ "directory": "nope/" }), 1)
        .await
        .unwrap();
    assert_eq!(missing, json!({ "error": "Not found" }));

    let val = reg
        .dispatch(&s, "optionalHelpAll", &json!({ "value": true }), 1)
        .await
        .unwrap();
    assert_eq!(val, Value::from(true));
}
