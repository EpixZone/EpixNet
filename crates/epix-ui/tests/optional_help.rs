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

/// The apps call the family with a capital O and positional args:
/// `OptionalHelp([directory, title, hub_addr])` (EpixPost js/PostMeta.js),
/// `OptionalHelpRemove([directory, hub_addr])`, and
/// `OptionalHelpList([hub_addr])` (js/User.js). Both casings must dispatch.
#[tokio::test]
async fn capital_o_aliases_match_the_app_call_shapes() {
    let (s, reg, addr) = session().await;
    let res = reg
        .dispatch(&s, "OptionalHelp", &json!(["big/", "Big set", addr]), 1)
        .await
        .unwrap();
    assert_eq!(res["num"], 2, "{res}");

    // The list round-trips what OptionalHelp recorded, then empties again.
    let list = reg.dispatch(&s, "OptionalHelpList", &json!([addr]), 1).await.unwrap();
    assert_eq!(list, json!({ "big/": "Big set" }));
    let ok = reg.dispatch(&s, "OptionalHelpRemove", &json!(["big/", addr]), 1).await.unwrap();
    assert_eq!(ok, Value::from("ok"));
    let list = reg.dispatch(&s, "optionalHelpList", &json!([]), 1).await.unwrap();
    assert_eq!(list, json!({}));
}

#[tokio::test]
async fn optional_help_family_is_forbidden_for_unrelated_sites() {
    let (s, reg, _addr) = session().await;
    let dir = tempfile::tempdir().unwrap();
    s.state
        .add_xite("1Other", XiteEntry { storage: XiteStorage::new(dir.path()), content: None })
        .await;
    std::mem::forget(dir);

    let err = reg.dispatch(&s, "OptionalHelpList", &json!(["1Other"]), 1).await.unwrap_err();
    assert_eq!(err, "Forbidden");
    let err = reg
        .dispatch(&s, "OptionalHelp", &json!(["big/", "T", "1Other"]), 1)
        .await
        .unwrap_err();
    assert_eq!(err, "Forbidden");
    let err = reg
        .dispatch(&s, "optionalHelpRemove", &json!(["big/", "1Other"]), 1)
        .await
        .unwrap_err();
    assert_eq!(err, "Forbidden");
}

/// A merger reaches the sites merged into it (MergerSite's hasSitePermission):
/// holding `Merger:Test` opens a `merged_type: Test` hub to the family.
#[tokio::test]
async fn merger_can_use_optional_help_on_its_merged_sites() {
    let (s, reg, addr) = session().await;
    let dir = tempfile::tempdir().unwrap();
    s.state
        .add_xite(
            "1Hub",
            XiteEntry {
                storage: XiteStorage::new(dir.path()),
                content: Some(json!({ "merged_type": "Test" })),
            },
        )
        .await;
    std::mem::forget(dir);

    // Not a merger yet: refused.
    let err = reg.dispatch(&s, "OptionalHelpList", &json!(["1Hub"]), 1).await.unwrap_err();
    assert_eq!(err, "Forbidden");

    s.state.add_permission(&addr, "Merger:Test").await;
    let res = reg
        .dispatch(&s, "OptionalHelp", &json!(["data/", "Hub files", "1Hub"]), 1)
        .await
        .unwrap();
    assert_eq!(res["num"], 0, "hub declares no optional files: {res}");
    let list = reg.dispatch(&s, "OptionalHelpList", &json!(["1Hub"]), 1).await.unwrap();
    assert_eq!(list, json!({ "data/": "Hub files" }));
}

#[tokio::test]
async fn xid_resolve_identity_is_registered_as_an_alias() {
    let (s, reg, _addr) = session().await;
    // A missing address makes the handler error; an unregistered name would
    // return Null instead. This proves the alias dispatches without touching
    // the chain resolver.
    let err = reg.dispatch(&s, "xidResolveIdentity", &json!([]), 1).await.unwrap_err();
    assert!(err.contains("address required"), "{err}");
}
