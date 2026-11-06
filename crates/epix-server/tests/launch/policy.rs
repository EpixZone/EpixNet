use super::*;

fn saved(root: &Path, value: Value) {
    std::fs::create_dir_all(root.join("private")).unwrap();
    std::fs::write(
        root.join("private/config.json"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
}

fn parse(args: &[&str]) -> Result<Arguments, String> {
    Arguments::parse(
        &args
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>(),
        "dashboard.epix",
    )
}

#[test]
fn fresh_launch_chooses_managed_browser_without_creating_node_data() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("new-node");
    assert_eq!(
        select(&root, None, None, false).unwrap(),
        Some(Browser::Epix)
    );
    assert!(!root.exists());
}

#[test]
fn explicit_choices_override_saved_preference_in_order() {
    let root = tempfile::tempdir().unwrap();
    saved(root.path(), serde_json::json!({"browser": "system"}));
    assert_eq!(
        select(root.path(), None, None, false).unwrap(),
        Some(Browser::System)
    );
    assert_eq!(
        select(root.path(), None, Some("epix"), false).unwrap(),
        Some(Browser::Epix)
    );
    assert_eq!(
        select(root.path(), Some(Browser::System), Some("epix"), false).unwrap(),
        Some(Browser::System)
    );
    assert_eq!(
        select(root.path(), Some(Browser::Epix), Some("invalid"), false).unwrap(),
        Some(Browser::Epix)
    );
    assert_eq!(
        select(root.path(), None, Some(""), false).unwrap(),
        Some(Browser::System)
    );
}

#[test]
fn saved_no_window_and_headless_veto_even_an_explicit_browser() {
    let root = tempfile::tempdir().unwrap();
    for value in [
        serde_json::json!(false),
        serde_json::json!("false"),
        serde_json::json!("off"),
    ] {
        saved(root.path(), serde_json::json!({"open_browser": value}));
        for browser in [Browser::Epix, Browser::System] {
            assert_eq!(
                select(root.path(), Some(browser), Some("epix"), false).unwrap(),
                None
            );
        }
    }
    saved(root.path(), serde_json::json!({"open_browser": true}));
    assert_eq!(
        select(root.path(), Some(Browser::Epix), Some("system"), true).unwrap(),
        None
    );
}

#[test]
fn ui_bool_strings_and_json_bools_enable_opening() {
    let root = tempfile::tempdir().unwrap();
    for value in [
        serde_json::json!(true),
        serde_json::json!("true"),
        serde_json::json!("on"),
    ] {
        saved(root.path(), serde_json::json!({"open_browser": value}));
        assert_eq!(
            select(root.path(), None, None, false).unwrap(),
            Some(Browser::Epix)
        );
    }
}

#[test]
fn invalid_settings_fail_instead_of_choosing_a_browser() {
    let root = tempfile::tempdir().unwrap();
    for value in [
        serde_json::json!({"open_browser": 1}),
        serde_json::json!({"open_browser": "maybe"}),
        serde_json::json!({"browser": true}),
        serde_json::json!({"browser": "other"}),
        serde_json::json!([]),
    ] {
        saved(root.path(), value);
        assert!(select(root.path(), None, None, false).is_err());
    }
    saved(root.path(), serde_json::json!({}));
    assert!(select(root.path(), None, Some("other"), false).is_err());
    std::fs::write(root.path().join("private/config.json"), b"{").unwrap();
    assert!(select(root.path(), None, None, false)
        .unwrap_err()
        .contains("Invalid node config"));
    std::fs::remove_file(root.path().join("private/config.json")).unwrap();
    std::fs::create_dir(root.path().join("private/config.json")).unwrap();
    assert!(select(root.path(), None, None, false)
        .unwrap_err()
        .contains("Cannot read node config"));
}

#[test]
fn preflight_does_not_apply_or_modify_staged_restore_settings() {
    let root = tempfile::tempdir().unwrap();
    saved(root.path(), serde_json::json!({"browser": "system"}));
    let pending = root.path().join("restore-pending");
    saved(&pending, serde_json::json!({"browser": "epix"}));
    assert_eq!(
        select(root.path(), None, None, false).unwrap(),
        Some(Browser::System)
    );
    assert!(pending.join("private/config.json").exists());
    assert!(!root.path().join("lock.pid").exists());
}

#[test]
fn arguments_accept_browser_option_on_either_side_of_target() {
    for args in [
        vec!["--browser", "system", "talk.epix"],
        vec!["talk.epix", "--browser=system"],
    ] {
        let parsed = parse(&args).unwrap();
        assert_eq!(parsed.browser, Some(Browser::System));
        assert_eq!(parsed.target, "talk.epix");
    }
    let parsed = parse(&[]).unwrap();
    assert_eq!(parsed.target, "dashboard.epix");
    assert_eq!(parsed.browser, None);
    let target = "epix://talk.epix/path?q=a%20b#thread";
    assert_eq!(parse(&[target]).unwrap().target, target);
}

#[test]
fn arguments_reject_missing_unknown_and_ambiguous_options() {
    for args in [
        vec!["--browser"],
        vec!["--browser=other"],
        vec!["--browser", "epix", "--browser=system"],
        vec!["--quit"],
        vec!["talk.epix", "mail.epix"],
    ] {
        assert!(parse(&args).is_err(), "{args:?}");
    }
}

#[test]
fn managed_browser_is_selected_only_from_server_installation_directory() {
    let root = Path::new("/installed app/bin/epix-server");
    let browser = sibling_browser(root).unwrap();
    assert_eq!(browser.parent(), root.parent());
    assert_eq!(
        browser.file_name().unwrap(),
        if cfg!(windows) {
            "epix-browser.exe"
        } else {
            "epix-browser"
        }
    );
}
