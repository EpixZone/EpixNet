//! Real HTTP/WebSocket sidebar regression checks. The browser connects to the
//! production UiServer and SidebarPlugin; no WebSocket responses are mocked.
//! Run with EPIX_BROWSER_TEST_TOOLS=/path/to/node_modules cargo test -p epix-plugins
//! --test sidebar_real_server -- --ignored --nocapture.
use epix_plugin::PluginRegistry;
use epix_plugins::SidebarPlugin;
use epix_ui::{AppState, UiServer};
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc, time::Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Node, Playwright and EPIX_BROWSER_TEST_TOOLS"]
async fn sidebar_actions_use_the_real_server_and_persist() {
    let root = tempfile::tempdir().unwrap();
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = std::env::var_os("EPIX_BROWSER_TEST_OUTPUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.path().join("browser-output"));
    std::fs::create_dir_all(&output).unwrap();
    let state = AppState::with_data_dir("sidebar-browser-test", root.path());
    state.set_plugins(vec!["Sidebar".into()]).await;
    let (address, key) = state.create_xite().await.unwrap();
    let identity = state.test_support_link_identity("sidebaruser").await;
    state
        .identity_select(&address, Some(&identity))
        .await
        .unwrap();
    let storage = XiteStorage::new(state.xite_dir(&address).unwrap());
    let schema = json!({"db_name":"Sidebar test","db_file":"data.db","version":1,
        "maps":{"data.json":{"to_table":[{"node":"posts","table":"post"}]}},
        "tables":{"post":{"cols":[["post_id","INTEGER"],["title","TEXT"],["json_id","INTEGER"]]}}});
    storage
        .write(
            "index.html",
            b"<!doctype html><title>Sidebar integration</title><h1>Local signed test xite</h1>",
        )
        .unwrap();
    storage
        .write("style.css", b"body { font-family: sans-serif; }")
        .unwrap();
    storage
        .write("app.js", b"window.sidebarIntegration = true;")
        .unwrap();
    storage
        .write(
            "data.json",
            br#"{"posts":[{"post_id":7,"title":"Real database row"}]}"#,
        )
        .unwrap();
    storage
        .write("dbschema.json", schema.to_string().as_bytes())
        .unwrap();
    storage
        .write("optional/present.txt", b"optional file already held")
        .unwrap();
    let mut content: Value =
        serde_json::from_slice(&storage.read("content.json").unwrap()).unwrap();
    content["title"] = json!("Sidebar integration");
    content["description"] = json!("Isolated real backend test");
    content["optional"] = json!("optional/.*");
    content["donate"] = json!("https://example.org/support");
    content["donate-btc"] = json!("1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
    let mut parent = json!({"address":address,"inner_path":"data/users/content.json","modified":1,"files":{},
        "user_contents":{"cert_signers":{},"permissions":{},"permission_rules":{
            ".*":{"files_allowed":"data.json","max_size":200000}}}});
    epix_content::sign(&mut parent, &key).unwrap();
    storage
        .write(
            "data/users/content.json",
            epix_content::dumps_content(&parent).as_bytes(),
        )
        .unwrap();
    content["includes"] = json!({"data/users/content.json":{}});
    content["files_optional"] = json!({"optional/missing.txt":{"size":18,"sha512":XiteStorage::hash_bytes(b"missing test bytes")}});
    storage
        .write("content.json", content.to_string().as_bytes())
        .unwrap();
    state.sign_xite(&address, &key).await.unwrap();
    assert!(state.rebuild_xite_db(&address).await);
    assert_eq!(
        state
            .db_query(
                &address,
                "SELECT title FROM post WHERE post_id = 7",
                &json!([])
            )
            .await
            .unwrap()[0]["title"],
        "Real database row"
    );
    // Restore a persisted failed-update counter, as a node does at startup.
    // The renderer must read actual state, not a pre-rendered HTML fixture.
    let registry_path = root.path().join("private/xites.json");
    let mut registry: Value =
        serde_json::from_slice(&std::fs::read(&registry_path).unwrap()).unwrap();
    registry[&address]["cache"]["bad_files"] = json!({"updates/missing.json":2});
    std::fs::write(&registry_path, registry.to_string()).unwrap();
    drop(state);
    let state = AppState::with_data_dir("sidebar-browser-test", root.path());
    assert!(state.restore_xites().await > 0);
    state.set_plugins(vec!["Sidebar".into()]).await;
    state
        .add_peer_endpoint(&address, "8.8.8.8:26552")
        .await
        .unwrap();
    state
        .add_peer_endpoint(&address, "8.8.4.4:26552")
        .await
        .unwrap();
    // Private entries may be operator-added, but must not escape in share links.
    state
        .add_peer_endpoint(&address, "192.168.100.15:26552")
        .await
        .unwrap();
    state.set_port_status(true, Some("1.1.1.1".into())).await;
    let mut deletion = Vec::new();
    for _ in 0..2 {
        deletion.push(state.create_xite().await.unwrap().0);
    }
    #[cfg(target_os = "linux")]
    let _launcher_environment = {
        use std::os::unix::fs::PermissionsExt;
        let bin = root.path().join("test-bin");
        std::fs::create_dir(&bin).unwrap();
        let opener = bin.join("xdg-open");
        std::fs::write(&opener, "#!/bin/sh\nprintf '%s' \"$1\" > \"$EPIX_TEST_OPENER_LOG\"\nexit $(cat \"$EPIX_TEST_OPENER_STATUS\")\n").unwrap();
        std::fs::set_permissions(&opener, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(root.path().join("opener-status"), "7").unwrap();
        Environment::set([
            (
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            ),
            (
                "EPIX_TEST_OPENER_LOG",
                root.path().join("opener-log").display().to_string(),
            ),
            (
                "EPIX_TEST_OPENER_STATUS",
                root.path().join("opener-status").display().to_string(),
            ),
        ])
    };
    let geo_bytes =
        std::fs::read(repo.join("crates/epix-server/assets/dbip-city-lite.mmdb.gz")).unwrap();
    if let Some(geo) = epix_ui::geoip::GeoIp::ensure(&geo_bytes, root.path().join("test.mmdb")) {
        state.set_geoip(geo).await;
    }
    let mut plugins = PluginRegistry::new();
    plugins.register(Arc::new(SidebarPlugin));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socket = listener.local_addr().unwrap();
    state.set_ui_port(socket.port()).await;
    state.set_ui_loopback(true).await;
    // A running node records its launch homepage. Keep it distinct from the
    // temporary xites exercised by the destructive-action checks.
    state.set_homepage(&address);
    let server = UiServer::with_registry_and_media(
        state.clone(),
        plugins.command_registry(),
        plugins.media_bundle(),
    );
    let task = tokio::spawn(server.serve_on(listener));
    let manifest = json!({"url":format!("http://{socket}/{address}/"),"address":address,"key":key,"identity":identity,"deletion":deletion,
        "root":root.path(),"xite_dir":storage.root(),"output":output,"test_opener":cfg!(target_os="linux")});
    let manifest_path = root.path().join("browser.json");
    std::fs::write(&manifest_path, manifest.to_string()).unwrap();
    let script = repo.join("ui/tests/sidebar-properties-real-browser.cjs");
    let status = tokio::time::timeout(
        Duration::from_secs(300),
        tokio::task::spawn_blocking(move || {
            std::process::Command::new("node")
                .arg(script)
                .arg(manifest_path)
                .status()
                .unwrap()
        }),
    )
    .await
    .expect("real sidebar browser test timed out")
    .unwrap();
    task.abort();
    if !status.success() {
        if std::env::var_os("EPIX_SIDEBAR_KEEP_DATA").is_some() {
            let data_root = root.keep();
            std::fs::write(
                output.join("failed-state.json"),
                json!({"root":data_root,"address":address}).to_string(),
            )
            .unwrap();
        }
        panic!(
            "real browser regression failed; artifacts: {}",
            output.display()
        );
    }
    let saved: Value = serde_json::from_slice(&storage.read("content.json").unwrap()).unwrap();
    assert_eq!(saved["title"], "Saved through the real sidebar");
    assert!(
        epix_content::verify_signer(&saved, &address),
        "metadata save leaves a valid signed manifest"
    );
    assert_eq!(
        state
            .db_query(
                &address,
                "SELECT title FROM post WHERE post_id = 7",
                &json!([])
            )
            .await
            .unwrap()[0]["title"],
        "Real database row"
    );
    let reopened = AppState::with_data_dir("sidebar-restarted", root.path());
    assert!(reopened.restore_xites().await > 0);
    let restored = reopened.xite_info(&address).await;
    assert_eq!(restored["settings"]["favorite"], true);
    assert_eq!(restored["settings"]["serving"], false);
    assert_eq!(restored["size_limit"], 275);
    assert_eq!(
        reopened.global_settings().await["sidebar_peer_map_open"],
        false
    );
    assert_eq!(restored["settings"]["download_optional"], false);
    assert_eq!(restored["settings"]["autodownloadoptional"], false);
    for deleted in deletion {
        assert!(
            !reopened.has_xite(&deleted).await,
            "successful UI deletion survives restart"
        );
    }
    println!(
        "Real sidebar browser and disk restoration passed: {}",
        output.display()
    );
    if std::env::var_os("EPIX_SIDEBAR_KEEP_DATA").is_some() {
        let data_root = root.keep();
        std::fs::write(
            output.join("retained-state.json"),
            json!({"root":data_root,"address":address}).to_string(),
        )
        .unwrap();
    }
}

#[cfg(target_os = "linux")]
struct Environment(Vec<(&'static str, Option<std::ffi::OsString>)>);
#[cfg(target_os = "linux")]
impl Environment {
    fn set<const N: usize>(values: [(&'static str, String); N]) -> Self {
        Self(
            values
                .into_iter()
                .map(|(key, value)| {
                    let old = std::env::var_os(key);
                    std::env::set_var(key, value);
                    (key, old)
                })
                .collect(),
        )
    }
}
#[cfg(target_os = "linux")]
impl Drop for Environment {
    fn drop(&mut self) {
        for (key, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}
