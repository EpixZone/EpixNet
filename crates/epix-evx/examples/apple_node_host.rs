//! Signed development fixture for node consent, manual execution and scheduling.
#[cfg(all(target_os = "macos", feature = "apple-xpc-development"))]
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    use epix_evx::apple_development::AppleDevelopmentBackend;
    use epix_evx::{EvxPlugin, EvxService, GrantMode, GrantRequest, Shown, CAPABILITY_KEY, PLUGIN_NAME};
    use epix_plugin::Plugin;
    use epix_ui::{AppState, XiteEntry};
    use epix_xite::XiteStorage;
    use evx_supervisor::apple_slots::{AppleServiceSlot, AppleSlotInventory, AppleSlotRegistry};
    use serde_json::json;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 4, "case fixture-root signed-host-identifier");
    let root = PathBuf::from(&args[2]);
    let authority = evx_supervisor::apple::authority_directory(&args[3]).unwrap();
    assert!(root.starts_with(authority.parent().unwrap().join("DevelopmentFixtures")));
    if args[1] == "cleanup" {
        if root.exists() { std::fs::remove_dir_all(root).unwrap(); }
        return;
    }
    let package_bootstrap = args[1] == "package-node";
    assert!(args[1] == "node" || package_bootstrap);
    assert!(!root.exists(), "one fresh fixture per unique signed service pool");
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&root).unwrap();
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&authority).unwrap();
    let manifest_path = std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().join("Resources/evx-services.json");
    let manifest: serde_json::Value = evx_api::strict::parse_typed(&std::fs::read(manifest_path).unwrap()).unwrap();
    assert_eq!(manifest["host_identifier"], args[3]);
    assert_eq!(manifest["profile"], if package_bootstrap { "apple-xpc-fixture" } else { "apple-xpc-development" });
    let slots: Vec<AppleServiceSlot> = serde_json::from_value(manifest["slots"].clone()).unwrap();
    let inventory = AppleSlotInventory::new(slots).unwrap();
    // The harness verifies the package and gives every suite unique service IDs.
    let (plugin, registry) = if package_bootstrap {
        let package = evx_supervisor::apple_package::ApplePackage::current_for_fixture().unwrap();
        (EvxPlugin::from_signed_apple_fixture().unwrap(), package.registry)
    } else {
        let registry = AppleSlotRegistry::provision_fresh(&root.join("registry"), [71;32], inventory.clone()).unwrap();
        let backend = Arc::new(AppleDevelopmentBackend::from_provisioned_registry(registry, &args[3]).unwrap());
        (EvxPlugin::with_apple_development(backend), AppleSlotRegistry::open(&root.join("registry"), [71;32], inventory.clone()).unwrap())
    };
    let app = AppState::with_data_dir("game fixture", root.join("node"));
    let key = epix_crypt::new_seed();
    let xite = epix_crypt::privatekey_to_address(&key).unwrap();
    let served = root.join("node/data").join(&xite);
    std::fs::create_dir_all(served.join("evx")).unwrap();
    let storage = XiteStorage::new(&served);
    let call = |request: serde_json::Value| {
        let bytes = serde_json::to_vec(&request).unwrap();
        let escaped: String = bytes.iter().map(|byte| format!("\\{byte:02x}")).collect();
        format!(r#"(module (import "evx" "call" (func $call (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1) (data (i32.const 0) "{escaped}")
            (func (export "run") (result i32) i32.const 0 i32.const {} i32.const 4096 i32.const 4096 call $call))"#, bytes.len())
    };
    let sources = [
        ("calc", r#"(module (memory (export "memory") 1) (func (export "run") (result i32) i32.const 42))"#.to_string(), vec![]),
        ("write", call(json!({"op":"workspace.write","path":"score.txt","text":"level=7"})), vec!["workspace.write"]),
        ("read", call(json!({"op":"workspace.read","path":"score.txt"})), vec!["workspace.read"]),
    ];
    let mut files = serde_json::Map::new();
    let mut programs = serde_json::Map::new();
    for (id, source, caps) in sources {
        let bytes = evx_runtime::text_to_binary(&source).unwrap();
        let path = format!("evx/{id}.wasm");
        storage.write(&path, &bytes).unwrap();
        files.insert(path.clone(), json!({"size":bytes.len(),"sha512":XiteStorage::hash_bytes(&bytes)}));
        programs.insert(id.into(), json!({"runtime_profile":"wasm-core-v1","entry":path,"allow_run_once":true,
            "capabilities":caps.into_iter().map(|api| json!({"api":api})).collect::<Vec<_>>(),
            "limits":{"wall_seconds":15.0,"host_call_seconds":3.0}}));
    }
    let mut content = json!({"address":xite,"title":"Game fixture","modified":1_700_000_000.0,"files":files,
        "evx":{"version":1,"programs":programs,"jobs":{"refresh":{"program":"calc",
            "schedule":{"type":"interval","seconds":1,"anchor":"unix_epoch","missed":"skip"},"max_concurrency":1}}}});
    epix_content::sign(&mut content, &key).unwrap();
    storage.write("content.json", epix_content::dumps_content(&content).as_bytes()).unwrap();
    app.add_xite(&xite, XiteEntry { storage, content:Some(content) }).await;
    plugin.start(&app);
    let service = app.capability::<EvxService>(CAPABILITY_KEY).unwrap();
    let inspection = service.inspect(&app, &xite).await.unwrap();
    assert!(service.execution().is_err(), "no direct-worker fallback");

    assert!(registry.lookup(&xite).unwrap().is_none(), "inspection allocated a slot");
    assert!(service.run_once(&app, &xite, "calc", None).await.is_err(), "execution needs consent");
    // Let any in-flight tick finish before establishing consent and pausing
    // the job. A claim racing that pause is refused and backs off, making the
    // later resume check depend on a scheduling accident during setup.
    app.set_plugin_enabled(PLUGIN_NAME, false).await;
    let ticks = service.scheduler_ticks();
    tokio::time::timeout(Duration::from_secs(5), async {
        while service.scheduler_ticks() == ticks {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("scheduler observed disabled setup");
    service.grant(&app, GrantRequest { xite:xite.clone(), declaration_digest:inspection.digest.clone(), mode:GrantMode::Enable,
        program:None, limits:None, label:None, shown:Some(Shown::of(&inspection)) }).await.unwrap();
    service.job_pause(&app, &xite, "refresh").await.unwrap();
    app.set_plugin_enabled(PLUGIN_NAME, true).await;
    let result = service.run_once(&app, &xite, "calc", None).await.unwrap();
    assert_eq!(result["status"], "ok", "{result}");
    assert_eq!(result["value"], 42);
    let write = service.run_once(&app, &xite, "write", None).await.unwrap();
    assert_eq!(write["status"], "ok", "{write}");
    let read = service.run_once(&app, &xite, "read", None).await.unwrap();
    assert_eq!(read["responses"][0]["data_b64"], "bGV2ZWw9Nw==", "{read}");
    assert!(registry.lookup(&xite).unwrap().is_some());
    assert!(!service.workspace_dir(&xite).exists(), "node used a direct workspace");
    assert_eq!(service.recover_workspace(&app, &xite).await.unwrap()["reconciled_paths"], 0);
    // Model a lost write acknowledgment using only its already authorized
    // digest. The actual signed file helper must read and reconcile it; an
    // absent direct workspace must not turn this into a no-op.
    let registry_root = if package_bootstrap { service.root().parent().unwrap().join("registry") } else { root.join("registry") };
    let provenance = registry_root.join("workspaces/.evx-provenance");
    let records: Vec<_> = std::fs::read_dir(provenance).unwrap().map(|entry| entry.unwrap().path()).collect();
    assert_eq!(records.len(), 1);
    let mut record: serde_json::Value = serde_json::from_slice(&std::fs::read(&records[0]).unwrap()).unwrap();
    assert_eq!(record["xite"], xite);
    record["entries"]["score.txt"]["pending"] = record["entries"]["score.txt"]["committed"].take();
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().write(true).truncate(true).open(&records[0]).unwrap();
        file.write_all(&serde_json::to_vec(&record).unwrap()).unwrap();
        file.sync_all().unwrap();
    }
    assert_eq!(service.recover_workspace(&app, &xite).await.unwrap()["reconciled_paths"], 1);
    let recovered: serde_json::Value = serde_json::from_slice(&std::fs::read(&records[0]).unwrap()).unwrap();
    assert!(recovered["entries"]["score.txt"]["pending"].is_null());
    assert!(recovered["entries"]["score.txt"]["committed"].is_string());
    let before = service.durable().runs(&xite).unwrap().len();
    service.job_resume(&app, &xite, "refresh").await.unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if service.durable().runs(&xite).unwrap().len() > before { break; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await.expect("background scheduler executed through signed services");
    service.job_pause(&app, &xite, "refresh").await.unwrap();
    let job = service.durable().jobs(&xite).unwrap().remove(0);
    assert!(job.last_occurrence.is_some());
    assert!(service.durable().runs(&xite).unwrap().iter().all(|run| run.status == "ok"));
    service.revoke(&app, &xite).await.unwrap();
    assert!(service.run_once(&app, &xite, "calc", None).await.is_err());
    service.shutdown();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status = service.status(&app, &xite).await.unwrap();
            if status["running"] == false && status["scheduler"]["busy_workers"] == 0 { break; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await.unwrap();
    println!("{}", json!({"manual":true,"files":true,"recovery":true,"scheduler":true,"revocation":true}));
}

#[cfg(not(all(target_os = "macos", feature = "apple-xpc-development")))]
fn main() {
    eprintln!("This development fixture requires macOS and apple-xpc-development");
    std::process::exit(1);
}
