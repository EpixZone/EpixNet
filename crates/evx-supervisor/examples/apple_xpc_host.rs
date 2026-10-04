//! Local packaging fixture for the real, disabled Apple execution backend.
#[cfg(all(target_os = "macos", feature = "apple-xpc"))]
fn main() {
    use evx_api::{Grant, HostCancellation, Limits, Status};
    use evx_supervisor::apple_slots::{AppleServiceSlot, AppleSlotInventory, AppleSlotRegistry};
    use evx_supervisor::apple_workspace::AppleWorkspace;
    use evx_supervisor::{run_guest, Broker, RunOptions};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 10, "case workspace guest-name guest-requirement compiler-name compiler-requirement file-name file-requirement authority-directory");
    use std::os::unix::fs::DirBuilderExt;
    let host_id = args[3].strip_suffix(".evx.slot-000.guest").unwrap();
    let authority = evx_supervisor::apple::authority_directory(host_id).unwrap();
    assert_eq!(authority, std::path::PathBuf::from(&args[9]));
    let workspace = std::path::PathBuf::from(&args[2]);
    assert!(workspace.starts_with(authority.parent().unwrap().join("DevelopmentFixtures")));
    if args[1] == "cleanup" {
        if workspace.exists() {
            std::fs::remove_dir_all(workspace).unwrap();
        }
        return;
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&authority)
        .unwrap();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&workspace)
        .unwrap();
    let manifest_path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("Resources/evx-services.json");
    let manifest: serde_json::Value =
        evx_api::strict::parse_typed(&std::fs::read(manifest_path).unwrap()).unwrap();
    assert_eq!(manifest["host_identifier"], host_id);
    assert_eq!(manifest["profile"], "apple-xpc-development");
    let slots: Vec<AppleServiceSlot> = serde_json::from_value(manifest["slots"].clone()).unwrap();
    assert_eq!(slots.len(), 3);
    assert_eq!(slots[0].guest.service, args[3]);
    assert_eq!(slots[0].guest.requirement, args[4]);
    assert_eq!(slots[0].compiler.service, args[5]);
    assert_eq!(slots[0].compiler.requirement, args[6]);
    assert_eq!(slots[0].file.service, args[7]);
    assert_eq!(slots[0].file.requirement, args[8]);
    let inventory = AppleSlotInventory::new(slots).unwrap();
    let registry_path = workspace.parent().unwrap().join("registry");
    let registry = if registry_path.exists() {
        AppleSlotRegistry::open(&registry_path, [42; 32], inventory).unwrap()
    } else {
        // The fixture package has a unique host and service pool per suite.
        AppleSlotRegistry::provision_fresh(&registry_path, [42; 32], inventory).unwrap()
    };
    let game = registry.allocate("game-a").unwrap();
    let other = registry.allocate("game-b").unwrap();
    let crash = registry.allocate("game-crash").unwrap();
    if args[1] == "crash-reopen" {
        assert!(matches!(
            AppleWorkspace::open(crash),
            Err(evx_api::Denied::Quarantined(_))
        ));
        println!("{}", serde_json::json!({"quarantined":true}));
        return;
    }
    let control = AppleWorkspace::open(if args[1] == "crash-start" {
        crash
    } else {
        game
    })
    .unwrap();
    let config = control.config(authority.clone());
    if matches!(
        args[1].as_str(),
        "file-roundtrip" | "cross-slot" | "uncertain-recovery" | "crash-start"
    ) {
        file_case(&args[1], &control, &config, other, authority);
        return;
    }
    let cancelling = args[1] == "cancel";
    let source = if cancelling {
        r#"(module (memory (export "memory") 1) (func (export "run") (result i32) (loop $again br $again) i32.const 0))"#
    } else {
        r#"(module (memory (export "memory") 1) (func (export "run") (result i32) i32.const 19 i32.const 23 i32.add))"#
    };
    let artifact = control
        .compile_text(&config, source.as_bytes())
        .expect("Apple compiler");
    assert!(artifact.engine_key.contains("/pulley"));
    if args[1] == "repeat" {
        for _ in 0..3 {
            assert_eq!(
                control
                    .compile_text(&config, source.as_bytes())
                    .expect("repeat compiler"),
                artifact
            );
        }
    }
    let mut limits = Limits::default();
    if cancelling {
        limits.fuel = 1_000_000_000_000;
        limits.wall_seconds = 10.0;
    }
    let broker = Broker::new_apple(
        control.clone(),
        Grant {
            xite: "game-a".into(),
            enabled: true,
            generation: 1,
            capabilities: Default::default(),
            publisher: Some("game".into()),
            publisher_public_key: None,
            runtime_profiles: Default::default(),
        },
        limits,
    )
    .unwrap();
    let revoke = Arc::new(AtomicBool::new(false));
    let mut options = RunOptions::default();
    let thread = cancelling.then(|| {
        options.revoke_event = Some(revoke.clone());
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            revoke.store(true, Ordering::Release);
        })
    });
    let result = run_guest(&config, &artifact, &broker, options);
    if let Some(thread) = thread {
        thread.join().unwrap();
    }
    println!("{}", serde_json::to_string(&result).unwrap());
    assert!(result.worker_started, "{result:?}");
    assert!(
        result.worker_exit_code.is_some(),
        "child not reaped: {result:?}"
    );
    assert_ne!(result.status, Status::Quarantined, "{result:?}");
    let usage = result.trusted_observations.as_ref().unwrap();
    assert!(
        usage.cpu_seconds > 0.0 && usage.peak_aggregate_rss_bytes > 0,
        "{usage:?}"
    );
    if cancelling {
        assert_eq!(
            result.host_cancellation,
            Some(HostCancellation::AuthorityChanged)
        );
        assert!(result.supervisor_elapsed_ms < 5000.0, "{result:?}");
    } else {
        assert_eq!(result.status, Status::Ok, "{result:?}");
        assert_eq!(result.value, Some(42));
        assert_eq!(result.worker_exit_code, Some(0));
    }
    if args[1] == "repeat" {
        let mut pids = std::collections::HashSet::from([result.worker_pid.unwrap()]);
        for _ in 0..3 {
            let again = run_guest(&config, &artifact, &broker, RunOptions::default());
            assert_eq!(again.status, Status::Ok, "repeat guest: {again:?}");
            assert_eq!(again.value, Some(42));
            assert!(
                pids.insert(again.worker_pid.unwrap()),
                "worker process reused"
            );
        }
    }
    evx_supervisor::process::child_admission_status().unwrap();
}

#[cfg(not(all(target_os = "macos", feature = "apple-xpc")))]
fn main() {
    eprintln!("This local fixture requires macOS and apple-xpc");
    std::process::exit(1);
}

#[cfg(all(target_os = "macos", feature = "apple-xpc"))]
fn file_case(
    case: &str,
    workspace: &std::sync::Arc<evx_supervisor::apple_workspace::AppleWorkspace>,
    config: &evx_supervisor::Config,
    other: evx_supervisor::apple_slots::AppleSlotAssignment,
    authority: std::path::PathBuf,
) {
    use base64::Engine;
    use evx_api::frames::HelperFault;
    use evx_api::{Capability, Grant, Limits, Response, Status};
    use evx_supervisor::{reconcile_workspace, run_guest, Broker, RunOptions};
    let make_broker =
        |workspace: &std::sync::Arc<evx_supervisor::apple_workspace::AppleWorkspace>| {
            let mut grant = Grant::new(workspace.xite(), true).unwrap();
            grant
                .capabilities
                .extend([Capability::WorkspaceRead, Capability::WorkspaceWrite]);
            let limits = Limits {
                host_call_seconds: 3.0,
                wall_seconds: 15.0,
                ..Limits::default()
            };
            Broker::new_apple(workspace.clone(), grant, limits).unwrap()
        };
    let broker = make_broker(workspace);
    let wat = |request: serde_json::Value| {
        let bytes = serde_json::to_vec(&request).unwrap();
        let escaped: String = bytes.iter().map(|byte| format!("\\{byte:02x}")).collect();
        format!(
            r#"(module (import "evx" "call" (func $call (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1) (data (i32.const 0) "{escaped}")
            (func (export "run") (result i32) i32.const 0 i32.const {} i32.const 4096 i32.const 4096 call $call))"#,
            bytes.len()
        )
    };
    let write = workspace
        .compile_text(
            config,
            wat(serde_json::json!({"op":"workspace.write", "path":"score.txt", "text":"level=7"}))
                .as_bytes(),
        )
        .unwrap();
    let read = workspace
        .compile_text(
            config,
            wat(serde_json::json!({"op":"workspace.read", "path":"score.txt"})).as_bytes(),
        )
        .unwrap();
    let assert_read = |result: &evx_api::RunResult, expected: &[u8]| {
        assert_eq!(result.status, Status::Ok, "{result:?}");
        let Response::Read {
            ok: true,
            data_b64,
            bytes,
        } = &result.responses[0]
        else {
            panic!("{result:?}");
        };
        assert_eq!(*bytes, expected.len());
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(data_b64)
                .unwrap(),
            expected
        );
        assert!(
            result.children.iter().all(|child| child.exit_code.is_some()),
            "{result:?}"
        );
    };
    let mut options = RunOptions::default();
    if case == "uncertain-recovery" {
        options.file_fault = Some(HelperFault::FailAfterReplace);
    }
    if case == "crash-start" {
        // This hook runs only after a real guest called a real file helper and
        // the helper acknowledged durable staging. Both role records are live.
        options.before_file_commit = Some(Box::new(|_| std::process::exit(23)));
    }
    let result = run_guest(config, &write, &broker, options);
    assert_ne!(
        case, "crash-start",
        "crash hook was not reached: {result:?}"
    );
    if case == "uncertain-recovery" {
        assert!(result.effect_outcome_unknown, "{result:?}");
        assert_eq!(reconcile_workspace(config, &broker).unwrap(), 1);
        let next = workspace.compile_text(config, wat(serde_json::json!({"op":"workspace.write", "path":"score.txt", "text":"level=8"})).as_bytes()).unwrap();
        let next = run_guest(config, &next, &broker, RunOptions::default());
        assert_eq!(next.status, Status::Ok, "{next:?}");
        let result = run_guest(config, &read, &broker, RunOptions::default());
        assert_read(&result, b"level=8");
        println!("{}", serde_json::to_string(&result).unwrap());
        return;
    }
    assert_eq!(result.status, Status::Ok, "{result:?}");
    assert!(
        matches!(
            result.responses.first(),
            Some(Response::Write { ok: true, .. })
        ),
        "{result:?}"
    );
    let result = run_guest(config, &read, &broker, RunOptions::default());
    assert_read(&result, b"level=7");
    if case == "cross-slot" {
        let other = evx_supervisor::apple_workspace::AppleWorkspace::open(other).unwrap();
        let other_config = other.config(authority);
        let other_broker = make_broker(&other);
        let other_write = other.compile_text(&other_config, wat(serde_json::json!({"op":"workspace.write", "path":"score.txt", "text":"other-game"})).as_bytes()).unwrap();
        assert_eq!(
            run_guest(
                &other_config,
                &other_write,
                &other_broker,
                RunOptions::default()
            )
            .status,
            Status::Ok
        );
        assert_read(
            &run_guest(&other_config, &read, &other_broker, RunOptions::default()),
            b"other-game",
        );
        let mut substituted = config.clone();
        substituted.apple_xpc.as_mut().unwrap().file_service = other_config
            .apple_xpc
            .as_ref()
            .unwrap()
            .file_service
            .clone();
        substituted.apple_xpc.as_mut().unwrap().file_requirement = other_config
            .apple_xpc
            .as_ref()
            .unwrap()
            .file_requirement
            .clone();
        let refused = run_guest(&substituted, &read, &broker, RunOptions::default());
        assert!(!refused.worker_started, "{refused:?}");
        assert!(workspace.compile_text(&substituted, b"(module)").is_err());
        assert!(reconcile_workspace(&substituted, &broker).is_err());
        assert_read(
            &run_guest(config, &read, &broker, RunOptions::default()),
            b"level=7",
        );
    } else {
        // Apple file helpers have native write authority in their own private
        // container even for a logical read. Such bytes have no host provenance.
        let probe = run_guest(
            config,
            &read,
            &broker,
            RunOptions {
                file_fault: Some(HelperFault::ReadOnlyWriteProbe),
                ..RunOptions::default()
            },
        );
        assert!(
            matches!(probe.responses.first(), Some(Response::Error { error, .. }) if error == "native write allowed"),
            "{probe:?}"
        );
        let unregistered = workspace
            .compile_text(
                config,
                wat(
                    serde_json::json!({"op":"workspace.read", "path":"read-only-native-probe.txt"}),
                )
                .as_bytes(),
            )
            .unwrap();
        let unregistered = run_guest(config, &unregistered, &broker, RunOptions::default());
        assert!(
            !unregistered
                .responses
                .iter()
                .any(|response| matches!(response, Response::Read { .. })),
            "{unregistered:?}"
        );
    }
    println!("{}", serde_json::to_string(&result).unwrap());
}
