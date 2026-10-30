#![cfg(windows)]
//! Properties the Windows backend claims (`docs/evx-windows-backend.md`)
//! and proves with real LPAC children: the guest container cannot open the
//! workspace natively while the file helper's can, no container can reach
//! its own package folder, a connected pipe cannot be opened by name, the
//! platform gate answers, and a dropped test fixture leaves no profile.

mod common;

use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use evx_api::frames::{encode, ToCompiler};
use evx_api::Status;
use evx_supervisor::process::{pipe_name, Event, Peer, Role};
use evx_supervisor::windows::{package_folder, workspace_profile_names, COMPILER_PROFILE};
use evx_supervisor::{run_guest, Config, RunOptions};

use common::*;

/// Run the hostile peer's `read_native` probe under `role` against the
/// fixture file in the workspace and return the value it reports: 0 for
/// an access denial, 1 for success, 2 for another error.
fn native_read_under(f: &Fixture, role: Role, mode: &str) -> i32 {
    let target = f.workspace.join("native-fixture.txt");
    std::fs::write(&target, "readable fixture").unwrap();
    native_probe_under(f, role, mode, "read_native", &target)
}

/// Run one hostile peer probe (`read_native`, `write_native` or
/// `list_native`) under `role` against `target` and return the value it
/// reports: 0 for an access denial, 1 for success, 2 for another error.
fn native_probe_under(f: &Fixture, role: Role, mode: &str, probe: &str, target: &Path) -> i32 {
    let mut config = Config::new(hostile_peer_binary());
    config.worker_args = vec![probe.into(), target.to_str().unwrap().into()];
    let (tx, rx) = mpsc::sync_channel(8);
    let lease = if role == Role::File {
        Some(f.broker.root().lease().unwrap())
    } else {
        None
    };
    let mut peer = Peer::spawn(
        &config,
        mode,
        &f.workspace,
        role,
        tx,
        lease.as_ref().map(evx_workspace::Lease::raw),
    )
    .unwrap();
    // The peer consumes one frame before answering.
    peer.send(&encode(&ToCompiler::Compile { module: vec![0] }).unwrap())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let value = loop {
        assert!(Instant::now() < deadline, "probe did not answer");
        peer.flush_input().unwrap();
        if let Ok(Event::Frame(_, _, body)) = rx.recv_timeout(Duration::from_millis(10)) {
            let frame: serde_json::Value = serde_json::from_slice(&body).unwrap();
            break frame["value"].as_i64().unwrap() as i32;
        }
    };
    peer.close(Duration::from_millis(50), Duration::from_secs(2))
        .unwrap();
    value
}

#[test]
fn guest_container_cannot_open_the_workspace_but_the_file_helper_can() {
    let f = Fixture::new();
    assert_eq!(
        native_read_under(&f, Role::Guest, "run"),
        0,
        "guest read the workspace natively"
    );
    assert_eq!(
        native_read_under(&f, Role::File, "file-read"),
        1,
        "file helper could not read the workspace"
    );
    assert_eq!(native_read_under(&f, Role::File, "file"), 1);
    // The broker path still works after the direct probes.
    assert_eq!(f.run(calc()).value, Some(42));
}

#[test]
fn guest_cannot_read_the_outside_secret_or_another_workspace() {
    let f = Fixture::new();
    for target in [f.outside.clone(), f.other.join("private.txt")] {
        let mut config = Config::new(hostile_peer_binary());
        config.worker_args = vec!["read_native".into(), target.to_str().unwrap().into()];
        let artifact = compile_ok(&f.config, calc());
        let result = run_guest(&config, &artifact, &f.broker, RunOptions::default());
        assert_eq!(result.status, Status::Ok, "{result:?}");
        assert_eq!(result.value, Some(0), "{}: {result:?}", target.display());
    }
}

/// Every ACE icacls lists for `path` and its whole subtree.
fn tree_aces(folder: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![folder.to_path_buf()];
    while let Some(path) = pending.pop() {
        let output = std::process::Command::new("icacls")
            .arg(&path)
            .output()
            .unwrap();
        found.extend(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| line.contains(":("))
                .map(|line| format!("{}: {}", path.display(), line.trim())),
        );
        if path.is_dir() {
            pending.extend(std::fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
        }
    }
    found
}

#[test]
fn no_container_can_write_or_list_its_own_package_folder() {
    let f = Fixture::new();
    // The compiler profile exists once something has compiled.
    assert_eq!(f.run(calc()).value, Some(42));
    let [guest, file, read] = workspace_profile_names(&f.workspace).unwrap();
    let containers = [
        (guest, Role::Guest, "run"),
        (COMPILER_PROFILE.to_string(), Role::Compiler, "compile"),
        (file, Role::File, "file"),
        (read, Role::File, "file-read"),
    ];
    for (name, role, mode) in &containers {
        let folder = package_folder(name).unwrap();
        let ac = folder.join("AC");
        assert!(ac.is_dir(), "{}", ac.display());
        assert_eq!(
            native_probe_under(&f, *role, mode, "write_native", &ac),
            0,
            "{name} wrote into its own package folder"
        );
        assert_eq!(
            native_probe_under(&f, *role, mode, "list_native", &ac),
            0,
            "{name} listed its own package folder"
        );
        assert_eq!(
            native_probe_under(&f, *role, mode, "write_native", &folder),
            0,
            "{name} wrote into its own package root"
        );
        assert!(!ac.join("evx-hostile-probe.txt").exists());
        assert!(!folder.join("evx-hostile-probe.txt").exists());
    }
    // Launching did not bring any package entry back anywhere in the trees.
    for (name, _, _) in &containers {
        for ace in tree_aces(&package_folder(name).unwrap()) {
            assert!(!ace.contains("S-1-15-2-"), "{ace}");
        }
    }
}

#[test]
fn a_dropped_fixture_leaves_no_profile_or_package_folder_behind() {
    let (names, folders) = {
        let f = Fixture::new();
        assert_eq!(f.run(calc()).value, Some(42));
        let names = workspace_profile_names(&f.workspace).unwrap();
        let folders = names.clone().map(|name| package_folder(&name).unwrap());
        for folder in &folders {
            assert!(folder.is_dir(), "{}", folder.display());
        }
        (names, folders)
    };
    for folder in &folders {
        assert!(
            !folder.exists(),
            "{} survived the fixture",
            folder.display()
        );
    }
    for name in &names {
        // Creating the name again reports a fresh profile; dropping the
        // unretained object deletes it again.
        let profile = evx_windows_native::Profile::create(name).unwrap();
        assert!(profile.created(), "{name} survived the fixture");
    }
}

#[test]
fn a_connected_child_pipe_cannot_be_opened_by_name() {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
    let f = Fixture::new();
    let (tx, _rx) = mpsc::sync_channel(8);
    let peer = Peer::spawn(&f.config, "compile", &f.workspace, Role::Compiler, tx, None).unwrap();
    for (number, access) in [(0, GENERIC_READ), (1, GENERIC_WRITE), (2, GENERIC_WRITE)] {
        let name: Vec<u16> = pipe_name(peer.id, number)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `name` is NUL-terminated; no attributes or template.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                access,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            // SAFETY: a handle this test opened, closed on drop.
            drop(unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(handle) });
            panic!("pipe {number} of peer {} was opened by name", peer.id);
        }
    }
    drop(peer);
}

#[test]
fn confinement_gate_answers_on_this_host() {
    evx_supervisor::confinement_available().unwrap();
}

#[test]
fn terminated_children_report_the_fixed_exit_code() {
    let f = Fixture::new();
    let limits = evx_api::Limits {
        fuel: 1_000_000_000_000,
        wall_seconds: 0.3,
        host_call_seconds: 0.2,
        ..Default::default()
    };
    f.broker.set_limits(limits).unwrap();
    let result = f.run(infinite_loop());
    assert_eq!(result.status, Status::Timeout, "{result:?}");
    assert!(
        result.worker_exit_code.is_some_and(terminated_by_host),
        "{result:?}"
    );
}
