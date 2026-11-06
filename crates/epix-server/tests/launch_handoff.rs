//! Exercise the real server entry point without a browser, node, or host profile.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

fn finish(mut child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!("Launch did not finish: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

fn run(command: &mut Command) -> Output {
    finish(
        command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    )
}

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let install = root.path().join("installation with spaces");
        std::fs::create_dir(&install).unwrap();
        // A symlink would make current_exe resolve the original build directory.
        // A hard link tests the installed location without copying a large binary.
        std::fs::hard_link(
            env!("CARGO_BIN_EXE_epix-server"),
            install.join("epix-server"),
        )
        .or_else(|_| {
            std::fs::copy(
                env!("CARGO_BIN_EXE_epix-server"),
                install.join("epix-server"),
            )
            .map(|_| ())
        })
        .unwrap();
        let fixture = Self { root };
        let private = fixture.root.path().join("node/private");
        std::fs::create_dir_all(&private).unwrap();
        // Even a dispatch regression must not start peer discovery from a test.
        std::fs::write(
            private.join("config.json"),
            br#"{"offline":true,"fileserver_port":"0","tor":"disable","i2p":"disable"}"#,
        )
        .unwrap();
        fixture.script(
            "xdg-open",
            "printf 'unexpected opener' > \"$EPIX_LAUNCH_RECORD\"\nexit 91\n",
        );
        // This current-directory/PATH impostor must never be selected.
        fixture.script(
            "epix-browser",
            "printf 'wrong browser' > \"$EPIX_LAUNCH_RECORD\"\nexit 92\n",
        );
        fixture
    }

    fn script(&self, relative: &str, body: &str) {
        let path = self.root.path().join(relative);
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn managed_browser(&self) {
        self.script(
            "installation with spaces/epix-browser",
            concat!(
            "test ! -e \"$EPIX_DATA_DIR/lock.pid\" || exit 93\n",
            "printf '%s\\n' \"$$\" \"$#\" \"$1\" \"$EPIX_DATA_DIR\" > \"$EPIX_LAUNCH_RECORD\"\n",
            "exit 47\n",
        ),
        );
    }

    fn command(&self) -> Command {
        let mut command = Command::new(
            self.root
                .path()
                .join("installation with spaces/epix-server"),
        );
        command
            .env_clear()
            .env("EPIX_DATA_DIR", self.root.path().join("node"))
            .env("EPIX_LAUNCH_RECORD", self.root.path().join("record"))
            .env("PATH", self.root.path())
            .current_dir(self.root.path());
        command
    }

    fn assert_no_launch(&self, output: &Output) {
        assert!(!self.root.path().join("record").exists(), "{output:?}");
        assert!(
            !self.root.path().join("node/lock.pid").exists(),
            "{output:?}"
        );
    }
}

#[test]
fn managed_default_replaces_server_before_node_data_is_owned() {
    let fixture = Fixture::new();
    fixture.managed_browser();
    let target = "epix://talk.epix/path?q=a%20b#thread";
    let child = fixture
        .command()
        .arg(target)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let output = finish(child);
    assert_eq!(output.status.code(), Some(47), "{output:?}");
    let record = std::fs::read_to_string(fixture.root.path().join("record")).unwrap();
    let lines = record.lines().collect::<Vec<_>>();
    assert_eq!(
        lines,
        [
            pid.to_string().as_str(),
            "1",
            target,
            fixture.root.path().join("node").to_str().unwrap()
        ]
    );
    assert!(!fixture.root.path().join("node/lock.pid").exists());
    assert!(!fixture.root.path().join("node/data").exists());
}

#[test]
fn missing_managed_installation_does_not_search_path_or_open_system_browser() {
    let fixture = Fixture::new();
    let output = run(&mut fixture.command());
    assert_eq!(output.status.code(), Some(1));
    let error = String::from_utf8(output.stderr.clone()).unwrap();
    assert!(error.contains("Cannot launch EpixNet Browser"), "{error}");
    assert!(error.contains("--browser system"), "{error}");
    assert!(error.contains("EPIX_HEADLESS=1"), "{error}");
    fixture.assert_no_launch(&output);
    assert!(!fixture.root.path().join("node/data").exists());
}

#[test]
fn help_version_and_cli_actions_never_dispatch_a_browser() {
    let fixture = Fixture::new();
    fixture.managed_browser();
    for (args, code) in [
        (vec!["--help"], 0),
        (vec!["--version"], 0),
        (vec!["cryptVerify", "--browser", "invalid"], 1),
    ] {
        let output = run(fixture.command().env("EPIX_BROWSER", "invalid").args(&args));
        assert_eq!(output.status.code(), Some(code), "{args:?}: {output:?}");
        if code == 1 {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("cryptVerify:"),
                "{output:?}"
            );
        }
        fixture.assert_no_launch(&output);
    }
}

#[test]
fn invalid_launch_choices_fail_before_node_or_browser_start() {
    let fixture = Fixture::new();
    fixture.managed_browser();
    let output = run(fixture.command().args(["--browser", "other"]));
    assert_eq!(output.status.code(), Some(2));
    fixture.assert_no_launch(&output);
    let output = run(fixture.command().env("EPIX_BROWSER", "other"));
    assert_eq!(output.status.code(), Some(1));
    fixture.assert_no_launch(&output);
    let private = fixture.root.path().join("node/private");
    std::fs::create_dir_all(&private).unwrap();
    std::fs::write(private.join("config.json"), b"{").unwrap();
    let output = run(&mut fixture.command());
    assert_eq!(output.status.code(), Some(1));
    fixture.assert_no_launch(&output);
}

#[test]
fn explicit_managed_option_preserves_target_and_overrides_environment() {
    let fixture = Fixture::new();
    fixture.managed_browser();
    let output = run(fixture.command().env("EPIX_BROWSER", "system").args([
        "talk.epix",
        "--browser",
        "epix",
    ]));
    assert_eq!(output.status.code(), Some(47), "{output:?}");
    let record = std::fs::read_to_string(fixture.root.path().join("record")).unwrap();
    assert_eq!(record.lines().nth(2), Some("talk.epix"));
}

#[test]
fn a_signal_to_managed_process_is_preserved_for_the_caller() {
    use std::os::unix::process::ExitStatusExt;
    let fixture = Fixture::new();
    fixture.script("installation with spaces/epix-browser", "kill -TERM $$\n");
    let output = run(&mut fixture.command());
    assert_eq!(output.status.signal(), Some(libc::SIGTERM), "{output:?}");
    assert!(!fixture.root.path().join("node/lock.pid").exists());
}

#[test]
fn explicit_non_unicode_data_directory_supplies_its_own_preferences() {
    use std::os::unix::ffi::OsStringExt;
    let fixture = Fixture::new();
    fixture.managed_browser();
    let root = fixture
        .root
        .path()
        .join(std::ffi::OsString::from_vec(b"node-\xff".to_vec()));
    std::fs::create_dir_all(root.join("private")).unwrap();
    std::fs::write(
        root.join("private/config.json"),
        br#"{"browser":"invalid"}"#,
    )
    .unwrap();
    let output = run(fixture.command().env("EPIX_DATA_DIR", &root));
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Node config browser"),
        "{output:?}"
    );
    fixture.assert_no_launch(&output);
    assert!(!root.join("lock.pid").exists());
}
