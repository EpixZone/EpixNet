use super::*;

#[test]
fn unscoped_open_cannot_request_browser_navigation() {
    assert_eq!(
        parse("EPIX-OPEN epix://talk.epix/private-target"),
        (None, false)
    );
}

#[test]
fn installer_ping_and_quit_remain_supported() {
    assert_eq!(parse("EPIX-PING"), (None, true));
    assert_eq!(parse("EPIX-QUIT"), (Some(Request::Quit), true));
}

#[test]
fn unknown_lines_are_neither_forwarded_nor_acknowledged() {
    assert_eq!(parse("GET / HTTP/1.1"), (None, false));
    assert_eq!(parse(""), (None, false));
    assert_eq!(parse("EPIX-QUIT now"), (None, false));
}

#[test]
fn cold_start_claims_a_free_control_port() {
    let root = tempfile::tempdir().unwrap();
    let requested = root_scope(root.path()).unwrap();
    // Reserve a port, then release it: nothing listens there any more.
    let address = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let started = Instant::now();
    let role = init_at(
        address,
        "dashboard.epix",
        true,
        &requested,
        ready_scope(root.path()),
    );
    // Windows refuses a loopback connect only after about two seconds. A
    // probe of the closed port must not fail the launch or delay it.
    assert!(matches!(role, Ok(Role::Primary(_))), "{:?}", role.err());
    assert!(started.elapsed() < Duration::from_millis(250));
}

fn ready_scope(root: &Path) -> SharedScope {
    Arc::new(Mutex::new(ScopeState::Ready(root_scope(root).unwrap())))
}

fn one_connection(
    state: SharedScope,
) -> (SocketAddr, Receiver<Request>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        handle_conn(stream, &tx, &state);
    });
    (address, rx, server)
}

#[test]
fn same_root_forwards_the_exact_target_on_the_scoped_connection() {
    let root = tempfile::tempdir().unwrap();
    let requested = root_scope(root.path()).unwrap();
    let state = ready_scope(root.path());
    let (address, requests, server) = one_connection(state.clone());
    let target = "epix://talk.epix/?Topic=Case-Sensitive&literal=;$(nothing)";
    assert!(matches!(
        init_at(address, target, true, &requested, state),
        Ok(Role::Secondary)
    ));
    server.join().unwrap();
    assert_eq!(requests.recv().unwrap(), Request::Open(target.into()));
}

#[test]
fn same_root_background_launch_does_not_open_a_window() {
    let root = tempfile::tempdir().unwrap();
    let state = ready_scope(root.path());
    let (address, requests, server) = one_connection(state.clone());
    assert!(matches!(
        init_at(
            address,
            "talk.epix",
            false,
            &root_scope(root.path()).unwrap(),
            state
        ),
        Ok(Role::Secondary)
    ));
    server.join().unwrap();
    assert!(requests.try_recv().is_err());
}

#[test]
fn different_root_is_rejected_for_foreground_and_background_launches() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    for open in [true, false] {
        let state = ready_scope(first.path());
        let (address, requests, server) = one_connection(state.clone());
        let result = init_at(
            address,
            "private.epix",
            open,
            &root_scope(second.path()).unwrap(),
            state,
        );
        let error = result
            .err()
            .expect("different roots must not reuse the instance");
        assert!(error.contains("different data directory"));
        assert!(!error.contains(first.path().to_str().unwrap()));
        assert!(!error.contains(second.path().to_str().unwrap()));
        server.join().unwrap();
        assert!(requests.try_recv().is_err());
    }
}

#[test]
fn occupied_legacy_listener_never_receives_the_target_or_starts_a_second_node() {
    let root = tempfile::tempdir().unwrap();
    let requested = root_scope(root.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        // The old listener reads one line and closes an unknown request.
        read_request(&mut BufReader::new(stream)).unwrap()
    });
    let result = init_at(
        address,
        "private.epix",
        true,
        &requested,
        ready_scope(root.path()),
    );
    assert!(result.err().unwrap().contains("older or incompatible"));
    let first_line = server.join().unwrap();
    assert_eq!(first_line, format!("{ROOT_PREFIX}{requested}"));
    assert!(!first_line.contains("private.epix"));
}

#[test]
fn preparing_root_refuses_forwarding_until_the_owner_confirms_it() {
    let root = tempfile::tempdir().unwrap();
    let requested = root_scope(root.path()).unwrap();
    let state = Arc::new(Mutex::new(ScopeState::Preparing(requested.clone())));
    let (address, requests, server) = one_connection(state.clone());
    let before = forward_at(address, "talk.epix", true, &requested).unwrap_err();
    assert!(before.contains("still preparing"));
    server.join().unwrap();
    assert!(requests.try_recv().is_err());
    confirm_scope(&state, &requested).unwrap();
    let (address, requests, server) = one_connection(state);
    assert!(forward_at(address, "talk.epix", true, &requested).unwrap());
    server.join().unwrap();
    assert_eq!(requests.recv().unwrap(), Request::Open("talk.epix".into()));
}

#[test]
fn a_pending_move_binds_forwarding_to_the_prepared_root() {
    let old = tempfile::tempdir().unwrap();
    let new = tempfile::tempdir().unwrap();
    let old_scope = root_scope(old.path()).unwrap();
    let new_scope = root_scope(new.path()).unwrap();
    let state = Arc::new(Mutex::new(ScopeState::Preparing(old_scope.clone())));
    confirm_scope(&state, &new_scope).unwrap();
    let (address, requests, server) = one_connection(state.clone());
    let error = forward_at(address, "private.epix", true, &old_scope).unwrap_err();
    assert!(error.contains("different data directory"));
    server.join().unwrap();
    assert!(requests.try_recv().is_err());

    let (address, requests, server) = one_connection(state.clone());
    assert!(forward_at(address, "talk.epix", true, &new_scope).unwrap());
    server.join().unwrap();
    assert_eq!(requests.recv().unwrap(), Request::Open("talk.epix".into()));
    confirm_scope(&state, &new_scope).unwrap();
    assert_eq!(scope_reply(&state, &new_scope), ACK);
}

#[test]
fn an_unexpected_later_root_change_disables_forwarding_until_restart() {
    let old = tempfile::tempdir().unwrap();
    let new = tempfile::tempdir().unwrap();
    let old_scope = root_scope(old.path()).unwrap();
    let new_scope = root_scope(new.path()).unwrap();
    let state = ready_scope(old.path());
    confirm_scope(&state, &new_scope).unwrap();
    for requested in [&old_scope, &new_scope] {
        let (address, requests, server) = one_connection(state.clone());
        let error = forward_at(address, "talk.epix", true, requested).unwrap_err();
        assert!(error.contains("changed data directories"));
        server.join().unwrap();
        assert!(requests.try_recv().is_err());
    }
    confirm_scope(&state, &old_scope).unwrap();
    assert_eq!(scope_reply(&state, &old_scope), ROOT_CHANGED);
}

#[test]
fn existing_and_new_directories_keep_the_same_scope_without_preflight_writes() {
    let root = tempfile::tempdir().unwrap();
    let new = root.path().join("missing/nested");
    let scope_before = root_scope(&new).unwrap();
    assert!(
        !new.exists(),
        "preflight must not create a profile or claim a lease"
    );
    std::fs::create_dir_all(&new).unwrap();
    assert_eq!(root_scope(&new).unwrap(), scope_before);
    assert_eq!(
        root_scope(&root.path().join(".")).unwrap(),
        root_scope(root.path()).unwrap()
    );
}

#[cfg(unix)]
#[test]
fn symlink_aliases_resolve_existing_prefixes_and_missing_suffixes() {
    let root = tempfile::tempdir().unwrap();
    let actual = root.path().join("actual");
    std::fs::create_dir(&actual).unwrap();
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&actual, &alias).unwrap();
    assert_eq!(root_scope(&actual).unwrap(), root_scope(&alias).unwrap());
    assert_eq!(
        root_scope(&actual.join("new")).unwrap(),
        root_scope(&alias.join("new")).unwrap()
    );
    assert!(!actual.join("new").exists());
}

#[cfg(unix)]
#[test]
fn non_unicode_data_directories_do_not_collapse_to_one_identity() {
    use std::os::unix::ffi::OsStringExt;
    let root = tempfile::tempdir().unwrap();
    let first = root
        .path()
        .join(std::ffi::OsString::from_vec(b"profile-\x80".to_vec()));
    let second = root
        .path()
        .join(std::ffi::OsString::from_vec(b"profile-\x81".to_vec()));
    assert_eq!(first.to_string_lossy(), second.to_string_lossy());
    assert_ne!(root_scope(&first).unwrap(), root_scope(&second).unwrap());
}

#[test]
fn installer_operations_work_without_a_root_handshake() {
    let root = tempfile::tempdir().unwrap();
    let state = Arc::new(Mutex::new(ScopeState::Preparing(
        root_scope(root.path()).unwrap(),
    )));
    for command in [PING, QUIT] {
        let (address, requests, server) = one_connection(state.clone());
        let mut stream = control_stream(address).unwrap();
        writeln!(stream, "{command}").unwrap();
        assert_eq!(read_request(&mut BufReader::new(stream)).unwrap(), ACK);
        server.join().unwrap();
        if command == QUIT {
            assert_eq!(requests.recv().unwrap(), Request::Quit);
        } else {
            assert!(requests.try_recv().is_err());
        }
    }
}

#[test]
fn unscoped_navigation_is_rejected_on_the_socket() {
    let root = tempfile::tempdir().unwrap();
    let (address, requests, server) = one_connection(ready_scope(root.path()));
    let mut stream = control_stream(address).unwrap();
    writeln!(stream, "{OPEN_PREFIX}talk.epix").unwrap();
    assert!(read_request(&mut BufReader::new(stream)).is_err());
    server.join().unwrap();
    assert!(requests.try_recv().is_err());
}

#[test]
fn target_and_wire_limits_reject_control_characters_and_unbounded_lines() {
    for target in ["talk.epix\nEPIX-QUIT", "talk.epix\r", "talk.epix\0"] {
        assert!(validate_target(target).is_err());
        assert_eq!(
            parse_scoped(&format!("{OPEN_PREFIX}{target}")),
            (None, false)
        );
    }
    assert!(validate_target(&"x".repeat(MAX_REQUEST_BYTES)).is_err());
    assert!(read_request(&mut std::io::Cursor::new(vec![b'x'; MAX_REQUEST_BYTES + 1])).is_err());
    assert!(read_request(&mut std::io::Cursor::new(b"EPIX-PING")).is_err());
    assert_eq!(
        read_request(&mut std::io::Cursor::new(b"EPIX-PING\r\n")).unwrap(),
        PING
    );
}

#[test]
fn relative_trusted_roots_match_absolute_paths_without_creating_missing_directories() {
    let working = std::env::current_dir().unwrap();
    let root = tempfile::tempdir_in(&working).unwrap();
    let relative = root.path().strip_prefix(&working).unwrap();
    assert_eq!(
        root_scope(relative).unwrap(),
        root_scope(root.path()).unwrap()
    );
    let nested = root.path().join("existing");
    std::fs::create_dir(&nested).unwrap();
    let relative_parent = relative.join("existing/../new");
    let expected = root.path().join("new");
    assert_eq!(
        root_scope(&relative_parent).unwrap(),
        root_scope(&expected).unwrap()
    );
    assert!(!expected.exists());
}
