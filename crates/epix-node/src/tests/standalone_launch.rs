use super::standalone_restart_argv;

#[test]
fn restart_keeps_explicit_browser_and_target_without_shell_interpretation() {
    let args = ["--browser", "system", "epix://talk.epix/path?q=a b&next=x"];
    let argv = standalone_restart_argv(
        "/installation with spaces/epix-server".into(),
        args.into_iter().map(Into::into),
    ).unwrap();
    assert_eq!(argv[0], "/installation with spaces/epix-server");
    assert_eq!(argv[1..], args);
}

#[cfg(unix)]
#[test]
fn invalid_unicode_arguments_do_not_produce_a_changed_restart_command() {
    use std::os::unix::ffi::OsStringExt;
    assert!(standalone_restart_argv(
        "/epix-server".into(),
        [std::ffi::OsString::from_vec(vec![0xff])],
    ).is_none());
}
