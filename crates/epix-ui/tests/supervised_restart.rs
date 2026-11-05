//! The service's restart policy must distinguish Restart from Quit.
use epix_ui::state::AppState;
use std::{
    process::Command,
    time::{Duration, Instant},
};

fn shutdown_status(restart: bool) -> std::process::ExitStatus {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "supervised_shutdown_child", "--nocapture"])
        .env(
            "EPIX_SUPERVISED_SHUTDOWN_TEST",
            if restart { "restart" } else { "quit" },
        )
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("shutdown child did not exit");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn restart_requests_service_restart() {
    assert_eq!(shutdown_status(true).code(), Some(75));
}

#[test]
fn quit_stops_the_service() {
    assert!(shutdown_status(false).success());
}

#[tokio::test]
async fn supervised_shutdown_child() {
    let Ok(mode) = std::env::var("EPIX_SUPERVISED_SHUTDOWN_TEST") else {
        return;
    };
    let state = AppState::new("test");
    state.set_supervised_restart();
    state.shutdown(mode == "restart").await;
    std::future::pending::<()>().await;
}
