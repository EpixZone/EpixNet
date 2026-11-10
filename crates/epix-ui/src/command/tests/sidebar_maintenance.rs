use super::{launch_directory_opener, open_path};

#[tokio::test]
async fn sidebar_directory_opener_reports_missing_directory_and_launcher() {
    let directory = tempfile::tempdir().unwrap();
    assert!(open_path(&directory.path().join("missing"))
        .await
        .unwrap_err()
        .contains("does not exist"));
    assert!(
        launch_directory_opener("/nonexistent/epix-file-manager", directory.path())
            .await
            .unwrap_err()
            .contains("Could not launch")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn sidebar_directory_opener_observes_the_actual_exit_status() {
    let directory = tempfile::tempdir().unwrap();
    launch_directory_opener("/bin/true", directory.path())
        .await
        .unwrap();
    assert!(launch_directory_opener("/bin/false", directory.path())
        .await
        .unwrap_err()
        .contains("could not open"));
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn sidebar_directory_opener_keeps_the_async_executor_available() {
    let directory = tempfile::tempdir().unwrap();
    let script = directory.path().join("file-manager.sh");
    std::fs::write(&script, "while [ ! -f \"$0.release\" ]; do sleep 0.01; done\n").unwrap();
    let timer_ran = std::cell::Cell::new(false);
    let opening = async {
        launch_directory_opener("/bin/sh", &script).await.unwrap();
        timer_ran.get()
    };
    let timer = async {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        std::fs::write(directory.path().join("file-manager.sh.release"), b"").unwrap();
        timer_ran.set(true);
    };
    let (timer_ran_before_completion, ()) = tokio::join!(opening, timer);
    assert!(timer_ran_before_completion, "file manager observation blocked the async executor");
}
