use super::*;

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
