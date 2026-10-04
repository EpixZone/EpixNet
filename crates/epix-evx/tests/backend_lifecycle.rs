//! Existing state remains inspectable when its process ownership cannot be proven.
use epix_evx::EvxService;
use epix_ui::AppState;
use std::sync::Arc;

#[tokio::test]
async fn legacy_state_keeps_inspection_and_requires_os_reboot_for_migration() {
    let dir = tempfile::tempdir().unwrap();
    let app = AppState::with_data_dir("fixture", dir.path());
    let root = dir.path().join("private/evx");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("legacy-preserved"), b"game data").unwrap();
    let service = Arc::new(EvxService::for_node(&app, None).unwrap());
    let error = service.execution_ready().unwrap_err();
    assert!(error.contains("restart the operating system"), "{error}");
    let status = service.status(&app, "game").await.unwrap();
    assert_eq!(status["host"]["execution"], false);
    assert_eq!(status["host"]["reason"], error);
    assert!(service.recover_workspace(&app, "game").await.unwrap_err().contains("restart the operating system"));
    assert_eq!(std::fs::read(root.join("legacy-preserved")).unwrap(), b"game data");
    assert!(root.join("lifecycle").exists());
    let reopened = EvxService::for_node(&app, None).unwrap();
    assert!(reopened.execution_ready().unwrap_err().contains("restart the operating system"));
}

#[tokio::test]
async fn lost_or_corrupt_lifecycle_is_not_reset_by_restart_or_recovery() {
    for lost in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let app = AppState::with_data_dir("fixture", dir.path());
        let service = EvxService::for_node(&app, None).unwrap();
        let lifecycle = service.root().join("lifecycle");
        assert!(lifecycle.is_dir());
        drop(service);
        if lost { std::fs::remove_dir_all(&lifecycle).unwrap(); }
        else { std::fs::write(lifecycle.join("lifecycle.json"), b"corrupt fixture").unwrap(); }
        let reopened = Arc::new(EvxService::for_node(&app, None).unwrap());
        assert!(reopened.execution_ready().is_err());
        assert_eq!(reopened.status(&app, "game").await.unwrap()["host"]["execution"], false);
        assert!(reopened.recover_workspace(&app, "game").await.is_err());
        if lost { assert!(reopened.execution_ready().unwrap_err().contains("restart the operating system")); }
        else { assert_eq!(std::fs::read(lifecycle.join("lifecycle.json")).unwrap(), b"corrupt fixture"); }
    }
}
