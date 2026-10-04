//! Scheduler regression that observes the private broker to prove guest
//! execution, without exposing a testing hook through the management API.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use epix_plugin::Plugin;
use epix_ui::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::json;

use crate::{EvxPlugin, EvxService, GrantMode, GrantRequest, Shown, CAPABILITY_KEY, HOST_CEILING, PLUGIN_NAME};

// One effect-free host call proves guest entry. The dependent floating-point
// loop then outlives the policy change, bounded by fuel and the wall ceiling.
const READY_THEN_SPIN: &str = r#"(module
    (import "evx" "call" (func $call (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 0) "{\22op\22:\22game.score.get\22}")
    (func (export "run") (result i32)
        (local $x f64)
        (drop (call $call (i32.const 0) (i32.const 23) (i32.const 4096) (i32.const 4096)))
        (local.set $x (f64.const 1234567.5))
        (loop
            (local.set $x (f64.div (f64.const 98765432.25) (f64.sqrt (f64.div (f64.const 8765432.5) (f64.sqrt (f64.add (local.get $x) (f64.const 2.5)))))))
            (local.set $x (f64.div (f64.const 12345678.75) (f64.sqrt (f64.div (f64.const 7654321.5) (f64.sqrt (f64.add (local.get $x) (f64.const 3.5)))))))
            (local.set $x (f64.div (f64.const 23456789.25) (f64.sqrt (f64.div (f64.const 6543210.5) (f64.sqrt (f64.add (local.get $x) (f64.const 4.5)))))))
            (local.set $x (f64.div (f64.const 34567890.75) (f64.sqrt (f64.div (f64.const 5432109.5) (f64.sqrt (f64.add (local.get $x) (f64.const 5.5)))))))
            (br 0))
        i32.const 0))"#;

fn build_worker_binary() -> PathBuf {
    let mut command = std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    command.args(["build", "-p", "evx-worker", "--locked"])
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    if evx_runtime::engine::backend_name().starts_with("pulley") {
        command.args(["--features", "evx-runtime/pulley"]);
    }
    if !cfg!(debug_assertions) {
        command.arg("--release");
    }
    assert!(command.status().expect("cargo build -p evx-worker").success());
    let exe = std::env::current_exe().unwrap();
    std::fs::canonicalize(exe.parent().unwrap().parent().unwrap().join("evx-worker")).unwrap()
}

fn worker_binary() -> PathBuf {
    static WORKER: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    WORKER.get_or_init(build_worker_binary).clone()
}

async fn wait_for(what: &str, check: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(20), async {
        while !check() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await.unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

async fn fixture(with_job: bool, scheduler: bool) -> (tempfile::TempDir, Arc<AppState>, Arc<EvxService>, String) {
    let worker = worker_binary();
    let dir = tempfile::tempdir().unwrap();
    let app = AppState::with_data_dir("test", dir.path());
    let key = epix_crypt::new_seed();
    let xite = epix_crypt::privatekey_to_address(&key).unwrap();
    let served = dir.path().join("data").join(&xite);
    std::fs::create_dir_all(served.join("evx")).unwrap();
    let storage = XiteStorage::new(&served);
    let module = evx_runtime::text_to_binary(READY_THEN_SPIN).unwrap();
    storage.write("evx/main.wasm", &module).unwrap();
    let mut content = json!({
        "address": xite, "title": "EVX cancellation fixture", "modified": 1_700_000_000.0,
        "files": { "evx/main.wasm": { "size": module.len(), "sha512": XiteStorage::hash_bytes(&module) } },
        "evx": { "version": 1, "programs": { "calc": {
            "runtime_profile": "wasm-core-v1", "entry": "evx/main.wasm", "allow_run_once": true,
            "capabilities": [{ "api": "game.score.get" }],
            "limits": { "fuel": HOST_CEILING.fuel, "wall_seconds": 30.0, "process_cpu_seconds": 30.0 }
        } }, "jobs": { "sync": {
            "program": "calc", "schedule": { "type": "interval", "seconds": 1, "anchor": "unix_epoch", "missed": "skip" },
            "max_concurrency": 1
        } } }
    });
    if !with_job {
        content["evx"]["jobs"] = json!({});
    }
    epix_content::sign(&mut content, &key).unwrap();
    storage.write("content.json", epix_content::dumps_content(&content).as_bytes()).unwrap();
    app.add_xite(&xite, XiteEntry { storage, content: Some(content) }).await;
    let service = if scheduler {
        EvxPlugin::with_worker(worker).start(&app);
        app.capability::<EvxService>(CAPABILITY_KEY).unwrap()
    } else {
        Arc::new(EvxService::for_node(&app, Some(worker)).unwrap())
    };
    let inspection = service.inspect(&app, &xite).await.unwrap();
    service.grant(&app, GrantRequest {
        xite: xite.clone(), declaration_digest: inspection.digest.clone(), mode: GrantMode::Enable,
        program: None, limits: None, label: None, shown: Some(Shown::of(&inspection)),
    }).await.unwrap();

    (dir, app, service, xite)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disabling_an_admitted_guest_does_not_delay_the_next_slot_after_re_enable() {
    let (_dir, app, service, xite) = fixture(true, true).await;
    wait_for("a host call from the running guest", || {
        let broker = service.running.lock().unwrap().get(&xite).cloned();
        broker.is_some_and(|broker| broker.lock().calls >= 1)
    }).await;
    let reserved = service.durable().incomplete_occurrences(Some(&xite)).unwrap().remove(0);
    assert!(reserved.execution_started);
    let used = service.durable().snapshot(&xite).unwrap().grant.unwrap().used;
    app.set_plugin_enabled(PLUGIN_NAME, false).await;
    wait_for("cancelled occurrence completion", || {
        !service.durable().runs(&xite).unwrap().is_empty()
            && service.durable().incomplete_occurrences(Some(&xite)).unwrap().is_empty()
    }).await;
    assert_eq!(service.durable().runs(&xite).unwrap()[0].status, "error", "active-guest revocation was exercised");
    let after = service.durable().jobs(&xite).unwrap().remove(0);
    assert_eq!(after.failures, 0, "an operator stop must not introduce task backoff");
    assert_eq!(after.paused_reason, None);
    assert_eq!(service.durable().snapshot(&xite).unwrap().grant.unwrap().used, used, "spent budget was preserved");
    assert_eq!(after.last_occurrence.as_deref(), Some(reserved.occurrence.as_str()), "the claimed occurrence remains reserved");
    let old_slot = after.last_slot;
    app.set_plugin_enabled(PLUGIN_NAME, true).await;
    wait_for("the next eligible slot after re-enable", || {
        service.durable().jobs(&xite).unwrap()[0].last_slot > old_slot
    }).await;
    app.set_plugin_enabled(PLUGIN_NAME, false).await;
    service.shutdown();
    wait_for("scheduler shutdown completion", || {
        service.scheduler.busy() == 0
            && service.running.lock().unwrap().is_empty()
            && service.durable().incomplete_occurrences(Some(&xite)).unwrap().is_empty()
    }).await;
}

async fn admitted_broker(service: &EvxService, xite: &str) -> Arc<evx_supervisor::Broker> {
    wait_for("a host call from the running guest", || {
        service.running.lock().unwrap().get(xite).is_some_and(|broker| broker.lock().calls >= 1)
    }).await;
    service.running.lock().unwrap().get(xite).unwrap().clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aborted_manual_request_keeps_its_lease_broker_and_run_history() {
    let (_dir, app, service, xite) = fixture(false, false).await;
    let s = service.clone();
    let a = app.clone();
    let x = xite.clone();
    let request = tokio::spawn(async move { s.run_once(&a, &x, "calc", None).await });
    let broker = admitted_broker(&service, &xite).await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    let free_while_running = service.run_lock_free(&xite).await;
    let s = service.clone();
    let a = app.clone();
    let x = xite.clone();
    let followup = tokio::spawn(async move { s.run_once(&a, &x, "calc", None).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let followup_finished_early = followup.is_finished();
    let original_registered = service.running.lock().unwrap().get(&xite)
        .is_some_and(|current| Arc::ptr_eq(current, &broker));
    let revoked = service.revoke(&app, &xite).await.unwrap();
    let original_revoked = !broker.grant().enabled;
    // Always clean up the fixture, including when exercising the broken code.
    broker.revoke();
    wait_for("original worker cleanup", || !broker.lock().running).await;
    let next = tokio::time::timeout(Duration::from_secs(20), followup).await.unwrap().unwrap();
    assert!(!free_while_running, "request abort released a live execution lease");
    assert!(!followup_finished_early, "a replacement ran while the first guest was live");
    assert!(original_registered, "a replacement hid the first guest's broker");
    assert!(original_revoked && revoked["stopped_run"] == true, "revoke missed the detached guest");
    assert!(next.is_err(), "queued request admitted after revoke: {next:?}");
    wait_for("detached run history", || service.durable().runs(&xite).unwrap().len() == 1).await;
    assert!(service.running.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aborted_manual_job_finishes_its_durable_occurrence() {
    let (_dir, app, service, xite) = fixture(true, false).await;
    let s = service.clone();
    let a = app.clone();
    let x = xite.clone();
    let request = tokio::spawn(async move { s.run_job(&a, &x, "sync").await });
    let broker = admitted_broker(&service, &xite).await;
    let open = service.durable().incomplete_occurrences(Some(&xite)).unwrap().remove(0);
    assert!(open.execution_started);
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    service.revoke(&app, &xite).await.unwrap();
    wait_for("original worker cleanup", || !broker.lock().running).await;
    wait_for("detached occurrence completion", || {
        service.durable().incomplete_occurrences(Some(&xite)).unwrap().is_empty()
            && !service.scheduler.holds(&xite, &open.occurrence)
    }).await;
    assert_eq!(service.durable().runs(&xite).unwrap().len(), 1);
    assert_eq!(service.durable().jobs(&xite).unwrap()[0].last_occurrence.as_deref(), Some(open.occurrence.as_str()));
    assert!(service.running.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_revokes_a_detached_guest_and_refuses_queued_admission() {
    let (_dir, app, service, xite) = fixture(false, false).await;
    let s = service.clone();
    let a = app.clone();
    let x = xite.clone();
    let request = tokio::spawn(async move { s.run_once(&a, &x, "calc", None).await });
    let broker = admitted_broker(&service, &xite).await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    service.shutdown();
    let authority_after_shutdown = broker.grant().enabled;
    broker.revoke();
    wait_for("shutdown cleanup", || !broker.lock().running).await;
    assert!(!authority_after_shutdown, "shutdown left a detached guest enabled");
    assert!(service.run_once(&app, &xite, "calc", None).await.unwrap_err().contains("stopped"));
    wait_for("shutdown run history", || service.durable().runs(&xite).unwrap().len() == 1).await;
    assert!(service.running.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn execution_lease_extends_through_durable_occurrence_completion() {
    let (_dir, app, service, xite) = fixture(true, false).await;
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *service.before_occurrence_finish.lock().unwrap() = Some(Box::new(move || {
        entered_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    }));
    let s = service.clone();
    let a = app.clone();
    let x = xite.clone();
    let request = tokio::spawn(async move { s.run_job(&a, &x, "sync").await });
    let broker = admitted_broker(&service, &xite).await;
    service.revoke(&app, &xite).await.unwrap();
    entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let free_before_completion = service.run_lock_free(&xite).await;
    assert!(!broker.lock().running, "test hook must run after worker cleanup");
    assert_eq!(service.durable().incomplete_occurrences(Some(&xite)).unwrap().len(), 1);
    release_tx.send(()).unwrap();
    request.await.unwrap().unwrap();
    assert!(!free_before_completion, "lease released before the occurrence result and pause were durable");
    assert!(service.durable().incomplete_occurrences(Some(&xite)).unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_queued_request_cannot_miss_plugin_disable_and_reenable() {
    let (_dir, app, service, xite) = fixture(false, false).await;
    let s = service.clone();
    let a = app.clone();
    let x = xite.clone();
    let first = tokio::spawn(async move { s.run_once(&a, &x, "calc", None).await });
    let broker = admitted_broker(&service, &xite).await;
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    *service.before_execution_wait.lock().unwrap() = Some(Box::new(move || {
        entered_tx.send(()).unwrap();
    }));
    let s = service.clone();
    let a = app.clone();
    let x = xite.clone();
    let second = tokio::spawn(async move { s.run_once(&a, &x, "calc", None).await });
    entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    app.set_plugin_enabled(PLUGIN_NAME, false).await;
    app.set_plugin_enabled(PLUGIN_NAME, true).await;
    // The fixture has no scheduler. Stop just the current broker, preserving
    // durable consent so only the queued request's captured epoch can deny it.
    broker.revoke();
    first.await.unwrap().unwrap();
    wait_for("queued request decision", || {
        second.is_finished() || service.running.lock().unwrap().get(&xite)
            .is_some_and(|broker| broker.lock().calls >= 1)
    }).await;
    if let Some(broker) = service.running.lock().unwrap().get(&xite) {
        broker.revoke();
    }
    let result = second.await.unwrap();
    if let Ok(result) = result {
        assert_eq!(result["worker_started"], false, "queued request missed the disabled epoch: {result}");
    }
}
