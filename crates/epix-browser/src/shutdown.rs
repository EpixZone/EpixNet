//! Bound desktop shutdown even when a blocking network or disk task is stuck.

pub fn shutdown(runtime: tokio::runtime::Runtime) {
    // Let asynchronous tasks shut down and give blocking work a short grace
    // period. Runtime::drop would wait indefinitely for a stuck worker.
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    const WORKER: &str = "EPIX_BROWSER_SHUTDOWN_TEST";
    const TEST_NAME: &str =
        "shutdown::tests::shutdown_returns_while_a_blocking_worker_is_still_running";

    #[test]
    fn shutdown_returns_while_a_blocking_worker_is_still_running() {
        if std::env::var_os(WORKER).is_some() {
            verify_bounded_shutdown();
            return;
        }
        // A regression must not hang the test runner. Killing this isolated
        // process also terminates its blocked thread, without leaking a worker.
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(WORKER, "1")
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(6);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "shutdown worker failed: {status}");
                return;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("shutdown waited indefinitely for a blocking worker");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn verify_bounded_shutdown() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (finished_tx, finished_rx) = mpsc::channel();
        runtime.spawn_blocking(move || {
            started_tx.send(()).unwrap();
            let _ = release_rx.recv();
            let _ = finished_tx.send(());
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        super::shutdown(runtime);

        // The bounded shutdown returned while this worker was still blocked.
        // Release it explicitly so the passing fixture also leaves no thread.
        assert!(matches!(
            finished_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        release_tx.send(()).unwrap();
        finished_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }
}
