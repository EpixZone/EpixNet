//! Explicit host reconciliation of uncertain workspace writes.
//! Reads use the same confined, killable helper, never host filesystem reads.

use crate::process::{
    child_admission_status, quarantine_child_admission, Event, Peer, Role, EVENT_CAPACITY,
    MAX_FRAMES, OUTPUT_QUOTA,
};
use crate::{Broker, Config};
use evx_api::frames::{encode, FromHelper, ToHelper};
use evx_api::{Capability, Denied, Limits, Request, Response};
use rustix::fs::{flock, FlockOperation};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Reconcile pending file-write provenance after an explicit operator action.
///
/// The host must serialize this with its xite execution and management paths.
/// The workspace lease also fences other host processes. Only bytes matching
/// a previously authorized version are accepted; this never enrolls existing
/// files, replays a write or executes guest code. Call before clearing a job's
/// reconciliation pause. Partial progress is durable if a later path fails.
pub fn reconcile_workspace(config: &Config, broker: &Broker) -> Result<usize, Denied> {
    reconcile_workspace_cancellable(config, broker, &|| false)
}

/// As [`reconcile_workspace`], with an additional trusted host cancellation
/// check. The callback must be bounded and must not derive authority from guest
/// input. Cancellation preserves every path that was not already reconciled.
pub fn reconcile_workspace_cancellable(
    config: &Config,
    broker: &Broker,
    cancelled: &dyn Fn() -> bool,
) -> Result<usize, Denied> {
    check_cancellation(cancelled)?;
    broker.check_backend(config)?;
    let (generation, limits) = {
        let mut inner = broker.lock();
        if inner.quarantined {
            return Err(Denied::Quarantined("workspace quarantined".into()));
        }
        if inner.running {
            return Err(Denied::new("workspace busy"));
        }
        flock(broker.root_fd(), FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| Denied::new("workspace busy"))?;
        inner.running = true;
        (inner.grant.generation, inner.limits.clone())
    };
    let result = (|| {
        let paths = broker.provenance.pending_paths()?;
        if paths.is_empty() {
            return Ok(0);
        }
        child_admission_status()?;
        let started = Instant::now();
        let mut cpu = 0.0;
        for path in &paths {
            if started.elapsed().as_secs_f64() >= limits.wall_seconds {
                return Err(Denied::new("workspace reconciliation deadline"));
            }
            let (response, used_cpu) = read_one(
                config, broker, path, generation, &limits, started, cpu, cancelled,
            )?;
            cpu += used_cpu;
            check_cancellation(cancelled)?;
            if broker.grant().generation != generation {
                return Err(Denied::Cancelled("execution grant revoked".into()));
            }
            broker.provenance.reconcile(path, response)?;
        }
        Ok(paths.len())
    })();
    let mut inner = broker.lock();
    inner.running = false;
    if !inner.quarantined {
        let _ = flock(broker.root_fd(), FlockOperation::Unlock);
    }
    result
}

fn check_cancellation(cancelled: &dyn Fn() -> bool) -> Result<(), Denied> {
    if cancelled() {
        Err(Denied::Cancelled(
            "workspace recovery cancelled by host policy".into(),
        ))
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn read_one(
    config: &Config,
    broker: &Broker,
    path: &str,
    generation: u64,
    limits: &Limits,
    started: Instant,
    spent_cpu: f64,
    cancelled: &dyn Fn() -> bool,
) -> Result<(Response, f64), Denied> {
    check_cancellation(cancelled)?;
    let (tx, rx) = mpsc::sync_channel(EVENT_CAPACITY);
    let mut helper = Peer::spawn(
        config,
        "file-read",
        broker.workspace(),
        Role::File,
        tx,
        broker.helper_lease_fd(),
    )?;
    let result = (|| {
        let xite = broker.grant().xite;
        helper.send(&encode(&ToHelper::Init {
            xite,
            generation,
            capabilities: vec![Capability::WorkspaceRead],
            limits: limits.clone(),
            request: Request::WorkspaceRead { path: path.into() },
            test_fault: None,
        })?)?;
        let mut response = None;
        loop {
            check_cancellation(cancelled)?;
            let inner = broker.lock();
            if inner.grant.generation != generation {
                return Err(Denied::Cancelled("execution grant revoked".into()));
            }
            let live_limits = inner.limits.clone();
            drop(inner);
            if started.elapsed().as_secs_f64() >= limits.wall_seconds.min(live_limits.wall_seconds)
                || helper.started.elapsed().as_secs_f64()
                    >= limits.host_call_seconds.min(live_limits.host_call_seconds)
            {
                return Err(Denied::new("workspace reconciliation deadline"));
            }
            helper.flush_input()?;
            helper.measure()?;
            let stopped = helper.poll().is_some();
            if spent_cpu + helper.max_cpu
                > limits
                    .process_cpu_seconds
                    .min(live_limits.process_cpu_seconds)
                // Reaping may supply an attributable terminal high-water
                // mark. Check it before returning bytes to provenance. Linux
                // has only post-exec live samples, so a stopped unsampled
                // helper has no attributable RSS observation to compare.
                || helper.last_rss.unwrap_or(if stopped { 0 } else { u64::MAX })
                    > limits.process_rss_bytes.min(live_limits.process_rss_bytes)
            {
                return Err(Denied::new("workspace reconciliation resource limit"));
            }
            if stopped && helper.readers == 0 {
                if helper.exit_code != Some(0) {
                    return Err(Denied::new("workspace reconciliation helper failed"));
                }
                return response
                    .ok_or_else(|| Denied::new("workspace reconciliation result missing"));
            }
            let event = match rx.recv_timeout(Duration::from_millis(20)) {
                Ok(event) => event,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) if helper.readers == 0 => {
                    // EOF can precede exit/reaping. Keep checking kernel
                    // observations and deadlines until the child stops.
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(_) => return Err(Denied::new("workspace reconciliation channel closed")),
            };
            if event.origin() != (Role::File, helper.id) {
                return Err(Denied::new("workspace reconciliation peer mismatch"));
            }
            match event {
                Event::Frame(_, _, body) => {
                    helper.frames += 1;
                    helper.output_bytes += body.len();
                    if response.is_some() {
                        return Err(Denied::new("workspace reconciliation extra frame"));
                    }
                    let frame: FromHelper = evx_api::strict::parse_typed(&body)?;
                    let FromHelper::FileResult { response: value } = frame else {
                        return Err(Denied::new("workspace reconciliation protocol"));
                    };
                    response = Some(value);
                }
                Event::Stderr(_, _, bytes) => helper.output_bytes += bytes.len(),
                Event::Closed(_, _, _, error) => {
                    if error.is_some() {
                        return Err(Denied::new("workspace reconciliation framing"));
                    }
                    helper.readers = helper.readers.saturating_sub(1);
                }
            }
            if helper.output_bytes > OUTPUT_QUOTA || helper.frames > MAX_FRAMES {
                return Err(Denied::new("workspace reconciliation output limit"));
            }
        }
    })();
    if helper
        .close(Duration::from_millis(50), Duration::from_secs(1))
        .is_err()
    {
        quarantine_child_admission();
        broker.lock().quarantined = true;
        return Err(Denied::Quarantined(
            "workspace reconciliation cleanup unconfirmed".into(),
        ));
    }
    result.map(|response| (response, helper.max_cpu))
}
