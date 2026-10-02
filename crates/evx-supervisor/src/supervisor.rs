//! One invocation: admission, the event loop, and result assembly.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustix::fs::{flock, FlockOperation};

use evx_api::frames::{
    encode, FromHelper, FromWorker, HelperFault, ToHelper, ToWorker, WorkerStatus,
};
use evx_api::grant::ActivationContext;
use evx_api::result::{safe_text, ChildReport};
use evx_api::{
    strict, Denied, Observations, Request, Response, RunResult, Status, MAX_REQUEST, MAX_RESPONSE,
};

use crate::broker::Broker;
use crate::compile::CompiledArtifact;
use crate::process::{Event, Peer, Role};

/// Host configuration for launching confined children.
#[derive(Debug, Clone)]
pub struct Config {
    pub worker_binary: PathBuf,
    /// Arguments inserted before the mode. Empty in production; a trusted
    /// test harness uses it to substitute a hostile peer script.
    pub worker_args: Vec<String>,
    pub compile_timeout: Duration,
}

impl Config {
    pub fn new(worker_binary: PathBuf) -> Config {
        Config {
            worker_binary,
            worker_args: Vec::new(),
            compile_timeout: Duration::from_secs(30),
        }
    }
}

/// Per-invocation options. Everything after `activation_context` is a trusted
/// test hook that never derives from guest input.
#[derive(Default)]
pub struct RunOptions {
    pub activation_context: Option<ActivationContext>,
    pub revoke_before_call: Option<u32>,
    pub stall_broker: bool,
    pub revoke_at_file_commit: bool,
    pub file_fault: Option<HelperFault>,
    pub revoke_event: Option<Arc<AtomicBool>>,
    pub before_file_commit: Option<Box<dyn Fn(&Broker) + Send>>,
}

const POLL: Duration = Duration::from_millis(20);
const OUTPUT_QUOTA: usize = 256 * 1024;
const MAX_FRAMES: u32 = 130;
const GRACE: Duration = Duration::from_millis(50);
const CLEANUP: Duration = Duration::from_secs(1);

/// Terminal outcome of the event loop: a status with optional value and error.
type LoopOutcome = Result<Option<(Status, Option<i32>, Option<String>)>, Denied>;

fn matches_activation(context: Option<&ActivationContext>, grant: &evx_api::Grant) -> bool {
    context.is_none_or(|c| c.matches(grant))
}

/// Admit and run one invocation of `artifact` under `broker`.
pub fn run_guest(
    config: &Config,
    artifact: &CompiledArtifact,
    broker: &Broker,
    options: RunOptions,
) -> RunResult {
    if broker.quarantined() {
        return RunResult::denied("workspace quarantined");
    }
    if !broker.grant().enabled {
        return RunResult::denied("EVX opt-in required");
    }
    if artifact.engine_key != evx_runtime::engine_key() {
        return RunResult::denied("artifact engine mismatch");
    }
    let generation;
    {
        let mut inner = broker.lock();
        if !inner.grant.enabled {
            return RunResult::denied("execution grant revoked");
        }
        generation = inner.grant.generation;
        if !matches_activation(options.activation_context.as_ref(), &inner.grant) {
            return RunResult::denied("activation authority changed");
        }
        if inner.running {
            return RunResult::denied("workspace busy");
        }
        if flock(broker.root_fd(), FlockOperation::NonBlockingLockExclusive).is_err() {
            return RunResult::denied("workspace busy");
        }
        inner.running = true;
        inner.active_capabilities = options
            .activation_context
            .as_ref()
            .map(|c| c.capabilities.clone());
        inner.calls = 0;
        inner.responses.clear();
    }
    let result = execute(config, artifact, broker, &options, generation);
    {
        let mut inner = broker.lock();
        inner.running = false;
        inner.active_capabilities = None;
        if !inner.quarantined {
            let _ = flock(broker.root_fd(), FlockOperation::Unlock);
        }
    }
    result
}

struct Loop<'a> {
    config: &'a Config,
    broker: &'a Broker,
    options: &'a RunOptions,
    generation: u64,
    worker: Peer,
    helper: Option<Peer>,
    helper_request: Option<Vec<u8>>,
    finished: Vec<Peer>,
    events: Vec<String>,
    commit_unknown: bool,
    peak_rss: u64,
    started: Instant,
    pending_response: Option<Response>,
}

fn execute(
    config: &Config,
    artifact: &CompiledArtifact,
    broker: &Broker,
    options: &RunOptions,
    generation: u64,
) -> RunResult {
    let started = Instant::now();
    let (tx, rx) = mpsc::channel();
    let limits = broker.limits();
    let init = match encode(&ToWorker::Init {
        artifact: artifact.bytes.clone(),
        artifact_sha256: artifact.sha256.clone(),
        limits: limits.clone(),
    }) {
        Ok(frame) => frame,
        Err(e) => return RunResult::denied(e.to_string()),
    };
    let worker = {
        let inner = broker.lock();
        if !inner.grant.enabled
            || inner.grant.generation != generation
            || !matches_activation(options.activation_context.as_ref(), &inner.grant)
        {
            return RunResult::denied("execution grant revoked");
        }
        match Peer::spawn(
            config,
            "run",
            broker.workspace(),
            Role::Guest,
            tx.clone(),
            None,
        ) {
            Ok(peer) => peer,
            Err(e) => return RunResult::denied(e.to_string()),
        }
    };
    let mut state = Loop {
        config,
        broker,
        options,
        generation,
        worker,
        helper: None,
        helper_request: None,
        finished: Vec::new(),
        events: Vec::new(),
        commit_unknown: false,
        peak_rss: 0,
        started,
        pending_response: None,
    };
    let worker_pid = state.worker.pid;
    let mut outcome: LoopOutcome = Ok(None);
    if let Err(e) = state.worker.send(&init) {
        outcome = Err(e);
    }
    let mut worker_result: Option<evx_api::frames::WorkerResult> = None;
    if outcome.is_ok() {
        outcome = state.run_loop(&rx, &tx, &mut worker_result);
    }

    // Terminate everything that is still alive and collect reports.
    let Loop {
        worker,
        helper,
        finished,
        events,
        mut commit_unknown,
        peak_rss,
        ..
    } = state;
    let mut quarantined = false;
    let mut peers: Vec<Peer> = Vec::with_capacity(finished.len() + 2);
    peers.push(worker);
    peers.extend(finished);
    if let Some(helper) = helper {
        peers.push(helper);
    }
    for peer in peers.iter_mut() {
        if peer.role == Role::File && peer.commit_sent && !peer.terminal {
            commit_unknown = true;
        }
        if peer.close(GRACE, CLEANUP).is_err() {
            quarantined = true;
        }
    }
    if quarantined {
        broker.lock().quarantined = true;
    }

    let (mut status, mut value, mut error) = match outcome {
        Ok(Some((status, value, error))) => (status, value, error),
        Ok(None) => (
            Status::Error,
            None,
            Some("worker did not finish".to_string()),
        ),
        Err(e) => (Status::Error, None, Some(e.to_string())),
    };
    let mut fuel_used = 0;
    let mut memory_bytes = 0;
    if status == Status::Ok {
        if let Some(result) = &worker_result {
            fuel_used = result.fuel_used;
            memory_bytes = result.memory_bytes;
            value = result.value;
            error = result.error.clone();
            if result.status == WorkerStatus::Error {
                status = Status::Error;
            }
        }
    } else if let Some(result) = &worker_result {
        fuel_used = result.fuel_used;
        memory_bytes = result.memory_bytes;
    }
    if quarantined {
        status = Status::Quarantined;
        error = Some("child termination unconfirmed".into());
    } else if commit_unknown {
        status = Status::EffectUnknown;
        error = Some("file commit outcome needs reconciliation; do not replay blindly".into());
    }
    let inner = broker.lock();
    let total_cpu: f64 = peers.iter().map(|p| p.max_cpu).sum();
    RunResult {
        status,
        value,
        error: error.map(|e| safe_text(&e, 2048)),
        worker_started: true,
        worker_pid: Some(worker_pid as u32),
        worker_exit_code: peers.first().and_then(|p| p.exit_code),
        supervisor_elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
        broker_calls: inner.calls,
        responses: inner.responses.clone(),
        events,
        diagnostics: safe_text(&String::from_utf8_lossy(&peers[0].diagnostics), 4096),
        effective_limits: Some(limits),
        effect_outcome_unknown: commit_unknown,
        trusted_observations: Some(Observations {
            peak_aggregate_rss_bytes: peak_rss,
            cpu_seconds: total_cpu,
            poll_interval_seconds: POLL.as_secs_f64(),
            source: "macOS libproc and terminal wait4 CPU; sampled detection, not a hard allocation ceiling".into(),
        }),
        children: peers
            .iter()
            .map(|p| ChildReport {
                role: p.role.name().into(),
                pid: p.pid as u32,
                exit_code: p.exit_code,
                diagnostics: safe_text(&String::from_utf8_lossy(&p.diagnostics), 2048),
            })
            .collect(),
        fuel_used,
        memory_bytes,
    }
}

impl<'a> Loop<'a> {
    fn revoked(&self) -> bool {
        let inner = self.broker.lock();
        !inner.grant.enabled
            || inner.grant.generation != self.generation
            || !matches_activation(self.options.activation_context.as_ref(), &inner.grant)
    }

    fn reply(&mut self, response: Response) -> Result<(), Denied> {
        let encoded =
            serde_json::to_vec(&response).map_err(|_| Denied::new("broker result encoding"))?;
        if encoded.len() > MAX_RESPONSE {
            return Err(Denied::new("broker result limit"));
        }
        self.broker.lock().responses.push(response);
        let frame = encode(&ToWorker::Response { response: encoded })?;
        self.worker.send(&frame)
    }

    fn run_loop(
        &mut self,
        rx: &mpsc::Receiver<Event>,
        tx: &mpsc::Sender<Event>,
        worker_result: &mut Option<evx_api::frames::WorkerResult>,
    ) -> LoopOutcome {
        let limits = self.broker.limits();
        loop {
            let now = Instant::now();
            if let Some(flag) = &self.options.revoke_event {
                if flag.load(Ordering::Relaxed) {
                    self.broker.revoke();
                    return Err(Denied::new("execution grant revoked"));
                }
            }
            if self.revoked() {
                return Err(Denied::new("execution grant revoked"));
            }
            if now.duration_since(self.started).as_secs_f64() >= limits.wall_seconds {
                return Ok(Some((
                    Status::Timeout,
                    None,
                    Some("supervisor wall deadline".into()),
                )));
            }
            // Kernel observations for every live child.
            self.worker.measure()?;
            if let Some(helper) = self.helper.as_mut() {
                helper.measure()?;
            }
            let worker_alive = self.worker.poll().is_none();
            let helper_alive = self.helper.as_mut().is_some_and(|h| h.poll().is_none());
            let mut rss = 0;
            if worker_alive {
                rss += self.worker.last_rss.unwrap_or(0);
            }
            if helper_alive {
                rss += self.helper.as_ref().and_then(|h| h.last_rss).unwrap_or(0);
            }
            self.peak_rss = self.peak_rss.max(rss);
            if rss > limits.process_rss_bytes {
                return Ok(Some((
                    Status::ResourceLimit,
                    None,
                    Some("observed process RSS limit".into()),
                )));
            }
            let cpu: f64 = self.worker.max_cpu
                + self.helper.as_ref().map_or(0.0, |h| h.max_cpu)
                + self.finished.iter().map(|p| p.max_cpu).sum::<f64>();
            if cpu > limits.process_cpu_seconds {
                return Ok(Some((
                    Status::ResourceLimit,
                    None,
                    Some("observed process CPU limit".into()),
                )));
            }
            // Native call deadline for the helper.
            if let Some(helper) = self.helper.as_mut() {
                if now.duration_since(helper.started).as_secs_f64() > limits.host_call_seconds {
                    self.commit_unknown |= helper.commit_sent;
                    self.events.push("native_call_deadline".into());
                    let mut helper = self.helper.take().expect("helper present");
                    let _ = helper
                        .close(GRACE, CLEANUP)
                        .map_err(|_| Denied::new("child termination unconfirmed"))?;
                    self.finished.push(helper);
                    if self.commit_unknown {
                        return Ok(Some((
                            Status::EffectUnknown,
                            None,
                            Some("file commit outcome needs reconciliation".into()),
                        )));
                    }
                    self.reply(Response::error("native operation deadline"))?;
                }
            }
            match rx.recv_timeout(POLL) {
                Ok(Event::Stderr(role, chunk)) => {
                    let peer = self.peer_mut(role);
                    if let Some(peer) = peer {
                        peer.output_bytes += chunk.len();
                        if peer.output_bytes > OUTPUT_QUOTA {
                            return Err(Denied::new("worker output quota"));
                        }
                        peer.record_stderr(&chunk);
                    }
                }
                Ok(Event::Closed(role, stream, protocol_error)) => {
                    if let Some(message) = protocol_error {
                        return Err(Denied::new(message));
                    }
                    if let Some(peer) = self.peer_mut(role) {
                        peer.readers = peer.readers.saturating_sub(1);
                    }
                    let _ = stream;
                }
                Ok(Event::Frame(role, body)) => {
                    let peer = self
                        .peer_mut(role)
                        .ok_or_else(|| Denied::new("stale helper message"))?;
                    peer.output_bytes += body.len();
                    peer.frames += 1;
                    if peer.output_bytes > OUTPUT_QUOTA {
                        return Err(Denied::new("worker output quota"));
                    }
                    if peer.frames > MAX_FRAMES {
                        return Err(Denied::new("worker frame count"));
                    }
                    match role {
                        Role::Guest => self.guest_frame(&body, tx, worker_result)?,
                        Role::File => self.helper_frame(&body)?,
                        Role::Compiler => return Err(Denied::new("worker protocol")),
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(Denied::new("worker channel closed"))
                }
            }
            // Helper completion.
            if let Some(helper) = self.helper.as_mut() {
                if helper.poll().is_some() && helper.readers == 0 {
                    let helper = self.helper.take().expect("helper present");
                    let ok = helper.terminal && helper.exit_code == Some(0);
                    if !ok {
                        self.commit_unknown |= helper.commit_sent;
                        self.finished.push(helper);
                        return Err(Denied::new("file helper failed"));
                    }
                    let response = self
                        .pending_response
                        .take()
                        .expect("helper result recorded");
                    self.finished.push(helper);
                    self.reply(response)?;
                }
            }
            // Worker completion.
            if self.worker.poll().is_some() && self.worker.readers == 0 {
                let code = self.worker.exit_code;
                let cpu: f64 = self.worker.max_cpu
                    + self.helper.as_ref().map_or(0.0, |h| h.max_cpu)
                    + self.finished.iter().map(|p| p.max_cpu).sum::<f64>();
                if cpu > limits.process_cpu_seconds {
                    return Ok(Some((
                        Status::ResourceLimit,
                        None,
                        Some("observed process CPU limit".into()),
                    )));
                }
                return match (worker_result.as_ref(), code) {
                    (Some(_), Some(0)) => Ok(Some((Status::Ok, None, None))),
                    _ => Ok(Some((
                        Status::Error,
                        None,
                        Some("worker exited without clean completion".into()),
                    ))),
                };
            }
        }
    }

    fn peer_mut(&mut self, role: Role) -> Option<&mut Peer> {
        match role {
            Role::Guest => Some(&mut self.worker),
            Role::File => self.helper.as_mut(),
            Role::Compiler => None,
        }
    }

    fn guest_frame(
        &mut self,
        body: &[u8],
        tx: &mpsc::Sender<Event>,
        worker_result: &mut Option<evx_api::frames::WorkerResult>,
    ) -> Result<(), Denied> {
        if self.worker.terminal {
            return Err(Denied::new("message after terminal result"));
        }
        let frame: FromWorker =
            strict::parse_typed(body).map_err(|_| Denied::new("worker protocol"))?;
        match frame {
            FromWorker::Call { request } => {
                if self.helper.is_some() {
                    return Err(Denied::new("overlapping broker request"));
                }
                if request.len() > MAX_REQUEST {
                    return Err(Denied::new("worker request limit"));
                }
                let limits = self.broker.limits();
                let calls = {
                    let mut inner = self.broker.lock();
                    inner.calls += 1;
                    inner.calls
                };
                if calls > limits.host_calls {
                    return Err(Denied::new("worker IPC call budget"));
                }
                if self.options.revoke_before_call == Some(calls) {
                    self.broker.revoke();
                }
                if self.options.stall_broker {
                    return Ok(());
                }
                let authorized = {
                    let inner = self.broker.lock();
                    Broker::authorize(&inner, &request, self.generation)
                };
                let decoded = match authorized {
                    Ok(request) => request,
                    Err(_) => return self.reply(Response::error("request or capability denied")),
                };
                if decoded == Request::GameScoreGet {
                    return self.reply(Response::Score {
                        ok: true,
                        score: 42,
                    });
                }
                let (snapshot, limits_generation, xite, capabilities) = {
                    let inner = self.broker.lock();
                    let caps: Vec<_> = inner
                        .active_capabilities
                        .clone()
                        .unwrap_or_else(|| inner.grant.capabilities.clone())
                        .into_iter()
                        .collect();
                    (
                        inner.limits.clone(),
                        inner.limits_generation,
                        inner.grant.xite.clone(),
                        caps,
                    )
                };
                let init = encode(&ToHelper::Init {
                    xite,
                    generation: self.generation,
                    capabilities,
                    limits: snapshot,
                    request: decoded,
                    test_fault: self.options.file_fault,
                })?;
                let lease_fd = rustix::fd::AsRawFd::as_raw_fd(&self.broker.root_fd());
                let mut helper = Peer::spawn(
                    self.config,
                    "file",
                    self.broker.workspace(),
                    Role::File,
                    tx.clone(),
                    Some(lease_fd),
                )?;
                helper.limits_generation = limits_generation;
                helper.send(&init)?;
                self.helper_request = Some(request);
                self.helper = Some(helper);
                Ok(())
            }
            FromWorker::Result(result) => {
                if self.helper.is_some() {
                    return Err(Denied::new("invalid terminal result"));
                }
                match result.status {
                    WorkerStatus::Ok if result.value.is_none() => {
                        return Err(Denied::new("invalid result value"))
                    }
                    WorkerStatus::Error if result.error.is_none() => {
                        return Err(Denied::new("invalid error value"))
                    }
                    _ => {}
                }
                self.worker.terminal = true;
                *worker_result = Some(result);
                Ok(())
            }
        }
    }

    fn helper_frame(&mut self, body: &[u8]) -> Result<(), Denied> {
        let frame: FromHelper =
            strict::parse_typed(body).map_err(|_| Denied::new("file helper protocol"))?;
        let helper = self
            .helper
            .as_mut()
            .ok_or_else(|| Denied::new("stale helper message"))?;
        if helper.terminal {
            return Err(Denied::new("stale helper message"));
        }
        match frame {
            FromHelper::Prepared => {
                if helper.prepared {
                    return Err(Denied::new("invalid commit request"));
                }
                helper.prepared = true;
                if self.options.revoke_at_file_commit {
                    self.broker.revoke();
                }
                if let Some(hook) = &self.options.before_file_commit {
                    hook(self.broker);
                }
                let request = self
                    .helper_request
                    .clone()
                    .ok_or_else(|| Denied::new("invalid commit request"))?;
                let limits = self.broker.limits();
                let helper = self.helper.as_mut().expect("helper present");
                {
                    let inner = self.broker.lock();
                    Broker::authorize(&inner, &request, self.generation)?;
                    if helper.limits_generation != inner.limits_generation {
                        return Err(Denied::new("limits changed before commit"));
                    }
                    let now = Instant::now();
                    if now.duration_since(helper.started).as_secs_f64() > limits.host_call_seconds
                        || now.duration_since(self.started).as_secs_f64() >= limits.wall_seconds
                    {
                        return Err(Denied::new("commit deadline"));
                    }
                    helper.send(&encode(&ToHelper::Commit)?)?;
                    helper.commit_sent = true;
                }
                self.events.push("file_commit_authorized".into());
                Ok(())
            }
            FromHelper::FileResult { response } => {
                helper.terminal = true;
                if helper.commit_sent && !response.is_ok() {
                    self.commit_unknown = true;
                }
                self.pending_response = Some(response);
                Ok(())
            }
            FromHelper::FaultEntered => {
                if self.options.file_fault.is_none() {
                    return Err(Denied::new("file helper protocol"));
                }
                self.events.push("native_fault_entered".into());
                Ok(())
            }
        }
    }
}
