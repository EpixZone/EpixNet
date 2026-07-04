//! `epix-worker` - parallel file download manager.
//!
//! Given a xite (with verified content.json) and a set of peers, download every
//! needed file concurrently - one worker per peer pulling from a shared queue -
//! verifying each file's hash before it is written to the xite's storage.

use epix_core::{PeerAddr, Result};
use epix_protocol::Connection;
use epix_xite::{FileEntry, Xite, XiteStorage};
use epix_transport::Transport;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Outcome of a sync pass.
#[derive(Debug, Default)]
pub struct SyncReport {
    pub downloaded: usize,
    pub bytes: u64,
    /// inner_paths that could not be fetched + verified after retries.
    pub failed: Vec<String>,
}

const MAX_ATTEMPTS: u8 = 3;

/// Download order, ported from EpixNet's `WorkerManager.getPriorityBoost`:
/// the visible page first (index.html, then css/js/dbschema), user-data json
/// later, `-default` scaffolding last. With the progressive file route this
/// is what makes a big site render seconds into a clone.
pub fn download_priority(inner_path: &str) -> i32 {
    if inner_path == "content.json" {
        return 9999;
    }
    if inner_path == "index.html" {
        return 9998;
    }
    if inner_path.contains("-default") {
        return -4;
    }
    if inner_path.ends_with("all.css") {
        return 14;
    }
    if inner_path.ends_with("all.js") {
        return 13;
    }
    if inner_path.ends_with("dbschema.json") {
        return 12;
    }
    if inner_path.ends_with("content.json") {
        return 1;
    }
    if inner_path.ends_with(".json") {
        return if inner_path.len() < 50 { 11 } else { 2 };
    }
    0
}

/// Per-file progress callback: `(inner_path, files_done, files_total)`, called
/// as each file finishes downloading. Drives the wrapper's loading screen.
pub type FileProgress = Arc<dyn Fn(&str, usize, usize) + Send + Sync>;

/// Download all files in `xite.files_needed()` from `peers` concurrently.
///
/// Spawns up to `max_workers` workers (capped by the peer count); each connects
/// to a peer and pulls files from a shared queue, verifying the hash before
/// writing. Failed files are retried (up to [`MAX_ATTEMPTS`]) on other workers.
pub async fn sync_files(
    xite: &Xite,
    peers: &[PeerAddr],
    transport: Arc<dyn Transport>,
    max_workers: usize,
) -> Result<SyncReport> {
    sync_files_with_progress(xite, peers, transport, max_workers, None).await
}

/// Shared state for one sync pass, cloned into each worker.
#[derive(Clone)]
struct SyncCtx {
    queue: Arc<Mutex<VecDeque<(FileEntry, u8)>>>,
    report: Arc<Mutex<SyncReport>>,
    address: Arc<String>,
    root: Arc<std::path::PathBuf>,
    transport: Arc<dyn Transport>,
    on_file: Option<FileProgress>,
    done: Arc<std::sync::atomic::AtomicUsize>,
    total: usize,
}

impl SyncCtx {
    fn new(
        mut needed: Vec<FileEntry>,
        xite: &Xite,
        transport: Arc<dyn Transport>,
        on_file: Option<FileProgress>,
    ) -> Self {
        // Highest priority first: the visible page downloads before the bulk.
        needed.sort_by_key(|f| std::cmp::Reverse(download_priority(&f.inner_path)));
        let total = needed.len();
        Self {
            queue: Arc::new(Mutex::new(needed.into_iter().map(|f| (f, 0u8)).collect())),
            report: Arc::new(Mutex::new(SyncReport::default())),
            address: Arc::new(xite.address.as_str().to_string()),
            root: Arc::new(xite.storage.root().to_path_buf()),
            transport,
            on_file,
            done: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            total,
        }
    }

    /// Drain into the final report (leftover queue items count as failed).
    async fn finish(self) -> SyncReport {
        let leftover: Vec<String> =
            self.queue.lock().await.drain(..).map(|(f, _)| f.inner_path).collect();
        let mut report = Arc::try_unwrap(self.report)
            .map(|m| m.into_inner())
            .unwrap_or_default();
        report.failed.extend(leftover);
        report
    }
}

/// One worker: connect to `peer` and pull files from the shared queue until
/// it drains or the peer stops cooperating.
async fn run_worker(peer: PeerAddr, ctx: SyncCtx) {
    let storage = XiteStorage::new((*ctx.root).clone());
    let mut conn = match connect(ctx.transport.as_ref(), &peer).await {
        Some(c) => c,
        None => {
            // Couldn't use this peer - leave the queue for other workers.
            return;
        }
    };
    // Files this peer already failed to deliver: one shot per file per peer,
    // so a peer missing a file can't burn the global retry budget by itself -
    // the file goes back in the queue for a different peer.
    let mut refused: std::collections::HashSet<String> = std::collections::HashSet::new();
    loop {
        let next = {
            let mut q = ctx.queue.lock().await;
            let mut next = None;
            for _ in 0..q.len() {
                if let Some((f, a)) = q.pop_front() {
                    if refused.contains(&f.inner_path) {
                        q.push_back((f, a));
                    } else {
                        next = Some((f, a));
                        break;
                    }
                }
            }
            next
        };
        let Some((file, attempts)) = next else { break };

        let fetched = tokio::time::timeout(
            FILE_TIMEOUT,
            conn.get_file(&ctx.address, &file.inner_path),
        )
        .await
        .unwrap_or_else(|_| Err(epix_core::Error::Protocol("file transfer timed out".into())));
        match fetched {
            Ok(bytes) if XiteStorage::hash_bytes(&bytes) == file.sha512 => {
                if storage.write(&file.inner_path, &bytes).is_ok() {
                    {
                        let mut r = ctx.report.lock().await;
                        r.downloaded += 1;
                        r.bytes += bytes.len() as u64;
                    }
                    if let Some(cb) = &ctx.on_file {
                        let n = ctx.done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                        cb(&file.inner_path, n, ctx.total);
                    }
                } else {
                    requeue_or_fail(&ctx.queue, &ctx.report, file, attempts).await;
                }
            }
            _ => {
                refused.insert(file.inner_path.clone());
                requeue_or_fail(&ctx.queue, &ctx.report, file, attempts).await;
                // The connection may be unhealthy; reconnect for the next item.
                match connect(ctx.transport.as_ref(), &peer).await {
                    Some(c) => conn = c,
                    None => break,
                }
            }
        }
    }
}

/// Download an explicit list of files (not just the root content.json's
/// `files`) - used for the files declared by included / user content.json,
/// which the xite's own `files_needed()` doesn't know about.
pub async fn sync_files_list(
    needed: Vec<FileEntry>,
    xite: &Xite,
    peers: &[PeerAddr],
    transport: Arc<dyn Transport>,
    max_workers: usize,
) -> Result<SyncReport> {
    if needed.is_empty() || peers.is_empty() {
        let mut report = SyncReport::default();
        report.failed = needed.into_iter().map(|f| f.inner_path).collect();
        return Ok(report);
    }
    let max_workers = scale_workers(max_workers, needed.len());
    let ctx = SyncCtx::new(needed, xite, transport, None);
    let worker_count = peers.len().min(max_workers.max(1));
    let mut handles = Vec::new();
    for i in 0..worker_count {
        handles.push(tokio::spawn(run_worker(peers[i % peers.len()].clone(), ctx.clone())));
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(ctx.finish().await)
}

/// [`sync_files`], reporting each finished file to `on_file` - the on-demand
/// clone path, where a loading screen is watching.
pub async fn sync_files_with_progress(
    xite: &Xite,
    peers: &[PeerAddr],
    transport: Arc<dyn Transport>,
    max_workers: usize,
    on_file: Option<FileProgress>,
) -> Result<SyncReport> {
    let needed = xite.files_needed();
    if needed.is_empty() || peers.is_empty() {
        let mut report = SyncReport::default();
        report.failed = needed.into_iter().map(|f| f.inner_path).collect();
        return Ok(report);
    }
    let max_workers = scale_workers(max_workers, needed.len());
    let ctx = SyncCtx::new(needed, xite, transport, on_file);
    let worker_count = peers.len().min(max_workers.max(1));
    let mut handles = Vec::new();
    for i in 0..worker_count {
        handles.push(tokio::spawn(run_worker(peers[i % peers.len()].clone(), ctx.clone())));
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(ctx.finish().await)
}

/// Streaming sync: peers arrive over a channel while the download runs.
/// A worker spawns the moment a peer is discovered (up to `max_workers`);
/// extras are kept as spares and replace workers whose peer stops
/// cooperating. Ends when every file is downloaded, or when the peer
/// channel closes and no worker or spare can make progress.
pub async fn sync_files_streaming(
    xite: &Xite,
    mut peers: tokio::sync::mpsc::UnboundedReceiver<PeerAddr>,
    transport: Arc<dyn Transport>,
    max_workers: usize,
    on_file: Option<FileProgress>,
) -> Result<SyncReport> {
    let needed = xite.files_needed();
    if needed.is_empty() {
        return Ok(SyncReport::default());
    }
    let max_workers = scale_workers(max_workers, needed.len()).max(1);
    let ctx = SyncCtx::new(needed, xite, transport, on_file);
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut spares: VecDeque<PeerAddr> = VecDeque::new();
    let mut join = tokio::task::JoinSet::new();
    let mut channel_open = true;

    loop {
        // No workers running: done, respawn from a spare, or (channel closed)
        // give up on whatever is left.
        if join.is_empty() {
            if ctx.queue.lock().await.is_empty() {
                break;
            }
            if let Some(peer) = spares.pop_front() {
                join.spawn(run_worker(peer, ctx.clone()));
            } else if !channel_open {
                break;
            }
        }
        tokio::select! {
            maybe = peers.recv(), if channel_open => {
                match maybe {
                    None => channel_open = false,
                    Some(peer) => {
                        if seen.insert(peer.to_string()) {
                            if join.len() < max_workers && !ctx.queue.lock().await.is_empty() {
                                join.spawn(run_worker(peer, ctx.clone()));
                            } else {
                                spares.push_back(peer);
                            }
                        }
                    }
                }
            }
            Some(_) = join.join_next(), if !join.is_empty() => {
                // A worker finished; the top of the loop decides what's next.
            }
            else => break,
        }
    }
    Ok(ctx.finish().await)
}

/// EpixNet's `getMaxWorkers`: triple the worker cap when the task list is
/// large, so big sites saturate more peers.
fn scale_workers(max_workers: usize, tasks: usize) -> usize {
    if tasks > 50 { max_workers * 3 } else { max_workers }
}

/// Dial + handshake bounded by a deadline: an unreachable peer must not hang
/// its worker (the OS TCP timeout is ~75s) while the rest of the queue idles.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// Per-file transfer deadline: a peer that stalls mid-transfer gets requeued.
const FILE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

async fn connect(transport: &dyn Transport, peer: &PeerAddr) -> Option<Connection> {
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        let mut conn = Connection::connect(transport, peer).await.ok()?;
        conn.handshake().await.ok()?;
        Some(conn)
    })
    .await
    .ok()
    .flatten()
}

async fn requeue_or_fail(
    queue: &Arc<Mutex<VecDeque<(FileEntry, u8)>>>,
    report: &Arc<Mutex<SyncReport>>,
    file: FileEntry,
    attempts: u8,
) {
    if attempts + 1 < MAX_ATTEMPTS {
        queue.lock().await.push_back((file, attempts + 1));
    } else {
        report.lock().await.failed.push(file.inner_path);
    }
}

#[cfg(test)]
mod tests {
    use super::download_priority;

    #[test]
    fn priority_orders_the_visible_page_first() {
        let mut files = vec![
            "data/users/1abc/content.json",
            "js/all.js",
            "index.html",
            "img/hero.png",
            "css/all.css",
            "dbschema.json",
            "index-default.html",
        ];
        files.sort_by_key(|f| std::cmp::Reverse(download_priority(f)));
        assert_eq!(
            files,
            vec![
                "index.html",
                "css/all.css",
                "js/all.js",
                "dbschema.json",
                "data/users/1abc/content.json",
                "img/hero.png",
                "index-default.html",
            ]
        );
    }
}
