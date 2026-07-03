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

    let total = needed.len();
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let queue: Arc<Mutex<VecDeque<(FileEntry, u8)>>> =
        Arc::new(Mutex::new(needed.into_iter().map(|f| (f, 0u8)).collect()));
    let report = Arc::new(Mutex::new(SyncReport::default()));
    let address = Arc::new(xite.address.as_str().to_string());
    let root = Arc::new(xite.storage.root().to_path_buf());

    let worker_count = peers.len().min(max_workers.max(1));
    let mut handles = Vec::new();
    for i in 0..worker_count {
        let peer = peers[i % peers.len()].clone();
        let queue = queue.clone();
        let report = report.clone();
        let address = address.clone();
        let storage = XiteStorage::new((*root).clone());
        let transport = transport.clone();
        let on_file = on_file.clone();
        let done = done.clone();

        handles.push(tokio::spawn(async move {
            let mut conn = match connect(transport.as_ref(), &peer).await {
                Some(c) => c,
                None => {
                    // Couldn't use this peer - leave the queue for other workers.
                    return;
                }
            };
            loop {
                let next = { queue.lock().await.pop_front() };
                let Some((file, attempts)) = next else { break };

                let fetched = tokio::time::timeout(
                    FILE_TIMEOUT,
                    conn.get_file(&address, &file.inner_path),
                )
                .await
                .unwrap_or_else(|_| Err(epix_core::Error::Protocol("file transfer timed out".into())));
                match fetched {
                    Ok(bytes) if XiteStorage::hash_bytes(&bytes) == file.sha512 => {
                        if storage.write(&file.inner_path, &bytes).is_ok() {
                            {
                                let mut r = report.lock().await;
                                r.downloaded += 1;
                                r.bytes += bytes.len() as u64;
                            }
                            if let Some(cb) = &on_file {
                                let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                                cb(&file.inner_path, n, total);
                            }
                        } else {
                            requeue_or_fail(&queue, &report, file, attempts).await;
                        }
                    }
                    _ => {
                        requeue_or_fail(&queue, &report, file, attempts).await;
                        // The connection may be unhealthy; reconnect for the next item.
                        match connect(transport.as_ref(), &peer).await {
                            Some(c) => conn = c,
                            None => break,
                        }
                    }
                }
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }
    // Any items still queued (all workers gave up) count as failed.
    let leftover: Vec<String> = queue
        .lock()
        .await
        .drain(..)
        .map(|(f, _)| f.inner_path)
        .collect();
    let mut report = Arc::try_unwrap(report)
        .map(|m| m.into_inner())
        .unwrap_or_default();
    report.failed.extend(leftover);
    Ok(report)
}

/// Dial + handshake bounded by a deadline: an unreachable peer must not hang
/// its worker (the OS TCP timeout is ~75s) while the rest of the queue idles.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
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
