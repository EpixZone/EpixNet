//! [`ReticulumTransport`]: the `epix-transport` [`Transport`] backed by a
//! Reticulum node. This is what plugs mesh into the stack - the wire protocol,
//! the DHT's `kad` RPCs, and the worker all dial through the same trait, so
//! `dial(PeerAddr::Rns(hash))` yields a `PeerStream` exactly like TCP does.
//!
//! Dialing a bare destination hash needs that destination's descriptor
//! (identity + name), which Reticulum learns from *announces*. So the transport
//! keeps a background task folding every announce it hears into a `hash -> desc`
//! table, and [`dial`](ReticulumTransport::dial) waits (up to a timeout) for the
//! target to appear there before opening the link.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use epix_core::{Error, PeerAddr, Result};
use epix_transport::{PeerStream, Transport};
use reticulum::destination::link::LinkStatus;
use reticulum::destination::DestinationDesc;
use reticulum::hash::AddressHash;
use reticulum::transport::Transport as RnsTransport;
use tokio::sync::Mutex;
use tokio::time::{sleep, Instant};

use crate::{reliable::ReliableStream, stream_protocol, ReticulumStream, StreamProtocol};

/// A mesh transport over a Reticulum node.
pub struct ReticulumTransport {
    inner: Arc<Mutex<RnsTransport>>,
    known: Arc<Mutex<HashMap<AddressHash, (DestinationDesc, Instant)>>>,
    dial_timeout: Duration,
    announce_task: tokio::task::JoinHandle<()>,
}

impl ReticulumTransport {
    /// Wrap a running Reticulum node (interfaces already spawned). Starts a
    /// task that learns destination descriptors from announces.
    pub fn new(inner: Arc<Mutex<RnsTransport>>) -> Self {
        let known: Arc<Mutex<HashMap<AddressHash, (DestinationDesc, Instant)>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let inner_task = inner.clone();
        let known_task = known.clone();
        let announce_task = tokio::spawn(async move {
            let mut announces = inner_task.lock().await.recv_announces().await;
            drop(inner_task);
            loop {
                let announce = match announces.recv().await {
                    Ok(announce) => announce,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };
                let desc = announce.destination.lock().await.desc;
                if stream_protocol(&desc.name).is_err() {
                    continue;
                }
                let mut known = known_task.lock().await;
                // Radio discovery is untrusted input even after signature validation.
                // Evict the oldest entry at capacity, so departed peers cannot
                // permanently prevent learning a newly encountered device.
                remember_announce(&mut known, desc, Instant::now());
            }
        });

        Self {
            inner,
            known,
            dial_timeout: Duration::from_secs(20),
            announce_task,
        }
    }

    /// How long `dial` waits for an announce / link activation. Defaults to 20s.
    pub fn with_dial_timeout(mut self, timeout: Duration) -> Self {
        self.dial_timeout = timeout;
        self
    }

    async fn await_desc(&self, hash: &AddressHash) -> Result<DestinationDesc> {
        let deadline = Instant::now() + self.dial_timeout;
        loop {
            {
                let known = self.known.lock().await;
                if let Some((desc, _)) = known.get(hash).copied() {
                    return Ok(preferred_descriptor(
                        desc,
                        known.values().map(|(desc, _)| desc),
                    ));
                }
            }
            if Instant::now() >= deadline {
                return Err(Error::Protocol(format!(
                    "no reticulum announce for {hash} within timeout"
                )));
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    /// Signature-verified, supported node destinations, not assertions about
    /// which xites the remote node serves. Prefer reliable radio streams.
    pub async fn candidates(&self) -> Vec<PeerAddr> {
        let known = self.known.lock().await;
        let now = Instant::now();
        let mut candidates: Vec<_> = known
            .values()
            .filter(|(desc, seen)| {
                now.duration_since(*seen) <= Duration::from_secs(120)
                    && matches!(stream_protocol(&desc.name), Ok(StreamProtocol::Reliable))
            })
            .map(|(desc, _)| {
                let mut hash = [0; 16];
                hash.copy_from_slice(desc.address_hash.as_slice());
                PeerAddr::Rns(hash)
            })
            .collect();
        candidates.sort_by_key(ToString::to_string);
        candidates.truncate(32);
        candidates
    }
}

impl Drop for ReticulumTransport {
    fn drop(&mut self) {
        self.announce_task.abort();
    }
}

fn remember_announce(
    known: &mut HashMap<AddressHash, (DestinationDesc, Instant)>,
    desc: DestinationDesc,
    now: Instant,
) {
    if known.len() >= 256 && !known.contains_key(&desc.address_hash) {
        if let Some(oldest) = known
            .iter()
            .min_by_key(|(_, (_, seen))| *seen)
            .map(|(hash, _)| *hash)
        {
            known.remove(&oldest);
        }
    }
    known.insert(desc.address_hash, (desc, now));
}

fn preferred_descriptor<'a>(
    desc: DestinationDesc,
    mut known: impl Iterator<Item = &'a DestinationDesc>,
) -> DestinationDesc {
    if !matches!(stream_protocol(&desc.name), Ok(StreamProtocol::Legacy)) {
        return desc;
    }
    known
        .find(|candidate| {
            matches!(
                stream_protocol(&candidate.name),
                Ok(StreamProtocol::Reliable)
            ) && candidate.identity.public_key.as_bytes() == desc.identity.public_key.as_bytes()
                && candidate.identity.verifying_key.as_bytes()
                    == desc.identity.verifying_key.as_bytes()
        })
        .copied()
        .unwrap_or(desc)
}

#[cfg(test)]
#[path = "tests/protocol.rs"]
mod protocol_tests;

#[async_trait]
impl Transport for ReticulumTransport {
    fn scheme(&self) -> &'static str {
        "rns"
    }

    async fn dial(&self, addr: &PeerAddr) -> Result<PeerStream> {
        let hash = match addr {
            PeerAddr::Rns(bytes) => AddressHash::new(*bytes),
            other => {
                return Err(Error::Protocol(format!(
                    "ReticulumTransport cannot dial a `{}` peer",
                    other.scheme()
                )))
            }
        };

        let desc = self.await_desc(&hash).await?;
        let protocol =
            stream_protocol(&desc.name).map_err(|error| Error::Protocol(error.to_string()))?;
        // Subscribe before the link is up so no early data slips past.
        let events = self.inner.lock().await.out_link_events();
        let link = self.inner.lock().await.link(desc).await;

        let deadline = Instant::now() + self.dial_timeout;
        loop {
            if link.lock().await.status() == LinkStatus::Active {
                break;
            }
            if Instant::now() >= deadline {
                return Err(Error::Protocol(format!(
                    "reticulum link to {hash} did not activate"
                )));
            }
            sleep(Duration::from_millis(50)).await;
        }

        let link_id = *link.lock().await.id();
        match protocol {
            StreamProtocol::Legacy => Ok(Box::pin(ReticulumStream::wrap(
                self.inner.clone(),
                link,
                link_id,
                events,
            ))),
            StreamProtocol::Reliable => ReliableStream::wrap(self.inner.clone(), link, link_id)
                .await
                .map(|stream| Box::pin(stream) as PeerStream)
                .map_err(|error| Error::Protocol(error.to_string())),
        }
    }
}
