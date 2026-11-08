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
    known: Arc<Mutex<HashMap<AddressHash, DestinationDesc>>>,
    dial_timeout: Duration,
}

impl ReticulumTransport {
    /// Wrap a running Reticulum node (interfaces already spawned). Starts a
    /// task that learns destination descriptors from announces.
    pub fn new(inner: Arc<Mutex<RnsTransport>>) -> Self {
        let known: Arc<Mutex<HashMap<AddressHash, DestinationDesc>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let inner_task = inner.clone();
        let known_task = known.clone();
        tokio::spawn(async move {
            let mut announces = inner_task.lock().await.recv_announces().await;
            while let Ok(announce) = announces.recv().await {
                let desc = announce.destination.lock().await.desc;
                known_task.lock().await.insert(desc.address_hash, desc);
            }
        });

        Self {
            inner,
            known,
            dial_timeout: Duration::from_secs(20),
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
                if let Some(desc) = known.get(hash).copied() {
                    return Ok(preferred_descriptor(desc, &known));
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
}

fn preferred_descriptor(
    desc: DestinationDesc,
    known: &HashMap<AddressHash, DestinationDesc>,
) -> DestinationDesc {
    if !matches!(stream_protocol(&desc.name), Ok(StreamProtocol::Legacy)) {
        return desc;
    }
    known
        .values()
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
