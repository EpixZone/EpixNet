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

use crate::ReticulumStream;

/// A mesh transport over a Reticulum node.
pub struct ReticulumTransport {
    inner: Arc<RnsTransport>,
    known: Arc<Mutex<HashMap<AddressHash, DestinationDesc>>>,
    dial_timeout: Duration,
}

impl ReticulumTransport {
    /// Wrap a running Reticulum node (interfaces already spawned). Starts a
    /// task that learns destination descriptors from announces.
    pub fn new(inner: Arc<RnsTransport>) -> Self {
        let known: Arc<Mutex<HashMap<AddressHash, DestinationDesc>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let inner_task = inner.clone();
        let known_task = known.clone();
        tokio::spawn(async move {
            let mut announces = inner_task.recv_announces().await;
            while let Ok(announce) = announces.recv().await {
                let desc = announce.destination.lock().await.desc;
                known_task.lock().await.insert(desc.address_hash, desc);
            }
        });

        Self { inner, known, dial_timeout: Duration::from_secs(20) }
    }

    /// How long `dial` waits for an announce / link activation. Defaults to 20s.
    pub fn with_dial_timeout(mut self, timeout: Duration) -> Self {
        self.dial_timeout = timeout;
        self
    }

    async fn await_desc(&self, hash: &AddressHash) -> Result<DestinationDesc> {
        let deadline = Instant::now() + self.dial_timeout;
        loop {
            if let Some(desc) = self.known.lock().await.get(hash).copied() {
                return Ok(desc);
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
        // Subscribe before the link is up so no early data slips past.
        let events = self.inner.out_link_events();
        let link = self.inner.link(desc).await;

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
        Ok(Box::pin(ReticulumStream::wrap(self.inner.clone(), link, link_id, events)))
    }
}
