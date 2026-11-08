//! [`MeshNode`]: the node-facing bring-up of a Reticulum mesh presence.
//!
//! The transport/server halves of this crate take a caller-constructed
//! [`reticulum::transport::Transport`]; this is the constructor the Epix node
//! uses. It loads (or creates and persists) the mesh identity, registers the
//! node's `epix.node` destination, spawns the configured interfaces, and
//! announces the destination so peers can link to it.
//!
//! Interfaces are Reticulum's physical layer. TCP first: a mesh usually has a
//! few always-on nodes reachable over IP that everything else meshes through
//! (Reticulum's "TCP interface" role); LoRa/BLE radios plug in as further
//! interface types later without touching this API.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::transport::{Transport as RnsTransport, TransportConfig};
use tokio::sync::Mutex;

use crate::{ReticulumServer, ReticulumTransport};
use epix_core::PeerAddr;

/// How the node joins the mesh.
#[derive(Debug, Clone, Default)]
pub struct MeshConfig {
    /// Where to persist the mesh identity (hex); a stable identity keeps the
    /// node's destination hash - its mesh address - across restarts. None
    /// uses an ephemeral identity (tests).
    pub identity_path: Option<PathBuf>,
    /// TCP interfaces to dial (`host:port`) - other mesh nodes or hubs.
    pub tcp_peers: Vec<String>,
    /// A TCP interface to listen on (`ip:port`), so other nodes can mesh
    /// through us over IP.
    pub tcp_listen: Option<String>,
}

/// A running mesh presence: the Reticulum node, our announced destination,
/// and the adapters that put the wire protocol on top.
pub struct MeshNode {
    transport: Arc<Mutex<RnsTransport>>,
    destination: Arc<Mutex<SingleInputDestination>>,
    legacy_destination: Arc<Mutex<SingleInputDestination>>,
    dest_hash: [u8; 16],
    reliable_dest_hash: [u8; 16],
    shutdown: Box<dyn Fn() + Send + Sync>,
}

impl MeshNode {
    /// Bring up the mesh: identity, destination, interfaces. Cheap and
    /// non-blocking - interfaces connect in the background.
    pub async fn spawn(config: MeshConfig) -> std::io::Result<MeshNode> {
        let identity = match &config.identity_path {
            Some(path) => match std::fs::read_to_string(path)
                .ok()
                .and_then(|hex| PrivateIdentity::new_from_hex_string(hex.trim()).ok())
            {
                Some(identity) => identity,
                None => {
                    let identity = PrivateIdentity::new_from_rand(OsRng);
                    if let Some(dir) = path.parent() {
                        std::fs::create_dir_all(dir)?;
                    }
                    std::fs::write(path, identity.to_hex_string())?;
                    identity
                }
            },
            None => PrivateIdentity::new_from_rand(OsRng),
        };

        // Mesh is explicitly opted in. Forward encrypted RNS packets so nearby
        // devices can reach one another through an intermediate phone.
        let mut transport =
            RnsTransport::new(TransportConfig::new("epix", &identity, true).set_retransmit(true));
        let legacy_destination = transport
            .add_destination(identity.clone(), DestinationName::new("epix", "node"))
            .await;
        let destination = transport
            .add_destination(identity, DestinationName::new("epix", "node.v2"))
            .await;
        let shutdown = transport.shutdown_token();
        let transport = Arc::new(Mutex::new(transport));

        let mut dest_hash = [0u8; 16];
        dest_hash.copy_from_slice(legacy_destination.lock().await.desc.address_hash.as_slice());
        let mut reliable_dest_hash = [0u8; 16];
        reliable_dest_hash.copy_from_slice(destination.lock().await.desc.address_hash.as_slice());

        {
            let manager_shared = transport.lock().await.iface_manager();
            let mut manager = manager_shared.lock().await;
            for peer in &config.tcp_peers {
                manager.spawn(TcpClient::new(peer.clone()), TcpClient::spawn);
            }
            if let Some(listen) = &config.tcp_listen {
                manager.spawn(
                    TcpServer::new(listen.clone(), manager_shared.clone()),
                    TcpServer::spawn,
                );
            }
        }

        Ok(MeshNode {
            transport,
            destination,
            legacy_destination,
            dest_hash,
            reliable_dest_hash,
            shutdown: Box::new(move || shutdown.cancel()),
        })
    }

    /// Our mesh address (the destination hash peers dial).
    pub fn addr(&self) -> PeerAddr {
        PeerAddr::Rns(self.dest_hash)
    }

    /// The destination hash as hex, for status displays.
    pub fn dest_hash_hex(&self) -> String {
        self.dest_hash.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Reliable v2 destination, signed by the same persistent mesh identity.
    pub fn reliable_dest_hash_hex(&self) -> String {
        self.reliable_dest_hash
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// A dialing [`ReticulumTransport`] over this mesh node.
    pub fn transport(&self) -> ReticulumTransport {
        ReticulumTransport::new(self.transport.clone())
    }

    /// Attach native byte streams to this generation's interface manager.
    pub async fn radio_hub(&self) -> crate::radio::RadioHub {
        crate::radio::RadioHub::new(self.transport.lock().await.iface_manager())
    }

    /// Revoke this generation even if an in-flight peer still retains it.
    pub fn shutdown(&self) {
        (self.shutdown)();
    }

    /// Announce our destination every `interval` so peers (re)learn the path
    /// to us. Runs until the returned task is aborted.
    pub fn spawn_announce(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let transport = self.transport.clone();
        let destination = self.destination.clone();
        let legacy_destination = self.legacy_destination.clone();
        tokio::spawn(async move {
            loop {
                let transport = transport.lock().await;
                transport.send_announce(&destination, None).await;
                transport.send_announce(&legacy_destination, None).await;
                drop(transport);
                tokio::time::sleep(interval).await;
            }
        })
    }

    /// Serve EDX to peers that link to us (the mesh-side `PeerServer`). Runs
    /// forever; spawn it. `edx` must be the no-Noise overlay hook - an RNS
    /// link already encrypts.
    pub async fn serve(&self, edx: epix_protocol::EdxHook) {
        ReticulumServer::new(edx)
            .serve(self.transport.clone())
            .await;
    }
}

impl Drop for MeshNode {
    fn drop(&mut self) {
        self.shutdown();
    }
}
