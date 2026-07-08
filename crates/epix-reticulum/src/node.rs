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
use epix_protocol::RequestHandler;

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
    transport: Arc<RnsTransport>,
    destination: Arc<Mutex<SingleInputDestination>>,
    dest_hash: [u8; 16],
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

        let mut transport =
            RnsTransport::new(TransportConfig::new("epix", &identity, true));
        let destination =
            transport.add_destination(identity, DestinationName::new("epix", "node")).await;
        let transport = Arc::new(transport);

        let mut dest_hash = [0u8; 16];
        dest_hash.copy_from_slice(destination.lock().await.desc.address_hash.as_slice());

        {
            let manager = transport.iface_manager();
            let mut manager = manager.lock().await;
            for peer in &config.tcp_peers {
                manager.spawn(TcpClient::new(peer.clone()), TcpClient::spawn);
            }
            if let Some(listen) = &config.tcp_listen {
                manager.spawn(
                    TcpServer::new(listen.clone(), transport.iface_manager()),
                    TcpServer::spawn,
                );
            }
        }

        Ok(MeshNode { transport, destination, dest_hash })
    }

    /// Our mesh address (the destination hash peers dial).
    pub fn addr(&self) -> PeerAddr {
        PeerAddr::Rns(self.dest_hash)
    }

    /// The destination hash as hex, for status displays.
    pub fn dest_hash_hex(&self) -> String {
        self.dest_hash.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A dialing [`ReticulumTransport`] over this mesh node.
    pub fn transport(&self) -> ReticulumTransport {
        ReticulumTransport::new(self.transport.clone())
    }

    /// Announce our destination every `interval` so peers (re)learn the path
    /// to us. Runs until the returned task is aborted.
    pub fn spawn_announce(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let transport = self.transport.clone();
        let destination = self.destination.clone();
        tokio::spawn(async move {
            loop {
                transport.send_announce(&destination, None).await;
                tokio::time::sleep(interval).await;
            }
        })
    }

    /// Serve the wire protocol to peers that link to us (the mesh-side
    /// `PeerServer`). Runs forever; spawn it.
    pub async fn serve(&self, handler: Arc<dyn RequestHandler>) {
        ReticulumServer::new(handler).serve(self.transport.clone()).await;
    }
}
