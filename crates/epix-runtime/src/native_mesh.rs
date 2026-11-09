//! Live mesh generations and the platform-neutral native socket bridge.
use crate::edx;
use async_trait::async_trait;
use epix_core::PeerAddr;
use epix_reticulum::{radio, MeshConfig, MeshNode, ReticulumTransport};
use epix_ui::state::native_radio::{
    NativeRadioBridge, NativeRadioKind, NativeRadioRead, NativeRadioState, NativeRadioStream,
};
use epix_ui::state::AppState;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Notify};

struct Bridge {
    hub: radio::RadioHub,
    transport: Arc<ReticulumTransport>,
    node: Arc<MeshNode>,
}

#[async_trait]
impl NativeRadioBridge for Bridge {
    async fn open(&self, _kind: NativeRadioKind) -> Result<Arc<dyn NativeRadioStream>, String> {
        self.hub
            .open()
            .await
            .map(|stream| Arc::new(Stream(stream)) as Arc<dyn NativeRadioStream>)
            .map_err(|error| error.to_string())
    }
    async fn candidates(&self) -> Vec<PeerAddr> {
        self.transport.candidates().await
    }
    fn close(&self) {
        self.node.shutdown();
        self.hub.close();
    }
}

struct Stream(Arc<radio::RadioStream>);

#[async_trait]
impl NativeRadioStream for Stream {
    async fn write(&self, bytes: Vec<u8>, timeout: Duration) -> Result<(), String> {
        self.0
            .write(bytes, timeout)
            .await
            .map_err(|error| error.to_string())
    }
    async fn read(&self, max_bytes: usize, timeout: Duration) -> Result<NativeRadioRead, String> {
        self.0
            .read(max_bytes, timeout)
            .await
            .map(|read| NativeRadioRead {
                data: read.data,
                closed: read.closed,
            })
            .map_err(|error| error.to_string())
    }
    fn close(&self) {
        self.0.close();
    }
}

struct Generation {
    node: Arc<MeshNode>,
    bridge: Arc<Bridge>,
    announce: tokio::task::JoinHandle<()>,
    serve: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Generation {
    fn drop(&mut self) {
        self.node.shutdown();
        self.bridge.close();
        self.announce.abort();
        if let Some(serve) = &self.serve {
            serve.abort();
        }
    }
}

pub(super) async fn supervise(
    state: Arc<AppState>,
    identity_path: Option<PathBuf>,
    tcp_peers: Vec<String>,
    tcp_listen: Option<String>,
    edx_cell: edx::EdxServeCell,
    shutdown: Arc<Notify>,
) {
    let mut changes = state.native_mesh_changes();
    let mut stopping = Box::pin(shutdown.notified());
    stopping.as_mut().enable();
    let config = MeshConfig {
        identity_path,
        tcp_peers,
        tcp_listen,
    };
    loop {
        changes.borrow_and_update();
        if state.native_radio_state().await == NativeRadioState::Starting {
            match start_generation(&state, config.clone(), &edx_cell).await {
                Ok(generation) => {
                    let stop =
                        run_generation(&state, &generation, &mut changes, &mut stopping).await;
                    generation.bridge.close();
                    generation.node.shutdown();
                    state.clear_native_radio().await;
                    epix_protocol::update_self_advert(|advert| advert.rns = None);
                    drop(generation);
                    if stop {
                        break;
                    }
                    continue;
                }
                Err(error) => {
                    state
                        .log("WARNING", format!("Mesh: bring-up failed: {error}"))
                        .await
                }
            }
        }
        tokio::select! {
            _ = &mut stopping => break,
            result = changes.changed() => { if result.is_err() { break; } },
        }
    }
}

async fn start_generation(
    state: &Arc<AppState>,
    config: MeshConfig,
    edx_cell: &edx::EdxServeCell,
) -> Result<Generation, String> {
    let node = Arc::new(
        MeshNode::spawn(config)
            .await
            .map_err(|error| error.to_string())?,
    );
    let transport = Arc::new(node.transport());
    let bridge = Arc::new(Bridge {
        hub: node.radio_hub().await,
        transport: transport.clone(),
        node: node.clone(),
    });
    if !state
        .install_native_radio(
            bridge.clone(),
            transport,
            &node.dest_hash_hex(),
            &node.reliable_dest_hash_hex(),
        )
        .await
    {
        node.shutdown();
        return Err("mesh disabled during startup".into());
    }
    let announce = node.spawn_announce(Duration::from_secs(15));
    let mut generation = Generation {
        node,
        bridge,
        announce,
        serve: None,
    };
    generation.serve = edx::ensure_edx_serve(edx_cell, state).await.map(|server| {
        let node = generation.node.clone();
        let hook = server.overlay_hook();
        tokio::spawn(async move { node.serve(hook).await })
    });
    state
        .log(
            "INFO",
            format!("Mesh: up, address rns:{}", generation.node.dest_hash_hex()),
        )
        .await;
    Ok(generation)
}

async fn run_generation<F: std::future::Future<Output = ()> + Unpin>(
    state: &AppState,
    generation: &Generation,
    changes: &mut watch::Receiver<()>,
    shutdown: &mut F,
) -> bool {
    let mut tick = tokio::time::interval(Duration::from_secs(3));
    let mut previous = Vec::new();
    loop {
        tokio::select! {
            _ = &mut *shutdown => return true,
            _ = changes.changed() => return false,
            _ = tick.tick() => {
                let candidates = generation.bridge.candidates().await;
                if candidates != previous {
                    previous = candidates;
                    state.request_all_xite_updates().await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
