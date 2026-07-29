//! [`ReticulumServer`]: the mesh-side counterpart to `epix-protocol`'s
//! `PeerServer`. Where `PeerServer` accepts TCP connections, this accepts
//! inbound Reticulum links, wraps each as a [`ReticulumStream`], and hands it
//! to the EDX serve hook. With both, a node can dial *and* be dialed over
//! mesh - the wire protocol is fully bidirectional over Reticulum.

use std::sync::Arc;

use epix_core::PeerAddr;
use epix_protocol::EdxHook;
use reticulum::destination::link::LinkEvent;
use reticulum::transport::Transport as RnsTransport;

use crate::ReticulumStream;

/// Serves EDX over inbound Reticulum links.
pub struct ReticulumServer {
    edx: EdxHook,
}

impl ReticulumServer {
    /// `edx` must be the no-Noise OVERLAY hook: an RNS link is already
    /// encrypted and endpoint-authenticated, so EDX skips Noise over it.
    pub fn new(edx: EdxHook) -> Self {
        Self { edx }
    }

    /// Accept inbound links on `transport` forever, serving each on its own
    /// task. The transport's destination(s) must already be registered (via
    /// `add_destination`) and announced so peers can link to it.
    pub async fn serve(self, transport: Arc<RnsTransport>) {
        let mut events = transport.in_link_events();
        while let Ok(ev) = events.recv().await {
            let LinkEvent::Activated = ev.event else {
                continue;
            };
            // Subscribe this link's stream before fetching the handle so no
            // early request data slips past between activation and wrapping.
            let stream_events = transport.in_link_events();
            let Some(link) = transport.find_in_link(&ev.id).await else {
                continue;
            };

            let stream = Box::pin(ReticulumStream::wrap(
                transport.clone(),
                link,
                ev.id,
                stream_events,
            ));

            let edx = self.edx.clone();
            tokio::spawn(async move {
                // The inbound link id (`ev.id`) is NOT the peer's dialable
                // destination hash - it's an ephemeral per-link identifier the
                // stream uses for I/O, not an address we could dial back. Serve
                // under the all-zero sentinel, which `is_wellformed` rejects so
                // it never enters a peer table.
                edx(PeerAddr::Rns([0u8; 16]), stream).await;
            });
        }
    }
}
