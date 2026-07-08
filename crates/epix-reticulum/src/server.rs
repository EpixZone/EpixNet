//! [`ReticulumServer`]: the mesh-side counterpart to `epix-protocol`'s
//! `PeerServer`. Where `PeerServer` accepts TCP connections, this accepts
//! inbound Reticulum links, wraps each as a [`ReticulumStream`], and runs the
//! same request/response loop (`serve_stream`) over it. With both, a node can
//! dial *and* be dialed over mesh - the wire protocol is fully bidirectional
//! over Reticulum.

use std::sync::Arc;

use epix_core::PeerAddr;
use epix_protocol::{serve_stream, RequestHandler};
use reticulum::destination::link::LinkEvent;
use reticulum::transport::Transport as RnsTransport;

use crate::ReticulumStream;

/// Serves the wire protocol over inbound Reticulum links.
pub struct ReticulumServer {
    handler: Arc<dyn RequestHandler>,
    version: String,
    rev: i64,
}

impl ReticulumServer {
    pub fn new(handler: Arc<dyn RequestHandler>) -> Self {
        Self { handler, version: "EpixRS".into(), rev: 8192 }
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

            let mut addr = [0u8; 16];
            addr.copy_from_slice(ev.id.as_slice());
            let stream = Box::pin(ReticulumStream::wrap(
                transport.clone(),
                link,
                ev.id,
                stream_events,
            ));

            let handler = self.handler.clone();
            let version = self.version.clone();
            let rev = self.rev;
            tokio::spawn(async move {
                // Mesh destinations aren't port-addressed; advertise 0.
                serve_stream(handler, PeerAddr::Rns(addr), stream, &version, rev, 0).await;
            });
        }
    }
}
