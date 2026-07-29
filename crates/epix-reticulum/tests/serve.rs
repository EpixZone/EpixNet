//! EDX over the **real Reticulum mesh**, inbound: a `ReticulumServer` accepts
//! a link and brings up an EDX connection on it, while a client dials the same
//! destination through `ReticulumTransport` and pings across it. This is the
//! mesh equivalent of a TCP accept loop plus an outbound dial, and it proves
//! `ReticulumStream` carries EDX framing in both directions over a link with no
//! shared IP routing.

use std::sync::Arc;
use std::time::Duration;

use epix_core::PeerAddr;
use epix_protocol::EdxHook;
use epix_reticulum::{ReticulumServer, ReticulumTransport};
use epix_transport::Transport;
use rand_core::OsRng;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport as RnsTransport, TransportConfig};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

#[tokio::test]
async fn edx_served_over_mesh() {
    timeout(Duration::from_secs(30), run()).await.expect("mesh serve round-trip timed out");
}

async fn run() {
    let name = DestinationName::new("epix", "mesh");

    // Server: register + announce a destination, bring EDX up on every
    // inbound link. An RNS link is already encrypted, so this is the
    // no-Noise overlay accept.
    let (served_tx, mut served_rx) = mpsc::channel::<()>(4);
    let hook: EdxHook = Arc::new(move |_peer, stream| {
        let served_tx = served_tx.clone();
        Box::pin(async move {
            let Ok((conn, incoming)) = epix_edx::link::accept_overlay(stream).await else {
                return;
            };
            let _ = served_tx.send(()).await;
            // Keep the connection (and its reader/writer tasks) alive so the
            // client's ping has something to answer it; the receiver is held
            // for the same reason.
            let _incoming = incoming;
            std::future::pending::<()>().await;
            drop(conn);
        })
    });

    let server_id = PrivateIdentity::new_from_rand(OsRng);
    let mut server_tp = RnsTransport::new(TransportConfig::new("server", &server_id, true));
    let server_dest = server_tp.add_destination(server_id.clone(), name).await;
    let server_tp = Arc::new(server_tp);
    server_tp.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:52041", Some("127.0.0.1:52042"), false),
        UdpInterface::spawn,
    );

    let mut hash = [0u8; 16];
    hash.copy_from_slice(server_dest.lock().await.desc.address_hash.as_slice());

    {
        let server_tp = server_tp.clone();
        let server_dest = server_dest.clone();
        tokio::spawn(async move {
            loop {
                server_tp.send_announce(&server_dest, None).await;
                sleep(Duration::from_millis(400)).await;
            }
        });
    }
    tokio::spawn(ReticulumServer::new(hook).serve(server_tp.clone()));

    // Client: a ReticulumTransport, then an EDX link over the dialed link.
    let client_id = PrivateIdentity::new_from_rand(OsRng);
    let client_rns = Arc::new(RnsTransport::new(TransportConfig::new("client", &client_id, true)));
    client_rns.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:52042", Some("127.0.0.1:52041"), false),
        UdpInterface::spawn,
    );
    let client = ReticulumTransport::new(client_rns);

    let stream = client.dial(&PeerAddr::Rns(hash)).await.expect("dial over mesh");
    let (conn, _incoming) =
        epix_edx::link::dial_overlay(stream).await.expect("EDX magic exchange over mesh");
    served_rx.recv().await.expect("the server brought EDX up on its side");

    let rtt = conn.ping().await.expect("ping answered over mesh");
    assert!(rtt < Duration::from_secs(30), "measured an RTT, got {rtt:?}");
}
