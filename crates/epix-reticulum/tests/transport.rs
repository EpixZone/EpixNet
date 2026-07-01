//! Exercises the `epix-transport::Transport` impl end to end: a client learns
//! the server's destination from an announce, then `dial(PeerAddr::Rns(hash))`
//! opens a mesh link and streams bytes — the same call site TCP uses.

use std::sync::Arc;
use std::time::Duration;

use epix_core::PeerAddr;
use epix_reticulum::{ReticulumStream, ReticulumTransport};
use epix_transport::Transport;
use rand_core::OsRng;
use reticulum::destination::link::LinkEvent;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport as RnsTransport, TransportConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

const REQUEST: &[u8] = b"handshake + getFile, dialed by destination hash";
const RESPONSE: &[u8] = b"served over ReticulumTransport";

#[tokio::test]
async fn dial_by_hash_streams_over_mesh() {
    timeout(Duration::from_secs(30), run())
        .await
        .expect("dial-by-hash round-trip timed out");
}

async fn run() {
    let name = DestinationName::new("epix", "mesh");

    // Server node: register + announce a destination, echo on inbound links.
    let server_id = PrivateIdentity::new_from_rand(OsRng);
    let mut server_tp = RnsTransport::new(TransportConfig::new("server", &server_id, true));
    let server_dest = server_tp.add_destination(server_id.clone(), name).await;
    let server_tp = Arc::new(server_tp);
    server_tp.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:52031", Some("127.0.0.1:52032"), false),
        UdpInterface::spawn,
    );

    // The 16-byte destination hash is the mesh peer address.
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

    let server_task = {
        let server_tp = server_tp.clone();
        tokio::spawn(async move {
            let mut in_events = server_tp.in_link_events();
            let link_id = loop {
                let ev = in_events.recv().await.expect("server link events");
                if let LinkEvent::Activated = ev.event {
                    break ev.id;
                }
            };
            let link = server_tp.find_in_link(&link_id).await.expect("in-link");
            let mut stream = ReticulumStream::wrap(server_tp.clone(), link, link_id, in_events);
            let mut buf = vec![0u8; REQUEST.len()];
            stream.read_exact(&mut buf).await.expect("server read");
            assert_eq!(buf, REQUEST);
            stream.write_all(RESPONSE).await.expect("server write");
            sleep(Duration::from_millis(500)).await;
        })
    };

    // Client node wrapped as a ReticulumTransport.
    let client_id = PrivateIdentity::new_from_rand(OsRng);
    let client_rns = Arc::new(RnsTransport::new(TransportConfig::new("client", &client_id, true)));
    client_rns.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:52032", Some("127.0.0.1:52031"), false),
        UdpInterface::spawn,
    );
    let client = ReticulumTransport::new(client_rns);

    // Dial by destination hash — the transport waits for the announce, links, streams.
    let mut stream = client
        .dial(&PeerAddr::Rns(hash))
        .await
        .expect("dial over mesh");

    sleep(Duration::from_millis(600)).await; // let the server accept the in-link
    stream.write_all(REQUEST).await.expect("client write");
    let mut buf = vec![0u8; RESPONSE.len()];
    stream.read_exact(&mut buf).await.expect("client read");
    assert_eq!(buf, RESPONSE, "client streamed the response over the dialed link");

    server_task.await.expect("server task");
}
