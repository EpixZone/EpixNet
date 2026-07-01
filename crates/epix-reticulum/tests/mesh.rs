//! Two Reticulum nodes over a UDP interface (loopback, no shared IP routing —
//! this is the RNS link itself, standing in for LoRa/BLE). A client dials the
//! server's destination, and a request/response round-trip flows as a byte
//! stream through [`ReticulumStream`] — proving the wire protocol can ride mesh.

use std::sync::Arc;
use std::time::Duration;

use epix_reticulum::ReticulumStream;
use rand_core::OsRng;
use reticulum::destination::link::{LinkEvent, LinkStatus};
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

const REQUEST: &[u8] = b"getFile content.json over the mesh";
const RESPONSE: &[u8] = b"pong: here is your file, delivered by Reticulum";

#[tokio::test]
async fn wire_bytes_round_trip_over_rns_link() {
    timeout(Duration::from_secs(30), run())
        .await
        .expect("mesh round-trip timed out");
}

async fn run() {
    let name = DestinationName::new("epix", "mesh");

    // --- Server: registers its destination, announces, serves inbound links.
    let server_id = PrivateIdentity::new_from_rand(OsRng);
    let mut server_tp = Transport::new(TransportConfig::new("server", &server_id, true));
    let server_dest = server_tp.add_destination(server_id.clone(), name).await;
    let server_tp = Arc::new(server_tp);
    server_tp.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:52011", Some("127.0.0.1:52012"), false),
        UdpInterface::spawn,
    );

    // --- Client: dials the announced destination.
    let client_id = PrivateIdentity::new_from_rand(OsRng);
    let client_tp = Arc::new(Transport::new(TransportConfig::new("client", &client_id, true)));
    client_tp.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:52012", Some("127.0.0.1:52011"), false),
        UdpInterface::spawn,
    );

    // Server keeps announcing so the client learns the destination descriptor.
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

    // Server side: accept the first inbound link, echo a response to a request.
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
            let link = server_tp
                .find_in_link(&link_id)
                .await
                .expect("server in-link handle");
            let mut stream =
                ReticulumStream::wrap(server_tp.clone(), link, link_id, in_events);

            let mut buf = vec![0u8; REQUEST.len()];
            stream.read_exact(&mut buf).await.expect("server read request");
            assert_eq!(buf, REQUEST, "server received the request bytes intact");

            stream.write_all(RESPONSE).await.expect("server write response");
            sleep(Duration::from_millis(500)).await; // let the writer task flush
        })
    };

    // Client side: wait for the announce, link, round-trip.
    let mut announces = client_tp.recv_announces().await;
    let out_events = client_tp.out_link_events();
    let desc = timeout(Duration::from_secs(15), async {
        loop {
            let ann = announces.recv().await.expect("client announce recv");
            break ann.destination.lock().await.desc;
        }
    })
    .await
    .expect("client learns server destination");

    let link = client_tp.link(desc).await;
    // Wait for the link to activate.
    timeout(Duration::from_secs(15), async {
        loop {
            if link.lock().await.status() == LinkStatus::Active {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("client link activates");

    let link_id = *link.lock().await.id();
    let mut stream = ReticulumStream::wrap(client_tp.clone(), link.clone(), link_id, out_events);

    // Give the server a beat to accept the inbound link and start reading.
    sleep(Duration::from_millis(600)).await;
    stream.write_all(REQUEST).await.expect("client write request");

    let mut buf = vec![0u8; RESPONSE.len()];
    stream.read_exact(&mut buf).await.expect("client read response");
    assert_eq!(buf, RESPONSE, "client received the response bytes intact");

    server_task.await.expect("server task");
}
