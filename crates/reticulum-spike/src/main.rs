//! Phase-0 spike: send a msgpack frame over a Reticulum Link between two nodes.
//!
//! Two in-process Reticulum stacks (server A + client B) bridged by a UDP
//! loopback link. A announces a destination; B discovers it, establishes a Link,
//! and sends a EpixNet-style msgpack frame; A receives it on its inbound link and
//! decodes it. Proves the Link can carry arbitrary payloads == our wire frames.

use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::link::LinkEvent;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};
use rmpv::Value;
use tokio::sync::oneshot;

const A_LISTEN: &str = "0.0.0.0:5151";
const A_FORWARD: &str = "127.0.0.1:5152";
const B_LISTEN: &str = "0.0.0.0:5152";
const B_FORWARD: &str = "127.0.0.1:5151";

fn frame() -> Vec<u8> {
    // A EpixNet-style request frame, exactly what epix-protocol would send.
    let msg = Value::Map(vec![
        (Value::from("cmd"), Value::from("ping")),
        (Value::from("req_id"), Value::from(7)),
        (Value::from("params"), Value::Map(vec![])),
    ]);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &msg).unwrap();
    buf
}

#[tokio::main]
async fn main() {
    println!("→ starting two in-process Reticulum nodes over UDP loopback");
    let (done_tx, done_rx) = oneshot::channel::<Vec<u8>>();

    // ---- Node A: server. Registers + announces a destination, receives links. ----
    let server = tokio::spawn(async move {
        let id = PrivateIdentity::new_from_rand(OsRng);
        let mut transport = Transport::new(TransportConfig::new("A-server", &id, true));
        let dest = transport
            .add_destination(id.clone(), DestinationName::new("epix", "mesh"))
            .await;
        let _ = transport.iface_manager().lock().await.spawn(
            UdpInterface::new(A_LISTEN, Some(A_FORWARD), false),
            UdpInterface::spawn,
        );

        let mut in_events = transport.in_link_events();
        let mut done_tx = Some(done_tx);
        loop {
            // Announce so B can discover us.
            transport.send_announce(&dest, None).await;
            // Drain inbound link events; a Data event carries B's msgpack frame.
            while let Ok(ev) = in_events.try_recv() {
                if let LinkEvent::Data(payload) = ev.event {
                    if let Some(tx) = done_tx.take() {
                        let _ = tx.send(payload.as_slice().to_vec());
                    }
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    // ---- Node B: client. Discovers A's announce, links, sends the frame. ----
    let client = tokio::spawn(async move {
        let id = PrivateIdentity::new_from_rand(OsRng);
        let transport = Transport::new(TransportConfig::new("B-client", &id, true));
        let _ = transport.iface_manager().lock().await.spawn(
            UdpInterface::new(B_LISTEN, Some(B_FORWARD), false),
            UdpInterface::spawn,
        );

        let mut announces = transport.recv_announces().await;
        let mut link = None;
        let mut sent = false;
        loop {
            while let Ok(announce) = announces.try_recv() {
                let desc = announce.destination.lock().await.desc;
                if link.is_none() {
                    println!("  B: discovered A's destination, establishing link…");
                    link = Some(transport.link(desc).await);
                }
            }
            if let Some(link) = &link {
                let guard = link.lock().await;
                if guard.status() == reticulum::destination::link::LinkStatus::Active && !sent {
                    println!("  B: link active → sending msgpack frame ({} bytes)", frame().len());
                    let packet = guard.data_packet(&frame()).unwrap();
                    drop(guard);
                    transport.send_packet(packet).await;
                    sent = true;
                }
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    });

    // ---- Await delivery (with timeout) ----
    let payload = match tokio::time::timeout(Duration::from_secs(30), done_rx).await {
        Ok(Ok(p)) => p,
        _ => {
            eprintln!("✗ timed out waiting for frame over the mesh link");
            std::process::exit(1);
        }
    };
    server.abort();
    client.abort();

    println!("✓ A received {} bytes over the Reticulum link", payload.len());
    let decoded = rmpv::decode::read_value(&mut payload.as_slice()).expect("decode msgpack");
    let cmd = decoded
        .as_map()
        .and_then(|m| m.iter().find(|(k, _)| k.as_str() == Some("cmd")))
        .and_then(|(_, v)| v.as_str());
    assert_eq!(cmd, Some("ping"), "decoded frame: {decoded:?}");
    assert_eq!(payload, frame(), "payload survived the link byte-for-byte");
    println!("✓ decoded msgpack frame intact: cmd={cmd:?}");
    println!("\n🎉 RETICULUM MESH LINK CONFIRMED — our wire frames travel over a Reticulum Link.");
}
