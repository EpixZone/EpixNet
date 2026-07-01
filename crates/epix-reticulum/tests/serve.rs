//! Full wire protocol over mesh, inbound: a `ReticulumServer` accepts a link
//! and answers requests, while a client dials it through `ReticulumTransport`
//! and drives a real `Connection` (handshake + a request). This is the mesh
//! equivalent of a TCP `PeerServer` + `Connection` round-trip.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use epix_core::PeerAddr;
use epix_protocol::{vmap, Connection, RequestHandler};
use epix_reticulum::{ReticulumServer, ReticulumTransport};
use rand_core::OsRng;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport as RnsTransport, TransportConfig};
use rmpv::Value;
use tokio::time::{sleep, timeout};

/// A handler that echoes back the `msg` param, proving request routing works.
struct EchoHandler;

#[async_trait]
impl RequestHandler for EchoHandler {
    async fn handle(&self, _peer: &PeerAddr, cmd: &str, params: &Value) -> Value {
        if cmd == "echo" {
            let msg = params
                .as_map()
                .and_then(|m| m.iter().find(|(k, _)| k.as_str() == Some("msg")))
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Nil);
            vmap(vec![("msg", msg)])
        } else {
            vmap(vec![("error", Value::from("unknown command"))])
        }
    }
}

#[tokio::test]
async fn wire_protocol_served_over_mesh() {
    timeout(Duration::from_secs(30), run())
        .await
        .expect("mesh serve round-trip timed out");
}

async fn run() {
    let name = DestinationName::new("epix", "mesh");

    // Server: register + announce a destination, serve the wire protocol on it.
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
    tokio::spawn(ReticulumServer::new(Arc::new(EchoHandler)).serve(server_tp.clone()));

    // Client: a ReticulumTransport, then a real Connection over the dialed link.
    let client_id = PrivateIdentity::new_from_rand(OsRng);
    let client_rns = Arc::new(RnsTransport::new(TransportConfig::new("client", &client_id, true)));
    client_rns.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:52042", Some("127.0.0.1:52041"), false),
        UdpInterface::spawn,
    );
    let client = ReticulumTransport::new(client_rns);

    let mut conn = Connection::connect(&client, &PeerAddr::Rns(hash))
        .await
        .expect("connect over mesh");

    let hs = conn.handshake().await.expect("handshake over mesh");
    assert_eq!(hs.version, "EpixRS", "server banner came back over mesh");

    let resp = conn
        .request("echo", vmap(vec![("msg", Value::from("hello mesh"))]))
        .await
        .expect("echo request over mesh");
    let echoed = resp
        .as_map()
        .and_then(|m| m.iter().find(|(k, _)| k.as_str() == Some("msg")))
        .and_then(|(_, v)| v.as_str());
    assert_eq!(echoed, Some("hello mesh"), "handler echoed the request over mesh");
}
