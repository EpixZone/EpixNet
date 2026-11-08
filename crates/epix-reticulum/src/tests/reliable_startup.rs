use super::*;
use crate::ReticulumTransport;
use epix_core::PeerAddr;
use epix_transport::Transport as PeerTransport;
use rand_core::OsRng;
use reticulum::destination::{link::LinkEvent, DestinationName};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::TransportConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn early_channel_bytes_retry_until_delayed_server_wrap_and_flush_waits_for_ack() {
    tokio::time::timeout(Duration::from_secs(15), early_send())
        .await
        .unwrap();
}

async fn early_send() {
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let mut server = Transport::new(TransportConfig::new("startup-server", &identity, true));
    let destination = server
        .add_destination(identity, DestinationName::new("epix", "node.v2"))
        .await;
    let hash = destination.lock().await.desc.address_hash;
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(hash.as_slice());
    let server = Arc::new(Mutex::new(server));
    server.lock().await.iface_manager().lock().await.spawn(
        UdpInterface::new("127.0.0.1:52045", Some("127.0.0.1:52046"), false),
        UdpInterface::spawn,
    );
    let mut events = server.lock().await.in_link_events();
    let (bind_tx, bind_rx) = tokio::sync::oneshot::channel();
    let accept = tokio::spawn({
        let server = server.clone();
        async move {
            let id = loop {
                let event = events.recv().await.unwrap();
                if matches!(event.event, LinkEvent::Activated) {
                    break event.id;
                }
            };
            // The client sends immediately after Active. No Channel is bound
            // here yet, so Link must not ACK and lose those early bytes.
            bind_rx.await.unwrap();
            let link = server.lock().await.find_in_link(&id).await.unwrap();
            let mut stream = ReliableStream::wrap(server, link, id).await.unwrap();
            let mut request = [0; 5];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"early");
            stream.write_all(b"ready").await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    let announce = tokio::spawn({
        let server = server.clone();
        async move {
            loop {
                server.lock().await.send_announce(&destination, None).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    });
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let client = Arc::new(Mutex::new(Transport::new(TransportConfig::new(
        "startup-client",
        &identity,
        true,
    ))));
    client.lock().await.iface_manager().lock().await.spawn(
        UdpInterface::new("127.0.0.1:52046", Some("127.0.0.1:52045"), false),
        UdpInterface::spawn,
    );
    let mut stream = ReticulumTransport::new(client)
        .dial(&PeerAddr::Rns(bytes))
        .await
        .unwrap();
    stream.write_all(b"early").await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), stream.flush())
            .await
            .is_err(),
        "unbound server cannot acknowledge delivery"
    );
    bind_tx.send(()).unwrap();
    stream.flush().await.unwrap();
    let mut response = [0; 5];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"ready");
    accept.await.unwrap();
    announce.abort();
}
