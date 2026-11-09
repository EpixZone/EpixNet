use super::{framing, RadioHub, MAX_RADIO_CHUNK, MAX_RADIO_LINKS};
use reticulum::iface::{InterfaceManager, TxMessage, TxMessageType};
use reticulum::packet::Packet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

fn fixture() -> (Arc<Mutex<InterfaceManager>>, RadioHub) {
    let manager = Arc::new(Mutex::new(InterfaceManager::new(8)));
    let hub = RadioHub::new(manager.clone());
    (manager, hub)
}

#[tokio::test]
async fn close_invalidates_generation_and_releases_waiters() {
    let (_, hub) = fixture();
    let stream = hub.open().await.unwrap();
    let reading = tokio::spawn({
        let stream = stream.clone();
        async move { stream.read(10, Duration::from_secs(5)).await.unwrap() }
    });
    hub.close();
    assert!(reading.await.unwrap().closed);
    assert!(stream.write(vec![1], Duration::ZERO).await.is_err());
    assert!(hub.open().await.is_err());
    let (_, replacement) = fixture();
    assert!(!replacement.open().await.unwrap().is_closed());
    assert!(stream.is_closed());
}

#[tokio::test]
async fn handle_limit_and_chunk_limits_are_enforced() {
    let (_, hub) = fixture();
    let mut streams = Vec::new();
    for _ in 0..MAX_RADIO_LINKS {
        streams.push(hub.open().await.unwrap());
    }
    assert!(hub.open().await.is_err());
    streams[0].close();
    tokio::task::yield_now().await;
    assert!(hub.open().await.is_ok());
    assert!(streams[1]
        .write(vec![0; MAX_RADIO_CHUNK + 1], Duration::ZERO)
        .await
        .is_err());
    assert!(streams[1].read(0, Duration::ZERO).await.is_err());
    assert!(streams[1]
        .read(MAX_RADIO_CHUNK + 1, Duration::ZERO)
        .await
        .is_err());
    let timeout = streams[1].read(1, Duration::from_millis(5)).await.unwrap();
    assert!(timeout.data.is_empty());
    assert!(!timeout.closed);
}

#[tokio::test]
async fn hdlc_packets_cross_chunk_boundaries() {
    let (manager, hub) = fixture();
    let stream = hub.open().await.unwrap();
    let mut packet = Packet::default();
    packet.data.write(&[0x7d, 0x7e, 1, 2]).unwrap();
    let encoded = framing::encode(&packet).unwrap();
    for byte in &encoded {
        stream
            .write(vec![*byte], Duration::from_secs(1))
            .await
            .unwrap();
    }
    let receive = manager.lock().await.receiver();
    let received = tokio::time::timeout(Duration::from_secs(1), receive.lock().await.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.packet, packet);
    manager
        .lock()
        .await
        .send(TxMessage {
            tx_type: TxMessageType::Broadcast(None),
            packet,
        })
        .await;
    let mut actual = Vec::new();
    while actual.len() < encoded.len() {
        let part = stream.read(3, Duration::from_secs(1)).await.unwrap();
        assert!(!part.data.is_empty());
        actual.extend(part.data);
    }
    assert_eq!(actual, encoded);
}

#[tokio::test]
async fn stalled_output_closes_only_its_interface() {
    let (manager, hub) = fixture();
    let stalled = hub.open().await.unwrap();
    let healthy = hub.open().await.unwrap();
    for _ in 0..32 {
        tokio::time::timeout(Duration::from_secs(1), async {
            manager
                .lock()
                .await
                .send(TxMessage {
                    tx_type: TxMessageType::Broadcast(None),
                    packet: Packet::default(),
                })
                .await;
            let next = healthy
                .read(MAX_RADIO_CHUNK, Duration::from_secs(1))
                .await
                .unwrap();
            assert!(!next.closed && !next.data.is_empty());
        })
        .await
        .unwrap();
    }
    assert!(stalled.is_closed());
    assert!(!healthy.is_closed());
}

#[tokio::test]
async fn stalled_packet_consumer_backpressures_whole_chunks_without_partial_writes() {
    let (manager, hub) = fixture();
    let stream = hub.open().await.unwrap();
    let encoded = framing::encode(&Packet::default()).unwrap();
    let mut accepted = 0;
    loop {
        match stream
            .write(encoded.clone(), Duration::from_millis(10))
            .await
        {
            Ok(()) => {
                accepted += 1;
                assert!(accepted <= 17);
            }
            Err(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
                break;
            }
        }
    }
    let receiver = manager.lock().await.receiver();
    for _ in 0..accepted {
        tokio::time::timeout(Duration::from_secs(1), receiver.lock().await.recv())
            .await
            .unwrap()
            .unwrap();
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(10), receiver.lock().await.recv())
            .await
            .is_err(),
        "timed-out write must not enqueue a partial packet"
    );
    assert!(!stream.is_closed());
}

#[tokio::test]
async fn shutdown_closes_tcp_listener_and_accepted_socket_despite_retained_transport() {
    use tokio::io::AsyncReadExt;
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let node = crate::MeshNode::spawn(crate::MeshConfig {
        tcp_listen: Some(address.to_string()),
        ..crate::MeshConfig::default()
    })
    .await
    .unwrap();
    let _retained_transport = node.transport();
    let mut socket = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(stream) = tokio::net::TcpStream::connect(address).await {
                break stream;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Give accept a turn, then revoke while the transport Arc is retained.
    tokio::task::yield_now().await;
    node.shutdown();
    let eof = tokio::time::timeout(Duration::from_secs(1), socket.read(&mut [0; 1]))
        .await
        .unwrap();
    assert!(matches!(eof, Ok(0)) || eof.is_err());
    tokio::time::timeout(Duration::from_secs(1), async {
        while tokio::net::TcpStream::connect(address).await.is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn oversized_and_malformed_frames_close_the_stream() {
    for bytes in [
        vec![0x7e, 0x7d, 0x7e],
        [vec![0x7e], vec![1; MAX_RADIO_CHUNK - 1]].concat(),
    ] {
        let (_, hub) = fixture();
        let stream = hub.open().await.unwrap();
        stream.write(bytes, Duration::from_secs(1)).await.unwrap();
        assert!(stream.read(1, Duration::from_secs(1)).await.unwrap().closed);
    }
}

#[tokio::test]
async fn oversized_packet_payload_is_rejected_and_maximum_payload_still_works() {
    let mut packet = Packet::default();
    packet
        .data
        .write(&vec![0x7e; reticulum::packet::PACKET_MDU])
        .unwrap();
    let valid = framing::encode(&packet).unwrap();
    let mut oversized = valid.clone();
    oversized.insert(oversized.len() - 1, 1);
    let mut decoder = framing::Decoder::default();
    let rejected = oversized
        .iter()
        .try_for_each(|byte| decoder.push(*byte).map(|_| ()));
    assert!(
        rejected.is_err(),
        "payload larger than PacketDataBuffer must return an error, not panic"
    );
    let (manager, hub) = fixture();
    let invalid_stream = hub.open().await.unwrap();
    for chunk in oversized.chunks(1024) {
        invalid_stream
            .write(chunk.to_vec(), Duration::from_secs(1))
            .await
            .unwrap();
    }
    assert!(
        invalid_stream
            .read(1, Duration::from_secs(1))
            .await
            .unwrap()
            .closed
    );
    let fresh = hub.open().await.unwrap();
    for chunk in valid.chunks(1024) {
        fresh
            .write(chunk.to_vec(), Duration::from_secs(1))
            .await
            .unwrap();
    }
    let receiver = manager.lock().await.receiver();
    let accepted = tokio::time::timeout(Duration::from_secs(1), receiver.lock().await.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.packet, packet);
    assert!(!fresh.is_closed());
}

fn pipe(from: Arc<super::RadioStream>, to: Arc<super::RadioStream>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let read = from
                .read(MAX_RADIO_CHUNK, Duration::from_millis(100))
                .await
                .unwrap();
            if read.closed {
                break;
            }
            for chunk in read.data.chunks(73) {
                if to
                    .write(chunk.to_vec(), Duration::from_secs(1))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    })
}

struct Circuit {
    streams: Vec<Arc<super::RadioStream>>,
    pumps: Vec<tokio::task::JoinHandle<()>>,
}

impl Circuit {
    async fn connect(a: &RadioHub, b: &RadioHub, c: &RadioHub) -> Self {
        let ab = a.open().await.unwrap();
        let ba = b.open().await.unwrap();
        let bc = b.open().await.unwrap();
        let cb = c.open().await.unwrap();
        let pumps = vec![
            pipe(ab.clone(), ba.clone()),
            pipe(ba.clone(), ab.clone()),
            pipe(bc.clone(), cb.clone()),
            pipe(cb.clone(), bc.clone()),
        ];
        Self {
            streams: vec![ab, ba, bc, cb],
            pumps,
        }
    }
}

impl Drop for Circuit {
    fn drop(&mut self) {
        for stream in &self.streams {
            stream.close();
        }
        for pump in &self.pumps {
            pump.abort();
        }
    }
}

async fn exchange(
    transport: &crate::ReticulumTransport,
    peer: &epix_core::PeerAddr,
) -> epix_edx::conn::Conn {
    use epix_transport::Transport;
    let stream = transport.dial(peer).await.unwrap();
    let (connection, _incoming) = epix_edx::link::dial_overlay(stream).await.unwrap();
    let payload: Vec<u8> = (0..16384).map(|i| (i % 251) as u8).collect();
    let reply = connection
        .request(epix_edx::msg::Req::Kad {
            payload: payload.clone(),
        })
        .await
        .unwrap();
    match reply {
        epix_edx::msg::Resp::Payload { bytes } => assert_eq!(bytes, payload),
        other => panic!("unexpected routed response {other:?}"),
    }
    connection
}

#[tokio::test]
async fn native_radio_three_node_route_survives_relay_reconnect() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let a = crate::MeshNode::spawn(crate::MeshConfig::default())
            .await
            .unwrap();
        let b = crate::MeshNode::spawn(crate::MeshConfig::default())
            .await
            .unwrap();
        let c = Arc::new(
            crate::MeshNode::spawn(crate::MeshConfig::default())
                .await
                .unwrap(),
        );
        let a_hub = a.radio_hub().await;
        let b_hub = b.radio_hub().await;
        let c_hub = c.radio_hub().await;
        // The only physical paths are A-B and B-C. No sockets or direct A-C path.
        let circuit = Circuit::connect(&a_hub, &b_hub, &c_hub).await;
        let transport = a.transport().with_dial_timeout(Duration::from_secs(10));
        let peer =
            epix_core::PeerAddr::parse(&format!("rns:{}", c.reliable_dest_hash_hex())).unwrap();
        let hook: epix_protocol::EdxHook = Arc::new(move |_, stream| {
            Box::pin(async move {
                let Ok((connection, mut incoming)) = epix_edx::link::accept_overlay(stream).await
                else {
                    return;
                };
                while let Some(request) = incoming.recv().await {
                    if let epix_edx::msg::Req::Kad { payload } = request.req {
                        if connection
                            .respond(
                                request.stream,
                                epix_edx::msg::Resp::Payload { bytes: payload },
                            )
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            })
        });
        let serve = tokio::spawn({
            let c = c.clone();
            async move { c.serve(hook).await }
        });
        let announces = [
            a.spawn_announce(Duration::from_millis(250)),
            b.spawn_announce(Duration::from_millis(250)),
            c.spawn_announce(Duration::from_millis(250)),
        ];
        let connection = exchange(&transport, &peer).await;
        eprintln!("initial A-B-C encrypted EDX 16KiB exchange passed");
        assert!(transport.candidates().await.contains(&peer));
        drop(circuit);
        assert!(
            !matches!(
                tokio::time::timeout(Duration::from_millis(300), connection.ping()).await,
                Ok(Ok(_))
            ),
            "A cannot bypass the lost relay"
        );
        connection.shutdown();
        eprintln!("relay loss blocked A-C traffic; reconnecting the two original edges");
        tokio::task::yield_now().await;
        let _reconnected = Circuit::connect(&a_hub, &b_hub, &c_hub).await;
        exchange(&transport, &peer).await.shutdown();
        for announce in announces {
            announce.abort();
        }
        serve.abort();
        a.shutdown();
        b.shutdown();
        c.shutdown();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_radio_discovery_rejects_forged_and_excessive_hop_announces() {
    use rand_core::OsRng;
    use reticulum::destination::{DestinationName, SingleInputDestination};
    use reticulum::identity::PrivateIdentity;
    let node = crate::MeshNode::spawn(crate::MeshConfig::default())
        .await
        .unwrap();
    let hub = node.radio_hub().await;
    let stream = hub.open().await.unwrap();
    let transport = node.transport();
    tokio::task::yield_now().await;
    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("epix", "node.v2"),
    );
    let valid = destination.announce(OsRng, None).unwrap();
    let mut forged = valid;
    forged.data.as_mut_slice()[100] ^= 1;
    stream
        .write(framing::encode(&forged).unwrap(), Duration::from_secs(1))
        .await
        .unwrap();
    let mut too_far = valid;
    too_far.header.hops = 255;
    stream
        .write(framing::encode(&too_far).unwrap(), Duration::from_secs(1))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(transport.candidates().await.is_empty());
    stream
        .write(framing::encode(&valid).unwrap(), Duration::from_secs(1))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while transport.candidates().await.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("valid announce still works after rejected packets");
    node.shutdown();
    assert!(stream.read(1, Duration::from_secs(1)).await.unwrap().closed);
}
