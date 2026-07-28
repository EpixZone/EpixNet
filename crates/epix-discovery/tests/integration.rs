//! Epix-tracker discovery: a reproducible mock tracker, plus an `#[ignore]`d
//! test against a real live tracker on the network.

use epix_core::PeerAddr;
use epix_discovery::{address_hash, discover_via_epix_tracker, AnnounceParams};
use epix_protocol::msg::{read_msg, send_msg, vget, vmap};
use epix_transport::TcpTransport;
use rmpv::Value;
use tokio::net::TcpListener;


/// Mock Epix tracker: handshakes, then answers `announce` with one ipv4 peer.
async fn spawn_mock_tracker(peer_ip: [u8; 4], peer_port: u16) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let mut stream: epix_transport::PeerStream = Box::pin(sock);
        let mut buf = Vec::new();
        while let Ok(req) = read_msg(&mut stream, &mut buf).await {
            let cmd = vget(&req, "cmd").and_then(|v| v.as_str()).unwrap_or("");
            let to = vget(&req, "req_id").and_then(|v| v.as_i64()).unwrap_or(0);
            let resp = match cmd {
                "handshake" => vmap(vec![
                    ("cmd", Value::from("response")),
                    ("to", Value::from(to)),
                    ("version", Value::from("MockTracker")),
                    ("protocol", Value::from("v2")),
                    ("rev", Value::from(8192i64)),
                ]),
                "announce" => {
                    // port little-endian, matching EpixNet packAddress.
                    let mut packed = peer_ip.to_vec();
                    packed.extend_from_slice(&peer_port.to_le_bytes());
                    let xite = vmap(vec![("ipv4", Value::Array(vec![Value::Binary(packed)]))]);
                    vmap(vec![
                        ("cmd", Value::from("response")),
                        ("to", Value::from(to)),
                        ("peers", Value::Array(vec![xite])),
                    ])
                }
                _ => vmap(vec![
                    ("cmd", Value::from("response")),
                    ("to", Value::from(to)),
                    ("error", Value::from("Unknown command")),
                ]),
            };
            if send_msg(&mut stream, &resp).await.is_err() {
                break;
            }
        }
    });
    addr
}

#[tokio::test]
async fn discovers_peers_via_epix_tracker() {
    let tracker = spawn_mock_tracker([203, 0, 113, 7], 26959).await;
    let hash = address_hash("epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g");
    let params = AnnounceParams {
        hashes: &[hash],
        port: 0,
        need_types: &["ipv4", "ipv6"],
        need_num: 20,
        add: &[],
        onions: &[],
        i2p: &[],
        onion_signer: None,
    };
    let peers = discover_via_epix_tracker(&TcpTransport, &PeerAddr::Ip(tracker), &params)
        .await
        .unwrap();
    assert_eq!(peers, vec![PeerAddr::parse("203.0.113.7:26959").unwrap()]);
}

/// Manual: query a real live Epix tracker for the Dashboard xite's peers.
/// `cargo test -p epix-discovery -- --ignored live_tracker --nocapture`
#[tokio::test]
#[ignore]
async fn live_tracker_discovers_real_peers() {
    let tracker = PeerAddr::parse("145.223.69.23:26959").unwrap();
    let hash = address_hash("epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g");
    let params = AnnounceParams {
        hashes: &[hash],
        port: 0,
        need_types: &["ipv4", "ipv6"],
        need_num: 20,
        add: &[],
        onions: &[],
        i2p: &[],
        onion_signer: None,
    };
    let peers = discover_via_epix_tracker(&TcpTransport, &tracker, &params)
        .await
        .expect("announce to live tracker");
    println!("discovered {} real peers for the Dashboard xite:", peers.len());
    for p in &peers {
        println!("  {p}");
    }
    assert!(!peers.is_empty(), "expected at least one peer from the live tracker");
}
