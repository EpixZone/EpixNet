//! Live PEX probe: connect to a running node's fileserver, run `pex` for a
//! site, and print the peer buckets it returns - used to confirm the node
//! advertises its own overlay (onion/i2p) addresses.
//!
//! Usage: cargo run -p epix-runtime --example pex_probe -- <ip:port> <site>

use epix_core::PeerAddr;
use epix_protocol::Connection;
use epix_transport::TcpTransport;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:26552".into());
    let site = args.next().unwrap_or_default();
    let transport = TcpTransport;
    let peer = PeerAddr::parse(&addr).expect("ip:port");

    let mut conn = Connection::connect(&transport, &peer).await.expect("connect");
    conn.handshake().await.expect("handshake");
    let reply = conn
        .pex(&site, Vec::new(), Vec::new(), Vec::new(), Vec::new(), 50)
        .await
        .expect("pex");

    println!("ipv4:  {} peers", reply.ipv4.len());
    println!("ipv6:  {} peers", reply.ipv6.len());
    println!("onion: {} peers", reply.onion.len());
    for b in &reply.onion {
        if let Some(p) = PeerAddr::unpack_onion(b) {
            println!("   {p}");
        }
    }
    println!("i2p:   {} peers", reply.i2p.len());
    for b in &reply.i2p {
        if let Some(p) = PeerAddr::unpack_i2p(b) {
            println!("   {p}");
        }
    }
}
