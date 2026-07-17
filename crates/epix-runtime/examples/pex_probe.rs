//! Live PEX/announce probe: connect to a running node's fileserver, run `pex`
//! and `announce` for a site, and print the peer buckets - used to confirm the
//! node advertises its own overlay (onion/i2p) addresses and acts as a tracker.
//!
//! Usage: cargo run -p epix-runtime --example pex_probe -- <ip:port> <site>

use epix_core::PeerAddr;
use epix_discovery::{address_hash, announce, AnnounceParams};
use epix_protocol::Connection;
use epix_transport::TcpTransport;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1); // nosemgrep: rust.lang.security.args.args
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:26552".into());
    let site = args.next().unwrap_or_default();
    let transport = TcpTransport;
    let peer = PeerAddr::parse(&addr).expect("ip:port");

    let mut conn = Connection::connect(&transport, &peer).await.expect("connect");
    conn.handshake().await.expect("handshake");
    let reply = conn
        .pex(&site, Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), 50)
        .await
        .expect("pex");

    println!("== pex ==");
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

    // Pull a file so the node accounts served bytes (Stats seeding graph).
    if !site.is_empty() {
        let mut conn = Connection::connect(&transport, &peer).await.expect("connect");
        conn.handshake().await.expect("handshake");
        match conn.get_file(&site, "content.json").await {
            Ok(bytes) => println!("== getFile content.json ==\n{} bytes served", bytes.len()),
            Err(e) => println!("== getFile content.json failed: {e} =="),
        }
    }

    // Announce to the node as if it were a tracker, requesting overlay peers.
    let hash = address_hash(&site);
    let params = AnnounceParams {
        hashes: &[hash],
        port: 0,
        need_types: &["ipv4", "ipv6", "onion", "i2p"],
        need_num: 50,
        add: &[],
        onions: &[],
        i2p: &[],
        onion_signer: None,
    };
    let mut conn = Connection::connect(&transport, &peer).await.expect("connect");
    conn.handshake().await.expect("handshake");
    let peers = announce(&mut conn, &params).await.expect("announce");
    println!("== announce (as tracker) for {site} ==");
    println!("{} peers", peers.len());
    for p in &peers {
        println!("   {p}");
    }

    // Prove the node records + serves i2p peers as a tracker: announce a fake
    // i2p address under a synthetic hash, then announce again under a second
    // identity and check the first address comes back.
    let test_hashes = [address_hash("pex_probe-tracker-selftest")];
    let need: [&str; 1] = ["i2p"];
    let add: [&str; 1] = ["i2p"];
    let a = "narvewf7cmhowltv4vybkf4y4zgt63xxf2kbiantnzrb3slglw2q.b32".to_string();
    let b = "6k2ogjmxenwjpznb37ipdzzmbayygbxw3ztjx32ogdzirfp7bloa.b32".to_string();
    // First announcer registers `a`.
    let mut conn = Connection::connect(&transport, &peer).await.expect("connect");
    conn.handshake().await.expect("handshake");
    let p1 = AnnounceParams {
        hashes: &test_hashes,
        port: 26552,
        need_types: &need,
        need_num: 50,
        add: &add,
        onions: &[],
        i2p: std::slice::from_ref(&a),
        onion_signer: None,
    };
    announce(&mut conn, &p1).await.expect("announce a");
    // Second announcer registers `b` and should discover `a`.
    let mut conn = Connection::connect(&transport, &peer).await.expect("connect");
    conn.handshake().await.expect("handshake");
    let p2 = AnnounceParams {
        hashes: &test_hashes,
        port: 26552,
        need_types: &need,
        need_num: 50,
        add: &add,
        onions: &[],
        i2p: std::slice::from_ref(&b),
        onion_signer: None,
    };
    let found = announce(&mut conn, &p2).await.expect("announce b");
    println!("== tracker i2p record+serve selftest ==");
    let want = PeerAddr::I2p { dest: a.clone(), port: 26552 };
    let got_a = found.contains(&want);
    let got_self = found.contains(&PeerAddr::I2p { dest: b.clone(), port: 26552 });
    println!("discovered peers: {found:?}");
    println!("serves other i2p peer (a): {got_a}");
    println!("excludes announcer itself (b): {}", !got_self);
    println!("RESULT: {}", if got_a && !got_self { "PASS" } else { "FAIL" });
}
