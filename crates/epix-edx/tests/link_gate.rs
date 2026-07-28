//! Stage 1 gate for the Phase C node integration: the assembled link
//! helpers (magic + Noise + Conn::start) establish a working EDX link over
//! a real TCP socket routed by the first-byte sniff, and the sniff leaves a
//! legacy (msgpack) stream untouched so both protocols share one port.

use std::sync::Arc;

use epix_blob::store::Store;
use epix_blob::{Ns, ObjId};
use epix_core::PeerAddr;
use epix_edx::frame::Sniff;
use epix_edx::link;
use epix_edx::msg::caps;
use epix_edx::server::{serve, ServeCtx, SignedProvider};
use epix_edx::fetch;
use epix_transport::{TcpTransport, Transport};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SERVER_KEY: &str = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
const CLIENT_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn temp_store() -> (Arc<Store>, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    (Arc::new(Store::open(dir.path()).unwrap()), dir)
}

fn test_data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
}

struct FixtureProvider;
#[async_trait::async_trait]
impl SignedProvider for FixtureProvider {
    async fn get_signed(&self, _x: &str, _p: &str) -> Option<Vec<u8>> {
        None
    }
    async fn list_signed(&self, _x: &str, _s: u64) -> Vec<(String, u64, u64)> {
        Vec::new()
    }
    async fn xite_summary(&self, _x: &str) -> Option<(u64, u64, u64)> {
        None
    }
    async fn apply_update(
        &self,
        _x: &str,
        _p: &str,
        _s: &[u8],
        _i: &[(ObjId, Vec<u8>)],
        _m: f64,
        _d: &[(String, Vec<u8>)],
        _sp: &[String],
    ) -> Result<bool, String> {
        Ok(true)
    }
}

/// A TCP server that routes each accepted socket by the first-byte sniff,
/// exactly as the node's serve fork will: EDX -> link::accept -> serve;
/// anything else is recorded so the test can prove legacy is untouched.
async fn spawn_sniffing_server(store: Arc<Store>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ctx = Arc::new(ServeCtx::new(store, Arc::new(FixtureProvider), SERVER_KEY.into()));
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else { break };
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let _ = sock.set_nodelay(true);
                let (kind, stream) = match link::read_sniff(Box::pin(sock)).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                match kind {
                    Sniff::Edx => {
                        let Ok(l) = link::accept(stream).await else { return };
                        serve(l.conn, l.incoming, ctx, Some(l.handshake_hash)).await;
                    }
                    // The legacy msgpack server would take the rewound stream
                    // here; this fixture just drops it.
                    _ => {}
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn assembled_link_streams_a_verified_range_over_tcp() {
    let (server_store, _sg) = temp_store();
    let data = test_data(600_000);
    let id = ObjId::of(&data);
    server_store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();

    let addr = spawn_sniffing_server(server_store).await;

    // Dial through the assembled helper: magic, Noise, mux, all in one call.
    let stream = TcpTransport.dial(&PeerAddr::Ip(addr)).await.unwrap();
    let l = link::dial(stream).await.unwrap();

    let (client_store, _cg) = temp_store();
    let cctx = ServeCtx {
        caps: caps::MESH,
        now: || 0,
        ..ServeCtx::new(client_store.clone(), Arc::new(FixtureProvider), CLIENT_KEY.into())
    };
    let id_srv = epix_edx::server::client_hello(&l.conn, &cctx, vec![], Some(l.handshake_hash))
        .await
        .unwrap();
    assert_eq!(
        id_srv.address,
        epix_crypt::privatekey_to_address(SERVER_KEY).unwrap(),
        "server identity is channel-bound to the link's Noise session"
    );

    client_store.ensure_sparse(id, Ns::Plain, data.len() as u64, 1).unwrap();
    let range = 300_000u64..350_000;
    let got = fetch::fetch_ranges(&l.conn, &client_store, id, data.len() as u64, &[range], 100, 2)
        .await
        .unwrap();
    assert!(got > 0, "the assembled link fetched and verified a mid-file range");
}

#[tokio::test]
async fn overlay_link_no_noise_streams_a_verified_range() {
    // Overlays (Tor/I2P/Reticulum) already encrypt, so EDX skips Noise: the
    // no-Noise link variant exchanges the magic and starts the mux, and a
    // verified range still transfers. (Here plain TCP stands in for the
    // already-encrypted overlay stream.)
    let (server_store, _sg) = temp_store();
    let data = test_data(500_000);
    let id = ObjId::of(&data);
    server_store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ctx = Arc::new(ServeCtx::new(server_store, Arc::new(FixtureProvider), SERVER_KEY.into()));
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else { break };
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let _ = sock.set_nodelay(true);
                let (kind, stream) = match link::read_sniff(Box::pin(sock)).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                if kind != Sniff::Edx {
                    return;
                }
                let Ok((conn, incoming)) = link::accept_overlay(stream).await else { return };
                // No handshake hash on overlay links.
                serve(conn, incoming, ctx, None).await;
            });
        }
    });

    let stream = TcpTransport.dial(&PeerAddr::Ip(addr)).await.unwrap();
    let (conn, _in) = link::dial_overlay(stream).await.unwrap();
    let (client_store, _cg) = temp_store();
    let cctx = ServeCtx {
        caps: caps::MESH,
        now: || 0,
        ..ServeCtx::new(client_store.clone(), Arc::new(FixtureProvider), CLIENT_KEY.into())
    };
    // No channel binding over an overlay: pass None.
    let id_srv = epix_edx::server::client_hello(&conn, &cctx, vec![], None).await.unwrap();
    assert_eq!(id_srv.address, epix_crypt::privatekey_to_address(SERVER_KEY).unwrap());

    client_store.ensure_sparse(id, Ns::Plain, data.len() as u64, 1).unwrap();
    let got = fetch::fetch_ranges(&conn, &client_store, id, data.len() as u64, &[100_000u64..160_000], 100, 2)
        .await
        .unwrap();
    assert!(got > 0, "the no-Noise overlay link fetched and verified a range");
}

#[tokio::test]
async fn sniff_routes_edx_and_preserves_a_legacy_first_byte() {
    // EDX magic sniffs as Edx.
    assert_eq!(epix_edx::frame::sniff(b'E'), Sniff::Edx);
    // A msgpack fixmap header sniffs as Legacy and is NOT consumed: the
    // rewound stream still yields it, so the legacy server sees a whole
    // message. This is what lets both protocols share one accept port.
    let (mut a, b) = tokio::io::duplex(64);
    tokio::spawn(async move {
        // A legacy peer's first message starts with a fixmap header (0x82)
        // followed by its body bytes.
        a.write_all(&[0x82, 0xAA, 0xBB, 0xCC]).await.unwrap();
    });
    let (kind, mut rewound) = link::read_sniff(Box::pin(b)).await.unwrap();
    assert_eq!(kind, Sniff::Legacy, "0x82 is a msgpack fixmap header");
    let mut seen = [0u8; 4];
    rewound.read_exact(&mut seen).await.unwrap();
    assert_eq!(seen, [0x82, 0xAA, 0xBB, 0xCC], "the routing byte is replayed, not swallowed");
}
