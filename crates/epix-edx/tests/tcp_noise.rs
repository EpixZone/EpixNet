//! Real-network gate: the full EDX stack over an actual 127.0.0.1 TCP
//! socket — TcpTransport dial, Noise-XX with channel binding on both
//! sides, Hello gate, verified range streaming, GetMany, and spoofed
//! identity rejection. The sim-transport gate (tests/wire.rs) proves the
//! protocol; this proves the composition over a real socket.

use std::sync::Arc;

use epix_blob::store::Store;
use epix_blob::verified::{encode_slice, OutboardBytes};
use epix_blob::{Ns, ObjId};
use epix_core::PeerAddr;
use epix_edx::conn::Conn;
use epix_edx::msg::{caps, Hello, Req, Resp};
use epix_edx::server::{serve, ServeCtx, SignedProvider};
use epix_edx::{fetch, noise};
use epix_transport::{TcpTransport, Transport};
use tempfile::TempDir;
use tokio::net::TcpListener;

const SERVER_KEY: &str = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
const CLIENT_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const VICTIM_KEY: &str = "3333333333333333333333333333333333333333333333333333333333333333";

fn temp_store() -> (Arc<Store>, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    (store, dir)
}

fn test_data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
}

struct FixtureProvider;

#[async_trait::async_trait]
impl SignedProvider for FixtureProvider {
    async fn get_signed(&self, _xite: &str, _inner_path: &str) -> Option<Vec<u8>> {
        None
    }
    async fn list_signed(&self, _xite: &str, _since: u64) -> Vec<(String, u64, u64)> {
        Vec::new()
    }
    async fn xite_summary(&self, _xite: &str) -> Option<(u64, u64, u64)> {
        None
    }
    async fn apply_update(
        &self,
        _xite: &str,
        _inner_path: &str,
        _signed: &[u8],
        _inline: &[(ObjId, Vec<u8>)],
        _modified: f64,
        _diffs: &[(String, Vec<u8>)],
        _sender_peers: &[String],
    ) -> Result<bool, String> {
        Ok(true)
    }
}

/// Bind a real TCP listener serving `store` behind Noise, return its addr.
async fn spawn_tcp_server(store: Arc<Store>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ctx = Arc::new(ServeCtx::new(store, Arc::new(FixtureProvider), SERVER_KEY.into()));
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else { break };
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let _ = sock.set_nodelay(true);
                // Clearnet link: mandatory Noise, then the handshake hash
                // binds the Hello identity to this session.
                let Ok(sec) = noise::secure_responder(Box::pin(sock)).await else { return };
                let (conn, incoming) = Conn::start(sec.stream, false);
                serve(conn, incoming, ctx, Some(sec.handshake_hash)).await;
            });
        }
    });
    addr
}

/// Dial through TcpTransport + Noise, return the conn and session hash.
async fn dial_noise(addr: std::net::SocketAddr) -> (Conn, [u8; 32]) {
    let stream = TcpTransport.dial(&PeerAddr::Ip(addr)).await.unwrap();
    let sec = noise::secure_initiator(stream).await.unwrap();
    let conn_pair = Conn::start(sec.stream, true);
    (conn_pair.0, sec.handshake_hash)
}

#[tokio::test]
async fn verified_streaming_over_real_tcp_with_noise() {
    let (server_store, _sg) = temp_store();

    // Seed a 2 MB object: large enough to cross many Noise records and
    // continuation frames on a real socket.
    let data = test_data(2_000_000);
    let id = ObjId::of(&data);
    server_store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();

    let addr = spawn_tcp_server(server_store.clone()).await;
    let (conn, hh) = dial_noise(addr).await;

    let (client_store, _cg) = temp_store();
    let cctx = ServeCtx {
        caps: caps::MESH,
        now: || 0,
        ..ServeCtx::new(client_store.clone(), Arc::new(FixtureProvider), CLIENT_KEY.into())
    };
    let identity = epix_edx::server::client_hello(&conn, &cctx, vec![], Some(hh)).await.unwrap();
    assert_eq!(
        identity.address,
        epix_crypt::privatekey_to_address(SERVER_KEY).unwrap(),
        "server identity is channel-bound to the Noise session"
    );

    // A mid-file seek: fetch a verified range, then prove the store can
    // re-serve exactly the canonical encoding of that range.
    client_store.ensure_sparse(id, Ns::Plain, data.len() as u64, 1).unwrap();
    let range = 1_200_000u64..1_300_000;
    let got = fetch::fetch_ranges(&conn, &client_store, id, data.len() as u64, &[range.clone()], 100, 2)
        .await
        .unwrap();
    assert!(got > 0);

    let mut slice = Vec::new();
    client_store.encode_slice(id, &[range.clone()], &mut slice, 3).unwrap();
    let ob = OutboardBytes::from_slice(&data);
    let mut expect = Vec::new();
    encode_slice(&data[..], &ob, &[range.clone()], &mut expect).unwrap();
    assert_eq!(slice, expect, "re-served slice matches the canonical encoding");

    // GetMany over the same encrypted connection, including one miss
    // (seeded after connect: the server store is shared behind the Arc).
    let blobs: Vec<Vec<u8>> = (0..3).map(|i| test_data(2000 + i)).collect();
    let ids: Vec<ObjId> = blobs
        .iter()
        .map(|b| {
            let id = ObjId::of(b);
            server_store.insert_bytes(id, Ns::Plain, b, 1).unwrap();
            id
        })
        .collect();

    let mut want = ids.clone();
    want.push(ObjId::of(b"not-on-server"));
    let (inserted, missing) = fetch::fetch_many(&conn, &client_store, &want, 2).await.unwrap();
    assert_eq!(inserted, 3);
    assert_eq!(missing, vec![ObjId::of(b"not-on-server")]);
    for (b, id) in blobs.iter().zip(&ids) {
        assert_eq!(&client_store.read_bytes(*id, 3).unwrap(), b);
    }
}

#[tokio::test]
async fn spoofed_hello_is_rejected_over_real_tcp() {
    let (server_store, _sg) = temp_store();
    let addr = spawn_tcp_server(server_store).await;
    let (conn, hh) = dial_noise(addr).await;

    // The attacker claims the victim's node_pk but can only sign the
    // channel binding with its own key. The Hello gate must refuse it.
    let victim_pk = epix_crypt::private_to_compressed_pubkey(VICTIM_KEY).unwrap();
    let spoofed = Hello {
        net: epix_edx::msg::NET_ID.into(),
        node_pk: victim_pk,
        binding_sig: noise::sign_binding(&hh, CLIENT_KEY).unwrap(),
        caps: caps::MESH,
        listen: vec![],
    };
    match conn.request(Req::Hello(spoofed)).await {
        Ok(Resp::Err { .. }) => {}
        Ok(other) => panic!("spoofed Hello must be refused, got {other:?}"),
        Err(_) => {} // connection torn down is also a refusal
    }

    // And an honest Hello on a fresh connection still succeeds.
    let (conn2, hh2) = dial_noise(addr).await;
    let (client_store, _cg) = temp_store();
    let cctx = ServeCtx {
        caps: caps::MESH,
        now: || 0,
        ..ServeCtx::new(client_store, Arc::new(FixtureProvider), CLIENT_KEY.into())
    };
    let identity = epix_edx::server::client_hello(&conn2, &cctx, vec![], Some(hh2)).await.unwrap();
    assert_eq!(identity.address, epix_crypt::privatekey_to_address(SERVER_KEY).unwrap());
}

#[tokio::test]
async fn replayed_binding_from_another_session_is_rejected() {
    let (server_store, _sg) = temp_store();
    let addr = spawn_tcp_server(server_store).await;

    // Capture a valid binding signature from session 1...
    let (_conn1, hh1) = dial_noise(addr).await;
    let old_sig = noise::sign_binding(&hh1, CLIENT_KEY).unwrap();

    // ...and replay it on session 2: the handshake hash differs, so the
    // signature no longer covers this session and must be refused.
    let (conn2, hh2) = dial_noise(addr).await;
    assert_ne!(hh1, hh2, "each Noise session has a fresh handshake hash");
    let replayed = Hello {
        net: epix_edx::msg::NET_ID.into(),
        node_pk: epix_crypt::private_to_compressed_pubkey(CLIENT_KEY).unwrap(),
        binding_sig: old_sig,
        caps: caps::MESH,
        listen: vec![],
    };
    match conn2.request(Req::Hello(replayed)).await {
        Ok(Resp::Err { .. }) => {}
        Ok(other) => panic!("replayed binding must be refused, got {other:?}"),
        Err(_) => {}
    }
}
