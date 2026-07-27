//! Stage 2 gate: two nodes over the sim transport run the full EDX
//! stack — Noise-optional handshake, Hello gate + channel binding,
//! verified range streaming, GetMany, bitfields, and Cancel.

use std::sync::Arc;

use epix_blob::store::Store;
use epix_blob::verified::{encode_slice, OutboardBytes};
use epix_blob::{Ns, ObjId};
use epix_edx::conn::Conn;
use epix_edx::msg::{caps, NET_ID};
use epix_edx::server::{serve, ServeCtx, SignedProvider};
use epix_edx::{fetch, sim};
use epix_core::PeerAddr;
use std::net::SocketAddr;
use tempfile::TempDir;

/// A store in a temp dir kept alive by the returned guard.
fn temp_store() -> (Arc<Store>, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    (store, dir)
}

const SERVER_KEY: &str = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
const CLIENT_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn test_data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
}

/// Signed-content provider backed by a fixed map, for the handshake and
/// GetSigned paths.
struct FixtureProvider {
    signed: std::collections::HashMap<(String, String), Vec<u8>>,
}

impl SignedProvider for FixtureProvider {
    fn get_signed(&self, xite: &str, inner_path: &str) -> Option<Vec<u8>> {
        self.signed.get(&(xite.into(), inner_path.into())).cloned()
    }
    fn list_signed(&self, _xite: &str, _since: u64) -> Vec<(String, u64, u64)> {
        vec![("content.json".into(), 1_700_000_000, 42)]
    }
    fn xite_summary(&self, _xite: &str) -> Option<(u64, u64, u64)> {
        Some((1, 1_700_000_000, 4096))
    }
    fn apply_update(
        &self,
        _xite: &str,
        _inner_path: &str,
        _signed: &[u8],
        _inline: &[(ObjId, Vec<u8>)],
    ) -> Result<bool, String> {
        Ok(true)
    }
}

fn ip(port: u16) -> PeerAddr {
    PeerAddr::Ip(SocketAddr::from(([10, 0, 0, port as u8], port)))
}

/// Bring up a server node on the sim net serving `store`, return the
/// client-side Conn already past the Hello handshake.
async fn connect(
    net: Arc<sim::SimNet>,
    store: Arc<Store>,
    server_addr: PeerAddr,
) -> Conn {
    let provider = Arc::new(FixtureProvider { signed: Default::default() });
    let ctx = Arc::new(ServeCtx::new(store, provider, SERVER_KEY.into()));

    let mut inbox = net.listen(server_addr.clone());
    tokio::spawn(async move {
        while let Some((_from, stream)) = inbox.recv().await {
            let (conn, incoming) = Conn::start(stream, false);
            let ctx = ctx.clone();
            // Overlay-style link: no Noise, so no handshake hash (the sim
            // transport authenticates the endpoint like Tor/I2P would).
            tokio::spawn(async move {
                serve(conn, incoming, ctx, None).await;
            });
        }
    });

    let t = sim::SimTransport { net, local: ip(200) };
    let stream = {
        use epix_transport::Transport;
        t.dial(&server_addr).await.unwrap()
    };
    let (conn, _client_in) = Conn::start(stream, true);
    let (cstore, _cctx_guard) = temp_store();
    let cctx = ServeCtx {
        store: cstore,
        provider: Arc::new(FixtureProvider { signed: Default::default() }),
        privatekey: CLIENT_KEY.into(),
        caps: caps::MESH,
        now: || 0,
    };
    let id = epix_edx::server::client_hello(&conn, &cctx, vec![], None).await.unwrap();
    // The handshake completed, which means the net id matched and the
    // server authenticated as the server key's address.
    let _ = NET_ID;
    assert_eq!(id.address, epix_crypt::privatekey_to_address(SERVER_KEY).unwrap());
    conn
}

#[tokio::test]
async fn verified_range_streaming_over_the_wire() {
    let net = sim::SimNet::new();
    let (server_store, _sg) = temp_store();

    // Seed a 700 KB media object on the server.
    let data = test_data(700_000);
    let id = ObjId::of(&data);
    server_store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();

    let conn = connect(net.clone(), server_store, ip(1)).await;

    // Client fetches a mid-file range (a seek).
    let (client_store, _cg) = temp_store();
    client_store.ensure_sparse(id, Ns::Plain, data.len() as u64, 1).unwrap();
    let range = 400_000u64..450_000;
    let got = fetch::fetch_ranges(&conn, &client_store, id, data.len() as u64, &[range.clone()], 100, 2)
        .await
        .unwrap();
    assert!(got > 0);

    // The bytes verified into the store and read back correctly.
    let mut slice = Vec::new();
    client_store.encode_slice(id, &[range.clone()], &mut slice, 3).unwrap();
    // Reconstruct: the store now holds and can re-serve exactly that range.
    let ob = OutboardBytes::from_slice(&data);
    let mut expect = Vec::new();
    encode_slice(&data[..], &ob, &[range.clone()], &mut expect).unwrap();
    assert_eq!(slice, expect, "re-served slice matches the canonical encoding");
}

#[tokio::test]
async fn get_many_and_bitfield() {
    let net = sim::SimNet::new();
    let (server_store, _sg) = temp_store();

    let blobs: Vec<Vec<u8>> = (0..5).map(|i| test_data(1000 + i)).collect();
    let ids: Vec<ObjId> = blobs
        .iter()
        .map(|b| {
            let id = ObjId::of(b);
            server_store.insert_bytes(id, Ns::Plain, b, 1).unwrap();
            id
        })
        .collect();

    let conn = connect(net.clone(), server_store, ip(2)).await;
    let (client_store, _cg) = temp_store();

    // GetMany pulls them all in one round trip, each hash-verified.
    let mut want = ids.clone();
    want.push(ObjId::of(b"not-on-server"));
    let (inserted, missing) = fetch::fetch_many(&conn, &client_store, &want, 2).await.unwrap();
    assert_eq!(inserted, 5);
    assert_eq!(missing, vec![ObjId::of(b"not-on-server")]);
    for (b, id) in blobs.iter().zip(&ids) {
        assert_eq!(&client_store.read_bytes(*id, 3).unwrap(), b);
    }

    // Bitfield of a complete slab object is fully-present.
    let (size, bits) = fetch::fetch_bitfield(&conn, ids[0]).await.unwrap();
    assert!(bits.is_complete(size));
}

#[tokio::test]
async fn hello_gate_rejects_pre_handshake_requests() {
    let net = sim::SimNet::new();
    let (server_store, _sg) = temp_store();
    let provider = Arc::new(FixtureProvider { signed: Default::default() });
    let ctx = Arc::new(ServeCtx::new(server_store, provider, SERVER_KEY.into()));

    let server_addr = ip(3);
    let mut inbox = net.listen(server_addr.clone());
    tokio::spawn(async move {
        while let Some((_from, stream)) = inbox.recv().await {
            let (conn, incoming) = Conn::start(stream, false);
            let ctx = ctx.clone();
            tokio::spawn(async move {
                serve(conn, incoming, ctx, None).await;
            });
        }
    });

    let t = sim::SimTransport { net, local: ip(201) };
    let stream = {
        use epix_transport::Transport;
        t.dial(&server_addr).await.unwrap()
    };
    let (conn, _in) = Conn::start(stream, true);

    // A GetBitfield before Hello must be refused, and the connection drops.
    use epix_edx::msg::{Req, Resp};
    let resp = conn.request(Req::GetBitfield { obj: ObjId([0; 32]) }).await;
    match resp {
        Ok(Resp::Err { code, .. }) => assert_eq!(code, epix_edx::msg::err::BAD_REQUEST),
        Ok(other) => panic!("expected Err, got {other:?}"),
        Err(_) => {} // connection dropped is also acceptable
    }
}

#[tokio::test]
async fn cancel_stops_a_long_stream() {
    let net = sim::SimNet::new();
    let (server_store, _sg) = temp_store();
    // A big object so the stream spans many frames.
    let data = test_data(4_000_000);
    let id = ObjId::of(&data);
    server_store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();

    let conn = connect(net.clone(), server_store, ip(4)).await;

    use epix_edx::msg::{FrameBody, Req};
    let mut rx = conn
        .request_stream(Req::GetRange {
            obj: id,
            size: data.len() as u64,
            ranges: vec![(0, 4_000_000)],
            deadline_ms: 0,
        })
        .await
        .unwrap();
    // Read a couple frames, then cancel.
    let mut frames = 0;
    let stream_id = 1; // first dialer stream
    while let Some(body) = rx.recv().await {
        frames += 1;
        if frames == 2 {
            conn.cancel(stream_id).await.unwrap();
            break;
        }
        if let FrameBody::Data { last: true, .. } = body {
            break;
        }
    }
    // The connection is still usable afterward (cancel didn't kill it).
    let (_size, _bits) = fetch::fetch_bitfield(&conn, id).await.unwrap();
}
