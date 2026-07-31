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

#[async_trait::async_trait]
impl SignedProvider for FixtureProvider {
    async fn get_signed(&self, xite: &str, inner_path: &str) -> Option<Vec<u8>> {
        self.signed.get(&(xite.into(), inner_path.into())).cloned()
    }
    async fn list_signed(&self, _xite: &str, _since: u64) -> Vec<(String, u64, u64)> {
        vec![("content.json".into(), 1_700_000_000, 42)]
    }
    async fn xite_summary(&self, _xite: &str) -> Option<(u64, u64, u64)> {
        Some((1, 1_700_000_000, 4096))
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
        caps: caps::MESH,
        now: || 0,
        ..ServeCtx::new(cstore, Arc::new(FixtureProvider { signed: Default::default() }), CLIENT_KEY.into())
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
async fn has_shards_returns_the_held_subset_as_a_packed_mask() {
    let net = sim::SimNet::new();
    let (server_store, _sg) = temp_store();

    // Hold 3 of 10 probed objects (indices 0, 4, 9), the rest absent. The
    // count is not a multiple of 8, so the top byte is partially used - the
    // packing edge worth pinning.
    let mut addrs = Vec::new();
    for i in 0..10u8 {
        let data = test_data(1000 + i as usize);
        let id = ObjId::of(&data);
        if i == 0 || i == 4 || i == 9 {
            server_store.insert_bytes(id, Ns::Shard, &data, 1).unwrap();
        }
        addrs.push(id);
    }
    // An addr the server has never seen: must read as not held.
    addrs.push(ObjId::of(b"never-seen"));

    let conn = connect(net.clone(), server_store, ip(5)).await;
    let held = fetch::fetch_has_shards(&conn, &addrs).await.unwrap();

    let expect: Vec<bool> =
        [true, false, false, false, true, false, false, false, false, true, false].to_vec();
    assert_eq!(held, expect, "mask reflects exactly the held subset");
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

/// Bring up a server on `addr` seeding `data`, return a handshaken conn.
async fn seed_and_connect(
    net: Arc<sim::SimNet>,
    addr: PeerAddr,
    class: sim::Class,
    data: &[u8],
) -> (Conn, ObjId) {
    net.set_class(addr.clone(), class);
    let (store, guard) = temp_store();
    let id = ObjId::of(data);
    store.insert_bytes(id, Ns::Plain, data, 1).unwrap();
    // Leak the guard so the store outlives this fn (test-lifetime).
    std::mem::forget(guard);
    let conn = connect(net, store, addr).await;
    (conn, id)
}

#[tokio::test(start_paused = true)]
async fn multi_peer_striping_and_tor_only_swarm() {
    use epix_edx::sched::{needed_groups, Deadline, PeerHandle, Swarm};
    let net = sim::SimNet::new();

    // Same 2 MB object seeded on three peers of different classes.
    let data = test_data(2_000_000);
    let (c1, id) = seed_and_connect(net.clone(), ip(11), sim::Class::Clearnet, &data).await;
    let (c2, _) = seed_and_connect(net.clone(), ip(12), sim::Class::I2p, &data).await;
    let (c3, _) = seed_and_connect(net.clone(), ip(13), sim::Class::Tor, &data).await;

    let bits = epix_blob::bitfield::GroupBits::complete(data.len() as u64);
    let peers = vec![
        PeerHandle { conn: c1, class: sim::Class::Clearnet, bits: bits.clone(), label: "clear".into() },
        PeerHandle { conn: c2, class: sim::Class::I2p, bits: bits.clone(), label: "i2p".into() },
        PeerHandle { conn: c3, class: sim::Class::Tor, bits: bits.clone(), label: "tor".into() },
    ];

    let (client_store, _g) = temp_store();
    let mut swarm = Swarm::new(client_store.clone(), id, data.len() as u64);
    client_store.ensure_sparse(id, Ns::Plain, data.len() as u64, 1).unwrap();
    let needed = needed_groups(&client_store, id, data.len() as u64).unwrap();
    let report = swarm.fetch(&needed, &peers, Deadline::background(), 2).await.unwrap();

    // The object completed and reads back correct.
    assert!(client_store.is_complete(id).unwrap(), "object completed");
    assert_eq!(client_store.read_bytes(id, 3).unwrap(), data);

    // Striping actually spread work across peers (not all from one).
    let peers_used = report.by_peer.len();
    assert!(peers_used >= 2, "work should stripe across peers, used {peers_used}: {:?}", report.by_peer);

    // The per-class EWMA was fed by the fetch: at least one class prior moved
    // off its static default (duplicate-on-timeout now uses measured RTT).
    let default = epix_edx::sched::ClassStats::default();
    let moved = [sim::Class::Clearnet, sim::Class::I2p, sim::Class::Tor]
        .iter()
        .any(|c| swarm.stats().rtt(*c) != default.rtt(*c));
    assert!(moved, "a class RTT prior should update after observing a real fetch");

    // A Tor-ONLY swarm still completes (no self-starvation when every
    // peer is slow — the whole reason for per-class scheduling).
    let (tc, _) = seed_and_connect(net.clone(), ip(14), sim::Class::Tor, &data).await;
    let tor_peers = vec![PeerHandle {
        conn: tc,
        class: sim::Class::Tor,
        bits: bits.clone(),
        label: "tor-only".into(),
    }];
    let (store2, _g2) = temp_store();
    let mut swarm2 = Swarm::new(store2.clone(), id, data.len() as u64);
    store2.ensure_sparse(id, Ns::Plain, data.len() as u64, 1).unwrap();
    let needed2 = needed_groups(&store2, id, data.len() as u64).unwrap();
    swarm2.fetch(&needed2, &tor_peers, Deadline::background(), 2).await.unwrap();
    assert!(store2.is_complete(id).unwrap(), "Tor-only swarm completes");
}

#[tokio::test]
async fn a_failing_peer_is_routed_around() {
    use epix_edx::conn::Conn;
    use epix_edx::sched::{needed_groups, Deadline, PeerHandle, Swarm};
    let net = sim::SimNet::new();
    let data = test_data(300_000);

    // A healthy seeded peer plus a dead peer (its far end dropped, so every
    // request errors). Both claim the whole object; the dead one is listed
    // first, so the scheduler tries it, and the failing-peer penalty routes
    // the retry to the healthy peer instead of retrying the dead one.
    let (good, id) = seed_and_connect(net.clone(), ip(20), sim::Class::Clearnet, &data).await;
    let dead = {
        let (a, b) = tokio::io::duplex(64);
        let (c, _in) = Conn::start(a, true);
        drop(b);
        c
    };
    let bits = epix_blob::bitfield::GroupBits::complete(data.len() as u64);
    let peers = vec![
        PeerHandle { conn: dead, class: sim::Class::Clearnet, bits: bits.clone(), label: "dead".into() },
        PeerHandle { conn: good, class: sim::Class::Clearnet, bits: bits.clone(), label: "good".into() },
    ];

    let (store, _g) = temp_store();
    let mut swarm = Swarm::new(store.clone(), id, data.len() as u64);
    store.ensure_sparse(id, Ns::Plain, data.len() as u64, 1).unwrap();
    let needed = needed_groups(&store, id, data.len() as u64).unwrap();
    let report = swarm.fetch(&needed, &peers, Deadline::background(), 2).await.unwrap();

    assert!(store.is_complete(id).unwrap(), "object completes despite a failing peer");
    assert_eq!(store.read_bytes(id, 3).unwrap(), data);
    assert!(report.by_peer.contains_key("good"), "the healthy peer served the object");
}

#[tokio::test]
async fn governed_server_chokes_bulk_but_serves_first_paint() {
    use epix_edx::choke::{Choker, Reach};
    use epix_edx::msg::{err, Req, Resp};
    use std::sync::Mutex;

    let net = sim::SimNet::new();
    let (server_store, _sg) = temp_store();

    // A first-paint-sized object (<= 1 MiB) and a bulk object (> 1 MiB).
    let small = test_data(500_000);
    let big = test_data(4_000_000);
    let small_id = ObjId::of(&small);
    let big_id = ObjId::of(&big);
    server_store.insert_bytes(small_id, Ns::Plain, &small, 1).unwrap();
    server_store.insert_bytes(big_id, Ns::Plain, &big, 1).unwrap();

    // Governed server: choker with slots filled by phantom high
    // contributors so our client (zero contribution) is choked for bulk.
    // The client reaches us over the sim link (no Noise) => Reach::Overlay,
    // so the phantom competitors are overlay too — otherwise the client
    // would grab the reserved overlay slot and never be choked.
    let choker = Arc::new(Mutex::new(Choker::new(1_000_000_000)));
    {
        let mut c = choker.lock().unwrap();
        for i in 20..26u8 {
            c.note_peer(&[i; 33], Reach::Overlay, 0);
            c.credit_peer(&[i; 33], 1_000_000, 0);
        }
    }
    let provider = Arc::new(FixtureProvider { signed: Default::default() });
    let ctx = Arc::new(
        ServeCtx { now: || 0, ..ServeCtx::new(server_store, provider, SERVER_KEY.into()) }
            .with_choker(choker),
    );

    let server_addr = ip(20);
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

    let t = sim::SimTransport { net, local: ip(202) };
    let stream = {
        use epix_transport::Transport;
        t.dial(&server_addr).await.unwrap()
    };
    let (conn, _in) = Conn::start(stream, true);
    let (cstore, _cg) = temp_store();
    let cctx = ServeCtx { now: || 0, ..ServeCtx::new(cstore, Arc::new(FixtureProvider { signed: Default::default() }), CLIENT_KEY.into()) };
    epix_edx::server::client_hello(&conn, &cctx, vec![], None).await.unwrap();

    // First-paint object: served (exempt).
    let mut rx = conn
        .request_stream(Req::GetRange { obj: small_id, size: small.len() as u64, ranges: vec![(0, 500_000)], deadline_ms: 250 })
        .await
        .unwrap();
    let first = rx.recv().await.unwrap();
    assert!(matches!(first, epix_edx::msg::FrameBody::Data { .. }), "first-paint served, got {first:?}");

    // Bulk object from the same choked freeloader: refused BUSY.
    let resp = conn
        .request(Req::GetRange { obj: big_id, size: big.len() as u64, ranges: vec![(0, 4_000_000)], deadline_ms: 0 })
        .await
        .unwrap();
    match resp {
        Resp::Err { code, .. } => assert_eq!(code, err::BUSY, "bulk from a freeloader is choked"),
        other => panic!("expected BUSY, got {other:?}"),
    }
}

#[tokio::test]
async fn cancel_stops_a_long_stream() {
    let net = sim::SimNet::new();
    let (server_store, _sg) = temp_store();
    // A big object so the stream spans many frames (more than the stream
    // channel can buffer), so a mid-stream cancel is observable.
    let data = test_data(12_000_000);
    let id = ObjId::of(&data);
    server_store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();

    let conn = connect(net.clone(), server_store, ip(4)).await;

    use epix_edx::msg::{FrameBody, Req};
    let mut rx = conn
        .request_stream(Req::GetRange {
            obj: id,
            size: data.len() as u64,
            ranges: vec![(0, 12_000_000)],
            deadline_ms: 0,
        })
        .await
        .unwrap();
    // Cancel the REAL stream this GetRange runs on (the handshake already
    // used stream 1, so this is stream 3, not 1).
    let stream_id = rx.id;

    // Read a couple frames, then cancel.
    let mut frames = 0usize;
    let mut saw_last = false;
    while let Some(body) = rx.recv().await {
        frames += 1;
        if let FrameBody::Data { last: true, .. } = body {
            saw_last = true;
            break;
        }
        if frames == 2 {
            conn.cancel(stream_id).await.unwrap();
            break;
        }
    }

    // Drain whatever was already buffered. A truly cancelled stream ends
    // WITHOUT a terminal (last:true) frame and delivers far fewer frames
    // than the full encode would.
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await {
            Ok(Some(FrameBody::Data { last: true, .. })) => {
                saw_last = true;
                frames += 1;
                break;
            }
            Ok(Some(_)) => frames += 1,
            Ok(None) => break, // stream closed by the cancel
            Err(_) => break,   // no further frames within the timeout
        }
    }

    assert!(!saw_last, "a cancelled stream must not deliver a terminal frame");
    let full_frames = data.len().div_ceil(64 * 1024);
    assert!(
        frames < full_frames / 2,
        "cancel should stop the stream early: got {frames} of ~{full_frames} frames"
    );

    // The connection is still usable afterward (cancel didn't kill it).
    let (_size, _bits) = fetch::fetch_bitfield(&conn, id).await.unwrap();
}

#[tokio::test]
async fn disjoint_holders_still_complete_the_object() {
    use epix_blob::bitfield::{group_count, GroupBits};
    use epix_edx::sched::{needed_groups, Deadline, PeerHandle, Swarm};
    let net = sim::SimNet::new();

    // Two peers that each hold only HALF the groups, interleaved at group
    // granularity (one even, one odd). No single peer holds a whole
    // rarest-first batch, so a holder-blind batcher strands the object
    // even though every group IS available from some peer.
    let data = test_data(300_000);
    let (c_even, id) = seed_and_connect(net.clone(), ip(31), sim::Class::Clearnet, &data).await;
    let (c_odd, _) = seed_and_connect(net.clone(), ip(32), sim::Class::Clearnet, &data).await;

    let size = data.len() as u64;
    let n = group_count(size);
    let mut even = GroupBits::new();
    let mut odd = GroupBits::new();
    for g in 0..n {
        if g % 2 == 0 {
            even.add(g..g + 1);
        } else {
            odd.add(g..g + 1);
        }
    }
    let peers = vec![
        PeerHandle { conn: c_even, class: sim::Class::Clearnet, bits: even, label: "even".into() },
        PeerHandle { conn: c_odd, class: sim::Class::Clearnet, bits: odd, label: "odd".into() },
    ];

    let (client_store, _g) = temp_store();
    let mut swarm = Swarm::new(client_store.clone(), id, size);
    client_store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
    let needed = needed_groups(&client_store, id, size).unwrap();
    swarm.fetch(&needed, &peers, Deadline::background(), 2).await.unwrap();

    assert!(client_store.is_complete(id).unwrap(), "object completes despite disjoint holders");
    assert_eq!(client_store.read_bytes(id, 3).unwrap(), data);
}

/// What a peer's `apply_update` received, captured for assertions.
#[derive(Default, Clone)]
struct Captured {
    xite: String,
    inner_path: String,
    signed: Vec<u8>,
    inline: Vec<(ObjId, Vec<u8>)>,
    modified: f64,
    diffs: Vec<(String, Vec<u8>)>,
    sender_peers: Vec<String>,
}

/// A provider that records the exact `apply_update` arguments so a test can
/// assert the whole `Req::Update` (diffs + version + dial-back peers +
/// inline) survives the wire and the server's destructure.
struct CapturingProvider {
    seen: std::sync::Arc<std::sync::Mutex<Option<Captured>>>,
}

#[async_trait::async_trait]
impl SignedProvider for CapturingProvider {
    async fn get_signed(&self, _: &str, _: &str) -> Option<Vec<u8>> {
        None
    }
    async fn list_signed(&self, _: &str, _: u64) -> Vec<(String, u64, u64)> {
        Vec::new()
    }
    async fn xite_summary(&self, _: &str) -> Option<(u64, u64, u64)> {
        None
    }
    async fn apply_update(
        &self,
        xite: &str,
        inner_path: &str,
        signed: &[u8],
        inline: &[(ObjId, Vec<u8>)],
        modified: f64,
        diffs: &[(String, Vec<u8>)],
        sender_peers: &[String],
    ) -> Result<bool, String> {
        *self.seen.lock().unwrap() = Some(Captured {
            xite: xite.into(),
            inner_path: inner_path.into(),
            signed: signed.to_vec(),
            inline: inline.to_vec(),
            modified,
            diffs: diffs.to_vec(),
            sender_peers: sender_peers.to_vec(),
        });
        Ok(true)
    }
}

#[tokio::test]
async fn push_update_delivers_every_field_to_the_provider() {
    let net = sim::SimNet::new();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
    let provider = Arc::new(CapturingProvider { seen: seen.clone() });
    let ctx = Arc::new(ServeCtx::new(temp_store().0, provider, SERVER_KEY.into()));

    let server_addr = ip(40);
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

    let t = sim::SimTransport { net, local: ip(203) };
    let stream = {
        use epix_transport::Transport;
        t.dial(&server_addr).await.unwrap()
    };
    let (conn, _in) = Conn::start(stream, true);
    let (cstore, _cg) = temp_store();
    let cctx = ServeCtx {
        now: || 0,
        ..ServeCtx::new(cstore, Arc::new(FixtureProvider { signed: Default::default() }), CLIENT_KEY.into())
    };
    epix_edx::server::client_hello(&conn, &cctx, vec![], None).await.unwrap();

    // Push a fully-populated update (a forum post with a data.json diff).
    let signed = br#"{"address":"1Forum","modified":2000}"#.to_vec();
    let inline = vec![(ObjId([3; 32]), vec![10, 20, 30])];
    let diffs = vec![("data.json".to_string(), br#"[["=",42],["+",["new"]]]"#.to_vec())];
    let sender_peers = vec!["abc.onion:15441".to_string(), "1.2.3.4:15441".to_string()];
    epix_edx::fetch::push_update(
        &conn,
        "1Forum",
        "data/users/alice/content.json",
        &signed,
        2000.5,
        diffs.clone(),
        sender_peers.clone(),
        inline.clone(),
    )
    .await
    .expect("peer accepts the push");

    let got = seen.lock().unwrap().clone().expect("provider saw the update");
    assert_eq!(got.xite, "1Forum");
    assert_eq!(got.inner_path, "data/users/alice/content.json");
    assert_eq!(got.signed, signed);
    assert_eq!(got.inline, inline);
    assert_eq!(got.modified, 2000.5);
    assert_eq!(got.diffs, diffs, "per-file diffs survive the wire");
    assert_eq!(got.sender_peers, sender_peers, "dial-back peers survive the wire");
}

#[tokio::test]
async fn oversized_multirange_request_is_rejected() {
    use epix_edx::msg::{err, Req, Resp};
    let net = sim::SimNet::new();
    let (server_store, _sg) = temp_store();
    // No object needed: the byte cap is checked before any store lookup.
    let conn = connect(net.clone(), server_store, ip(33)).await;

    // Two ranges of exactly 2^63 bytes each: a naive u64 .sum() wraps to 0
    // and slips past MAX_BYTES_PER_REQ. Saturating accumulation trips
    // LIMIT instead.
    let big = 1u64 << 63;
    let resp = conn
        .request(Req::GetRange {
            obj: ObjId([0; 32]),
            size: u64::MAX,
            ranges: vec![(0, big), (0, big)],
            deadline_ms: 0,
        })
        .await
        .unwrap();
    match resp {
        Resp::Err { code, .. } => {
            assert_eq!(code, err::LIMIT, "an overflowing byte total must trip LIMIT")
        }
        other => panic!("expected LIMIT Err, got {other:?}"),
    }
}

/// A signed list far larger than one frame must arrive complete.
///
/// Regression: `SignedList` was packed into a single frame. Past the
/// 64 KiB cap the encode failed inside the writer task, which tore down
/// the WHOLE multiplexed connection, not just that stream - so a forum
/// with a few thousand per-user content.json files became unsyncable
/// from every peer at once. The reply is chunked now.
#[tokio::test]
async fn a_signed_list_larger_than_one_frame_survives() {
    /// Enough entries to blow well past MAX_FRAME_LEN (~1071 was the
    /// measured break point for this path length).
    const N: usize = 5_000;

    struct BigList;
    #[async_trait::async_trait]
    impl SignedProvider for BigList {
        async fn get_signed(&self, _x: &str, _p: &str) -> Option<Vec<u8>> {
            None
        }
        async fn list_signed(&self, _x: &str, _s: u64) -> Vec<(String, u64, u64)> {
            (0..N)
                .map(|i| (format!("data/users/user{i:06}/content.json"), 1_700_000_000 + i as u64, 4096))
                .collect()
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

    let net = sim::SimNet::new();
    let (store, _g) = temp_store();
    let server_addr = ip(21);
    let ctx = Arc::new(ServeCtx::new(store, Arc::new(BigList), SERVER_KEY.into()));
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
    let (cstore, _cg) = temp_store();
    let cctx = ServeCtx {
        caps: caps::MESH,
        now: || 0,
        ..ServeCtx::new(cstore, Arc::new(BigList), CLIENT_KEY.into())
    };
    epix_edx::server::client_hello(&conn, &cctx, vec![], None).await.unwrap();

    let entries = fetch::list_signed(&conn, "1Abc", 0).await.expect("oversize list must arrive");
    assert_eq!(entries.len(), N, "every entry must survive chunking");
    assert_eq!(entries[0].0, "data/users/user000000/content.json");
    assert_eq!(entries[N - 1].0, format!("data/users/user{:06}/content.json", N - 1));

    // The connection must still be usable: the whole point of the bug was
    // that an oversize reply killed the link for every other stream.
    let summary = fetch::fetch_signed(&conn, "1Abc", "content.json").await;
    assert!(summary.is_err(), "provider has no signed content, but the link answered");
}
