//! End-to-end piecewise big-file download: a peer serves `getFile` (ranged),
//! and a client pulls **only** the pieces a byte range needs, verifying each
//! against the piecemap before writing it into a sparse file.

use std::sync::Arc;

use async_trait::async_trait;
use epix_core::PeerAddr;
use epix_protocol::{vget, vmap, Connection, PeerServer, RequestHandler};
use epix_transport::TcpTransport;
use epix_ui::fileserve::FileService;
use epix_ui::{AppState, XiteEntry};
use epix_xite::{Piecefield, XiteStorage};
use rmpv::Value as Rmp;
use serde_json::json;
use tokio::net::TcpListener;

/// A peer that answers `getFile` from a storage, honoring `location`/`read_bytes`.
struct FileServe {
    storage: XiteStorage,
}

#[async_trait]
impl RequestHandler for FileServe {
    async fn handle(&self, _peer: &PeerAddr, cmd: &str, params: &Rmp) -> Rmp {
        if cmd != "getFile" {
            return vmap(vec![("error", Rmp::from("unknown command"))]);
        }
        let inner = vget(params, "inner_path").and_then(|v| v.as_str()).unwrap_or("");
        let location = vget(params, "location").and_then(|v| v.as_u64()).unwrap_or(0);
        let read_bytes = vget(params, "read_bytes").and_then(|v| v.as_u64()).unwrap_or(512 * 1024);
        let bytes = self.storage.read(inner).unwrap_or_default();
        let start = (location as usize).min(bytes.len());
        let end = (start + read_bytes as usize).min(bytes.len());
        let chunk = bytes[start..end].to_vec();
        vmap(vec![
            ("body", Rmp::Binary(chunk)),
            ("size", Rmp::from(bytes.len() as i64)),
            ("location", Rmp::from(end as i64)),
        ])
    }
}

/// Raw (binary) SHA-512/256 of `data` - the piecemap's per-piece hash format.
fn raw_hash(data: &[u8]) -> Vec<u8> {
    hex::decode(XiteStorage::hash_bytes(data)).unwrap()
}

#[tokio::test]
async fn piecewise_download_pulls_only_needed_pieces() {
    let piece_size = 1024 * 1024u64;
    // A ~2.5-piece file with varied bytes so pieces differ.
    let big: Vec<u8> = (0..(2 * piece_size + 500)).map(|i| (i % 251) as u8).collect();
    let piece_len = |off: u64| piece_size.min(big.len() as u64 - off);

    // --- Source peer: the file + its piecemap.
    let src_dir = tempfile::tempdir().unwrap();
    let src = XiteStorage::new(src_dir.path());
    src.write("movie.mp4", &big).unwrap();
    let mut piece_hashes = Vec::new();
    let mut off = 0;
    while off < big.len() as u64 {
        let len = piece_len(off);
        piece_hashes.push(Rmp::Binary(raw_hash(&big[off as usize..(off + len) as usize])));
        off += len;
    }
    let piecemap = Rmp::Map(vec![(
        Rmp::from("movie.mp4"),
        Rmp::Map(vec![
            (Rmp::from("sha512_pieces"), Rmp::Array(piece_hashes)),
            (Rmp::from("piece_size"), Rmp::from(piece_size as i64)),
        ]),
    )]);
    let mut pm_bytes = Vec::new();
    rmpv::encode::write_value(&mut pm_bytes, &piecemap).unwrap();
    src.write("movie.mp4.piecemap.msgpack", &pm_bytes).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    tokio::spawn(PeerServer::new(Arc::new(FileServe { storage: src.clone() })).serve(listener));

    // --- Client: declares the big file + piecemap, has neither on disk.
    let cli_dir = tempfile::tempdir().unwrap();
    let content = json!({
        "files": { "movie.mp4.piecemap.msgpack": { "size": pm_bytes.len(), "sha512": XiteStorage::hash_bytes(&pm_bytes) } },
        "files_optional": { "movie.mp4": {
            "size": big.len(), "sha512": XiteStorage::hash_bytes(&big),
            "piecemap": "movie.mp4.piecemap.msgpack", "piece_size": piece_size,
        } },
    });
    let xite = epix_crypt::privatekey_to_address("11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7").unwrap();
    let state = AppState::new("test");
    state.add_xite(&xite, XiteEntry { storage: XiteStorage::new(cli_dir.path()), content: Some(content) }).await;
    state.set_transport(Arc::new(TcpTransport)).await;
    state.add_peers(&xite, [PeerAddr::Ip(peer_addr)]).await;

    // Fetch just the second piece's window - only piece 1 should download.
    state.bigfile_fetch_range(&xite, "movie.mp4", piece_size, 100).await.unwrap();
    let chunk = state.read_file_range(&xite, "movie.mp4", piece_size, 100).await.unwrap();
    assert_eq!(chunk, &big[piece_size as usize..piece_size as usize + 100]);
    // The first piece was NOT fetched (still a hole of zeros).
    let piece0 = state.read_file_range(&xite, "movie.mp4", 0, piece_size as usize).await.unwrap();
    assert!(piece0.iter().all(|&b| b == 0), "unrequested piece stays a hole");

    // Now fetch the whole range - every piece present, file matches the source.
    state.bigfile_fetch_range(&xite, "movie.mp4", 0, big.len() as u64).await.unwrap();
    let whole = std::fs::read(cli_dir.path().join("movie.mp4")).unwrap();
    assert_eq!(whole, big, "reassembled big file matches the source byte-for-byte");
}

#[tokio::test]
async fn get_piecefields_reports_which_pieces_a_peer_holds() {
    let piece_size = 1024 * 1024u64;
    let big: Vec<u8> = (0..(2 * piece_size + 500)).map(|i| (i % 251) as u8).collect();
    let ps = piece_size as usize;

    // Piece hashes over the *full* file (what the piecemap declares).
    let piece_len = |off: u64| piece_size.min(big.len() as u64 - off);
    let mut piece_hashes = Vec::new();
    let mut off = 0;
    while off < big.len() as u64 {
        let len = piece_len(off);
        piece_hashes.push(Rmp::Binary(raw_hash(&big[off as usize..(off + len) as usize])));
        off += len;
    }
    let piecemap = Rmp::Map(vec![(
        Rmp::from("movie.mp4"),
        Rmp::Map(vec![
            (Rmp::from("sha512_pieces"), Rmp::Array(piece_hashes)),
            (Rmp::from("piece_size"), Rmp::from(piece_size as i64)),
        ]),
    )]);
    let mut pm_bytes = Vec::new();
    rmpv::encode::write_value(&mut pm_bytes, &piecemap).unwrap();

    // Server holds pieces 0 and 2 but NOT piece 1 (that piece is a zero hole).
    let mut on_disk = vec![0u8; big.len()];
    on_disk[0..ps].copy_from_slice(&big[0..ps]);
    on_disk[2 * ps..].copy_from_slice(&big[2 * ps..]);
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("movie.mp4", &on_disk).unwrap();
    storage.write("movie.mp4.piecemap.msgpack", &pm_bytes).unwrap();

    let sha512 = XiteStorage::hash_bytes(&big);
    let content = json!({
        "files_optional": { "movie.mp4": {
            "size": big.len(), "sha512": sha512,
            "piecemap": "movie.mp4.piecemap.msgpack", "piece_size": piece_size,
        } },
    });
    let state = AppState::new("seed");
    state.add_xite("1BigSeed", XiteEntry { storage, content: Some(content) }).await;

    // Serve via the real FileService and query piecefields from a client.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(PeerServer::new(Arc::new(FileService::new(state))).serve(listener));

    let mut conn = Connection::connect(&TcpTransport, &PeerAddr::Ip(addr)).await.unwrap();
    conn.handshake().await.unwrap();
    let fields = conn.get_piecefields("1BigSeed").await.unwrap();
    let packed = fields.get(&sha512).expect("piecefield for the big file");
    let pf = Piecefield::unpack(packed);
    assert!(pf.get(0), "piece 0 is held");
    assert!(!pf.get(1), "piece 1 is a hole");
    assert!(pf.get(2), "piece 2 is held");
    assert_eq!(pf.count_present(), 2);
}
