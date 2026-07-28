//! Big-file piecefields: which pieces of a piecemap'd file a node holds are
//! reported over `getPiecefields` so peers can find seeders of individual
//! pieces.

use std::sync::Arc;

use epix_core::PeerAddr;
use epix_protocol::{Connection, PeerServer};
use epix_transport::TcpTransport;
use epix_ui::fileserve::FileService;
use epix_ui::{AppState, XiteEntry};
use epix_xite::{Piecefield, XiteStorage};
use rmpv::Value as Rmp;
use serde_json::json;
use tokio::net::TcpListener;

/// Raw (binary) SHA-512/256 of `data` - the piecemap's per-piece hash format.
fn raw_hash(data: &[u8]) -> Vec<u8> {
    hex::decode(XiteStorage::hash_bytes(data)).unwrap()
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
