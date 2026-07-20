//! End-to-end peer-wire test against an in-process fake seed over loopback TCP.
//!
//! The swarm's peer protocol (BEP3 handshake, BEP10 extension, BEP9 metadata,
//! BEP3 piece download) is the part that can't be covered by pure unit tests, so
//! this stands up a minimal seed that speaks just enough of the wire to answer a
//! metadata request and a piece request, and drives a real [`epix_bt::peer::Peer`]
//! against it: fetch the info dict, then fetch and check a piece.

use std::collections::BTreeMap;

use epix_bt::bencode::{encode, Value};
use epix_bt::peer::Peer;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The fake peer's own `ut_metadata` id (what the client addresses requests to).
const SEED_UT_METADATA: u8 = 2;

/// A synthetic single-file torrent: raw file bytes, the info-dict bytes, and its
/// info-hash. `piece_len` is tiny so the test exercises multiple pieces.
struct Torrent {
    data: Vec<u8>,
    info: Vec<u8>,
    info_hash: [u8; 20],
    piece_len: usize,
}

fn build_torrent() -> Torrent {
    let piece_len = 16usize;
    let data: Vec<u8> = (0..40u8).collect(); // 40 bytes => pieces of 16,16,8
    let mut pieces = Vec::new();
    for chunk in data.chunks(piece_len) {
        pieces.extend_from_slice(&Sha1::digest(chunk));
    }
    let info = Value::Dict(BTreeMap::from([
        (b"length".to_vec(), Value::Int(data.len() as i64)),
        (b"name".to_vec(), Value::Bytes(b"clip.bin".to_vec())),
        (b"piece length".to_vec(), Value::Int(piece_len as i64)),
        (b"pieces".to_vec(), Value::Bytes(pieces)),
    ]));
    let info = encode(&info);
    let info_hash: [u8; 20] = Sha1::digest(&info).into();
    Torrent { data, info, info_hash, piece_len }
}

/// Send one length-prefixed peer-wire message.
async fn send(s: &mut TcpStream, id: u8, payload: &[u8]) {
    let len = (1 + payload.len()) as u32;
    s.write_all(&len.to_be_bytes()).await.unwrap();
    s.write_all(&[id]).await.unwrap();
    s.write_all(payload).await.unwrap();
}

/// The fake seed: complete both handshakes, then answer metadata + piece
/// requests until the client hangs up.
async fn run_seed(mut s: TcpStream, t: Torrent) {
    // BitTorrent handshake: read the client's 68 bytes, reply with ours.
    let mut hs = [0u8; 68];
    s.read_exact(&mut hs).await.unwrap();
    let mut reply = [0u8; 68];
    reply[0] = 19;
    reply[1..20].copy_from_slice(b"BitTorrent protocol");
    reply[25] |= 0x10; // extension bit
    reply[28..48].copy_from_slice(&t.info_hash);
    reply[48..68].copy_from_slice(&[b'S'; 20]);
    s.write_all(&reply).await.unwrap();

    // Our extended handshake: advertise ut_metadata + metadata_size.
    let ext = Value::Dict(BTreeMap::from([
        (
            b"m".to_vec(),
            Value::Dict(BTreeMap::from([(
                b"ut_metadata".to_vec(),
                Value::Int(SEED_UT_METADATA as i64),
            )])),
        ),
        (b"metadata_size".to_vec(), Value::Int(t.info.len() as i64)),
    ]));
    let mut ext_payload = vec![0u8];
    ext_payload.extend_from_slice(&encode(&ext));
    send(&mut s, 20, &ext_payload).await;

    // Advertise every piece.
    let bits = t.data.len().div_ceil(t.piece_len);
    let mut bitfield = vec![0u8; bits.div_ceil(8)];
    for i in 0..bits {
        bitfield[i / 8] |= 1 << (7 - (i % 8));
    }
    send(&mut s, 5, &bitfield).await;

    // Learn the client's ut_metadata id (default 1) from its extended handshake.
    let mut client_ut = 1u8;

    loop {
        let mut len_buf = [0u8; 4];
        if s.read_exact(&mut len_buf).await.is_err() {
            return; // client closed
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 {
            continue;
        }
        let mut body = vec![0u8; len];
        if s.read_exact(&mut body).await.is_err() {
            return;
        }
        let id = body[0];
        let payload = &body[1..];
        match id {
            2 => send(&mut s, 1, &[]).await, // interested -> unchoke
            6 => {
                // request: index, begin, length -> piece message
                let index = u32::from_be_bytes(payload[0..4].try_into().unwrap());
                let begin = u32::from_be_bytes(payload[4..8].try_into().unwrap());
                let length = u32::from_be_bytes(payload[8..12].try_into().unwrap()) as usize;
                let start = index as usize * t.piece_len + begin as usize;
                let mut msg = Vec::new();
                msg.extend_from_slice(&index.to_be_bytes());
                msg.extend_from_slice(&begin.to_be_bytes());
                msg.extend_from_slice(&t.data[start..start + length]);
                send(&mut s, 7, &msg).await;
            }
            20 => {
                let ext_id = payload[0];
                let rest = &payload[1..];
                if ext_id == 0 {
                    // Client's extended handshake: pick up its ut_metadata id.
                    if let Ok(v) = epix_bt::bencode::decode(rest) {
                        if let Some(n) =
                            v.get("m").and_then(|m| m.get("ut_metadata")).and_then(Value::as_int)
                        {
                            client_ut = n as u8;
                        }
                    }
                } else if ext_id == SEED_UT_METADATA {
                    // A metadata request: reply with the piece's bytes.
                    let v = epix_bt::bencode::decode(rest).unwrap();
                    let piece = v.get("piece").and_then(Value::as_int).unwrap() as usize;
                    let start = piece * 16384;
                    let end = (start + 16384).min(t.info.len());
                    let reply = Value::Dict(BTreeMap::from([
                        (b"msg_type".to_vec(), Value::Int(1)),
                        (b"piece".to_vec(), Value::Int(piece as i64)),
                        (b"total_size".to_vec(), Value::Int(t.info.len() as i64)),
                    ]));
                    let mut out = vec![client_ut];
                    out.extend_from_slice(&encode(&reply));
                    out.extend_from_slice(&t.info[start..end]);
                    send(&mut s, 20, &out).await;
                }
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn fetches_metadata_and_a_piece_over_the_wire() {
    let t = build_torrent();
    let (want_info, want_hash, want_data, plen) =
        (t.info.clone(), t.info_hash, t.data.clone(), t.piece_len);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = match listener.local_addr().unwrap() {
        std::net::SocketAddr::V4(v4) => v4,
        _ => unreachable!(),
    };

    // The seed runs until the client drops.
    let seed = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        run_seed(sock, t).await;
    });

    let mut peer = Peer::connect(addr, want_hash, [b'C'; 20], None).await.unwrap();
    assert!(peer.supports_metadata());
    assert_eq!(peer.metadata_size(), Some(want_info.len()));

    // BEP9: the reassembled info dict matches and verifies against the hash.
    let info = peer.fetch_metadata(want_hash).await.unwrap();
    assert_eq!(info, want_info);

    // BEP3: piece 0 (a full piece) and the short last piece come back intact.
    let p0 = peer.fetch_piece(0, plen as u32).await.unwrap();
    assert_eq!(p0, &want_data[0..plen]);

    let last = (want_data.len() / plen) as u32;
    let last_len = (want_data.len() - last as usize * plen) as u32;
    let plast = peer.fetch_piece(last, last_len).await.unwrap();
    assert_eq!(plast, &want_data[last as usize * plen..]);

    drop(peer);
    let _ = seed.await;
}
