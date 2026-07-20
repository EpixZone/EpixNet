//! The peer swarm: discovery + metadata + piece serving for a bare magnet.
//!
//! Where [`crate::webseed::WebSeed`] streams from an HTTP host, a `Swarm`
//! streams from BitTorrent peers. It (1) finds peers on the mainline DHT
//! ([`crate::dht`]), (2) connects to several and pulls the metainfo from the
//! first that speaks BEP9, then (3) serves piece requests from the connected
//! peers. It exposes the same `read_range(global_off, len)` shape the engine
//! already uses, so a magnet with no web seed streams through the identical
//! ensure-piece / verify / store path - only the byte source differs.
//!
//! A streaming session is long-lived and its peers are not: connections drop,
//! and over Tor they drop often. So the swarm self-heals - when the live peers
//! can't serve a piece it connects spares and, failing that, re-runs DHT
//! discovery for fresh peers, rather than caching itself into a permanent dead
//! end. Connections are dialed directly (Tor off) or through the node's SOCKS5
//! proxy (Tor on but not "always").

use std::collections::HashSet;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::dht;
use crate::metainfo::{MetaError, MetaInfo};
use crate::peer::{Peer, PeerError};

/// How many peers to fetch from the DHT and try to reach per discovery round.
const WANT_PEERS: usize = 60;
/// How long to spend on the initial DHT lookup.
const DISCOVERY_BUDGET: Duration = Duration::from_secs(25);
/// A shorter budget for a mid-stream re-discovery (peers died, need more).
const REDISCOVER_BUDGET: Duration = Duration::from_secs(20);
/// Cap the live connections kept for serving pieces.
const KEEP_PEERS: usize = 12;
/// Max peers a single piece is split across. Torrents often use multi-MB pieces;
/// downloading one from a single (Tor-routed) peer is the streaming bottleneck,
/// so fan the piece's blocks out across this many peers at once.
const MAX_PARALLEL: usize = 8;
/// BitTorrent block size (16 KiB); a piece is fetched as a run of these.
const BLOCK: usize = 16 * 1024;
/// A single piece fetch (including any reconnection / re-discovery) gives up
/// after this, so a stalled stream surfaces an error the player can retry
/// instead of hanging a request open forever.
const FETCH_DEADLINE: Duration = Duration::from_secs(90);

#[derive(Debug, thiserror::Error)]
pub enum SwarmError {
    #[error("no peers found on the DHT for this info-hash")]
    NoPeers,
    #[error("connected to peers but none served valid metadata")]
    NoMetadata,
    #[error(transparent)]
    Meta(#[from] MetaError),
    #[error("no connected peer could serve piece {0}")]
    PieceUnavailable(u32),
}

/// A live peer plus its address (kept out-of-band so rediscovery can dedupe
/// without locking every connection).
#[derive(Clone)]
struct PeerHandle {
    addr: SocketAddrV4,
    peer: Arc<Mutex<Peer>>,
}

/// A connected swarm for one info-hash: the metainfo plus the live peer set.
pub struct Swarm {
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    socks: Option<SocketAddr>,
    meta: Arc<MetaInfo>,
    /// Live peer connections. Dead peers are pruned as fetches fail; the set is
    /// refilled from spares / fresh discovery on demand.
    peers: Mutex<Vec<PeerHandle>>,
    /// Discovered-but-not-connected addresses, used to top up cheaply.
    spare: Mutex<Vec<SocketAddrV4>>,
}

impl Swarm {
    /// Discover peers, fetch + verify the metainfo, and return a ready swarm.
    /// `socks` routes peer connections through Tor when set.
    pub async fn connect(
        info_hash: [u8; 20],
        socks: Option<SocketAddr>,
    ) -> Result<Swarm, SwarmError> {
        // The first UDP burst after a cold start is often dropped (OS/firewall
        // warm-up), so a single lookup can come back empty even when peers
        // exist. Retry once before giving up.
        let mut addrs = dht::get_peers(info_hash, WANT_PEERS, DISCOVERY_BUDGET).await;
        if addrs.is_empty() {
            addrs = dht::get_peers(info_hash, WANT_PEERS, DISCOVERY_BUDGET).await;
        }
        if addrs.is_empty() {
            return Err(SwarmError::NoPeers);
        }

        let peer_id = gen_peer_id();
        let (dialing, spare) = split_dialing(&addrs);
        let live = dial_batch(dialing, info_hash, peer_id, socks, KEEP_PEERS).await;
        if live.is_empty() {
            return Err(SwarmError::NoPeers);
        }

        // Pull the metainfo from the first peer that speaks BEP9.
        let meta = fetch_metadata(&live, info_hash).await.ok_or(SwarmError::NoMetadata)?;

        Ok(Swarm {
            info_hash,
            peer_id,
            socks,
            meta: Arc::new(meta),
            peers: Mutex::new(live),
            spare: Mutex::new(spare),
        })
    }

    /// The verified metainfo the swarm pulled from a peer.
    pub fn metainfo(&self) -> Arc<MetaInfo> {
        Arc::clone(&self.meta)
    }

    /// Number of live peers (diagnostics).
    pub async fn peer_count(&self) -> usize {
        self.peers.lock().await.len()
    }

    /// Read `[global_off, global_off+len)` of the torrent's data. The engine
    /// calls this exactly on piece boundaries (a whole torrent piece), so this
    /// fetches that piece from a peer and returns the requested slice of it.
    pub async fn read_range(&self, global_off: u64, len: u64) -> Result<Vec<u8>, SwarmError> {
        let plen = self.meta.piece_length;
        let index = (global_off / plen) as u32;
        let piece_len = self.meta.piece_size(index as usize) as u32;
        let piece = self.fetch_piece(index, piece_len).await?;

        let off_in_piece = (global_off - index as u64 * plen) as usize;
        if off_in_piece >= piece.len() {
            return Err(SwarmError::PieceUnavailable(index));
        }
        let end = (off_in_piece + len as usize).min(piece.len());
        Ok(piece[off_in_piece..end].to_vec())
    }

    /// Fetch one whole piece, self-healing the peer set as needed: split it
    /// across the live peers in parallel, and when they can't serve it, connect
    /// spares and finally re-run DHT discovery, until a deadline. The engine
    /// verifies the piece SHA-1, so a peer that lies is caught there.
    async fn fetch_piece(&self, index: u32, piece_len: u32) -> Result<Vec<u8>, SwarmError> {
        let deadline = Instant::now() + FETCH_DEADLINE;
        loop {
            if let Some(bytes) = self.try_fetch_parallel(index, piece_len).await {
                return Ok(bytes);
            }
            if Instant::now() >= deadline {
                return Err(SwarmError::PieceUnavailable(index));
            }
            // The live peers couldn't serve it. Bring in more: spares first
            // (cheap), then a fresh DHT lookup (expensive). If neither yields a
            // new peer, there's nothing left to try.
            if !self.top_up().await && !self.rediscover().await {
                return Err(SwarmError::PieceUnavailable(index));
            }
        }
    }

    /// Split piece `index` into contiguous segments and fetch each from a
    /// different peer concurrently, so a big piece downloads in parallel rather
    /// than serially from one slow (often Tor-routed) connection. Returns the
    /// assembled piece only if every segment arrived; on any failure the dead
    /// peers are pruned and it returns `None` so the caller can heal and retry.
    async fn try_fetch_parallel(&self, index: u32, piece_len: u32) -> Option<Vec<u8>> {
        let peers: Vec<PeerHandle> = self.peers.lock().await.clone();
        if peers.is_empty() {
            return None;
        }
        let blocks = (piece_len as usize).div_ceil(BLOCK);
        let parts = peers.len().min(MAX_PARALLEL).min(blocks).max(1);
        let segments = segment_bounds(piece_len, parts);

        // One task per segment, each on a distinct peer (segments.len() <= peers).
        let mut join: JoinSet<(SocketAddrV4, u32, Result<Vec<u8>, PeerError>)> = JoinSet::new();
        for (i, &(begin, len)) in segments.iter().enumerate() {
            let ph = peers[i].clone();
            join.spawn(async move {
                let mut guard = ph.peer.lock().await;
                let r = guard.fetch_range(index, begin, len).await;
                (ph.addr, begin, r)
            });
        }

        let mut buf = vec![0u8; piece_len as usize];
        let mut ok = true;
        let mut dead: Vec<SocketAddrV4> = Vec::new();
        while let Some(res) = join.join_next().await {
            match res {
                Ok((_addr, begin, Ok(bytes))) => {
                    let b = begin as usize;
                    buf[b..b + bytes.len()].copy_from_slice(&bytes);
                }
                Ok((addr, _begin, Err(_))) => {
                    dead.push(addr);
                    ok = false;
                }
                Err(_) => ok = false, // task join error (panic/abort)
            }
        }
        for addr in dead {
            self.remove_peer(addr).await;
        }
        ok.then_some(buf)
    }

    /// Drop a peer from the live set by address.
    async fn remove_peer(&self, addr: SocketAddrV4) {
        self.peers.lock().await.retain(|h| h.addr != addr);
    }

    /// The addresses we already know about (live or spare), so discovery can
    /// avoid re-dialing them.
    async fn known_addrs(&self) -> HashSet<SocketAddrV4> {
        let mut set: HashSet<SocketAddrV4> =
            self.peers.lock().await.iter().map(|h| h.addr).collect();
        set.extend(self.spare.lock().await.iter().copied());
        set
    }

    /// Connect a batch of spare addresses. Returns whether any new peer joined.
    async fn top_up(&self) -> bool {
        let batch: Vec<SocketAddrV4> = {
            let mut spare = self.spare.lock().await;
            let n = spare.len().min(KEEP_PEERS);
            spare.drain(..n).collect()
        };
        if batch.is_empty() {
            return false;
        }
        let live = dial_batch(batch, self.info_hash, self.peer_id, self.socks, KEEP_PEERS).await;
        self.add_peers(live).await
    }

    /// Re-run DHT discovery for fresh peers (used when spares are exhausted).
    /// Returns whether any new peer joined.
    async fn rediscover(&self) -> bool {
        let addrs = dht::get_peers(self.info_hash, WANT_PEERS, REDISCOVER_BUDGET).await;
        let known = self.known_addrs().await;
        let fresh: Vec<SocketAddrV4> = addrs.into_iter().filter(|a| !known.contains(a)).collect();
        if fresh.is_empty() {
            return false;
        }
        let (dial, extra) = split_dialing(&fresh);
        let live = dial_batch(dial, self.info_hash, self.peer_id, self.socks, KEEP_PEERS).await;
        self.spare.lock().await.extend(extra);
        self.add_peers(live).await
    }

    /// Add freshly connected peers to the live set. Returns whether any were added.
    async fn add_peers(&self, live: Vec<PeerHandle>) -> bool {
        if live.is_empty() {
            return false;
        }
        self.peers.lock().await.extend(live);
        true
    }
}

/// Dial a batch of addresses concurrently, keeping up to `keep` that handshake.
async fn dial_batch(
    addrs: Vec<SocketAddrV4>,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    socks: Option<SocketAddr>,
    keep: usize,
) -> Vec<PeerHandle> {
    let mut join: JoinSet<Result<Peer, PeerError>> = JoinSet::new();
    for addr in addrs {
        join.spawn(async move { Peer::connect(addr, info_hash, peer_id, socks).await });
    }
    let mut live: Vec<PeerHandle> = Vec::new();
    while let Some(res) = join.join_next().await {
        if let Ok(Ok(peer)) = res {
            live.push(PeerHandle { addr: peer.addr(), peer: Arc::new(Mutex::new(peer)) });
            if live.len() >= keep {
                join.abort_all();
                break;
            }
        }
    }
    live
}

/// Fetch and verify the metainfo from whichever connected peer serves it first.
async fn fetch_metadata(peers: &[PeerHandle], info_hash: [u8; 20]) -> Option<MetaInfo> {
    for h in peers {
        let mut guard = h.peer.lock().await;
        if !guard.supports_metadata() {
            continue;
        }
        if let Ok(info) = guard.fetch_metadata(info_hash).await {
            if let Ok(meta) = MetaInfo::from_info_dict(&info, info_hash) {
                return Some(meta);
            }
        }
    }
    None
}

/// Divide a piece of `piece_len` bytes into at most `parts` contiguous,
/// block-aligned segments (the last runs to the piece end). Each segment is
/// handed to a different peer.
fn segment_bounds(piece_len: u32, parts: usize) -> Vec<(u32, u32)> {
    let total_blocks = piece_len.div_ceil(BLOCK as u32);
    let blocks_per = (total_blocks as usize).div_ceil(parts.max(1)) as u32;
    let seg = blocks_per * BLOCK as u32;
    let mut out = Vec::new();
    let mut begin = 0u32;
    while begin < piece_len {
        let len = seg.min(piece_len - begin);
        out.push((begin, len));
        begin += len;
    }
    out
}

/// Split discovered addresses into the initial dial set and the spares.
fn split_dialing(addrs: &[SocketAddrV4]) -> (Vec<SocketAddrV4>, Vec<SocketAddrV4>) {
    // Dial more than KEEP_PEERS up front since many won't answer.
    let dial_n = addrs.len().min(KEEP_PEERS * 3);
    (addrs[..dial_n].to_vec(), addrs[dial_n..].to_vec())
}

/// An Azureus-style peer id: `-EP0001-` plus 12 random bytes.
fn gen_peer_id() -> [u8; 20] {
    let mut id = [0u8; 20];
    id[..8].copy_from_slice(b"-EP0001-");
    let tail: [u8; 12] = rand::random();
    id[8..].copy_from_slice(&tail);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_has_client_prefix() {
        let id = gen_peer_id();
        assert_eq!(&id[..8], b"-EP0001-");
        // Two ids differ in the random tail (astronomically unlikely to match).
        assert_ne!(gen_peer_id()[8..], id[8..]);
    }

    #[test]
    fn segment_bounds_split_a_piece_evenly_and_aligned() {
        // A 4 MiB piece across 8 peers => eight 512 KiB block-aligned segments.
        let segs = segment_bounds(4 * 1024 * 1024, 8);
        assert_eq!(segs.len(), 8);
        assert!(segs.iter().all(|&(b, _)| b % BLOCK as u32 == 0));
        assert_eq!(segs.iter().map(|&(_, l)| l as u64).sum::<u64>(), 4 * 1024 * 1024);
        assert_eq!(segs[0], (0, 512 * 1024));

        // A short piece smaller than one block is a single segment.
        let one = segment_bounds(40, 8);
        assert_eq!(one, vec![(0, 40)]);

        // Contiguity: each segment begins where the previous ended.
        let mut cursor = 0u32;
        for (b, l) in segment_bounds(3 * 1024 * 1024 + 123, 5) {
            assert_eq!(b, cursor);
            cursor += l;
        }
        assert_eq!(cursor, 3 * 1024 * 1024 + 123);
    }

    #[test]
    fn split_dialing_caps_initial_dials() {
        let addrs: Vec<SocketAddrV4> =
            (0..100).map(|i| SocketAddrV4::new([10, 0, 0, 1].into(), 1000 + i)).collect();
        let (dial, spare) = split_dialing(&addrs);
        assert_eq!(dial.len(), KEEP_PEERS * 3);
        assert_eq!(spare.len(), 100 - KEEP_PEERS * 3);

        let few = &addrs[..5];
        let (dial, spare) = split_dialing(few);
        assert_eq!(dial.len(), 5);
        assert!(spare.is_empty());
    }
}
