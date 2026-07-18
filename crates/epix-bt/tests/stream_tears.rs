//! Live end-to-end streaming test against the public Tears of Steel web seed.
//!
//! This exercises the whole engine: parse the magnet, fetch the real `.torrent`
//! from `xs=`, recompute + match the info-hash, pick the largest file, fetch the
//! covering 512 KiB piece(s) from the BEP19 web seed, SHA-1-verify each against
//! the metainfo, write to the sparse store, and read the requested range back.
//!
//! It hits the network (webtorrent.io), so it is `#[ignore]`d by default. Run:
//!   cargo test -p epix-bt --test stream_tears -- --ignored --nocapture
//!
//! NB: webtorrent.io is behind Cloudflare, which blocks Tor exit nodes, so this
//! only passes over clearnet (BT_SOCKS unset). Streaming this particular magnet
//! through a Tor-always node needs a Tor-reachable web seed or the peer wire.

use epix_bt::Engine;

const TEARS: &str = "magnet:?xt=urn:btih:209c8226b299b308beaf2b9cd3fb49212dbd13ec\
&dn=Tears+of+Steel\
&ws=https%3A%2F%2Fwebtorrent.io%2Ftorrents%2F\
&xs=https%3A%2F%2Fwebtorrent.io%2Ftorrents%2Ftears-of-steel.torrent";

/// Length of the primary file, `Tears of Steel.webm`.
const WEBM_LEN: u64 = 571_346_576;

#[tokio::test]
#[ignore = "hits the network (webtorrent.io); run with --ignored"]
async fn streams_verified_tears_of_steel_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(dir.path());

    // First 256 KiB: the engine fetches + SHA-1-verifies piece 0 (512 KiB) to
    // serve it.
    let served = engine.stream(TEARS, Some("bytes=0-262143")).await.expect("stream first range");
    assert_eq!(served.start, 0);
    assert_eq!(served.end, 262_143);
    assert_eq!(served.bytes.len(), 262_144);
    assert_eq!(served.content_type, "video/webm");
    assert_eq!(served.total, WEBM_LEN, "Content-Range denominator is the streamed file length");
    // EBML/WebM signature - proof the served bytes are the real, hash-verified
    // video, not an error page or garbage.
    assert_eq!(&served.bytes[0..4], &[0x1a, 0x45, 0xdf, 0xa3], "WebM magic bytes");

    // A deeper range exercises the piece math across the multi-file boundary
    // (the webm starts after eight .srt files) and a second web-seed fetch.
    let served2 =
        engine.stream(TEARS, Some("bytes=2097152-2097407")).await.expect("stream deep range");
    assert_eq!(served2.start, 2_097_152);
    assert_eq!(served2.end, 2_097_407);
    assert_eq!(served2.bytes.len(), 256);

    // An open-ended range near EOF must clamp to the file end, not overrun.
    let last_start = WEBM_LEN - 100;
    let served3 = engine
        .stream(TEARS, Some(&format!("bytes={last_start}-")))
        .await
        .expect("stream tail range");
    assert_eq!(served3.end, WEBM_LEN - 1);
    assert_eq!(served3.bytes.len(), 100);
}

/// A bare `.torrent` URL with NO web seed declared (only a UDP tracker). The
/// engine must fetch the `.torrent`, then derive the web seed from the URL's own
/// directory (the `.webm` sits next to the `.torrent`) and stream from it. This
/// host, unlike webtorrent.io, is not behind Cloudflare, so it also works over
/// Tor.
#[tokio::test]
#[ignore = "hits the network (download.stefan.ubbink.org); run with --ignored"]
async fn streams_from_bare_torrent_url_via_implicit_web_seed() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(dir.path());

    let url = "http://download.stefan.ubbink.org/ToS/tears_of_steel_1080p.webm.torrent";
    let served = engine.stream(url, Some("bytes=0-262143")).await.expect("stream from .torrent url");
    assert_eq!(served.start, 0);
    assert_eq!(served.end, 262_143);
    assert_eq!(served.bytes.len(), 262_144);
    assert_eq!(served.content_type, "video/webm");
    assert_eq!(served.total, WEBM_LEN);
    assert_eq!(&served.bytes[0..4], &[0x1a, 0x45, 0xdf, 0xa3], "WebM magic bytes");
}
