//! The clearnet (Noise) inbound path must release an idle connection.
//!
//! The overlay path hands its stream straight to `Conn::start`, so the server's
//! idle reaper frees it. The clearnet path goes through `noise::secure`, which
//! moves the stream into two detached pump tasks - so the reaper firing tore down
//! the plaintext duplex and left the real socket, and its /Stats row, held by the
//! inbound pump. A gateway accumulated rows stuck at `last recv = Hello` with
//! zero activity, still listed hours later.
//!
//! The peer here stays connected and silent, which is the case that leaked: the
//! inbound pump had no wakeup source, so only the peer closing could free it.

use std::sync::Arc;
use std::time::Duration;

use epix_blob::store::Store;
use epix_core::PeerAddr;
use epix_edx::server::{client_hello, ServeCtx, SignedProvider, UpdateSource};
use epix_runtime::edx::{edx_hook, ControlHandles};
use epix_transport::{TcpTransport, Transport};
use epix_ui::AppState;

struct NoProvider;
#[async_trait::async_trait]
impl SignedProvider for NoProvider {
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
        _i: &[(epix_blob::ObjId, Vec<u8>)],
        _m: f64,
        _d: &[(String, Vec<u8>)],
        _sp: &[String],
        _source: UpdateSource,
    ) -> Result<bool, String> {
        Ok(true)
    }
}

// Real time, because the reaper deadline is a 300s const and the handshake runs
// over a real socket (virtual time auto-advances past the dial timeouts before
// the I/O completes). The mechanism itself is covered in CI by the fast
// epix-edx noise_teardown tests; this is the end-to-end wiring check.
// Run with: cargo test -p epix-runtime --test clearnet_idle_reap -- --ignored
#[ignore = "takes 310s: waits out the real IDLE_TIMEOUT"]
#[tokio::test]
async fn idle_clearnet_inbound_leaves_the_stats_page() {
    epix_protocol::set_self_advert(epix_protocol::SelfAdvert {
        version: "0.3.28".into(),
        ..Default::default()
    });

    let state = AppState::new("0.3.28");
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    state.set_edx_store(store.clone()).await.unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = epix_protocol::PeerServer::new(edx_hook(
        state,
        store,
        epix_crypt::new_seed(),
        None,
        ControlHandles::detached(),
        false,
        None,
    ));
    tokio::spawn(async move {
        let _ = server.serve(listener).await;
    });

    // Peer: dial, Noise, Hello with an onion dial-back, then hold the socket
    // open and say nothing (exactly what the gateway's peer does).
    let stream = TcpTransport.dial(&PeerAddr::Ip(addr)).await.unwrap();
    let link = epix_edx::link::dial(stream).await.unwrap();
    let d = tempfile::tempdir().unwrap();
    let cstore = Arc::new(Store::open(d.path()).unwrap());
    let cctx = ServeCtx::new(cstore, Arc::new(NoProvider), epix_crypt::new_seed())
        .with_version("0.3.28".into());
    let dialback =
        PeerAddr::parse("6m4j2es4wom2xyhlvj4vjmsdsabqascped5d7t7knz3w2ku5hqlywwid.onion:26552")
            .unwrap();
    client_hello(&link.conn, &cctx, vec![dialback.clone()], Some(link.handshake_hash)).await.unwrap();

    assert!(
        epix_protocol::registry::snapshot().iter().any(|r| r.addr == dialback),
        "the inbound clearnet link should be listed after its Hello"
    );

    // Silent past IDLE_TIMEOUT (300s). The peer (this test) keeps its Conn -
    // and therefore its socket - alive the whole time, like a pooled link.
    tokio::time::sleep(Duration::from_secs(310)).await;

    let rows: Vec<String> = epix_protocol::registry::snapshot()
        .into_iter()
        .filter(|r| r.addr == dialback)
        .map(|r| format!("id={} open={}s idle={}s last_recv={:?}", r.id, r.opened_secs, r.idle_secs, r.last_cmd_recv))
        .collect();
    assert!(
        rows.is_empty(),
        "the idle clearnet inbound link is still listed after IDLE_TIMEOUT, so its socket \
         and its /Stats row leaked: {rows:?}"
    );
}
