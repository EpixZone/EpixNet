//! Exercise the runtime's I2P bringup using the real SAM client and a local
//! SAM control server. No router installation or public tunnels are required.

use std::sync::Arc;
use std::time::Duration;

use super::{edx, i2p_loop};
use epix_ui::AppState;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Notify;

async fn check_i2p_advert(fileserver_port: Option<u16>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sam_port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut io = BufReader::new(stream);
                let mut line = String::new();
                assert!(io.read_line(&mut line).await.unwrap() > 0);
                assert!(line.starts_with("HELLO VERSION"));
                io.write_all(b"HELLO REPLY RESULT=OK VERSION=3.1\n")
                    .await
                    .unwrap();
                line.clear();
                if io.read_line(&mut line).await.unwrap() == 0 {
                    return;
                }
                if line.starts_with("SESSION CREATE") {
                    io.write_all(b"SESSION STATUS RESULT=OK DESTINATION=test-private-key\n")
                        .await
                        .unwrap();
                } else {
                    assert!(
                        line.starts_with("STREAM ACCEPT"),
                        "unexpected SAM command: {line}"
                    );
                    io.write_all(b"STREAM STATUS RESULT=OK\n").await.unwrap();
                }
                // Keep the session alive, with no inbound remote stream.
                line.clear();
                let _ = io.read_line(&mut line).await;
            });
        }
    });

    let data = tempfile::tempdir().unwrap();
    tokio::fs::create_dir(data.path().join("i2p")).await.unwrap();
    // A persisted identity avoids generating keys on the fake router. The
    // destination bytes still go through production base64/SHA256/base32.
    tokio::fs::write(
        data.path().join("i2p/destination.key"),
        "AQID\ntest-private-key\n",
    )
    .await
    .unwrap();
    let state = AppState::with_data_dir("i2p-client", data.path());
    state
        .set_transport(Arc::new(epix_transport::TcpTransport))
        .await;
    let shutdown = Arc::new(Notify::new());
    let runtime = tokio::spawn(i2p_loop(
        state.clone(),
        data.path().join("i2p"),
        "external".into(),
        sam_port,
        fileserver_port,
        edx::new_serve_cell(edx::ControlHandles::detached()),
        shutdown.clone(),
    ));
    tokio::time::timeout(Duration::from_secs(12), async {
        while state.i2p_status().await["phase"] != "Ready" {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("real SAM client reached Ready");
    let advert = state.self_advert().await;
    shutdown.notify_one();
    runtime.await.unwrap();
    server.abort();
    assert!(
        advert.want_i2p,
        "download-only clients still discover I2P holders"
    );
    assert_eq!(
        advert.i2p.is_some(),
        fileserver_port.is_some(),
        "only a node with an I2P accept handler may announce its destination"
    );
}

#[tokio::test]
async fn download_only_i2p_node_does_not_advertise_an_unserved_destination() {
    check_i2p_advert(None).await;
}

#[tokio::test]
async fn i2p_seeder_advertises_after_its_accept_handler_is_ready() {
    // I2P addresses have no physical port: Some(0) still enables its handler.
    check_i2p_advert(Some(0)).await;
}
