use super::{ctx_for, store_in, Fixture, TEST_KEY};
use crate::choke::Reach;
use crate::conn::Conn;
use crate::msg::{Hello, HelloAck, Req, Resp, NET_ID};
use crate::server::{client_hello, serve, ServeCtx, SignedProvider, UpdateSource};
use epix_blob::ObjId;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Interests(Mutex<Vec<(String, UpdateSource)>>);

#[async_trait::async_trait]
impl SignedProvider for Interests {
    async fn note_interest(&self, xite: &str, source: UpdateSource) {
        self.0.lock().unwrap().push((xite.into(), source));
    }
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
        _: &str,
        _: &str,
        _: &[u8],
        _: &[(ObjId, Vec<u8>)],
        _: f64,
        _: &[(String, Vec<u8>)],
        _: &[String],
        _: UpdateSource,
    ) -> Result<bool, String> {
        Ok(false)
    }
}

fn request() -> Req {
    Req::GetSigned {
        xite: "requested-xite".into(),
        inner_path: "content.json".into(),
    }
}

#[tokio::test]
async fn unauthenticated_and_forged_hello_never_report_interest() {
    for first in [
        request(),
        Req::Hello(Hello {
            net: NET_ID.into(),
            node_pk: epix_crypt::private_to_compressed_pubkey(TEST_KEY).unwrap(),
            binding_sig: Vec::new(),
            caps: 0,
            listen: Vec::new(),
            version: String::new(),
        }),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let interests = Arc::new(Interests::default());
        let ctx = Arc::new(ServeCtx::new(
            store_in(&directory),
            interests.clone(),
            TEST_KEY.into(),
        ));
        let (a, b) = tokio::io::duplex(4096);
        let (client, _incoming) = Conn::start(a, true);
        let (server, incoming) = Conn::start(b, false);
        let task = tokio::spawn(serve(server, incoming, ctx, Some([4; 32])));
        assert!(matches!(
            client.request(first).await.unwrap(),
            Resp::Err { .. }
        ));
        assert!(task.await.unwrap().is_none());
        assert!(interests.0.lock().unwrap().is_empty());
        client.shutdown();
    }
}

#[tokio::test]
async fn valid_hello_binds_interest_to_the_same_channel_and_identity() {
    let directory = tempfile::tempdir().unwrap();
    let interests = Arc::new(Interests::default());
    let ctx = Arc::new(ServeCtx::new(
        store_in(&directory),
        interests.clone(),
        TEST_KEY.into(),
    ));
    let (a, b) = tokio::io::duplex(4096);
    let (client, _incoming) = Conn::start(a, true);
    let (server, incoming) = Conn::start(b, false);
    let task = tokio::spawn(serve(server.clone(), incoming, ctx.clone(), Some([4; 32])));
    client_hello(&client, &ctx, Vec::new(), Some([4; 32]))
        .await
        .unwrap();
    assert!(matches!(
        client.request(request()).await.unwrap(),
        Resp::Err { .. }
    ));
    {
        let seen = interests.0.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "requested-xite");
        assert!(seen[0].1.conn.same_connection(&server));
        assert_eq!(
            seen[0].1.identity.address,
            epix_crypt::privatekey_to_address(TEST_KEY).unwrap()
        );
        assert_eq!(seen[0].1.reach, Reach::Clearnet);
    }
    client.shutdown();
    task.await.unwrap();
}

#[tokio::test]
async fn session_handles_are_excluded_from_hello_and_pex_wire_messages() {
    let directory = tempfile::tempdir().unwrap();
    let ctx = ctx_for(
        store_in(&directory),
        Fixture {
            signed: None,
            block: false,
        },
    );
    let (a, b) = tokio::io::duplex(4096);
    let (client, _incoming) = Conn::start(a, true);
    let (server, mut incoming) = Conn::start(b, false);
    let real = epix_core::PeerAddr::parse("192.0.2.1:26552").unwrap();
    let expected = real.clone();
    let task = tokio::spawn(async move {
        let hello = incoming.recv().await.unwrap();
        let Req::Hello(payload) = hello.req else {
            panic!("expected Hello")
        };
        assert_eq!(payload.listen, vec![expected.clone()]);
        server
            .respond(
                hello.stream,
                Resp::HelloAck(HelloAck {
                    net: NET_ID.into(),
                    node_pk: epix_crypt::private_to_compressed_pubkey(TEST_KEY).unwrap(),
                    binding_sig: Vec::new(),
                    caps: 0,
                    observed: None,
                    version: String::new(),
                }),
            )
            .await
            .unwrap();
        let pex = incoming.recv().await.unwrap();
        let Req::Pex { peers, .. } = pex.req else {
            panic!("expected Pex")
        };
        assert_eq!(peers, vec![expected]);
        server
            .respond(pex.stream, Resp::Peers { peers: Vec::new() })
            .await
            .unwrap();
    });
    let handles = vec![
        real,
        epix_core::PeerAddr::Session {
            id: [3; 32],
            network: epix_core::IpType::Ipv4,
        },
    ];
    client_hello(&client, &ctx, handles.clone(), None)
        .await
        .unwrap();
    assert!(crate::fetch::pex(&client, "requested-xite", 10, handles)
        .await
        .unwrap()
        .is_empty());
    task.await.unwrap();
    client.shutdown();
}
