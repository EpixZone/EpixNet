//! A bare positional parameter (`cmd("x", "value")`) fills the FIRST
//! parameter only. It must never also fill a second one (ecdsaSign's key,
//! identityLinkComplete's name, xidResolveName's tld), nor be ignored
//! (identitySelect), and vrfGetBeacon takes a bare height.

use super::{arg_str_at, CommandRegistry, WsSession};
use crate::state::{AppState, XiteEntry};
use serde_json::{json, Value};

async fn session_with_xite() -> (WsSession, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::new("bare-params-test");
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    state
        .add_xite(
            &address,
            XiteEntry {
                storage: epix_xite::XiteStorage::new(dir.path()),
                content: Some(json!({ "address": address })),
            },
        )
        .await;
    (WsSession::new(state, Some(address)), dir)
}

#[test]
fn a_bare_string_fills_only_the_first_parameter() {
    let bare = json!("alice.epix");
    assert_eq!(arg_str_at(&bare, "name", 0), Some("alice.epix"));
    assert_eq!(arg_str_at(&bare, "tld", 1), None);
    let listed = json!(["epix1auth", "alice.epix"]);
    assert_eq!(arg_str_at(&listed, "auth_address", 0), Some("epix1auth"));
    assert_eq!(arg_str_at(&listed, "name", 1), Some("alice.epix"));
    let keyed = json!({ "name": "alice.epix" });
    assert_eq!(arg_str_at(&keyed, "name", 1), Some("alice.epix"));
    assert_eq!(arg_str_at(&keyed, "auth_address", 0), None);
}

#[tokio::test]
async fn ecdsa_sign_never_reads_a_bare_string_as_the_private_key() {
    let (session, _dir) = session_with_xite().await;
    let registry = CommandRegistry::with_defaults();
    // No identity selected: the bare data string is signed with the xite's
    // identity key, which is missing, rather than used as a key itself.
    let error = registry
        .dispatch(&session, "ecdsaSign", &json!("hello"), 1)
        .await
        .unwrap_err();
    assert_eq!(error, epix_user::XID_REQUIRED);
    // An explicit key still signs.
    let key = epix_crypt::new_seed();
    let signer = epix_crypt::privatekey_to_address(&key).unwrap();
    let signature = registry
        .dispatch(&session, "ecdsaSign", &json!(["hello", key]), 1)
        .await
        .unwrap();
    assert!(epix_crypt::verify("hello", &signer, signature.as_str().unwrap()));
}

#[tokio::test]
async fn xid_resolve_name_reads_the_tld_from_a_bare_fqdn() {
    let (session, _dir) = session_with_xite().await;
    let registry = CommandRegistry::with_defaults();
    // An address-shaped label with a bad checksum is refused before any
    // network lookup, but only when the tld is read as "epix": with the bare
    // string also taken as the tld this guard was skipped.
    let address = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
    let last = address.chars().last().unwrap();
    let typo = format!("{}{}", &address[..address.len() - 1], if last == 'q' { 'p' } else { 'q' });
    let result = registry
        .dispatch(&session, "xidResolveName", &json!(format!("{typo}.epix")), 1)
        .await
        .unwrap();
    let error = result["error"].as_str().unwrap_or_default();
    assert!(error.contains("mistyped epix1 address"), "{result}");
    assert!(error.starts_with(&format!("{typo}.epix ")), "{result}");
}

#[tokio::test]
async fn identity_select_does_not_ignore_a_bare_string() {
    let (session, _dir) = session_with_xite().await;
    let registry = CommandRegistry::with_defaults();
    // An unknown identity is an error, not a silent reset to the default.
    let error = registry
        .dispatch(&session, "identitySelect", &json!("epix1unknownidentity"), 1)
        .await
        .unwrap_err();
    assert!(error.contains("unknown identity"), "{error}");
    // A bare "" chooses anonymous browsing, as {auth_address: ""} does.
    let result = registry
        .dispatch(&session, "identitySelect", &json!(""), 1)
        .await
        .unwrap();
    assert_eq!(result, Value::from("ok"));
    let result = registry
        .dispatch(&session, "identitySelect", &json!({ "auth_address": "" }), 1)
        .await
        .unwrap();
    assert_eq!(result, Value::from("Not changed"));
}

#[tokio::test]
async fn vrf_get_beacon_accepts_a_bare_height() {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut chunk).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
        }
        let body = br#"{"beacon":{"height":"424242","beacon":"ab","proposer":"p","timestamp":"5"}}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
        String::from_utf8(request).unwrap()
    });
    let (session, _dir) = session_with_xite().await;
    session.state.config_set("chain_rpc_url", json!(url)).await;
    let registry = CommandRegistry::with_defaults();
    let result = registry
        .dispatch(&session, "vrfGetBeacon", &json!(424242), 1)
        .await
        .unwrap();
    assert_eq!(result["height"], 424242, "{result}");
    assert_eq!(result["beacon"], "ab");
    let request = server.join().unwrap();
    assert!(request.starts_with("GET /vrf/v1/beacon/424242 "), "{request}");
}
