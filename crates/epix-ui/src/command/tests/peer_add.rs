use super::*;
use crate::state::XiteEntry;
use epix_xite::XiteStorage;

#[tokio::test]
async fn peer_endpoint_requires_operator_permission_and_preserves_network_policy() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::new("peer-bootstrap-test");
    state
        .add_xite(
            "fixture",
            XiteEntry {
                storage: XiteStorage::new(dir.path()),
                content: None,
            },
        )
        .await;
    state.config_set("tor", json!("always")).await;
    state.config_set("offline", json!(true)).await;
    state.config_set("mesh", json!("disable")).await;
    let commands = CommandRegistry::with_defaults();
    let page = WsSession::new(state.clone(), Some("fixture".into()));
    let wrapper = WsSession::new_wrapper(state.clone(), Some("fixture".into()));
    let peer = "rns:0123456789abcdef0123456789abcdef";
    let args = json!({"peer":peer});
    assert!(commands.dispatch(&page, "peerAdd", &args, 1).await.is_err());
    assert_eq!(state.peer_counts("fixture").await.total, 0);
    assert_eq!(
        commands
            .dispatch(&wrapper, "peerAdd", &args, WRAPPER_ID_BASE)
            .await
            .unwrap(),
        "updated"
    );
    assert_eq!(state.peer_counts("fixture").await.total, 1);
    for (key, expected) in [
        ("tor", json!("always")),
        ("offline", json!(true)),
        ("mesh", json!("disable")),
    ] {
        assert_eq!(state.config_get(key).await, Some(expected));
    }
    state.config_set("ui_restrict", json!(true)).await;
    assert!(commands
        .dispatch(&wrapper, "peerAdd", &args, WRAPPER_ID_BASE)
        .await
        .unwrap_err()
        .contains("gateway"));
}

#[tokio::test]
async fn peer_endpoint_validates_target_shape_self_and_legacy_port() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::new("peer-bootstrap-test");
    state
        .add_xite(
            "fixture",
            XiteEntry {
                storage: XiteStorage::new(dir.path()),
                content: None,
            },
        )
        .await;
    let session = WsSession::new_trusted(state.clone(), Some("fixture".into()));
    for peer in [
        "rns:xyz",
        "rns:00000000000000000000000000000000",
        "rns:0123456789abcdef0123456789abcdef:1",
        "https://127.0.0.1/",
        "127.0.0.1:0",
    ] {
        assert!(
            PeerAdd
                .handle(&session, &json!({"peer":peer}))
                .await
                .is_err(),
            "{peer}"
        );
    }
    let own = "0123456789abcdef0123456789abcdef";
    state.set_rns_reliable_address(own).await;
    assert!(PeerAdd
        .handle(&session, &json!({"peer":format!("rns:{own}")}))
        .await
        .is_err());
    assert!(PeerAdd
        .handle(
            &session,
            &json!({"peer":"127.0.0.1:42424","site_address":"missing"})
        )
        .await
        .is_err());
    for port in [-1, 0, 65536] {
        assert!(PeerAdd
            .handle(&session, &json!(["127.0.0.1", port]))
            .await
            .is_err());
    }
    assert_eq!(
        PeerAdd
            .handle(&session, &json!(["127.0.0.1", 42424]))
            .await
            .unwrap(),
        "updated"
    );
    assert_eq!(state.peer_counts("fixture").await.total, 1);
}
