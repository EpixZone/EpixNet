//! Shared xID thumbnail protocol through the actual command dispatcher.
use base64::{engine::general_purpose::STANDARD, Engine};
use epix_ui::command::{CommandRegistry, WsSession, WRAPPER_ID_BASE};
use epix_ui::state::AppState;
use serde_json::{json, Value};

async fn get(
    commands: &CommandRegistry,
    session: &WsSession,
    key: &Value,
) -> Result<Value, String> {
    commands
        .dispatch(session, "avatarCacheGet", key, WRAPPER_ID_BASE)
        .await
}

#[tokio::test]
async fn wrappers_reuse_public_thumbnails_across_xites_and_restarts() {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("test", root.path());
    let talk = WsSession::new_wrapper(state, Some("talk.epix".into()));
    let commands = CommandRegistry::with_defaults();
    let key = json!({"url":"https://images.example.org/avatar.png","size":80});
    let miss = get(&commands, &talk, &key).await.unwrap();
    assert_eq!(
        miss,
        json!({"thumbnail":null}),
        "the backend must distinguish a cache miss from an unsupported command"
    );
    let pixels = [18, 80, 76, 255].repeat(80 * 80);
    let mut write = key.clone();
    write["width"] = json!(80);
    write["rgba"] = json!(STANDARD.encode(&pixels));
    let stored = commands
        .dispatch(&talk, "avatarCachePut", &write, WRAPPER_ID_BASE)
        .await
        .unwrap();
    let encoded = stored["thumbnail"]
        .as_str()
        .unwrap()
        .strip_prefix("data:image/png;base64,")
        .unwrap();
    let png = STANDARD.decode(encoded).unwrap();
    assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(u32::from_be_bytes(png[16..20].try_into().unwrap()), 80);
    assert_eq!(u32::from_be_bytes(png[20..24].try_into().unwrap()), 80);
    let mut reader = png::Decoder::new(std::io::Cursor::new(&png))
        .read_info()
        .unwrap();
    let mut decoded = vec![0; reader.output_buffer_size().unwrap()];
    reader.next_frame(&mut decoded).unwrap();
    assert_eq!(
        decoded, pixels,
        "PNG preserves the wrapper's exact RGBA samples"
    );
    drop(talk);

    let state = AppState::with_data_dir("test", root.path());
    let post = WsSession::new_wrapper(state, Some("post.epix".into()));
    assert_eq!(
        get(&commands, &post, &key).await.unwrap(),
        stored,
        "a different xite after restart reuses the exact PNG"
    );
    let mut fragment = key.clone();
    fragment["url"] = json!("https://images.example.org/avatar.png#profile-card");
    assert_eq!(get(&commands, &post, &fragment).await.unwrap(), stored);
    let mut changed = key.clone();
    changed["url"] = json!("https://images.example.org/avatar.png?v=2");
    assert_eq!(get(&commands, &post, &changed).await.unwrap(), miss);
    let mut smaller = key.clone();
    smaller["size"] = json!(56);
    assert_eq!(get(&commands, &post, &smaller).await.unwrap(), miss);
}

#[tokio::test]
async fn pages_cannot_inspect_or_poison_the_shared_cache() {
    let state = AppState::new("test");
    let commands = CommandRegistry::with_defaults();
    let key = json!({"url":"https://images.example.org/avatar.png","size":1});
    let put = json!({"url":key["url"],"size":1,"width":1,"rgba":"/////w=="});
    let mut page = WsSession::new(state.clone(), Some("evil.epix".into()));
    page.admin = true;
    let wrapper = WsSession::new_wrapper(state.clone(), Some("evil.epix".into()));
    for (command, params) in [("avatarCacheGet", &key), ("avatarCachePut", &put)] {
        assert!(commands
            .dispatch(&page, command, params, WRAPPER_ID_BASE)
            .await
            .is_err());
        assert!(commands
            .dispatch(&wrapper, command, params, 1)
            .await
            .is_err());
        for (caller, id) in [(&page, 1), (&wrapper, WRAPPER_ID_BASE)] {
            let rebound = json!({"address":"another.epix","cmd":command,"params":params});
            assert!(commands.dispatch(caller, "as", &rebound, id).await.is_err());
        }
    }
    state.config_set("ui_restrict", json!(true)).await;
    assert!(get(&commands, &wrapper, &key).await.is_err());
    assert!(commands
        .dispatch(&wrapper, "avatarCachePut", &put, WRAPPER_ID_BASE)
        .await
        .is_err());
}

#[tokio::test]
async fn rejects_invalid_pixels_sizes_and_private_urls() {
    let wrapper = WsSession::new_wrapper(AppState::new("test"), Some("blog.epix".into()));
    let commands = CommandRegistry::with_defaults();
    let put =
        json!({"url":"https://images.example.org/p.png","size":1,"width":1,"rgba":"/////w=="});
    for (field, value) in [
        ("size", json!(0)),
        ("size", json!(129)),
        ("size", json!(1.5)),
        ("width", json!(2)),
        ("width", json!(-1)),
        ("rgba", json!("AAAAAAAA")),
        ("rgba", json!("data:image/svg+xml,<svg/>")),
        ("rgba", json!("!!!!!!!!")),
        ("url", json!("file:///tmp/avatar")),
        ("url", json!("https://localhost/p.png")),
        ("url", json!("http://127.0.0.1/Backup")),
        ("url", json!("http://[::1]/")),
        ("url", json!("https://talk.content.epix/")),
        ("url", json!("https://user:pass@photos.example.org/")),
    ] {
        let mut bad = put.clone();
        bad[field] = value;
        assert!(
            commands
                .dispatch(&wrapper, "avatarCachePut", &bad, WRAPPER_ID_BASE)
                .await
                .is_err(),
            "{field}"
        );
    }
}
