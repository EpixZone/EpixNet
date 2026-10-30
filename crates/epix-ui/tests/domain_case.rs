//! Name matching ignores ASCII case without changing paths or address validity.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use epix_ui::{rewrite_proxy_host, AppState, OnDemandResolver, ResolvedHost, UiServer, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

const QUERY: &str = "Token=AbC%2FZ&Path=Keep%2FCase";
const MIXED_BYTES: &[u8] = b"Mixed-case asset";
const LOWER_BYTES: &[u8] = b"different lowercase asset";

struct Fixture {
    root: tempfile::TempDir,
    state: Arc<AppState>,
    router: axum::Router,
    address: String,
}

impl Fixture {
    async fn new() -> Self {
        // This isolated integration process uses the default finality-off
        // policy, like wrapper_canonical_paths. No network lookup is needed.
        assert!(!epix_chain::verify_finality_enabled());
        let root = tempfile::tempdir().unwrap();
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let storage = XiteStorage::new(root.path().join("data").join(&address));
        let mut files = serde_json::Map::new();
        for (path, bytes) in [
            (
                "index.html",
                b"<!doctype html><title>Case fixture</title>".as_slice(),
            ),
            (
                "Docs/Mixed.html",
                b"<!doctype html><p>Mixed document</p>".as_slice(),
            ),
            ("Docs/Mixed.txt", MIXED_BYTES),
            ("docs/lower.txt", LOWER_BYTES),
        ] {
            storage.write(path, bytes).unwrap();
            files.insert(
                path.into(),
                json!({
                    "size": bytes.len(), "sha512": XiteStorage::hash_bytes(bytes)
                }),
            );
        }
        let mut content = json!({
            "address": address, "domain": "talk.epix", "modified": 1, "files": files
        });
        epix_content::sign(&mut content, &key).unwrap();
        storage
            .write(
                "content.json",
                epix_content::dumps_content(&content).as_bytes(),
            )
            .unwrap();
        let state = AppState::with_data_dir("domain-case-test", root.path());
        state
            .add_xite(
                &address,
                XiteEntry {
                    storage,
                    content: Some(content),
                },
            )
            .await;
        state.config_set("ui_check_cors", json!(true)).await;
        let router = UiServer::new(state.clone()).router();
        let fixture = Self {
            root,
            state,
            router,
            address,
        };
        fixture.map_name("talk.epix");
        fixture.map_name("epix1shop.epix");
        fixture
    }

    fn map_name(&self, name: &str) {
        let path = self.root.path().join("resolve-cache.json");
        let mut cache: serde_json::Map<String, Value> = std::fs::read(&path)
            .ok()
            .map(|bytes| serde_json::from_slice(&bytes).unwrap())
            .unwrap_or_default();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        cache.insert(
            name.into(),
            json!({ "address": self.address, "resolved_at": now }),
        );
        std::fs::write(path, serde_json::to_vec(&cache).unwrap()).unwrap();
    }

    async fn get(
        &self,
        host: &str,
        uri: &str,
        headers: &[(&str, &str)],
    ) -> axum::response::Response {
        let mut request = Request::builder().uri(uri).header("host", host);
        for (key, value) in headers {
            request = request.header(*key, *value);
        }
        tokio::time::timeout(
            Duration::from_secs(3),
            self.router
                .clone()
                .oneshot(rewrite_proxy_host(request.body(Body::empty()).unwrap())),
        )
        .await
        .expect("local case normalization must not wait on the network")
        .unwrap()
    }
}

async fn text(response: axum::response::Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

/// A wrapper template value, decoded from its JavaScript string literal (the
/// wrapper escapes `&`, `<` and `>` as `\uXXXX` inside script strings).
fn wrapper_value(html: &str, key: &str) -> String {
    let prefix = format!("{key} = \"");
    let raw = html
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .and_then(|line| line.strip_suffix('"'))
        .unwrap_or_else(|| panic!("missing wrapper value {key}"));
    serde_json::from_str(&format!("\"{raw}\"")).unwrap_or_else(|_| panic!("invalid wrapper string {key}: {raw}"))
}

const NAVIGATE: &[(&str, &str)] = &[
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-dest", "document"),
];

#[tokio::test]
async fn cached_and_display_names_match_without_ascii_case() {
    let fixture = Fixture::new().await;
    for name in ["talk.epix", "Talk.epix", "TALK.EPIX", "tAlK.ePiX"] {
        assert_eq!(
            fixture.state.resolve_name_verified(name).await,
            Some((fixture.address.clone(), true)),
            "cache lookup for {name}"
        );
        assert_eq!(
            fixture.state.canonical_key(name).await,
            fixture.address,
            "{name}"
        );
    }
    std::fs::remove_file(fixture.root.path().join("resolve-cache.json")).unwrap();
    fixture
        .state
        .set_display(&fixture.address, "talk.epix")
        .await;
    assert_eq!(
        fixture.state.canonical_key("TaLk.EpIx").await,
        fixture.address
    );
    fixture
        .state
        .set_display(&fixture.address, "TaLk.EpIx")
        .await;
    assert_eq!(
        fixture.state.canonical_key("talk.epix").await,
        fixture.address,
        "existing display metadata can itself contain uppercase letters"
    );
}

#[tokio::test]
async fn mixed_case_loopback_wrappers_bind_the_address_and_preserve_path_and_query() {
    let fixture = Fixture::new().await;
    for name in ["talk.epix", "Talk.epix", "TALK.EPIX", "tAlK.ePiX"] {
        let response = fixture
            .get(
                "127.0.0.1:42222",
                &format!("/{name}/Docs/Mixed.html?{QUERY}"),
                NAVIGATE,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{name}");
        let html = text(response).await;
        assert_eq!(wrapper_value(&html, "address"), fixture.address, "{name}");
        assert_eq!(wrapper_value(&html, "resolving_host"), "");
        assert_eq!(wrapper_value(&html, "file_inner_path"), "Docs/Mixed.html");
        let iframe = wrapper_value(&html, "iframe_src");
        let (path, query) = iframe.split_once('?').unwrap();
        assert_eq!(
            path.strip_prefix('/').unwrap().split_once('/').unwrap().1,
            "Docs/Mixed.html"
        );
        assert!(
            query.starts_with(&format!("{QUERY}&wrapper_nonce=")),
            "{iframe}"
        );
    }
}

#[tokio::test]
async fn mixed_case_proxy_wrappers_load_the_document_from_the_content_host() {
    let fixture = Fixture::new().await;
    for host in ["talk.epix", "Talk.epix", "TALK.EPIX", "tAlK.ePiX"] {
        let response = fixture
            .get(host, &format!("/Docs/Mixed.html?{QUERY}"), NAVIGATE)
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{host}");
        let html = text(response).await;
        assert_eq!(wrapper_value(&html, "address"), fixture.address, "{host}");
        assert_eq!(wrapper_value(&html, "resolving_host"), "");
        assert_eq!(wrapper_value(&html, "file_inner_path"), "Docs/Mixed.html");
        // The page's own origin is the xite's content host, in lower case;
        // the document path and query keep theirs.
        assert!(
            wrapper_value(&html, "iframe_src")
                .starts_with(&format!("//talk.content.epix/Docs/Mixed.html?{QUERY}&wrapper_nonce=")),
            "{host}: {}",
            wrapper_value(&html, "iframe_src")
        );
    }
}

#[tokio::test]
async fn domain_case_does_not_change_asset_path_case() {
    let fixture = Fixture::new().await;
    for (path, expected) in [
        ("Docs/Mixed.txt", MIXED_BYTES),
        ("docs/lower.txt", LOWER_BYTES),
    ] {
        // Path mode serves the file under the loopback origin.
        let response = fixture
            .get(
                "127.0.0.1:42222",
                &format!("/TaLk.EPIX/{path}?{QUERY}"),
                &[
                    ("referer", "http://127.0.0.1:42222/talk.epix/Docs/Mixed.html"),
                    ("sec-fetch-mode", "same-origin"),
                ],
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(&to_bytes(response.into_body(), 1024).await.unwrap()[..], expected);
        // A chrome host, whatever its case, sends the xite's files to its
        // content host in lower case, with the path case and query intact.
        let response = fixture
            .get(
                "TaLk.EPIX",
                &format!("/{path}?{QUERY}"),
                &[
                    ("referer", "http://tAlK.ePiX/Docs/Mixed.html?Topic=Keep.epix/Mixed"),
                    ("sec-fetch-mode", "same-origin"),
                ],
            )
            .await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT, "{path}");
        assert_eq!(
            response.headers()["location"],
            format!("//talk.content.epix/{path}?{QUERY}")
        );
        // The content host serves it, whatever its case.
        let response = fixture
            .get(
                "TaLk.CONTENT.EPIX",
                &format!("/{path}?{QUERY}"),
                &[
                    ("referer", "http://tAlK.cOnTeNt.ePiX/Docs/Mixed.html?Topic=Keep.epix/Mixed"),
                    ("sec-fetch-mode", "same-origin"),
                ],
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(&to_bytes(response.into_body(), 1024).await.unwrap()[..], expected);
    }
}

#[tokio::test]
async fn same_xite_origin_and_referer_ignore_host_case_without_allowing_foreign_origins() {
    let fixture = Fixture::new().await;
    let uri = "/Docs/Mixed.txt";
    // The page lives on the xite's content host; its own fetches pass in any case.
    let same_referer = "https://tAlK.cOnTeNt.ePiX/Docs/Mixed.html";
    let response = fixture
        .get(
            "TALK.CONTENT.EPIX",
            uri,
            &[("origin", "https://Talk.content.epix"), ("referer", same_referer)],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        &to_bytes(response.into_body(), 1024).await.unwrap()[..],
        MIXED_BYTES
    );
    // The chrome host never serves the file itself: it sends the page's own
    // fetch on to the content host.
    let response = fixture
        .get(
            "TALK.EPIX",
            uri,
            &[("origin", "https://Talk.epix"), ("referer", "https://tAlK.ePiX/Docs/Mixed.html")],
        )
        .await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    for headers in [
        vec![
            ("origin", "https://evil.example"),
            ("referer", same_referer),
        ],
        vec![("referer", "https://Other.EPIX/Docs/Mixed.html")],
        vec![("referer", "https://oThEr.cOnTeNt.EPIX/Docs/Mixed.html")],
    ] {
        assert_eq!(
            fixture.get("TALK.CONTENT.EPIX", uri, &headers).await.status(),
            StatusCode::FORBIDDEN,
            "{headers:?}"
        );
    }
}

#[tokio::test]
async fn mixed_case_cross_xite_redirect_preserves_encoded_path_and_query() {
    let fixture = Fixture::new().await;
    let suffix = "/Docs/a%23b%252Fc.html?Token=AbC%2FZ";
    let response = fixture
        .get("dashboard.epix", &format!("/TaLk.EPIX{suffix}"), NAVIGATE)
        .await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        response.headers()["location"],
        format!("//talk.epix{suffix}")
    );
}

struct UnknownName;

#[async_trait::async_trait]
impl OnDemandResolver for UnknownName {
    async fn ensure(&self, _: &str) -> Result<(), String> {
        Err("fixture name is unregistered".into())
    }
    async fn resolve(&self, _: &str) -> Option<ResolvedHost> {
        None
    }
}

#[tokio::test]
async fn unknown_names_keep_an_empty_wrapper_identity() {
    let fixture = Fixture::new().await;
    fixture.state.set_on_demand(Arc::new(UnknownName)).await;
    for name in [
        "Unknown.epix",
        "UNKNOWN.EPIX",
        "uNkNoWn.EpIx",
        "epix1brand.epix",
        "Epix1Brand.EPIX",
    ] {
        assert_eq!(fixture.state.resolve_name_verified(name).await, None);
        assert_eq!(
            fixture.state.canonical_key(name).await,
            name,
            "an unchanged key is the resolver's unresolved sentinel"
        );
        for (host, uri) in [
            (
                "127.0.0.1:42222",
                format!("/{name}/Docs/Mixed.html?{QUERY}"),
            ),
            (name, format!("/Docs/Mixed.html?{QUERY}")),
        ] {
            let response = fixture.get(host, &uri, NAVIGATE).await;
            assert_eq!(response.status(), StatusCode::OK, "{host}{uri}");
            let html = text(response).await;
            assert_eq!(wrapper_value(&html, "address"), "");
            assert!(wrapper_value(&html, "resolving_host").eq_ignore_ascii_case(name));
            assert!(wrapper_value(&html, "iframe_src").starts_with("about:blank?"));
            assert_eq!(wrapper_value(&html, "file_inner_path"), "Docs/Mixed.html");
        }
    }
}

#[tokio::test]
async fn short_epix1_brand_names_remain_resolvable() {
    let fixture = Fixture::new().await;
    for name in ["epix1shop.epix", "Epix1Shop.EPIX", "EPIX1SHOP.EPIX"] {
        assert_eq!(
            fixture.state.canonical_key(name).await,
            fixture.address,
            "{name}"
        );
        let response = fixture
            .get("127.0.0.1:42222", &format!("/{name}/"), NAVIGATE)
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{name}");
        assert_eq!(
            wrapper_value(&text(response).await, "address"),
            fixture.address
        );
    }
}

#[tokio::test]
async fn valid_address_alias_accepts_suffix_case_without_changing_address_validation() {
    let fixture = Fixture::new().await;
    for label in [
        fixture.address.clone(),
        fixture.address.to_ascii_uppercase(),
    ] {
        assert!(epix_crypt::is_valid_address(&label));
        for suffix in ["epix", "EPIX", "EpIx"] {
            assert_eq!(
                fixture
                    .state
                    .canonical_key(&format!("{label}.{suffix}"))
                    .await,
                fixture.address
            );
        }
    }
}

#[tokio::test]
async fn mixed_case_and_bad_checksum_addresses_cannot_become_resolvable_names() {
    let fixture = Fixture::new().await;
    let mixed = format!("E{}", &fixture.address[1..]);
    assert!(!epix_crypt::is_valid_address(&mixed));
    assert!(epix_crypt::is_valid_address(&mixed.to_ascii_lowercase()));
    let mut typo = fixture.address.clone();
    let last = typo.pop().unwrap();
    typo.push(if last == 'q' { 'p' } else { 'q' });
    assert_eq!(
        epix_core::classify_label(&typo),
        epix_core::LabelClass::AddressShaped
    );
    for name in [
        format!("{mixed}.epix"),
        format!("{mixed}.EPIX"),
        format!("{typo}.epix"),
        format!("{}.EPIX", typo.to_ascii_uppercase()),
    ] {
        // Even a cached name registration must not claim the address typo space.
        fixture.map_name(&name);
        fixture.map_name(&name.to_ascii_lowercase());
        assert_eq!(fixture.state.canonical_key(&name).await, name);
    }
}

#[tokio::test]
async fn invalid_or_mixed_case_address_targets_cannot_become_redirect_origins() {
    let fixture = Fixture::new().await;
    let mixed_address = format!("E{}.EPIX", &fixture.address[1..]);
    for target in [
        "-Talk.EPIX",
        "Talk-.EPIX",
        "nested.Talk.EPIX",
        "Talk%40evil.EPIX",
        &mixed_address,
    ] {
        let response = fixture
            .get(
                "dashboard.epix",
                &format!("/{target}/Docs/Mixed.html?{QUERY}"),
                NAVIGATE,
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{target}");
        assert!(!response.headers().contains_key("location"));
    }
}
#[tokio::test]
async fn legacy_uppercase_cache_keys_and_string_values_remain_usable() {
    let fixture = Fixture::new().await;
    let path = fixture.root.path().join("resolve-cache.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({"TaLk.EPIX": fixture.address})).unwrap(),
    )
    .unwrap();
    for name in ["talk.epix", "TALK.EPIX", "TaLk.EPIX"] {
        assert_eq!(
            fixture.state.resolve_name_verified(name).await,
            Some((fixture.address.clone(), true))
        );
    }
    for key in ["1LegacySource", "1source", "unknown.txt"] {
        assert_eq!(fixture.state.canonical_key(key).await, key);
    }
}

#[tokio::test]
async fn resolve_progress_uses_one_key_for_all_name_cases() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .resolve_status_set("TaLk.EPIX", "resolving", None, None)
        .await;
    fixture.state.resolve_status_attempt("TALK.epix").await;
    fixture
        .state
        .resolve_status_resolved("talk.EPIX", &fixture.address, true)
        .await;
    for name in ["talk.epix", "TALK.EPIX", "TaLk.EPIX"] {
        let status = fixture.state.resolve_status_json(name).await;
        assert_eq!(status["state"], "resolved");
        assert_eq!(status["address"], fixture.address);
        assert_eq!(status["attempts"], 1);
        assert!(fixture.state.resolve_status(name).await.unwrap().verified);
    }
}

#[tokio::test]
async fn websocket_origins_match_host_case_and_keep_foreign_origins_separate() {
    let fixture = Fixture::new().await;
    assert!(fixture.state.is_ws_origin_allowed("talk.epix", "TaLk.EPIX"));
    assert!(!fixture
        .state
        .is_ws_origin_allowed("other.epix", "TaLk.EPIX"));
    fixture.state.allow_ws_origin("TaLk.EPIX:42222");
    assert!(fixture
        .state
        .is_ws_origin_allowed("talk.epix:42222", "127.0.0.1:42222"));
    assert!(!fixture
        .state
        .is_ws_origin_allowed("talk.epix:42223", "127.0.0.1:42222"));
    assert!(!fixture
        .state
        .is_ws_origin_allowed("other.epix:42222", "127.0.0.1:42222"));
}
