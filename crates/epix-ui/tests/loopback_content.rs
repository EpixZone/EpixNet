//! A local xite gets a stable origin without gaining the node wrapper's authority.
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Method, Request, StatusCode},
    response::Response,
};
use epix_ui::{rewrite_proxy_host, AppState, UiServer, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::json;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

const PORT: u16 = 42222;
const NODE: &str = "127.0.0.1:42222";
const A_HTML: &str = "<!doctype html><title>Alpha fixture</title><script src='/app.js'></script>";
const B_HTML: &str = "<!doctype html><title>Beta fixture</title>";

struct Fixture {
    _directory: tempfile::TempDir,
    state: Arc<AppState>,
    router: axum::Router,
    a: String,
    b: String,
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let state = AppState::with_data_dir("loopback-origin-test", directory.path());
        let mut addresses = Vec::new();
        let mut cache = serde_json::Map::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for (domain, html, data) in [
            ("alpha.epix", A_HTML, "alpha-private-fixture"),
            ("beta.epix", B_HTML, "beta-private-fixture"),
        ] {
            let key = epix_crypt::new_seed();
            let address = epix_crypt::privatekey_to_address(&key).unwrap();
            let storage = XiteStorage::new(directory.path().join("data").join(&address));
            let files = [
                ("index.html", html),
                ("app.js", "window.loopbackFixture = true;"),
                ("data.txt", data),
                ("data.json", "{\"fixture\":\"routing\"}"),
                (
                    "fixture.svg",
                    "<svg xmlns='http://www.w3.org/2000/svg' width='1' height='1'/>",
                ),
                ("fixture.pdf", "%PDF-1.0\ntransport fixture\n%%EOF\n"),
                ("docs/a#b%2Fc.html", html),
            ];
            let mut manifest_files = serde_json::Map::new();
            for (path, bytes) in files {
                storage.write(path, bytes.as_bytes()).unwrap();
                manifest_files.insert(
                    path.into(),
                    json!({
                        "size": bytes.len(), "sha512": XiteStorage::hash_bytes(bytes.as_bytes())
                    }),
                );
            }
            let mut content = json!({
                "address": address, "domain": domain, "modified": 1,
                "title": domain, "files": manifest_files, "merged_type": "Fixture"
            });
            epix_content::sign(&mut content, &key).unwrap();
            storage
                .write(
                    "content.json",
                    epix_content::dumps_content(&content).as_bytes(),
                )
                .unwrap();
            state
                .add_xite(
                    &address,
                    XiteEntry {
                        storage,
                        content: Some(content),
                    },
                )
                .await;
            cache.insert(
                domain.into(),
                json!({ "address": address, "resolved_at": now }),
            );
            addresses.push(address);
        }
        assert!(!epix_chain::verify_finality_enabled());
        std::fs::write(
            directory.path().join("resolve-cache.json"),
            json!(cache).to_string(),
        )
        .unwrap();
        state.set_ui_loopback(true).await;
        state.set_ui_port(PORT).await;
        // The content-host boundary must stand even when the optional CORS gate is off.
        state.config_set("ui_check_cors", json!(false)).await;
        std::fs::create_dir(directory.path().join("wallet-ui")).unwrap();
        std::fs::write(
            directory.path().join("wallet-ui/mobile.html"),
            "wallet-private-fixture",
        )
        .unwrap();
        let router = UiServer::new(state.clone()).router();
        Self {
            _directory: directory,
            state,
            router,
            a: addresses.remove(0),
            b: addresses.remove(0),
        }
    }

    fn content_host(&self) -> String {
        format!("epix-{}.localhost:{PORT}", self.a)
    }

    async fn request(&self, host: &str, path: &str, headers: &[(&str, &str)]) -> Response {
        self.request_method(Method::GET, host, path, headers).await
    }

    async fn request_method(
        &self,
        method: Method,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Response {
        let body = if method == Method::POST {
            Body::from(format!("csrf={}", self.state.ui_csrf_token()))
        } else {
            Body::empty()
        };
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", host)
            .header("content-type", "application/x-www-form-urlencoded");
        for (key, value) in headers {
            request = request.header(*key, *value);
        }
        let mut request = request.body(body).unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:49152".parse::<SocketAddr>().unwrap(),
        ));
        self.router
            .clone()
            .oneshot(rewrite_proxy_host(request))
            .await
            .unwrap()
    }

    async fn wrapper(&self, host: &str, path: &str) -> String {
        let mut path = path.to_string();
        for _ in 0..4 {
            let response = self.request(host, &path, NAVIGATE).await;
            if response.status().is_redirection() {
                path = response.headers()["location"].to_str().unwrap().to_string();
                assert!(
                    path.starts_with('/') && !path.starts_with("//"),
                    "local wrapper redirect: {path}"
                );
                continue;
            }
            assert_eq!(response.status(), StatusCode::OK, "{host}{path}");
            return text(response).await;
        }
        panic!("wrapper redirect loop: {host}{path}");
    }

    async fn upload(
        &self,
        host: &str,
        token: &str,
        origin: Option<&str>,
        cookie: Option<&str>,
        body: Vec<u8>,
    ) -> Response {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(format!(
                "/EpixNet-Internal/BigfileUpload?upload_nonce={token}"
            ))
            .header("host", host)
            .header("content-type", "application/octet-stream");
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        let mut request = request.body(Body::from(body)).unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:49152".parse::<SocketAddr>().unwrap(),
        ));
        self.router
            .clone()
            .oneshot(rewrite_proxy_host(request))
            .await
            .unwrap()
    }
}

const NAVIGATE: &[(&str, &str)] = &[
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-dest", "document"),
];
const IFRAME: &[(&str, &str)] = &[("sec-fetch-mode", "navigate"), ("sec-fetch-dest", "iframe")];

async fn text(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

fn wrapper_value(html: &str, key: &str) -> String {
    let prefix = format!("{key} = ");
    let literal = html
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing {key}"));
    serde_json::from_str(literal).unwrap()
}

fn sandbox(html: &str) -> &str {
    html.split("sandbox=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
}

#[tokio::test]
async fn canonical_address_alias_and_name_share_one_content_origin() {
    let fixture = Fixture::new().await;
    let expected = format!("//{}/index.html?", fixture.content_host());
    for reference in [&fixture.a, "alpha.epix", &format!("{}.epix", fixture.a)] {
        let html = fixture.wrapper(NODE, &format!("/{reference}/")).await;
        assert_eq!(wrapper_value(&html, "address"), fixture.a);
        assert!(
            wrapper_value(&html, "iframe_src").starts_with(&expected),
            "{reference}: {}",
            wrapper_value(&html, "iframe_src")
        );
        assert!(sandbox(&html)
            .split_whitespace()
            .any(|token| token == "allow-same-origin"));
        assert!(html.contains("id='inner-iframe'"));
    }
}

#[tokio::test]
async fn content_origin_preserves_the_local_node_port() {
    let fixture = Fixture::new().await;
    fixture.state.set_ui_port(31234).await;
    for host in ["127.0.0.1:31234", "localhost:31234", "[::1]:31234"] {
        let html = fixture.wrapper(host, "/alpha.epix/").await;
        let expected = format!("//epix-{}.localhost:31234/index.html?", fixture.a);
        assert!(
            wrapper_value(&html, "iframe_src").starts_with(&expected),
            "{host}: {}",
            wrapper_value(&html, "iframe_src")
        );
    }
    let response = fixture
        .request(&fixture.content_host(), "/index.html", IFRAME)
        .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a different port must not claim this node's content origin"
    );
}

#[tokio::test]
async fn own_html_and_resources_never_contain_wrapper_secrets() {
    let fixture = Fixture::new().await;
    let host = fixture.content_host();
    let (wrapper_key, ajax_key) = fixture.state.wrapper_keys(&fixture.a).await;
    for (path, expected, headers) in [
        ("/index.html?wrapper_nonce=fixture", A_HTML, IFRAME),
        ("/app.js", "window.loopbackFixture = true;", &[][..]),
        ("/data.txt", "alpha-private-fixture", &[][..]),
        (
            "/docs/a%23b%252Fc.html?wrapper_nonce=fixture",
            A_HTML,
            IFRAME,
        ),
    ] {
        let response = fixture.request(&host, path, headers).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let body = text(response).await;
        assert_eq!(body, expected, "{path}");
        assert!(!body.contains(&wrapper_key) && !body.contains(&ajax_key));
        assert!(!body.contains("id='inner-iframe'"));
    }
}

#[tokio::test]
async fn own_resources_work_with_the_cross_origin_gate_enabled() {
    let fixture = Fixture::new().await;
    fixture.state.config_set("ui_check_cors", json!(true)).await;
    let host = fixture.content_host();
    let origin = format!("http://{host}");
    let referer = format!("{origin}/index.html");
    for headers in [
        vec![
            ("origin", origin.as_str()),
            ("referer", referer.as_str()),
            ("sec-fetch-mode", "cors"),
            ("sec-fetch-dest", "empty"),
        ],
        vec![
            ("referer", referer.as_str()),
            ("sec-fetch-mode", "no-cors"),
            ("sec-fetch-dest", "script"),
        ],
    ] {
        let response = fixture.request(&host, "/app.js", &headers).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(text(response).await, "window.loopbackFixture = true;");
    }
}

#[tokio::test]
async fn content_hosts_refuse_node_routes_even_with_tokens_and_cors_disabled() {
    let fixture = Fixture::new().await;
    let host = fixture.content_host();
    let origin = format!("http://{host}");
    let (wrapper_key, ajax_key) = fixture.state.wrapper_keys(&fixture.a).await;
    let query = format!(
        "?csrf={}&wrapper_key={wrapper_key}&ajax_key={ajax_key}",
        fixture.state.ui_csrf_token()
    );
    let paths = [
        "/Config",
        "/Config/",
        "/Plugins",
        "/Stats",
        "/StatsJson",
        "/Backup",
        "/Backup/Download",
        "/Backup/Upload",
        "/EpixWallet",
        "/EpixWallet/mobile.html",
        "/EpixNet-Internal/Status",
        "/EpixNet-Internal/Websocket",
        "/EpixNet-Internal/Zip",
        "/EpixNet-Internal/Resolve",
        "/EpixNet-Internal/AddonBroker",
        "/EpixNet-Internal/BigfileUpload",
        "/Login",
        "/Logout",
    ];
    for path in paths {
        for method in [Method::GET, Method::POST, Method::OPTIONS] {
            let response = fixture
                .request_method(
                    method.clone(),
                    &host,
                    &format!("{path}{query}"),
                    &[
                        ("origin", &origin),
                        ("sec-fetch-site", "same-origin"),
                        ("sec-fetch-mode", "no-cors"),
                        ("sec-fetch-dest", "image"),
                    ],
                )
                .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
            let body = text(response).await;
            assert!(!body.contains(&wrapper_key) && !body.contains(fixture.state.ui_csrf_token()));
            assert!(!body.contains("wallet-private-fixture"));
        }
    }
    for path in [
        format!("/list/{}/", fixture.a),
        format!("/EpixNet-Internal/Revert/{}/index.html", fixture.a),
    ] {
        let response = fixture.request(&host, &path, NAVIGATE).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }
}

#[tokio::test]
async fn another_xites_bytes_cannot_be_served_under_this_content_origin() {
    let fixture = Fixture::new().await;
    let host = fixture.content_host();
    let (_, other_ajax_key) = fixture.state.wrapper_keys(&fixture.b).await;
    let other = &fixture.b;
    let paths = [
        format!("/{other}/index.html"),
        format!("/{other}/data.txt"),
        "/beta.epix/index.html".into(),
        format!("/{other}.epix/data.txt"),
        format!("/raw/{other}/index.html"),
        format!("/raw/{other}/data.txt"),
        format!("/merged-Fixture/{other}/index.html"),
        format!("/merged-Fixture/{other}/data.txt"),
        format!("/%72aw/{other}/index.html"),
        format!("/%65{}%2findex.html", &other[1..]),
        format!("/../{other}/index.html"),
        format!("/%2e%2e/{other}/index.html"),
        format!("/{}/%2e%2e/{other}/data.txt", fixture.a),
    ];
    for path in paths {
        let path = format!("{path}?ajax_key={other_ajax_key}&wrapper_nonce=fixture");
        let response = fixture
            .request(
                &host,
                &path,
                &[("sec-fetch-mode", "no-cors"), ("sec-fetch-dest", "script")],
            )
            .await;
        assert!(
            response.status().is_client_error(),
            "{path}: {}",
            response.status()
        );
        let body = text(response).await;
        assert!(
            !body.contains("Beta fixture") && !body.contains("beta-private-fixture"),
            "{path}"
        );
        assert!(!body.contains("wrapper_key ="), "{path}");
    }
}

#[tokio::test]
async fn top_level_identity_navigation_returns_to_the_node_wrapper() {
    let fixture = Fixture::new().await;
    let path = format!(
        "/{}/?linkIdentity=fixture&returnTo=/{}/",
        fixture.b, fixture.a
    );
    let response = fixture
        .request(&fixture.content_host(), &path, NAVIGATE)
        .await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        response.headers()["location"],
        format!("http://{NODE}{path}")
    );
    assert!(!text(response).await.contains("wrapper_key ="));

    let path = "/docs/a%23b%252Fc.html?returnTo=%2Falpha.epix%2F&view=a%2Fb";
    let response = fixture
        .request(&fixture.content_host(), path, NAVIGATE)
        .await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        response.headers()["location"],
        format!("http://{NODE}/{}{path}", fixture.a)
    );
}

#[tokio::test]
async fn encoded_navigation_cannot_choose_an_external_redirect_host() {
    let fixture = Fixture::new().await;
    for path in [
        "//evil.example/",
        "/%2f%2fevil.example/",
        "/alpha.epix%2f%2f@evil.example/",
        "/alpha.epix%5c@evil.example/",
        "/%5c%5cevil.example/",
        "/alpha.epix%3f@evil.example/",
    ] {
        let response = fixture
            .request(&fixture.content_host(), path, NAVIGATE)
            .await;
        assert!(!response.status().is_success(), "{path}");
        if response.status().is_redirection() {
            let location = response.headers()["location"].to_str().unwrap();
            let url = reqwest::Url::parse(location).unwrap();
            assert_eq!(url.host_str(), Some("127.0.0.1"), "{path}: {location}");
            assert_eq!(url.port(), Some(PORT), "{path}: {location}");
            assert_eq!(url.scheme(), "http");
        }
    }
}

#[tokio::test]
async fn lan_and_gateway_wrappers_keep_opaque_content() {
    let fixture = Fixture::new().await;
    fixture.state.set_ui_loopback(false).await;
    let response = fixture
        .request(&fixture.content_host(), "/index.html", IFRAME)
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let html = fixture.wrapper(NODE, "/alpha.epix/").await;
    assert!(!wrapper_value(&html, "iframe_src").contains(".localhost"));
    assert!(!sandbox(&html)
        .split_whitespace()
        .any(|token| token == "allow-same-origin"));

    fixture.state.set_ui_loopback(true).await;
    fixture
        .state
        .config_set("ui_host", json!("gateway.example"))
        .await;
    for host in ["192.168.1.2:42222", "gateway.example"] {
        let html = fixture.wrapper(host, "/alpha.epix/").await;
        assert!(
            !wrapper_value(&html, "iframe_src").contains(".localhost"),
            "{host}"
        );
        assert!(
            !sandbox(&html)
                .split_whitespace()
                .any(|token| token == "allow-same-origin"),
            "{host}"
        );
    }
    fixture.state.config_set("ui_restrict", json!(true)).await;
    let response = fixture
        .request(&fixture.content_host(), "/index.html", IFRAME)
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let html = fixture.wrapper(NODE, "/alpha.epix/").await;
    assert!(!wrapper_value(&html, "iframe_src").contains(".localhost"));
    assert!(!sandbox(&html)
        .split_whitespace()
        .any(|token| token == "allow-same-origin"));
}

#[tokio::test]
async fn content_host_names_require_a_complete_valid_canonical_address() {
    let fixture = Fixture::new().await;
    let mut invalid_checksum = fixture.a.clone();
    let final_char = invalid_checksum.pop().unwrap();
    invalid_checksum.push(if final_char == 'q' { 'p' } else { 'q' });
    for host in [
        "anything.localhost".into(),
        "epix-alpha.localhost".into(),
        format!("epix-{invalid_checksum}.localhost"),
        format!("epix-{}.localhost.evil.example", fixture.a),
        format!("extra.epix-{}.localhost", fixture.a),
    ] {
        let response = fixture.request(&host, "/index.html", IFRAME).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{host}");
    }
}

#[tokio::test]
async fn existing_epix_proxy_origins_keep_their_content_host() {
    let fixture = Fixture::new().await;
    let response = fixture.request("alpha.epix", "/", NAVIGATE).await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = text(response).await;
    assert!(wrapper_value(&html, "iframe_src").starts_with("//alpha.content.epix/index.html?"));
    assert!(sandbox(&html)
        .split_whitespace()
        .any(|token| token == "allow-same-origin"));
    let response = fixture
        .request(
            "alpha.content.epix",
            "/index.html?wrapper_nonce=fixture",
            IFRAME,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(text(response).await, A_HTML);
}

#[tokio::test]
async fn authorized_merged_data_keeps_the_mergers_session_and_cannot_become_a_document() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .add_permission(&fixture.a, "Merger:Fixture")
        .await;
    let a_host = fixture.content_host();
    let a_origin = format!("http://{a_host}");
    let b_host = format!("epix-{}.localhost:{PORT}", fixture.b);
    let b_origin = format!("http://{b_host}");
    let path = format!("/merged-Fixture/{}/data.txt", fixture.b);
    let headers = [
        ("origin", a_origin.as_str()),
        ("sec-fetch-mode", "cors"),
        ("sec-fetch-dest", "empty"),
    ];
    let response = fixture.request(&a_host, &path, &headers).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("location").is_none());
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());
    assert_data_response_is_sandboxed(&response);
    assert_eq!(text(response).await, "beta-private-fixture");

    // A document on B cannot acquire A's merger permission by copying its URL.
    for origin in [
        b_origin,
        format!("http://epix-{}.localhost:31234", fixture.a),
        "null".into(),
    ] {
        let response = fixture
            .request(
                &a_host,
                &path,
                &[
                    ("origin", &origin),
                    ("sec-fetch-mode", "cors"),
                    ("sec-fetch-dest", "empty"),
                ],
            )
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{origin}");
        assert!(response
            .headers()
            .get("access-control-allow-origin")
            .is_none());
    }
    let copied = fixture
        .request(&b_host, &format!("/{}{path}", fixture.a), &headers)
        .await;
    assert_eq!(
        copied.status(),
        StatusCode::FORBIDDEN,
        "the merger API belongs to A's host"
    );
    fixture
        .state
        .remove_permission(&fixture.a, "Merger:Fixture")
        .await;
    let response = fixture.request(&a_host, &path, &headers).await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "every read rechecks the grant"
    );
}

fn assert_data_response_is_sandboxed(response: &Response) {
    let policy = response.headers()["content-security-policy"]
        .to_str()
        .unwrap();
    let tokens = policy
        .split(';')
        .find_map(|directive| {
            let mut tokens = directive.split_whitespace();
            (tokens.next() == Some("sandbox")).then(|| tokens.collect::<Vec<_>>())
        })
        .expect("merged data must carry a response-level sandbox, even without browser metadata");
    assert!(!tokens.contains(&"allow-same-origin"));
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()["cache-control"], "no-store");
}

#[tokio::test]
async fn merged_html_without_fetch_metadata_still_has_an_opaque_response_sandbox() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .add_permission(&fixture.a, "Merger:Fixture")
        .await;
    let host = fixture.content_host();
    let path = format!("/merged-Fixture/{}/index.html", fixture.b);
    let response = fixture.request(&host, &path, &[]).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_data_response_is_sandboxed(&response);
    assert_eq!(text(response).await, B_HTML);

    for destination in ["iframe", "frame", "object", "embed"] {
        let response = fixture
            .request(
                &host,
                &path,
                &[
                    ("sec-fetch-mode", "navigate"),
                    ("sec-fetch-dest", destination),
                ],
            )
            .await;
        assert_eq!(
            response.status(),
            StatusCode::TEMPORARY_REDIRECT,
            "{destination}"
        );
        assert_eq!(
            response.headers()["location"],
            format!("http://epix-{}.localhost:{PORT}/index.html", fixture.b)
        );
    }
}

#[tokio::test]
async fn a_cors_grant_allows_scoped_data_reads_without_becoming_transitive() {
    let fixture = Fixture::new().await;
    let a_host = fixture.content_host();
    let a_origin = format!("http://{a_host}");
    let path = format!("/{}/data.txt", fixture.b);
    let headers = [
        ("origin", a_origin.as_str()),
        ("sec-fetch-mode", "cors"),
        ("sec-fetch-dest", "empty"),
    ];
    let denied = fixture.request(&a_host, &path, &headers).await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let permission = format!("Cors:{}", fixture.b);
    fixture.state.add_permission(&fixture.a, &permission).await;
    let response = fixture.request(&a_host, &path, &headers).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_data_response_is_sandboxed(&response);
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());
    assert_eq!(text(response).await, "beta-private-fixture");

    let c = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
    fixture
        .state
        .add_permission(&c, &format!("Cors:{}", fixture.a))
        .await;
    let c_origin = format!("http://epix-{c}.localhost:{PORT}");
    let third_party = fixture
        .request(
            &a_host,
            &path,
            &[
                ("origin", &c_origin),
                ("sec-fetch-mode", "cors"),
                ("sec-fetch-dest", "empty"),
            ],
        )
        .await;
    assert_eq!(third_party.status(), StatusCode::FORBIDDEN);
    assert!(third_party
        .headers()
        .get("access-control-allow-origin")
        .is_none());
    fixture
        .state
        .remove_permission(&fixture.a, &permission)
        .await;
    let denied = fixture.request(&a_host, &path, &headers).await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn merged_html_never_executes_under_the_mergers_content_origin() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .add_permission(&fixture.a, "Merger:Fixture")
        .await;
    let host = fixture.content_host();
    let b_host = format!("epix-{}.localhost:{PORT}", fixture.b);
    for file in ["index.html", "docs/a%23b%252Fc.html"] {
        let path = format!("/merged-Fixture/{}/{file}?wrapper_nonce=fixture", fixture.b);
        let response = fixture.request(&host, &path, IFRAME).await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response.headers()["location"].to_str().unwrap();
        let target = reqwest::Url::parse(location).unwrap();
        assert_eq!(
            target.host_str(),
            Some(format!("epix-{}.localhost", fixture.b).as_str())
        );
        assert_eq!(target.port(), Some(PORT));
        assert_eq!(
            target.path(),
            format!("/{file}"),
            "B-relative assets and literal percent filenames must remain intact"
        );
        assert!(!text(response).await.contains("Beta fixture"));
        let document = fixture
            .request(&b_host, &format!("/{file}?wrapper_nonce=fixture"), IFRAME)
            .await;
        assert_eq!(document.status(), StatusCode::OK);
        assert_eq!(text(document).await, B_HTML);
    }
}

#[tokio::test]
async fn passive_cross_xite_resources_redirect_without_granting_script_reads() {
    let fixture = Fixture::new().await;
    let a_host = fixture.content_host();
    let a_origin = format!("http://{a_host}");
    let b_host = format!("epix-{}.localhost:{PORT}", fixture.b);
    for destination in ["image", "audio", "video", "track", "font"] {
        let response = fixture
            .request(
                &a_host,
                &format!("/{}/data.txt", fixture.b),
                &[
                    ("sec-fetch-mode", "no-cors"),
                    ("sec-fetch-dest", destination),
                ],
            )
            .await;
        assert_eq!(
            response.status(),
            StatusCode::TEMPORARY_REDIRECT,
            "{destination}"
        );
        assert_eq!(
            response.headers()["location"],
            format!("http://{b_host}/data.txt")
        );
        assert!(response
            .headers()
            .get("access-control-allow-origin")
            .is_none());
        assert!(!text(response).await.contains("beta-private-fixture"));
    }
    let opaque = fixture
        .request(
            &b_host,
            "/data.txt",
            &[
                ("origin", &a_origin),
                ("sec-fetch-mode", "no-cors"),
                ("sec-fetch-dest", "image"),
            ],
        )
        .await;
    assert_eq!(opaque.status(), StatusCode::OK);
    assert!(opaque
        .headers()
        .get("access-control-allow-origin")
        .is_none());
    assert_eq!(text(opaque).await, "beta-private-fixture");
    let readable = fixture
        .request(
            &b_host,
            "/data.txt",
            &[
                ("origin", &a_origin),
                ("sec-fetch-mode", "cors"),
                ("sec-fetch-dest", "empty"),
            ],
        )
        .await;
    assert_eq!(readable.status(), StatusCode::FORBIDDEN);
    assert!(readable
        .headers()
        .get("access-control-allow-origin")
        .is_none());
}

#[tokio::test]
async fn a_foreign_referrer_cannot_borrow_another_xites_merger_grant() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .add_permission(&fixture.a, "Merger:Fixture")
        .await;
    let a_host = fixture.content_host();
    let b_host = format!("epix-{}.localhost:{PORT}", fixture.b);
    let path = format!("/{}/merged-Fixture/{}/data.txt", fixture.a, fixture.b);
    for referrer in [
        format!("http://{b_host}/index.html"),
        format!("http://epix-{}.localhost:31234/index.html", fixture.a),
    ] {
        let response = fixture
            .request(
                &a_host,
                &path,
                &[
                    ("referer", &referrer),
                    ("sec-fetch-mode", "no-cors"),
                    ("sec-fetch-dest", "script"),
                ],
            )
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{referrer}");
    }
    let response = fixture
        .request(
            &a_host,
            &path,
            &[
                ("referer", &format!("http://{a_host}/index.html")),
                ("sec-fetch-mode", "no-cors"),
                ("sec-fetch-dest", "script"),
            ],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());
    assert_eq!(text(response).await, "beta-private-fixture");
}

#[tokio::test]
async fn content_origins_cannot_open_node_websockets_even_with_the_wrapper_key() {
    let fixture = Fixture::new().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = UiServer::new(fixture.state.clone());
    let task = tokio::spawn(async move {
        server.serve_on(listener).await.unwrap();
    });
    let (wrapper_key, _) = fixture.state.wrapper_keys(&fixture.a).await;
    let content_host = format!("epix-{}.localhost:{}", fixture.a, address.port());
    let content_origin = format!("http://{content_host}");
    let wrapper = reqwest::Client::new()
        .get(format!("http://{address}/alpha.epix/"))
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "document")
        .send()
        .await
        .unwrap();
    assert_eq!(wrapper.status(), StatusCode::OK);
    let html = wrapper.text().await.unwrap();
    assert!(
        wrapper_value(&html, "iframe_src").starts_with(&format!("//{content_host}/index.html?")),
        "serve_on must synchronize the actual listener port"
    );
    for host in [address.to_string(), content_host] {
        for key in [&wrapper_key, &fixture.a] {
            let request = tokio_tungstenite::tungstenite::http::Request::builder()
                .uri(format!(
                    "ws://{address}/EpixNet-Internal/Websocket?wrapper_key={key}"
                ))
                .header("Host", &host)
                .header("Origin", &content_origin)
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket")
                .header("Sec-WebSocket-Version", "13")
                .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                .body(())
                .unwrap();
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                tokio_tungstenite::connect_async(request),
            )
            .await
            .unwrap();
            match result {
                Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                    assert_eq!(response.status(), StatusCode::FORBIDDEN, "{host}")
                }
                other => {
                    panic!("content-origin WebSocket was not rejected with403: {host}: {other:?}")
                }
            }
        }
    }
    task.abort();
    let _ = task.await;
}

#[cfg(feature = "ui-password")]
#[tokio::test]
async fn password_sessions_unlock_only_xite_files_on_content_hosts() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .config_set("ui_password", json!("fixture-password"))
        .await;
    let host = fixture.content_host();
    let blocked = fixture.request(&host, "/index.html", IFRAME).await;
    assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
    assert!(
        !text(blocked).await.contains("/Login"),
        "the node's login form must not run as xite content"
    );

    let nonce = fixture.state.issue_wrapper_nonce();
    let response = fixture
        .request(&host, &format!("/index.html?wrapper_nonce={nonce}"), IFRAME)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie_header = response.headers()["set-cookie"].to_str().unwrap();
    assert!(cookie_header.contains("HttpOnly"));
    assert!(cookie_header
        .split(';')
        .any(|attribute| attribute.trim() == "Secure"));
    assert!(cookie_header
        .split(';')
        .any(|attribute| attribute.trim() == "SameSite=None"));
    let cookie = cookie_header.split(';').next().unwrap().to_string();
    assert_eq!(text(response).await, A_HTML);
    let resource = fixture
        .request(&host, "/data.txt", &[("cookie", &cookie)])
        .await;
    assert_eq!(resource.status(), StatusCode::OK);
    assert_eq!(text(resource).await, "alpha-private-fixture");

    for path in [
        "/Config",
        "/Login",
        "/EpixWallet/mobile.html",
        "/EpixNet-Internal/Status",
    ] {
        let response = fixture.request(&host, path, &[("cookie", &cookie)]).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }
    let replay = fixture
        .request(&host, &format!("/index.html?wrapper_nonce={nonce}"), IFRAME)
        .await;
    assert_eq!(
        replay.status(),
        StatusCode::FORBIDDEN,
        "the session bootstrap nonce is single use"
    );
}

#[cfg(feature = "ui-password")]
#[tokio::test]
async fn content_like_authority_aliases_never_render_the_node_login_page() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .config_set("ui_password", json!("fixture-password"))
        .await;
    let bare = format!("epix-{}.localhost", fixture.a);
    fixture
        .state
        .config_set("ui_host", json!(format!("{bare}.\n{bare}\nuser@{bare}")))
        .await;
    for host in [
        format!("{bare}.:{PORT}"),
        format!("user@{bare}:{PORT}"),
        format!("{bare}:not-a-port"),
        format!("{bare}:{PORT}:extra"),
        format!("{bare}:31234"),
    ] {
        for path in ["/Login", "/Config", "/index.html"] {
            let response = fixture.request(&host, path, NAVIGATE).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{host}{path}");
            let body = text(response).await;
            assert!(
                !body.contains("/Login") && !body.contains("type=\"password\""),
                "{host}{path}"
            );
        }
    }
}

#[cfg(feature = "ui-password")]
#[tokio::test]
async fn session_bootstrap_nonce_does_not_grant_cross_xite_reads() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .config_set("ui_password", json!("fixture-password"))
        .await;
    // Existing wrapper nonces establish a node login, not a xite identity:
    // AppState stores a global set without an address. A page knowing an
    // outstanding nonce must still satisfy the separate origin/permission gate.
    let nonce = fixture.state.issue_wrapper_nonce();
    let a_host = fixture.content_host();
    let b_origin = format!("http://epix-{}.localhost:{PORT}", fixture.b);
    let (_, ajax_key) = fixture.state.wrapper_keys(&fixture.a).await;
    for path in [
        "/data.txt",
        "/index.html",
        "/Config",
        "/EpixWallet/mobile.html",
    ] {
        let response = fixture
            .request(
                &a_host,
                &format!("{path}?wrapper_nonce={nonce}&ajax_key={ajax_key}"),
                &[
                    ("origin", &b_origin),
                    ("sec-fetch-mode", "cors"),
                    ("sec-fetch-dest", "empty"),
                ],
            )
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        assert!(response
            .headers()
            .get("access-control-allow-origin")
            .is_none());
        assert!(response.headers().get("set-cookie").is_none());
        assert!(!text(response).await.contains("alpha-private-fixture"));
    }
}

#[cfg(feature = "ui-password")]
#[tokio::test]
async fn authenticated_cross_xite_reads_do_not_require_another_hosts_cookie() {
    for merger in [true, false] {
        let fixture = Fixture::new().await;
        fixture
            .state
            .config_set("ui_password", json!("fixture-password"))
            .await;
        let permission = if merger {
            "Merger:Fixture".to_string()
        } else {
            format!("Cors:{}", fixture.b)
        };
        fixture.state.add_permission(&fixture.a, &permission).await;
        let a_host = fixture.content_host();
        let a_origin = format!("http://{a_host}");
        let nonce = fixture.state.issue_wrapper_nonce();
        let login = fixture
            .request(
                &a_host,
                &format!("/index.html?wrapper_nonce={nonce}"),
                IFRAME,
            )
            .await;
        assert_eq!(login.status(), StatusCode::OK);
        let cookie = login.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let path = if merger {
            format!("/merged-Fixture/{}/data.txt", fixture.b)
        } else {
            format!("/{}/data.txt", fixture.b)
        };
        let mut response = fixture
            .request(
                &a_host,
                &path,
                &[
                    ("cookie", &cookie),
                    ("referer", &format!("{a_origin}/index.html")),
                    ("x-requested-with", "XMLHttpRequest"),
                    ("sec-fetch-mode", "cors"),
                    ("sec-fetch-dest", "empty"),
                ],
            )
            .await;
        if response.status().is_redirection() {
            let target =
                reqwest::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
            let host = format!("{}:{}", target.host_str().unwrap(), target.port().unwrap());
            let path = target.path();
            // Browsers do not forward A's host-only session to B. An AJAX header
            // also requires a cookie-less preflight after a cross-origin redirect.
            let preflight = fixture
                .request_method(
                    Method::OPTIONS,
                    &host,
                    path,
                    &[
                        ("origin", &a_origin),
                        ("access-control-request-method", "GET"),
                        ("access-control-request-headers", "x-requested-with"),
                    ],
                )
                .await;
            assert!(
                preflight.status().is_success(),
                "a permitted merger read must not require B's session for preflight: {}",
                preflight.status()
            );
            assert_eq!(preflight.headers()["access-control-allow-origin"], a_origin);
            response = fixture
                .request(
                    &host,
                    path,
                    &[
                        ("origin", &a_origin),
                        ("x-requested-with", "XMLHttpRequest"),
                        ("sec-fetch-mode", "cors"),
                        ("sec-fetch-dest", "empty"),
                    ],
                )
                .await;
            assert_eq!(
                response
                    .headers()
                    .get("access-control-allow-origin")
                    .and_then(|value| value.to_str().ok()),
                Some(a_origin.as_str())
            );
        }
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "an authenticated A page can read its permitted merged data"
        );
        assert_eq!(text(response).await, "beta-private-fixture");
    }
}

#[tokio::test]
async fn upload_tokens_are_bound_to_the_content_host_and_survive_foreign_attempts() {
    let fixture = Fixture::new().await;
    fixture.state.set_owned(&fixture.a, true).await;
    let body = b"EpixNet upload fixture\n";
    let (token, _, _) = fixture
        .state
        .bigfile_upload_init(&fixture.a, "uploads/fixture.bin", body.len() as u64)
        .await
        .unwrap();
    let a_host = fixture.content_host();
    let a_origin = format!("http://{a_host}");
    let b_host = format!("epix-{}.localhost:{PORT}", fixture.b);
    let b_origin = format!("http://{b_host}");
    for (host, origin) in [
        (b_host.as_str(), Some(b_origin.as_str())),
        (a_host.as_str(), Some(b_origin.as_str())),
        (a_host.as_str(), Some("null")),
        (a_host.as_str(), None),
    ] {
        let denied = fixture
            .upload(host, &token, origin, None, body.to_vec())
            .await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN, "{host} {origin:?}");
    }
    let response = fixture
        .upload(&a_host, &token, Some(&a_origin), None, body.to_vec())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let result: serde_json::Value = serde_json::from_str(&text(response).await).unwrap();
    assert_eq!(result["inner_path"], "uploads/fixture.bin");
    assert_eq!(
        std::fs::read(
            fixture
                ._directory
                .path()
                .join("data")
                .join(&fixture.a)
                .join("uploads/fixture.bin")
        )
        .unwrap(),
        body
    );
    let replay = fixture
        .upload(&a_host, &token, Some(&a_origin), None, body.to_vec())
        .await;
    assert_eq!(replay.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn content_uploads_keep_the_existing_body_limit_without_consuming_the_token() {
    let fixture = Fixture::new().await;
    fixture.state.set_owned(&fixture.a, true).await;
    let body = b"bounded upload fixture";
    let (token, _, _) = fixture
        .state
        .bigfile_upload_init(&fixture.a, "uploads/bounded.bin", body.len() as u64)
        .await
        .unwrap();
    let host = fixture.content_host();
    let origin = format!("http://{host}");
    let response = fixture
        .upload(
            &host,
            &token,
            Some(&origin),
            None,
            vec![b'x'; 2 * 1024 * 1024 + 1],
        )
        .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(!fixture
        ._directory
        .path()
        .join("data")
        .join(&fixture.a)
        .join("uploads/bounded.bin")
        .exists());
    let response = fixture
        .upload(&host, &token, Some(&origin), None, body.to_vec())
        .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a refused body must not consume a valid upload token"
    );
}

#[cfg(feature = "ui-password")]
#[tokio::test]
async fn a_valid_upload_token_does_not_bypass_the_node_password() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .config_set("ui_password", json!("fixture-password"))
        .await;
    fixture.state.set_owned(&fixture.a, true).await;
    let body = b"authenticated upload fixture";
    let (token, _, _) = fixture
        .state
        .bigfile_upload_init(&fixture.a, "uploads/authenticated.bin", body.len() as u64)
        .await
        .unwrap();
    let host = fixture.content_host();
    let origin = format!("http://{host}");
    let denied = fixture
        .upload(&host, &token, Some(&origin), None, body.to_vec())
        .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let nonce = fixture.state.issue_wrapper_nonce();
    let login = fixture
        .request(&host, &format!("/index.html?wrapper_nonce={nonce}"), IFRAME)
        .await;
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = login.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let response = fixture
        .upload(&host, &token, Some(&origin), Some(&cookie), body.to_vec())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[cfg(feature = "bittorrent")]
#[tokio::test]
async fn only_authenticated_passive_media_requests_reach_the_stream_handler() {
    let fixture = Fixture::new().await;
    let host = fixture.content_host();
    let origin = format!("http://{host}");
    let referrer = format!("{origin}/index.html");
    // An invalid source is rejected before any peer or network activity.
    let path = "/bt/stream?m=invalid";
    for method in [Method::GET, Method::HEAD] {
        for destination in ["audio", "video"] {
            let response = fixture
                .request_method(
                    method.clone(),
                    &host,
                    path,
                    &[
                        ("origin", &origin),
                        ("sec-fetch-mode", "no-cors"),
                        ("sec-fetch-dest", destination),
                    ],
                )
                .await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{method} {destination}"
            );
            assert_data_response_is_sandboxed(&response);
            if method == Method::HEAD {
                assert!(text(response).await.is_empty());
            }
        }
    }
    let response = fixture
        .request(
            &host,
            path,
            &[("referer", &referrer), ("sec-fetch-dest", "video")],
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    for (path, destination, origin) in [
        (path, "empty", origin.as_str()),
        (path, "script", origin.as_str()),
        (path, "video", "null"),
        ("/bt/other?m=invalid", "video", origin.as_str()),
        ("/bt/stream/?m=invalid", "video", origin.as_str()),
    ] {
        let response = fixture
            .request(
                &host,
                path,
                &[("origin", origin), ("sec-fetch-dest", destination)],
            )
            .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{path} {destination}"
        );
    }
    let untraceable = fixture
        .request(&host, path, &[("sec-fetch-dest", "video")])
        .await;
    assert_eq!(untraceable.status(), StatusCode::FORBIDDEN);
    let write = fixture
        .request_method(
            Method::POST,
            &host,
            path,
            &[("origin", &origin), ("sec-fetch-dest", "video")],
        )
        .await;
    assert_eq!(write.status(), StatusCode::FORBIDDEN);
    #[cfg(feature = "ui-password")]
    {
        fixture
            .state
            .config_set("ui_password", json!("fixture-password"))
            .await;
        let denied = fixture
            .request(
                &host,
                path,
                &[("origin", &origin), ("sec-fetch-dest", "video")],
            )
            .await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let nonce = fixture.state.issue_wrapper_nonce();
        let login = fixture
            .request(&host, &format!("/index.html?wrapper_nonce={nonce}"), IFRAME)
            .await;
        let cookie = login.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let response = fixture
            .request(
                &host,
                path,
                &[
                    ("origin", &origin),
                    ("cookie", &cookie),
                    ("sec-fetch-dest", "video"),
                ],
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn no_referrer_foreign_scripts_cannot_borrow_the_hosts_read_grant() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .add_permission(&fixture.a, "Merger:Fixture")
        .await;
    fixture
        .state
        .add_permission(&fixture.a, &format!("Cors:{}", fixture.b))
        .await;
    let host = fixture.content_host();
    for path in [
        format!("/merged-Fixture/{}/app.js", fixture.b),
        format!("/{}/app.js", fixture.b),
    ] {
        for site in ["cross-site", "same-site"] {
            for destination in ["script", "empty"] {
                let response = fixture
                    .request(
                        &host,
                        &path,
                        &[
                            ("sec-fetch-site", site),
                            ("sec-fetch-mode", "no-cors"),
                            ("sec-fetch-dest", destination),
                        ],
                    )
                    .await;
                assert_eq!(
                    response.status(),
                    StatusCode::FORBIDDEN,
                    "{site} {destination} {path}"
                );
            }
        }
        let own = fixture
            .request(
                &host,
                &path,
                &[
                    ("sec-fetch-site", "same-origin"),
                    ("sec-fetch-mode", "cors"),
                    ("sec-fetch-dest", "empty"),
                ],
            )
            .await;
        assert_eq!(
            own.status(),
            StatusCode::OK,
            "A's no-referrer fetch still works"
        );
        assert_data_response_is_sandboxed(&own);
        assert_eq!(text(own).await, "window.loopbackFixture = true;");
    }
}

#[tokio::test]
async fn headerless_scripts_are_protected_from_cross_origin_classic_inclusion() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .add_permission(&fixture.a, "Merger:Fixture")
        .await;
    let host = fixture.content_host();
    for path in [
        "/app.js".into(),
        format!("/merged-Fixture/{}/app.js", fixture.b),
    ] {
        let response = fixture.request(&host, &path, &[]).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["cross-origin-resource-policy"],
            "same-origin",
            "{path}"
        );
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(text(response).await, "window.loopbackFixture = true;");
    }
}

#[tokio::test]
async fn dashboard_node_links_redirect_only_top_level_get_navigation() {
    let fixture = Fixture::new().await;
    let host = fixture.content_host();
    for path in ["/Config", "/Plugins", "/Stats", "/Backup"] {
        let response = fixture.request(&host, path, NAVIGATE).await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT, "{path}");
        assert_eq!(
            response.headers()["location"],
            format!("http://{NODE}{path}")
        );
        for headers in [
            IFRAME,
            &[][..],
            &[("sec-fetch-mode", "cors"), ("sec-fetch-dest", "empty")][..],
        ] {
            let response = fixture.request(&host, path, headers).await;
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{path} {headers:?}"
            );
        }
        let response = fixture
            .request_method(Method::POST, &host, path, NAVIGATE)
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path} POST");
    }
    let response = fixture
        .request(&host, "/EpixNet-Internal/Status", NAVIGATE)
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let mut request = Request::builder()
        .uri("/Config")
        .header("host", &host)
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "document")
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo("[::1]:49152".parse::<SocketAddr>().unwrap()));
    let response = fixture
        .router
        .clone()
        .oneshot(rewrite_proxy_host(request))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        response.headers()["location"],
        format!("http://[::1]:{PORT}/Config")
    );
}

#[cfg(feature = "ui-password")]
#[tokio::test]
async fn authenticated_passive_and_frame_redirects_bootstrap_the_target_session() {
    for (file, destination, mode, expected) in [
        ("data.txt", "image", "no-cors", "beta-private-fixture"),
        ("index.html", "iframe", "navigate", B_HTML),
    ] {
        let fixture = Fixture::new().await;
        fixture
            .state
            .config_set("ui_password", json!("fixture-password"))
            .await;
        let a_host = fixture.content_host();
        let nonce = fixture.state.issue_wrapper_nonce();
        let login = fixture
            .request(
                &a_host,
                &format!("/index.html?wrapper_nonce={nonce}"),
                IFRAME,
            )
            .await;
        assert_eq!(login.status(), StatusCode::OK);
        let a_cookie = login.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let path = format!(
            "/{}/{file}?first=a%2Fb&wrapper_nonce=oldNonce&last=%2525",
            fixture.b
        );
        let source = format!("http://{a_host}/index.html");
        let headers = [
            ("referer", source.as_str()),
            ("sec-fetch-mode", mode),
            ("sec-fetch-dest", destination),
        ];
        let unauthenticated = fixture.request(&a_host, &path, &headers).await;
        assert_eq!(unauthenticated.status(), StatusCode::FORBIDDEN);
        assert!(unauthenticated.headers().get("location").is_none());
        let mut authenticated = headers.to_vec();
        authenticated.push(("cookie", &a_cookie));
        let redirect = fixture.request(&a_host, &path, &authenticated).await;
        assert_eq!(redirect.status(), StatusCode::TEMPORARY_REDIRECT);
        let target = reqwest::Url::parse(redirect.headers()["location"].to_str().unwrap()).unwrap();
        assert_eq!(redirect.headers()["cache-control"], "no-store");
        let query = target
            .query()
            .expect("the redirect bootstraps B without a shared cookie");
        assert!(
            query.starts_with("first=a%2Fb&"),
            "raw query preserved: {query}"
        );
        assert!(query.contains("last=%2525"), "raw query preserved: {query}");
        assert!(!query.contains("oldNonce"));
        let nonces: Vec<_> = target
            .query_pairs()
            .filter(|(key, _)| key == "wrapper_nonce")
            .collect();
        assert_eq!(
            nonces.len(),
            1,
            "replace the stale nonce instead of duplicating it"
        );
        assert!(!nonces[0].1.is_empty());
        let b_host = format!("{}:{}", target.host_str().unwrap(), target.port().unwrap());
        let uri = format!(
            "{}{}",
            target.path(),
            target
                .query()
                .map(|query| format!("?{query}"))
                .unwrap_or_default()
        );
        // B has never been visited, so this request carries no B cookie and
        // cannot reuse A's host-only cookie. Destination is a transport fixture;
        // actual browser cookie acceptance is checked separately in Firefox.
        let response = fixture.request(&b_host, &uri, &headers).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "authenticated A -> unvisited B {destination}"
        );
        let b_cookie_header = response.headers()["set-cookie"].to_str().unwrap();
        assert!(b_cookie_header.contains("HttpOnly"));
        assert!(b_cookie_header
            .split(';')
            .any(|attribute| attribute.trim() == "Secure"));
        assert!(b_cookie_header
            .split(';')
            .any(|attribute| attribute.trim() == "SameSite=None"));
        assert!(!b_cookie_header.to_ascii_lowercase().contains("domain="));
        let b_cookie = b_cookie_header.split(';').next().unwrap().to_string();
        assert_ne!(a_cookie, b_cookie);
        assert_eq!(text(response).await, expected);
        let own_resource = fixture
            .request(
                &b_host,
                "/app.js",
                &[
                    ("cookie", &b_cookie),
                    ("referer", &format!("http://{b_host}/index.html")),
                    ("sec-fetch-mode", "no-cors"),
                    ("sec-fetch-dest", "script"),
                ],
            )
            .await;
        assert_eq!(own_resource.status(), StatusCode::OK);
        let replay = fixture.request(&b_host, &uri, &headers).await;
        assert_eq!(replay.status(), StatusCode::FORBIDDEN);
    }
}

#[cfg(feature = "ui-password")]
#[tokio::test]
async fn top_navigation_reaches_the_node_without_a_partitioned_content_cookie() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .config_set("ui_password", json!("fixture-password"))
        .await;
    let host = fixture.content_host();
    let nonce = fixture.state.issue_wrapper_nonce();
    assert!(fixture.state.consume_wrapper_nonce(&nonce));
    let return_path = format!(
        "/{}/index.html?returnTo=%2F{}%2F&wrapper_nonce={nonce}&Topic=fixture%2Ftopic",
        fixture.b, fixture.a
    );
    let return_target = format!(
        "/{}/index.html?returnTo=%2F{}%2F&Topic=fixture%2Ftopic",
        fixture.b, fixture.a
    );
    let mut paths: Vec<_> = [
        format!("wrapper_nonce={nonce}"),
        format!("wrapper%5Fnonce={nonce}"),
        format!("%77rapper_nonce={nonce}"),
        "wrapper_nonce".into(),
        format!("wrapper_nonce=old&%77rapper_nonce={nonce}"),
    ]
    .into_iter()
    .map(|pair| {
        (
            format!(
                "/{}/index.html?returnTo=%2F{}%2F&{pair}&Topic=fixture%2Ftopic",
                fixture.b, fixture.a
            ),
            return_target.clone(),
        )
    })
    .collect();
    paths.extend(
        ["/Config", "/Plugins", "/Stats", "/Backup"]
            .into_iter()
            .map(|path| (path.to_string(), path.to_string())),
    );
    let login = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/Login")
                .header("host", NODE)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("password=fixture-password"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let node_cookie = login.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    for (peer, node) in [
        ("127.0.0.1:49152", NODE.to_string()),
        ("[::1]:49152", format!("[::1]:{PORT}")),
    ] {
        for (path, target) in &paths {
            // A browser may partition the iframe's session under the node's
            // top-level site. Its top-level navigation then has no content
            // cookie, but it must still reach the node's own login gate.
            let mut request = Request::builder()
                .uri(path.as_str())
                .header("host", &host)
                .header("sec-fetch-mode", "navigate")
                .header("sec-fetch-dest", "document")
                .body(Body::empty())
                .unwrap();
            request
                .extensions_mut()
                .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
            let response = fixture
                .router
                .clone()
                .oneshot(rewrite_proxy_host(request))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::TEMPORARY_REDIRECT,
                "{peer} {path}"
            );
            assert_eq!(
                response.headers()["location"],
                format!("http://{node}{target}")
            );
            assert!(response.headers().get("set-cookie").is_none());
            let body = text(response).await;
            assert!(!body.contains("private-fixture") && !body.contains("type=\"password\""));

            let destination = fixture.request(&node, target, NAVIGATE).await;
            assert_eq!(destination.status(), StatusCode::OK);
            assert!(destination.headers().get("set-cookie").is_none());
            let body = text(destination).await;
            assert!(body.contains("<form action=\"/Login\""));
            assert!(!body.contains("wrapper_key =") && !body.contains("private-fixture"));
            if target == &return_target {
                let mut authenticated = NAVIGATE.to_vec();
                authenticated.push(("cookie", &node_cookie));
                let mut destination_path = target.clone();
                let mut html = None;
                for _ in 0..4 {
                    let destination = fixture
                        .request(&node, &destination_path, &authenticated)
                        .await;
                    if destination.status().is_redirection() {
                        destination_path =
                            destination.headers()["location"].to_str().unwrap().into();
                        assert!(
                            destination_path.starts_with('/')
                                && !destination_path.starts_with("//")
                        );
                        continue;
                    }
                    assert_eq!(destination.status(), StatusCode::OK);
                    html = Some(text(destination).await);
                    break;
                }
                let html = html.expect("authenticated node wrapper redirects must terminate");
                assert_eq!(wrapper_value(&html, "address"), fixture.b);
                assert!(wrapper_value(&html, "iframe_src").contains("Topic=fixture%2Ftopic"));
            }
        }
    }
    for path in [
        "/index.html",
        "/data.txt",
        "/Config",
        "/EpixNet-Internal/Status",
    ] {
        for headers in [IFRAME, &[][..], &[("sec-fetch-mode", "cors")][..]] {
            let response = fixture.request(&host, path, headers).await;
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{path} {headers:?}"
            );
            assert!(response.headers().get("location").is_none());
            assert!(response.headers().get("set-cookie").is_none());
        }
    }
    let post = fixture
        .request_method(Method::POST, &host, &return_path, NAVIGATE)
        .await;
    assert_eq!(post.status(), StatusCode::FORBIDDEN);
    assert!(post.headers().get("location").is_none());
}

#[tokio::test]
async fn raw_xite_files_never_execute_on_the_loopback_node_origin() {
    let fixture = Fixture::new().await;
    let valid_query = format!("?wrapper_nonce={}", fixture.state.issue_wrapper_nonce());
    for file in [
        "index.html",
        "app.js",
        "data.txt",
        "data.json",
        "fixture.svg",
        "fixture.pdf",
        "content.json",
    ] {
        for (headers, query) in [
            (IFRAME, ""),
            (&[][..], ""),
            (IFRAME, "?wrapper_nonce=invalid"),
            (&[][..], "?wrapper_nonce=invalid"),
            (NAVIGATE, "?wrapper_nonce=invalid"),
            (NAVIGATE, "?%77rapper_nonce=invalid"),
            (IFRAME, valid_query.as_str()),
            (NAVIGATE, valid_query.as_str()),
        ] {
            let response = fixture
                .request(NODE, &format!("/{}/{file}{query}", fixture.a), headers)
                .await;
            assert_eq!(
                response.status(),
                StatusCode::TEMPORARY_REDIRECT,
                "{file}{query} {headers:?}"
            );
            let location = response.headers()["location"].to_str().unwrap();
            let target = reqwest::Url::parse(&format!("http://{NODE}"))
                .unwrap()
                .join(location)
                .unwrap();
            assert_eq!(
                target.host_str().unwrap(),
                format!("epix-{}.localhost", fixture.a)
            );
            assert_eq!(target.port(), Some(PORT));
            assert_eq!(target.path(), format!("/{file}"));
            let body = text(response).await;
            assert!(!body.contains("Alpha fixture") && !body.contains("window.loopbackFixture"));
            if file != "index.html" {
                let uri = format!(
                    "{}{}",
                    target.path(),
                    target
                        .query()
                        .map(|query| format!("?{query}"))
                        .unwrap_or_default()
                );
                let content = fixture
                    .request(&fixture.content_host(), &uri, NAVIGATE)
                    .await;
                assert_eq!(
                    content.status(),
                    StatusCode::OK,
                    "raw top-level {file} must not redirect back to node"
                );
                assert!(content.headers().get("location").is_none());
                if file.ends_with(".svg") || file.ends_with(".pdf") {
                    assert_eq!(content.headers()["content-disposition"], "attachment");
                }
                let bytes = to_bytes(content.into_body(), 1 << 20).await.unwrap();
                let original = std::fs::read(
                    fixture
                        ._directory
                        .path()
                        .join("data")
                        .join(&fixture.a)
                        .join(file),
                )
                .unwrap();
                assert_eq!(bytes.as_ref(), original);
            }
        }
    }
    let html = fixture
        .wrapper(NODE, &format!("/{}/index.html", fixture.a))
        .await;
    assert_eq!(wrapper_value(&html, "address"), fixture.a);
    assert!(
        wrapper_value(&html, "iframe_src").starts_with(&format!("//{}/", fixture.content_host()))
    );
}

#[cfg(feature = "ui-password")]
#[tokio::test]
async fn raw_node_redirect_preserves_password_admission_and_content_bootstrap() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .config_set("ui_password", json!("fixture-password"))
        .await;
    let login = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/Login")
                .header("host", NODE)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("password=fixture-password"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let cookie = login.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    for (file, metadata) in [
        ("index.html", IFRAME),
        ("data.json", NAVIGATE),
        ("fixture.svg", NAVIGATE),
        ("fixture.pdf", NAVIGATE),
    ] {
        let mut path = format!(
            "/{}/{file}?wrapper_nonce=invalid&Topic=fixture%2Ftopic",
            fixture.a
        );
        if metadata == NAVIGATE {
            let direct = fixture
                .request(
                    &fixture.content_host(),
                    &format!("/{file}?wrapper_nonce=invalid&Topic=fixture%2Ftopic"),
                    NAVIGATE,
                )
                .await;
            assert_eq!(direct.status(), StatusCode::TEMPORARY_REDIRECT);
            let node_target =
                reqwest::Url::parse(direct.headers()["location"].to_str().unwrap()).unwrap();
            assert_eq!(node_target.host_str(), Some("127.0.0.1"));
            assert_eq!(node_target.port(), Some(PORT));
            assert!(!node_target.query().unwrap().contains("wrapper_nonce"));
            path = format!("{}?{}", node_target.path(), node_target.query().unwrap());
        }
        let denied = fixture.request(NODE, &path, metadata).await;
        assert_eq!(denied.status(), StatusCode::OK);
        assert!(text(denied).await.contains("<form action=\"/Login\""));
        let mut headers = metadata.to_vec();
        headers.push(("cookie", &cookie));
        let response = fixture.request(NODE, &path, &headers).await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let target = reqwest::Url::parse(&format!("http://{NODE}"))
            .unwrap()
            .join(response.headers()["location"].to_str().unwrap())
            .unwrap();
        assert_eq!(
            target.host_str().unwrap(),
            format!("epix-{}.localhost", fixture.a)
        );
        assert_eq!(target.port(), Some(PORT));
        assert!(target.query().unwrap().contains("Topic=fixture%2Ftopic"));
        assert!(!target.query().unwrap().contains("invalid"));
        let target_path = format!("{}?{}", target.path(), target.query().unwrap());
        let content = fixture
            .request(&fixture.content_host(), &target_path, metadata)
            .await;
        assert_eq!(content.status(), StatusCode::OK, "{file}");
        assert!(content.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("SameSite=None; Secure; HttpOnly"));
        assert!(content.headers().get("location").is_none());
        let bytes = to_bytes(content.into_body(), 1 << 20).await.unwrap();
        let original = std::fs::read(
            fixture
                ._directory
                .path()
                .join("data")
                .join(&fixture.a)
                .join(file),
        )
        .unwrap();
        assert_eq!(bytes.as_ref(), original);
        let replay = fixture
            .request(&fixture.content_host(), &target_path, metadata)
            .await;
        if metadata == NAVIGATE {
            assert_eq!(replay.status(), StatusCode::TEMPORARY_REDIRECT);
            let target =
                reqwest::Url::parse(replay.headers()["location"].to_str().unwrap()).unwrap();
            assert_eq!(target.host_str(), Some("127.0.0.1"));
            assert!(!target.query().unwrap().contains("wrapper_nonce"));
            let destination = fixture
                .request(
                    NODE,
                    &format!("{}?{}", target.path(), target.query().unwrap()),
                    NAVIGATE,
                )
                .await;
            assert!(text(destination).await.contains("<form action=\"/Login\""));
        } else {
            assert_eq!(replay.status(), StatusCode::FORBIDDEN);
        }
    }
}
