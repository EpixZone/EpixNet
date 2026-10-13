//! Canonical wrapper redirects preserve the browser's encoded document URL.
use axum::{body::Body, http::Request};
use epix_ui::{rewrite_proxy_host, AppState, UiServer, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

async fn fixture() -> (tempfile::TempDir, axum::Router, String) {
    fixture_with_title("Verified xite").await
}

async fn fixture_with_title(title: &str) -> (tempfile::TempDir, axum::Router, String) {
    let directory = tempfile::tempdir().unwrap();
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let storage = XiteStorage::new(directory.path().join("data").join(&address));
    let index = b"<!doctype html><title>Verified xite</title>";
    let mut content = json!({
        "address": address, "domain": "talk.epix", "modified": 1, "title": title,
        "files": { "index.html": {
            "size": index.len(), "sha512": XiteStorage::hash_bytes(index)
        } }
    });
    epix_content::sign(&mut content, &key).unwrap();
    storage.write("index.html", index).unwrap();
    storage
        .write(
            "content.json",
            epix_content::dumps_content(&content).as_bytes(),
        )
        .unwrap();
    // This isolated integration-test process uses the default finality-off
    // policy; a current resolver cache entry is authoritative under that policy.
    assert!(!epix_chain::verify_finality_enabled());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    tokio::fs::write(
        directory.path().join("resolve-cache.json"),
        json!({ "talk.epix": { "address": address, "resolved_at": now } }).to_string(),
    )
    .await
    .unwrap();
    let state = AppState::with_data_dir("canonical-path-test", directory.path());
    state
        .add_xite(
            &address,
            XiteEntry {
                storage,
                content: Some(content),
            },
        )
        .await;
    (directory, UiServer::new(state).router(), address)
}

async fn wrapper_document(router: &axum::Router, uri: &str) -> (String, String) {
    let request = Request::builder()
        .uri(uri)
        .header("host", "127.0.0.1:42222")
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "document")
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), 200);
    let csp = response.headers()["content-security-policy"].to_str().unwrap().to_string();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (csp, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn publisher_title_cannot_inject_a_nonce_authorized_wrapper_script() {
    let title = "</title><script nonce=\"{script_nonce}\">window.evxWrapperFixture=true</script><title>";
    let (_directory, router, _address) = fixture_with_title(title).await;
    let (csp, body) = wrapper_document(&router, "/talk.epix/").await;
    let nonce = csp.split("script-src 'nonce-").nth(1).unwrap().split('\'').next().unwrap();
    assert!(!body.contains(&format!("<script nonce=\"{nonce}\">window.evxWrapperFixture=true</script>")),
        "publisher HTML received the wrapper's valid CSP nonce");
    assert!(body.contains("&lt;/title&gt;&lt;script nonce=&quot;{script_nonce}&quot;&gt;"),
        "publisher titles must remain literal text");
}

#[tokio::test]
async fn publisher_text_cannot_expand_wrapper_secrets() {
    let title = "Fixture {wrapper_key} {ajax_key} {script_nonce}";
    let (_directory, router, _address) = fixture_with_title(title).await;
    let (_, body) = wrapper_document(&router, "/talk.epix/").await;
    assert!(body.contains(&format!("<title>{title} - EpixNet</title>")),
        "template placeholders inside publisher text must never expand");
}

#[tokio::test]
async fn document_path_cannot_break_out_of_the_wrapper_script_string() {
    let (_directory, router, _address) = fixture().await;
    let (_, body) = wrapper_document(&router,
        "/talk.epix/docs/%22%3Bwindow.evxPathFixture%3Dtrue%3B%2F%2F.html").await;
    let literal = body.lines().find_map(|line| line.strip_prefix("file_inner_path = ")).unwrap();
    let decoded: String = serde_json::from_str(literal)
        .expect("the decoded path must remain one complete JavaScript string, not executable statements");
    assert_eq!(decoded, "docs/\";window.evxPathFixture=true;//.html");
}

async fn redirect(router: &axum::Router, host: &str, uri: &str) -> String {
    let request = Request::builder()
        .uri(uri)
        .header("host", host)
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "document")
        .body(Body::empty())
        .unwrap();
    let response = router
        .clone()
        .oneshot(rewrite_proxy_host(request))
        .await
        .unwrap();
    assert_eq!(response.status(), 307, "{host}{uri}");
    response.headers()["location"].to_str().unwrap().to_string()
}

#[tokio::test]
async fn consent_wrapper_refuses_framing_in_path_and_host_modes() {
    let (_directory, router, _address) = fixture().await;
    for (host, uri) in [("127.0.0.1:42222", "/talk.epix/"), ("talk.epix", "/")] {
        let request = Request::builder()
            .uri(uri)
            .header("host", host)
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-dest", "iframe")
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(rewrite_proxy_host(request)).await.unwrap();
        assert_eq!(response.status(), 200, "{host}{uri}");
        let csp = response.headers()["content-security-policy"].to_str().unwrap();
        assert!(csp.split(';').any(|directive| directive.trim() == "frame-ancestors 'none'"),
            "the real wrapper response allows framing on {host}: {csp}");
        assert_eq!(response.headers().get("x-frame-options").and_then(|value| value.to_str().ok()),
            Some("DENY"), "legacy framing protection on {host}");
    }
}

#[tokio::test]
async fn verified_host_redirect_preserves_encoded_path_and_query() {
    let (_directory, router, address) = fixture().await;
    let path = "/docs/a%23b%252Fc.html?view=a%2Fb";
    assert_eq!(
        redirect(&router, &format!("{address}.epix"), path).await,
        format!("//talk.epix{path}")
    );
}

#[tokio::test]
async fn verified_loopback_redirect_preserves_encoded_path_and_query() {
    let (_directory, router, address) = fixture().await;
    let path = "/docs/a%23b%252Fc.html?view=a%2Fb";
    assert_eq!(
        redirect(&router, "127.0.0.1:42222", &format!("/{address}{path}")).await,
        format!("/talk.epix{path}")
    );
}

#[tokio::test]
async fn explicit_index_filenames_are_not_rewritten_as_directories() {
    let (_directory, router, address) = fixture().await;
    for path in [
        "/index.html?keep=1",
        "/myindex.html?keep=1",
        "/docs/index.html?keep=1",
        "/docs/?keep=1",
    ] {
        assert_eq!(
            redirect(&router, &format!("{address}.epix"), path).await,
            format!("//talk.epix{path}")
        );
    }
}

#[tokio::test]
async fn cross_xite_origin_normalization_preserves_the_encoded_document_path() {
    let (_directory, router, address) = fixture().await;
    for path in ["/docs/a%23b%252Fc.html?view=a%2Fb", "/myindex.html?keep=1"] {
        assert_eq!(
            redirect(&router, "dashboard.epix", &format!("/{address}{path}")).await,
            format!("//{address}.epix{path}")
        );
    }
}

async fn rejects_external_target(target: &str) {
    let (_directory, router, _address) = fixture().await;
    let request = Request::builder()
        .uri(format!("/{target}/docs/"))
        .header("host", "dashboard.epix")
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "document")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(rewrite_proxy_host(request)).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "untrusted path segment must not become an origin: {:?}",
        response.headers().get("location")
    );
    assert!(!response.headers().contains_key("location"));
}

#[tokio::test]
async fn cross_xite_normalization_rejects_userinfo_in_an_address_shaped_path() {
    rejects_external_target("epix12345678901234567890@evil.example").await;
}

#[tokio::test]
async fn cross_xite_normalization_rejects_encoded_userinfo() {
    rejects_external_target("epix12345678901234567890%40evil.example").await;
}

#[tokio::test]
async fn cross_xite_normalization_rejects_encoded_host_delimiters() {
    for target in [
        "evil.example%23.epix",
        "evil.example%2Fignored.epix",
        "evil.example%5Cignored.epix",
    ] {
        rejects_external_target(target).await;
    }
}

#[tokio::test]
async fn cross_xite_normalization_accepts_valid_names_and_address_aliases() {
    let (_directory, router, address) = fixture().await;
    for target in [
        "talk.epix".to_string(),
        "safe-name.epix".to_string(),
        format!("{address}.epix"),
    ] {
        assert_eq!(
            redirect(
                &router,
                "dashboard.epix",
                &format!("/{target}/docs/?keep=1")
            )
            .await,
            format!("//{target}/docs/?keep=1")
        );
    }
    assert_eq!(
        redirect(&router, "dashboard.epix", "/Talk.epix/docs/").await,
        "//talk.epix/docs/"
    );
}

#[tokio::test]
async fn cross_xite_normalization_requires_an_exact_valid_hostname() {
    for target in [
        "%20talk.epix",
        "talk%20.epix",
        "-talk.epix",
        "talk-.epix",
        "nested.talk.epix",
    ] {
        rejects_external_target(target).await;
    }
}

async fn loopback_request(
    router: &axum::Router,
    uri: &str,
    mode: &str,
    destination: Option<&str>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .uri(uri)
        .header("host", "127.0.0.1:42222")
        .header("sec-fetch-mode", mode)
        .header("referer", "http://127.0.0.1:42222/talk.epix/index.html");
    if let Some(destination) = destination {
        request = request.header("sec-fetch-dest", destination);
    }
    router.clone().oneshot(request.body(Body::empty()).unwrap()).await.unwrap()
}

#[tokio::test]
async fn loopback_relative_xite_links_leave_the_source_xite() {
    let (_directory, router, source) = fixture().await;
    let address = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
    for destination in [Some("document"), Some("iframe"), None] {
        let mut suffixes = vec!["/", "", "/docs/a%23b%252Fc/?view=a%2Fb"];
        if destination == Some("document") {
            suffixes.push("/docs/a%23b%252Fc.html?view=a%2Fb");
        }
        for (target, expected) in [
            (format!("{address}.epix"), format!("{address}.epix")),
            (address.clone(), format!("{address}.epix")),
            ("Blocktone.epix".to_string(), "blocktone.epix".to_string()),
        ] {
            for suffix in &suffixes {
                let uri = format!("/{source}/{target}{suffix}");
                let response = loopback_request(&router, &uri, "navigate", destination).await;
                assert_eq!(response.status(), 307, "{uri} ({destination:?})");
                let suffix = if suffix.is_empty() { "/" } else { *suffix };
                assert_eq!(response.headers()["location"], format!("/{expected}{suffix}"));
            }
        }
    }
}

#[tokio::test]
async fn loopback_relative_xite_links_do_not_retarget_files_or_ordinary_directories() {
    let (directory, router, address) = fixture().await;
    let storage = XiteStorage::new(directory.path().join("data").join(&address));
    storage.write("blocktone.epix/page.html", b"local file").unwrap();
    for (uri, mode, destination) in [
        ("/talk.epix/blocktone.epix/page.html", "same-origin", Some("empty")),
        ("/talk.epix/blocktone.epix/page.html", "navigate", Some("iframe")),
        ("/talk.epix/blocktone.epix/page.html?wrapper_nonce=fixture", "navigate", Some("document")),
    ] {
        let response = loopback_request(&router, uri, mode, destination).await;
        assert_eq!(response.status(), 200, "{uri}");
        assert!(!response.headers().contains_key("location"));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"local file");
    }
    // These destinations would otherwise qualify for cross-xite navigation.
    for (mode, destination) in [("same-origin", "document"), ("navigate", "empty")] {
        let response = loopback_request(
            &router, "/talk.epix/blocktone.epix/", mode, Some(destination),
        ).await;
        assert_eq!(response.status(), 200);
        assert!(!response.headers().contains_key("location"));
    }
    for directory in [
        "docs", "nested/blocktone.epix", "bad%40host.epix", "nested.talk.epix",
        "talk.epix%2Fother", "bad%23host.epix", "bad%5Chost.epix",
    ] {
        let uri = format!("/talk.epix/{directory}/");
        let response = loopback_request(&router, &uri, "navigate", Some("iframe")).await;
        assert_eq!(response.status(), 200, "{uri}");
        assert!(!response.headers().contains_key("location"), "{uri}");
    }
}
