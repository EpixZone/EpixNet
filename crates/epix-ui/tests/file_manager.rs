//! File-manager routes reached from both transparent xite origins and mobile URLs.

use epix_ui::state::{AppState, XiteEntry};
use epix_ui::{rewrite_proxy_host, UiServer};
use epix_xite::XiteStorage;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

const ADDRESS: &str = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";

async fn fixture() -> (tempfile::TempDir, Arc<AppState>, axum::Router) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("xite");
    tokio::fs::create_dir_all(root.join("docs#draft's/nested"))
        .await
        .unwrap();
    for name in [
        "part#one.txt",
        "part%2Ftwo.txt",
        "writer's file.txt",
        "café.txt",
    ] {
        tokio::fs::write(root.join(name), name.as_bytes())
            .await
            .unwrap();
    }
    tokio::fs::write(root.join("docs#draft's/nested/readme.txt"), b"nested file")
        .await
        .unwrap();
    tokio::fs::write(root.join("quote' onclick='fixture.txt"), b"quoted name")
        .await
        .unwrap();
    tokio::fs::create_dir(directory.path().join("private"))
        .await
        .unwrap();
    tokio::fs::write(
        directory.path().join("private/private-marker.txt"),
        b"outside xite",
    )
    .await
    .unwrap();
    let state = AppState::new("file-manager-test");
    state
        .add_xite(
            ADDRESS,
            XiteEntry {
                storage: XiteStorage::new(&root),
                content: Some(json!({ "address": ADDRESS })),
            },
        )
        .await;
    state.set_display(ADDRESS, "dashboard.epix").await;
    (directory, state.clone(), UiServer::new(state).router())
}

async fn request(router: &axum::Router, host: &str, uri: &str) -> (u16, String) {
    let request = axum::extract::Request::builder()
        .uri(uri)
        .header("host", host)
        .header("sec-fetch-mode", "navigate")
        .header("referer", format!("http://{host}/list/{ADDRESS}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router
        .clone()
        .oneshot(rewrite_proxy_host(request))
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn lists_current_xite_on_named_address_alias_and_loopback_origins() {
    let (_directory, _state, router) = fixture().await;
    for host in [
        "dashboard.epix",
        &format!("{ADDRESS}.epix"),
        "127.0.0.1:42222",
    ] {
        for reference in [ADDRESS, "dashboard.epix", &format!("{ADDRESS}.epix")] {
            let (status, html) = request(&router, host, &format!("/list/{reference}")).await;
            assert_eq!(status, 200, "host={host}, reference={reference}: {html}");
            assert!(
                html.contains("part#one.txt"),
                "listing contains the current xite's files"
            );
        }
    }
}

#[tokio::test]
async fn file_links_preserve_reserved_characters_and_round_trip_to_the_file() {
    let (_directory, _state, router) = fixture().await;
    for host in ["dashboard.epix", "127.0.0.1:42222"] {
        let (_, html) = request(&router, host, &format!("/list/{ADDRESS}")).await;
        for (name, encoded) in [
            ("part#one.txt", "part%23one.txt"),
            ("part%2Ftwo.txt", "part%252Ftwo.txt"),
            ("writer's file.txt", "writer%27s%20file.txt"),
            ("café.txt", "caf%C3%A9.txt"),
        ] {
            let link = format!("/{ADDRESS}/{encoded}");
            assert!(
                html.contains(&format!("href='{link}'")),
                "missing encoded link for {name}"
            );
            let (status, bytes) = request(&router, host, &link).await;
            assert_eq!(status, 200, "file link for {name}: {bytes}");
            assert_eq!(bytes, name);
        }
    }
}

#[tokio::test]
async fn directory_and_parent_links_preserve_reserved_characters() {
    let (_directory, _state, router) = fixture().await;
    for host in ["dashboard.epix", "127.0.0.1:42222"] {
        let (_, root) = request(&router, host, &format!("/list/{ADDRESS}")).await;
        let directory = format!("/list/{ADDRESS}/docs%23draft%27s");
        assert!(
            root.contains(&format!("href='{directory}'")),
            "directory link must be encoded"
        );
        let (status, html) = request(&router, host, &directory).await;
        assert_eq!(status, 200);
        let nested = format!("{directory}/nested");
        assert!(html.contains(&format!("href='{nested}'")));
        let (status, html) = request(&router, host, &nested).await;
        assert_eq!(status, 200);
        assert!(
            html.matches(&format!("href='{directory}'")).count() >= 2,
            "both parent navigation and breadcrumbs use encoded paths"
        );
    }
}

#[tokio::test]
async fn quoted_filenames_cannot_add_html_attributes() {
    let (_directory, _state, router) = fixture().await;
    let (_, html) = request(&router, "dashboard.epix", &format!("/list/{ADDRESS}")).await;
    let injected = html
        .split("<a ")
        .filter_map(|part| part.split_once('>'))
        .any(|(attributes, _)| attributes.contains(" onclick='"));
    assert!(!injected, "a filename created an HTML event attribute");
    assert!(html.contains("quote%27%20onclick%3D%27fixture.txt"));
}

#[tokio::test]
async fn file_manager_rejects_parent_directory_traversal() {
    let (_directory, _state, router) = fixture().await;
    for inner in [
        "../private",
        "%2e%2e/private",
        "docs%23draft%27s/../../private",
    ] {
        let (status, html) = request(
            &router,
            "dashboard.epix",
            &format!("/list/{ADDRESS}/{inner}"),
        )
        .await;
        assert_eq!(
            status,
            404,
            "directory traversal {inner}, leaked marker={}",
            html.contains("private-marker.txt")
        );
        assert!(!html.contains("private-marker.txt"));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn file_manager_rejects_a_directory_symlink_outside_the_xite() {
    let (directory, _state, router) = fixture().await;
    tokio::fs::symlink(
        directory.path().join("private"),
        directory.path().join("xite/escape"),
    )
    .await
    .unwrap();
    let (status, html) = request(
        &router,
        "dashboard.epix",
        &format!("/list/{ADDRESS}/escape"),
    )
    .await;
    assert_eq!(
        status,
        404,
        "directory symlink leaked marker={}",
        html.contains("private-marker.txt")
    );
    assert!(!html.contains("private-marker.txt"));
}

#[tokio::test]
async fn recursive_file_list_rejects_parent_directory_traversal() {
    let (_directory, state, _router) = fixture().await;
    for inner in ["../private", "docs#draft's/../../private"] {
        assert!(
            state.walk_files(ADDRESS, inner).await.is_none(),
            "recursive listing escaped through {inner}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn recursive_file_list_rejects_a_directory_symlink_outside_the_xite() {
    let (directory, state, _router) = fixture().await;
    tokio::fs::symlink(
        directory.path().join("private"),
        directory.path().join("xite/escape"),
    )
    .await
    .unwrap();
    assert!(
        state.walk_files(ADDRESS, "escape").await.is_none(),
        "recursive listing followed an external directory symlink"
    );
}

#[tokio::test]
async fn recursive_file_list_keeps_paths_relative_to_the_requested_directory() {
    let (_directory, state, _router) = fixture().await;
    assert_eq!(
        state.walk_files(ADDRESS, "docs#draft's").await.unwrap(),
        vec!["nested/readme.txt"]
    );
}

#[cfg(unix)]
#[tokio::test]
async fn an_operator_relocated_xite_root_remains_browsable() {
    let (directory, _state, _router) = fixture().await;
    let relocated = directory.path().join("relocated");
    tokio::fs::symlink(directory.path().join("xite"), &relocated)
        .await
        .unwrap();
    let state = AppState::new("relocated-file-manager-test");
    state
        .add_xite(
            ADDRESS,
            XiteEntry {
                storage: XiteStorage::new(relocated),
                content: Some(json!({ "address": ADDRESS })),
            },
        )
        .await;
    let entries = state.list_dir(ADDRESS, "").await.unwrap();
    assert!(entries.iter().any(|entry| entry["name"] == "part#one.txt"));
    assert_eq!(
        state.walk_files(ADDRESS, "docs#draft's").await.unwrap(),
        vec!["nested/readme.txt"]
    );
}
