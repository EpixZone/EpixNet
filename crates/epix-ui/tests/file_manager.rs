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

// ---------------------------------------------------------------------------
// The inert EVX inspection panel (`/list/<xite>/?evx=1`).
// ---------------------------------------------------------------------------

const ENTRY: &[u8] = b"\0asm\x01\0\0\0presence";
const LIB: &[u8] = b"\0asm\x01\0\0\0lib";

/// The baseline declaration of `crates/evx-declaration`'s tests: one program
/// with a dependency, a capability set and explicit limits, and one interval
/// job.
fn baseline_evx() -> serde_json::Value {
    json!({
        "version": 1,
        "programs": {
            "presence": {
                "runtime_profile": "wasm-core-v1",
                "entry": "evx/presence.wasm",
                "dependencies": ["evx/lib.wasm"],
                "allow_run_once": true,
                "capabilities": [{ "api": "workspace.read" }, { "api": "workspace.write" }],
                "limits": { "memory_bytes": 2_097_152, "fuel": 500_000 }
            }
        },
        "jobs": {
            "presence-every-30m": {
                "program": "presence",
                "schedule": { "type": "interval", "seconds": 1800, "anchor": "unix_epoch", "missed": "skip" },
                "max_concurrency": 1
            }
        }
    })
}

fn manifest_entry(bytes: &[u8]) -> serde_json::Value {
    json!({ "size": bytes.len(), "sha512": XiteStorage::hash_bytes(bytes) })
}

/// A xite whose root content.json carries `evx`, with the two program files
/// on disk. Signed by a fresh owner key when `signed`, else stored as an
/// unsigned local copy under the fixed test address. Returns the served
/// address and the root as loaded.
async fn evx_fixture(
    signed: bool,
    evx: serde_json::Value,
) -> (tempfile::TempDir, Arc<AppState>, axum::Router, String, serde_json::Value) {
    evx_fixture_edited(signed, evx, |_| {}).await
}

/// The stored content.json of an `evx_fixture` xite, as bytes.
fn stored_root(directory: &tempfile::TempDir) -> Vec<u8> {
    std::fs::read(directory.path().join("xite/content.json")).unwrap()
}

/// `evx_fixture` with `edit` applied to the root before it is signed, so a
/// test can shape the manifest (move a file to `files_optional`, change a
/// declared size) and still get a validly signed document.
async fn evx_fixture_edited(
    signed: bool,
    evx: serde_json::Value,
    edit: impl FnOnce(&mut serde_json::Value),
) -> (tempfile::TempDir, Arc<AppState>, axum::Router, String, serde_json::Value) {
    let directory = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(directory.path().join("xite"));
    let index = b"<html>presence</html>";
    storage.write("index.html", index).unwrap();
    storage.write("evx/presence.wasm", ENTRY).unwrap();
    storage.write("evx/lib.wasm", LIB).unwrap();
    let (address, key) = if signed {
        let key = epix_crypt::new_seed();
        (epix_crypt::privatekey_to_address(&key).unwrap(), Some(key))
    } else {
        (ADDRESS.to_string(), None)
    };
    let mut root = json!({
        "address": address,
        "title": "Presence",
        "modified": 1_700_000_000.0_f64,
        "files": {
            "index.html": manifest_entry(index),
            "evx/presence.wasm": manifest_entry(ENTRY),
            "evx/lib.wasm": manifest_entry(LIB),
        },
        "evx": evx
    });
    edit(&mut root);
    if let Some(key) = key {
        epix_content::sign(&mut root, &key).unwrap();
    }
    storage
        .write("content.json", epix_content::dumps_content(&root).as_bytes())
        .unwrap();
    let state = AppState::new("evx-file-manager-test");
    state
        .add_xite(&address, XiteEntry { storage, content: Some(root.clone()) })
        .await;
    let router = UiServer::new(state.clone()).router();
    (directory, state, router, address, root)
}

#[tokio::test]
async fn evx_panel_renders_the_signed_declaration_with_digest_hashes_and_statuses() {
    let (_directory, _state, router, address, root) = evx_fixture(true, baseline_evx()).await;
    let host = "127.0.0.1:42222";
    let (status, html) = request(&router, host, &format!("/list/{address}?evx=1")).await;
    assert_eq!(status, 200, "{html}");
    assert!(html.contains("id='evx-panel'"), "panel present: {html}");
    for label in ["Integrity verified", "EVX profile valid", "EVX enabled for this xite"] {
        assert!(html.contains(&format!("<dt>{label}</dt>")), "status row {label}: {html}");
    }
    assert!(html.contains("<dd class='ok'>verified</dd>"), "signed and complete: {html}");
    assert!(html.contains("<dd class='ok'>valid</dd>"), "declaration valid: {html}");
    assert!(
        html.contains("<dd class='bad'>no: no grant is stored for this xite</dd>"),
        "no grant source installed: {html}"
    );
    let digest = evx_declaration::declaration_digest(&root).unwrap();
    assert!(html.contains(&format!("<code>{digest}</code>")), "digest: {html}");
    for (path, bytes) in [("evx/presence.wasm", ENTRY), ("evx/lib.wasm", LIB)] {
        assert!(html.contains(&XiteStorage::hash_bytes(bytes)), "sha512 of {path}");
        assert!(
            html.contains(&format!("<a href='/raw/{address}/{path}' download>{path}</a>")),
            "download link for {path} on the raw route: {html}"
        );
        assert!(html.contains(&format!("<td>{} B</td>", bytes.len())), "size of {path}");
    }
    assert!(html.contains(&format!("<p>{} B in all.</p>", ENTRY.len() + LIB.len())));
    for expected in [
        "<code>workspace.read</code>, <code>workspace.write</code>",
        "<code>memory_bytes=2097152</code>",
        "<code>fuel=500000</code>",
        "<dt>Run once</dt><dd>requested</dd>",
        "<code>presence-every-30m</code>",
        "every 1800 s from unix_epoch, missed: skip",
    ] {
        assert!(html.contains(expected), "missing {expected:?}: {html}");
    }
    // The plain listing offers the panel; the panel does not offer itself.
    let (_, listing) = request(&router, host, &format!("/list/{address}")).await;
    let link = format!("href='/list/{address}?evx=1'");
    assert!(listing.contains(&link), "listing links to the panel: {listing}");
    assert!(!listing.contains("id='evx-panel'"));
    assert!(!html.contains(&link));
}

#[tokio::test]
async fn evx_panel_reports_an_unsigned_content_json() {
    let (_directory, _state, router, address, _) = evx_fixture(false, baseline_evx()).await;
    let (status, html) = request(&router, "dashboard.epix", &format!("/list/{address}?evx=1")).await;
    assert_eq!(status, 200, "{html}");
    assert!(
        html.contains("<dt>Integrity verified</dt><dd class='bad'>unsigned: "),
        "unsigned status: {html}"
    );
    assert!(!html.contains("<dd class='ok'>verified</dd>"));
    // The declaration itself still parses and shows: the status is what
    // tells the reader not to trust it yet.
    assert!(html.contains("<dd class='ok'>valid</dd>"), "{html}");
    assert!(html.contains(&XiteStorage::hash_bytes(ENTRY)));
}

#[tokio::test]
async fn evx_panel_lists_unsupported_items_with_their_reasons() {
    let mut evx = baseline_evx();
    evx["programs"]["native"] = json!({
        "runtime_profile": "native-v9",
        "entry": "bin/native",
        "capabilities": []
    });
    evx["streams"] = json!({ "presence": { "retention": "forever" } });
    let (_directory, _state, router, address, _) = evx_fixture(true, evx).await;
    let (status, html) = request(&router, "127.0.0.1:42222", &format!("/list/{address}?evx=1")).await;
    assert_eq!(status, 200, "{html}");
    assert!(
        html.contains("<dd class='warn'>valid, with 2 unsupported items</dd>"),
        "profile status counts the items: {html}"
    );
    for expected in [
        "<code>programs.native</code>: <span class='reason'>runtime profile &quot;native-v9&quot; not supported</span>",
        "<code>streams.presence</code>: <span class='reason'>retained streams not supported</span>",
        "<h4><code>native</code></h4><p class='reason'>Unsupported:</p><ul class='reason'><li>runtime profile &quot;native-v9&quot; not supported</li></ul>",
    ] {
        assert!(html.contains(expected), "missing {expected:?}: {html}");
    }
    // The usable program is unaffected.
    assert!(html.contains("<h4><code>presence</code></h4><table>"), "{html}");
    assert!(!html.contains("bin/native' download"), "an unsupported program is never linked");
}

#[tokio::test]
async fn evx_panel_escapes_a_hostile_program_id_and_entry_path() {
    // A hostile entry path passes the parser (it is a valid relative path) and
    // reaches the programs table; a hostile id fails it and reaches the page
    // through the parser's message. Both must come out inert.
    let hostile_entry = "evx/<img src=x onerror='alert(1)'>.wasm";
    let mut evx = baseline_evx();
    evx["programs"]["presence"]["entry"] = json!(hostile_entry);
    let (_directory, _state, router, address, _) = evx_fixture(true, evx).await;
    let (_, html) = request(&router, "127.0.0.1:42222", &format!("/list/{address}?evx=1")).await;
    assert!(!html.contains("<img"), "entry path became markup: {html}");
    assert!(!html.contains("onerror='alert"), "entry path became an attribute: {html}");
    assert!(
        html.contains("&lt;img src=x onerror=&#x27;alert(1)&#x27;&gt;.wasm"),
        "entry path shown escaped: {html}"
    );

    let hostile_id = "<svg onload='alert(1)'>";
    let mut evx = baseline_evx();
    evx["programs"][hostile_id] = evx["programs"]["presence"].clone();
    let (_directory, _state, router, address, _) = evx_fixture(true, evx).await;
    let (_, html) = request(&router, "127.0.0.1:42222", &format!("/list/{address}?evx=1")).await;
    assert!(html.contains("<dd class='bad'>malformed: "), "a bad id fails the section: {html}");
    assert!(!html.contains("<svg"), "program id became markup: {html}");
    assert!(html.contains("&lt;svg onload=&#x27;alert(1)&#x27;&gt;"), "id shown escaped: {html}");
}

#[tokio::test]
async fn evx_panel_is_absent_for_a_xite_without_an_evx_section() {
    let (_directory, _state, router) = fixture().await;
    let (status, html) = request(&router, "dashboard.epix", &format!("/list/{ADDRESS}?evx=1")).await;
    assert_eq!(status, 200);
    assert!(!html.contains("evx-panel"), "no panel without a declaration: {html}");
    assert!(!html.contains("EVX declaration"), "no link either: {html}");
    assert!(html.contains("part#one.txt"), "the listing is unchanged");
}

#[tokio::test]
async fn evx_panel_reads_the_grant_through_the_installed_source() {
    let (_directory, state, router, address, _) = evx_fixture(true, baseline_evx()).await;
    let expected = address.clone();
    state.set_evx_grant_summary_source(Box::new(move |xite| {
        (xite == expected).then(|| grant_record(true))
    }));
    let (_, html) = request(&router, "127.0.0.1:42222", &format!("/list/{address}?evx=1")).await;
    assert!(
        html.contains("<dt>EVX enabled for this xite</dt><dd class='ok'>yes</dd>"),
        "{html}"
    );
    assert!(html.contains("<h3>Stored grant</h3>"), "{html}");
    for expected in [
        "<dt>Enabled</dt><dd>yes</dd>",
        "<dt>Authority generation</dt><dd>7</dd>",
        "<dt>Expires</dt><dd>at unix time 1800000000</dd>",
    ] {
        assert!(html.contains(expected), "grant status fact {expected:?}: {html}");
    }
    assert_no_grant_record(&html);
}

/// A stored grant as the service's reader would render it: the status facts
/// the view may show next to the record fields it must not (the operator's
/// device label, the consent history, the capability and profile sets).
fn grant_record(enabled: bool) -> serde_json::Value {
    json!({
        "xite": "whatever",
        "publisher": "epix1publisher",
        "enabled": enabled,
        "generation": 7,
        "limits_generation": 3,
        "expires_unix": 1_800_000_000_u64,
        "created_unix": 1_700_000_000_u64,
        "label": "<b>brad's laptop</b>",
        "capabilities": ["workspace.read", "workspace.write"],
        "runtime_profiles": ["wasm-core-v1"],
        "limits": { "memory_bytes": 2_097_152, "fuel": 500_000 },
        "allow_run_once": true,
        "allow_background": false
    })
}

/// None of the record's fields reach the page, raw or escaped.
fn assert_no_grant_record(html: &str) {
    for leaked in [
        "brad",
        "laptop",
        "&lt;b&gt;",
        "<b>",
        "epix1publisher",
        "1700000000",
        "created_unix",
        "allow_background",
        "runtime_profiles",
        "limits_generation",
        "evx-grant'>{",
        "\"enabled\"",
    ] {
        assert!(!html.contains(leaked), "grant record field {leaked:?} reached the page: {html}");
    }
}

#[tokio::test]
async fn evx_panel_reports_a_disabled_grant_without_printing_it() {
    let (_directory, state, router, address, _) = evx_fixture(true, baseline_evx()).await;
    let expected = address.clone();
    state.set_evx_grant_summary_source(Box::new(move |xite| {
        (xite == expected).then(|| grant_record(false))
    }));
    let (_, html) = request(&router, "127.0.0.1:42222", &format!("/list/{address}?evx=1")).await;
    assert!(
        html.contains("<dt>EVX enabled for this xite</dt><dd class='bad'>no: the stored grant is disabled</dd>"),
        "{html}"
    );
    assert!(html.contains("<h3>Stored grant</h3>"), "{html}");
    assert!(html.contains("<dt>Enabled</dt><dd>no</dd>"), "{html}");
    assert!(!html.contains("<dd class='ok'>yes</dd>"), "{html}");
    assert_no_grant_record(&html);
}

#[tokio::test]
async fn evx_panel_on_a_restricted_gateway_says_nothing_about_the_grant() {
    let (_directory, state, router, address, _) = evx_fixture(true, baseline_evx()).await;
    let expected = address.clone();
    state.set_evx_grant_summary_source(Box::new(move |xite| {
        (xite == expected).then(|| grant_record(true))
    }));
    state.config_set("ui_restrict", json!(true)).await;
    let (status, html) = request(&router, "127.0.0.1:42222", &format!("/list/{address}?evx=1")).await;
    assert_eq!(status, 200, "{html}");
    // The panel still inspects the declaration...
    assert!(html.contains("id='evx-panel'"), "{html}");
    assert!(html.contains("<dd class='ok'>verified</dd>"), "{html}");
    assert!(html.contains(&XiteStorage::hash_bytes(ENTRY)), "{html}");
    // ...but carries no grant row, no grant section and no grant field.
    for absent in ["EVX enabled for this xite", "Stored grant", "grant", "Authority generation", "Expires"] {
        assert!(!html.contains(absent), "restricted gateway mentions the grant ({absent:?}): {html}");
    }
    assert_no_grant_record(&html);
    // Lifting the restriction brings the status back, so the gate is the
    // restriction and not a missing source.
    state.config_set("ui_restrict", json!(false)).await;
    let (_, html) = request(&router, "127.0.0.1:42222", &format!("/list/{address}?evx=1")).await;
    assert!(html.contains("<dt>EVX enabled for this xite</dt><dd class='ok'>yes</dd>"), "{html}");
}

#[tokio::test]
async fn evx_panel_reports_a_declared_file_missing_on_disk_as_incomplete() {
    let (directory, _state, router, address, _) = evx_fixture(true, baseline_evx()).await;
    std::fs::remove_file(directory.path().join("xite/evx/lib.wasm")).unwrap();
    let (status, html) = request(&router, "127.0.0.1:42222", &format!("/list/{address}?evx=1")).await;
    assert_eq!(status, 200, "{html}");
    assert!(
        html.contains("<dt>Integrity verified</dt><dd class='bad'>incomplete: a declared file is missing on this node</dd>"),
        "incomplete status: {html}"
    );
    assert!(!html.contains("<dd class='ok'>verified</dd>"), "{html}");
    // The declaration and its manifest pins are still shown: the signed
    // manifest says what the missing file must be.
    assert!(html.contains("<dd class='ok'>valid</dd>"), "{html}");
    assert!(html.contains(&XiteStorage::hash_bytes(LIB)), "{html}");
}

#[tokio::test]
async fn evx_panel_does_not_link_a_program_whose_closure_cannot_bind_to_the_manifest() {
    // An entry or dependency listed only in files_optional is not part of
    // what every node downloads, so the manifest does not pin it.
    let (_directory, _state, router, address, _) =
        evx_fixture_edited(true, baseline_evx(), |root| {
            let pinned = root["files"].as_object_mut().unwrap().remove("evx/lib.wasm").unwrap();
            root["files_optional"] = json!({ "evx/lib.wasm": pinned });
        })
        .await;
    let (status, html) = request(&router, "127.0.0.1:42222", &format!("/list/{address}?evx=1")).await;
    assert_eq!(status, 200, "{html}");
    assert!(html.contains("<p class='reason'>Cannot bind to the manifest: "), "{html}");
    assert!(html.contains("<li>entry <code>evx/presence.wasm</code></li>"), "{html}");
    assert!(html.contains("<li>dependency <code>evx/lib.wasm</code></li>"), "{html}");
    assert!(!html.contains(" download>"), "an unbound closure is never linked: {html}");
    assert!(!html.contains(&format!("/raw/{address}/evx/")), "no href to an unbound file: {html}");
    assert!(!html.contains("<th>sha512</th>"), "no pinned table: {html}");
    // The statuses are unaffected: the document is signed, complete and valid.
    assert!(html.contains("<dd class='ok'>verified</dd>"), "{html}");
    assert!(html.contains("<dd class='ok'>valid</dd>"), "{html}");

    // A declared size over evx_activation::MAX_ARTIFACT (1 MiB) fails the
    // bind the same way.
    let (_directory, _state, router, address, _) =
        evx_fixture_edited(true, baseline_evx(), |root| {
            root["files"]["evx/lib.wasm"]["size"] = json!(1_048_576 + 1);
        })
        .await;
    let (_, html) = request(&router, "127.0.0.1:42222", &format!("/list/{address}?evx=1")).await;
    assert!(html.contains("<p class='reason'>Cannot bind to the manifest: "), "{html}");
    assert!(html.contains("exceeds 1048576 bytes"), "the bound is the activation loader's: {html}");
    assert!(!html.contains(" download>"), "an oversized closure is never linked: {html}");
    assert!(!html.contains(&format!("/raw/{address}/evx/")), "{html}");
}

#[tokio::test]
async fn evx_panel_reports_a_content_json_with_duplicate_keys_as_malformed_without_a_digest() {
    let (directory, _state, router, address, root) = evx_fixture(true, baseline_evx()).await;
    // Publisher signs the benign baseline, then publishes bytes carrying a
    // decoy `evx` first and the signed section last. A last-wins decoder
    // (serde_json, hence AppState::content) sees the signed section and the
    // signature verifies on it; a first-wins reader sees the decoy.
    let mut decoy = baseline_evx();
    decoy["programs"]["presence"]["entry"] = json!("evx/decoy.wasm");
    let signed = serde_json::to_string(&root).unwrap();
    let bytes = format!("{{\"evx\": {decoy}, {}", &signed[1..]).into_bytes();
    let collapsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        epix_content::verify_signer(&collapsed, &address),
        "the decoy document verifies once the duplicate has collapsed"
    );
    assert_eq!(collapsed["evx"], root["evx"]);
    XiteStorage::new(directory.path().join("xite")).write("content.json", &bytes).unwrap();
    assert_eq!(stored_root(&directory), bytes);

    let (status, html) = request(&router, "127.0.0.1:42222", &format!("/list/{address}?evx=1")).await;
    assert_eq!(status, 200, "{html}");
    assert!(html.contains("id='evx-panel'"), "the panel explains the malformed section: {html}");
    assert!(
        html.contains("<dt>EVX profile valid</dt><dd class='bad'>malformed: "),
        "duplicate keys are malformed: {html}"
    );
    assert!(html.contains("duplicate keys"), "the reason names duplicate keys: {html}");
    assert!(!html.contains("<dd class='ok'>valid</dd>"), "{html}");
    assert!(!html.contains("<dd class='ok'>verified</dd>"), "{html}");
    assert!(
        html.contains("<dt>Integrity verified</dt><dd class='bad'>unverifiable: "),
        "no signature verdict on a document that does not decode strictly: {html}"
    );
    assert!(!html.contains("evx-digest"), "no digest row: {html}");
    let digest = evx_declaration::declaration_digest(&collapsed).unwrap();
    assert!(!html.contains(&digest), "the collapsed section's digest is not shown: {html}");
    assert!(!html.contains(" download>"), "nothing is bound or linked: {html}");
    assert!(!html.contains("evx/decoy.wasm"), "nor is the decoy shown as a program: {html}");
}

/// A GET with `Sec-Fetch-Dest: document`: what a middle-click, a new tab or a
/// typed URL sends, where the anchor's `download` hint does not apply.
async fn document_navigation(
    router: &axum::Router,
    host: &str,
    uri: &str,
) -> (u16, axum::http::HeaderMap, String) {
    let request = axum::extract::Request::builder()
        .uri(uri)
        .header("host", host)
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "document")
        .header("referer", format!("http://{host}/list/{ADDRESS}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router
        .clone()
        .oneshot(rewrite_proxy_host(request))
        .await
        .unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, headers, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn evx_panel_program_links_never_navigate_into_the_wrapper() {
    let mut evx = baseline_evx();
    evx["programs"]["presence"]["entry"] = json!("index.html");
    let (_directory, _state, router, address, _) = evx_fixture(true, evx).await;
    let (_, html) = request(&router, "127.0.0.1:42222", &format!("/list/{address}?evx=1")).await;
    let href = format!("/raw/{address}/index.html");
    assert!(
        html.contains(&format!("<a href='{href}' download>index.html</a>")),
        "the entry is linked on the raw route: {html}"
    );
    assert!(
        !panel(&html).contains(&format!("href='/{address}/index.html'")),
        "the panel never links the wrapper route: {html}"
    );

    // The same URL as a top-level document navigation on the wrapper route
    // renders the wrapper; that is what the panel must never link.
    let (status, _, body) = document_navigation(&router, "127.0.0.1:42222", &format!("/{address}/index.html")).await;
    assert_eq!(status, 200);
    assert!(body.contains("id='inner-iframe'"), "control: the wrapper route wraps a .html document: {body}");

    // The panel's link, navigated the same way, serves the bytes inert.
    let (status, headers, body) = document_navigation(&router, "127.0.0.1:42222", &href).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, "<html>presence</html>", "raw bytes, no wrapper");
    assert!(!body.contains("id='inner-iframe'"));
    let csp = headers.get("content-security-policy").unwrap().to_str().unwrap();
    assert!(csp.starts_with("default-src 'none'; sandbox"), "noscript sandbox policy: {csp}");

    // On a transparent proxy host every path naming another xite is sent to
    // that xite's own origin, so there is no inert route to link: the panel
    // shows the paths as text next to their hashes and links nothing.
    let (_, html) = request(&router, "dashboard.epix", &format!("/list/{address}?evx=1")).await;
    let panel = panel(&html);
    assert!(panel.contains("<td><code>index.html</code></td>"), "path as text: {html}");
    assert!(panel.contains(&XiteStorage::hash_bytes(b"<html>presence</html>")), "{html}");
    assert!(!panel.contains(" download>"), "no link on a proxy host: {html}");
    assert!(!panel.contains("href="), "no href at all in the panel on a proxy host: {html}");
}

/// The EVX panel's own markup, without the listing below it.
fn panel(html: &str) -> &str {
    let (_, rest) = html.split_once("id='evx-panel'").expect("panel present");
    let (panel, _) = rest.split_once("</section>").expect("panel closed");
    panel
}
