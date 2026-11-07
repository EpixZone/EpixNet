use anyhow::Result;
use epix_mirror::{
    checked_stream, decode, encode, export, fresh, node_origin, open_regular, safe_path, stage,
    unpack, validate, Catalog, ExportOptions, FileInfo, Server, StageOptions, CATALOG,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Cursor, Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

fn expiry() -> String {
    (chrono::Utc::now() + chrono::Duration::hours(12)).to_rfc3339()
}
fn info(bytes: &[u8]) -> FileInfo {
    FileInfo {
        size: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}
struct Fixture {
    _dir: tempfile::TempDir,
    source: PathBuf,
    snapshot: PathBuf,
    catalog: Catalog,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("public");
        let snapshot = dir.path().join("snapshot");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("fixture.1.nupkg"), b"native fixture bytes\n").unwrap();
        let catalog = stage(StageOptions {
            source: &source,
            output: &snapshot,
            manager: "chocolatey",
            expires: &expiry(),
            url_map: None,
        })
        .unwrap();
        Self {
            _dir: dir,
            source,
            snapshot,
            catalog,
        }
    }
    fn archive(&self, address: &str, extra: Option<(&str, &[u8])>) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        for (name, bytes) in [
            (
                "content.json".to_string(),
                serde_json::to_vec(&json!({"address":address})).unwrap(),
            ),
            (
                CATALOG.to_string(),
                fs::read(self.snapshot.join(CATALOG)).unwrap(),
            ),
            (
                "repo/fixture.1.nupkg".to_string(),
                fs::read(self.snapshot.join("repo/fixture.1.nupkg")).unwrap(),
            ),
        ] {
            writer.start_file(name, options).unwrap();
            writer.write_all(&bytes).unwrap();
        }
        if let Some((name, bytes)) = extra {
            writer.start_file(name, options).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }
}
struct Running {
    port: u16,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<Result<()>>>,
}

fn zip64(bytes: &[u8], entries: Option<u64>, index_size: Option<u64>) -> Vec<u8> {
    let position = bytes.len() - 22;
    let footer = &bytes[position..];
    let actual_entries = u16::from_le_bytes(footer[10..12].try_into().unwrap()) as u64;
    let actual_size = u32::from_le_bytes(footer[12..16].try_into().unwrap()) as u64;
    let offset = u32::from_le_bytes(footer[16..20].try_into().unwrap()) as u64;
    let mut output = bytes[..position].to_vec();
    output.extend(b"PK\x06\x06");
    output.extend(44u64.to_le_bytes());
    output.extend(45u16.to_le_bytes());
    output.extend(45u16.to_le_bytes());
    output.extend(0u32.to_le_bytes());
    output.extend(0u32.to_le_bytes());
    output.extend(entries.unwrap_or(actual_entries).to_le_bytes());
    output.extend(entries.unwrap_or(actual_entries).to_le_bytes());
    output.extend(index_size.unwrap_or(actual_size).to_le_bytes());
    output.extend(offset.to_le_bytes());
    output.extend(b"PK\x06\x07");
    output.extend(0u32.to_le_bytes());
    output.extend((position as u64).to_le_bytes());
    output.extend(1u32.to_le_bytes());
    let mut legacy = footer.to_vec();
    legacy[8..12].fill(255);
    legacy[12..20].fill(255);
    output.extend(legacy);
    output
}

#[test]
fn zip64_metadata_is_bounded_before_index_allocation() {
    let fixture = Fixture::new();
    let address = "epix-fixture";
    let bytes = fixture.archive(address, None);
    for (label, archive, message) in [
        (
            "count",
            zip64(&bytes, Some(u64::MAX), None),
            "Too many ZIP entries",
        ),
        (
            "span",
            zip64(&bytes, None, Some(u64::MAX)),
            "oversized ZIP central directory",
        ),
    ] {
        let target = fixture._dir.path().join(label);
        fs::create_dir(&target).unwrap();
        let error = unpack(Cursor::new(archive), &target, address).unwrap_err();
        assert!(error.to_string().contains(message), "{error:#}");
        assert_eq!(fs::read_dir(target).unwrap().count(), 0);
    }
    let target = fixture._dir.path().join("valid-zip64");
    fs::create_dir(&target).unwrap();
    let catalog = unpack(Cursor::new(zip64(&bytes, None, None)), &target, address).unwrap();
    assert_eq!(catalog.snapshot, fixture.catalog.snapshot);
}
impl Running {
    fn new(snapshot: &Path) -> Self {
        let server = Server::bind(snapshot, 0).unwrap();
        let port = server.port();
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let thread = thread::spawn(move || server.run(signal));
        Self {
            port,
            stop,
            thread: Some(thread),
        }
    }
    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.thread.take().unwrap().join().unwrap().unwrap();
    }
}

#[test]
fn stage_preserves_bytes_and_detects_mutation() {
    let f = Fixture::new();
    assert_eq!(
        fs::read(f.source.join("fixture.1.nupkg")).unwrap(),
        fs::read(f.snapshot.join("repo/fixture.1.nupkg")).unwrap()
    );
    assert_eq!(validate(&f.snapshot).unwrap().snapshot, f.catalog.snapshot);
    fs::write(f.snapshot.join("repo/fixture.1.nupkg"), b"changed").unwrap();
    assert!(validate(&f.snapshot).is_err());
}
#[test]
fn existing_output_and_source_descendants_are_refused() {
    let f = Fixture::new();
    assert!(stage(StageOptions {
        source: &f.source,
        output: &f.snapshot,
        manager: "chocolatey",
        expires: &expiry(),
        url_map: None
    })
    .is_err());
    assert!(stage(StageOptions {
        source: &f.source,
        output: &f.source.join("inside"),
        manager: "chocolatey",
        expires: &expiry(),
        url_map: None
    })
    .is_err());
    assert!(!f.source.join("inside").exists());
}
#[test]
fn unsafe_paths_identity_data_and_duplicates_are_rejected() {
    for path in [
        "../secret",
        "/absolute",
        "a//b",
        "a/./b",
        "a/../b",
        "hidden/.git",
        "file ",
        "file.",
        "C:evil",
        "a\\b",
        "NUL",
        "NUL .txt",
        "COM1.txt",
        "COM¹.txt",
    ] {
        assert!(safe_path(path).is_err(), "{path}");
    }
    assert!(decode(br#"{"files":{"a":1,"a":2}}"#).is_err());
    let f = Fixture::new();
    fs::write(f.source.join("users.json"), b"private").unwrap();
    let output = f._dir.path().join("unsafe");
    assert!(stage(StageOptions {
        source: &f.source,
        output: &output,
        manager: "chocolatey",
        expires: &expiry(),
        url_map: None
    })
    .is_err());
    assert!(!output.exists());
}
#[test]
fn unicode_and_ascii_case_aliases_cannot_enter_catalog() {
    for names in [["A.nupkg", "a.nupkg"], ["ß.nupkg", "ss.nupkg"]] {
        let files = names
            .into_iter()
            .map(|n| (n.to_string(), info(b"x")))
            .collect();
        assert!(Catalog::new("chocolatey".into(), expiry(), files, BTreeMap::new()).is_err());
    }
    let encoded = encode(&json!({"z":"😀","a":"café"})).unwrap();
    assert_eq!(
        std::str::from_utf8(&encoded).unwrap(),
        "{\"a\":\"caf\\u00e9\",\"z\":\"\\ud83d\\ude00\"}\n"
    );
}
#[test]
fn stale_or_tampered_catalogs_fail() {
    let f = Fixture::new();
    let mut catalog = f.catalog.clone();
    catalog.expires = "2000-01-01T00:00:00Z".into();
    assert!(fresh(&catalog).is_err());
    catalog.snapshot = catalog.digest().unwrap();
    fs::write(
        f.snapshot.join(CATALOG),
        encode(&serde_json::to_value(catalog).unwrap()).unwrap(),
    )
    .unwrap();
    assert!(validate(&f.snapshot).is_err());
}
#[test]
fn node_origin_is_strict_literal_loopback() {
    for allowed in [
        "http://127.0.0.1:42222",
        "http://[::1]:42222/",
        "http://127.0.0.1:80",
    ] {
        assert!(node_origin(allowed).is_ok());
    }
    for denied in [
        "https://127.0.0.1:42222",
        "http://localhost:42222",
        "http://example.org:42222",
        "http://127.0.0.1",
        "http://2130706433:42222",
        "http://127.0.0.1:0",
        "http://user@127.0.0.1:42222",
        "http://127.0.0.1:42222/path",
        "http://127.0.0.1:42222?x=1",
    ] {
        assert!(node_origin(denied).is_err(), "{denied}");
    }
}
#[test]
fn descriptor_checked_bytes_survive_path_replacement() {
    let f = Fixture::new();
    let path = f.snapshot.join("repo/fixture.1.nupkg");
    let mut stream = checked_stream(
        &f.snapshot,
        "repo/fixture.1.nupkg",
        &f.catalog.files["fixture.1.nupkg"],
    )
    .unwrap();
    #[cfg(unix)]
    {
        fs::rename(&path, path.with_extension("old")).unwrap();
        fs::write(&path, b"replacement").unwrap();
    }
    #[cfg(windows)]
    {
        assert!(fs::rename(&path, path.with_extension("old")).is_err());
        assert!(fs::write(&path, b"replacement").is_err());
    }
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"native fixture bytes\n");
    drop(stream);
    fs::write(path, b"changed").unwrap();
    assert!(checked_stream(
        &f.snapshot,
        "repo/fixture.1.nupkg",
        &f.catalog.files["fixture.1.nupkg"]
    )
    .is_err());
}
#[cfg(unix)]
#[test]
fn symlinks_and_fifo_substitution_fail_without_blocking() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    symlink(&f.source, f.snapshot.join("linked")).unwrap();
    assert!(open_regular(&f.snapshot, "linked/fixture.1.nupkg").is_err());
    let fifo = f.snapshot.join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    let start = std::time::Instant::now();
    assert!(open_regular(&f.snapshot, "fifo").is_err());
    assert!(start.elapsed() < std::time::Duration::from_secs(1));
}
#[test]
fn bounded_catalog_read_refuses_sparse_oversize() {
    let f = Fixture::new();
    let file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(f.snapshot.join(CATALOG))
        .unwrap();
    file.set_len(epix_mirror::MAX_CATALOG + 1).unwrap();
    drop(file);
    assert!(validate(&f.snapshot).is_err());
}
#[test]
fn http_server_enforces_host_methods_ranges_and_exact_catalog() {
    let f = Fixture::new();
    let running = Running::new(&f.snapshot);
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    let url = format!("{}/fixture.1.nupkg", running.url());
    let response = client.get(&url).send().unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(
        response.bytes().unwrap().as_ref(),
        b"native fixture bytes\n"
    );
    let range = client
        .get(&url)
        .header("Range", "bytes=7-13")
        .send()
        .unwrap();
    assert_eq!(range.status(), 206);
    assert_eq!(range.bytes().unwrap().as_ref(), b"fixture");
    assert_eq!(
        client.head(&url).send().unwrap().headers()["content-length"],
        "21"
    );
    assert_eq!(
        client
            .get(&url)
            .header("Host", "attacker.invalid")
            .send()
            .unwrap()
            .status(),
        403
    );
    assert_eq!(client.post(&url).send().unwrap().status(), 405);
    assert_eq!(
        client
            .get(format!("{}/../private/users.json", running.url()))
            .send()
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client
            .get(format!("{url}?ignored=1"))
            .send()
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client
            .get(&url)
            .header("Range", "bytes=999-")
            .send()
            .unwrap()
            .status(),
        416
    );
    fs::write(f.snapshot.join("repo/fixture.1.nupkg"), b"mutation").unwrap();
    assert_eq!(client.get(&url).send().unwrap().status(), 409);
}
#[test]
fn homebrew_only_serves_exact_pinned_artifact_routes() {
    let f = Fixture::new();
    let mapping = f._dir.path().join("routes.json");
    fs::write(
        &mapping,
        br#"{"/v2/test/blobs/sha256:abc":"fixture.1.nupkg"}"#,
    )
    .unwrap();
    let snapshot = f._dir.path().join("brew");
    stage(StageOptions {
        source: &f.source,
        output: &snapshot,
        manager: "homebrew",
        expires: &expiry(),
        url_map: Some(&mapping),
    })
    .unwrap();
    let running = Running::new(&snapshot);
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    assert_eq!(
        client
            .get(format!("{}/v2/test/blobs/sha256:abc", running.url()))
            .send()
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .get(format!("{}/https://evil.invalid/file", running.url()))
            .send()
            .unwrap()
            .status(),
        404
    );
}
#[test]
fn unpack_checks_address_hashes_paths_and_collisions() {
    let f = Fixture::new();
    let address = epix_crypt::privatekey_to_address(&hex::encode([1; 32])).unwrap();
    for extra in [
        Some(("../escape", b"x".as_slice())),
        Some(("REPO/fixture.1.nupkg", b"x".as_slice())),
    ] {
        let dest = tempfile::tempdir().unwrap();
        assert!(unpack(
            Cursor::new(f.archive(&address, extra)),
            dest.path(),
            &address
        )
        .is_err());
    }
    let dest = tempfile::tempdir().unwrap();
    assert!(unpack(
        Cursor::new(f.archive(&address, None)),
        dest.path(),
        "wrong-address"
    )
    .is_err());
    let dest = tempfile::tempdir().unwrap();
    let catalog = unpack(
        Cursor::new(f.archive(&address, None)),
        dest.path(),
        &address,
    )
    .unwrap();
    assert_eq!(catalog.snapshot, f.catalog.snapshot);
    assert!(dest.path().join("epix-export.json").exists());
}

fn mock_node(body: Vec<u8>, status: &str, extra: &str) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let status = status.to_string();
    let extra = extra.to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            request.push_str(&line);
            if line == "\r\n" {
                break;
            }
        }
        write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/zip\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",body.len()).unwrap();
        stream.write_all(&body).unwrap();
        request
    });
    (origin, handle)
}
#[test]
fn local_export_keeps_auth_headers_and_pins_snapshot_atomically() {
    let f = Fixture::new();
    let address = epix_crypt::privatekey_to_address(&hex::encode([1; 32])).unwrap();
    let (origin, server) = mock_node(f.archive(&address, None), "200 OK", "");
    let cookie = f._dir.path().join("cookie.txt");
    fs::write(&cookie,"# Netscape HTTP Cookie File\n127.0.0.1\tFALSE\t/\tFALSE\t0\tepix_session\tdisposable\nexample.org\tFALSE\t/\tFALSE\t0\tforeign\tnever-send\n").unwrap();
    let output = f._dir.path().join("export");
    let catalog = export(ExportOptions {
        node: &origin,
        address: &address,
        output: &output,
        cookie_file: Some(&cookie),
        expected_snapshot: Some(&f.catalog.snapshot),
    })
    .unwrap();
    assert_eq!(catalog.snapshot, f.catalog.snapshot);
    let request = server.join().unwrap().to_lowercase();
    assert!(request.contains("cookie: epix_session=disposable"));
    assert!(!request.contains("never-send"));
    assert!(request.contains(&format!("origin: {origin}")));
    assert!(request.contains(&format!("referer: {origin}/{address}/")));
}
#[test]
fn export_refuses_redirect_and_wrong_pin_without_publishing() {
    let f = Fixture::new();
    let address = epix_crypt::privatekey_to_address(&hex::encode([1; 32])).unwrap();
    let (origin, server) = mock_node(
        Vec::new(),
        "302 Found",
        "Location: http://example.invalid/\r\n",
    );
    let output = f._dir.path().join("redirect");
    assert!(export(ExportOptions {
        node: &origin,
        address: &address,
        output: &output,
        cookie_file: None,
        expected_snapshot: None
    })
    .is_err());
    server.join().unwrap();
    assert!(!output.exists());
    let (origin, server) = mock_node(f.archive(&address, None), "200 OK", "");
    assert!(export(ExportOptions {
        node: &origin,
        address: &address,
        output: &output,
        cookie_file: None,
        expected_snapshot: Some(&"0".repeat(64))
    })
    .is_err());
    server.join().unwrap();
    assert!(!output.exists());
}
