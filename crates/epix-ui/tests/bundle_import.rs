use epix_ui::AppState;
use epix_xite::XiteStorage;
use serde_json::json;
use std::io::Write;
use std::path::Path;

fn bundle(path: &Path, archive_name: &str) -> String {
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let data = b"public unicode file";
    let mut content = json!({
        "address": address, "modified": 1,
        "files": {"café.txt": {"size": data.len(), "sha512": XiteStorage::hash_bytes(data)}}
    });
    epix_content::sign(&mut content, &key).unwrap();
    let mut writer = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
    for (name, bytes) in [
        (
            "content.json",
            epix_content::dumps_content(&content).into_bytes(),
        ),
        (archive_name, data.to_vec()),
    ] {
        writer
            .start_file(
                format!("bundle/{address}/{name}"),
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        writer.write_all(&bytes).unwrap();
    }
    writer.finish().unwrap();
    address
}

#[tokio::test]
async fn wrapped_bundle_preserves_unicode_file_names() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bundle.zip");
    let address = bundle(&path, "café.txt");
    let root = directory.path().join("node");
    let state = AppState::with_data_dir("bundle-test", &root);
    assert_eq!(
        state.import_bundle(&path).await.unwrap(),
        vec![address.clone()]
    );
    assert!(state.has_xite(&address).await);
    assert_eq!(
        std::fs::read(root.join("data").join(address).join("café.txt")).unwrap(),
        b"public unicode file"
    );
}

#[tokio::test]
async fn wrapped_bundle_preserves_legacy_cp437_file_names() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bundle.zip");
    let address = bundle(&path, "caf_.txt");
    let mut bytes = std::fs::read(&path).unwrap();
    let offsets: Vec<_> = bytes
        .windows(b"caf_.txt".len())
        .enumerate()
        .filter_map(|(i, part)| (part == b"caf_.txt").then_some(i))
        .collect();
    assert_eq!(offsets.len(), 2);
    for offset in offsets {
        bytes[offset + 3] = 0x82;
    }
    std::fs::write(&path, bytes).unwrap();
    let root = directory.path().join("node");
    let state = AppState::with_data_dir("bundle-test", &root);
    assert_eq!(
        state.import_bundle(&path).await.unwrap(),
        vec![address.clone()]
    );
    assert!(state.has_xite(&address).await);
    assert_eq!(
        std::fs::read(root.join("data").join(address).join("café.txt")).unwrap(),
        b"public unicode file"
    );
}
