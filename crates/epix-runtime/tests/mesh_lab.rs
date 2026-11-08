//! Opt-in native mesh endpoint for isolated interoperability labs.
//! Runs in a network namespace with only loopback and task-owned profiles.

#![cfg(feature = "mesh")]

use epix_core::PeerAddr;
use epix_runtime::{NodeRuntime, RuntimeConfig};
use epix_ui::AppState;
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn fixture_bytes() -> Vec<u8> {
    (0..16_384).map(|index| ((index * 31 + 7) % 251) as u8).collect()
}

fn write_json(path: &Path, value: &Value) {
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated network namespace and task-owned lab profiles"]
async fn isolated_mesh_endpoint() {
    assert_eq!(std::env::var("EPIX_MESH_LAB").as_deref(), Ok("isolated-719"));
    let expected_namespace = std::env::var("EPIX_MESH_LAB_NETNS").unwrap();
    assert_eq!(std::fs::read_link("/proc/self/ns/net").unwrap().to_string_lossy(), expected_namespace);
    let root = PathBuf::from(std::env::var_os("EPIX_MESH_LAB_ROOT").unwrap());
    assert!(root.join("lab-owned").is_file());
    let role = std::env::var("EPIX_MESH_LAB_ROLE").unwrap();
    assert!(matches!(role.as_str(), "seed" | "client"));
    let bridge = std::env::var("EPIX_MESH_LAB_BRIDGE").unwrap();
    let endpoint: std::net::SocketAddr = bridge.parse().unwrap();
    assert!(endpoint.ip().is_loopback());
    let state = AppState::with_data_dir("mesh-lab-719", &root);
    let seed_metadata = root.parent().unwrap().join("seed/ready.json");
    let address = if role == "seed" {
        let (address, key) = state.create_xite().await.unwrap();
        let storage = XiteStorage::new(root.join("data").join(&address));
        storage.write("fixture.bin", &fixture_bytes()).unwrap();
        storage.write("index.html", b"<!doctype html><title>Offline mesh fixture</title><h1>Signed xite over Reticulum</h1>").unwrap();
        state.sign_xite(&address, &key).await.unwrap();
        address
    } else {
        let metadata: Value = serde_json::from_slice(&std::fs::read(&seed_metadata).unwrap()).unwrap();
        let address = metadata["xite"].as_str().unwrap().to_string();
        state.register_for_download(&address).await.unwrap();
        state.add_peers(&address, [PeerAddr::parse(metadata["rns"].as_str().unwrap()).unwrap()]).await;
        address
    };
    let config = RuntimeConfig {
        mesh_enabled: true,
        mesh_peers: if role == "seed" && std::env::var_os("EPIX_MESH_DIRECT").is_some() { vec![] } else { vec![bridge.clone()] },
        mesh_listen: if role == "seed" && std::env::var_os("EPIX_MESH_DIRECT").is_some() { Some(bridge) } else { None },
        fileserver_port: None,
        ..Default::default()
    };
    let mut runtime = NodeRuntime::with_config(state.clone(), vec![], config).with_data_dir(&root);
    runtime.start().await.unwrap();
    let rns = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(address) = state.rns_reliable_address().await { break address; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await.expect("mesh runtime startup");
    let legacy = state.rns_address().await.unwrap();
    write_json(&root.join("ready.json"), &json!({"role":role,"xite":address,"rns":format!("rns:{rns}"),"legacy_rns":format!("rns:{legacy}")}));
    if role == "seed" {
        tokio::time::timeout(Duration::from_secs(240), async {
            while !root.join("stop").exists() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await.expect("lab coordinator must stop the seeder");
    } else {
        let result = tokio::time::timeout(Duration::from_secs(160), async {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(150);
            loop {
                let result = state.resync_xite(&address).await;
                let storage = XiteStorage::new(root.join("data").join(&address));
                if storage.exists("fixture.bin") {
                    let bytes = storage.read("fixture.bin").unwrap();
                    let content: Value = serde_json::from_slice(&storage.read("content.json").unwrap()).unwrap();
                    let signed = epix_content::verify_signer(&content, &address);
                    let exact = bytes == fixture_bytes();
                    let digest = content["files"]["fixture.bin"]["sha512"].as_str().unwrap();
                    let hash_valid = storage.verify("fixture.bin", digest);
                    return json!({"success":signed && exact && hash_valid,"bytes":bytes.len(),"signed_manifest":signed,"exact_payload":exact,"signed_file_hash":hash_valid,"xite":address});
                }
                if tokio::time::Instant::now() >= deadline {
                    return json!({"success":false,"last_resync":format!("{result:?}"),"xite":address});
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }).await.unwrap_or_else(|_| json!({"success":false,"error":"mesh transfer timeout"}));
        write_json(&root.join("result.json"), &result);
        runtime.shutdown().await;
        assert_eq!(result["success"], true, "mesh result: {result}");
        return;
    }
    runtime.shutdown().await;
}
