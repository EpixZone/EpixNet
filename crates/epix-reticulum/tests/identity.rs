use epix_reticulum::{MeshConfig, MeshNode};

#[tokio::test]
async fn persistent_mesh_identity_keeps_both_endpoints_across_restart() {
    let root = std::env::temp_dir().join(format!(
        "epix-mesh-identity-{}-{}",
        std::process::id(),
        rand_core::OsRng.next_u64()
    ));
    let config = MeshConfig {
        identity_path: Some(root.join("identity")),
        ..Default::default()
    };
    let first = MeshNode::spawn(config.clone()).await.unwrap();
    let legacy = first.dest_hash_hex();
    let reliable = first.reliable_dest_hash_hex();
    assert_ne!(legacy, reliable);
    drop(first);
    let second = MeshNode::spawn(config).await.unwrap();
    assert_eq!(second.dest_hash_hex(), legacy);
    assert_eq!(second.reliable_dest_hash_hex(), reliable);
    std::fs::remove_dir_all(root).unwrap();
}
use rand_core::RngCore;
