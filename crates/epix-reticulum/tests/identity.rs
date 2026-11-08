use epix_reticulum::{MeshConfig, MeshNode};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
async fn persistent_mesh_identity_keeps_both_endpoints_across_restart() {
    let mut builder = tempfile::Builder::new();
    builder.prefix("epix-mesh-identity-");
    #[cfg(unix)]
    builder.permissions(std::fs::Permissions::from_mode(0o700));
    let root = builder.tempdir().unwrap();
    #[cfg(unix)]
    {
        let permissions = std::fs::metadata(root.path()).unwrap().permissions();
        assert_eq!(permissions.mode() & 0o077, 0);
    }
    let config = MeshConfig {
        identity_path: Some(root.path().join("identity")),
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
    drop(second);
    root.close().unwrap();
}
