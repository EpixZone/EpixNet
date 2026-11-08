use super::*;
use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination, SingleOutputDestination};
use reticulum::identity::{Identity, PrivateIdentity};

fn descriptor(identity: &PrivateIdentity, version: &str) -> DestinationDesc {
    SingleInputDestination::new(identity.clone(), DestinationName::new("epix", version)).desc
}

#[test]
fn legacy_upgrade_requires_both_identity_keys_and_known_signed_protocol() {
    let owner = PrivateIdentity::new_from_rand(OsRng);
    let stranger = PrivateIdentity::new_from_rand(OsRng);
    let legacy = descriptor(&owner, "node");
    let reliable = descriptor(&owner, "node.v2");
    let wrong_owner = descriptor(&stranger, "node.v2");
    let wrong_version = descriptor(&owner, "node.v3");
    let mixed_key = Identity::new(
        owner.as_identity().public_key,
        stranger.as_identity().verifying_key,
    );
    let mixed =
        SingleOutputDestination::new(mixed_key, DestinationName::new("epix", "node.v2")).desc;
    let mixed_other_key = Identity::new(
        stranger.as_identity().public_key,
        owner.as_identity().verifying_key,
    );
    let mixed_other =
        SingleOutputDestination::new(mixed_other_key, DestinationName::new("epix", "node.v2")).desc;
    let mut known = HashMap::new();
    for candidate in [wrong_owner, wrong_version, mixed, mixed_other] {
        known.insert(candidate.address_hash, candidate);
    }
    assert_eq!(
        preferred_descriptor(legacy, known.values()).address_hash,
        legacy.address_hash
    );
    known.insert(reliable.address_hash, reliable);
    assert_eq!(
        preferred_descriptor(legacy, known.values()).address_hash,
        reliable.address_hash
    );
    known.clear();
    known.insert(legacy.address_hash, legacy);
    assert_eq!(
        preferred_descriptor(reliable, known.values()).address_hash,
        reliable.address_hash,
        "explicit v2 never falls back"
    );
    assert!(stream_protocol(&wrong_version.name).is_err());
}

#[test]
fn announcement_descriptor_cache_is_bounded_and_replaces_oldest() {
    let owner = PrivateIdentity::new_from_rand(OsRng);
    let mut desc = descriptor(&owner, "node.v2");
    let now = Instant::now();
    let mut known = HashMap::new();
    for index in 0..257u16 {
        let mut hash = [0; 16];
        hash[..2].copy_from_slice(&index.to_le_bytes());
        desc.address_hash = AddressHash::new(hash);
        remember_announce(
            &mut known,
            desc,
            now + Duration::from_millis(u64::from(index)),
        );
    }
    assert_eq!(known.len(), 256);
    assert!(!known.contains_key(&AddressHash::new([0; 16])));
    assert!(known.contains_key(&desc.address_hash));
}

#[tokio::test]
async fn departed_nodes_stop_being_automatic_candidates() {
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let inner = Arc::new(Mutex::new(RnsTransport::new(
        reticulum::transport::TransportConfig::new("candidate-test", &identity, false),
    )));
    let transport = ReticulumTransport::new(inner);
    let desc = descriptor(&identity, "node.v2");
    remember_announce(
        &mut *transport.known.lock().await,
        desc,
        Instant::now() - Duration::from_secs(121),
    );
    assert!(transport.candidates().await.is_empty());
    remember_announce(&mut *transport.known.lock().await, desc, Instant::now());
    assert_eq!(transport.candidates().await.len(), 1);
}
