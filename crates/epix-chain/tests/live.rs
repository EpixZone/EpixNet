//! Live resolution against the Epix chain (network-dependent, so `#[ignore]`d).
//! `cargo test -p epix-chain -- --ignored --nocapture`

use epix_chain::XidResolver;

#[tokio::test]
#[ignore]
async fn resolves_a_real_name_chain_verified() {
    let resolver = XidResolver::new(epix_chain::DEFAULT_RPC_URL);
    let domain = resolver.resolve("quasin", "epix").await.expect("resolve");
    println!("{} -> owner {}", domain.fqdn(), domain.owner);
    for id in &domain.identities {
        println!("  identity {} (label={:?}, active={})", id.address, id.label, id.active);
    }
    assert_eq!(domain.name, "quasin");
    assert!(domain.owner.starts_with("epix1"));
    assert!(domain.active_identity().is_some());
    // Second call hits the cache.
    let again = resolver.resolve("quasin", "epix").await.unwrap();
    assert_eq!(domain, again);
}

#[tokio::test]
#[ignore]
async fn unknown_name_is_not_found() {
    let resolver = XidResolver::new(epix_chain::DEFAULT_RPC_URL);
    let res = resolver
        .resolve("this-name-should-not-exist-xyz123", "epix")
        .await;
    assert!(matches!(res, Err(epix_chain::ChainError::NotFound(_))));
}
