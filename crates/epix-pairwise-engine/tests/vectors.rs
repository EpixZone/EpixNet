//! Frozen known-answer vectors — a regression lock on the exact cryptographic
//! construction (HKDF-SHA256, HMAC-SHA256, X3DH SK, identity/prekey derivation,
//! tag chain, chain KDF). These deterministic values are produced by
//! `cargo run --example gen_vectors` and MUST NOT drift silently: any change to a
//! primitive, a domain-separation context, or a derivation formula changes them
//! and fails here on purpose. A second, independent implementation of the spec
//! (`docs/channel-crypto-spec.md`) must reproduce every value below.
//!
//! Regenerate intentionally (only when the construction is deliberately changed):
//!   cargo run -q -p epix-pairwise-engine --example gen_vectors

use epix_pairwise_engine::{crypto, curve, keys};

// --- frozen expected values (from examples/gen_vectors.rs) -------------------
const KDF_KAT: &str = "2c27864d5c97576d648101cd57fb39880156de46e0f189768fa71dd19dc8683f";
const MAC_KAT: &str = "21bbc9a314d4aaecde6711d51bdda95e5f04eb117f43e59777d3c11e539f5203";
const IK_A_PRIV: &str = "3294f5ebba45946bf7f5dae14b86b21e3b2805a4971e68b9a7caf98bc750ae1e";
const IK_A_PUB: &str = "109e614bb2a8dbf604ce13504b7dfef24d201e7dd166966dd1e2330512414639";
const SPK_B_PRIV: &str = "b6f134631347b0b9f2b39df1e72ff0859d7ee1286d39fa3d1eac2e2662d9180b";
const SPK_B_PUB: &str = "55af52675782b169fd44702f695e25fef216f5abce603c341a5ad8cfc76aab76";
const IK_B_PUB: &str = "08f8207dcb10ec89541293ea0af588c40e7569a090b7ffb0da45c84fd5d76717";
const X3DH_SK: &str = "8df67768d2cc21369471e7fa9558f8e3698d79678354b46669e9d20c027576e5";
const FC_KEY: &str = "b629292a3064950cc751a5ce5b314a4e1b0accf5942f360b5b66fa2da2729e0b";
const TAG: &str = "443b8c114d23b314a1e171ef56891b6f4cba1ae5efbf8dc62ea4a0c8b8516318";
const HK: &str = "af6889c4cb14f23e0bb5bb54887250e6b9862e023abec846cfbbaa9412f6a865";
const NEXT_TCK: &str = "8e2a9e5c9b40eff739ff677473ccdc4c35892a2c36f1259395fbfd11f0d66c0d";
const MK: &str = "57c022b2dc9141e2cc4962c09115683cefac9120b7368aee1477e057fbaf5e94";
const CK_NEXT: &str = "f825f92c80e12abbaee8eebfae2e1772fe07e4751fe89fc36b2d3136e4239bc3";

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

#[test]
fn frozen_vectors_match() {
    let seed_a = [1u8; 32];
    let seed_b = [2u8; 32];
    let eph = [3u8; 32];
    let spk_idx = 2954u32;

    // Primitive KATs — pin HKDF-SHA256 and HMAC-SHA256.
    assert_eq!(h(&crypto::kdf32("epix-channel/test/v1", b"salt", b"ikm")), KDF_KAT, "HKDF-SHA256");
    assert_eq!(h(&crypto::mac(&[7u8; 32], b"data")), MAC_KAT, "HMAC-SHA256");

    // Identity / prekey derivation.
    let ik_a = keys::ik_priv(&seed_a);
    let spk_b = keys::spk_priv(&seed_b, spk_idx);
    let ik_b = keys::ik_priv(&seed_b);
    assert_eq!(h(&ik_a), IK_A_PRIV, "IK_a derivation");
    assert_eq!(h(&curve::public_key(&ik_a)), IK_A_PUB);
    assert_eq!(h(&spk_b), SPK_B_PRIV, "SPK_b derivation");
    assert_eq!(h(&curve::public_key(&spk_b)), SPK_B_PUB);
    assert_eq!(h(&curve::public_key(&ik_b)), IK_B_PUB);

    // X3DH SK from the three DH values (initiator view) + first-contact key.
    let dh1 = curve::dh(&ik_a, &curve::public_key(&spk_b));
    let dh2 = curve::dh(&eph, &curve::public_key(&ik_b));
    let dh3 = curve::dh(&eph, &curve::public_key(&spk_b));
    let mut ikm = Vec::new();
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    assert_eq!(h(&crypto::kdf32("epix-channel/x3dh/v1", &[0xFFu8; 32], &ikm)), X3DH_SK, "X3DH SK");
    assert_eq!(h(&crypto::kdf32("epix-channel/fc-hdr/v1", &[9u8; 32], &dh2)), FC_KEY, "fc_key");

    // Tag chain: tag/hk/next_tck = MAC(tck, label).
    let tck = [5u8; 32];
    assert_eq!(h(&crypto::mac(&tck, b"tag")), TAG, "tag_of");
    assert_eq!(h(&crypto::mac(&tck, b"hdr")), HK, "hk_of");
    assert_eq!(h(&crypto::mac(&tck, b"chain")), NEXT_TCK, "next_tck");

    // Chain KDF: mk = MAC(ck, 0x01), ck' = MAC(ck, 0x02).
    let ck = [6u8; 32];
    assert_eq!(h(&crypto::mac(&ck, &[1u8])), MK, "kdf_ck mk");
    assert_eq!(h(&crypto::mac(&ck, &[2u8])), CK_NEXT, "kdf_ck ck'");
}

/// A cross-check that the X3DH values agree from the responder's side too (the
/// DH symmetry the whole handshake relies on) — independent of the frozen SK.
#[test]
fn x3dh_dh_values_agree_from_both_sides() {
    let seed_a = [1u8; 32];
    let seed_b = [2u8; 32];
    let eph = [3u8; 32];
    let idx = 2954u32;
    let ik_a = keys::ik_priv(&seed_a);
    let ik_b = keys::ik_priv(&seed_b);
    let spk_b = keys::spk_priv(&seed_b, idx);
    let eph_pub = curve::public_key(&eph);

    // Initiator: DH1=DH(IK_a,SPK_b) DH2=DH(EK,IK_b) DH3=DH(EK,SPK_b)
    // Responder: DH1=DH(SPK_b,IK_a) DH2=DH(IK_b,EK)  DH3=DH(SPK_b,EK)
    assert_eq!(curve::dh(&ik_a, &curve::public_key(&spk_b)), curve::dh(&spk_b, &curve::public_key(&ik_a)));
    assert_eq!(curve::dh(&eph, &curve::public_key(&ik_b)), curve::dh(&ik_b, &eph_pub));
    assert_eq!(curve::dh(&eph, &curve::public_key(&spk_b)), curve::dh(&spk_b, &eph_pub));
}
