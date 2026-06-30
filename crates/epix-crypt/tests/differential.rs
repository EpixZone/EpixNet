//! Differential test: assert epix-crypt matches EpixNet's CryptEpix.py
//! over 1000+ vectors generated from the actual Python implementation.

use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    hd: Vec<HdVec>,
    address_from_priv: Vec<AddrVec>,
    signatures: Vec<SigVec>,
}

#[derive(Deserialize)]
struct HdVec {
    seed: String,
    child: u64,
    wif: String,
    address: String,
}

#[derive(Deserialize)]
struct AddrVec {
    privatekey_hex: String,
    address: String,
}

#[derive(Deserialize)]
struct SigVec {
    privatekey_hex: String,
    data: String,
    address: String,
    sig_dbl_b64: String,
    recovered_dbl: String,
    sig_keccak_b64: String,
    recovered_keccak: String,
}

fn load() -> Vectors {
    let raw = include_str!("vectors.json");
    serde_json::from_str(raw).expect("parse vectors.json")
}

#[test]
fn hd_derivation_and_addresses_match() {
    let v = load();
    assert!(v.hd.len() >= 1000, "expected >=1000 hd vectors");
    for (i, t) in v.hd.iter().enumerate() {
        let wif = epix_crypt::hd_privatekey(&t.seed, t.child).expect("hd");
        assert_eq!(
            wif, t.wif,
            "HD wif mismatch #{i} seed={} child={}",
            t.seed, t.child
        );
        let addr = epix_crypt::privatekey_to_address(&wif).expect("addr");
        assert_eq!(
            addr, t.address,
            "HD address mismatch #{i} seed={} child={}",
            t.seed, t.child
        );
    }
}

#[test]
fn address_from_raw_priv_matches() {
    let v = load();
    for (i, t) in v.address_from_priv.iter().enumerate() {
        let addr = epix_crypt::privatekey_to_address(&t.privatekey_hex).expect("addr");
        assert_eq!(addr, t.address, "raw-priv address mismatch #{i}");
    }
}

#[test]
fn recover_python_signatures_to_correct_address() {
    let v = load();
    for (i, t) in v.signatures.iter().enumerate() {
        // Our address derivation matches Python's.
        let addr = epix_crypt::privatekey_to_address(&t.privatekey_hex).expect("addr");
        assert_eq!(addr, t.address, "sig-vec address mismatch #{i}");
        assert_eq!(t.recovered_dbl, t.address, "python self-consistency dbl #{i}");
        assert_eq!(t.recovered_keccak, t.address, "python self-consistency keccak #{i}");

        // We can recover the signer address from Python-produced signatures
        // (proves our digest + recover + address pipeline matches the wire).
        let r_dbl = epix_crypt::get_sign_address_64(&t.data, &t.sig_dbl_b64).expect("rec dbl");
        assert_eq!(r_dbl, t.address, "recover(python dbl sig) mismatch #{i}");
        let r_kec = epix_crypt::get_sign_address_keccak(&t.data, &t.sig_keccak_b64)
            .expect("rec keccak");
        assert_eq!(r_kec, t.address, "recover(python keccak sig) mismatch #{i}");
    }
}

#[test]
fn our_signatures_round_trip_and_interop() {
    let v = load();
    for (i, t) in v.signatures.iter().enumerate() {
        // Our signatures recover to the right address...
        let sd = epix_crypt::sign(&t.data, &t.privatekey_hex).expect("sign dbl");
        let rd = epix_crypt::get_sign_address_64(&t.data, &sd).expect("rec our dbl");
        assert_eq!(rd, t.address, "our dbl sign/recover mismatch #{i}");
        let sk = epix_crypt::sign_keccak(&t.data, &t.privatekey_hex).expect("sign keccak");
        let rk = epix_crypt::get_sign_address_keccak(&t.data, &sk).expect("rec our keccak");
        assert_eq!(rk, t.address, "our keccak sign/recover mismatch #{i}");

        // ...and report whether bytes are identical to Python (RFC6979 + low-s).
        // Not asserted: EpixNet verify recovers-by-address, so byte-identity is
        // a bonus, not a compat requirement.
        if sd == t.sig_dbl_b64 && sk == t.sig_keccak_b64 {
            // byte-identical — great
        }
    }
}
