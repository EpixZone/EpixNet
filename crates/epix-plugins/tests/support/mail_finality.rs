//! A two-name chain fixture with a real Merkle root and validator signature.
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use epix_chain::{PinnedSet, PinnedValidator};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

fn varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 128 {
        output.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    output.push(value as u8);
}

fn attestation(key: &SigningKey, root: &str, now: i64) -> Value {
    let height = 2;
    let mut extension = vec![8, height, 16];
    varint(now as u64, &mut extension);
    extension.extend([26, root.len() as u8]);
    extension.extend(root.as_bytes());
    let canonical =
        epix_chain::canonical_vote_ext_bytes(&extension, i64::from(height), 0, "mail-test");
    json!({
        "height": height.to_string(), "block_time": now.to_string(),
        "attestations": [{
            "validator_cons_addr": "epixvalcons1test", "round": "0",
            "signature": hex::encode(key.sign(&canonical).to_bytes()),
            "vote_extension": base64::engine::general_purpose::STANDARD.encode(extension),
        }]
    })
}

#[derive(Default)]
pub struct Attestations {
    unavailable: AtomicBool,
    failures: AtomicUsize,
}

impl Attestations {
    pub async fn pause(&self) {
        self.unavailable.store(true, Ordering::Release);
        epix_chain::clear_xid_caches().await;
    }

    pub fn resume(&self) {
        self.unavailable.store(false, Ordering::Release);
    }

    pub fn failures(&self) -> usize {
        self.failures.load(Ordering::Acquire)
    }

    fn rejects(&self, path: &str) -> bool {
        if path.starts_with("/xid/v1/attestations?") && self.unavailable.load(Ordering::Acquire) {
            self.failures.fetch_add(1, Ordering::AcqRel);
            return true;
        }
        false
    }
}

pub async fn serve(checkpoint: &Path, alice: &[&str], bob: &[&str]) -> Arc<Attestations> {
    let leaves = [("alice", alice), ("bob", bob)].map(|(name, addresses)| {
        let identities: Vec<_> = addresses
            .iter()
            .map(|auth| json!({"address": auth, "active": true}))
            .collect();
        serde_json::to_vec(
            &json!({"name": name, "tld":"epix", "owner":"fixture", "identities":identities}),
        )
        .unwrap()
    });
    let hashes = leaves.each_ref().map(Sha256::digest);
    let root = hex::encode(Sha256::digest(
        [hashes[0].as_slice(), hashes[1].as_slice()].concat(),
    ));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let validator_seed: [u8; 32] = Sha256::digest(epix_crypt::new_seed().as_bytes()).into();
    let validator = SigningKey::from_bytes(&validator_seed);
    let validators = HashMap::from([(
        "epixvalcons1test".into(),
        PinnedValidator {
            pubkey: validator.verifying_key().to_bytes(),
            voting_power: 1,
        },
    )]);
    epix_chain::set_pinned_validators(Some(
        PinnedSet::new(validators, "mail-test", now, 1).unwrap(),
    ));
    epix_chain::configure_finality_checkpoint(checkpoint).unwrap();
    epix_chain::set_verify_finality(true);
    let mut replies = HashMap::new();
    for (index, name) in ["alice", "bob"].iter().enumerate() {
        replies.insert(format!("/xid/v1/resolve_with_proof/epix/{name}"), json!({
            "leaf_preimage": hex::encode(&leaves[index]),
            "proof": {"root": root, "leaf_hash": hex::encode(hashes[index]), "leaf_index":index, "siblings":[hex::encode(hashes[1-index])]}
        }));
    }
    replies.insert(
        format!("/xid/v1/attestations?digest={root}"),
        attestation(&validator, &root, now),
    );
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    epix_chain::set_chain_rpc_urls(&[format!("http://{}", listener.local_addr().unwrap())]);
    let control = Arc::new(Attestations::default());
    let attestations = control.clone();
    tokio::spawn(async move {
        while let Ok((mut connection, _)) = listener.accept().await {
            let mut input = BufReader::new(&mut connection);
            let mut line = String::new();
            if input.read_line(&mut line).await.unwrap_or(0) == 0 {
                continue;
            }
            let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
            while !line.trim().is_empty() {
                line.clear();
                if input.read_line(&mut line).await.unwrap_or(0) == 0 {
                    break;
                }
            }
            let (status, value) = if attestations.rejects(&path) {
                ("503 Service Unavailable", &Value::Null)
            } else {
                ("200 OK", replies.get(&path).unwrap_or(&Value::Null))
            };
            let body = serde_json::to_vec(value).unwrap();
            let header = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
            if connection.write_all(header.as_bytes()).await.is_ok() {
                let _ = connection.write_all(&body).await;
            }
        }
    });
    control
}
