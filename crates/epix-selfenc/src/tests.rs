//! Unit tests for the self-encryption layer.
//!
//! Kept in their own file (not inline in lib.rs) so CodeQL's paths-ignore
//! can exclude them: the pinned salts and keys here are test vectors, and
//! scanning them produced a wall of false "hard-coded cryptographic value"
//! alerts. Do not move these back inline; see .github/codeql/codeql-config.yml.

use super::*;
use std::cell::Cell;
use std::collections::HashMap;
use std::io::{self, Write};

fn shard_map(enc: &Encrypted) -> HashMap<Hash, Vec<u8>> {
    enc.shards.iter().cloned().collect()
}

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(97) % 251) as u8).collect()
}

#[test]
fn kdf_context_frozen() {
    assert_eq!(KDF_CONTEXT, "epixnet-selfenc-v1");
    let k = blake3::derive_key(KDF_CONTEXT, b"probe");
    assert_eq!(k, blake3::derive_key(KDF_CONTEXT, b"probe"));
}

#[test]
fn convergent_round_trip_multi_chunk() {
    let d = data(CHUNK_SIZE * 2 + 1234); // 3 chunks
    let salt = b"owner-salt";
    let enc = encrypt_convergent(&d, salt);
    assert_eq!(enc.chunks.len(), 3);
    let shards = shard_map(&enc);
    let got = decrypt(enc.mode, &enc.chunks, salt, |a| shards.get(a).cloned()).unwrap();
    assert_eq!(got, d);
}

#[test]
fn streaming_matches_decrypt_and_finishes_each_chunk_before_fetching_the_next() {
    struct ShortWriter<'a> {
        expected: &'a [u8],
        written: &'a Cell<usize>,
        largest: usize,
        calls: usize,
    }
    impl Write for ShortWriter<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.largest = self.largest.max(bytes.len());
            self.calls += 1;
            let count = bytes.len().min(7001);
            let start = self.written.get();
            assert_eq!(&bytes[..count], &self.expected[start..start + count]);
            self.written.set(start + count);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            panic!("flushing belongs to the caller");
        }
    }

    let plain = data(CHUNK_SIZE * 2 + 17);
    let key = b3(b"streaming-round-trip");
    for mode in [Mode::SaltedConvergent, Mode::RandomKey] {
        let enc = match mode {
            Mode::SaltedConvergent => encrypt_convergent(&plain, &key),
            Mode::RandomKey => encrypt_random_key(&plain, &key),
        };
        let shards = shard_map(&enc);
        assert_eq!(
            decrypt(mode, &enc.chunks, &key, |addr| shards.get(addr).cloned()).unwrap(),
            plain
        );
        let written = Cell::new(0);
        let mut writer = ShortWriter { expected: &plain, written: &written, largest: 0, calls: 0 };
        let mut fetched = 0;
        let count = decrypt_into(
            mode,
            &enc.chunks,
            &key,
            |addr| {
                assert_eq!(written.get(), fetched * CHUNK_SIZE);
                assert_eq!(*addr, enc.chunks[fetched].cipher_addr);
                fetched += 1;
                Ok(shards[addr].clone())
            },
            &mut writer,
        )
        .unwrap();
        assert_eq!(count, plain.len() as u64);
        assert_eq!(written.get(), plain.len());
        assert_eq!(fetched, 3);
        assert_eq!(writer.largest, CHUNK_SIZE);
        assert!(writer.calls > fetched, "short writes must be retried");
    }
}

#[test]
fn streaming_and_buffered_decrypt_reject_incorrect_declared_lengths() {
    let plain = data(CHUNK_SIZE + 32);
    let key = b3(b"declared-length");
    for mode in [Mode::SaltedConvergent, Mode::RandomKey] {
        let enc = match mode {
            Mode::SaltedConvergent => encrypt_convergent(&plain, &key),
            Mode::RandomKey => encrypt_random_key(&plain, &key),
        };
        let shards = shard_map(&enc);
        for wrong_length in [31, 33] {
            let mut chunks = enc.chunks.clone();
            chunks[1].len = wrong_length;
            let mut out = Vec::new();
            let result = decrypt_into(mode, &chunks, &key, |addr| Ok(shards[addr].clone()), &mut out);
            assert_eq!(result, Err(SelfEncError::PlaintextLengthMismatch(1)));
            assert_eq!(out, plain[..CHUNK_SIZE], "invalid chunk must never reach the writer");
            assert_eq!(
                decrypt(mode, &chunks, &key, |addr| shards.get(addr).cloned()),
                Err(SelfEncError::PlaintextLengthMismatch(1))
            );
        }
    }
}

#[test]
fn streaming_rejects_oversized_declared_chunk_before_fetching_any_shards() {
    let enc = encrypt_convergent(&data(CHUNK_SIZE + 1), b"size-limit");
    let mut chunks = enc.chunks;
    chunks[1].len = CHUNK_SIZE as u32 + 1;
    let mut out = Vec::new();
    let result = decrypt_into(
        enc.mode,
        &chunks,
        b"size-limit",
        |_| panic!("all declared lengths must be checked before fetching"),
        &mut out,
    );
    assert_eq!(result, Err(SelfEncError::ChunkTooLarge(1)));
    assert!(out.is_empty());
}

#[test]
fn streaming_rejects_oversized_ciphertext_before_decrypting() {
    let ciphertext = vec![0; CHUNK_SIZE + 17];
    let chunk = ChunkRef { plain_hash: b3(b""), cipher_addr: b3(&ciphertext), len: 0 };
    let mut out = Vec::new();
    let result = decrypt_into(
        Mode::SaltedConvergent,
        &[chunk],
        b"size-limit",
        |_| Ok(ciphertext.clone()),
        &mut out,
    );
    assert_eq!(result, Err(SelfEncError::ChunkTooLarge(0)));
    assert!(out.is_empty());
}

#[test]
fn streaming_verifies_ciphertext_and_plaintext_before_writing() {
    let key = b3(b"streaming-integrity");
    let enc = encrypt_random_key(&data(100), &key);
    let mut damaged = enc.shards[0].1.clone();
    damaged[0] ^= 1;
    let mut out = Vec::new();
    assert_eq!(
        decrypt_into(enc.mode, &enc.chunks, &key, |_| Ok(damaged.clone()), &mut out),
        Err(SelfEncError::CorruptShard(enc.chunks[0].cipher_addr))
    );
    assert!(out.is_empty());

    let mut chunks = enc.chunks.clone();
    chunks[0].plain_hash[0] ^= 1;
    assert_eq!(
        decrypt_into(enc.mode, &chunks, &key, |_| Ok(enc.shards[0].1.clone()), &mut out),
        Err(SelfEncError::PlaintextHashMismatch(0))
    );
    assert!(out.is_empty());
    assert_eq!(
        decrypt_into(enc.mode, &enc.chunks, b"wrong-key", |_| Ok(enc.shards[0].1.clone()), &mut out),
        Err(SelfEncError::DecryptFailed(0))
    );
    assert!(out.is_empty());
}

#[test]
fn streaming_propagates_fetch_cancellation_without_fetching_later_chunks() {
    let plain = data(CHUNK_SIZE * 2 + 1);
    let enc = encrypt_convergent(&plain, b"fetch-cancel");
    let mut fetched = 0;
    let mut out = Vec::new();
    let result = decrypt_into(
        enc.mode,
        &enc.chunks,
        b"fetch-cancel",
        |addr| {
            fetched += 1;
            match fetched {
                1 => {
                    assert_eq!(*addr, enc.shards[0].0);
                    Ok(enc.shards[0].1.clone())
                }
                2 => Err(io::Error::new(io::ErrorKind::Interrupted, "export cancelled")),
                _ => panic!("fetch cancellation must stop the stream"),
            }
        },
        &mut out,
    );
    assert_eq!(
        result,
        Err(SelfEncError::Io { kind: io::ErrorKind::Interrupted, message: "export cancelled".into() })
    );
    assert_eq!(fetched, 2);
    assert_eq!(out, plain[..CHUNK_SIZE]);
}

#[test]
fn streaming_propagates_writer_failure_without_fetching_later_chunks() {
    struct FailingWriter(Vec<u8>);
    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                self.0.extend_from_slice(&bytes[..11]);
                Ok(11)
            } else {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "export cancelled"))
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            panic!("flushing belongs to the caller");
        }
    }
    let plain = data(CHUNK_SIZE + 1);
    let enc = encrypt_convergent(&plain, b"writer-cancel");
    let mut writer = FailingWriter(Vec::new());
    let mut fetched = 0;
    let result = decrypt_into(
        enc.mode,
        &enc.chunks,
        b"writer-cancel",
        |addr| {
            fetched += 1;
            assert_eq!(fetched, 1, "writer cancellation must stop further fetches");
            assert_eq!(*addr, enc.shards[0].0);
            Ok(enc.shards[0].1.clone())
        },
        &mut writer,
    );
    assert_eq!(
        result,
        Err(SelfEncError::Io { kind: io::ErrorKind::BrokenPipe, message: "export cancelled".into() })
    );
    assert_eq!(writer.0, plain[..11]);
}

#[test]
fn streaming_rejects_a_writer_that_makes_no_progress() {
    let enc = encrypt_convergent(b"nonempty", b"zero-writer");
    // A full slice writer returns Ok(0), which write_all must reject.
    let mut full: &mut [u8] = &mut [];
    let result = decrypt_into(
        enc.mode,
        &enc.chunks,
        b"zero-writer",
        |_| Ok(enc.shards[0].1.clone()),
        &mut full,
    );
    assert!(matches!(result, Err(SelfEncError::Io { kind: io::ErrorKind::WriteZero, .. })));
}

#[test]
fn shard_addresses_are_ciphertext_hashes() {
    let enc = encrypt_convergent(&data(5000), b"s");
    for (addr, ct) in &enc.shards {
        assert_eq!(*addr, b3(ct), "shard address must be BLAKE3(ciphertext)");
    }
}

#[test]
fn salt_changes_every_shard_address() {
    // The same plaintext under a different owner salt produces
    // entirely different shard addresses.
    let d = data(CHUNK_SIZE + 10);
    let a = encrypt_convergent(&d, b"salt-a");
    let b = encrypt_convergent(&d, b"salt-b");
    let addrs_a: Vec<_> = a.chunks.iter().map(|c| c.cipher_addr).collect();
    let addrs_b: Vec<_> = b.chunks.iter().map(|c| c.cipher_addr).collect();
    for (x, y) in addrs_a.iter().zip(&addrs_b) {
        assert_ne!(x, y, "salt must change the shard address");
    }
}

#[test]
fn same_salt_same_content_dedups() {
    let d = data(CHUNK_SIZE + 500);
    let a = encrypt_convergent(&d, b"salt");
    let b = encrypt_convergent(&d, b"salt");
    // Convergent: identical addresses (dedup preserved).
    let aa: Vec<_> = a.chunks.iter().map(|c| c.cipher_addr).collect();
    let bb: Vec<_> = b.chunks.iter().map(|c| c.cipher_addr).collect();
    assert_eq!(aa, bb);
}

#[test]
fn random_key_round_trip_and_no_dedup() {
    let d = data(CHUNK_SIZE * 2);
    let key1 = b3(b"key-one");
    let key2 = b3(b"key-two");
    let a = encrypt_random_key(&d, &key1);
    let b = encrypt_random_key(&d, &key2);
    // Different keys -> different addresses (no cross-key dedup).
    assert_ne!(
        a.chunks[0].cipher_addr, b.chunks[0].cipher_addr,
        "random-key mode must not dedup across keys"
    );
    let shards = shard_map(&a);
    let got = decrypt(a.mode, &a.chunks, &key1, |x| shards.get(x).cloned()).unwrap();
    assert_eq!(got, d);
}

#[test]
fn wrong_key_material_fails_to_decrypt() {
    let d = data(2000);
    let enc = encrypt_convergent(&d, b"right-salt");
    let shards = shard_map(&enc);
    let res = decrypt(enc.mode, &enc.chunks, b"wrong-salt", |a| shards.get(a).cloned());
    assert!(matches!(res, Err(SelfEncError::DecryptFailed(_))));
}

#[test]
fn corrupt_shard_is_rejected() {
    let d = data(3000);
    let enc = encrypt_convergent(&d, b"s");
    let mut shards = shard_map(&enc);
    // Flip a byte in the first shard's ciphertext.
    let addr = enc.chunks[0].cipher_addr;
    shards.get_mut(&addr).unwrap()[0] ^= 1;
    let res = decrypt(enc.mode, &enc.chunks, b"s", |a| shards.get(a).cloned());
    // The address no longer matches BLAKE3(ciphertext).
    assert_eq!(res, Err(SelfEncError::CorruptShard(addr)));
}

#[test]
fn datamap_seals_and_opens() {
    let d = data(CHUNK_SIZE + 77);
    let enc = encrypt_convergent(&d, b"salt");
    let vk = b3(b"viewing-key");
    let (addr, sealed) = seal_datamap(&enc.chunks, enc.mode, &vk);
    assert_eq!(addr, b3(&sealed), "sealed data-map is content-addressed");
    let (chunks, mode) = open_datamap(&sealed, &vk).unwrap();
    assert_eq!(mode, Mode::SaltedConvergent);
    assert_eq!(chunks, enc.chunks);
    // Wrong viewing key fails.
    assert_eq!(open_datamap(&sealed, &b3(b"nope")), Err(SelfEncError::DatamapDecryptFailed));
}

#[test]
fn full_bootstrap_round_trip() {
    // The complete flow: viewing key -> sealed data-map -> chunk list
    // -> fetch+decrypt shards -> plaintext.
    let d = data(CHUNK_SIZE * 3 + 9);
    let salt = b"owner-salt";
    let enc = encrypt_convergent(&d, salt);
    let vk = b3(b"vk");
    let (_addr, sealed) = seal_datamap(&enc.chunks, enc.mode, &vk);
    let store = shard_map(&enc);

    // A reader who has the viewing key + salt + sealed data-map:
    let (chunks, mode) = open_datamap(&sealed, &vk).unwrap();
    let got = decrypt(mode, &chunks, salt, |a| store.get(a).cloned()).unwrap();
    assert_eq!(got, d);
}

#[test]
fn empty_file_round_trips() {
    let enc = encrypt_convergent(b"", b"s");
    let shards = shard_map(&enc);
    let got = decrypt(enc.mode, &enc.chunks, b"s", |a| shards.get(a).cloned()).unwrap();
    assert_eq!(got, b"");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Known-answer test: hard-coded frozen vectors, NOT recomputed at test
/// time. These hex literals were generated once from this
/// implementation and pinned, so any change to the KDF context, key
/// layout, nonce schedule, AEAD, or data-map serialization makes this
/// fail loudly. Regenerating them is a deliberate format revision (bump
/// KDF_CONTEXT). Salt "kat-salt" over a deterministic 3-chunk input.
#[test]
fn known_answer_vectors() {
    let d = data(CHUNK_SIZE * 2 + 500);
    let enc = encrypt_convergent(&d, b"kat-salt");
    assert_eq!(enc.chunks.len(), 3);

    const PLAIN_HASHES: [&str; 3] = [
        "40da47a7aa27ad6b41b2dc55bf5020d88893783d4dfc79f4ba898157aad29fdd",
        "8af4b10c2d2184f85e6a162634a8e34696d6bf8dfc5062403fbd8a77844e6e83",
        "dd18f979a836f326e9458cf61f4fe6e887dd4ccce6fff693cbcb4cd4869db067",
    ];
    const CIPHER_ADDRS: [&str; 3] = [
        "ef623e66e8c63d263b588da356fd2010482bbb07b7306ebe5b298d9065f5ce8e",
        "eb488a5615b4096785278b67b94deae3f35e15895cc633ef6c22b50d282c9ec2",
        "9a230413c7cad30456a1868dcb8922e42ce36b92f64f8f892553d79fa48daede",
    ];
    for (i, c) in enc.chunks.iter().enumerate() {
        assert_eq!(hex(&c.plain_hash), PLAIN_HASHES[i], "chunk {i} plain hash drifted");
        assert_eq!(hex(&c.cipher_addr), CIPHER_ADDRS[i], "chunk {i} shard address drifted");
    }

    // The convergent data-map serialization must be byte-frozen.
    const DATAMAP_HEX: &str = "000300000040da47a7aa27ad6b41b2dc55bf5020d88893783d4dfc79f4ba898157aad29fddef623e66e8c63d263b588da356fd2010482bbb07b7306ebe5b298d9065f5ce8e000010008af4b10c2d2184f85e6a162634a8e34696d6bf8dfc5062403fbd8a77844e6e83eb488a5615b4096785278b67b94deae3f35e15895cc633ef6c22b50d282c9ec200001000dd18f979a836f326e9458cf61f4fe6e887dd4ccce6fff693cbcb4cd4869db0679a230413c7cad30456a1868dcb8922e42ce36b92f64f8f892553d79fa48daedef4010000";
    assert_eq!(
        hex(&serialize_datamap(&enc.chunks, enc.mode)),
        DATAMAP_HEX,
        "data-map wire format drifted"
    );

    // And it must still decrypt end to end.
    let shards = shard_map(&enc);
    assert_eq!(decrypt(enc.mode, &enc.chunks, b"kat-salt", |a| shards.get(a).cloned()).unwrap(), d);
}

/// Regression for the data-map nonce-reuse bug: sealing under one
/// viewing key must draw a fresh random nonce every time, so re-sealing
/// (an updated or even identical data-map for the same readers) never
/// reuses the (key, nonce) pair. With the old constant nonce, identical
/// input produced byte-identical sealed blobs — keystream reuse.
#[test]
fn datamap_seal_uses_fresh_nonce_no_reuse() {
    let vk = b3(b"viewing-key");
    let enc1 = encrypt_convergent(&data(1000), b"salt");
    let enc2 = encrypt_convergent(&data(2000), b"salt-two");
    assert_ne!(enc1.chunks, enc2.chunks, "test needs two distinct data-maps");

    // Two DIFFERENT data-maps under the SAME key: distinct blobs.
    let (_a1, s1) = seal_datamap(&enc1.chunks, enc1.mode, &vk);
    let (_a2, s2) = seal_datamap(&enc2.chunks, enc2.mode, &vk);
    assert_ne!(s1, s2);

    // The IDENTICAL data-map sealed twice must still differ, because the
    // nonce is random per call (this is what the constant-nonce code got
    // wrong). Compare the 24-byte nonce prefixes directly.
    let (_a3, s3) = seal_datamap(&enc1.chunks, enc1.mode, &vk);
    let (_a4, s4) = seal_datamap(&enc1.chunks, enc1.mode, &vk);
    assert_ne!(s3[..24], s4[..24], "re-sealing must draw a fresh nonce, not reuse it");
    assert_ne!(s3, s4, "re-sealing identical input must not produce identical bytes");

    // Every sealed blob still round-trips and is content-addressed.
    for (chunks, mode, sealed) in [
        (&enc1.chunks, enc1.mode, &s1),
        (&enc2.chunks, enc2.mode, &s2),
        (&enc1.chunks, enc1.mode, &s3),
    ] {
        let (got, got_mode) = open_datamap(sealed, &vk).unwrap();
        assert_eq!(&got, chunks);
        assert_eq!(got_mode, mode);
    }
}

/// Regression for the data-map count overflow: the entry count is
/// attacker-influenced, so the body-length check must not wrap. On
/// 32-bit targets `count * 68` in usize wrapped for
/// count = 63_161_284 (68 * count = 2^32 + 16), letting a 16-byte body
/// pass and then asking for a ~4.3 GB allocation. The widened compare
/// rejects every mismatch on both widths.
#[test]
fn deserialize_rejects_bogus_count() {
    let cases: [(u32, usize); 4] = [
        // 68 * count == 2^32 + 16, the wrapping case.
        (63_161_284, 16),
        (u32::MAX, 68),
        // Plain mismatches that must stay rejected.
        (2, 68),
        (0, 68),
    ];
    for (count, body_len) in cases {
        assert!(
            !body_len_matches(count, body_len),
            "count {count} must not match a {body_len}-byte body"
        );
        let mut bytes = vec![0u8]; // mode = SaltedConvergent
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.resize(bytes.len() + body_len, 0);
        assert_eq!(
            deserialize_datamap(&bytes),
            Err(SelfEncError::MalformedDatamap),
            "count {count} with a {body_len}-byte body must be rejected"
        );
    }

    // A well-formed data-map still parses.
    let enc = encrypt_convergent(&data(CHUNK_SIZE + 3), b"salt");
    let wire = serialize_datamap(&enc.chunks, enc.mode);
    assert_eq!(deserialize_datamap(&wire).unwrap(), (enc.chunks, enc.mode));
}

/// The wrap the widened check exists to stop. On a 64-bit host the old
/// `count * 68` in usize happens to reject the same inputs, so
/// `deserialize_rejects_bogus_count` alone cannot show the difference
/// there. This pins it by modelling the 32-bit product directly, so the
/// divergence is asserted on every target CI builds.
#[test]
fn body_len_check_does_not_wrap_on_32_bit() {
    // What `body.len() != count * 68` computed when usize is 32 bits.
    fn matches_in_32_bit_usize(count: u32, body_len: usize) -> bool {
        body_len as u32 == count.wrapping_mul(68)
    }
    // 68 * 63_161_284 == 2^32 + 16: the 32-bit product is 16, so the old
    // check accepted a 16-byte body and then asked for ~4.3 GB.
    assert!(
        matches_in_32_bit_usize(63_161_284, 16),
        "vector must be the one a 32-bit multiply mis-accepts"
    );
    assert!(!body_len_matches(63_161_284, 16), "the widened check must reject it");
    // Honest lengths agree on both widths, so nothing legitimate is lost.
    for count in [0u32, 1, 2, 100, 1000] {
        let body_len = count as usize * 68;
        assert!(body_len_matches(count, body_len), "count {count} must accept its own body");
        assert!(matches_in_32_bit_usize(count, body_len));
    }
}
