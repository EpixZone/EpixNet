//! Clean-room self-encryption for EDX shards.
//!
//! A file in the shard namespace is split into sub-chunks, each encrypted
//! with a key derived from content hashes (plus an owner salt), and each
//! ciphertext chunk is addressed by `BLAKE3(ciphertext)` — the shard
//! address. A cache node can store and integrity-check shards by their
//! address without the decryption key, and identical content from the
//! same owner deduplicates.
//!
//! Two modes (see [`Mode`]):
//!
//! - [`Mode::SaltedConvergent`] — dedup-preserving. Each chunk's key is
//!   derived from its own plaintext hash, its two predecessors' hashes,
//!   its index, and the owner salt (which changes the ciphertext address
//!   per owner so caches that never learned the xite address cannot
//!   recompute it from known plaintext). Deduplicates across an owner's
//!   content.
//! - [`Mode::RandomKey`] — a random per-file key; no dedup, but the only
//!   sound choice for guessable/low-entropy content and the only mode
//!   supporting revocation (rotate the key, stop distributing wraps).
//!
//! **Data-map bootstrap.** A data-map is a list of content-derived
//! hashes, not derivable from a key alone. So the outer data-map is
//! ordinary symmetric ciphertext under a key derived from the viewing
//! key, addressed by the hash of that ciphertext — one decryption yields
//! the chunk list. No convergence at the outer layer (that would be
//! circular). See [`seal_datamap`] / [`open_datamap`].
//!
//! Per-chunk nonces are deterministic and domain-separated (`nonce_for`),
//! which is safe because every convergent/random-key chunk key is
//! single-use for exactly one chunk, so that (key, nonce) never repeats.
//! The data-map seal reuses one viewing-key-derived key across every
//! re-seal, so it does NOT get a deterministic nonce: [`seal_datamap`]
//! draws a fresh random 24-byte nonce per call and stores it alongside
//! the ciphertext. See `PROVENANCE.md` (clean-room).

#![forbid(unsafe_code)]

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// How a shard-namespace file is encrypted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Content-derived keys salted with the owner's xite salt.
    /// Dedup-preserving; confirmable by anyone holding the xite address.
    SaltedConvergent,
    /// Random per-file key, wrapped per recipient. Revocable; no dedup.
    RandomKey,
}

/// Domain-separation context for every key this crate derives.
/// Part of the frozen format — never change without a version bump.
pub const KDF_CONTEXT: &str = "epixnet-selfenc-v1";

/// Sub-chunk size: files are split into this many bytes per chunk (the
/// final chunk may be shorter). Part of the frozen format.
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// A 32-byte content/address value.
pub type Hash = [u8; 32];

fn b3(data: &[u8]) -> Hash {
    *blake3::hash(data).as_bytes()
}

/// One chunk's data-map entry: plaintext hash (identity/verify), cipher
/// address (BLAKE3 of ciphertext = where it's stored), and plaintext len.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkRef {
    pub plain_hash: Hash,
    pub cipher_addr: Hash,
    pub len: u32,
}

/// The result of encrypting a file: the ordered chunk refs (the data-map)
/// and the ciphertext shards to store, each keyed by its address.
#[derive(Clone, Debug)]
pub struct Encrypted {
    pub mode: Mode,
    pub chunks: Vec<ChunkRef>,
    /// (address, ciphertext) for every shard; address == BLAKE3(ciphertext).
    pub shards: Vec<(Hash, Vec<u8>)>,
    /// For RandomKey mode: the file key that must be wrapped per recipient
    /// (None for SaltedConvergent, whose keys are content-derived).
    pub file_key: Option<Hash>,
}

/// Deterministic per-chunk nonce. Safe because each derived key encrypts
/// exactly one chunk, so (key, nonce) is globally unique. Domain-tagged
/// with `NONCE_CHUNK` so the tag byte is pinned as part of the frozen
/// format. The data-map seal does not use this (it draws a random nonce).
fn nonce_for(tag: u8, index: u64) -> XNonce {
    let mut n = [0u8; 24];
    n[0] = tag;
    n[1..9].copy_from_slice(&index.to_le_bytes());
    XNonce::from(n)
}

const NONCE_CHUNK: u8 = 1;

/// Derive a salted-convergent chunk key from content hashes.
/// `key_i = BLAKE3::derive_key(ctx, salt ‖ own ‖ prev1 ‖ prev2 ‖ le64(i))`.
fn convergent_key(salt: &[u8], own: &Hash, prev1: &Hash, prev2: &Hash, i: u64) -> Hash {
    let mut material = Vec::with_capacity(salt.len() + 32 * 3 + 8);
    material.extend_from_slice(salt);
    material.extend_from_slice(own);
    material.extend_from_slice(prev1);
    material.extend_from_slice(prev2);
    material.extend_from_slice(&i.to_le_bytes());
    blake3::derive_key(KDF_CONTEXT, &material)
}

fn aead(key: &Hash) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&(*key).into())
}

/// Encrypt `data` in [`Mode::SaltedConvergent`] under the owner `salt`.
/// The salt is supplied to `decrypt` as key material; a reader obtains it
/// with the owner's viewing material, so it is not secret from anyone who
/// can resolve the xite.
pub fn encrypt_convergent(data: &[u8], salt: &[u8]) -> Encrypted {
    let plain_chunks = split(data);
    // Precompute plaintext hashes (needed as predecessors).
    let hashes: Vec<Hash> = plain_chunks.iter().map(|c| b3(c)).collect();
    let zero = [0u8; 32];

    let mut chunks = Vec::with_capacity(plain_chunks.len());
    let mut shards = Vec::with_capacity(plain_chunks.len());
    for (i, chunk) in plain_chunks.iter().enumerate() {
        let own = &hashes[i];
        let prev1 = if i >= 1 { &hashes[i - 1] } else { &zero };
        let prev2 = if i >= 2 { &hashes[i - 2] } else { &zero };
        let key = convergent_key(salt, own, prev1, prev2, i as u64);
        let ct = aead(&key)
            .encrypt(&nonce_for(NONCE_CHUNK, i as u64), chunk.as_slice())
            .expect("xchacha encrypt");
        let addr = b3(&ct);
        chunks.push(ChunkRef { plain_hash: *own, cipher_addr: addr, len: chunk.len() as u32 });
        shards.push((addr, ct));
    }
    Encrypted { mode: Mode::SaltedConvergent, chunks, shards, file_key: None }
}

/// Encrypt `data` in [`Mode::RandomKey`] under a caller-supplied random
/// `file_key` (32 bytes). No dedup; the key must be wrapped per recipient
/// and can be rotated to revoke.
pub fn encrypt_random_key(data: &[u8], file_key: &Hash) -> Encrypted {
    let plain_chunks = split(data);
    let mut chunks = Vec::with_capacity(plain_chunks.len());
    let mut shards = Vec::with_capacity(plain_chunks.len());
    for (i, chunk) in plain_chunks.iter().enumerate() {
        // Per-chunk subkey from the file key + index, so one nonce reuse
        // across chunks is impossible even with a fixed file key.
        let key = blake3::derive_key(KDF_CONTEXT, &[file_key.as_slice(), &(i as u64).to_le_bytes()].concat());
        let ct = aead(&key)
            .encrypt(&nonce_for(NONCE_CHUNK, i as u64), chunk.as_slice())
            .expect("xchacha encrypt");
        let addr = b3(&ct);
        chunks.push(ChunkRef { plain_hash: b3(chunk), cipher_addr: addr, len: chunk.len() as u32 });
        shards.push((addr, ct));
    }
    Encrypted { mode: Mode::RandomKey, chunks, shards, file_key: Some(*file_key) }
}

/// Reassemble plaintext from the data-map + a shard fetcher.
///
/// `fetch(addr)` returns the ciphertext shard at `addr` (from the store
/// or the swarm). For convergent mode `key_material` is the owner salt;
/// for random-key mode it is the file key. Every chunk is verified
/// against its `plain_hash` after decrypt.
pub fn decrypt(
    mode: Mode,
    chunks: &[ChunkRef],
    key_material: &[u8],
    mut fetch: impl FnMut(&Hash) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, SelfEncError> {
    let mut out = Vec::new();
    let zero = [0u8; 32];
    for (i, chunk) in chunks.iter().enumerate() {
        let ct = fetch(&chunk.cipher_addr).ok_or(SelfEncError::MissingShard(chunk.cipher_addr))?;
        if b3(&ct) != chunk.cipher_addr {
            return Err(SelfEncError::CorruptShard(chunk.cipher_addr));
        }
        let key = match mode {
            Mode::SaltedConvergent => {
                let prev1 = if i >= 1 { &chunks[i - 1].plain_hash } else { &zero };
                let prev2 = if i >= 2 { &chunks[i - 2].plain_hash } else { &zero };
                convergent_key(key_material, &chunk.plain_hash, prev1, prev2, i as u64)
            }
            Mode::RandomKey => {
                blake3::derive_key(KDF_CONTEXT, &[key_material, &(i as u64).to_le_bytes()].concat())
            }
        };
        let pt = aead(&key)
            .decrypt(&nonce_for(NONCE_CHUNK, i as u64), ct.as_slice())
            .map_err(|_| SelfEncError::DecryptFailed(i))?;
        if b3(&pt) != chunk.plain_hash {
            return Err(SelfEncError::PlaintextHashMismatch(i));
        }
        out.extend_from_slice(&pt);
    }
    Ok(out)
}

/// Serialize + symmetrically encrypt a data-map (the outer bootstrap
/// layer). Key is derived from the viewing key; the sealed bytes are
/// content-addressed by their own hash (returned). This is ordinary
/// symmetric ciphertext — NOT convergent — because a data-map cannot be
/// convergently addressed without circularity.
///
/// The derived key is the SAME every time a given viewing key re-seals a
/// data-map, so the nonce must NOT be deterministic: re-sealing an updated
/// data-map under the same viewing key with a fixed nonce would reuse the
/// (key, nonce) pair across different plaintext, which is catastrophic for
/// XChaCha20-Poly1305. So a fresh random 24-byte nonce is drawn per call
/// and prepended to the ciphertext.
///
/// Sealed format: `nonce(24) ‖ ciphertext`, addressed by `BLAKE3` of the
/// whole blob.
pub fn seal_datamap(chunks: &[ChunkRef], mode: Mode, viewing_key: &Hash) -> (Hash, Vec<u8>) {
    let plain = serialize_datamap(chunks, mode);
    let key = blake3::derive_key(KDF_CONTEXT, &[viewing_key.as_slice(), b"datamap"].concat());
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).expect("os csprng");
    let ct = aead(&key).encrypt(&XNonce::from(nonce), plain.as_slice()).expect("seal");
    let mut sealed = Vec::with_capacity(24 + ct.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ct);
    (b3(&sealed), sealed)
}

/// Inverse of [`seal_datamap`]. Splits the 24-byte random nonce prefix
/// from the ciphertext.
pub fn open_datamap(sealed: &[u8], viewing_key: &Hash) -> Result<(Vec<ChunkRef>, Mode), SelfEncError> {
    if sealed.len() < 24 {
        return Err(SelfEncError::DatamapDecryptFailed);
    }
    let (nonce, ct) = sealed.split_at(24);
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes.copy_from_slice(nonce);
    let key = blake3::derive_key(KDF_CONTEXT, &[viewing_key.as_slice(), b"datamap"].concat());
    let plain = aead(&key)
        .decrypt(&XNonce::from(nonce_bytes), ct)
        .map_err(|_| SelfEncError::DatamapDecryptFailed)?;
    deserialize_datamap(&plain)
}

fn split(data: &[u8]) -> Vec<Vec<u8>> {
    if data.is_empty() {
        return vec![Vec::new()];
    }
    data.chunks(CHUNK_SIZE).map(<[u8]>::to_vec).collect()
}

/// Frozen data-map wire format: `mode(1) ‖ count(u32 LE) ‖
/// [plain_hash(32) ‖ cipher_addr(32) ‖ len(u32 LE)]*`.
fn serialize_datamap(chunks: &[ChunkRef], mode: Mode) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + chunks.len() * 68);
    out.push(match mode {
        Mode::SaltedConvergent => 0,
        Mode::RandomKey => 1,
    });
    out.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
    for c in chunks {
        out.extend_from_slice(&c.plain_hash);
        out.extend_from_slice(&c.cipher_addr);
        out.extend_from_slice(&c.len.to_le_bytes());
    }
    out
}

/// Whether a `body_len`-byte data-map body holds exactly `count` 68-byte
/// entries. The product is taken in u64 because `count * 68` in usize wraps
/// on 32-bit targets (count is attacker-supplied), which would let a short
/// body pass and then over-allocate. A true result also bounds
/// `count <= body_len / 68` on every width.
fn body_len_matches(count: u32, body_len: usize) -> bool {
    body_len as u64 == count as u64 * 68
}

fn deserialize_datamap(bytes: &[u8]) -> Result<(Vec<ChunkRef>, Mode), SelfEncError> {
    if bytes.len() < 5 {
        return Err(SelfEncError::MalformedDatamap);
    }
    let mode = match bytes[0] {
        0 => Mode::SaltedConvergent,
        1 => Mode::RandomKey,
        _ => return Err(SelfEncError::MalformedDatamap),
    };
    let count = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
    let body = &bytes[5..];
    if !body_len_matches(count, body.len()) {
        return Err(SelfEncError::MalformedDatamap);
    }
    // Bounded by the check above, so `i * 68` below stays inside `body`.
    let count = count as usize;
    let mut chunks = Vec::with_capacity(count);
    for i in 0..count {
        let o = i * 68;
        let mut plain_hash = [0u8; 32];
        let mut cipher_addr = [0u8; 32];
        plain_hash.copy_from_slice(&body[o..o + 32]);
        cipher_addr.copy_from_slice(&body[o + 32..o + 64]);
        let len = u32::from_le_bytes(body[o + 64..o + 68].try_into().unwrap());
        chunks.push(ChunkRef { plain_hash, cipher_addr, len });
    }
    Ok((chunks, mode))
}

/// Errors from the self-encryption layer.
#[derive(Debug, PartialEq, Eq)]
pub enum SelfEncError {
    MissingShard(Hash),
    CorruptShard(Hash),
    DecryptFailed(usize),
    PlaintextHashMismatch(usize),
    DatamapDecryptFailed,
    MalformedDatamap,
}

impl std::fmt::Display for SelfEncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SelfEncError {}

#[cfg(test)]
mod tests;
