//! The `edx: 1` content.json evolution: per-file BLAKE3 roots, bundle
//! references, and the files merkle root.
//!
//! The signing model is untouched — these are plain JSON fields folded
//! into the signed payload (unknown fields are already accepted by every
//! verifier), added at signing time and read at fetch time:
//!
//! ```jsonc
//! "edx": 1,
//! "files": {
//!   "index.html": {"size": 5120, "sha512": "…",             // legacy, migration window
//!                   "b3": "…", "bundle": "…", "off": 0},     // EDX
//!   "movie.mp4":  {"size": 734003200, "sha512": "…", "b3": "…"}
//! },
//! "bundles": {"<b3 hex>": {"size": 262144, "seq": 0}},
//! "files_merkle_root": "<hex>"
//! ```
//!
//! A bundled file's `b3` is the hash of ITS OWN bytes (so cross-xite
//! dedup and whole-file verification work no matter how it is packed);
//! `bundle` + `off` locate those bytes inside the bundle object. The
//! merkle root commits to the (path, b3, size) set — the format is
//! specified in docs/edx-manifest.md and frozen by golden tests.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::bundle::BundleResult;
use crate::ObjId;

/// The manifest generation this build writes.
pub const EDX_VERSION: u64 = 1;

/// One file's EDX entry, as read back from a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdxEntry {
    pub size: u64,
    pub b3: ObjId,
    /// Present iff the file lives inside a bundle.
    pub bundle: Option<BundleRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleRef {
    pub id: ObjId,
    pub off: u64,
}

/// Whether a parsed content.json declares EDX support.
pub fn edx_version(content: &Value) -> Option<u64> {
    content.get("edx").and_then(Value::as_u64)
}

/// Read one file's EDX entry (`files` then `files_optional`).
pub fn edx_entry(content: &Value, inner_path: &str) -> Option<EdxEntry> {
    let entry = ["files", "files_optional"]
        .iter()
        .find_map(|k| content.get(k).and_then(|f| f.get(inner_path)))?;
    parse_entry(entry, content)
}

fn parse_entry(entry: &Value, content: &Value) -> Option<EdxEntry> {
    let size = entry.get("size").and_then(Value::as_u64)?;
    let b3 = ObjId::from_hex(entry.get("b3")?.as_str()?)?;
    let bundle = match entry.get("bundle") {
        Some(b) => {
            let id = ObjId::from_hex(b.as_str()?)?;
            // The bundle must be declared (its size is needed to fetch it).
            content.get("bundles")?.get(b.as_str()?)?;
            let off = entry.get("off").and_then(Value::as_u64)?;
            Some(BundleRef { id, off })
        }
        None => None,
    };
    Some(EdxEntry { size, b3, bundle })
}

/// One chunk of an encrypted-shard file's data-map: the plaintext hash
/// (for post-decrypt verification), the ciphertext object address (where
/// the shard is stored/fetched), and the plaintext length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardChunk {
    pub plain_hash: [u8; 32],
    pub cipher_addr: ObjId,
    /// Plaintext length of this chunk.
    pub len: u32,
    /// Ciphertext object length (what the fetcher must request for the
    /// content-addressed shard at `cipher_addr`).
    pub csize: u32,
}

/// A private/encrypted file's manifest entry: the plaintext size, the
/// self-encryption mode, and the ordered chunk data-map. The data-map lives
/// in the (signed) content.json, so a reader who resolves the xite can
/// decrypt, while a volunteer that only holds ciphertext shards by hash
/// (and no content.json) cannot map or read them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardEntry {
    pub size: u64,
    /// 0 = salted-convergent (dedup, keyed by the xite salt), 1 = random-key.
    pub mode: u8,
    pub chunks: Vec<ShardChunk>,
}

/// The owner salt for salted-convergent shards (from `edx_salt`, hex).
pub fn edx_salt(content: &Value) -> Option<Vec<u8>> {
    let hex = content.get("edx_salt")?.as_str()?;
    // The value comes from a remote (owner-signed, but unvalidated)
    // content.json: reject odd lengths here and use `get` below so a
    // multi-byte char cannot slice off a char boundary.
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| hex.get(i..i + 2).and_then(|p| u8::from_str_radix(p, 16).ok()))
        .collect()
}

/// Read one file's encrypted-shard entry from `files_shard`.
pub fn edx_shard_entry(content: &Value, inner_path: &str) -> Option<ShardEntry> {
    let e = content.get("files_shard")?.get(inner_path)?;
    let size = e.get("size").and_then(Value::as_u64)?;
    let mode = e.get("mode").and_then(Value::as_u64).unwrap_or(0) as u8;
    let arr = e.get("chunks")?.as_array()?;
    let mut chunks = Vec::with_capacity(arr.len());
    for c in arr {
        let mut plain_hash = [0u8; 32];
        let ph = c.get("ph")?.as_str()?;
        for (i, b) in plain_hash.iter_mut().enumerate() {
            *b = u8::from_str_radix(ph.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        let cipher_addr = ObjId::from_hex(c.get("ca")?.as_str()?)?;
        let len = c.get("len").and_then(Value::as_u64)? as u32;
        let csize = c.get("cs").and_then(Value::as_u64)? as u32;
        chunks.push(ShardChunk { plain_hash, cipher_addr, len, csize });
    }
    Some(ShardEntry { size, mode, chunks })
}

/// Write a file's shard entry into `files_shard` (used at signing time).
pub fn set_shard_entry(content: &mut Value, inner_path: &str, entry: &ShardEntry) {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let chunks: Vec<Value> = entry
        .chunks
        .iter()
        .map(|c| json!({ "ph": hex(&c.plain_hash), "ca": c.cipher_addr.to_string(), "len": c.len, "cs": c.csize }))
        .collect();
    let obj = content.as_object_mut().expect("content object");
    obj.entry("files_shard").or_insert_with(|| json!({})).as_object_mut().unwrap().insert(
        inner_path.to_string(),
        json!({ "size": entry.size, "mode": entry.mode, "chunks": chunks }),
    );
}

/// Every declared bundle: id -> size.
pub fn bundles(content: &Value) -> BTreeMap<ObjId, u64> {
    let mut out = BTreeMap::new();
    if let Some(Value::Object(map)) = content.get("bundles") {
        for (hex, meta) in map {
            if let (Some(id), Some(size)) =
                (ObjId::from_hex(hex), meta.get("size").and_then(Value::as_u64))
            {
                out.insert(id, size);
            }
        }
    }
    out
}

/// The previous bundle memberships, reconstructed from a manifest (for
/// stable re-assignment at the next signing). Ordered by bundle creation
/// order (the persisted `seq`), members ordered by their offset.
pub fn prev_memberships(content: &Value) -> Vec<Vec<String>> {
    // bundle hex -> [(off, path)]
    let mut by_bundle: BTreeMap<String, Vec<(u64, String)>> = BTreeMap::new();
    let mut bundle_order: Vec<String> = Vec::new();
    if let Some(Value::Object(map)) = content.get("bundles") {
        // Order by the persisted `seq` (creation order). Legacy manifests
        // have no `seq`; fall back to the map's key order (hex-sorted) so
        // they still parse, keyed by enumeration index to keep it stable.
        let mut ordered: Vec<(u64, usize, String)> = map
            .keys()
            .enumerate()
            .map(|(i, hex)| {
                let seq = map[hex].get("seq").and_then(Value::as_u64).unwrap_or(i as u64);
                (seq, i, hex.clone())
            })
            .collect();
        ordered.sort();
        bundle_order = ordered.into_iter().map(|(_, _, hex)| hex).collect();
    }
    for key in ["files", "files_optional"] {
        if let Some(Value::Object(files)) = content.get(key) {
            for (path, entry) in files {
                if let (Some(bundle), Some(off)) = (
                    entry.get("bundle").and_then(Value::as_str),
                    entry.get("off").and_then(Value::as_u64),
                ) {
                    by_bundle.entry(bundle.to_string()).or_default().push((off, path.clone()));
                }
            }
        }
    }
    bundle_order
        .iter()
        .filter_map(|b| {
            let mut members = by_bundle.remove(b)?;
            members.sort();
            Some(members.into_iter().map(|(_, p)| p).collect())
        })
        .collect()
}

/// Compute the files merkle root over (path, b3, size) triples.
///
/// Frozen format (docs/edx-manifest.md): leaves sorted by path bytes;
/// leaf hash = BLAKE3(0x00 ‖ le32(len(path)) ‖ path ‖ b3 ‖ le64(size));
/// parent = BLAKE3(0x01 ‖ left ‖ right); an odd node is promoted
/// unhashed; the empty set is 32 zero bytes.
pub fn files_merkle_root(entries: &BTreeMap<String, (ObjId, u64)>) -> ObjId {
    let mut level: Vec<[u8; 32]> = entries
        .iter()
        .map(|(path, (b3, size))| {
            let mut h = blake3::Hasher::new();
            h.update(&[0x00]);
            h.update(&(path.len() as u32).to_le_bytes());
            h.update(path.as_bytes());
            h.update(&b3.0);
            h.update(&size.to_le_bytes());
            *h.finalize().as_bytes()
        })
        .collect();
    if level.is_empty() {
        return ObjId([0u8; 32]);
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [left, right] => {
                    let mut h = blake3::Hasher::new();
                    h.update(&[0x01]);
                    h.update(left);
                    h.update(right);
                    *h.finalize().as_bytes()
                }
                [odd] => *odd,
                _ => unreachable!(),
            })
            .collect();
    }
    ObjId(level[0])
}

/// Apply the EDX fields to a content.json about to be signed:
///
/// - every entry in `files`/`files_optional` gains its `b3` (from
///   `roots`: path -> per-file BLAKE3 root);
/// - bundled files gain `bundle` + `off` from the assignment;
/// - `bundles` and `files_merkle_root` are (re)written;
/// - `edx` is set to [`EDX_VERSION`].
///
/// Legacy `sha512`/`size` fields are left exactly as they are (the
/// migration window needs both). Files without an entry in `roots` are
/// left untouched. Returns the merkle root that was written.
pub fn apply_edx(
    content: &mut Value,
    roots: &BTreeMap<String, ObjId>,
    assignment: &BundleResult,
) -> Option<ObjId> {
    let obj = content.as_object_mut()?;

    let mut merkle_entries: BTreeMap<String, (ObjId, u64)> = BTreeMap::new();
    for key in ["files", "files_optional"] {
        let Some(Value::Object(files)) = obj.get_mut(key) else { continue };
        for (path, entry) in files.iter_mut() {
            let Some(e) = entry.as_object_mut() else { continue };
            let Some(root) = roots.get(path) else { continue };
            let size = e.get("size").and_then(Value::as_u64).unwrap_or(0);
            e.insert("b3".into(), json!(root.to_string()));
            match assignment.members.get(path) {
                Some((idx, off, _len)) => {
                    let bundle = &assignment.bundles[*idx];
                    e.insert("bundle".into(), json!(bundle.id.to_string()));
                    e.insert("off".into(), json!(off));
                }
                None => {
                    e.remove("bundle");
                    e.remove("off");
                }
            }
            merkle_entries.insert(path.clone(), (*root, size));
        }
    }

    let mut bundles_json = Map::new();
    for (i, b) in assignment.bundles.iter().enumerate() {
        // `seq` records the assignment (creation) order so re-signing can
        // recover it: the JSON object is a BTreeMap here and would
        // otherwise iterate in hex-id order, not creation order.
        bundles_json.insert(
            b.id.to_string(),
            json!({"size": b.bytes.len() as u64, "seq": i as u64}),
        );
    }
    if bundles_json.is_empty() {
        obj.remove("bundles");
    } else {
        obj.insert("bundles".into(), Value::Object(bundles_json));
    }

    let root = files_merkle_root(&merkle_entries);
    obj.insert("files_merkle_root".into(), json!(root.to_string()));
    obj.insert("edx".into(), json!(EDX_VERSION));
    Some(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle;

    fn sample_files() -> BTreeMap<String, Vec<u8>> {
        [
            ("css/all.css", 3000usize),
            ("index.html", 1500),
            ("js/app.js", 8000),
        ]
        .iter()
        .map(|(p, n)| (p.to_string(), vec![blake3::hash(p.as_bytes()).as_bytes()[0]; *n]))
        .collect()
    }

    fn manifest_for(files: &BTreeMap<String, Vec<u8>>) -> (Value, BundleResult) {
        let mut content = json!({
            "address": "epix1xite",
            "files": files
                .iter()
                .map(|(p, b)| (p.clone(), json!({"sha512": "aa", "size": b.len()})))
                .collect::<Map<String, Value>>(),
            "modified": 1,
        });
        let assignment = bundle::assign(files, &[]);
        let roots: BTreeMap<String, ObjId> = files
            .iter()
            .map(|(p, b)| (p.clone(), ObjId(*blake3::hash(b).as_bytes())))
            .collect();
        apply_edx(&mut content, &roots, &assignment).unwrap();
        (content, assignment)
    }

    #[test]
    fn apply_then_read_back() {
        let files = sample_files();
        let (content, assignment) = manifest_for(&files);
        assert_eq!(edx_version(&content), Some(EDX_VERSION));

        for (path, bytes) in &files {
            let e = edx_entry(&content, path).expect(path);
            assert_eq!(e.size, bytes.len() as u64);
            assert_eq!(e.b3, ObjId(*blake3::hash(bytes).as_bytes()));
            let (idx, off, _) = assignment.members[path];
            let b = e.bundle.expect("small files are bundled");
            assert_eq!(b.id, assignment.bundles[idx].id);
            assert_eq!(b.off, off);
        }
        // Legacy fields preserved.
        assert_eq!(content["files"]["index.html"]["sha512"], json!("aa"));
        // Declared bundles match the assignment.
        assert_eq!(bundles(&content).len(), assignment.bundles.len());
    }

    #[test]
    fn memberships_round_trip_through_manifest() {
        let files = sample_files();
        let (content, assignment) = manifest_for(&files);
        let prev = prev_memberships(&content);
        let expected: Vec<Vec<String>> =
            assignment.bundles.iter().map(|b| b.members.clone()).collect();
        assert_eq!(prev, expected);
        // Re-assigning with the recovered memberships is a fixpoint.
        let again = bundle::assign(&files, &prev);
        assert_eq!(
            again.bundles.iter().map(|b| b.id).collect::<Vec<_>>(),
            assignment.bundles.iter().map(|b| b.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn membership_order_survives_round_trip() {
        // Nine ~100 KiB files pack into three 256 KiB bundles, so the
        // recovered order is not a single bundle where order is moot.
        let files: BTreeMap<String, Vec<u8>> = (0..9)
            .map(|i| {
                let p = format!("m/f{i:02}.bin");
                let seed = blake3::hash(p.as_bytes());
                (p, vec![seed.as_bytes()[0]; 100_000])
            })
            .collect();
        let (content, assignment) = manifest_for(&files);
        assert!(
            assignment.bundles.len() >= 3,
            "want 3+ bundles, got {}",
            assignment.bundles.len()
        );

        // The recovered order must equal the bundler's creation order, NOT
        // the hex-id order the JSON object iterates in. Guard that the two
        // actually differ so this test exercises the reordering.
        let creation: Vec<ObjId> = assignment.bundles.iter().map(|b| b.id).collect();
        let mut hex_sorted = creation.clone();
        hex_sorted.sort_by_key(|id| id.to_string());
        assert_ne!(creation, hex_sorted, "corpus must exercise hex-vs-creation order");

        let expected: Vec<Vec<String>> =
            assignment.bundles.iter().map(|b| b.members.clone()).collect();
        let prev = prev_memberships(&content);
        assert_eq!(prev, expected, "recovered order must equal creation order");
    }

    #[test]
    fn legacy_manifest_without_seq_still_parses() {
        // A manifest predating `seq`: prev_memberships must fall back to
        // the map's key order instead of panicking or dropping bundles.
        let b0 = ObjId([0xaa; 32]).to_string();
        let b1 = ObjId([0xbb; 32]).to_string();
        let content = json!({
            "edx": 1,
            "files": {
                "a": {"size": 1, "b3": ObjId([1; 32]).to_string(), "bundle": b0, "off": 0},
                "b": {"size": 1, "b3": ObjId([2; 32]).to_string(), "bundle": b1, "off": 0},
            },
            "bundles": {b0.clone(): {"size": 1}, b1.clone(): {"size": 1}},
        });
        let prev = prev_memberships(&content);
        assert_eq!(prev, vec![vec!["a".to_string()], vec!["b".to_string()]]);
    }

    #[test]
    fn merkle_root_frozen_vectors() {
        // Empty set.
        assert_eq!(files_merkle_root(&BTreeMap::new()), ObjId([0u8; 32]));

        // Golden: three fixed entries. If this hash ever changes, the
        // manifest format changed (docs/edx-manifest.md).
        let entries: BTreeMap<String, (ObjId, u64)> = [
            ("a.txt", blake3::hash(b"a"), 1u64),
            ("b/c.bin", blake3::hash(b"bc"), 2),
            ("d.css", blake3::hash(b"d"), 3),
        ]
        .into_iter()
        .map(|(p, h, s)| (p.to_string(), (ObjId(*h.as_bytes()), s)))
        .collect();
        let root = files_merkle_root(&entries);
        assert_eq!(
            root.to_string(),
            // Computed once by this implementation; frozen thereafter.
            golden_three_entry_root()
        );

        // Any mutation moves the root.
        let mut moved = entries.clone();
        moved.insert("a.txt".into(), (ObjId(*blake3::hash(b"A").as_bytes()), 1));
        assert_ne!(files_merkle_root(&moved), root);
        let mut resized = entries.clone();
        resized.insert("d.css".into(), (ObjId(*blake3::hash(b"d").as_bytes()), 4));
        assert_ne!(files_merkle_root(&resized), root);
    }

    fn golden_three_entry_root() -> String {
        // Recompute-by-hand of the frozen construction, kept verbose so
        // the test fails loudly if the production code drifts from the
        // documented format rather than silently following it.
        let leaf = |path: &str, b3: &blake3::Hash, size: u64| {
            let mut h = blake3::Hasher::new();
            h.update(&[0x00]);
            h.update(&(path.len() as u32).to_le_bytes());
            h.update(path.as_bytes());
            h.update(b3.as_bytes());
            h.update(&size.to_le_bytes());
            *h.finalize().as_bytes()
        };
        let parent = |l: &[u8; 32], r: &[u8; 32]| {
            let mut h = blake3::Hasher::new();
            h.update(&[0x01]);
            h.update(l);
            h.update(r);
            *h.finalize().as_bytes()
        };
        let a = leaf("a.txt", &blake3::hash(b"a"), 1);
        let b = leaf("b/c.bin", &blake3::hash(b"bc"), 2);
        let d = leaf("d.css", &blake3::hash(b"d"), 3);
        let ab = parent(&a, &b);
        let root = parent(&ab, &d); // odd leaf promoted, then paired
        ObjId(root).to_string()
    }

    #[test]
    fn malformed_edx_salt_is_rejected() {
        let salt = |s: &str| edx_salt(&json!({"edx_salt": s}));
        assert_eq!(salt("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        // Odd length: the last pair would read past the end of the string.
        assert_eq!(salt("abc"), None);
        // Multi-byte chars: a byte range can land off a char boundary.
        assert_eq!(salt("aa\u{20ac}b"), None);
        assert_eq!(salt("\u{20ac}\u{20ac}"), None);
        // Non-hex digits stay a parse failure, not a panic.
        assert_eq!(salt("zz"), None);
        assert_eq!(edx_salt(&json!({"edx_salt": 1})), None);
        assert_eq!(edx_salt(&json!({})), None);
    }

    #[test]
    fn entry_with_undeclared_bundle_is_rejected() {
        let content = json!({
            "edx": 1,
            "files": {"x": {"size": 10, "b3": ObjId([1;32]).to_string(),
                              "bundle": ObjId([2;32]).to_string(), "off": 0}},
            // no "bundles" section
        });
        assert!(edx_entry(&content, "x").is_none());
    }
}
