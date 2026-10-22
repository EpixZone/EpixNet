//! A local, verified public snapshot. No directory walk, peer fetch, or materialization.

use epix_blob::{store::Store, ObjId};
use epix_content::verify::{
    exact_nonnegative_size, is_valid_relative_path, portable_path_case_keys,
};
use epix_xite::XiteStorage;
use serde_json::Value;
use sha2::{Digest, Sha512};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

const IO_CHUNK: usize = 64 * 1024;
const MAX_METADATA: u64 = 8 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 32 * 1024 * 1024;
const MAX_MANIFESTS: usize = 8192;
const MAX_PATH: usize = 1024;
const MAX_PATH_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENTRIES: usize = 65_536;
const MAX_ENTRY_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_SPOOL_BYTES: u64 = MAX_TOTAL_BYTES + 64 * 1024 * 1024;
const MAX_SHARDS: usize = (MAX_ENTRY_BYTES / epix_selfenc::CHUNK_SIZE as u64) as usize + 1;

pub(crate) struct MergeRule {
    pub signers: Arc<Vec<String>>,
    pub max_size: u64,
}

pub(crate) struct ExportInput {
    pub storage: XiteStorage,
    pub spool_directory: Option<PathBuf>,
    pub manifests: Vec<(String, Value)>,
    pub store: Option<Arc<Store>>,
    pub merged: HashMap<String, MergeRule>,
}

fn unavailable(message: impl std::fmt::Display) -> String {
    format!("Public export unavailable: {message}")
}

fn check_cancelled(cancelled: &AtomicBool) -> io::Result<()> {
    if cancelled.load(Ordering::Acquire) {
        // Write::write_all retries Interrupted, so cancellation must be terminal.
        Err(io::Error::other("ZIP export cancelled"))
    } else {
        Ok(())
    }
}

// A Value comparison cannot detect duplicate JSON keys: serde_json normally
// retains only the final value. Reject duplicates before exporting unchanged raw
// metadata so that every byte has the authority represented by the parsed tree.
struct UniqueValue(Value);

impl<'de> serde::Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(v.into())))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(v.into())))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|v| UniqueValue(Value::Number(v)))
                    .ok_or_else(|| E::custom("invalid JSON number"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v.to_owned())))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueValue(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON object key"));
                    }
                    let UniqueValue(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

fn parse_metadata(raw: &[u8]) -> Result<Value, String> {
    serde_json::from_slice::<UniqueValue>(raw)
        .map(|value| value.0)
        .map_err(unavailable)
}

struct CountBytes {
    written: u64,
    limit: u64,
}

impl Write for CountBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.written = self
            .written
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| io::Error::other("manifest metadata size limit exceeded"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Apply before cloning accepted metadata and before allocating an export plan.
/// Serialization counts bytes without allocating another copy of the manifests.
pub(crate) fn validate_manifest_values<'a>(
    values: impl Iterator<Item = &'a Value>,
) -> Result<(), String> {
    let mut total = 0;
    for (index, value) in values.enumerate() {
        if index >= MAX_MANIFESTS {
            return Err(unavailable("manifest count limit exceeded"));
        }
        let mut count = CountBytes {
            written: 0,
            limit: MAX_METADATA.min(MAX_MANIFEST_BYTES - total),
        };
        serde_json::to_writer(&mut count, value).map_err(unavailable)?;
        total += count.written;
    }
    Ok(())
}

fn merged_records(container: &Value) -> Result<&Vec<Value>, String> {
    let object = container
        .as_object()
        .ok_or_else(|| unavailable("invalid merged record container"))?;
    if object.len() != 2
        || object.get("record_format").and_then(Value::as_str) != Some(epix_content::RECORD_FORMAT)
    {
        return Err(unavailable(
            "invalid merged record format or unsigned container fields",
        ));
    }
    object
        .get("post")
        .and_then(Value::as_array)
        .ok_or_else(|| unavailable("invalid merged record array"))
}

/// Pin the configured root endpoint. Its trusted ancestry may contain symlinks,
/// but the root itself and every untrusted descendant must be direct objects.
struct Root {
    directory: File,
    path: PathBuf,
}

impl Root {
    #[cfg(unix)]
    fn open(path: &Path) -> io::Result<Self> {
        use rustix::fs::{Mode, OFlags};
        let path = std::path::absolute(path)?;
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("xite root has no parent"))?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("xite root has no name"))?;
        let parent = rustix::fs::open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let directory = rustix::fs::openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self {
            directory: directory.into(),
            path,
        })
    }

    #[cfg(windows)]
    fn open(path: &Path) -> io::Result<Self> {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        // Win32 flags: BACKUP_SEMANTICS opens directories, OPEN_REPARSE_POINT
        // checks the endpoint itself, and omitting SHARE_DELETE pins its name.
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x1 | 0x2)
            .custom_flags(0x02000000 | 0x00200000)
            .open(path)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err(io::Error::other("xite root is not a direct directory"));
        }
        Ok(Self {
            directory,
            path: path.to_path_buf(),
        })
    }

    #[cfg(not(any(unix, windows)))]
    fn open(_: &Path) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no secure export reader on this platform",
        ))
    }

    #[cfg(unix)]
    fn file(&self, path: &str) -> io::Result<File> {
        use rustix::fs::{Mode, OFlags};
        let mut directory = self.directory.try_clone()?;
        let mut components = path.split('/').peekable();
        while let Some(name) = components.next() {
            let final_component = components.peek().is_none();
            let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            flags |= if final_component {
                OFlags::NONBLOCK
            } else {
                OFlags::DIRECTORY
            };
            directory = rustix::fs::openat(&directory, name, flags, Mode::empty())?.into();
        }
        if !directory.metadata()?.is_file() {
            return Err(io::Error::other("export source is not a regular file"));
        }
        Ok(directory)
    }

    #[cfg(windows)]
    fn file(&self, path: &str) -> io::Result<File> {
        epix_fs::open_regular_file_beneath(&self.path, Path::new(path))
    }

    #[cfg(not(any(unix, windows)))]
    fn file(&self, _: &str) -> io::Result<File> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no secure export reader on this platform",
        ))
    }

    fn read_metadata(
        &self,
        path: &str,
        limit: u64,
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>, String> {
        let mut file = self
            .file(path)
            .map_err(|error| unavailable(format!("{path}: {error}")))?;
        let size = file.metadata().map_err(unavailable)?.len();
        if size > limit {
            return Err(unavailable(format!(
                "{path} exceeds the metadata size limit"
            )));
        }
        let mut bytes = vec![0; usize::try_from(size).map_err(unavailable)?];
        for chunk in bytes.chunks_mut(IO_CHUNK) {
            check_cancelled(cancelled).map_err(unavailable)?;
            file.read_exact(chunk)
                .map_err(|error| unavailable(format!("{path} changed: {error}")))?;
        }
        let mut extra = [0];
        if file.read(&mut extra).map_err(unavailable)? != 0 {
            return Err(unavailable(format!("{path} changed while reading")));
        }
        Ok(bytes)
    }

    fn check_current(&self) -> Result<(), String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let current = Self::open(&self.path).map_err(unavailable)?;
            let before = self.directory.metadata().map_err(unavailable)?;
            let after = current.directory.metadata().map_err(unavailable)?;
            if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
                return Err(unavailable("xite root changed during export"));
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct Paths {
    lower: HashMap<String, (String, bool)>,
    upper: HashMap<String, (String, bool)>,
    count: usize,
    bytes: usize,
}

impl Paths {
    fn add(&mut self, path: &str) -> Result<(), String> {
        validate_path(path)?;
        self.count += 1;
        if self.count > MAX_ENTRIES {
            return Err(unavailable("archive path count/size limit exceeded"));
        }
        let mut prefix = String::new();
        let mut components = path.split('/').peekable();
        while let Some(part) = components.next() {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            let file = components.peek().is_none();
            let (lower, upper) = portable_path_case_keys(&prefix);
            for prior in [self.lower.get(&lower), self.upper.get(&upper)]
                .into_iter()
                .flatten()
            {
                if prior.0 != prefix || prior.1 || file {
                    return Err(unavailable(format!(
                        "archive path collision: {} and {path}",
                        prior.0
                    )));
                }
            }
            if !self.lower.contains_key(&lower) {
                // Charge stored prefixes too: deeply nested paths otherwise
                // turn a small input path budget into quadratic allocations.
                self.bytes = self
                    .bytes
                    .checked_add(lower.len() + upper.len() + 2 * prefix.len())
                    .filter(|bytes| *bytes <= MAX_PATH_BYTES)
                    .ok_or_else(|| unavailable("archive path storage limit exceeded"))?;
                self.lower.insert(lower, (prefix.clone(), file));
                self.upper.insert(upper, (prefix.clone(), file));
            }
        }
        Ok(())
    }
}

fn validate_path(path: &str) -> Result<(), String> {
    if path.len() > MAX_PATH || !is_valid_relative_path(path) {
        return Err(unavailable(format!("unsafe archive path: {path}")));
    }
    Ok(())
}

fn section<'a>(
    value: &'a Value,
    name: &str,
) -> Result<Option<&'a serde_json::Map<String, Value>>, String> {
    value
        .get(name)
        .map(|value| {
            value
                .as_object()
                .ok_or_else(|| unavailable(format!("invalid {name} section")))
        })
        .transpose()
}

fn size(value: Option<&Value>) -> Result<u64, String> {
    let size = value
        .and_then(exact_nonnegative_size)
        .ok_or_else(|| unavailable("invalid signed file size"))? as u64;
    if size > MAX_ENTRY_BYTES {
        return Err(unavailable("file exceeds the 8 GiB export limit"));
    }
    Ok(size)
}

fn hash(value: &Value, field: &str) -> Result<[u8; 32], String> {
    let text = value
        .as_str()
        .ok_or_else(|| unavailable(format!("invalid {field} hash")))?;
    if text.len() != 64 {
        return Err(unavailable(format!("invalid {field} hash length")));
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(text, &mut bytes)
        .map_err(|_| unavailable(format!("invalid {field} hash")))?;
    Ok(bytes)
}

#[derive(Default)]
struct Hashes {
    b3: Option<ObjId>,
    sha512: Option<[u8; 32]>,
}

struct Plain {
    size: u64,
    hashes: Hashes,
    bundle: Option<(ObjId, u64, u64)>,
    optional: bool,
}

fn plain(meta: &Value, manifest: &Value, optional: bool) -> Result<Plain, String> {
    let size = size(meta.get("size"))?;
    let hashes = Hashes {
        b3: meta
            .get("b3")
            .map(|value| hash(value, "b3").map(ObjId))
            .transpose()?,
        sha512: meta
            .get("sha512")
            .map(|value| hash(value, "sha512"))
            .transpose()?,
    };
    if hashes.b3.is_none() && hashes.sha512.is_none() {
        return Err(unavailable("file has no signed content hash"));
    }
    let bundle = meta
        .get("bundle")
        .map(|value| {
            let id = ObjId(hash(value, "bundle")?);
            if hashes.b3.is_none() {
                return Err(unavailable("bundle member has no b3 hash"));
            }
            let declared = manifest
                .get("bundles")
                .and_then(|map| map.get(value.as_str()?))
                .ok_or_else(|| unavailable("bundle is not declared"))?;
            let total = self::size(declared.get("size"))?;
            let off = meta
                .get("off")
                .and_then(Value::as_u64)
                .ok_or_else(|| unavailable("invalid bundle offset"))?;
            if off.checked_add(size).is_none_or(|end| end > total) {
                return Err(unavailable("bundle member range exceeds its signed bundle"));
            }
            Ok((id, off, total))
        })
        .transpose()?;
    Ok(Plain {
        size,
        hashes,
        bundle,
        optional,
    })
}

struct Shards {
    size: u64,
    salt: Vec<u8>,
    chunks: Vec<epix_selfenc::ChunkRef>,
    cipher_sizes: HashMap<[u8; 32], u64>,
}

fn shards(meta: &Value, manifest: &Value) -> Result<Option<Shards>, String> {
    let mode = match meta.get("mode") {
        None => 0,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| unavailable("invalid shard mode"))?,
    };
    if mode == 1 {
        return Ok(None);
    }
    if mode != 0 {
        return Err(unavailable("unsupported shard mode"));
    }
    let size = size(meta.get("size"))?;
    let salt = manifest
        .get("edx_salt")
        .and_then(Value::as_str)
        .ok_or_else(|| unavailable("missing public shard salt"))?;
    if salt.len() > 2048 {
        return Err(unavailable("shard salt exceeds metadata limit"));
    }
    let salt = hex::decode(salt).map_err(|_| unavailable("invalid public shard salt"))?;
    let raw = meta
        .get("chunks")
        .and_then(Value::as_array)
        .ok_or_else(|| unavailable("invalid shard list"))?;
    if raw.is_empty() || raw.len() > MAX_SHARDS {
        return Err(unavailable("shard count limit exceeded"));
    }
    let mut chunks = Vec::with_capacity(raw.len());
    let mut cipher_sizes = HashMap::new();
    let mut total = 0u64;
    for chunk in raw {
        let len = chunk
            .get("len")
            .and_then(Value::as_u64)
            .ok_or_else(|| unavailable("invalid shard length"))?;
        let cs = chunk
            .get("cs")
            .and_then(Value::as_u64)
            .ok_or_else(|| unavailable("invalid ciphertext size"))?;
        if len > epix_selfenc::CHUNK_SIZE as u64 || cs != len + 16 {
            return Err(unavailable("invalid shard length or ciphertext size"));
        }
        total = total
            .checked_add(len)
            .ok_or_else(|| unavailable("shard size overflow"))?;
        let plain_hash = hash(
            chunk
                .get("ph")
                .ok_or_else(|| unavailable("missing shard hash"))?,
            "shard plaintext",
        )?;
        let cipher_addr = hash(
            chunk
                .get("ca")
                .ok_or_else(|| unavailable("missing ciphertext address"))?,
            "ciphertext",
        )?;
        if cipher_sizes
            .insert(cipher_addr, cs)
            .is_some_and(|old| old != cs)
        {
            return Err(unavailable("conflicting ciphertext sizes"));
        }
        chunks.push(epix_selfenc::ChunkRef {
            plain_hash,
            cipher_addr,
            len: len as u32,
        });
    }
    if total != size {
        return Err(unavailable(
            "signed shard size does not match chunk lengths",
        ));
    }
    Ok(Some(Shards {
        size,
        salt,
        chunks,
        cipher_sizes,
    }))
}

enum Kind {
    Manifest(usize),
    Plain(Plain),
    Shards(Shards),
    Merged,
}
struct Entry {
    path: String,
    kind: Kind,
}

fn plan(input: &ExportInput, cancelled: &AtomicBool) -> Result<Vec<Entry>, String> {
    let mut paths = Paths::default();
    let mut entries = Vec::new();
    let mut manifests = HashSet::new();
    for (index, (path, _)) in input.manifests.iter().enumerate() {
        check_cancelled(cancelled).map_err(unavailable)?;
        if path != "content.json" && !path.ends_with("/content.json") {
            return Err(unavailable("invalid governing manifest path"));
        }
        paths.add(path)?;
        manifests.insert(path.as_str());
        entries.push(Entry {
            path: path.clone(),
            kind: Kind::Manifest(index),
        });
    }
    if !manifests.contains("content.json") {
        return Err(unavailable("missing root manifest"));
    }
    let mut merged = HashSet::new();
    for (path, content) in &input.manifests {
        let prefix = path
            .strip_suffix("content.json")
            .expect("checked manifest suffix");
        if let Some(includes) = section(content, "includes")? {
            for relative in includes.keys() {
                validate_path(relative)?;
                let full = format!("{prefix}{relative}");
                validate_path(&full)?;
                if !manifests.contains(full.as_str()) {
                    return Err(unavailable(format!("missing required manifest {full}")));
                }
            }
        }
        for name in ["files", "files_optional", "files_shard", "files_merged"] {
            let Some(files) = section(content, name)? else {
                continue;
            };
            for (relative, meta) in files {
                check_cancelled(cancelled).map_err(unavailable)?;
                validate_path(relative)?;
                let full = format!("{prefix}{relative}");
                paths.add(&full)?;
                let kind = match name {
                    "files_shard" => match shards(meta, content)? {
                        Some(shards) => Kind::Shards(shards),
                        None => continue, // Never inspect cached random-key plaintext.
                    },
                    "files_merged" => {
                        if !input.merged.contains_key(&full) {
                            return Err(unavailable(format!("missing merge authority for {full}")));
                        }
                        merged.insert(full.clone());
                        Kind::Merged
                    }
                    _ => Kind::Plain(plain(meta, content, name == "files_optional")?),
                };
                entries.push(Entry { path: full, kind });
            }
        }
    }
    if input.merged.keys().any(|path| !merged.contains(path)) {
        return Err(unavailable("merge authority contains an undeclared path"));
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

enum Source {
    Loose(File),
    Stored {
        store: Arc<Store>,
        id: ObjId,
        off: u64,
        object_size: u64,
    },
}

fn complete(store: &Store, id: ObjId, size: u64) -> Result<bool, String> {
    match store.info(id).map_err(unavailable)? {
        None | Some((_, false)) => Ok(false),
        Some((actual, true)) if actual == size => Ok(true),
        Some(_) => Err(unavailable("stored object has changed size")),
    }
}

fn source(
    root: &Root,
    path: &str,
    meta: &Plain,
    store: Option<&Arc<Store>>,
) -> Result<Option<Source>, String> {
    match root.file(path) {
        Ok(file) => {
            if file.metadata().map_err(unavailable)?.len() != meta.size {
                return Err(unavailable(format!("{path} changed size")));
            }
            return Ok(Some(Source::Loose(file)));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(unavailable(format!("{path}: {error}"))),
    }
    if let Some(store) = store {
        if let Some(id) = meta.hashes.b3 {
            if complete(store, id, meta.size)? {
                return Ok(Some(Source::Stored {
                    store: store.clone(),
                    id,
                    off: 0,
                    object_size: meta.size,
                }));
            }
        }
        if let Some((id, off, object_size)) = meta.bundle {
            if complete(store, id, object_size)? {
                return Ok(Some(Source::Stored {
                    store: store.clone(),
                    id,
                    off,
                    object_size,
                }));
            }
        }
    }
    if meta.optional {
        Ok(None)
    } else {
        Err(unavailable(format!("missing required file {path}")))
    }
}

impl Source {
    fn copy(
        &mut self,
        size: u64,
        output: &mut impl Write,
        cancelled: &AtomicBool,
    ) -> Result<(), String> {
        let file = match self {
            Self::Stored {
                store,
                id,
                off,
                object_size,
            } => {
                if !complete(store, *id, *object_size)? {
                    return Err(unavailable("stored file became incomplete"));
                }
                let end = off
                    .checked_add(size)
                    .ok_or_else(|| unavailable("stored file range overflow"))?;
                let written = store
                    .copy_verified_range(*id, *off..end, output, 0, || check_cancelled(cancelled))
                    .map_err(unavailable)?;
                if written != size {
                    return Err(unavailable("stored file changed while reading"));
                }
                return Ok(());
            }
            Self::Loose(file) => file,
        };
        let mut buffer = vec![0; IO_CHUNK];
        let mut position = 0;
        while position < size {
            check_cancelled(cancelled).map_err(unavailable)?;
            let length = (size - position).min(IO_CHUNK as u64) as usize;
            file.read_exact(&mut buffer[..length])
                .map_err(unavailable)?;
            output.write_all(&buffer[..length]).map_err(unavailable)?;
            position += length as u64;
        }
        let mut extra = [0];
        if file.read(&mut extra).map_err(unavailable)? != 0 {
            return Err(unavailable("file grew during export"));
        }
        Ok(())
    }
}

struct Spool {
    file: File,
    position: u64,
    limit: u64,
    cancelled: Arc<AtomicBool>,
}

impl Write for Spool {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        check_cancelled(&self.cancelled)?;
        if self
            .position
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.limit)
        {
            return Err(io::Error::other("ZIP spool size limit exceeded"));
        }
        let n = self.file.write(bytes)?;
        self.position += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for Spool {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        check_cancelled(&self.cancelled)?;
        self.position = self.file.seek(from)?;
        if self.position > self.limit {
            return Err(io::Error::other("ZIP spool size limit exceeded"));
        }
        Ok(self.position)
    }
}

struct VerifiedWriter<'a> {
    zip: &'a mut zip::ZipWriter<Spool>,
    expected: u64,
    written: u64,
    b3: blake3::Hasher,
    sha512: Sha512,
}

impl Write for VerifiedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .written
            .checked_add(bytes.len() as u64)
            .is_none_or(|n| n > self.expected)
        {
            return Err(io::Error::other("file exceeds its signed size"));
        }
        let n = self.zip.write(bytes)?;
        self.b3.update(&bytes[..n]);
        self.sha512.update(&bytes[..n]);
        self.written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.zip.flush()
    }
}

impl VerifiedWriter<'_> {
    fn finish(self, hashes: &Hashes) -> Result<(), String> {
        if self.written != self.expected
            || hashes
                .b3
                .is_some_and(|id| self.b3.finalize().as_bytes() != &id.0)
            || hashes
                .sha512
                .is_some_and(|hash| self.sha512.finalize()[..32] != hash)
        {
            return Err(unavailable(
                "file bytes changed or do not match their signed hash/size",
            ));
        }
        Ok(())
    }
}

fn start<'a>(
    zip: &'a mut zip::ZipWriter<Spool>,
    path: &str,
    size: u64,
    total: &mut u64,
) -> Result<VerifiedWriter<'a>, String> {
    *total = total
        .checked_add(size)
        .filter(|n| *n <= MAX_TOTAL_BYTES)
        .ok_or_else(|| unavailable("total export exceeds the 16 GiB limit"))?;
    if size > MAX_ENTRY_BYTES {
        return Err(unavailable("file exceeds the 8 GiB export limit"));
    }
    zip.start_file(
        path,
        zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .large_file(size >= u32::MAX as u64),
    )
    .map_err(unavailable)?;
    Ok(VerifiedWriter {
        zip,
        expected: size,
        written: 0,
        b3: blake3::Hasher::new(),
        sha512: Sha512::new(),
    })
}

fn write_bytes(
    zip: &mut zip::ZipWriter<Spool>,
    path: &str,
    bytes: &[u8],
    total: &mut u64,
) -> Result<(), String> {
    let mut output = start(zip, path, bytes.len() as u64, total)?;
    for chunk in bytes.chunks(IO_CHUNK) {
        output.write_all(chunk).map_err(unavailable)?;
    }
    output.finish(&Hashes::default())
}

pub(crate) fn build(input: ExportInput, cancelled: Arc<AtomicBool>) -> Result<File, String> {
    check_cancelled(&cancelled).map_err(unavailable)?;
    validate_manifest_values(input.manifests.iter().map(|(_, value)| value))?;
    let entries = plan(&input, &cancelled)?;
    let root = Root::open(input.storage.root()).map_err(unavailable)?;
    let spool = Spool {
        file: match &input.spool_directory {
            Some(directory) => tempfile::tempfile_in(directory),
            None => tempfile::tempfile(),
        }
        .map_err(unavailable)?,
        position: 0,
        limit: MAX_SPOOL_BYTES,
        cancelled: cancelled.clone(),
    };
    let mut zip = zip::ZipWriter::new(spool);
    let mut total = 0;
    let mut manifest_bytes = 0;
    for entry in entries {
        check_cancelled(&cancelled).map_err(unavailable)?;
        match entry.kind {
            Kind::Manifest(index) => {
                let raw = root.read_metadata(
                    &entry.path,
                    MAX_METADATA.min(MAX_MANIFEST_BYTES - manifest_bytes),
                    &cancelled,
                )?;
                manifest_bytes += raw.len() as u64;
                let value = parse_metadata(&raw)?;
                if value != input.manifests[index].1 {
                    return Err(unavailable(format!(
                        "accepted manifest {} changed",
                        entry.path
                    )));
                }
                write_bytes(&mut zip, &entry.path, &raw, &mut total)?;
            }
            Kind::Merged => {
                let rule = &input.merged[&entry.path];
                let raw =
                    root.read_metadata(&entry.path, rule.max_size.min(MAX_METADATA), &cancelled)?;
                let container = parse_metadata(&raw)?;
                let records = merged_records(&container)?;
                let now = epix_core::now_ms();
                for record in records {
                    check_cancelled(&cancelled).map_err(unavailable)?;
                    epix_content::verify_record(record, &rule.signers, now).map_err(|error| {
                        unavailable(format!("invalid merged record: {error:?}"))
                    })?;
                }
                write_bytes(&mut zip, &entry.path, &raw, &mut total)?;
            }
            Kind::Plain(meta) => {
                let Some(mut source) = source(&root, &entry.path, &meta, input.store.as_ref())?
                else {
                    continue;
                };
                let mut output = start(&mut zip, &entry.path, meta.size, &mut total)?;
                source.copy(meta.size, &mut output, &cancelled)?;
                output.finish(&meta.hashes)?;
            }
            Kind::Shards(shards) => {
                let mut output = start(&mut zip, &entry.path, shards.size, &mut total)?;
                // Public maps sign every plaintext chunk hash. A local public
                // file can be checked directly without re-encrypting it or
                // requiring a Store. Mode-1 never reaches this branch.
                match root.file(&entry.path) {
                    Ok(mut file) => {
                        if file.metadata().map_err(unavailable)?.len() != shards.size {
                            return Err(unavailable("public shard plaintext changed size"));
                        }
                        let mut buffer = vec![0; epix_selfenc::CHUNK_SIZE];
                        for chunk in &shards.chunks {
                            check_cancelled(&cancelled).map_err(unavailable)?;
                            let bytes = &mut buffer[..chunk.len as usize];
                            file.read_exact(bytes).map_err(unavailable)?;
                            if blake3::hash(bytes).as_bytes() != &chunk.plain_hash {
                                return Err(unavailable("public shard plaintext changed hash"));
                            }
                            for part in bytes.chunks(IO_CHUNK) {
                                output.write_all(part).map_err(unavailable)?;
                            }
                        }
                        let mut extra = [0];
                        if file.read(&mut extra).map_err(unavailable)? != 0 {
                            return Err(unavailable("public shard plaintext grew during export"));
                        }
                        output.finish(&Hashes::default())?;
                        continue;
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(unavailable(format!("{}: {error}", entry.path))),
                }
                let store = input
                    .store
                    .as_ref()
                    .ok_or_else(|| unavailable("missing public shard Store"))?;
                let written = epix_selfenc::decrypt_into(
                    epix_selfenc::Mode::SaltedConvergent,
                    &shards.chunks,
                    &shards.salt,
                    |address| {
                        check_cancelled(&cancelled)?;
                        let size = shards.cipher_sizes[address];
                        let id = ObjId(*address);
                        if !complete(store, id, size).map_err(io::Error::other)? {
                            return Err(io::Error::other(
                                "missing or incomplete public ciphertext",
                            ));
                        }
                        let bytes = store.read_range(id, 0, size, 0)?;
                        if bytes.len() as u64 != size {
                            return Err(io::Error::other("ciphertext size changed"));
                        }
                        Ok(bytes)
                    },
                    &mut output,
                )
                .map_err(unavailable)?;
                if written != shards.size {
                    return Err(unavailable("decrypted file size changed"));
                }
                output.finish(&Hashes::default())?;
            }
        }
    }
    check_cancelled(&cancelled).map_err(unavailable)?;
    root.check_current()?;
    let mut spool = zip.finish().map_err(unavailable)?;
    spool.file.rewind().map_err(unavailable)?;
    Ok(spool.file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn raw_metadata_rejects_duplicate_keys_at_every_depth() {
        for raw in [
            r#"{"title":"unverified","title":"accepted"}"#,
            r#"{"post":[{"body":"unverified","body":"accepted"}]}"#,
            r#"{"nested":{"x":1,"\u0078":1}}"#,
        ] {
            assert!(parse_metadata(raw.as_bytes())
                .unwrap_err()
                .contains("duplicate"));
        }
        let raw = br#" {"post": [], "record_format": "format", "x": [null, true, -1, 1, 0.5]} "#;
        assert_eq!(
            parse_metadata(raw).unwrap(),
            serde_json::from_slice::<Value>(raw).unwrap()
        );
    }

    #[test]
    fn merged_containers_reject_unsigned_top_level_fields() {
        let valid = json!({"record_format": epix_content::RECORD_FORMAT, "post": []});
        assert!(merged_records(&valid).unwrap().is_empty());
        let mut extra = valid;
        extra["debug_private"] = json!("must not escape via a public record container");
        assert!(merged_records(&extra).is_err());
    }

    #[test]
    fn manifest_preflight_limits_count_and_serialized_bytes_without_copying() {
        assert!(
            validate_manifest_values(std::iter::repeat(&Value::Null).take(MAX_MANIFESTS)).is_ok()
        );
        assert!(
            validate_manifest_values(std::iter::repeat(&Value::Null).take(MAX_MANIFESTS + 1))
                .is_err()
        );
        let value = Value::String("a".repeat(MAX_METADATA as usize - 2));
        assert!(validate_manifest_values(std::iter::repeat(&value).take(4)).is_ok());
        assert!(validate_manifest_values(std::iter::repeat(&value).take(5)).is_err());
        let oversized = Value::String("a".repeat(MAX_METADATA as usize));
        assert!(validate_manifest_values(std::iter::once(&oversized)).is_err());
    }

    #[test]
    fn spool_enforces_disk_limit_and_terminal_cancellation() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut spool = Spool {
            file: tempfile::tempfile().unwrap(),
            position: 0,
            limit: 4,
            cancelled: cancelled.clone(),
        };
        spool.write_all(b"abcd").unwrap();
        assert!(spool
            .write_all(b"e")
            .unwrap_err()
            .to_string()
            .contains("limit"));
        assert_eq!(spool.file.metadata().unwrap().len(), 4);
        spool.rewind().unwrap();
        cancelled.store(true, Ordering::Release);
        let error = spool.write(b"z").unwrap_err();
        assert_ne!(
            error.kind(),
            io::ErrorKind::Interrupted,
            "write_all must not retry cancellation forever"
        );
        assert!(error.to_string().contains("cancelled"));
        assert!(spool.seek(SeekFrom::Start(0)).is_err());
    }

    #[test]
    fn total_and_entry_limits_fail_before_creating_a_zip_member() {
        let spool = Spool {
            file: tempfile::tempfile().unwrap(),
            position: 0,
            limit: MAX_SPOOL_BYTES,
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        let mut zip = zip::ZipWriter::new(spool);
        let mut total = MAX_TOTAL_BYTES;
        assert!(start(&mut zip, "extra.bin", 1, &mut total).is_err());
        total = 0;
        assert!(start(&mut zip, "large.bin", MAX_ENTRY_BYTES + 1, &mut total).is_err());
        let spool = zip.finish().unwrap();
        let archive = zip::ZipArchive::new(spool.file).unwrap();
        assert_eq!(archive.len(), 0);
    }

    #[test]
    fn configured_private_spool_directory_is_required_and_cleans_up() {
        let directory = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(directory.path().join("xite"));
        let raw = br#"{"files":{}}"#;
        storage.write("content.json", raw).unwrap();
        let spool_directory = directory.path().join("private-spool");
        let input = || ExportInput {
            storage: storage.clone(),
            spool_directory: Some(spool_directory.clone()),
            manifests: vec![("content.json".into(), parse_metadata(raw).unwrap())],
            store: None,
            merged: HashMap::new(),
        };
        // Do not silently fall back to a platform-global directory when the
        // configured private location is unavailable, as on Android.
        assert!(build(input(), Arc::new(AtomicBool::new(false))).is_err());
        std::fs::create_dir(&spool_directory).unwrap();
        let file = build(input(), Arc::new(AtomicBool::new(false))).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let mut actual = Vec::new();
        archive
            .by_name("content.json")
            .unwrap()
            .read_to_end(&mut actual)
            .unwrap();
        assert_eq!(actual, raw);
        drop(archive);
        assert_eq!(std::fs::read_dir(&spool_directory).unwrap().count(), 0);
    }

    #[test]
    fn cancelled_build_stops_before_inspecting_storage() {
        let input = ExportInput {
            spool_directory: None,
            storage: XiteStorage::new("missing-export-root"),
            manifests: Vec::new(),
            store: None,
            merged: HashMap::new(),
        };
        let error = build(input, Arc::new(AtomicBool::new(true))).unwrap_err();
        assert!(error.contains("cancelled"), "{error}");
    }

    #[test]
    fn directory_case_aliases_and_file_directory_collisions_are_rejected() {
        for (first, second) in [
            ("Assets/a.txt", "assets/b.txt"),
            ("a/b.txt", "a"),
            ("a", "a/b.txt"),
            ("straße/a.txt", "STRASSE/b.txt"),
        ] {
            let mut paths = Paths::default();
            paths.add(first).unwrap();
            assert!(paths.add(second).is_err(), "{first} and {second}");
        }
        let mut paths = Paths::default();
        paths.add("assets/a.txt").unwrap();
        paths.add("assets/b.txt").unwrap();
        assert!(paths.add("assets/a.txt").is_err());
    }

    #[test]
    fn path_budget_counts_stored_prefixes_not_only_leaf_names() {
        let mut paths = Paths {
            bytes: MAX_PATH_BYTES - 10,
            ..Paths::default()
        };
        assert!(paths.add("a/b/c.txt").is_err());
    }

    #[test]
    fn public_shard_metadata_rejects_narrowing_and_mismatched_totals() {
        let content = json!({"edx_salt": "ab".repeat(32)});
        let valid = json!({"mode": 0, "size": 1, "chunks": [{"ph": "11".repeat(32), "ca": "22".repeat(32), "len": 1, "cs": 17}]});
        assert!(shards(&valid, &content).unwrap().is_some());
        for field in ["mode", "size", "len", "cs"] {
            let mut malformed = valid.clone();
            match field {
                "mode" => malformed["mode"] = json!(256),
                "size" => malformed["size"] = json!(2),
                field => {
                    malformed["chunks"][0][field] =
                        json!((1u64 << 32) + if field == "len" { 1 } else { 17 })
                }
            }
            assert!(shards(&malformed, &content).is_err(), "{field}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn pinned_root_accepts_trusted_ancestry_but_detects_root_replacement() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let real_parent = directory.path().join("real");
        std::fs::create_dir(&real_parent).unwrap();
        std::fs::create_dir(real_parent.join("xite")).unwrap();
        std::fs::write(real_parent.join("xite/file.txt"), b"public").unwrap();
        let alias = directory.path().join("alias");
        symlink(&real_parent, &alias).unwrap();
        let root = Root::open(&alias.join("xite")).unwrap();
        assert_eq!(
            root.read_metadata("file.txt", 10, &AtomicBool::new(false))
                .unwrap(),
            b"public"
        );
        std::fs::rename(real_parent.join("xite"), real_parent.join("old")).unwrap();
        std::fs::create_dir(real_parent.join("xite")).unwrap();
        assert!(root.check_current().is_err());
        assert_eq!(
            root.read_metadata("file.txt", 10, &AtomicBool::new(false))
                .unwrap(),
            b"public"
        );
    }
}
