//! Content-addressed object store: sparse files for streaming objects,
//! append-only slab packfiles for complete small objects and shards, and
//! a `redb` index with refcounts and LRU eviction.
//!
//! Layout under the store root:
//!
//! ```text
//! index.redb            object records, slab metadata, schema version
//! sparse/<hex>          partially- or fully-held large objects (sparse)
//! sparse/<hex>.obao     their pre-order outboards (filled as slices land)
//! slabs/<n>.slab        packfiles: complete small objects, appended
//! ```
//!
//! Encrypted-shard caches use the same store: a shard is just an object
//! in `Ns::Shard`, and the index records only `(addr, size, refcount,
//! last_access)` — never a shard-to-xite association.
//!
//! Durability stance: the index is transactional (redb); object bytes are
//! synced before an insert/slice is indexed, but a crash can still leave
//! a sparse file behind its index record — [`Store::revalidate`] re-scans
//! an object against its outboard and shrinks the present set, so torn
//! writes are refetched instead of served.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};

use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::bitfield::{group_count, groups_for_bytes, GroupBits, GROUP_BYTES};
use crate::verified::{self, outboard_size, OutboardBytes};
use crate::{Ns, ObjId};

const OBJECTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("objects");
const SLABS: TableDefinition<u32, &[u8]> = TableDefinition::new("slabs");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
/// Where a [`Loc::Extern`] object's bytes live, RELATIVE to
/// [`StoreConfig::xite_root`] (`<address>/<inner_path>`). Relative, not
/// absolute, so relocating the data directory does not orphan every object.
const EXTERN: TableDefinition<&[u8], &str> = TableDefinition::new("extern");
/// Object IDs with this Store's one persistent accepted-manifest reference.
/// Multiple manifests that declare the same ID share this single owner.
const MANIFEST_OWNERS: TableDefinition<&[u8], u8> =
    TableDefinition::new("manifest_owners");
/// Object IDs with this Store's one persistent derived-feed reference.
const FEED_OWNERS: TableDefinition<&[u8], u8> = TableDefinition::new("feed_owners");

const SCHEMA_VERSION: u64 = 2;
static STORE_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Hard ceiling on a declared object size. [`Store::ensure_sparse`] takes
/// the size from an untrusted publisher's manifest before any peer has
/// proven the object exists, so the reservation it makes must be bounded.
pub const MAX_OBJECT_BYTES: u64 = 64 << 30;

/// Ceiling on the store's outstanding reservation: the sum, over sparse
/// records, of the declared bytes no peer has sent yet.
///
/// The quota charges held bytes, never the declared size, so one bogus
/// manifest entry cannot wipe the cache. But [`Store::ensure_sparse`]
/// pre-sizes the file pair with `set_len`, and that is a free hole only on
/// filesystems that support one: on NTFS the clusters are really allocated,
/// so unfilled reservations consume disk the quota cannot see. Bounding
/// them keeps "enforce_quota bounds total disk" true there too. The floor is
/// [`MAX_OBJECT_BYTES`]: anything lower would reclaim a single legal
/// max-size fetch while it is still running. Reclaim is LRU, so a
/// reservation that is making progress is the last one considered.
pub const MAX_RESERVED_BYTES: u64 = 2 * MAX_OBJECT_BYTES;

/// Where an object's bytes live.
///
/// Variants are serialized by postcard as a varint discriminant, so a new
/// one may only be APPENDED: inserting ahead of `Slab` would silently
/// reinterpret every record an older build wrote. That is also why adding
/// `Extern` needed no [`SCHEMA_VERSION`] bump — indices 0 and 1 still mean
/// what they always meant, and no existing record carries index 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Loc {
    /// Its own (possibly partial) file pair under `sparse/`.
    Sparse,
    /// A byte range of a slab packfile; always complete.
    Slab { slab: u32, off: u64 },
    /// A COMPLETE file in the xite tree, which is the canonical copy of
    /// those bytes: the store keeps only the `.obao` beside it (~0.4% of
    /// the data) and reads through to the file. The path lives in the
    /// [`EXTERN`] table rather than in this variant, so `Loc` stays `Copy`
    /// and `ObjRecord`'s postcard layout is untouched.
    ///
    /// This is what makes a downloaded xite an ordinary directory of
    /// ordinary files instead of a hash-named cache the user has to export
    /// from, and it is why a completed download is no longer counted as
    /// evictable cache (see [`ObjRecord::held`] and [`Store::evict_lru`]).
    Extern,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ObjRecord {
    size: u64,
    ns: u8,
    loc: Loc,
    /// GroupBits wire runs for sparse objects; unused for slab objects
    /// (they are complete by construction).
    present: Vec<u64>,
    refcount: u32,
    last_access: u64,
}

/// Decode a present set we persisted ourselves. Unlike
/// [`GroupBits::from_wire`] this applies no run cap: the runs come from our
/// own `to_wire`, not from a peer, and a comb-shaped set on a multi-gigabyte
/// object can legitimately hold more runs than the peer-facing decoder
/// accepts. Capping here would silently empty the record, and the next
/// `write_slice` would fold into that empty set and persist it, discarding
/// every group the object holds.
fn bits_from_local(wire: &[u64]) -> GroupBits {
    let mut bits = GroupBits::new();
    let mut cursor = 0u64;
    let mut present = true; // the first run counts present groups
    for &run in wire {
        let end = cursor.saturating_add(run);
        if present && run > 0 {
            bits.add(cursor..end);
        }
        cursor = end;
        present = !present;
    }
    bits
}

/// Records the byte extents a verified decode wrote into the sparse file,
/// so a decode that dies mid-stream can still commit the groups that made
/// it to disk (`Store::write_slice_partial`). The decoder only writes a
/// leaf after verifying it, so every recorded extent holds verified bytes.
struct TrackWrites<W> {
    inner: W,
    written: Vec<Range<u64>>,
}

impl<W: positioned_io::WriteAt> positioned_io::WriteAt for TrackWrites<W> {
    fn write_at(&mut self, pos: u64, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write_at(pos, buf)?;
        if n > 0 {
            let end = pos + n as u64;
            // Leaves arrive in order, so extending the last extent is the
            // common case; anything else opens a new one.
            match self.written.last_mut() {
                Some(last) if last.end == pos => last.end = end,
                _ => self.written.push(pos..end),
            }
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// The chunk groups every byte of which lies inside one of `written`'s
/// extents (the object's final group counts as covered at `size`). A group
/// only partially written must not be marked present: its unwritten tail
/// would be served as zeros.
fn fully_covered_groups(mut written: Vec<Range<u64>>, size: u64) -> GroupBits {
    written.sort_by_key(|r| r.start);
    let mut merged: Vec<Range<u64>> = Vec::new();
    for r in written {
        match merged.last_mut() {
            Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
            _ => merged.push(r),
        }
    }
    let mut bits = GroupBits::new();
    for r in merged {
        let first = r.start.div_ceil(GROUP_BYTES);
        let last = if r.end >= size { group_count(size) } else { r.end / GROUP_BYTES };
        if first < last {
            bits.add(first..last);
        }
    }
    bits
}

impl ObjRecord {
    fn bits(&self) -> GroupBits {
        match self.loc {
            // Both are complete by construction: a slab object is only ever
            // inserted whole, and an object only becomes Extern once every
            // group has landed and verified.
            Loc::Slab { .. } | Loc::Extern => GroupBits::complete(self.size),
            Loc::Sparse => bits_from_local(&self.present),
        }
    }

    fn is_complete(&self) -> bool {
        matches!(self.loc, Loc::Slab { .. } | Loc::Extern) || self.bits().is_complete(self.size)
    }

    /// Bytes actually held on disk. The quota charges this and never
    /// `size`: `size` is a declared value from an untrusted manifest, so
    /// a record for an object nobody ever sent must charge nothing.
    ///
    /// An `Extern` object charges NOTHING either, for a different reason:
    /// its bytes are the user's own file in the xite tree, accounted by
    /// that xite's size, not cache this store is free to reclaim. Charging
    /// it would make the cache quota evict the user's downloads to make
    /// room for someone else's.
    fn held(&self) -> u64 {
        match self.loc {
            Loc::Slab { .. } => self.size,
            Loc::Extern => 0,
            Loc::Sparse => {
                let mut held = 0u64;
                for r in self.bits().ranges() {
                    let start = r.start.saturating_mul(GROUP_BYTES).min(self.size);
                    let end = r.end.saturating_mul(GROUP_BYTES).min(self.size);
                    held = held.saturating_add(end - start);
                }
                held
            }
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SlabMeta {
    len: u64,
    /// Bytes belonging to evicted objects (reclaimed by compaction).
    dead: u64,
    sealed: bool,
}

/// Tuning knobs (tests shrink these radically).
#[derive(Clone, Debug)]
pub struct StoreConfig {
    /// A slab is sealed once it reaches this size and a new one opens.
    pub slab_seal_bytes: u64,
    /// A sealed slab with more than this fraction dead (in 1/256ths) is
    /// compacted on the next eviction pass.
    pub compact_dead_num: u64,
    /// The xite data root (`<data_dir>/data`), which [`Loc::Extern`] paths
    /// are relative to. `None` disables extern objects entirely:
    /// [`Store::adopt_extern`] and [`Store::materialize`] fail, and nothing
    /// else changes. Tools that open a bare store (`examples/export.rs`)
    /// and most unit tests leave it unset.
    pub xite_root: Option<PathBuf>,
}

/// Result of retargeting a materialized object's canonical extern path.
///
/// A second xite can materialize an object whose canonical bytes already
/// live in another xite. In that case [`Store::materialize`] copies the bytes
/// but deliberately leaves the store row pointing at the original owner.
/// Promotion must distinguish that valid shared-object case from a staged
/// extern row that it owns and must retarget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternRelocation {
    /// The row named the exact old path and now names the new path.
    Relocated,
    /// The row names another verified canonical copy and was not changed.
    CanonicalElsewhere,
}

/// Result of rolling back a staged materialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternRollback {
    /// The staged extern bytes moved back into the sparse store and the row
    /// now records [`Loc::Sparse`].
    RestoredSparse,
    /// The row names another verified canonical copy. The caller owns only
    /// the staged duplicate and may remove that file without changing the
    /// store.
    CanonicalElsewhere,
}

/// One extern row retargeted by [`Store::relocate_extern_prefix`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternPrefixEntry {
    /// The content-addressed object whose canonical path moved.
    pub id: ObjId,
    /// Its exact path before the filesystem rename.
    pub old_path: PathBuf,
    /// Its exact path after the filesystem rename.
    pub new_path: PathBuf,
}

/// One canonical extern row whose path is at or below an exact prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternPathEntry {
    pub id: ObjId,
    pub path: PathBuf,
}

/// Result of retiring a revoked extern copy at one exact path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternRetirement {
    /// The exact row was removed, including its outboard.
    Retired,
    /// The live row does not name the requested exact path. It was left
    /// untouched, so the caller may delete only its own duplicate.
    CanonicalElsewhere,
}

/// Result of preserving a revoked extern object's bytes inside the Store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternInternalization {
    /// The exact extern row became a complete sparse row. The xite file was
    /// left untouched because its caller still owns that filesystem path.
    Internalized,
    /// The live row names another verified canonical copy and was unchanged.
    CanonicalElsewhere,
}

/// Bounded random-access sink used to decode one verified Bao range without
/// allocating the prefix before that range in a large object.
struct VerifiedRangeBuffer {
    offset: u64,
    bytes: Vec<u8>,
}

impl positioned_io::WriteAt for VerifiedRangeBuffer {
    fn write_at(&mut self, position: u64, input: &[u8]) -> io::Result<usize> {
        let relative = position.checked_sub(self.offset).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "verified range write precedes buffer")
        })?;
        let start = usize::try_from(relative).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "verified range offset is too large")
        })?;
        let end = start.checked_add(input.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "verified range write overflow")
        })?;
        let destination = self.bytes.get_mut(start..end).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "verified range write exceeds buffer")
        })?;
        destination.copy_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Default for StoreConfig {
    fn default() -> Self {
        // 1 GiB, 50%
        Self { slab_seal_bytes: 1 << 30, compact_dead_num: 128, xite_root: None,
        }
    }
}

/// The store. All methods are `&self`; internal locking makes it safe to
/// share behind an `Arc` (the async layer calls in via spawn_blocking).
pub struct Store {
    root: PathBuf,
    db: Database,
    cfg: StoreConfig,
    /// Serializes slab appends (id + current length of the open slab).
    open_slab: Mutex<(u32, u64)>,
    /// Objects with a sparse verified decode in flight (`write_slice` /
    /// `write_slice_partial`), by count. The delete paths skip an id with
    /// an active writer — and hold this lock across record-delete + file
    /// unlink — so a decode can never mark groups present on a record
    /// recreated over files it did not write: without this, a detached
    /// salvage decode racing a remove + re-`ensure_sparse` would poison
    /// the fresh record's present bits with groups whose bytes went to
    /// the unlinked inode.
    sparse_writers: Mutex<HashMap<ObjId, usize>>,
    /// Objects held out of QUOTA eviction's reach while a caller finishes
    /// post-completion work (a bulk fetch queueing its materialize). A
    /// complete-but-not-yet-materialized object is refcount-0 — exactly what
    /// `evict_lru` reclaims first at quota — so without a hold, one file's
    /// completing `enforce_quota` could evict the bytes another just spent
    /// an hour fetching. In-memory deliberately: a crash drops every hold,
    /// the object is ordinary cache again, and the file re-checks as
    /// missing and refetches. Only eviction consults this; an explicit
    /// `remove` (the user deleting content) still proceeds.
    evict_holds: Mutex<HashMap<ObjId, usize>>,
    /// Narrow per-object serialization for source-preserving location
    /// transitions. Weak entries disappear once the final caller drops its
    /// lock, so the map cannot grow with every object ever seen.
    object_mutation_locks: Mutex<HashMap<ObjId, Weak<Mutex<()>>>>,
    /// Shared for exact extern transitions and exclusive for subtree moves.
    /// A prefix promotion must freeze creation of previously unseen extern
    /// rows below that prefix before it collects and locks the known ids.
    extern_mutation_gate: RwLock<()>,
}

/// Registration of one in-flight sparse decode (see `Store::sparse_writers`).
struct SparseWriteGuard<'a> {
    store: &'a Store,
    id: ObjId,
}

impl<'a> SparseWriteGuard<'a> {
    fn register(store: &'a Store, id: ObjId) -> Self {
        *store.sparse_writers.lock().expect("sparse_writers").entry(id).or_insert(0) += 1;
        Self { store, id }
    }
}

impl Drop for SparseWriteGuard<'_> {
    fn drop(&mut self) {
        let mut writers = self.store.sparse_writers.lock().expect("sparse_writers");
        if let Some(n) = writers.get_mut(&self.id) {
            *n -= 1;
            if *n == 0 {
                writers.remove(&self.id);
            }
        }
    }
}

/// One live hold keeping an object out of eviction while it lives (see
/// `Store::evict_holds`). Counted, so overlapping fetches of the same object
/// each hold independently. Releases on drop, error paths included.
pub struct EvictionHold<'a> {
    store: &'a Store,
    id: ObjId,
}

impl Drop for EvictionHold<'_> {
    fn drop(&mut self) {
        let mut holds = self.store.evict_holds.lock().expect("evict_holds");
        if let Some(n) = holds.get_mut(&self.id) {
            *n -= 1;
            if *n == 0 {
                holds.remove(&self.id);
            }
        }
    }
}

fn db_err(e: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(e)
}

fn enc<T: Serialize>(v: &T) -> Vec<u8> {
    postcard::to_stdvec(v).expect("postcard encode cannot fail on plain data")
}

fn dec<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> io::Result<T> {
    postcard::from_bytes(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

impl Store {
    /// Stable filesystem identity used by higher-level durable receipts.
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        Self::open_with(root, StoreConfig::default())
    }

    pub fn open_with(root: impl Into<PathBuf>, cfg: StoreConfig) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("sparse"))?;
        fs::create_dir_all(root.join("slabs"))?;
        let db = Database::create(root.join("index.redb")).map_err(db_err)?;
        // Only the process that successfully owns this redb handle may clean
        // abandoned Store temporaries. A losing concurrent opener must not
        // unlink an active internalization or outboard staging file.
        cleanup_store_temps(&root.join("sparse"))?;

        let txn = db.begin_write().map_err(db_err)?;
        let mut open_slab;
        // (slab id, tracked len) for every slab, so torn appends that left
        // a slab file longer than its indexed len can be truncated back.
        let mut slab_lens: Vec<(u32, u64)> = Vec::new();
        {
            let mut meta = txn.open_table(META).map_err(db_err)?;
            let schema = meta.get("schema").map_err(db_err)?.map(|g| g.value());
            let migrate_legacy_owners = match schema {
                None => {
                    meta.insert("schema", SCHEMA_VERSION).map_err(db_err)?;
                    false
                }
                Some(SCHEMA_VERSION) => false,
                Some(1) => {
                    meta.insert("schema", SCHEMA_VERSION).map_err(db_err)?;
                    true
                }
                Some(v) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("store schema v{v}, this build speaks v{SCHEMA_VERSION}"),
                    ))
                }
            };
            drop(meta);
            if migrate_legacy_owners {
                // Schema v1 had one undifferentiated refcount. Manifest pins
                // and process-local feed pins could not be distinguished after
                // a crash, so reset them once and let activation rebuild exact
                // typed owners from verified manifests. Cached objects remain
                // complete and simply become eviction-eligible meanwhile.
                let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
                let mut records = Vec::new();
                for row in objects.iter().map_err(db_err)? {
                    let (key, value) = row.map_err(db_err)?;
                    records.push((key.value().to_vec(), dec::<ObjRecord>(value.value())?));
                }
                for (key, mut record) in records {
                    record.refcount = 0;
                    objects
                        .insert(key.as_slice(), enc(&record).as_slice())
                        .map_err(db_err)?;
                }
                drop(objects);
                txn.open_table(MANIFEST_OWNERS).map_err(db_err)?.retain(|_, _| false).map_err(db_err)?;
                txn.open_table(FEED_OWNERS).map_err(db_err)?.retain(|_, _| false).map_err(db_err)?;
            }
            let mut slabs = txn.open_table(SLABS).map_err(db_err)?;
            let open_rows = {
                let mut found = Vec::new();
                for row in slabs.iter().map_err(db_err)? {
                    let (k, v) = row.map_err(db_err)?;
                    let m: SlabMeta = dec(v.value())?;
                    slab_lens.push((k.value(), m.len));
                    if !m.sealed {
                        found.push((k.value(), m));
                    }
                }
                found
            };
            let newest_open = open_rows.last().map(|(id, metadata)| (*id, metadata.len));
            // A prior uncertain append can abandon an open slab and advance
            // the runtime cursor to a newer one. Seal every older open row on
            // restart so its dead tail remains eligible for compaction.
            for (id, mut metadata) in open_rows.into_iter().rev().skip(1) {
                metadata.sealed = true;
                slabs.insert(id, enc(&metadata).as_slice()).map_err(db_err)?;
            }
            open_slab = match newest_open {
                Some(s) => s,
                None => {
                    let next = slabs
                        .iter()
                        .map_err(db_err)?
                        .last()
                        .transpose()
                        .map_err(db_err)?
                        .map(|(k, _)| k.value() + 1)
                        .unwrap_or(0);
                    slabs.insert(next, enc(&SlabMeta::default()).as_slice()).map_err(db_err)?;
                    (next, 0)
                }
            };
            // Make sure OBJECTS and EXTERN exist even in an empty store.
            txn.open_table(OBJECTS).map_err(db_err)?;
            txn.open_table(EXTERN).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        cleanup_unindexed_sparse_files(&root.join("sparse"), &db)?;
        cleanup_unindexed_slab_files(&root.join("slabs"), &db)?;

        // Reconcile physical slab files with the committed lengths. A write
        // that synced bytes but crashed before the index txn committed (or a
        // torn append) leaves the file longer than its tracked len; without
        // this every later O_APPEND insert is recorded at the tracked offset
        // but physically lands past the drift, so reads mis-address. Shrink
        // any over-long slab back to its tracked len. A file shorter than
        // its tracked len means lost committed bytes, so leave it be and let
        // reads fail loudly instead of silently extending with zeros.
        let mut damaged_open = false;
        for (slab, len) in slab_lens {
            let path = root.join("slabs").join(format!("{slab}.slab"));
            let actual = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            if actual > len {
                let f = OpenOptions::new().write(true).open(&path)?;
                f.set_len(len)?;
                f.sync_all()?;
            } else if actual < len && slab == open_slab.0 {
                damaged_open = true;
            }
        }
        // The open slab is SHORTER than its committed len: committed bytes
        // are gone (lost fs writes on a hard kill). O_APPEND writes land at
        // the PHYSICAL end while records use the tracked offset, so every
        // future insert into this slab would be recorded at an address its
        // bytes never reach - each one an unreadable object, and the store
        // poisons itself a little more with every fetch. Seal the damaged
        // slab and append into a fresh one; the lost records' reads still
        // fail loudly and revalidate retires them.
        if damaged_open {
            let txn = db.begin_write().map_err(db_err)?;
            let fresh;
            {
                let mut slabs = txn.open_table(SLABS).map_err(db_err)?;
                let mut m: SlabMeta = slabs
                    .get(open_slab.0)
                    .map_err(db_err)?
                    .map(|g| dec(g.value()))
                    .transpose()?
                    .unwrap_or_default();
                m.sealed = true;
                slabs.insert(open_slab.0, enc(&m).as_slice()).map_err(db_err)?;
                fresh = slabs
                    .iter()
                    .map_err(db_err)?
                    .last()
                    .transpose()
                    .map_err(db_err)?
                    .map(|(k, _)| k.value() + 1)
                    .unwrap_or(0);
                slabs.insert(fresh, enc(&SlabMeta::default()).as_slice()).map_err(db_err)?;
            }
            txn.commit().map_err(db_err)?;
            open_slab = (fresh, 0);
        }

        Ok(Self {
            root,
            db,
            cfg,
            open_slab: Mutex::new(open_slab),
            sparse_writers: Mutex::new(HashMap::new()),
            evict_holds: Mutex::new(HashMap::new()),
            object_mutation_locks: Mutex::new(HashMap::new()),
            extern_mutation_gate: RwLock::new(()),
        })
    }

    fn sparse_path(&self, id: ObjId) -> PathBuf {
        self.root.join("sparse").join(id.to_string())
    }

    fn obao_path(&self, id: ObjId) -> PathBuf {
        self.root.join("sparse").join(format!("{id}.obao"))
    }

    fn install_outboard_atomic(&self, id: ObjId, data: &[u8]) -> io::Result<()> {
        let destination = self.obao_path(id);
        let temporary = store_temp_path(&destination, "outboard")?;
        let result = (|| -> io::Result<()> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            file.write_all(data)?;
            file.sync_all()?;
            drop(file);
            replace_file_atomic(&temporary, &destination)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    /// The relative path recorded for an [`Loc::Extern`] object, if any.
    fn extern_rel(&self, id: ObjId) -> io::Result<Option<String>> {
        let txn = self.db.begin_read().map_err(db_err)?;
        // A store that has never held an extern object has no table yet;
        // that is "no path", not an error.
        let Ok(table) = txn.open_table(EXTERN) else { return Ok(None);
        };
        Ok(table.get(id.0.as_slice()).map_err(db_err)?.map(|g| g.value().to_string()))
    }

    /// The configured xite data root, or an error naming why extern
    /// objects are unavailable.
    fn xite_root(&self) -> io::Result<&std::path::Path> {
        self.cfg.xite_root.as_deref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no xite_root configured for extern objects",
            )
        })
    }

    /// `path` expressed relative to the xite root, which is what the
    /// [`EXTERN`] table stores. Rejects anything outside the root: an
    /// object's bytes must live in a xite tree, never at an arbitrary
    /// path this store would then read through to.
    ///
    /// The stored string is OS-native and purely local — it is an index
    /// detail, never transmitted, and never part of any signed manifest.
    fn rel_of(&self, path: &std::path::Path) -> io::Result<String> {
        let root = self.xite_root()?;
        let rel = path.strip_prefix(root).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is outside the xite root {}", path.display(), root.display()),
            )
        })?;
        // strip_prefix is lexical, so `root/../elsewhere` passes it with a
        // leading `..` that would resolve back OUT of the root when joined.
        // Every production caller already routes through XiteStorage::path,
        // which rejects traversal - this makes the store safe on its own
        // terms rather than by courtesy of its callers.
        use std::path::Component;
        if rel
            .components()
            .any(|c| {
            matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_))
        })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} escapes the xite root {}", path.display(), root.display()),
            ));
        }
        let normalized = normalized_extern_rel(rel)?;
        validate_no_symlink_components(root, &normalized)?;
        normalized
            .to_str()
            .map(str::to_string)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 xite path"))
    }

    /// Open a xite-tree path through a component-by-component no-follow
    /// traversal. A lexical relative path is not enough because an accepted
    /// directory can be replaced by a symlink after manifest verification.
    fn open_xite_file(&self, path: &std::path::Path) -> io::Result<File> {
        let relative = normalized_extern_rel(self.rel_of(path)?)?;
        open_regular_beneath(self.xite_root()?, &relative)
    }

    fn xite_file_exists(&self, path: &std::path::Path) -> io::Result<bool> {
        match self.open_xite_file(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn remove_xite_file(&self, path: &std::path::Path) -> io::Result<()> {
        let relative = normalized_extern_rel(self.rel_of(path)?)?;
        remove_regular_beneath(self.xite_root()?, &relative)
    }

    fn open_extern_file(&self, id: ObjId) -> io::Result<File> {
        let relative = self.extern_rel(id)?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("no extern path for {id}"))
        })?;
        open_regular_beneath(self.xite_root()?, &normalized_extern_rel(relative)?)
    }

    fn open_data_file(&self, id: ObjId, rec: &ObjRecord) -> io::Result<File> {
        match rec.loc {
            Loc::Sparse => File::open(self.sparse_path(id)),
            Loc::Extern => self.open_extern_file(id),
            Loc::Slab { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "slab object has no data file",
            )),
        }
    }

    /// Open a path that can be either a trusted Store backing or a public
    /// xite path. Public paths always use the no-follow traversal.
    fn open_verified_path(&self, path: &std::path::Path) -> io::Result<File> {
        if self
            .cfg
            .xite_root
            .as_deref()
            .is_some_and(|root| path.strip_prefix(root).is_ok())
        {
            return self.open_xite_file(path);
        }
        let file = File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular file", path.display()),
            ));
        }
        Ok(file)
    }

    /// Resolve an extern relative path against the configured xite root.
    fn extern_path(&self, id: ObjId) -> io::Result<PathBuf> {
        let root = self.xite_root()?;
        let rel = self.extern_rel(id)?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("no extern path for {id}"))
        })?;
        Ok(root.join(rel))
    }

    /// Record (or clear) an object's extern path inside `txn`.
    fn put_extern_in(
        txn: &redb::WriteTransaction,
        id: ObjId,
        rel: Option<&str>) -> io::Result<()> {
        let mut table = txn.open_table(EXTERN).map_err(db_err)?;
        match rel {
            Some(rel) => {
                table.insert(id.0.as_slice(), rel).map_err(db_err)?;
            }
            None => {
                table.remove(id.0.as_slice()).map_err(db_err)?;
            }
        }
        Ok(())
    }

    /// An owner marker is meaningful only while its object record exists.
    /// Every record deletion clears both typed domains in the same redb
    /// transaction, so a later reinsertion can claim fresh references instead
    /// of inheriting marker-only phantom ownership.
    fn clear_owner_markers_in(
        txn: &redb::WriteTransaction,
        id: ObjId,
    ) -> io::Result<()> {
        txn.open_table(MANIFEST_OWNERS)
            .map_err(db_err)?
            .remove(id.0.as_slice())
            .map_err(db_err)?;
        txn.open_table(FEED_OWNERS)
            .map_err(db_err)?
            .remove(id.0.as_slice())
            .map_err(db_err)?;
        Ok(())
    }

    fn slab_path(&self, slab: u32) -> PathBuf {
        self.root.join("slabs").join(format!("{slab}.slab"))
    }

    fn get_record(&self, id: ObjId) -> io::Result<Option<ObjRecord>> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(OBJECTS).map_err(db_err)?;
        match table.get(id.0.as_slice()).map_err(db_err)? {
            Some(g) => Ok(Some(dec(g.value())?)),
            None => Ok(None),
        }
    }

    fn object_mutation_lock(&self, id: ObjId) -> Arc<Mutex<()>> {
        let mut locks = self.object_mutation_locks.lock().expect("object_mutation_locks");
        if let Some(lock) = locks.get(&id).and_then(Weak::upgrade) {
            return lock;
        }
        locks.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(Mutex::new(()));
        locks.insert(id, Arc::downgrade(&lock));
        lock
    }

    /// Overwrite a record wholesale. Only the tests plant records this way
    /// now — every production path either inserts inside its own txn
    /// (`insert_bytes`, `commit_extern`) or read-modify-writes through
    /// [`Self::update_record_with`], which folds in concurrent updates
    /// instead of clobbering them with a stale snapshot.
    #[cfg(test)]
    fn put_record(&self, id: ObjId, rec: &ObjRecord) -> io::Result<()> {
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = txn.open_table(OBJECTS).map_err(db_err)?;
            table.insert(id.0.as_slice(), enc(rec).as_slice()).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)
    }

    /// Read-modify-write one record inside a single write transaction.
    /// Callers that do slow IO (streaming a slice to a peer, decoding one)
    /// must land their change this way: redb serializes write txns, so a
    /// concurrent `present`/`refcount` update is folded in rather than
    /// clobbered by the stale snapshot the caller started from.
    fn update_record_with(
        &self,
        id: ObjId,
        durability: Durability,
        f: impl FnOnce(&mut ObjRecord),
    ) -> io::Result<ObjRecord> {
        let mut txn = self.db.begin_write().map_err(db_err)?;
        txn.set_durability(durability).map_err(db_err)?;
        let updated;
        {
            let mut table = txn.open_table(OBJECTS).map_err(db_err)?;
            let mut rec: ObjRecord = match table.get(id.0.as_slice()).map_err(db_err)? {
                Some(g) => dec(g.value())?,
                None => {
                    return Err(io::Error::new(io::ErrorKind::NotFound, format!("object {id}"),
                    ))
                }
            };
            f(&mut rec);
            table.insert(id.0.as_slice(), enc(&rec).as_slice()).map_err(db_err)?;
            updated = rec;
        }
        txn.commit().map_err(db_err)?;
        Ok(updated)
    }

    fn update_record(&self, id: ObjId, f: impl FnOnce(&mut ObjRecord)) -> io::Result<ObjRecord> {
        self.update_record_with(id, Durability::Immediate, f)
    }

    /// Bump an object's LRU stamp. Non-durable on purpose: every read a
    /// peer asks for touches, and an fsync per touch serializes the whole
    /// store behind the disk. A stamp lost to a crash only costs eviction
    /// ordering, and the next real write commits durably.
    fn touch(&self, id: ObjId, now: u64) -> io::Result<()> {
        let r = self.update_record_with(id, Durability::None, |rec| {
            rec.last_access = rec.last_access.max(now);
        });
        match r {
            Ok(_) => Ok(()),
            // Evicted between the read and the touch: nothing to stamp.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn required(&self, id: ObjId) -> io::Result<ObjRecord> {
        self.get_record(id)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("object {id}")))
    }

    /// Prepare an empty sparse file pair exactly, and make both directory
    /// entries durable before an OBJECTS row can name them. This is used only
    /// while the per-object mutation lock is held and no claimed groups are
    /// being preserved, so shrinking crash residue is safe.
    fn prepare_empty_sparse_backing(&self, id: ObjId, size: u64) -> io::Result<()> {
        let sparse = self.sparse_path(id);
        let outboard = self.obao_path(id);
        let data = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&sparse)?;
        data.set_len(size)?;
        data.sync_all()?;
        let obao = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&outboard)?;
        obao.set_len(outboard_size(size))?;
        obao.sync_all()?;
        sync_directory_entry(self.root.join("sparse").as_path())
    }

    fn insert_empty_sparse_record_if_absent(
        &self,
        id: ObjId,
        ns: u8,
        size: u64,
        now: u64,
    ) -> io::Result<()> {
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
            if objects.get(id.0.as_slice()).map_err(db_err)?.is_none() {
                let record = ObjRecord {
                    size,
                    ns,
                    loc: Loc::Sparse,
                    present: Vec::new(),
                    refcount: 0,
                    last_access: now,
                };
                objects
                    .insert(id.0.as_slice(), enc(&record).as_slice())
                    .map_err(db_err)?;
            }
        }
        txn.commit().map_err(db_err)
    }

    fn book_dead_slab_append(&self, slab: u32, end: u64, bytes: u64) -> io::Result<()> {
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut slabs = txn.open_table(SLABS).map_err(db_err)?;
            let mut metadata = slabs
                .get(slab)
                .map_err(db_err)?
                .map(|guard| dec::<SlabMeta>(guard.value()))
                .transpose()?
                .unwrap_or_default();
            metadata.len = metadata.len.max(end);
            metadata.dead = metadata.dead.saturating_add(bytes);
            if metadata.len >= self.cfg.slab_seal_bytes {
                metadata.sealed = true;
                if slabs.get(slab + 1).map_err(db_err)?.is_none() {
                    slabs
                        .insert(slab + 1, enc(&SlabMeta::default()).as_slice())
                        .map_err(db_err)?;
                }
            }
            slabs
                .insert(slab, enc(&metadata).as_slice())
                .map_err(db_err)?;
        }
        txn.commit().map_err(db_err)
    }

    /// Whether the store has any record of this object.
    pub fn contains(&self, id: ObjId) -> io::Result<bool> {
        Ok(self.get_record(id)?.is_some())
    }

    /// Present chunk groups (complete for slab objects, absent -> empty).
    pub fn present_bits(&self, id: ObjId) -> io::Result<GroupBits> {
        Ok(self.get_record(id)?.map(|r| r.bits()).unwrap_or_default())
    }

    /// Whether the object is fully present.
    pub fn is_complete(&self, id: ObjId) -> io::Result<bool> {
        Ok(self.get_record(id)?.map(|r| r.is_complete()).unwrap_or(false))
    }

    /// Whether this object's bytes are already the xite's own file
    /// ([`Loc::Extern`]) rather than a copy in the store. Callers use it to
    /// skip a materialize that has already happened.
    pub fn is_extern(&self, id: ObjId) -> io::Result<bool> {
        Ok(self.get_record(id)?.map(|r| matches!(r.loc, Loc::Extern)).unwrap_or(false))
    }

    /// (size, complete) for an indexed object, `None` if unknown.
    pub fn info(&self, id: ObjId) -> io::Result<Option<(u64, bool)>> {
        Ok(self.get_record(id)?.map(|r| (r.size, r.is_complete())))
    }

    /// Insert a COMPLETE object (verified against its id before a byte is
    /// written — a poisoned insert fails, it does not stick). Returns
    /// false if the object was already present (dedup hit).
    ///
    /// Bytes land in the open slab, so this is meant for small objects
    /// and shards; stream big public files through the sparse path.
    pub fn insert_bytes(&self, id: ObjId, ns: Ns, bytes: &[u8], now: u64) -> io::Result<bool> {
        if !verified::verify_whole(bytes, id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bytes do not hash to {id}"),
            ));
        }
        let _externs = self.extern_mutation_gate.read().expect("extern mutation");
        let object_lock = self.object_mutation_lock(id);
        let _object = object_lock.lock().expect("object mutation");
        let existing = self.get_record(id)?;
        if let Some(rec) = existing.as_ref() {
            if rec.is_complete() {
                let valid = match rec.loc {
                    Loc::Slab { slab, off } => match self.read_slab(slab, off, rec.size) {
                        Ok(stored) => verified::verify_whole(&stored, id),
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::NotFound
                                    | io::ErrorKind::UnexpectedEof
                                    | io::ErrorKind::InvalidData
                            ) =>
                        {
                            false
                        }
                        Err(error) => return Err(error),
                    },
                    Loc::Sparse => {
                        match verify_complete_file(id, rec.size, &self.sparse_path(id)) {
                            Ok(()) => {
                                self.install_outboard_from_path(
                                    id,
                                    rec.size,
                                    &self.sparse_path(id),
                                )?;
                                true
                            }
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::NotFound
                                        | io::ErrorKind::UnexpectedEof
                                        | io::ErrorKind::InvalidData
                                ) =>
                            {
                                false
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    Loc::Extern => self.extern_still_matches(id, rec)?,
                };
                if valid {
                    if rec.last_access < now {
                        self.touch(id, now)?;
                    }
                    return Ok(false);
                }
            }
        }
        // A sparse decode never takes `object_mutation_lock`. Exclude its
        // registration through the backing swap so verified whole bytes
        // cannot race a late present-bit commit for the old sparse files.
        let sparse_writers = existing
            .as_ref()
            .filter(|record| matches!(record.loc, Loc::Sparse))
            .map(|_| self.sparse_writers.lock().expect("sparse_writers"));
        if let Some(writers) = sparse_writers.as_ref() {
            if writers.contains_key(&id) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!("object {id} has an active sparse writer"),
                ));
            }
        }

        let mut open = self.open_slab.lock().expect("slab lock");
        let (slab, off) = (open.0, open.1);
        let slab_path = self.slab_path(slab);
        let slab_existed = slab_path.exists();
        let mut f = OpenOptions::new().create(true).append(true).open(&slab_path)?;
        if f.metadata()?.len() != off {
            // A runtime-discovered torn slab can be physically shorter than
            // its committed tracked length. Restore the append position
            // before recording this verified repair at `off`.
            f.set_len(off)?;
            f.sync_data()?;
        }
        if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_data()) {
            // Torn append (e.g. disk full): shrink the slab back to the
            // pre-write offset so the next insert is not mis-addressed.
            let _ = f.set_len(off);
            let _ = f.sync_data();
            return Err(e);
        }
        if !slab_existed {
            sync_directory_entry(self.root.join("slabs").as_path())?;
        }
        let new_len = off + bytes.len() as u64;

        let txn = self.db.begin_write().map_err(db_err)?;
        let previous;
        {
            let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
            previous = objects
                .get(id.0.as_slice())
                .map_err(db_err)?
                .map(|guard| dec::<ObjRecord>(guard.value()))
                .transpose()?;
            let rec = ObjRecord {
                size: bytes.len() as u64,
                ns: ns_to_u8(ns),
                loc: Loc::Slab { slab, off },
                present: Vec::new(),
                refcount: previous.as_ref().map(|record| record.refcount).unwrap_or(0),
                last_access: previous
                    .as_ref()
                    .map(|record| record.last_access.max(now))
                    .unwrap_or(now),
            };
            objects
                .insert(id.0.as_slice(), enc(&rec).as_slice())
                .map_err(db_err)?;
            if previous
                .as_ref()
                .is_some_and(|record| matches!(record.loc, Loc::Extern))
            {
                Self::put_extern_in(&txn, id, None)?;
            }

            let mut slabs = txn.open_table(SLABS).map_err(db_err)?;
            let mut m: SlabMeta = slabs
                .get(slab)
                .map_err(db_err)?
                .map(|g| dec(g.value()))
                .transpose()?
                .unwrap_or_default();
            m.len = new_len;
            if let Some(ObjRecord {
                loc: Loc::Slab { slab: old_slab, .. },
                size: old_size,
                ..
            }) = previous.as_ref()
            {
                if *old_slab == slab {
                    m.dead = m.dead.saturating_add(*old_size);
                } else {
                    let mut old: SlabMeta = slabs
                        .get(*old_slab)
                        .map_err(db_err)?
                        .map(|guard| dec(guard.value()))
                        .transpose()?
                        .unwrap_or_default();
                    old.dead = old.dead.saturating_add(*old_size);
                    slabs
                        .insert(*old_slab, enc(&old).as_slice())
                        .map_err(db_err)?;
                }
            }
            if m.len >= self.cfg.slab_seal_bytes {
                m.sealed = true;
                slabs.insert(slab + 1, enc(&SlabMeta::default()).as_slice()).map_err(db_err)?;
            }
            slabs.insert(slab, enc(&m).as_slice()).map_err(db_err)?;
        }
        let next_open = if new_len >= self.cfg.slab_seal_bytes {
            (slab + 1, 0)
        } else {
            (slab, new_len)
        };
        if let Err(commit_error) = txn.commit().map_err(db_err) {
            match self.get_record(id) {
                Ok(Some(record))
                    if record.loc == (Loc::Slab { slab, off })
                        && record.size == bytes.len() as u64 =>
                {
                    // The new row is visible, but the failed commit did not
                    // prove it durable. Keep every prior backing intact and
                    // return the original error. A later idempotent insert can
                    // verify this row and finish cleanup.
                    *open = next_open;
                }
                Ok(_) => {
                    // A successful status read proves this process still sees
                    // the prior row. Roll back only the unindexed append.
                    if f.set_len(off).and_then(|()| f.sync_data()).is_err() {
                        let recovery =
                            self.book_dead_slab_append(slab, new_len, bytes.len() as u64);
                        *open = next_open;
                        if let Err(recovery_error) = recovery {
                            return Err(io::Error::other(format!(
                                "{commit_error}; could not record failed slab append: {recovery_error}"
                            )));
                        }
                    }
                }
                Err(_) => {
                    // The outcome is unknown. Never truncate bytes that a
                    // durable row may name. Stop appending to this slab for
                    // this process. Startup will reconcile its physical tail
                    // against the committed metadata.
                    *open = (slab.saturating_add(1), 0);
                }
            }
            return Err(commit_error);
        }
        *open = next_open;
        if let Some(previous) = previous {
            match previous.loc {
                Loc::Sparse => {
                    let _ = remove_file_durable(&self.sparse_path(id));
                    let _ = remove_file_durable(&self.obao_path(id));
                }
                Loc::Extern => {
                    let _ = remove_file_durable(&self.obao_path(id));
                }
                Loc::Slab { .. } => {}
            }
        }
        drop(sparse_writers);
        Ok(true)
    }

    fn cleanup_sparse_duplicate_after_extern(&self, id: ObjId) -> io::Result<u64> {
        let writers = self.sparse_writers.lock().expect("sparse_writers");
        if writers.contains_key(&id) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("object {id} still has an active sparse writer"),
            ));
        }
        self.remove_sparse_duplicate_file(id)
    }

    fn remove_sparse_duplicate_file(&self, id: ObjId) -> io::Result<u64> {
        let sparse = self.sparse_path(id);
        let metadata = match fs::symlink_metadata(&sparse) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error),
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected sparse duplicate for {id}"),
            ));
        }
        remove_file_durable(&sparse)?;
        Ok(metadata.len())
    }

    /// Adopt a COMPLETE file already in the xite tree as this object: the
    /// file stays exactly where it is and becomes the object's canonical
    /// bytes, and the store keeps only the outboard computed by streaming
    /// it. `rel` is relative to [`StoreConfig::xite_root`]
    /// (`<address>/<inner_path>`). Returns false if the object is already
    /// in the store.
    ///
    /// This is both the migration pass (a xite's existing files become EDX
    /// objects with no re-download) and what the publisher's own content
    /// uses, so an author's directory is byte-for-byte what every
    /// downloader ends up with.
    ///
    /// Nothing is linked or copied. An earlier version hard-linked the file
    /// into `sparse/`, which meant editing your own file silently changed
    /// the object under the store; now an edit simply makes the file stop
    /// matching, which [`Self::read_range`] and [`Self::revalidate`] catch
    /// and turn into a refetch. Re-signing a xite re-adopts under the
    /// file's new id.
    pub fn adopt_extern(
        &self,
        id: ObjId,
        ns: Ns,
        path: &std::path::Path,
        now: u64,
    ) -> io::Result<bool> {
        let _externs = self.extern_mutation_gate.write().expect("extern mutation");
        let object_lock = self.object_mutation_lock(id);
        let _object = object_lock.lock().expect("object mutation");
        let rel = self.rel_of(path)?;
        let existing = self.get_record(id)?;
        if let Some(rec) = existing.as_ref() {
            let valid = if rec.is_complete() {
                match rec.loc {
                    Loc::Slab { slab, off } => match self.read_slab(slab, off, rec.size) {
                        Ok(stored) => verified::verify_whole(&stored, id),
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::NotFound
                                    | io::ErrorKind::UnexpectedEof
                                    | io::ErrorKind::InvalidData
                            ) =>
                        {
                            false
                        }
                        Err(error) => return Err(error),
                    },
                    Loc::Sparse => {
                        match verify_complete_file(id, rec.size, &self.sparse_path(id)) {
                            Ok(()) => {
                                self.install_outboard_from_path(
                                    id,
                                    rec.size,
                                    &self.sparse_path(id),
                                )?;
                                true
                            }
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::NotFound
                                        | io::ErrorKind::UnexpectedEof
                                        | io::ErrorKind::InvalidData
                                ) =>
                            {
                                false
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    Loc::Extern => self.extern_still_matches(id, rec)?,
                }
            } else {
                false
            };
            if valid {
                if matches!(rec.loc, Loc::Extern) {
                    self.cleanup_sparse_duplicate_after_extern(id)?;
                }
                if rec.last_access < now {
                    self.touch(id, now)?;
                }
                return Ok(false);
            }
        }
        self.ensure_extern_destination_available(id, &normalized_extern_key(&rel)?)?;
        let source = self.open_xite_file(path)?;
        let size = source.metadata()?.len();
        let ob = OutboardBytes::from_reader(io::BufReader::new(source), size)?;
        if ob.root != id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} does not hash to {id}", path.display()),
            ));
        }
        // A sparse decoder does not take the object lock. Exclude its
        // registration through the record swap so it cannot commit present
        // bits into the new extern row.
        let sparse_write = if existing
            .as_ref()
            .is_some_and(|record| matches!(record.loc, Loc::Sparse))
        {
            let mut writers = self.sparse_writers.lock().expect("sparse_writers");
            if writers.contains_key(&id) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!("object {id} has an active sparse writer"),
                ));
            }
            writers.insert(id, 1);
            Some(SparseWriteGuard { store: self, id })
        } else {
            None
        };
        let outboard_existed = self.obao_path(id).exists();
        self.install_outboard_atomic(id, &ob.data)?;
        match self.commit_extern(id, ns, size, &rel, now) {
            Ok(inserted) => {
                if sparse_write.is_some() {
                    self.remove_sparse_duplicate_file(id)?;
                }
                Ok(inserted)
            }
            Err(error) => {
                // A failed commit can have an uncertain durable outcome.
                // Preserve both the previous backing and the new outboard.
                // A later idempotent adoption verifies the visible row and
                // removes any stale sparse duplicate.
                if !outboard_existed && matches!(self.get_record(id), Ok(None)) {
                    let _ = remove_file_durable(&self.obao_path(id));
                }
                Err(error)
            }
        }
    }

    /// One-time reclaim for stores written before extern objects existed:
    /// if this object is a COMPLETE sparse copy of a file that is already
    /// sitting in the xite tree, adopt the tree's copy and delete the
    /// store's. Returns the bytes reclaimed (0 when there was nothing to do).
    ///
    /// Every materialized file used to be stored twice - once as the xite's
    /// file, once as the object - which on a real node meant the object
    /// store matching the data directory byte for byte. This gives that
    /// space back on the next start, with no re-download: the outboard is
    /// already correct for those bytes, so adopting is just a record swap
    /// after re-verifying the tree copy really is the object.
    pub fn reclaim_duplicate(&self, id: ObjId, path: &std::path::Path, now: u64,
    ) -> io::Result<u64> {
        let _externs = self.extern_mutation_gate.write().expect("extern mutation");
        let object_lock = self.object_mutation_lock(id);
        let _object = object_lock.lock().expect("object mutation");
        let rel = self.rel_of(path)?;
        let Some(rec) = self.get_record(id)? else { return Ok(0);
        };
        if matches!(rec.loc, Loc::Extern) && rec.is_complete() {
            if self.extern_still_matches(id, &rec)? {
                return self.cleanup_sparse_duplicate_after_extern(id);
            }
            return Ok(0);
        }
        if !matches!(rec.loc, Loc::Sparse) || !rec.is_complete() {
            return Ok(0);
        }
        let source = self.open_xite_file(path)?;
        if source.metadata()?.len() != rec.size {
            return Ok(0);
        }
        // Re-verify the TREE copy against the object id before trusting it:
        // the sparse copy is the one we know verified, and the file may have
        // been edited since it was written.
        let ob = OutboardBytes::from_reader(io::BufReader::new(source), rec.size)?;
        if ob.root != id {
            return Ok(0);
        }
        // The sparse record may be complete while its outboard is missing or
        // torn after a crash. The verified tree copy gives us an exact fresh
        // outboard. Install it durably before exposing the extern row.
        self.install_outboard_atomic(id, &ob.data)?;
        let freed = rec.held();
        // Guarded like `materialize`: no delete path may unlink the sparse
        // file between the swap and our own removal of it.
        let _writing = SparseWriteGuard::register(self, id);
        match self.commit_extern(id, u8_to_ns(rec.ns), rec.size, &rel, now) {
            Ok(_) => {
                self.remove_sparse_duplicate_file(id)?;
                Ok(freed)
            }
            // Preserve the verified sparse source on every uncertain commit.
            // A retry that observes the extern row removes the duplicate.
            Err(error) => Err(error),
        }
    }

    /// Turn a COMPLETE sparse object into an extern one by moving its bytes
    /// into the xite tree at `rel`: the download stops being a hash-named
    /// blob in the cache and becomes the user's file, stored once.
    ///
    /// This is the step that makes a streamed video an actual file. The
    /// outboard stays in the store beside it, so the object goes on serving
    /// verified ranges to peers with no re-hash and no second copy.
    ///
    /// The sparse source stays intact until the extern row commits. A hard
    /// link avoids a second physical copy on the normal same-filesystem path;
    /// filesystems without hard links fall back to a synced copy. This order
    /// makes a crash before the index commit retryable as a sparse object,
    /// instead of leaving the index pointed at bytes that were already moved.
    pub fn materialize(&self, id: ObjId, dst: &std::path::Path, now: u64) -> io::Result<()> {
        let _externs = self.extern_mutation_gate.write().expect("extern mutation");
        let object_lock = self.object_mutation_lock(id);
        let _object = object_lock.lock().expect("object mutation");
        let rel = self.rel_of(dst)?;
        let destination_rel = normalized_extern_rel(&rel)?;
        self.ensure_extern_destination_available(id, &normalized_extern_key(&rel)?)?;
        let rec = self.required(id)?;
        match rec.loc {
            // Already extern somewhere. That is NOT automatically "nothing to
            // do": the record points at ONE canonical path, and the caller may
            // be materializing a DIFFERENT declared path with the same bytes
            // (two identical files in a xite, or the same movie in two xites -
            // cross-xite dedup). An early unconditional Ok here left every
            // such second path a phantom: reported materialized, never on
            // disk. And if the user deleted the canonical file, Ok was a lie
            // outright - the record must retire so the caller refetches.
            Loc::Extern => return self.materialize_from_extern(id, &rec, dst),
            Loc::Slab { .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "slab objects materialize by writing their bytes, not by moving",
                ))
            }
            Loc::Sparse => {}
        }
        if !rec.is_complete() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{id} is incomplete; only a whole object becomes a file"),
            ));
        }
        // Registered for the same reason `write_slice` does: from here to
        // the record swap the delete paths must leave this object alone,
        // or an eviction could unlink the sparse file mid-move.
        let _writing = SparseWriteGuard::register(self, id);
        let src = self.sparse_path(id);
        if !src.is_file() && self.open_xite_file(dst).is_ok() {
            // Legacy/interrupted order moved sparse -> destination before the
            // row commit. Verify the only surviving bytes and finish the row
            // swap idempotently on restart.
            self.verify_extern_bytes_at(id, &rec, dst)?;
            self.install_outboard_from_path(id, rec.size, dst)?;
            self.commit_extern(id, u8_to_ns(rec.ns), rec.size, &rel, now)?;
            return Ok(());
        }
        if !src.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("sparse backing for {id} is missing"),
            ));
        }
        let source = File::open(&src)?;
        // The outboard returned here was computed over the INSTALLED inode
        // (the post-link re-verify); installing it directly skips a third
        // full read+hash pass over the file.
        let outboard = copy_regular_file_beneath(
            self.xite_root()?,
            &destination_rel,
            source,
            Some(&src),
            rec.size,
            id,
        )
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot preserve sparse {} while materializing {}: {error}",
                    src.display(),
                    dst.display()
                ),
            )
        })?;
        self.install_outboard_atomic(id, &outboard.data)?;
        if let Err(error) = self.commit_extern(id, u8_to_ns(rec.ns), rec.size, &rel, now) {
            // redb may have made the commit durable before reporting an I/O
            // error. Keep both verified copies so the idempotent retry can
            // inspect the live row and complete the right side.
            return Err(error);
        }
        fs::remove_file(&src)?;
        Ok(())
    }

    /// Materialize `dst` for an object that is ALREADY extern at its
    /// canonical path. Three cases:
    ///
    /// - `dst` IS the canonical path and the file is there: idempotent no-op
    ///   (a concurrent fetch won the race, or the caller retried).
    /// - `dst` is a different path and the canonical file still verifies:
    ///   copy it out, so the second xite's tree is self-contained too. The
    ///   record keeps pointing at the one canonical path; the copy is an
    ///   ordinary tree file like any other. Verified before copying because
    ///   the canonical file is user-editable - handing xite B a file the
    ///   user edited under xite A would give B bytes that fail its manifest.
    /// - The canonical file is missing or no longer matches: retire the
    ///   record and return NotFound, so the caller's error path leads to a
    ///   real refetch instead of an eternal "complete but fileless" loop.
    fn materialize_from_extern(
        &self,
        id: ObjId,
        rec: &ObjRecord,
        dst: &std::path::Path,
    ) -> io::Result<()> {
        let cur = self.extern_path(id)?;
        if normalized_extern_key(self.rel_of(&cur)?)?
            == normalized_extern_key(self.rel_of(dst)?)?
        {
            // The canonical path itself: cheap existence check, not a full
            // re-hash - this is the hot idempotent-retry case, and an edited
            // file at its own path is revalidate's job, as it always was.
            match self.open_xite_file(&cur) {
                Ok(_) => {
                    let sparse = self.sparse_path(id);
                    if sparse.is_file() {
                        // Source-preserving materialization committed the extern
                        // row before unlinking its old sparse copy. Verify both
                        // before completing that final cleanup on retry.
                        self.verify_extern_bytes_at(id, rec, &cur)?;
                        self.verify_extern_bytes_at(id, rec, &sparse)?;
                        remove_file_durable(&sparse)?;
                    }
                    return Ok(());
                }
                Err(error)
                    if !matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::InvalidInput
                    ) =>
                {
                    return Err(error);
                }
                Err(_) => {}
            }
        } else {
            match self.extern_still_matches(id, rec) {
                Ok(true) => {
                    // Keep two canonical tree paths independent. A hard link here
                    // would let an edit under one xite silently mutate the other.
                    let source = self.open_xite_file(&cur)?;
                    let destination_rel = normalized_extern_rel(self.rel_of(dst)?)?;
                    copy_regular_file_beneath(
                        self.xite_root()?,
                        &destination_rel,
                        source,
                        None,
                        rec.size,
                        id,
                    )?;
                    return Ok(());
                }
                Ok(false) => {}
                Err(error) => return Err(error),
            }
        }
        self.retire_extern(id)?;
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("extern backing for {id} at {} is gone or altered; retired for refetch", cur.display()),
        ))
    }

    /// Retarget an extern row after its owned file has been renamed from
    /// `old` to `new` during an atomic xite promotion.
    ///
    /// Both paths must be inside the configured xite root. The new bytes are
    /// re-hashed before the row changes. The write transaction then rechecks
    /// that the object is still extern and that its row still names the exact
    /// old path. A valid canonical copy owned by another xite is reported as
    /// [`ExternRelocation::CanonicalElsewhere`] and is never retargeted.
    pub fn relocate_extern(
        &self,
        id: ObjId,
        old: &std::path::Path,
        new: &std::path::Path,
    ) -> io::Result<ExternRelocation> {
        let _externs = self.extern_mutation_gate.write().expect("extern mutation");
        let object_lock = self.object_mutation_lock(id);
        let _object = object_lock.lock().expect("object mutation");
        self.relocate_extern_locked(id, old, new)
    }

    /// Move a caller-owned path and its exact extern row under one object
    /// mutation lock. `canonical_old` is the path currently named by the Store;
    /// `source` can differ when two identical promotion versions share one id.
    /// If row relocation fails before committing, the filesystem move is
    /// reversed before the lock is released.
    pub fn move_and_relocate_extern(
        &self,
        id: ObjId,
        canonical_old: &std::path::Path,
        source: &std::path::Path,
        destination: &std::path::Path,
        mut move_path: impl FnMut(&std::path::Path, &std::path::Path) -> io::Result<()>,
    ) -> io::Result<ExternRelocation> {
        let _externs = self.extern_mutation_gate.write().expect("extern mutation");
        let object_lock = self.object_mutation_lock(id);
        let _object = object_lock.lock().expect("object mutation");
        let old_key = normalized_extern_key(self.rel_of(canonical_old)?)?;
        let destination_rel = normalized_extern_rel(self.rel_of(destination)?)?;
        let new_key = normalized_extern_key(&destination_rel)?;
        let rec = self.required(id)?;
        if !matches!(rec.loc, Loc::Extern) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object {id} is not extern"),
            ));
        }
        let current = self.extern_rel(id)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("extern object {id} has no path"),
            )
        })?;
        let canonical_elsewhere = normalized_extern_key(&current)? != old_key;
        if canonical_elsewhere && !self.extern_still_matches(id, &rec)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "extern object {id} does not own {} and its canonical copy is invalid",
                    canonical_old.display()
                ),
            ));
        }
        self.ensure_extern_destination_available(id, &new_key)?;

        if let Err(error) = move_path(source, destination) {
            if source.exists() || !destination.exists() {
                return Err(error);
            }
            let rollback = move_path(destination, source);
            if source.exists() && !destination.exists() {
                return Err(match rollback {
                    Ok(()) => error,
                    Err(rollback) => io::Error::new(
                        error.kind(),
                        format!(
                            "filesystem move failed after rename: {error}; rollback sync failed: {rollback}"
                        ),
                    ),
                });
            }
            self.verify_extern_bytes_at(id, &rec, destination)
                .map_err(|verify| {
                    io::Error::new(
                        verify.kind(),
                        format!(
                            "filesystem move failed after rename: {error}; rollback did not restore {}; destination verification failed: {verify}",
                            source.display()
                        ),
                    )
                })?;
            if canonical_elsewhere {
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "filesystem move kept a separate canonical Store owner but was not durably synced: {error}"
                    ),
                ));
            }
            self.relocate_extern_locked(id, canonical_old, destination)
                .map_err(|relocate| {
                    io::Error::new(
                        relocate.kind(),
                        format!(
                            "filesystem move failed after rename: {error}; rollback did not restore {}; Store relocation also failed: {relocate}",
                            source.display()
                        ),
                    )
                })?;
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "filesystem move was aligned in the Store but was not durably synced: {error}"
                ),
            ));
        }
        if let Err(error) = self.verify_extern_bytes_at(id, &rec, destination) {
            if let Err(rollback) = move_path(destination, source) {
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "moved extern verification failed: {error}; filesystem rollback failed: {rollback}"
                    ),
                ));
            }
            return Err(error);
        }
        if canonical_elsewhere {
            return Ok(ExternRelocation::CanonicalElsewhere);
        }
        match self.relocate_extern_locked(id, canonical_old, destination) {
            Ok(result) => Ok(result),
            Err(error) => {
                // A failed database commit can have an uncertain return value.
                // If the live row already names the destination, keep the
                // matching filesystem move and finish as relocated.
                match self.extern_rel(id) {
                    Ok(Some(path))
                        if normalized_extern_rel(&path)
                            .is_ok_and(|path| path == destination_rel) =>
                    {
                        return Ok(ExternRelocation::Relocated);
                    }
                    Err(status) => {
                        return Err(io::Error::new(
                            status.kind(),
                            format!(
                                "extern relocation failed: {error}; commit status could not be read: {status}; destination was preserved"
                            ),
                        ));
                    }
                    _ => {}
                }
                if let Err(rollback) = move_path(destination, source) {
                    return Err(io::Error::new(
                        error.kind(),
                        format!(
                            "extern relocation failed: {error}; filesystem rollback failed: {rollback}"
                        ),
                    ));
                }
                Err(error)
            }
        }
    }

    fn ensure_extern_destination_available(
        &self,
        id: ObjId,
        destination_key: &(String, String),
    ) -> io::Result<()> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(EXTERN).map_err(db_err)?;
        for row in table.iter().map_err(db_err)? {
            let (key, value) = row.map_err(db_err)?;
            let raw: [u8; 32] = key.value().try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "malformed extern object id")
            })?;
            let claimant = ObjId(raw);
            if claimant != id && normalized_extern_key(value.value())? == *destination_key {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("extern destination is already claimed by {claimant}"),
                ));
            }
        }
        Ok(())
    }

    fn relocate_extern_locked(
        &self,
        id: ObjId,
        old: &std::path::Path,
        new: &std::path::Path,
    ) -> io::Result<ExternRelocation> {
        let old_rel = normalized_extern_rel(self.rel_of(old)?)?;
        let new_rel = normalized_extern_rel(self.rel_of(new)?)?;
        let old_key = normalized_extern_key(&old_rel)?;
        let new_key = normalized_extern_key(&new_rel)?;
        let rec = self.required(id)?;
        if !matches!(rec.loc, Loc::Extern) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object {id} is not extern"),
            ));
        }
        self.verify_extern_bytes_at(id, &rec, new)?;

        let current = self.extern_rel(id)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("extern object {id} has no path"),
            )
        })?;
        if normalized_extern_key(&current)? != old_key {
            if self.extern_still_matches(id, &rec)? {
                return Ok(ExternRelocation::CanonicalElsewhere);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "extern object {id} does not own {} and its canonical copy is invalid",
                    old.display()
                ),
            ));
        }

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let objects = txn.open_table(OBJECTS).map_err(db_err)?;
            let current_rec: ObjRecord = objects
                .get(id.0.as_slice())
                .map_err(db_err)?
                .map(|g| dec(g.value()))
                .transpose()?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("object {id}")))?;
            if !matches!(current_rec.loc, Loc::Extern) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("object {id} stopped being extern during relocation"),
                ));
            }
            let mut externs = txn.open_table(EXTERN).map_err(db_err)?;
            let current_rel = externs
                .get(id.0.as_slice())
                .map_err(db_err)?
                .map(|g| g.value().to_string())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("extern object {id} has no path"),
                    )
                })?;
            if normalized_extern_key(&current_rel)? != old_key {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "extern object {id} moved from {} while it was being promoted",
                        old.display()
                    ),
                ));
            }
            for row in externs.iter().map_err(db_err)? {
                let (key, value) = row.map_err(db_err)?;
                let raw: [u8; 32] = key.value().try_into().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "malformed extern object id")
                })?;
                let claimant = ObjId(raw);
                if claimant != id && normalized_extern_key(value.value())? == new_key {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("extern destination is already claimed by {claimant}"),
                    ));
                }
            }
            let new_rel = new_rel.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 extern path")
            })?;
            externs.insert(id.0.as_slice(), new_rel).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        Ok(ExternRelocation::Relocated)
    }

    /// List canonical extern rows at or below `prefix` using path-component
    /// boundaries. The xite root itself is deliberately rejected so callers
    /// cannot turn a narrow archive cleanup into a store-wide mutation.
    pub fn externs_under(
        &self,
        prefix: &std::path::Path,
    ) -> io::Result<Vec<ExternPathEntry>> {
        let prefix_rel = normalized_extern_rel(self.rel_of(prefix)?)?;
        if prefix_rel.as_os_str().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "extern prefix must be narrower than the xite root",
            ));
        }
        let entries = self.extern_entries()?;
        let prefix_components = normalized_extern_component_keys(&prefix_rel)?;
        let mut matching = Vec::new();
        for entry in entries {
            let entry_rel = normalized_extern_rel(self.rel_of(&entry.path)?)?;
            let entry_components = normalized_extern_component_keys(&entry_rel)?;
            if entry_components.starts_with(&prefix_components) {
                matching.push(entry);
            }
        }
        Ok(matching)
    }

    /// List every exact canonical extern row. Startup reconciliation uses
    /// this before the Store is exposed, including rows whose xite is no
    /// longer loaded and therefore cannot be found by walking live xites.
    pub fn extern_entries(&self) -> io::Result<Vec<ExternPathEntry>> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(EXTERN).map_err(db_err)?;
        let objects = txn.open_table(OBJECTS).map_err(db_err)?;
        let mut entries = Vec::new();
        for row in table.iter().map_err(db_err)? {
            let (key, value) = row.map_err(db_err)?;
            let raw: [u8; 32] = key.value().try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "malformed extern object id")
            })?;
            let id = ObjId(raw);
            let current = normalized_extern_rel(value.value().to_string())?;
            let rec: ObjRecord = objects
                .get(id.0.as_slice())
                .map_err(db_err)?
                .map(|guard| dec(guard.value()))
                .transpose()?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("extern path exists for missing object {id}"),
                    )
                })?;
            if !matches!(rec.loc, Loc::Extern) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("object {id} has an extern path but is not extern"),
                ));
            }
            // Resolved per row on purpose: a Store without a configured xite
            // root (extern objects disabled) must still answer "no extern
            // entries" instead of erroring - activation calls this
            // unconditionally on every store.
            entries.push(ExternPathEntry { id, path: self.xite_root()?.join(current) });
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path).then(left.id.0.cmp(&right.id.0)));
        Ok(entries)
    }

    /// Return the complete extern object whose canonical row names `path`.
    ///
    /// Promotion uses this to discover the Store's actual owner without
    /// trusting a manifest hash that may be missing or stale. The mapping and
    /// object record come from one database snapshot. Malformed rows and two
    /// object IDs claiming the same exact path fail closed. Before an owner is
    /// returned, the bytes at `path` are streamed and verified against it.
    pub fn complete_extern_owner_at(
        &self,
        path: &std::path::Path,
    ) -> io::Result<Option<ObjId>> {
        let _externs = self.extern_mutation_gate.read().expect("extern mutation");
        let expected = normalized_extern_key(self.rel_of(path)?)?;
        let txn = self.db.begin_read().map_err(db_err)?;
        let externs = txn.open_table(EXTERN).map_err(db_err)?;
        let objects = txn.open_table(OBJECTS).map_err(db_err)?;
        let mut owner: Option<(ObjId, ObjRecord)> = None;

        for row in externs.iter().map_err(db_err)? {
            let (key, value) = row.map_err(db_err)?;
            let raw: [u8; 32] = key.value().try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "malformed extern object id")
            })?;
            let id = ObjId(raw);
            let current = normalized_extern_key(value.value())?;
            if current != expected {
                continue;
            }
            if let Some((other, _)) = owner {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "extern path {} is claimed by both {other} and {id}",
                        path.display()
                    ),
                ));
            }
            let rec: ObjRecord = objects
                .get(id.0.as_slice())
                .map_err(db_err)?
                .map(|guard| dec(guard.value()))
                .transpose()?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("extern path {} names missing object {id}", path.display()),
                    )
                })?;
            if !matches!(rec.loc, Loc::Extern) || !rec.is_complete() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "extern path {} names object {id} without a complete extern record",
                        path.display()
                    ),
                ));
            }
            owner = Some((id, rec));
        }

        let Some((id, rec)) = owner else {
            return Ok(None);
        };
        self.verify_extern_bytes_at(id, &rec, path)?;
        Ok(Some(id))
    }

    /// Stream-hash an exact candidate path against an object id without
    /// changing Store state. Rehome uses this under the declaring xite's tree
    /// lock immediately before adopting and pinning the path.
    pub fn verify_object_path(
        &self,
        id: ObjId,
        path: &std::path::Path,
    ) -> io::Result<()> {
        let file = self.open_xite_file(path)?;
        let size = file.metadata()?.len();
        let outboard = OutboardBytes::from_reader(io::BufReader::new(file), size)?;
        if outboard.root != id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} does not hash to {id}", path.display()),
            ));
        }
        Ok(())
    }

    /// Retarget every canonical extern row below a filesystem subtree after
    /// the caller atomically renamed that subtree from `old_prefix` to
    /// `new_prefix`. Every destination is verified before one database row is
    /// changed, then all rows change in one redb transaction.
    pub fn relocate_extern_prefix(
        &self,
        old_prefix: &std::path::Path,
        new_prefix: &std::path::Path,
    ) -> io::Result<Vec<ExternPrefixEntry>> {
        let _externs = self.extern_mutation_gate.write().expect("extern mutation");
        loop {
            let before = self.externs_under(old_prefix)?;
            let mut ids: Vec<_> = before.iter().map(|entry| entry.id).collect();
            ids.sort_by_key(|id| id.0);
            ids.dedup();
            let locks: Vec<_> = ids.iter().map(|id| self.object_mutation_lock(*id)).collect();
            let _objects: Vec<_> = locks
                .iter()
                .map(|lock| lock.lock().expect("object mutation"))
                .collect();
            let live = self.externs_under(old_prefix)?;
            let mut live_ids: Vec<_> = live.iter().map(|entry| entry.id).collect();
            live_ids.sort_by_key(|id| id.0);
            live_ids.dedup();
            if live_ids == ids {
                return self.relocate_extern_prefix_locked(old_prefix, new_prefix);
            }
        }
    }

    /// Move a filesystem subtree and every exact extern row below it while
    /// holding the affected object locks in object-id order. This prevents a
    /// background revalidation from retiring the temporarily missing old path.
    pub fn move_and_relocate_extern_prefix(
        &self,
        old_prefix: &std::path::Path,
        new_prefix: &std::path::Path,
        mut move_path: impl FnMut(&std::path::Path, &std::path::Path) -> io::Result<()>,
    ) -> io::Result<Vec<ExternPrefixEntry>> {
        let _externs = self.extern_mutation_gate.write().expect("extern mutation");
        loop {
            let before = self.externs_under(old_prefix)?;
            let mut ids: Vec<_> = before.iter().map(|entry| entry.id).collect();
            ids.sort_by_key(|id| id.0);
            ids.dedup();
            let locks: Vec<_> = ids.iter().map(|id| self.object_mutation_lock(*id)).collect();
            let _objects: Vec<_> = locks
                .iter()
                .map(|lock| lock.lock().expect("object mutation"))
                .collect();
            let live = self.externs_under(old_prefix)?;
            let mut live_ids: Vec<_> = live.iter().map(|entry| entry.id).collect();
            live_ids.sort_by_key(|id| id.0);
            live_ids.dedup();
            if live_ids != ids {
                continue;
            }

            self.preflight_extern_prefix_destinations(old_prefix, new_prefix)?;
            if let Err(error) = move_path(old_prefix, new_prefix) {
                if old_prefix.exists() || !new_prefix.exists() {
                    return Err(error);
                }
                let rollback = move_path(new_prefix, old_prefix);
                if old_prefix.exists() && !new_prefix.exists() {
                    return Err(match rollback {
                        Ok(()) => error,
                        Err(rollback) => io::Error::new(
                            error.kind(),
                            format!(
                                "filesystem prefix move failed after rename: {error}; rollback sync failed: {rollback}"
                            ),
                        ),
                    });
                }
                self.relocate_extern_prefix_locked(old_prefix, new_prefix)
                    .map_err(|relocate| {
                        io::Error::new(
                            relocate.kind(),
                            format!(
                                "filesystem prefix move failed after rename: {error}; rollback did not restore {}; Store relocation also failed: {relocate}",
                                old_prefix.display()
                            ),
                        )
                    })?;
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "filesystem prefix move was aligned in the Store but was not durably synced: {error}"
                    ),
                ));
            }
            match self.relocate_extern_prefix_locked(old_prefix, new_prefix) {
                Ok(entries) => return Ok(entries),
                Err(error) => {
                    if let Some(entries) =
                        self.prefix_rows_at_destination(&live, old_prefix, new_prefix)?
                    {
                        return Ok(entries);
                    }
                    if let Err(rollback) = move_path(new_prefix, old_prefix) {
                        return Err(io::Error::new(
                            error.kind(),
                            format!(
                                "extern prefix relocation failed: {error}; filesystem rollback failed: {rollback}"
                            ),
                        ));
                    }
                    return Err(error);
                }
            }
        }
    }

    fn preflight_extern_prefix_destinations(
        &self,
        old_prefix: &std::path::Path,
        new_prefix: &std::path::Path,
    ) -> io::Result<()> {
        let old_rel = normalized_extern_rel(self.rel_of(old_prefix)?)?;
        let new_rel = normalized_extern_rel(self.rel_of(new_prefix)?)?;
        let moving = self.externs_under(old_prefix)?;
        let moving_ids: HashSet<_> = moving.iter().map(|entry| entry.id).collect();
        let mut destination_keys = HashSet::new();
        for entry in &moving {
            let entry_rel = normalized_extern_rel(self.rel_of(&entry.path)?)?;
            let suffix = extern_suffix_after_prefix(&entry_rel, &old_rel)?;
            let destination = if suffix.as_os_str().is_empty() {
                new_rel.clone()
            } else {
                new_rel.join(suffix)
            };
            if !destination_keys.insert(normalized_extern_key(destination)?) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "two extern rows alias the same relocation destination",
                ));
            }
        }
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(EXTERN).map_err(db_err)?;
        for row in table.iter().map_err(db_err)? {
            let (key, value) = row.map_err(db_err)?;
            let raw: [u8; 32] = key.value().try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "malformed extern object id")
            })?;
            if !moving_ids.contains(&ObjId(raw))
                && destination_keys.contains(&normalized_extern_key(value.value())?)
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "extern prefix destination is already claimed",
                ));
            }
        }
        Ok(())
    }

    fn prefix_rows_at_destination(
        &self,
        entries: &[ExternPathEntry],
        old_prefix: &std::path::Path,
        new_prefix: &std::path::Path,
    ) -> io::Result<Option<Vec<ExternPrefixEntry>>> {
        let old_rel = normalized_extern_rel(self.rel_of(old_prefix)?)?;
        let new_rel = normalized_extern_rel(self.rel_of(new_prefix)?)?;
        let root = self.xite_root()?;
        let mut relocated = Vec::with_capacity(entries.len());
        for entry in entries {
            let entry_rel = normalized_extern_rel(self.rel_of(&entry.path)?)?;
            let suffix = extern_suffix_after_prefix(&entry_rel, &old_rel)?;
            let destination_rel = if suffix.as_os_str().is_empty() {
                new_rel.clone()
            } else {
                new_rel.join(suffix)
            };
            let Some(live) = self.extern_rel(entry.id)? else {
                return Ok(None);
            };
            if normalized_extern_rel(live)? != destination_rel {
                return Ok(None);
            }
            relocated.push(ExternPrefixEntry {
                id: entry.id,
                old_path: entry.path.clone(),
                new_path: root.join(destination_rel),
            });
        }
        Ok(Some(relocated))
    }

    fn relocate_extern_prefix_locked(
        &self,
        old_prefix: &std::path::Path,
        new_prefix: &std::path::Path,
    ) -> io::Result<Vec<ExternPrefixEntry>> {
        ensure_same_filesystem(old_prefix, new_prefix)?;
        let old_rel = normalized_extern_rel(self.rel_of(old_prefix)?)?;
        let new_rel = normalized_extern_rel(self.rel_of(new_prefix)?)?;
        if old_rel.as_os_str().is_empty() || new_rel.as_os_str().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "extern relocation prefixes must be narrower than the xite root",
            ));
        }
        let root = self.xite_root()?.to_path_buf();
        let current = self.externs_under(old_prefix)?;
        let mut moves = Vec::with_capacity(current.len());
        for entry in current {
            let entry_rel = normalized_extern_rel(self.rel_of(&entry.path)?)?;
            let suffix = extern_suffix_after_prefix(&entry_rel, &old_rel).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "extern path {} escaped its planned prefix: {error}",
                        entry.path.display()
                    ),
                )
            })?;
            let mapped_rel = if suffix.as_os_str().is_empty() {
                new_rel.clone()
            } else {
                new_rel.join(suffix)
            };
            let mapped = root.join(&mapped_rel);
            let rec = self.required(entry.id)?;
            self.verify_extern_bytes_at(entry.id, &rec, &mapped)?;
            moves.push((entry.id, entry_rel, mapped_rel, entry.path, mapped));
        }
        if moves.is_empty() {
            return Ok(Vec::new());
        }

        let moving_ids: HashSet<_> = moves.iter().map(|(id, ..)| *id).collect();
        let mut destination_keys = HashSet::new();
        for (_, _, new_rel, _, _) in &moves {
            if !destination_keys.insert(normalized_extern_key(new_rel)?) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "two extern rows alias the same relocation destination",
                ));
            }
        }

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let objects = txn.open_table(OBJECTS).map_err(db_err)?;
            let mut externs = txn.open_table(EXTERN).map_err(db_err)?;
            for row in externs.iter().map_err(db_err)? {
                let (key, value) = row.map_err(db_err)?;
                let raw: [u8; 32] = key.value().try_into().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "malformed extern object id")
                })?;
                if !moving_ids.contains(&ObjId(raw))
                    && destination_keys.contains(&normalized_extern_key(value.value())?)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "extern prefix destination is already claimed",
                    ));
                }
            }
            for (id, old_rel, new_rel, _, _) in &moves {
                let rec: ObjRecord = objects
                    .get(id.0.as_slice())
                    .map_err(db_err)?
                    .map(|guard| dec(guard.value()))
                    .transpose()?
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, format!("object {id}"))
                    })?;
                if !matches!(rec.loc, Loc::Extern) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("object {id} stopped being extern during prefix relocation"),
                    ));
                }
                let live = externs
                    .get(id.0.as_slice())
                    .map_err(db_err)?
                    .map(|guard| guard.value().to_string())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("extern object {id} has no path"),
                        )
                    })?;
                if normalized_extern_key(live)? != normalized_extern_key(old_rel)? {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("extern object {id} moved during prefix relocation"),
                    ));
                }
                let new_rel = new_rel.to_str().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 extern path")
                })?;
                externs.insert(id.0.as_slice(), new_rel).map_err(db_err)?;
            }
        }
        txn.commit().map_err(db_err)?;
        Ok(moves
            .into_iter()
            .map(|(id, _, _, old_path, new_path)| ExternPrefixEntry {
                id,
                old_path,
                new_path,
            })
            .collect())
    }

    /// Retire an extern mapping only if its live `(id, path)` still matches.
    ///
    /// This is the local delete/overwrite repair path. It deliberately does
    /// not read or hash the caller-owned file, so an edited or missing backing
    /// cannot leave the Store serving a dangling row. The object record and
    /// extern path are compared and removed in one write transaction. A
    /// missing, non-extern, or changed owner is left untouched and reported as
    /// [`ExternRetirement::CanonicalElsewhere`]. The filesystem path itself
    /// remains the caller's responsibility.
    pub fn retire_extern_mapping_at(
        &self,
        id: ObjId,
        expected_path: &std::path::Path,
    ) -> io::Result<ExternRetirement> {
        let _externs = self.extern_mutation_gate.read().expect("extern mutation");
        let object_lock = self.object_mutation_lock(id);
        let _object = object_lock.lock().expect("object mutation");
        let expected_key = normalized_extern_key(self.rel_of(expected_path)?)?;
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
            let record: Option<ObjRecord> = objects
                .get(id.0.as_slice())
                .map_err(db_err)?
                .map(|guard| dec(guard.value()))
                .transpose()?;
            let mut externs = txn.open_table(EXTERN).map_err(db_err)?;
            let current = externs
                .get(id.0.as_slice())
                .map_err(db_err)?
                .map(|guard| guard.value().to_string());

            let (record, current) = match (record, current) {
                (None, None) => return Ok(ExternRetirement::CanonicalElsewhere),
                (Some(record), None) if !matches!(record.loc, Loc::Extern) => {
                    return Ok(ExternRetirement::CanonicalElsewhere);
                }
                (None, Some(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("extern path exists for missing object {id}"),
                    ));
                }
                (Some(_record), None) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("extern object {id} has no path"),
                    ));
                }
                (Some(record), Some(_)) if !matches!(record.loc, Loc::Extern) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("non-extern object {id} has an extern path"),
                    ));
                }
                (Some(record), Some(current)) => (record, current),
            };
            if !record.is_complete() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("extern object {id} is incomplete"),
                ));
            }
            if normalized_extern_key(&current)? != expected_key {
                return Ok(ExternRetirement::CanonicalElsewhere);
            }

            // A corrupt index can contain two object IDs for one path. Do not
            // retire one claimant and make the other look authoritative.
            for row in externs.iter().map_err(db_err)? {
                let (key, value) = row.map_err(db_err)?;
                let raw: [u8; 32] = key.value().try_into().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "malformed extern object id")
                })?;
                let claimant = ObjId(raw);
                if claimant != id && normalized_extern_key(value.value())? == expected_key {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "extern path {} is also claimed by {claimant}",
                            expected_path.display()
                        ),
                    ));
                }
            }

            objects.remove(id.0.as_slice()).map_err(db_err)?;
            externs.remove(id.0.as_slice()).map_err(db_err)?;
            Self::clear_owner_markers_in(&txn, id)?;
        }
        txn.commit().map_err(db_err)?;
        let _ = remove_file_durable(&self.obao_path(id));
        Ok(ExternRetirement::Retired)
    }

    /// Preserve an exact extern object's bytes in Store-owned sparse storage.
    ///
    /// Manifest ownership can disappear while another independent owner, such
    /// as a settled feed, still references the same object. Deleting the
    /// extern row would also delete that owner's only backing. This operation
    /// verifies the exact `(id, path)` owner, durably duplicates its bytes into
    /// the sparse store, and atomically changes only the location metadata.
    /// The refcount and caller-owned xite file are preserved.
    pub fn internalize_extern_at(
        &self,
        id: ObjId,
        expected_path: &std::path::Path,
    ) -> io::Result<ExternInternalization> {
        let _externs = self.extern_mutation_gate.read().expect("extern mutation");
        let object_lock = self.object_mutation_lock(id);
        let _object = object_lock.lock().expect("object mutation");
        let expected_rel = normalized_extern_rel(self.rel_of(expected_path)?)?;
        let _writing = SparseWriteGuard::register(self, id);
        let rec = self.required(id)?;
        if matches!(rec.loc, Loc::Sparse) {
            self.verify_extern_bytes_at(id, &rec, &self.sparse_path(id))?;
            return Ok(ExternInternalization::Internalized);
        }
        if !matches!(rec.loc, Loc::Extern) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object {id} is not extern"),
            ));
        }
        let current = self.extern_rel(id)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("extern object {id} has no path"),
            )
        })?;
        if normalized_extern_key(current)? != normalized_extern_key(&expected_rel)? {
            if self.extern_still_matches(id, &rec)? {
                return Ok(ExternInternalization::CanonicalElsewhere);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "extern object {id} does not own {} and its canonical copy is invalid",
                    expected_path.display()
                ),
            ));
        }
        self.verify_extern_bytes_at(id, &rec, expected_path)?;

        let sparse = self.sparse_path(id);
        if verify_complete_file(id, rec.size, &sparse).is_err() {
            if let Some(parent) = sparse.parent() {
                fs::create_dir_all(parent)?;
            }
            let temporary = store_temp_path(&sparse, "internalize")?;
            let source = self.open_xite_file(expected_path)?;
            copy_open_file_complete(source, &temporary, rec.size, id).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "cannot preserve extern {} inside the Store as {}: {error}",
                        expected_path.display(),
                        temporary.display()
                    ),
                )
            })?;
            if let Err(error) = replace_file_atomic(&temporary, &sparse) {
                let _ = fs::remove_file(&temporary);
                return Err(error);
            }
        }
        let outboard = OutboardBytes::from_reader(io::BufReader::new(File::open(&sparse)?), rec.size)?;
        if outboard.root != id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} does not hash to {id}", sparse.display()),
            ));
        }
        self.install_outboard_atomic(id, &outboard.data)?;

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
            let mut live: ObjRecord = objects
                .get(id.0.as_slice())
                .map_err(db_err)?
                .map(|guard| dec(guard.value()))
                .transpose()?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("object {id}")))?;
            if !matches!(live.loc, Loc::Extern) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("object {id} stopped being extern during internalization"),
                ));
            }
            let externs = txn.open_table(EXTERN).map_err(db_err)?;
            let live_rel = externs
                .get(id.0.as_slice())
                .map_err(db_err)?
                .map(|guard| guard.value().to_string())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("extern object {id} has no path"),
                    )
                })?;
            if normalized_extern_key(live_rel)? != normalized_extern_key(&expected_rel)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("extern object {id} moved during internalization"),
                ));
            }
            drop(externs);
            live.loc = Loc::Sparse;
            objects
                .insert(id.0.as_slice(), enc(&live).as_slice())
                .map_err(db_err)?;
            Self::put_extern_in(&txn, id, None)?;
        }
        txn.commit().map_err(db_err)?;
        Ok(ExternInternalization::Internalized)
    }

    /// Retire an extern object only when its live row still names
    /// `expected_path`. The caller keeps ownership of the file itself and may
    /// unlink it after this succeeds. A verified canonical owner elsewhere is
    /// left untouched and reported explicitly.
    pub fn retire_extern_at(
        &self,
        id: ObjId,
        expected_path: &std::path::Path,
    ) -> io::Result<ExternRetirement> {
        let _externs = self.extern_mutation_gate.read().expect("extern mutation");
        let object_lock = self.object_mutation_lock(id);
        let _object = object_lock.lock().expect("object mutation");
        let expected_rel = normalized_extern_rel(self.rel_of(expected_path)?)?;
        let rec = self.required(id)?;
        if !matches!(rec.loc, Loc::Extern) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object {id} is not extern"),
            ));
        }
        let current = self.extern_rel(id)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("extern object {id} has no path"),
            )
        })?;
        if normalized_extern_key(current)? != normalized_extern_key(&expected_rel)? {
            if self.extern_still_matches(id, &rec)? {
                return Ok(ExternRetirement::CanonicalElsewhere);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "extern object {id} does not own {} and its canonical copy is invalid",
                    expected_path.display()
                ),
            ));
        }
        self.verify_extern_bytes_at(id, &rec, expected_path)?;

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
            let live: ObjRecord = objects
                .get(id.0.as_slice())
                .map_err(db_err)?
                .map(|guard| dec(guard.value()))
                .transpose()?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("object {id}")))?;
            if !matches!(live.loc, Loc::Extern) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("object {id} stopped being extern during retirement"),
                ));
            }
            let externs = txn.open_table(EXTERN).map_err(db_err)?;
            let live_rel = externs
                .get(id.0.as_slice())
                .map_err(db_err)?
                .map(|guard| guard.value().to_string())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("extern object {id} has no path"),
                    )
                })?;
            if normalized_extern_key(live_rel)? != normalized_extern_key(&expected_rel)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("extern object {id} moved during retirement"),
                ));
            }
            drop(externs);
            objects.remove(id.0.as_slice()).map_err(db_err)?;
            Self::put_extern_in(&txn, id, None)?;
            Self::clear_owner_markers_in(&txn, id)?;
        }
        txn.commit().map_err(db_err)?;
        let _ = remove_file_durable(&self.obao_path(id));
        Ok(ExternRetirement::Retired)
    }

    /// Roll an owned staged extern back into the sparse store.
    ///
    /// The staged source stays intact until the sparse row commits. A hard
    /// link normally avoids copying; a synced copy is the compatibility
    /// fallback. The row and refcount stay intact. If another verified
    /// canonical extern owns the object, the row is left alone and the caller
    /// may remove its staged duplicate.
    pub fn rollback_staged_extern(
        &self,
        id: ObjId,
        staged: &std::path::Path,
    ) -> io::Result<ExternRollback> {
        let _externs = self.extern_mutation_gate.read().expect("extern mutation");
        let object_lock = self.object_mutation_lock(id);
        let _object = object_lock.lock().expect("object mutation");
        let staged_rel = self.rel_of(staged)?;
        // Keep a Sparse winner alive through every retry branch, including
        // the branch that removes a duplicate staged copy.
        let _writing = SparseWriteGuard::register(self, id);
        let rec = self.required(id)?;
        if matches!(rec.loc, Loc::Sparse) {
            let sparse = self.sparse_path(id);
            let sparse_valid = if sparse.is_file() {
                match self.verify_extern_bytes_at(id, &rec, &sparse) {
                    Ok(()) => true,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::InvalidData
                                | io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::NotFound
                        ) =>
                    {
                        false
                    }
                    Err(error) => return Err(error),
                }
            } else {
                false
            };
            if !sparse_valid && self.xite_file_exists(staged)? {
                self.verify_extern_bytes_at(id, &rec, staged)?;
                if let Some(parent) = sparse.parent() {
                    fs::create_dir_all(parent)?;
                }
                let source = self.open_xite_file(staged)?;
                copy_open_file_complete_atomic(source, &sparse, rec.size, id, "rollback")?;
            } else if !sparse_valid {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("sparse and staged backing for {id} are both missing"),
                ));
            }
            if self.xite_file_exists(staged)? {
                self.verify_extern_bytes_at(id, &rec, staged)?;
                self.remove_xite_file(staged)?;
            }
            self.install_outboard_from_path(id, rec.size, &sparse)?;
            return Ok(ExternRollback::RestoredSparse);
        }
        if !matches!(rec.loc, Loc::Extern) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object {id} is not extern"),
            ));
        }
        let current = self.extern_rel(id)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("extern object {id} has no path"),
            )
        })?;
        if normalized_extern_key(current)? != normalized_extern_key(&staged_rel)? {
            if self.extern_still_matches(id, &rec)? {
                return Ok(ExternRollback::CanonicalElsewhere);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "extern object {id} does not own {} and its canonical copy is invalid",
                    staged.display()
                ),
            ));
        }
        let sparse = self.sparse_path(id);
        let prepared_sparse = if sparse.is_file() {
            // A crash can leave this copy beside the staged source with the
            // old source-preserving order, or as the only copy after the
            // legacy rename order. Both are the same pending DB transition.
            match self.verify_extern_bytes_at(id, &rec, &sparse) {
                Ok(()) => true,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::InvalidData
                            | io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::NotFound
                    ) =>
                {
                    false
                }
                Err(error) => return Err(error),
            }
        } else {
            false
        };
        if !prepared_sparse {
            self.verify_extern_bytes_at(id, &rec, staged)?;
        }
        if sparse.exists() && !sparse.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("cannot roll {id} back: {} already exists", sparse.display()),
            ));
        }
        if let Some(parent) = sparse.parent() {
            fs::create_dir_all(parent)?;
        }

        let created_sparse = !prepared_sparse;
        if created_sparse {
            let source = self.open_xite_file(staged)?;
            copy_open_file_complete_atomic(source, &sparse, rec.size, id, "rollback").map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "cannot preserve staged extern {} while restoring {}: {error}",
                        staged.display(),
                        sparse.display()
                    ),
                )
            })?;
        }
        self.install_outboard_from_path(id, rec.size, &sparse)?;
        let txn = self.db.begin_write().map_err(db_err)?;
        let prepare = (|| -> io::Result<()> {
            let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
            let mut updated: ObjRecord = objects
                .get(id.0.as_slice())
                .map_err(db_err)?
                .map(|g| dec(g.value()))
                .transpose()?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("object {id}")))?;
            if !matches!(updated.loc, Loc::Extern) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("object {id} stopped being extern during rollback"),
                ));
            }
            let externs = txn.open_table(EXTERN).map_err(db_err)?;
            let current_rel = externs
                .get(id.0.as_slice())
                .map_err(db_err)?
                .map(|g| g.value().to_string())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("extern object {id} has no path"),
                    )
                })?;
            if normalized_extern_key(current_rel)? != normalized_extern_key(&staged_rel)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "extern object {id} moved from {} while it was being rolled back",
                        staged.display()
                    ),
                ));
            }
            drop(externs);
            updated.loc = Loc::Sparse;
            objects
                .insert(id.0.as_slice(), enc(&updated).as_slice())
                .map_err(db_err)?;
            Self::put_extern_in(&txn, id, None)?;
            Ok(())
        })();
        if let Err(error) = prepare {
            // Another writer may already have committed this sparse copy.
            // Preserve both verified paths and let the idempotent retry read
            // the live row rather than guessing from this failed txn.
            return Err(error);
        }
        if let Err(commit_error) = txn.commit().map_err(db_err) {
            // Commit outcome is uncertain on an I/O error. Preserve both
            // verified copies. A retry handles either the old Extern row or
            // the new Sparse row without guessing which reached disk.
            return Err(commit_error);
        }
        if self.xite_file_exists(staged)? {
            self.remove_xite_file(staged)?;
        }
        Ok(ExternRollback::RestoredSparse)
    }

    fn verify_extern_bytes_at(
        &self,
        id: ObjId,
        rec: &ObjRecord,
        path: &std::path::Path,
    ) -> io::Result<()> {
        let file = self.open_verified_path(path)?;
        let size = file.metadata()?.len();
        if size != rec.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} is {size} bytes, expected {} for {id}",
                    path.display(),
                    rec.size
                ),
            ));
        }
        let ob = OutboardBytes::from_reader(io::BufReader::new(file), size)?;
        if ob.root != id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} does not hash to {id}", path.display()),
            ));
        }
        Ok(())
    }

    fn install_outboard_from_path(
        &self,
        id: ObjId,
        size: u64,
        path: &std::path::Path,
    ) -> io::Result<()> {
        let file = self.open_verified_path(path)?;
        if file.metadata()?.len() != size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} has an unexpected size", path.display()),
            ));
        }
        let outboard = OutboardBytes::from_reader(io::BufReader::new(file), size)?;
        if outboard.root != id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} does not hash to {id}", path.display()),
            ));
        }
        self.install_outboard_atomic(id, &outboard.data)
    }

    /// Commit the record + path row for an extern object in one txn, so a
    /// reader can never see `Loc::Extern` without a path to resolve it.
    fn commit_extern(
        &self,
        id: ObjId,
        ns: Ns,
        size: u64,
        rel: &str,
        now: u64) -> io::Result<bool> {
        let destination_key = normalized_extern_key(rel)?;
        let txn = self.db.begin_write().map_err(db_err)?;
        let prev_loc;
        {
            let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
            // Preserve a refcount/LRU stamp another path committed while we
            // were hashing or moving bytes; only `loc` and `present` are ours
            // to decide here.
            let prev: Option<ObjRecord> = match objects.get(id.0.as_slice()).map_err(db_err)? {
                Some(g) => Some(dec(g.value())?),
                None => None,
            };
            prev_loc = prev.as_ref().map(|r| r.loc);
            // A racer can have landed the same bytes as a slab object between
            // our record check and this txn (adopt vs a concurrent small-file
            // insert). Overwriting its loc is correct - the bytes are
            // identical, hash-addressed - but the slab range it occupied must
            // be booked dead, exactly as `delete_object` books it, or the
            // space is never compacted away.
            if let Some(Loc::Slab { slab, .. }) = prev_loc {
                let mut slabs = txn.open_table(SLABS).map_err(db_err)?;
                let meta: Option<SlabMeta> = slabs
                    .get(slab)
                    .map_err(db_err)?
                    .map(|g| dec::<SlabMeta>(g.value()))
                    .transpose()?;
                if let Some(mut m) = meta {
                    m.dead += prev.as_ref().map(|r| r.size).unwrap_or(0);
                    slabs.insert(slab, enc(&m).as_slice()).map_err(db_err)?;
                }
            }
            let rec = ObjRecord {
                size,
                ns: ns_to_u8(ns),
                loc: Loc::Extern,
                present: GroupBits::complete(size).to_wire(),
                refcount: prev.as_ref().map(|r| r.refcount).unwrap_or(0),
                last_access: prev.as_ref().map(|r| r.last_access.max(now)).unwrap_or(now),
            };
            objects.insert(id.0.as_slice(), enc(&rec).as_slice()).map_err(db_err)?;
            let mut externs = txn.open_table(EXTERN).map_err(db_err)?;
            for row in externs.iter().map_err(db_err)? {
                let (key, value) = row.map_err(db_err)?;
                let raw: [u8; 32] = key.value().try_into().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "malformed extern object id")
                })?;
                let claimant = ObjId(raw);
                if claimant != id
                    && normalized_extern_key(value.value())? == destination_key
                {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("extern destination is already claimed by {claimant}"),
                    ));
                }
            }
            externs.insert(id.0.as_slice(), rel).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        // Same race, sparse flavor (adopt vs a concurrent ensure_sparse): the
        // record is extern now, so nothing would ever unlink the orphaned
        // sparse data file. A materialize's own rename has already moved it -
        // the remove is then a no-op ENOENT. Skipped while a decode is
        // writing into the file (same courtesy every delete path extends);
        // that leaks the orphan in an already-vanishing race window, which
        // beats yanking a file out from under a verified write.
        if let Some(Loc::Sparse) = prev_loc {
            let writers = self.sparse_writers.lock().expect("sparse_writers");
            if !writers.contains_key(&id) {
                let _ = remove_file_durable(&self.sparse_path(id));
            }
        }
        Ok(true)
    }

    /// Create the sparse file pair for an object we are about to fetch.
    /// Existing complete objects are left alone. An empty Sparse row is
    /// checked against the requested namespace/size and its crash-damaged
    /// backing pair is repaired before returning.
    pub fn ensure_sparse(&self, id: ObjId, ns: Ns, size: u64, now: u64) -> io::Result<()> {
        if size > MAX_OBJECT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("declared size {size} exceeds the {MAX_OBJECT_BYTES} byte object cap"),
            ));
        }
        let object_lock = self.object_mutation_lock(id);
        let _object = object_lock.lock().expect("object mutation");
        let requested_ns = ns_to_u8(ns);
        if let Some(rec) = self.get_record(id)? {
            if !matches!(rec.loc, Loc::Sparse) {
                if rec.size != size || rec.ns != requested_ns {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "existing object {id} has size/namespace {}/{}, requested {size}/{requested_ns}",
                            rec.size, rec.ns,
                        ),
                    ));
                }
                return Ok(());
            }
            let claimed = rec.bits();
            let writers = self.sparse_writers.lock().expect("sparse_writers");
            let writer_active = writers.contains_key(&id);
            if rec.size != size || rec.ns != requested_ns {
                if !claimed.is_empty() || writer_active {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "sparse object {id} has size/namespace {}/{}, requested {size}/{requested_ns}",
                            rec.size, rec.ns,
                        ),
                    ));
                }
                self.prepare_empty_sparse_backing(id, size)?;
                self.update_record(id, |current| {
                    current.size = size;
                    current.ns = requested_ns;
                    current.present.clear();
                    current.last_access = current.last_access.max(now);
                })?;
                return Ok(());
            }
            let backing_exact = backing_length(&self.sparse_path(id))? == Some(size)
                && backing_length(&self.obao_path(id))? == Some(outboard_size(size));
            if claimed.is_empty() {
                if writer_active {
                    return Ok(());
                }
                self.prepare_empty_sparse_backing(id, size)?;
                if rec.last_access < now {
                    self.touch(id, now)?;
                }
                return Ok(());
            }
            if backing_exact {
                return Ok(());
            }
            if writer_active {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!("sparse object {id} is being written while its backing is repaired"),
                ));
            }
            // Claimed groups backed by a missing or wrong-length file pair
            // cannot be trusted. Reset the backing and present set in place,
            // preserving typed manifest/feed ownership and its reference.
            self.update_record(id, |current| {
                current.present.clear();
                current.last_access = current.last_access.max(now);
            })?;
            self.prepare_empty_sparse_backing(id, size)?;
            return Ok(());
        }
        let writers = self.sparse_writers.lock().expect("sparse_writers");
        if writers.contains_key(&id) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("sparse object {id} is being written while it is reserved"),
            ));
        }
        self.prepare_empty_sparse_backing(id, size)?;
        self.insert_empty_sparse_record_if_absent(id, requested_ns, size, now)
    }

    /// Decode a verified slice into a sparse object: data lands at its
    /// file offsets, interior hashes land in the `.obao`, and the covered
    /// groups are marked present — all only if every byte verifies.
    pub fn write_slice(
        &self,
        id: ObjId,
        byte_ranges: &[Range<u64>],
        encoded: impl Read,
        now: u64,
    ) -> io::Result<()> {
        // Registered before the record is read: from here to the present-
        // bits commit, the delete paths leave this object alone (see
        // `sparse_writers`).
        let _writing = SparseWriteGuard::register(self, id);
        let rec = self.required(id)?;
        let Loc::Sparse = rec.loc else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "object is slab-complete",
            ));
        };
        for r in byte_ranges {
            if r.end > rec.size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("range {r:?} beyond size {}", rec.size),
                ));
            }
        }
        let mut data = OpenOptions::new().read(true).write(true).open(self.sparse_path(id))?;
        let mut obao = OpenOptions::new().read(true).write(true).open(self.obao_path(id))?;
        verified::decode_slice_into(encoded, id, rec.size, byte_ranges, &mut data, &mut obao)?;
        data.sync_data()?;
        obao.sync_data()?;

        // Fold the new groups into whatever the record holds NOW, not into
        // the snapshot taken before the decode: another writer may have
        // committed groups of the same object while this decode ran.
        self.update_record(id, |cur| {
            let mut bits = cur.bits();
            for r in byte_ranges {
                bits.add(groups_for_bytes(r));
            }
            cur.present = bits.to_wire();
            cur.last_access = cur.last_access.max(now);
        })?;
        Ok(())
    }

    /// Like [`Store::write_slice`], but commits progress incrementally: the
    /// chunk groups whose verified bytes reached the sparse file are marked
    /// present even when the encoded stream ends early (a stalled peer, an
    /// abandoned fetch). The decode writes a leaf only after it verifies, so
    /// every fully-written group is safe to mark; the outboard likewise only
    /// ever receives parents that verified up the chain to the root. Returns
    /// the verified payload bytes written; a decode error is still returned
    /// AFTER the groups that did land are committed, so a timed-out transfer
    /// keeps its bytes instead of discarding the whole batch.
    pub fn write_slice_partial(
        &self,
        id: ObjId,
        byte_ranges: &[Range<u64>],
        encoded: impl Read,
        now: u64,
    ) -> io::Result<u64> {
        // Registered before the record is read: this also runs UNCLAIMED on
        // detached salvage threads (`fetch::RangeGuard`), where only this
        // registration keeps a concurrent remove + re-ensure_sparse from
        // recreating the record while the decode writes the old, unlinked
        // files — the groups would be marked present with no bytes behind
        // them, poisoning the object until eviction.
        let _writing = SparseWriteGuard::register(self, id);
        let rec = self.required(id)?;
        let Loc::Sparse = rec.loc else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "object is slab-complete",
            ));
        };
        for r in byte_ranges {
            if r.end > rec.size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("range {r:?} beyond size {}", rec.size),
                ));
            }
        }
        let data = OpenOptions::new().read(true).write(true).open(self.sparse_path(id))?;
        let mut obao = OpenOptions::new().read(true).write(true).open(self.obao_path(id))?;
        let mut tracked = TrackWrites { inner: data, written: Vec::new(),
        };
        let res = verified::decode_slice_into(encoded, id, rec.size, byte_ranges, &mut tracked, &mut obao,
        );
        let TrackWrites { inner: data, written,
        } = tracked;
        let landed = fully_covered_groups(written, rec.size);
        let held: u64 = landed
            .ranges()
            .iter()
            .map(|r| {
                let start = r.start * GROUP_BYTES;
                let end = (r.end * GROUP_BYTES).min(rec.size);
                end - start
            })
            .sum();
        if !landed.is_empty() {
            data.sync_data()?;
            obao.sync_data()?;
            // Fold into whatever the record holds NOW (see write_slice): a
            // concurrent writer's groups must not be dropped.
            self.update_record(id, |cur| {
                let mut bits = cur.bits();
                for r in landed.ranges() {
                    bits.add(r.clone());
                }
                cur.present = bits.to_wire();
                cur.last_access = cur.last_access.max(now);
            })?;
        }
        res?;
        Ok(held)
    }

    /// Serve a verified slice for the requested ranges. Fails with
    /// `NotFound` if any needed group is absent and `InvalidData` if the
    /// stored bytes no longer verify (nothing corrupt ever leaves).
    pub fn encode_slice(
        &self,
        id: ObjId,
        byte_ranges: &[Range<u64>],
        out: impl Write,
        now: u64,
    ) -> io::Result<()> {
        let rec = self.required(id)?;
        let bits = rec.bits();
        for r in byte_ranges {
            if !bits.contains_all(&groups_for_bytes(r)) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("groups for {r:?} not present"),
                ));
            }
        }
        match rec.loc {
            // Extern serves straight out of the xite file, with the outboard
            // still beside it in the store - which is the whole point: the
            // bytes a peer downloads from us are the same bytes the user
            // sees in their own directory, stored once.
            Loc::Sparse | Loc::Extern => {
                let data = self.open_data_file(id, &rec)?;
                let obao = File::open(self.obao_path(id))?;
                verified::encode_slice_from(&data, &obao, id, rec.size, byte_ranges, out)?;
            }
            Loc::Slab { slab, off } => {
                let bytes = self.read_slab(slab, off, rec.size)?;
                let ob = OutboardBytes::from_slice(&bytes);
                if ob.root != id {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("slab bytes for {id} are corrupt"),
                    ));
                }
                verified::encode_slice(&bytes[..], &ob, byte_ranges, out)?;
            }
        }
        // `out` is the peer's sink, so the encode above can park on peer
        // backpressure for minutes. Only stamp the LRU here; writing the
        // pre-encode snapshot back would revert everything the fetch path
        // committed meanwhile.
        if rec.last_access < now {
            self.touch(id, now)?;
        }
        Ok(())
    }

    /// Read a COMPLETE object's bytes (verified for slab objects by the
    /// caller's own use; sparse completeness comes from verified writes).
    pub fn read_bytes(&self, id: ObjId, now: u64) -> io::Result<Vec<u8>> {
        let rec = self.required(id)?;
        if !rec.is_complete() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("{id} incomplete"),
            ));
        }
        let bytes = match rec.loc {
            Loc::Slab { slab, off } => {
                let b = self.read_slab(slab, off, rec.size)?;
                // Slab reads are addressed by (slab, off); a torn append or
                // offset drift would return a neighbor's bytes. Verify the
                // hash so a mis-addressed read fails loudly, never silent.
                if !verified::verify_whole(&b, id) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("slab bytes for {id} are corrupt"),
                    ));
                }
                b
            }
            Loc::Sparse | Loc::Extern => {
                let mut file = self.open_data_file(id, &rec)?;
                let mut bytes = Vec::with_capacity(rec.size.min(usize::MAX as u64) as usize);
                file.read_to_end(&mut bytes)?;
                if bytes.len() as u64 != rec.size || !verified::verify_whole(&bytes, id) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("complete bytes for {id} are corrupt"),
                    ));
                }
                bytes
            }
        };
        if rec.last_access < now {
            self.touch(id, now)?;
        }
        Ok(bytes)
    }

    /// Read the byte range `[start, start+len)` of an object, clamped to its
    /// size. Requires the covering chunk groups to be present (verified on
    /// write); errors `NotFound` otherwise. For a sparse object this reads
    /// only the range from disk, so a media seek never materializes the whole
    /// file.
    pub fn read_range(&self, id: ObjId, start: u64, len: u64, now: u64) -> io::Result<Vec<u8>> {
        let rec = self.required(id)?;
        let end = start.saturating_add(len).min(rec.size);
        if start >= rec.size || end <= start {
            return Ok(Vec::new());
        }
        let bytes = match rec.loc {
            Loc::Slab { slab, off } => {
                let b = self.read_slab(slab, off, rec.size)?;
                if !verified::verify_whole(&b, id) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("slab bytes for {id} are corrupt"),
                    ));
                }
                b[start as usize..end as usize].to_vec()
            }
            Loc::Sparse => {
                let groups = crate::bitfield::groups_for_bytes(&(start..end));
                if !rec.bits().contains_all(&groups) {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("{id} range [{start},{end}) not present"),
                    ));
                }
                // An extern object reads through to the xite file. If the
                // user deleted or replaced it, this open (or the short read
                // below) fails, the caller refetches, and `revalidate`
                // retires the stale record - the same stance a sparse file
                // torn by a crash gets.
                let f = self.open_data_file(id, &rec)?;
                let mut buf = vec![0u8; (end - start) as usize];
                positioned_io::ReadAt::read_exact_at(&f, start, &mut buf)?;
                buf
            }
            Loc::Extern => {
                // Encode validates the exact chunk groups while reading them
                // from the mutable xite file. Decode then returns bytes from
                // that same verified slice. This avoids both a check/use
                // reread race and whole-object allocation for media seeks.
                let data = self.open_data_file(id, &rec)?;
                let obao = File::open(self.obao_path(id))?;
                let range = start..end;
                let requested = std::slice::from_ref(&range);
                let mut encoded = Vec::new();
                verified::encode_slice_from(
                    &data,
                    &obao,
                    id,
                    rec.size,
                    requested,
                    &mut encoded,
                )?;
                let group_bytes = crate::BLOCK_SIZE.bytes() as u64;
                let group_start = (start / group_bytes) * group_bytes;
                let group_end = end.div_ceil(group_bytes).saturating_mul(group_bytes).min(rec.size);
                let buffer_len = usize::try_from(group_end.saturating_sub(group_start)).map_err(
                    |_| io::Error::new(io::ErrorKind::InvalidInput, "requested range is too large"),
                )?;
                let mut decoded = VerifiedRangeBuffer {
                    offset: group_start,
                    bytes: vec![0u8; buffer_len],
                };
                verified::decode_slice(
                    encoded.as_slice(),
                    id,
                    rec.size,
                    requested,
                    &mut decoded,
                )?;
                let local_start = usize::try_from(start - group_start).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "range start is too large")
                })?;
                let local_end = usize::try_from(end - group_start).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "range end is too large")
                })?;
                decoded.bytes[local_start..local_end].to_vec()
            }
        };
        if rec.last_access < now {
            self.touch(id, now)?;
        }
        Ok(bytes)
    }

    fn read_slab(&self, slab: u32, off: u64, size: u64) -> io::Result<Vec<u8>> {
        let f = File::open(self.slab_path(slab))?;
        let mut buf = vec![0u8; size as usize];
        positioned_io::ReadAt::read_exact_at(&f, off, &mut buf)?;
        Ok(buf)
    }

    /// Bump / drop manifest references. An object with refcount 0 is
    /// eviction-eligible; eviction never touches refcounted objects.
    pub fn ref_delta(&self, id: ObjId, delta: i64) -> io::Result<u32> {
        let rec = self.update_record(id, |cur| {
            cur.refcount = (cur.refcount as i64 + delta).max(0) as u32;
        })?;
        Ok(rec.refcount)
    }

    /// Install this Store's one persistent accepted-manifest reference.
    ///
    /// A legacy idempotent `pin` with no typed feed owner is migrated into
    /// manifest ownership without inflation. If the persistent feed marker is
    /// present, this atomically adds a distinct manifest reference instead.
    pub fn claim_manifest(&self, id: ObjId) -> io::Result<bool> {
        let txn = self.db.begin_write().map_err(db_err)?;
        let claimed = {
            let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
            let mut record: ObjRecord = objects
                .get(id.0.as_slice())
                .map_err(db_err)?
                .map(|guard| dec(guard.value()))
                .transpose()?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("object {id}")))?;
            let mut owners = txn.open_table(MANIFEST_OWNERS).map_err(db_err)?;
            if owners
                .get(id.0.as_slice())
                .map_err(db_err)?
                .is_some()
            {
                // Already owned: idempotent, even for an incomplete record -
                // revalidate deliberately converts a torn slab to an empty
                // sparse target WHILE preserving its owner markers, and a
                // re-claim of that preserved owner must not error.
                false
            } else {
                if !record.is_complete() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("object {id} is incomplete"),
                    ));
                }
                let feed_owned = txn
                    .open_table(FEED_OWNERS)
                    .map_err(db_err)?
                    .get(id.0.as_slice())
                    .map_err(db_err)?
                    .is_some();
                if feed_owned || record.refcount == 0 {
                    record.refcount = record.refcount.checked_add(1).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("manifest reference count overflow for {id}"),
                        )
                    })?;
                    objects
                        .insert(id.0.as_slice(), enc(&record).as_slice())
                        .map_err(db_err)?;
                }
                owners.insert(id.0.as_slice(), 1).map_err(db_err)?;
                true
            }
        };
        txn.commit().map_err(db_err)?;
        Ok(claimed)
    }

    /// Release this Store's persistent accepted-manifest reference. Missing
    /// markers are idempotent. A corrupt zero refcount fails closed and keeps
    /// the owner marker so a later reconciliation can retry after repair.
    pub fn release_manifest(&self, id: ObjId) -> io::Result<bool> {
        let txn = self.db.begin_write().map_err(db_err)?;
        let released = {
            let mut owners = txn.open_table(MANIFEST_OWNERS).map_err(db_err)?;
            if owners
                .get(id.0.as_slice())
                .map_err(db_err)?
                .is_none()
            {
                false
            } else {
                let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
                let record = objects
                    .get(id.0.as_slice())
                    .map_err(db_err)?
                    .map(|guard| dec::<ObjRecord>(guard.value()))
                    .transpose()?;
                if let Some(mut record) = record {
                    if record.refcount == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("manifest-owned object {id} has zero references"),
                        ));
                    }
                    record.refcount -= 1;
                    objects
                        .insert(id.0.as_slice(), enc(&record).as_slice())
                        .map_err(db_err)?;
                }
                owners.remove(id.0.as_slice()).map_err(db_err)?;
                true
            }
        };
        txn.commit().map_err(db_err)?;
        Ok(released)
    }

    /// Release the persistent manifest owner and delete the object in the
    /// same transaction when no independent reference remains. A busy sparse
    /// writer or eviction hold leaves the marker intact and returns
    /// `WouldBlock`, so an authority reconciliation can retry without losing
    /// its durable cleanup receipt.
    pub fn release_manifest_and_delete_unowned(&self, id: ObjId) -> io::Result<bool> {
        let _externs = self.extern_mutation_gate.read().expect("extern mutation");
        let object_lock = self.object_mutation_lock(id);
        let _object = object_lock.lock().expect("object mutation");
        let writers = self.sparse_writers.lock().expect("sparse_writers");
        if writers.contains_key(&id) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("object {id} has an active sparse writer"),
            ));
        }
        let holds = self.evict_holds.lock().expect("evict_holds");
        if holds.contains_key(&id) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("object {id} has an active eviction hold"),
            ));
        }

        let txn = self.db.begin_write().map_err(db_err)?;
        let deleted = {
            let mut owners = txn.open_table(MANIFEST_OWNERS).map_err(db_err)?;
            if owners
                .get(id.0.as_slice())
                .map_err(db_err)?
                .is_none()
            {
                None
            } else {
                let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
                let record = objects
                    .get(id.0.as_slice())
                    .map_err(db_err)?
                    .map(|guard| dec::<ObjRecord>(guard.value()))
                    .transpose()?;
                let Some(mut record) = record else {
                    owners.remove(id.0.as_slice()).map_err(db_err)?;
                    drop(objects);
                    drop(owners);
                    txn.commit().map_err(db_err)?;
                    return Ok(false);
                };
                if record.refcount == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("manifest-owned object {id} has zero references"),
                    ));
                }
                record.refcount -= 1;
                let feed_owned = txn
                    .open_table(FEED_OWNERS)
                    .map_err(db_err)?
                    .get(id.0.as_slice())
                    .map_err(db_err)?
                    .is_some();
                if record.refcount == 0 {
                    if feed_owned {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("feed-owned object {id} would lose its final reference"),
                        ));
                    }
                    objects.remove(id.0.as_slice()).map_err(db_err)?;
                    if let Loc::Slab { slab, .. } = record.loc {
                        let mut slabs = txn.open_table(SLABS).map_err(db_err)?;
                        let meta = slabs
                            .get(slab)
                            .map_err(db_err)?
                            .map(|guard| dec::<SlabMeta>(guard.value()))
                            .transpose()?;
                        if let Some(mut meta) = meta {
                            meta.dead = meta.dead.saturating_add(record.size);
                            slabs
                                .insert(slab, enc(&meta).as_slice())
                                .map_err(db_err)?;
                        }
                    }
                    if matches!(record.loc, Loc::Extern) {
                        Self::put_extern_in(&txn, id, None)?;
                    }
                    owners.remove(id.0.as_slice()).map_err(db_err)?;
                    Some(record)
                } else {
                    objects
                        .insert(id.0.as_slice(), enc(&record).as_slice())
                        .map_err(db_err)?;
                    owners.remove(id.0.as_slice()).map_err(db_err)?;
                    None
                }
            }
        };
        txn.commit().map_err(db_err)?;
        if let Some(record) = deleted {
            match record.loc {
                Loc::Sparse => {
                    let _ = remove_file_durable(&self.sparse_path(id));
                    let _ = remove_file_durable(&self.obao_path(id));
                }
                Loc::Extern => {
                    let _ = remove_file_durable(&self.obao_path(id));
                }
                Loc::Slab { .. } => {}
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// IDs currently carrying this Store's accepted-manifest reference.
    pub fn manifest_owned_ids(&self) -> io::Result<Vec<ObjId>> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let Ok(owners) = txn.open_table(MANIFEST_OWNERS) else {
            return Ok(Vec::new());
        };
        let mut ids = Vec::new();
        for row in owners.iter().map_err(db_err)? {
            let (key, _) = row.map_err(db_err)?;
            let raw: [u8; 32] = key.value().try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "malformed manifest owner id")
            })?;
            ids.push(ObjId(raw));
        }
        Ok(ids)
    }

    /// Install the Store's one persistent derived-feed reference for `id`.
    /// Unlike legacy `pin`, this always adds a distinct reference when the
    /// marker is new, even if an accepted manifest already owns the object.
    pub fn claim_feed(&self, id: ObjId) -> io::Result<bool> {
        let txn = self.db.begin_write().map_err(db_err)?;
        let claimed = {
            let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
            let mut record: ObjRecord = objects
                .get(id.0.as_slice())
                .map_err(db_err)?
                .map(|guard| dec(guard.value()))
                .transpose()?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("object {id}")))?;
            let mut owners = txn.open_table(FEED_OWNERS).map_err(db_err)?;
            if owners
                .get(id.0.as_slice())
                .map_err(db_err)?
                .is_some()
            {
                // Already owned: idempotent, even for an incomplete record -
                // revalidate preserves feed markers on a converted torn slab.
                false
            } else {
                if !record.is_complete() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("object {id} is incomplete"),
                    ));
                }
                record.refcount = record.refcount.checked_add(1).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("feed reference count overflow for {id}"),
                    )
                })?;
                objects
                    .insert(id.0.as_slice(), enc(&record).as_slice())
                    .map_err(db_err)?;
                owners.insert(id.0.as_slice(), 1).map_err(db_err)?;
                true
            }
        };
        txn.commit().map_err(db_err)?;
        Ok(claimed)
    }

    /// Release the Store's persistent derived-feed reference for `id`.
    pub fn release_feed(&self, id: ObjId) -> io::Result<bool> {
        let txn = self.db.begin_write().map_err(db_err)?;
        let released = {
            let mut owners = txn.open_table(FEED_OWNERS).map_err(db_err)?;
            if owners
                .get(id.0.as_slice())
                .map_err(db_err)?
                .is_none()
            {
                false
            } else {
                let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
                let record = objects
                    .get(id.0.as_slice())
                    .map_err(db_err)?
                    .map(|guard| dec::<ObjRecord>(guard.value()))
                    .transpose()?;
                if let Some(mut record) = record {
                    if record.refcount == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("feed-owned object {id} has zero references"),
                        ));
                    }
                    record.refcount -= 1;
                    objects
                        .insert(id.0.as_slice(), enc(&record).as_slice())
                        .map_err(db_err)?;
                }
                owners.remove(id.0.as_slice()).map_err(db_err)?;
                true
            }
        };
        txn.commit().map_err(db_err)?;
        Ok(released)
    }

    /// Drop every persisted feed-owner reference. Feed caches are process
    /// local and never survive restart or Store activation, so the activation
    /// barrier calls this before rebuilding ownership for the new session.
    pub fn clear_feed_owners(&self) -> io::Result<()> {
        let ids = {
            let txn = self.db.begin_read().map_err(db_err)?;
            let Ok(owners) = txn.open_table(FEED_OWNERS) else {
                return Ok(());
            };
            let mut ids = Vec::new();
            for row in owners.iter().map_err(db_err)? {
                let (key, _) = row.map_err(db_err)?;
                let raw: [u8; 32] = key.value().try_into().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "malformed feed owner id")
                })?;
                ids.push(ObjId(raw));
            }
            ids
        };
        for id in ids {
            self.release_feed(id)?;
        }
        Ok(())
    }

    /// Drop an object unconditionally (tools/tests; normal flow evicts) —
    /// unless a sparse decode is mid-flight on it, in which case the
    /// delete is skipped: the writer's verified bytes matter more than the
    /// cleanup, which the next pass (or `drop_if_unfilled`'s next caller)
    /// can redo.
    pub fn remove(&self, id: ObjId) -> io::Result<()> {
        let _externs = self.extern_mutation_gate.read().expect("extern mutation");
        let object_lock = self.object_mutation_lock(id);
        let _object = object_lock.lock().expect("object mutation");
        self.remove_locked(id)
    }

    fn remove_locked(&self, id: ObjId) -> io::Result<()> {
        self.delete_object(id)?;
        self.compact_if_worthwhile()
    }

    fn delete_object(&self, id: ObjId) -> io::Result<()> {
        // Held across the record delete AND the unlink: a sparse decode
        // registering meanwhile blocks on this lock and then finds the
        // record gone (its decode aborts) instead of opening files this
        // delete is about to unlink; one already registered wins, and the
        // delete is skipped (see `sparse_writers`).
        let writers = self.sparse_writers.lock().expect("sparse_writers");
        if writers.contains_key(&id) {
            return Ok(());
        }
        self.delete_object_without_writer(id)
    }

    /// Delete after the caller has excluded new sparse-writer registration
    /// by holding `sparse_writers` and has checked that `id` is absent there.
    fn delete_object_without_writer(&self, id: ObjId) -> io::Result<()> {
        let txn = self.db.begin_write().map_err(db_err)?;
        let rec;
        {
            let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
            let Some(live) = objects
                .get(id.0.as_slice())
                .map_err(db_err)?
                .map(|guard| dec::<ObjRecord>(guard.value()))
                .transpose()?
            else {
                return Ok(());
            };
            rec = live;
            objects.remove(id.0.as_slice()).map_err(db_err)?;
            if let Loc::Slab { slab, .. } = rec.loc {
                let mut slabs = txn.open_table(SLABS).map_err(db_err)?;
                let meta: Option<SlabMeta> = slabs
                    .get(slab)
                    .map_err(db_err)?
                    .map(|g| dec::<SlabMeta>(g.value()))
                    .transpose()?;
                if let Some(mut m) = meta {
                    m.dead += rec.size;
                    slabs.insert(slab, enc(&m).as_slice()).map_err(db_err)?;
                }
            }
            if let Loc::Extern = rec.loc {
                Self::put_extern_in(&txn, id, None)?;
            }
            Self::clear_owner_markers_in(&txn, id)?;
        }
        txn.commit().map_err(db_err)?;
        match rec.loc {
            Loc::Sparse => {
                let _ = remove_file_durable(&self.sparse_path(id));
                let _ = remove_file_durable(&self.obao_path(id));
            }
            // The data file belongs to the XITE, not to this cache: only the
            // outboard is ours to drop. Callers that really mean to delete
            // the content (optionalFileDelete, removing a xite) unlink the
            // tree themselves.
            Loc::Extern => {
                let _ = remove_file_durable(&self.obao_path(id));
            }
            Loc::Slab { .. } => {}
        }
        Ok(())
    }

    /// Delete an object only if it is still unreferenced, deciding and
    /// removing in one write transaction. Eviction snapshots its candidate
    /// list minutes before it reaches a given object; redb serializes write
    /// txns, so a `pin` committed after that snapshot is seen here and the
    /// object is left alone. Returns the deleted record, `None` if the
    /// object was pinned meanwhile, has a sparse decode mid-flight (evict
    /// it next pass — see `sparse_writers`), or is already gone.
    fn delete_if_unreferenced(&self, id: ObjId) -> io::Result<Option<ObjRecord>> {
        let object_lock = self.object_mutation_lock(id);
        let _object = object_lock.lock().expect("object mutation");
        // Held across the delete + unlink, same as `delete_object`.
        let writers = self.sparse_writers.lock().expect("sparse_writers");
        if writers.contains_key(&id) {
            return Ok(None);
        }
        // Also held across the delete: a hold taken while this txn commits
        // waits here, so it either precedes the check or sees the record
        // already gone (and the holder's materialize fails into a refetch).
        let holds = self.evict_holds.lock().expect("evict_holds");
        if holds.contains_key(&id) {
            return Ok(None);
        }
        let txn = self.db.begin_write().map_err(db_err)?;
        let deleted: Option<ObjRecord>;
        {
            let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
            let cur: Option<ObjRecord> = match objects.get(id.0.as_slice()).map_err(db_err)? {
                Some(g) => Some(dec(g.value())?),
                None => None,
            };
            match cur {
                // An extern object is the user's own file, not reclaimable
                // cache, so eviction must never take it. `evict_lru` already
                // skips it; this is the second gate, on the path that
                // actually deletes.
                Some(rec) if rec.refcount == 0 && !matches!(rec.loc, Loc::Extern) => {
                    objects.remove(id.0.as_slice()).map_err(db_err)?;
                    if let Loc::Slab { slab, .. } = rec.loc {
                        let mut slabs = txn.open_table(SLABS).map_err(db_err)?;
                        let meta: Option<SlabMeta> = slabs
                            .get(slab)
                            .map_err(db_err)?
                            .map(|g| dec::<SlabMeta>(g.value()))
                            .transpose()?;
                        if let Some(mut m) = meta {
                            m.dead += rec.size;
                            slabs.insert(slab, enc(&m).as_slice()).map_err(db_err)?;
                        }
                    }
                    Self::clear_owner_markers_in(&txn, id)?;
                    deleted = Some(rec);
                }
                _ => deleted = None,
            }
        }
        txn.commit().map_err(db_err)?;
        if let Some(rec) = &deleted {
            if let Loc::Sparse = rec.loc {
                let _ = remove_file_durable(&self.sparse_path(id));
                let _ = remove_file_durable(&self.obao_path(id));
            }
        }
        Ok(deleted)
    }

    /// Bytes actually held by all stored objects (the quota basis). A
    /// record's declared `size` is not charged: it comes from an untrusted
    /// manifest, so one bogus entry could otherwise blow the whole quota
    /// and evict every other cached object.
    pub fn total_bytes(&self) -> io::Result<u64> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(OBJECTS).map_err(db_err)?;
        let mut total = 0u64;
        for row in table.iter().map_err(db_err)? {
            let (_, v) = row.map_err(db_err)?;
            let rec: ObjRecord = dec(v.value())?;
            total = total.saturating_add(rec.held());
        }
        Ok(total)
    }

    /// Bytes actually held in one namespace. Used as a volunteer's soft
    /// budget gate (stop pulling shards once `Ns::Shard` reaches its
    /// donated quota). Reads only `(ns, size, present)` per record - no
    /// shard-to-xite association is ever consulted, preserving deniability.
    /// The namespace an existing record was reserved under, if any. Fetch
    /// paths use this so a whole-blob insert lands in the reserved namespace
    /// instead of re-filing the object (a shard pull's ciphertext must stay
    /// in `Ns::Shard` for the volunteer budget to count it).
    pub fn object_ns(&self, id: ObjId) -> io::Result<Option<Ns>> {
        Ok(self.get_record(id)?.map(|record| u8_to_ns(record.ns)))
    }

    pub fn ns_bytes(&self, ns: Ns) -> io::Result<u64> {
        let want = ns_to_u8(ns);
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(OBJECTS).map_err(db_err)?;
        let mut total = 0u64;
        for row in table.iter().map_err(db_err)? {
            let (_, v) = row.map_err(db_err)?;
            let rec: ObjRecord = dec(v.value())?;
            if rec.ns == want {
                total = total.saturating_add(rec.held());
            }
        }
        Ok(total)
    }

    /// Hold `id` out of eviction's reach until the returned guard drops
    /// (see `evict_holds`). Unlike [`Store::pin`] this is not persisted:
    /// it protects a completed download only for as long as the process is
    /// still on its way to materializing it.
    pub fn hold_eviction(&self, id: ObjId) -> EvictionHold<'_> {
        *self.evict_holds.lock().expect("evict_holds").entry(id).or_insert(0) += 1;
        EvictionHold { store: self, id }
    }

    /// Pin an object so eviction never reclaims it (the node's own content).
    /// Idempotent: raises refcount to at least 1, never higher, so repeated
    /// registration across restarts does not inflate it.
    pub fn pin(&self, id: ObjId) -> io::Result<()> {
        // Cheap pre-check so re-registering an already pinned object costs
        // no write txn; the write itself re-checks under the txn.
        if self.required(id)?.refcount != 0 {
            return Ok(());
        }
        self.update_record(id, |cur| {
            if cur.refcount == 0 {
                cur.refcount = 1;
            }
        })?;
        Ok(())
    }

    /// Enforce a byte quota: if the store exceeds `quota`, evict LRU
    /// refcount-0 (unpinned, i.e. cached-from-others) objects down to it.
    /// Also caps the outstanding reservation (see [`MAX_RESERVED_BYTES`]),
    /// which the held-byte quota cannot see. Returns bytes freed. Pinned
    /// own content is never touched.
    pub fn enforce_quota(&self, quota: u64) -> io::Result<u64> {
        let mut freed = self.enforce_reservation_bound()?;
        let total = self.total_bytes()?;
        if total > quota {
            freed = freed.saturating_add(self.evict_lru(total - quota)?);
        }
        Ok(freed)
    }

    /// Reclaim LRU unreferenced sparse records until the store's outstanding
    /// reservation is back under [`MAX_RESERVED_BYTES`]. Returns the held
    /// bytes freed. A record only counts while it is short of its declared
    /// size, so a completed object never keeps this pass busy, and the sort
    /// is by `last_access`: a fetch that is still landing groups stamps
    /// itself on every `write_slice`, so it is the last candidate reached.
    fn enforce_reservation_bound(&self) -> io::Result<u64> {
        let mut reserved = 0u64;
        // (last_access, id, unfilled bytes) for the reclaimable ones.
        let mut candidates: Vec<(u64, ObjId, u64)> = Vec::new();
        {
            let txn = self.db.begin_read().map_err(db_err)?;
            let table = txn.open_table(OBJECTS).map_err(db_err)?;
            for row in table.iter().map_err(db_err)? {
                let (k, v) = row.map_err(db_err)?;
                let rec: ObjRecord = dec(v.value())?;
                let Loc::Sparse = rec.loc else { continue };
                let unfilled = rec.size.saturating_sub(rec.held());
                if unfilled == 0 {
                    continue;
                }
                reserved = reserved.saturating_add(unfilled);
                if rec.refcount == 0 {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(k.value());
                    candidates.push((rec.last_access, ObjId(id), unfilled));
                }
            }
        }
        if reserved <= MAX_RESERVED_BYTES {
            return Ok(0);
        }
        candidates.sort();
        let mut freed = 0u64;
        for (_, id, unfilled) in candidates {
            if reserved <= MAX_RESERVED_BYTES {
                break;
            }
            if let Some(rec) = self.delete_if_unreferenced(id)? {
                reserved = reserved.saturating_sub(unfilled);
                freed = freed.saturating_add(rec.held());
            }
        }
        Ok(freed)
    }

    /// Evict least-recently-used refcount-0 objects until at least
    /// `bytes_needed` are freed (or candidates run out). Returns freed
    /// bytes. Sealed slabs past the dead threshold are compacted.
    pub fn evict_lru(&self, bytes_needed: u64) -> io::Result<u64> {
        let mut candidates: Vec<(u64, ObjId)> = Vec::new();
        {
            let txn = self.db.begin_read().map_err(db_err)?;
            let table = txn.open_table(OBJECTS).map_err(db_err)?;
            for row in table.iter().map_err(db_err)? {
                let (k, v) = row.map_err(db_err)?;
                let rec: ObjRecord = dec(v.value())?;
                // Extern objects are the user's downloaded files, not cache.
                // They charge nothing (`held()` is 0), so evicting one frees
                // nothing anyway - but without this the record would still be
                // dropped and the file would stop serving.
                if rec.refcount == 0 && !matches!(rec.loc, Loc::Extern) {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(k.value());
                    candidates.push((rec.last_access, ObjId(id)));
                }
            }
        }
        candidates.sort();
        let mut freed = 0u64;
        for (_, id) in candidates {
            if freed >= bytes_needed {
                break;
            }
            // Re-check refcount inside the delete txn: this loop is one
            // committed txn per object, so a pin can land after the scan.
            if let Some(rec) = self.delete_if_unreferenced(id)? {
                freed += rec.held();
            }
        }
        self.compact_if_worthwhile()?;
        Ok(freed)
    }

    fn compact_if_worthwhile(&self) -> io::Result<()> {
        let sealed_dead: Vec<u32> = {
            let txn = self.db.begin_read().map_err(db_err)?;
            let slabs = txn.open_table(SLABS).map_err(db_err)?;
            let mut v = Vec::new();
            for row in slabs.iter().map_err(db_err)? {
                let (k, val) = row.map_err(db_err)?;
                let m: SlabMeta = dec(val.value())?;
                if m.sealed && m.len > 0 && m.dead * 256 >= m.len * self.cfg.compact_dead_num {
                    v.push(k.value());
                }
            }
            v
        };
        for slab in sealed_dead {
            self.compact_slab(slab)?;
        }
        Ok(())
    }

    /// Rewrite a sealed slab's live objects into the open slab, then
    /// delete the slab file. Object ids and refcounts are preserved.
    fn compact_slab(&self, victim: u32) -> io::Result<()> {
        // Collect live objects of this slab.
        let live: Vec<(ObjId, ObjRecord)> = {
            let txn = self.db.begin_read().map_err(db_err)?;
            let table = txn.open_table(OBJECTS).map_err(db_err)?;
            let mut v = Vec::new();
            for row in table.iter().map_err(db_err)? {
                let (k, val) = row.map_err(db_err)?;
                let rec: ObjRecord = dec(val.value())?;
                if matches!(rec.loc, Loc::Slab { slab, .. } if slab == victim) {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(k.value());
                    v.push((ObjId(id), rec));
                }
            }
            v
        };

        for (id, rec) in live {
            let Loc::Slab { off, .. } = rec.loc else { continue;
            };
            let was = Loc::Slab { slab: victim, off };
            let bytes = self.read_slab(victim, off, rec.size)?;

            let mut open = self.open_slab.lock().expect("slab lock");
            let (slab, new_off) = (open.0, open.1);
            let slab_path = self.slab_path(slab);
            let slab_existed = slab_path.exists();
            let mut f = OpenOptions::new().create(true).append(true).open(&slab_path)?;
            if let Err(e) = f.write_all(&bytes).and_then(|()| f.sync_data()) {
                // Torn append: shrink the slab back to the pre-write offset
                // so the next insert is not mis-addressed.
                let _ = f.set_len(new_off);
                let _ = f.sync_data();
                return Err(e);
            }
            if !slab_existed {
                sync_directory_entry(self.root.join("slabs").as_path())?;
            }
            let new_len = new_off + bytes.len() as u64;

            let txn = self.db.begin_write().map_err(db_err)?;
            {
                let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
                // Re-read the row inside the txn and rewrite only `loc`. The
                // snapshot above was taken before a long run of reads and
                // fsyncs, so a pin, a ref_delta or an eviction can have
                // landed since; inserting the snapshot back would revert the
                // refcount or resurrect an object eviction just removed.
                let cur: Option<ObjRecord> = match objects.get(id.0.as_slice()).map_err(db_err)? {
                    Some(g) => Some(dec(g.value())?),
                    None => None,
                };
                let moved = match cur {
                    Some(mut cur) if cur.loc == was => {
                        cur.loc = Loc::Slab { slab, off: new_off };
                        objects.insert(id.0.as_slice(), enc(&cur).as_slice()).map_err(db_err)?;
                        true
                    }
                    _ => false,
                };
                let mut slabs = txn.open_table(SLABS).map_err(db_err)?;
                let mut m: SlabMeta = slabs
                    .get(slab)
                    .map_err(db_err)?
                    .map(|g| dec(g.value()))
                    .transpose()?
                    .unwrap_or_default();
                m.len = new_len;
                if !moved {
                    // The bytes are already appended and the tracked len has
                    // to cover them or the next insert is mis-addressed, but
                    // nothing points at them: book them as dead so a later
                    // compaction reclaims the space.
                    m.dead = m.dead.saturating_add(bytes.len() as u64);
                }
                if m.len >= self.cfg.slab_seal_bytes {
                    m.sealed = true;
                    slabs.insert(slab + 1, enc(&SlabMeta::default()).as_slice()).map_err(db_err)?;
                }
                slabs.insert(slab, enc(&m).as_slice()).map_err(db_err)?;
            }
            let next_open = if new_len >= self.cfg.slab_seal_bytes {
                (slab + 1, 0)
            } else {
                (slab, new_len)
            };
            if let Err(commit_error) = txn.commit().map_err(db_err) {
                match self.get_record(id) {
                    Ok(Some(record))
                        if record.loc == (Loc::Slab { slab, off: new_off }) =>
                    {
                        // The move is visible but its durability is unknown.
                        // Preserve the victim slab and report the commit error.
                        *open = next_open;
                    }
                    Ok(_) => {
                        if f.set_len(new_off).and_then(|()| f.sync_data()).is_err() {
                            let recovery =
                                self.book_dead_slab_append(slab, new_len, bytes.len() as u64);
                            *open = next_open;
                            if let Err(recovery_error) = recovery {
                                return Err(io::Error::other(format!(
                                    "{commit_error}; could not record failed compact append: {recovery_error}"
                                )));
                            }
                        }
                    }
                    Err(_) => {
                        // Do not truncate on an unknown outcome. Leave this
                        // slab behind and let open-time reconciliation settle
                        // any unindexed physical tail after a restart.
                        *open = (slab.saturating_add(1), 0);
                    }
                }
                return Err(commit_error);
            }
            *open = next_open;
        }

        // All live objects moved; drop the victim slab.
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut slabs = txn.open_table(SLABS).map_err(db_err)?;
            slabs.remove(victim).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        remove_file_durable(&self.slab_path(victim))?;
        Ok(())
    }

    /// Re-verify a sparse object's held bytes against its outboard and
    /// shrink the present set to what actually verifies (used after a
    /// crash or a failed serve — distrust, don't repair).
    ///
    /// An extern object is re-verified too, and is all-or-nothing: its bytes
    /// are a file the user can rename, edit or delete at will, so anything
    /// short of a full match retires the record (see
    /// [`Self::retire_extern`]) and the next fetch starts over as a normal
    /// download. A partial present-set is not an option there — the store
    /// does not own those bytes and must not write into them.
    pub fn revalidate(&self, id: ObjId) -> io::Result<GroupBits> {
        let _externs = self.extern_mutation_gate.read().expect("extern mutation");
        let object_lock = self.object_mutation_lock(id);
        let _object = object_lock.lock().expect("object mutation");
        let rec = self.required(id)?;
        if let Loc::Extern = rec.loc {
            return match self.extern_still_matches(id, &rec) {
                Ok(true) => Ok(GroupBits::complete(rec.size)),
                Ok(false) => {
                    self.retire_extern(id)?;
                    Ok(GroupBits::new())
                }
                Err(error) => Err(error),
            };
        }
        // A slab record used to be trusted blindly here, so a torn append (a
        // hard-killed process mid-write) left a "complete" record whose bytes
        // could never be read. Convert broken slab metadata to an empty sparse
        // fetch target in place. This preserves durable typed-owner markers
        // and their refcounts while making every group refetchable.
        if let Loc::Slab { slab, off } = rec.loc {
            let ok = match self.read_slab(slab, off, rec.size) {
                Ok(bytes) => verified::verify_whole(&bytes, id),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound
                            | io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::InvalidData
                    ) =>
                {
                    false
                }
                Err(error) => return Err(error),
            };
            if ok {
                return Ok(GroupBits::complete(rec.size));
            }
            self.prepare_empty_sparse_backing(id, rec.size)?;
            let txn = self.db.begin_write().map_err(db_err)?;
            {
                let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
                let current = objects
                    .get(id.0.as_slice())
                    .map_err(db_err)?
                    .map(|guard| dec::<ObjRecord>(guard.value()))
                    .transpose()?;
                let Some(mut current) = current else {
                    return Ok(GroupBits::new());
                };
                if current.loc != (Loc::Slab { slab, off }) {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        format!("object {id} changed while its broken slab was repaired"),
                    ));
                }
                current.loc = Loc::Sparse;
                current.present.clear();
                objects
                    .insert(id.0.as_slice(), enc(&current).as_slice())
                    .map_err(db_err)?;
                let mut slabs = txn.open_table(SLABS).map_err(db_err)?;
                let meta = slabs
                    .get(slab)
                    .map_err(db_err)?
                    .map(|guard| dec::<SlabMeta>(guard.value()))
                    .transpose()?;
                if let Some(mut meta) = meta {
                    meta.dead = meta.dead.saturating_add(current.size);
                    slabs
                        .insert(slab, enc(&meta).as_slice())
                        .map_err(db_err)?;
                }
            }
            txn.commit().map_err(db_err)?;
            return Ok(GroupBits::new());
        }
        let Loc::Sparse = rec.loc else {
            return Ok(GroupBits::complete(rec.size));
        };
        let claimed = rec.bits();
        let writers = self.sparse_writers.lock().expect("sparse_writers");
        if writers.contains_key(&id) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("sparse object {id} is being written while it is revalidated"),
            ));
        }
        if claimed.is_empty() {
            let backing_exact = backing_length(&self.sparse_path(id))? == Some(rec.size)
                && backing_length(&self.obao_path(id))? == Some(outboard_size(rec.size));
            if !backing_exact {
                self.prepare_empty_sparse_backing(id, rec.size)?;
            }
            return Ok(claimed);
        }
        // A sparse record whose file pair is GONE is the crash window between
        // a materialize's rename and its record commit (or an outside rm of
        // the store dir). The record claims groups no file backs, so every
        // read fails while nothing refetches - the bits say present. Drop the
        // record (via `remove`, which respects in-flight decodes) and report
        // nothing held; the next fetch starts clean with `ensure_sparse`.
        let backing_exact = backing_length(&self.sparse_path(id))? == Some(rec.size)
            && backing_length(&self.obao_path(id))? == Some(outboard_size(rec.size));
        if !backing_exact {
            self.update_record(id, |current| current.present.clear())?;
            self.prepare_empty_sparse_backing(id, rec.size)?;
            return Ok(GroupBits::new());
        }
        drop(writers);
        let obao_bytes = fs::read(self.obao_path(id))?;
        let data = File::open(self.sparse_path(id))?;
        let ob = OutboardBytes { root: id, size: rec.size, data: obao_bytes,
        };
        let valid = match verified::valid_ranges(
            &ob,
            &data,
            &claimed.to_chunk_ranges_clamped(rec.size),
        ) {
            Ok(valid) => valid,
            // Hash mismatches are represented by a smaller valid set. An Err
            // is an ordinary backing I/O failure. Do not destroy verified
            // progress, or race a writer that landed after the initial
            // writers-map check, on an unclassified transient error.
            Err(error) => return Err(error),
        };

        // Intersect: keep only claimed groups whose chunks all verified.
        // The tail group's chunk range must be clamped to the object's real
        // chunk count, or valid_ranges (which never yields a chunk past the
        // end) can't cover it and the pristine tail is wrongly dropped.
        let mut kept = GroupBits::new();
        for r in claimed.ranges() {
            for g in r.clone() {
                let mut one = GroupBits::new();
                one.add(g..g + 1);
                if valid.is_superset(&one.to_chunk_ranges_clamped(rec.size)) {
                    kept.add(g..g + 1);
                }
            }
        }
        // Subtract only the groups that failed, so groups a concurrent
        // write_slice added during the (slow) re-hash are not dropped.
        let failed = kept.added_in(&claimed);
        let updated = self.update_record(id, |cur| {
            let mut bits = cur.bits();
            for r in failed.ranges() {
                bits.remove(r.clone());
            }
            cur.present = bits.to_wire();
        })?;
        Ok(updated.bits())
    }

    /// Whether an extern object's file is still exactly the bytes it was
    /// adopted as: right size, and every chunk group verifies against the
    /// stored outboard. A MISSING backing file answers `Ok(false)` - the
    /// caller (revalidate) must retire the record so the object refetches,
    /// exactly as `materialize_from_extern` treats the same condition;
    /// propagating NotFound instead left a "complete" record whose bytes
    /// could never be served again.
    fn extern_still_matches(&self, id: ObjId, rec: &ObjRecord) -> io::Result<bool> {
        let file = match self.open_extern_file(id) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if file.metadata()?.len() != rec.size {
            return Ok(false);
        }
        let all = GroupBits::complete(rec.size);
        let want = all.to_chunk_ranges_clamped(rec.size);
        let valid_existing = match fs::read(self.obao_path(id)) {
            Ok(data) => {
                let ob = OutboardBytes { root: id, size: rec.size, data };
                match verified::valid_ranges(&ob, &file.try_clone()?, &want) {
                    Ok(valid) => valid.is_superset(&want),
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
                        ) =>
                    {
                        false
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        if valid_existing {
            return Ok(true);
        }

        // Legacy/crashed adopts can leave a valid canonical file with a
        // missing or torn outboard. Rebuild it from the exact source instead
        // of retiring a sound manifest object and forcing a refetch.
        let rebuilt = OutboardBytes::from_reader(io::BufReader::new(file), rec.size)?;
        if rebuilt.root != id {
            return Ok(false);
        }
        self.install_outboard_atomic(id, &rebuilt.data)?;
        Ok(true)
    }

    /// Drop an extern object's record and outboard, leaving the user's file
    /// exactly where it is. The object simply becomes unknown to the store,
    /// so the next fetch re-downloads it as a normal sparse object.
    fn retire_extern(&self, id: ObjId) -> io::Result<()> {
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
            objects.remove(id.0.as_slice()).map_err(db_err)?;
            Self::put_extern_in(&txn, id, None)?;
            Self::clear_owner_markers_in(&txn, id)?;
        }
        txn.commit().map_err(db_err)?;
        let _ = remove_file_durable(&self.obao_path(id));
        Ok(())
    }

    /// Total bytes of all indexed objects (present or claimed).
    pub fn indexed_bytes(&self) -> io::Result<u64> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(OBJECTS).map_err(db_err)?;
        let mut sum = 0;
        for row in table.iter().map_err(db_err)? {
            let (_, v) = row.map_err(db_err)?;
            let rec: ObjRecord = dec(v.value())?;
            sum += rec.size;
        }
        Ok(sum)
    }
}

fn normalized_extern_rel(path: impl AsRef<std::path::Path>) -> io::Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.as_ref().components() {
        match component {
            std::path::Component::Normal(part) => normalized.push(part),
            std::path::Component::CurDir => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsafe extern path: {}", path.as_ref().display()),
                ));
            }
        }
    }
    Ok(normalized)
}

fn backing_length(path: &std::path::Path) -> io::Result<Option<u64>> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata.len())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn validate_no_symlink_components(
    root: &std::path::Path,
    relative: &std::path::Path,
) -> io::Result<()> {
    let root_metadata = fs::symlink_metadata(root)?;
    if metadata_is_link_like(&root_metadata) || !root_metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("xite root {} is not a real directory", root.display()),
        ));
    }
    let components = relative.components().collect::<Vec<_>>();
    let mut current = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(component) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsafe extern path component",
            ));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata_is_link_like(&metadata) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("extern path crosses symlink {}", current.display()),
                    ));
                }
                if index + 1 < components.len() && !metadata.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("extern path ancestor is not a directory: {}", current.display()),
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn metadata_is_link_like(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn cap_metadata_is_link_like(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_link_like(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(unix)]
fn unix_openat(
    directory: &File,
    name: &std::ffi::OsStr,
    flags: rustix::fs::OFlags,
    mode: rustix::fs::Mode,
) -> io::Result<File> {
    rustix::fs::openat(directory, name, flags, mode)
        .map(File::from)
        .map_err(io::Error::from)
}

#[cfg(unix)]
fn unix_root_directory(root: &std::path::Path) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags};

    rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(io::Error::from)
}

#[cfg(unix)]
fn unix_parent_beneath(
    root: &std::path::Path,
    relative: &std::path::Path,
    create: bool,
) -> io::Result<(File, std::ffi::OsString)> {
    use rustix::fs::{Mode, OFlags};

    let mut components = relative.components().collect::<Vec<_>>();
    let Some(final_component) = components.pop() else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty extern path"));
    };
    let std::path::Component::Normal(final_name) = final_component else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsafe extern path"));
    };
    let mut directory = unix_root_directory(root)?;
    for component in components {
        let std::path::Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsafe extern path component",
            ));
        };
        match unix_openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(next) => directory = next,
            Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                if let Err(error) = rustix::fs::mkdirat(
                    &directory,
                    name,
                    Mode::from_bits_truncate(0o755),
                ) {
                    let mkdir_error = io::Error::from(error);
                    if mkdir_error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(mkdir_error);
                    }
                } else {
                    directory.sync_all()?;
                }
                directory = unix_openat(
                    &directory,
                    name,
                    OFlags::RDONLY
                        | OFlags::DIRECTORY
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok((directory, final_name.to_os_string()))
}

#[cfg(unix)]
fn open_regular_beneath(
    root: &std::path::Path,
    relative: &std::path::Path,
) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags};

    let (directory, name) = unix_parent_beneath(root, relative, false)?;
    let file = unix_openat(
        &directory,
        &name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "extern target is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn remove_regular_beneath(
    root: &std::path::Path,
    relative: &std::path::Path,
) -> io::Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags};

    let (directory, name) = unix_parent_beneath(root, relative, false)?;
    let file = unix_openat(
        &directory,
        &name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "extern target is not a regular file",
        ));
    }
    drop(file);
    rustix::fs::unlinkat(&directory, &name, AtFlags::empty()).map_err(io::Error::from)
}

#[cfg(windows)]
fn windows_root_directory(root: &std::path::Path) -> io::Result<cap_std::fs::Dir> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    // Excluding FILE_SHARE_DELETE pins this exact root directory while the
    // capability walker resolves descendants. OPEN_REPARSE_POINT makes the
    // metadata check describe the root endpoint instead of a junction target.
    let root_file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(root)?;
    let metadata = root_file.metadata()?;
    if metadata_is_link_like(&metadata) || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("xite root {} is not a real directory", root.display()),
        ));
    }
    Ok(cap_std::fs::Dir::from_std_file(root_file))
}

#[cfg(windows)]
fn open_regular_beneath(
    root: &std::path::Path,
    relative: &std::path::Path,
) -> io::Result<File> {
    validate_no_symlink_components(root, relative)?;
    // cap-std resolves one component at a time from the pinned root handle.
    // The lexical check rejects stable reparse namespaces. The capability
    // walk prevents a concurrent junction swap from escaping the root.
    let file = windows_root_directory(root)?.open(relative)?.into_std();
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "extern target is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn remove_regular_beneath(
    root: &std::path::Path,
    relative: &std::path::Path,
) -> io::Result<()> {
    validate_no_symlink_components(root, relative)?;
    let directory = windows_root_directory(root)?;
    let metadata = directory.symlink_metadata(relative)?;
    if cap_metadata_is_link_like(&metadata) || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "extern target is not a regular file",
        ));
    }
    directory.remove_file(relative)
}

#[cfg(not(any(unix, windows)))]
fn open_regular_beneath(
    root: &std::path::Path,
    relative: &std::path::Path,
) -> io::Result<File> {
    validate_no_symlink_components(root, relative)?;
    let file = File::open(root.join(relative))?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "extern target is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn remove_regular_beneath(
    root: &std::path::Path,
    relative: &std::path::Path,
) -> io::Result<()> {
    validate_no_symlink_components(root, relative)?;
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)?;
    if metadata_is_link_like(&metadata) || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "extern target is not a regular file",
        ));
    }
    fs::remove_file(path)
}

#[cfg(unix)]
fn copy_regular_file_beneath(
    root: &std::path::Path,
    relative: &std::path::Path,
    mut source: File,
    link_source: Option<&std::path::Path>,
    expected_size: u64,
    expected_id: ObjId,
) -> io::Result<OutboardBytes> {
    use std::io::{Seek, SeekFrom};
    use rustix::fs::{AtFlags, Mode, OFlags};

    match open_regular_beneath(root, relative) {
        Ok(installed) => {
            return verify_open_file_complete(installed, expected_size, expected_id);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let (directory, final_name) = unix_parent_beneath(root, relative, true)?;
    let sequence = STORE_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary_name = std::ffi::OsString::from(format!(
        ".epix-materialize-{}-{sequence}.tmp",
        std::process::id()
    ));
    let source_metadata = source.metadata()?;
    if !source_metadata.is_file() || source_metadata.len() != expected_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "materialization source is {} bytes, expected {expected_size}",
                source_metadata.len()
            ),
        ));
    }
    let linked = link_source.is_some_and(|path| {
        rustix::fs::linkat(
            rustix::fs::CWD,
            path,
            &directory,
            &temporary_name,
            AtFlags::empty(),
        )
        .is_ok()
    });
    let mut temporary = if linked {
        match unix_openat(
            &directory,
            &temporary_name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(file) => file,
            Err(error) => {
                let _ = rustix::fs::unlinkat(&directory, &temporary_name, AtFlags::empty());
                return Err(error);
            }
        }
    } else {
        unix_openat(
            &directory,
            &temporary_name,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )?
    };
    let result = (|| -> io::Result<OutboardBytes> {
        if !linked {
            source.seek(SeekFrom::Start(0))?;
            let copied =
                io::copy(&mut source.take(expected_size.saturating_add(1)), &mut temporary)?;
            if copied != expected_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("source is {copied} bytes, expected {expected_size}"),
                ));
            }
            temporary.sync_all()?;
            temporary.set_permissions(source_metadata.permissions())?;
        }
        temporary.seek(SeekFrom::Start(0))?;
        let outboard = OutboardBytes::from_reader(io::BufReader::new(&temporary), expected_size)?;
        if outboard.root != expected_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("materialized bytes do not hash to {expected_id}"),
            ));
        }
        let verify_existing_and_drop_temporary = |directory: &File| -> io::Result<OutboardBytes> {
            let installed = open_regular_beneath(root, relative)?;
            let outboard = verify_open_file_complete(installed, expected_size, expected_id)?;
            rustix::fs::unlinkat(directory, &temporary_name, AtFlags::empty())
                .map_err(io::Error::from)?;
            directory.sync_all()?;
            Ok(outboard)
        };
        let mut moved = false;
        match rustix::fs::linkat(
            &directory,
            &temporary_name,
            &directory,
            &final_name,
            AtFlags::empty(),
        ) {
            Ok(()) => {}
            Err(error)
                if io::Error::from(error).kind() == io::ErrorKind::AlreadyExists =>
            {
                return verify_existing_and_drop_temporary(&directory);
            }
            // Android SELinux denies linkat for app domains outright. A
            // rename with NOREPLACE installs the temporary with the same
            // never-replace contract, it just cannot keep the temporary
            // name alive through the swap (nothing needs it afterwards).
            Err(error)
                if io::Error::from(error).kind() == io::ErrorKind::PermissionDenied =>
            {
                match rustix::fs::renameat_with(
                    &directory,
                    &temporary_name,
                    &directory,
                    &final_name,
                    rustix::fs::RenameFlags::NOREPLACE,
                ) {
                    Ok(()) => moved = true,
                    Err(error)
                        if io::Error::from(error).kind() == io::ErrorKind::AlreadyExists =>
                    {
                        return verify_existing_and_drop_temporary(&directory);
                    }
                    Err(error) => return Err(io::Error::from(error)),
                }
            }
            Err(error) => return Err(io::Error::from(error)),
        }
        if !moved {
            rustix::fs::unlinkat(&directory, &temporary_name, AtFlags::empty())
                .map_err(io::Error::from)?;
        }
        directory.sync_all()?;
        let installed = open_regular_beneath(root, relative)?;
        verify_open_file_complete(installed, expected_size, expected_id)
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(&directory, &temporary_name, AtFlags::empty());
        let _ = directory.sync_all();
    }
    result
}

#[cfg(windows)]
fn copy_regular_file_beneath(
    root: &std::path::Path,
    relative: &std::path::Path,
    mut source: File,
    _link_source: Option<&std::path::Path>,
    expected_size: u64,
    expected_id: ObjId,
) -> io::Result<OutboardBytes> {
    use std::io::{Seek, SeekFrom};
    match open_regular_beneath(root, relative) {
        Ok(installed) => {
            return verify_open_file_complete(installed, expected_size, expected_id);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    validate_no_symlink_components(root, relative)?;
    let directory = windows_root_directory(root)?;
    let parent = relative.parent().unwrap_or_else(|| std::path::Path::new(""));
    if !parent.as_os_str().is_empty() {
        directory.create_dir_all(parent)?;
    }
    let sequence = STORE_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".epix-materialize-{}-{sequence}.tmp",
        std::process::id()
    ));
    let source_metadata = source.metadata()?;
    if !source_metadata.is_file() || source_metadata.len() != expected_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "materialization source is {} bytes, expected {expected_size}",
                source_metadata.len()
            ),
        ));
    }
    source.seek(SeekFrom::Start(0))?;
    let mut options = cap_std::fs::OpenOptions::new();
    options.create_new(true).read(true).write(true);
    let mut output = directory.open_with(&temporary, &options)?.into_std();
    let mut renamed = false;
    let result = (|| -> io::Result<OutboardBytes> {
        let copied = io::copy(&mut source.take(expected_size.saturating_add(1)), &mut output)?;
        if copied != expected_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("source is {copied} bytes, expected {expected_size}"),
            ));
        }
        output.sync_all()?;
        output.set_permissions(source_metadata.permissions())?;
        output.seek(SeekFrom::Start(0))?;
        let outboard = OutboardBytes::from_reader(io::BufReader::new(&output), expected_size)?;
        if outboard.root != expected_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("materialized bytes do not hash to {expected_id}"),
            ));
        }
        drop(output);
        match epix_fs::install_file_write_through(
            &root.join(&temporary),
            &root.join(relative),
        ) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let installed = open_regular_beneath(root, relative)?;
                let outboard =
                    verify_open_file_complete(installed, expected_size, expected_id)?;
                directory.remove_file(&temporary)?;
                return Ok(outboard);
            }
            Err(error) => return Err(error),
        }
        renamed = true;
        let installed = open_regular_beneath(root, relative)?;
        verify_open_file_complete(installed, expected_size, expected_id)
    })();
    if result.is_err() {
        if renamed {
            let _ = directory.rename(relative, &directory, &temporary);
        }
        let _ = directory.remove_file(&temporary);
    }
    result
}

#[cfg(not(any(unix, windows)))]
fn copy_regular_file_beneath(
    root: &std::path::Path,
    relative: &std::path::Path,
    mut source: File,
    _link_source: Option<&std::path::Path>,
    expected_size: u64,
    expected_id: ObjId,
) -> io::Result<OutboardBytes> {
    use std::io::{Seek, SeekFrom};
    match open_regular_beneath(root, relative) {
        Ok(installed) => {
            return verify_open_file_complete(installed, expected_size, expected_id);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    validate_no_symlink_components(root, relative)?;
    let destination = root.join(relative);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = store_temp_path(&destination, "materialize")?;
    let source_metadata = source.metadata()?;
    if !source_metadata.is_file() || source_metadata.len() != expected_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "materialization source is {} bytes, expected {expected_size}",
                source_metadata.len()
            ),
        ));
    }
    source.seek(SeekFrom::Start(0))?;
    let mut output = OpenOptions::new().create_new(true).read(true).write(true).open(&temporary)?;
    let copied = io::copy(&mut source.take(expected_size.saturating_add(1)), &mut output)?;
    if copied != expected_size {
        let _ = fs::remove_file(&temporary);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("source is {copied} bytes, expected {expected_size}"),
        ));
    }
    output.sync_all()?;
    output.set_permissions(source_metadata.permissions())?;
    output.seek(SeekFrom::Start(0))?;
    let outboard = OutboardBytes::from_reader(io::BufReader::new(&output), expected_size)?;
    if outboard.root != expected_id {
        let _ = fs::remove_file(&temporary);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("materialized bytes do not hash to {expected_id}"),
        ));
    }
    match epix_fs::install_file_write_through(&temporary, &destination) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
    }
    let installed = open_regular_beneath(root, relative)?;
    verify_open_file_complete(installed, expected_size, expected_id)
}

/// Portable comparison key for an extern path. Windows treats Unicode case
/// aliases as one path, while a Store can be moved between filesystems. Both
/// the lowercase and uppercase mappings must match. Requiring both is more
/// conservative than either mapping alone for characters with expanding or
/// context-sensitive case conversions.
fn normalized_extern_key(
    path: impl AsRef<std::path::Path>,
) -> io::Result<(String, String)> {
    let normalized = normalized_extern_rel(path)?;
    let value = normalized.to_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 extern path")
    })?;
    let lower = value.chars().flat_map(char::to_lowercase).collect();
    let upper = value.chars().flat_map(char::to_uppercase).collect();
    Ok((lower, upper))
}

fn normalized_extern_component_keys(
    path: impl AsRef<std::path::Path>,
) -> io::Result<Vec<(String, String)>> {
    let normalized = normalized_extern_rel(path)?;
    normalized
        .components()
        .map(|component| {
            let std::path::Component::Normal(value) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsafe extern path component",
                ));
            };
            let value = value.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 extern path")
            })?;
            Ok((
                value.chars().flat_map(char::to_lowercase).collect(),
                value.chars().flat_map(char::to_uppercase).collect(),
            ))
        })
        .collect()
}

fn extern_suffix_after_prefix(
    path: impl AsRef<std::path::Path>,
    prefix: impl AsRef<std::path::Path>,
) -> io::Result<PathBuf> {
    let path = normalized_extern_rel(path)?;
    let prefix = normalized_extern_rel(prefix)?;
    let path_keys = normalized_extern_component_keys(&path)?;
    let prefix_keys = normalized_extern_component_keys(&prefix)?;
    if !path_keys.starts_with(&prefix_keys) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is outside extern prefix {}", path.display(), prefix.display()),
        ));
    }
    Ok(path
        .components()
        .skip(prefix_keys.len())
        .map(std::path::Component::as_os_str)
        .collect())
}

/// Create a complete destination while keeping `source` valid. The caller
/// commits its index transition only after this succeeds, then unlinks the
/// source. Hard links make the common same-filesystem case constant-time.
#[cfg(test)]
fn duplicate_complete_file(
    source: &std::path::Path,
    destination: &std::path::Path,
    expected_size: u64,
    expected_id: ObjId,
) -> io::Result<()> {
    duplicate_complete_file_with(
        source,
        destination,
        expected_size,
        expected_id,
        |source, destination| fs::hard_link(source, destination),
    )
}

/// Copy from an already opened, no-follow source handle. This is used when
/// the source lives in the mutable xite tree. Keeping the verified handle
/// avoids reopening a pathname after an attacker swaps an ancestor.
fn copy_open_file_complete(
    mut source: File,
    destination: &std::path::Path,
    expected_size: u64,
    expected_id: ObjId,
) -> io::Result<()> {
    let metadata = source.metadata()?;
    if !metadata.is_file() || metadata.len() != expected_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("source is not a regular {expected_size}-byte file"),
        ));
    }
    if destination.exists() {
        fs::remove_file(destination)?;
    }
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    let copied = match io::copy(&mut source, &mut output) {
        Ok(copied) => copied,
        Err(error) => {
            drop(output);
            let _ = fs::remove_file(destination);
            return Err(error);
        }
    };
    if copied != expected_size {
        drop(output);
        let _ = fs::remove_file(destination);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("short copy: {copied} of {expected_size} bytes"),
        ));
    }
    output.sync_all()?;
    drop(output);
    if let Err(error) = verify_complete_file(expected_id, expected_size, destination)
        .and_then(|()| sync_parent(destination))
    {
        let _ = fs::remove_file(destination);
        return Err(error);
    }
    fs::set_permissions(destination, metadata.permissions())
}

fn copy_open_file_complete_atomic(
    source: File,
    destination: &std::path::Path,
    expected_size: u64,
    expected_id: ObjId,
    purpose: &str,
) -> io::Result<()> {
    let temporary = store_temp_path(destination, purpose)?;
    let result = copy_open_file_complete(source, &temporary, expected_size, expected_id)
        .and_then(|()| replace_file_atomic(&temporary, destination));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
fn duplicate_complete_file_with(
    source: &std::path::Path,
    destination: &std::path::Path,
    expected_size: u64,
    expected_id: ObjId,
    try_link: impl FnOnce(&std::path::Path, &std::path::Path) -> io::Result<()>,
) -> io::Result<()> {
    let source_metadata = fs::metadata(source)?;
    if source_metadata.len() != expected_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "source is {} bytes, expected {expected_size}",
                source_metadata.len()
            ),
        ));
    }
    if destination.exists() {
        fs::remove_file(destination)?;
    }
    let linked = try_link(source, destination).is_ok();
    if linked {
        // The source's existing inode already contains the durable bytes.
        // Only the new directory entry needs syncing. In particular, do not
        // reopen a read-only inode for writing just to call sync_all.
        sync_parent(destination)?;
    } else {
        let mut input = File::open(source)?;
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)?;
        let copied = match io::copy(&mut input, &mut output) {
            Ok(copied) => copied,
            Err(error) => {
                drop(output);
                let _ = fs::remove_file(destination);
                return Err(error);
            }
        };
        if copied != expected_size {
            drop(output);
            let _ = fs::remove_file(destination);
            return Err(io::Error::other(format!(
                "short copy: {copied} of {expected_size} bytes"
            )));
        }
        if let Err(error) = output.sync_all() {
            drop(output);
            let _ = fs::remove_file(destination);
            return Err(error);
        }
        drop(output);
        if let Err(error) = sync_parent(destination) {
            let _ = fs::remove_file(destination);
            return Err(error);
        }
        if let Err(error) = fs::set_permissions(destination, source_metadata.permissions()) {
            let _ = fs::remove_file(destination);
            return Err(error);
        }
    }
    let actual = fs::metadata(destination)?.len();
    if actual != expected_size {
        let _ = fs::remove_file(destination);
        return Err(io::Error::other(format!(
            "destination is {actual} bytes, expected {expected_size}"
        )));
    }
    if let Err(error) = verify_complete_file(expected_id, expected_size, destination) {
        let _ = fs::remove_file(destination);
        return Err(error);
    }
    sync_parent(destination)
}

fn sync_parent(path: &std::path::Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        #[cfg(not(unix))]
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn remove_file_durable(path: &std::path::Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => sync_parent(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// `sync_parent` is a silent no-op on Windows (std's `File::open` cannot open
/// a directory), so a plain remove_file + sync gave no durability there.
/// epix-fs's tombstone move (`MOVEFILE_WRITE_THROUGH`) makes the entry
/// removal durable the same way epix-xite's delete path already does.
#[cfg(windows)]
fn remove_file_durable(path: &std::path::Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => epix_fs::remove_file_write_through(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn replace_file_atomic(source: &std::path::Path, destination: &std::path::Path) -> io::Result<()> {
    let source_parent = source
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "source has no parent"))?;
    let destination_parent = destination.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent")
    })?;
    if source_parent != destination_parent {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic replacement requires one parent directory",
        ));
    }
    epix_fs::replace_file_write_through(source, destination)
}

#[cfg(not(windows))]
fn replace_file_atomic(source: &std::path::Path, destination: &std::path::Path) -> io::Result<()> {
    fs::rename(source, destination)?;
    sync_parent(destination)
}

fn store_temp_path(destination: &std::path::Path, purpose: &str) -> io::Result<PathBuf> {
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::other("Store destination has no parent"))?;
    let name = destination
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("object");
    let sequence = STORE_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Ok(parent.join(format!(
        ".{name}.{purpose}-{}-{sequence}.tmp",
        std::process::id()
    )))
}

fn cleanup_store_temps(sparse: &std::path::Path) -> io::Result<()> {
    for entry in fs::read_dir(sparse)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
        let Some(body) = name.strip_prefix('.').and_then(|name| name.strip_suffix(".tmp"))
        else {
            continue;
        };
        let valid_hex = |value: &str| {
            value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        };
        let valid_suffix = |value: &str| {
            let mut parts = value.split('-');
            parts.next().is_some_and(|part| {
                !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
            }) && parts.next().is_some_and(|part| {
                !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
            }) && parts.next().is_none()
        };
        let internalize = body
            .split_once(".internalize-")
            .is_some_and(|(id, suffix)| valid_hex(id) && valid_suffix(suffix));
        let outboard = body
            .split_once(".obao.outboard-")
            .is_some_and(|(id, suffix)| valid_hex(id) && valid_suffix(suffix));
        let rollback = body
            .split_once(".rollback-")
            .is_some_and(|(id, suffix)| valid_hex(id) && valid_suffix(suffix));
        if !internalize && !outboard && !rollback {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_file() {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn cleanup_unindexed_sparse_files(
    sparse: &std::path::Path,
    database: &Database,
) -> io::Result<()> {
    const MAX_SPARSE_ENTRIES: usize = 2_000_000;

    let txn = database.begin_read().map_err(db_err)?;
    let objects = txn.open_table(OBJECTS).map_err(db_err)?;
    let mut removed = false;
    for (index, entry) in fs::read_dir(sparse)?.enumerate() {
        if index >= MAX_SPARSE_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sparse directory entry limit exceeded",
            ));
        }
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
        let (id_text, outboard) = match name.strip_suffix(".obao") {
            Some(id) => (id, true),
            None => (name.as_str(), false),
        };
        let Some(id) = ObjId::from_hex(id_text) else { continue };
        let record = objects
            .get(id.0.as_slice())
            .map_err(db_err)?
            .map(|guard| dec::<ObjRecord>(guard.value()))
            .transpose()?;
        let owned = match (record.as_ref().map(|record| record.loc), outboard) {
            (Some(Loc::Sparse), _) => true,
            (Some(Loc::Extern), true) => true,
            _ => false,
        };
        if owned {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_file() && !metadata.file_type().is_symlink() {
            fs::remove_file(entry.path())?;
            removed = true;
        }
    }
    if removed {
        sync_directory_entry(sparse)?;
    }
    Ok(())
}

fn cleanup_unindexed_slab_files(slabs_dir: &std::path::Path, database: &Database) -> io::Result<()> {
    const MAX_SLAB_ENTRIES: usize = 1_000_000;

    let txn = database.begin_read().map_err(db_err)?;
    let slabs = txn.open_table(SLABS).map_err(db_err)?;
    let mut indexed = HashSet::new();
    for row in slabs.iter().map_err(db_err)? {
        let (key, _) = row.map_err(db_err)?;
        indexed.insert(key.value());
    }
    drop(slabs);
    drop(txn);

    for (index, entry) in fs::read_dir(slabs_dir)?.enumerate() {
        if index >= MAX_SLAB_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "slab directory entry limit exceeded",
            ));
        }
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
        let Some(raw_id) = name.strip_suffix(".slab") else { continue };
        let Ok(id) = raw_id.parse::<u32>() else { continue };
        if name != format!("{id}.slab") || indexed.contains(&id) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_file() && !metadata.file_type().is_symlink() {
            remove_file_durable(&entry.path())?;
        }
    }
    Ok(())
}

fn verify_complete_file(
    id: ObjId,
    expected_size: u64,
    path: &std::path::Path,
) -> io::Result<()> {
    let actual = fs::metadata(path)?.len();
    if actual != expected_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} is {actual} bytes, expected {expected_size} for {id}",
                path.display()
            ),
        ));
    }
    let outboard = OutboardBytes::from_reader(io::BufReader::new(File::open(path)?), actual)?;
    if outboard.root != id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} does not hash to {id}", path.display()),
        ));
    }
    Ok(())
}

/// Returns the verified outboard so the caller can install it directly
/// instead of re-reading and re-hashing the whole file a third time.
fn verify_open_file_complete(
    mut file: File,
    expected_size: u64,
    id: ObjId,
) -> io::Result<OutboardBytes> {
    let actual = file.metadata()?.len();
    if actual != expected_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("installed file is {actual} bytes, expected {expected_size} for {id}"),
        ));
    }
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let outboard = OutboardBytes::from_reader(io::BufReader::new(file), actual)?;
    if outboard.root != id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("installed file does not hash to {id}"),
        ));
    }
    Ok(outboard)
}

#[cfg(unix)]
fn ensure_same_filesystem(left: &std::path::Path, right: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    fn existing_metadata(path: &std::path::Path) -> io::Result<std::fs::Metadata> {
        let mut current = Some(path);
        while let Some(candidate) = current {
            match fs::metadata(candidate) {
                Ok(metadata) => return Ok(metadata),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    current = candidate.parent();
                }
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no existing ancestor for {}", path.display()),
        ))
    }

    if existing_metadata(left)?.dev() != existing_metadata(right)?.dev() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "extern relocation cannot cross filesystems: {} to {}",
                left.display(),
                right.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_same_filesystem(_left: &std::path::Path, _right: &std::path::Path) -> io::Result<()> {
    // The caller proves this with an atomic filesystem rename before the Store
    // row is retargeted. A cross-volume rename fails without mutation.
    Ok(())
}

fn sync_directory_entry(path: &std::path::Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        if let Ok(directory) = File::open(path) {
            let _ = directory.sync_all();
        }
    }
    Ok(())
}

fn ns_to_u8(ns: Ns) -> u8 {
    match ns {
        Ns::Plain => 0,
        Ns::Shard => 1,
    }
}

/// Inverse of [`ns_to_u8`], for paths that rewrite an existing record and
/// must carry its namespace forward. An unknown byte reads as `Plain`: the
/// field is ours, so this only fires on a corrupt record, and treating it
/// as plain content is the conservative choice (shards are the namespace
/// with the deniability property to protect).
fn u8_to_ns(v: u8) -> Ns {
    match v {
        1 => Ns::Shard,
        _ => Ns::Plain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
    }

    fn slice_for(data: &[u8], ranges: &[Range<u64>]) -> (ObjId, u64, Vec<u8>) {
        let ob = OutboardBytes::from_slice(data);
        let mut out = Vec::new();
        verified::encode_slice(data, &ob, ranges, &mut out).unwrap();
        (ob.root, ob.size, out)
    }

    fn rooted_store<'a>(
        store_dir: &'a tempfile::TempDir,
        tree: &'a tempfile::TempDir,
    ) -> Store {
        Store::open_with(
            store_dir.path(),
            StoreConfig {
                xite_root: Some(tree.path().to_path_buf()),
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn extern_adoption_rejects_a_symlinked_namespace() {
        use std::os::unix::fs::symlink;

        let store_dir = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let store = rooted_store(&store_dir, &tree);
        let bytes = test_data(120_000);
        let id = ObjId::of(&bytes);
        let site = tree.path().join("site");
        std::fs::create_dir_all(&site).unwrap();
        std::fs::write(outside.path().join("secret.bin"), &bytes).unwrap();
        symlink(outside.path(), site.join("link")).unwrap();

        let error = store
            .adopt_extern(id, Ns::Plain, &site.join("link/secret.bin"), 1)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!store.contains(id).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn materialization_rejects_a_symlinked_destination_namespace() {
        use std::os::unix::fs::symlink;

        let store_dir = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let store = rooted_store(&store_dir, &tree);
        let bytes = test_data(120_000);
        let (id, size, slice) = slice_for(&bytes, &[0..bytes.len() as u64]);
        store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
        store
            .write_slice(id, &[0..bytes.len() as u64], &slice[..], 2)
            .unwrap();
        let site = tree.path().join("site");
        std::fs::create_dir_all(&site).unwrap();
        let destination = outside.path().join("asset.bin");
        std::fs::write(&destination, b"outside sentinel").unwrap();
        symlink(outside.path(), site.join("link")).unwrap();

        let error = store.materialize(id, &site.join("link/asset.bin"), 3).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(std::fs::read(destination).unwrap(), b"outside sentinel");
        assert!(!store.is_extern(id).unwrap());
        assert_eq!(store.read_bytes(id, 4).unwrap(), bytes);
    }

    #[test]
    fn materialization_rejects_an_extended_sparse_source_before_replacing_destination() {
        let store_dir = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        let store = rooted_store(&store_dir, &tree);
        let bytes = test_data(120_000);
        let (id, size, slice) = slice_for(&bytes, &[0..bytes.len() as u64]);
        store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
        store
            .write_slice(id, &[0..bytes.len() as u64], &slice[..], 2)
            .unwrap();
        OpenOptions::new()
            .append(true)
            .open(store.sparse_path(id))
            .unwrap()
            .write_all(b"trailing")
            .unwrap();
        let destination = tree.path().join("site/asset.bin");
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::write(&destination, b"sentinel").unwrap();

        assert!(store.materialize(id, &destination, 3).is_err());
        assert_eq!(std::fs::read(destination).unwrap(), b"sentinel");
        assert!(!store.is_extern(id).unwrap());
    }

    #[test]
    fn adopt_repairs_a_complete_broken_sparse_record_and_preserves_owners() {
        let store_dir = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        let store = rooted_store(&store_dir, &tree);
        let bytes = test_data(120_000);
        let (id, size, slice) = slice_for(&bytes, &[0..bytes.len() as u64]);
        store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
        store
            .write_slice(id, &[0..bytes.len() as u64], &slice[..], 2)
            .unwrap();
        store.claim_manifest(id).unwrap();
        std::fs::remove_file(store.sparse_path(id)).unwrap();
        let path = tree.path().join("site/asset.bin");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &bytes).unwrap();

        assert!(store.adopt_extern(id, Ns::Plain, &path, 3).unwrap());
        assert!(store.is_extern(id).unwrap());
        assert_eq!(store.get_record(id).unwrap().unwrap().refcount, 1);
        assert!(store.manifest_owned_ids().unwrap().contains(&id));
        assert_eq!(store.read_bytes(id, 4).unwrap(), bytes);
    }

    #[test]
    fn extern_case_alias_ambiguity_blocks_lookup_and_retirement() {
        let store_dir = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        let store = rooted_store(&store_dir, &tree);
        let data = test_data(120_000);
        let owner = ObjId::of(&data);
        let other = ObjId::of(b"different object");
        let path = tree.path().join("xite1").join("Owned.bin");
        let alias = tree.path().join("xite1").join("owned.BIN");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &data).unwrap();
        store.adopt_extern(owner, Ns::Plain, &path, 1).unwrap();
        if !alias.exists() {
            std::fs::hard_link(&path, &alias).unwrap();
        }

        let rel = store.rel_of(&alias).unwrap();
        assert!(
            store
                .commit_extern(other, Ns::Plain, data.len() as u64, &rel, 2)
                .is_err(),
            "normal commits reject portable path aliases"
        );
        store
            .put_record(
                other,
                &ObjRecord {
                    size: data.len() as u64,
                    ns: ns_to_u8(Ns::Plain),
                    loc: Loc::Extern,
                    present: GroupBits::complete(data.len() as u64).to_wire(),
                    refcount: 0,
                    last_access: 2,
                },
            )
            .unwrap();
        let txn = store.db.begin_write().unwrap();
        {
            let mut externs = txn.open_table(EXTERN).unwrap();
            externs.insert(other.0.as_slice(), rel.as_str()).unwrap();
        }
        txn.commit().unwrap();

        let error = store.complete_extern_owner_at(&alias).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("claimed by both"));

        let error = store.retire_extern_mapping_at(owner, &alias).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(store.contains(owner).unwrap());
        assert!(store.contains(other).unwrap());
    }

    #[test]
    fn complete_extern_owner_rejects_a_path_row_without_an_object() {
        let store_dir = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        let store = rooted_store(&store_dir, &tree);
        let id = ObjId::of(b"missing object row");
        let path = tree.path().join("xite1").join("orphan.bin");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, test_data(120_000)).unwrap();
        let rel = store.rel_of(&path).unwrap();

        let txn = store.db.begin_write().unwrap();
        {
            let mut externs = txn.open_table(EXTERN).unwrap();
            externs.insert(id.0.as_slice(), rel.as_str()).unwrap();
        }
        txn.commit().unwrap();

        let error = store.complete_extern_owner_at(&path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("missing object"));
    }

    #[test]
    fn complete_extern_owner_rejects_bytes_that_do_not_match_the_row() {
        let store_dir = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        let store = rooted_store(&store_dir, &tree);
        let data = test_data(120_000);
        let id = ObjId::of(&data);
        let path = tree.path().join("xite1").join("corrupt.bin");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &data).unwrap();
        store.adopt_extern(id, Ns::Plain, &path, 1).unwrap();

        let mut corrupt = data;
        corrupt[50_000] ^= 0xff;
        std::fs::write(&path, corrupt).unwrap();

        let error = store.complete_extern_owner_at(&path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn materialize_recovers_sparse_row_after_legacy_bytes_move() {
        let store_dir = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        let store = rooted_store(&store_dir, &tree);
        let data = test_data(120_000);
        let (id, size, slice) = slice_for(&data, &[0..120_000]);
        store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
        store.write_slice(id, &[0..120_000], &slice[..], 1).unwrap();

        let sparse = store.sparse_path(id);
        let staged = tree.path().join(".epix-stage").join(id.to_string());
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        std::fs::rename(&sparse, &staged).unwrap();

        store.materialize(id, &staged, 2).unwrap();
        assert!(store.is_extern(id).unwrap());
        assert!(!sparse.exists());
        assert_eq!(store.read_bytes(id, 3).unwrap(), data);
    }

    #[test]
    fn staged_rollback_recovers_extern_row_after_legacy_bytes_move() {
        let store_dir = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        let store = rooted_store(&store_dir, &tree);
        let data = test_data(120_000);
        let (id, size, slice) = slice_for(&data, &[0..120_000]);
        store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
        store.write_slice(id, &[0..120_000], &slice[..], 1).unwrap();
        let staged = tree.path().join(".epix-stage").join(id.to_string());
        store.materialize(id, &staged, 2).unwrap();

        let sparse = store.sparse_path(id);
        std::fs::rename(&staged, &sparse).unwrap();
        assert!(store.is_extern(id).unwrap(), "the simulated DB commit did not happen");

        assert_eq!(
            store.rollback_staged_extern(id, &staged).unwrap(),
            ExternRollback::RestoredSparse
        );
        assert!(!store.is_extern(id).unwrap());
        assert!(!staged.exists());
        assert_eq!(store.read_bytes(id, 3).unwrap(), data);
    }

    #[test]
    fn materialize_retry_reconciles_both_source_preserving_crash_phases() {
        let store_dir = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        let store = rooted_store(&store_dir, &tree);
        let data = test_data(120_000);
        let (id, size, slice) = slice_for(&data, &[0..120_000]);
        store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
        store.write_slice(id, &[0..120_000], &slice[..], 1).unwrap();
        let sparse = store.sparse_path(id);
        let staged = tree.path().join(".epix-stage").join(id.to_string());
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();

        // Crash after destination durability, before the row commit.
        duplicate_complete_file(&sparse, &staged, size, id).unwrap();
        drop(store);
        let store = rooted_store(&store_dir, &tree);
        store.materialize(id, &staged, 2).unwrap();
        assert!(store.is_extern(id).unwrap());
        assert!(!sparse.exists());

        // Crash after row commit, before sparse-source unlink.
        duplicate_complete_file(&staged, &sparse, size, id).unwrap();
        drop(store);
        let store = rooted_store(&store_dir, &tree);
        store.materialize(id, &staged, 3).unwrap();
        assert!(store.is_extern(id).unwrap());
        assert!(!sparse.exists());
        assert_eq!(store.read_bytes(id, 4).unwrap(), data);
    }

    #[test]
    fn rollback_retry_reconciles_both_source_preserving_crash_phases() {
        let store_dir = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        let store = rooted_store(&store_dir, &tree);
        let data = test_data(120_000);
        let (id, size, slice) = slice_for(&data, &[0..120_000]);
        store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
        store.write_slice(id, &[0..120_000], &slice[..], 1).unwrap();
        let staged = tree.path().join(".epix-stage").join(id.to_string());
        store.materialize(id, &staged, 2).unwrap();
        let sparse = store.sparse_path(id);

        // Crash after sparse durability, before the row commit.
        duplicate_complete_file(&staged, &sparse, size, id).unwrap();
        drop(store);
        let store = rooted_store(&store_dir, &tree);
        assert_eq!(
            store.rollback_staged_extern(id, &staged).unwrap(),
            ExternRollback::RestoredSparse
        );
        assert!(!store.is_extern(id).unwrap());
        assert!(!staged.exists());

        // Crash after row commit, before staged-source unlink.
        duplicate_complete_file(&sparse, &staged, size, id).unwrap();
        drop(store);
        let store = rooted_store(&store_dir, &tree);
        assert_eq!(
            store.rollback_staged_extern(id, &staged).unwrap(),
            ExternRollback::RestoredSparse
        );
        assert!(!store.is_extern(id).unwrap());
        assert!(!staged.exists());
        assert_eq!(store.read_bytes(id, 3).unwrap(), data);
    }

    #[test]
    fn internalizing_an_extern_preserves_its_bytes_path_and_refcount() {
        let store_dir = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        let store = rooted_store(&store_dir, &tree);
        let data = test_data(120_000);
        let id = ObjId::of(&data);
        let path = tree.path().join("xite1").join("owned.bin");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &data).unwrap();
        store.adopt_extern(id, Ns::Plain, &path, 1).unwrap();
        store.ref_delta(id, 2).unwrap();
        std::fs::remove_file(store.obao_path(id)).unwrap();
        std::fs::write(store.sparse_path(id), b"torn residue").unwrap();

        assert_eq!(
            store.internalize_extern_at(id, &path).unwrap(),
            ExternInternalization::Internalized
        );
        assert!(!store.is_extern(id).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), data);
        assert_eq!(store.read_bytes(id, 2).unwrap(), data);
        assert_eq!(store.required(id).unwrap().refcount, 2);

        std::fs::write(&path, b"replacement").unwrap();
        store.revalidate(id).unwrap();
        assert!(store.is_complete(id).unwrap());
        assert_eq!(store.read_bytes(id, 3).unwrap(), data);
        let mut encoded = Vec::new();
        store
            .encode_slice(id, &[0..data.len() as u64], &mut encoded, 4)
            .unwrap();
        assert!(!encoded.is_empty());

        assert_eq!(
            store.internalize_extern_at(id, &path).unwrap(),
            ExternInternalization::Internalized
        );
        assert_eq!(store.required(id).unwrap().refcount, 2);
    }

    #[test]
    fn revalidate_repairs_a_missing_extern_outboard() {
        let store_dir = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        let store = rooted_store(&store_dir, &tree);
        let data = test_data(120_000);
        let id = ObjId::of(&data);
        let path = tree.path().join("xite1").join("owned.bin");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &data).unwrap();
        store.adopt_extern(id, Ns::Plain, &path, 1).unwrap();
        std::fs::remove_file(store.obao_path(id)).unwrap();

        assert_eq!(store.revalidate(id).unwrap(), GroupBits::complete(data.len() as u64));
        assert!(store.obao_path(id).is_file());
        let mut encoded = Vec::new();
        store
            .encode_slice(id, &[0..data.len() as u64], &mut encoded, 2)
            .unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn reopen_removes_only_validated_abandoned_store_temps() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path()).unwrap();
        let id = ObjId::of(b"temp cleanup");
        let sparse = store_dir.path().join("sparse");
        let abandoned = sparse.join(format!(
            ".{id}.internalize-{}-7.tmp",
            std::process::id()
        ));
        let unrelated = sparse.join(format!(".{id}.user.tmp"));
        std::fs::write(&abandoned, b"partial").unwrap();
        std::fs::write(&unrelated, b"keep").unwrap();
        drop(store);

        let _store = Store::open(store_dir.path()).unwrap();
        assert!(!abandoned.exists());
        assert!(unrelated.exists());
    }

    #[test]
    fn manifest_and_feed_owners_keep_distinct_persistent_references() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path()).unwrap();
        let data = test_data(1024);
        let id = ObjId::of(&data);
        store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();

        assert!(store.claim_feed(id).unwrap());
        store.pin(id).unwrap();
        assert!(store.claim_manifest(id).unwrap());
        assert_eq!(store.ref_delta(id, 0).unwrap(), 2);
        assert_eq!(store.manifest_owned_ids().unwrap(), vec![id]);

        drop(store);
        let store = Store::open(store_dir.path()).unwrap();
        assert_eq!(store.ref_delta(id, 0).unwrap(), 2);
        assert!(store.release_manifest(id).unwrap());
        assert_eq!(store.ref_delta(id, 0).unwrap(), 1);
        store.clear_feed_owners().unwrap();
        assert_eq!(store.ref_delta(id, 0).unwrap(), 0);
    }

    #[test]
    fn manifest_claim_migrates_one_legacy_pin_without_inflation() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path()).unwrap();
        let data = test_data(1024);
        let id = ObjId::of(&data);
        store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();
        store.pin(id).unwrap();

        assert!(store.claim_manifest(id).unwrap());
        assert!(!store.claim_manifest(id).unwrap());
        assert_eq!(store.ref_delta(id, 0).unwrap(), 1);
        assert!(store.release_manifest(id).unwrap());
        assert_eq!(store.ref_delta(id, 0).unwrap(), 0);
    }

    #[test]
    fn manifest_claim_after_restart_distinguishes_a_persisted_feed_owner() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path()).unwrap();
        let data = test_data(1024);
        let id = ObjId::of(&data);
        store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();
        store.claim_feed(id).unwrap();
        drop(store);

        let store = Store::open(store_dir.path()).unwrap();
        assert!(store.claim_manifest(id).unwrap());
        assert_eq!(store.ref_delta(id, 0).unwrap(), 2);
        store.release_manifest(id).unwrap();
        assert_eq!(store.ref_delta(id, 0).unwrap(), 1);
        store.release_feed(id).unwrap();
        assert_eq!(store.ref_delta(id, 0).unwrap(), 0);
    }

    #[test]
    fn schema_v1_migration_resets_legacy_untyped_pins() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path()).unwrap();
        let data = test_data(1024);
        let id = ObjId::of(&data);
        store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();
        store.pin(id).unwrap();
        let txn = store.db.begin_write().unwrap();
        {
            txn.open_table(META)
                .unwrap()
                .insert("schema", 1)
                .unwrap();
        }
        txn.commit().unwrap();
        drop(store);

        let store = Store::open(store_dir.path()).unwrap();
        assert!(store.is_complete(id).unwrap());
        assert_eq!(store.ref_delta(id, 0).unwrap(), 0);
        assert!(store.claim_feed(id).unwrap());
        assert_eq!(store.ref_delta(id, 0).unwrap(), 1);
        assert!(store.release_feed(id).unwrap());
        assert_eq!(store.ref_delta(id, 0).unwrap(), 0);
    }

    #[test]
    fn object_recreation_can_reclaim_cleared_typed_owner_markers() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path()).unwrap();
        let data = test_data(1024);
        let id = ObjId::of(&data);

        store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();
        store.claim_manifest(id).unwrap();
        store.remove(id).unwrap();
        store.insert_bytes(id, Ns::Plain, &data, 2).unwrap();
        assert!(store.claim_manifest(id).unwrap());
        assert_eq!(store.ref_delta(id, 0).unwrap(), 1);
        store.release_manifest(id).unwrap();

        store.claim_feed(id).unwrap();
        store.remove(id).unwrap();
        store.insert_bytes(id, Ns::Plain, &data, 3).unwrap();
        assert!(store.claim_feed(id).unwrap());
        assert_eq!(store.ref_delta(id, 0).unwrap(), 1);
        store.release_feed(id).unwrap();
        assert_eq!(store.ref_delta(id, 0).unwrap(), 0);
    }

    /// A peer sink that commits store work the first time the encode writes
    /// to it, standing in for a slow peer that lets the fetch path land more
    /// groups (and a pin) while the serve is parked on backpressure.
    struct Meddler<'a> {
        store: &'a Store,
        id: ObjId,
        ranges: &'a [Range<u64>],
        slice: &'a [u8],
        fired: bool,
    }

    impl Write for Meddler<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if !self.fired {
                self.fired = true;
                self.store.write_slice(self.id, self.ranges, self.slice, 9).unwrap();
                self.store.pin(self.id).unwrap();
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn revalidate_retires_a_torn_slab_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let data = test_data(4_000);
        let ob = OutboardBytes::from_slice(&data);
        let id = ob.root;
        assert!(store.insert_bytes(id, Ns::Plain, &data, 1).unwrap());

        // A hard kill that loses fs writes leaves the slab file shorter than
        // its committed len: the record points at bytes that are not there.
        let Loc::Slab { slab, .. } = store.get_record(id).unwrap().unwrap().loc else {
            panic!("small insert must land in a slab");
        };
        let slab_file = store.slab_path(slab);
        drop(store);
        std::fs::write(&slab_file, b"garbage").unwrap();

        // Reopen (the crashed process restarting): the damaged open slab must
        // be sealed with a fresh one opened for appends, or every future
        // insert is recorded at an offset its bytes never reach.
        let store = Store::open(dir.path()).unwrap();
        assert!(store.read_bytes(id, 2).is_err(), "corrupt slab read must fail");

        // Revalidate must stop trusting Loc::Slab: the record converts to an
        // empty sparse fetch target in place (preserving any typed-owner
        // markers), so the object stops being a black hole and refetches
        // cleanly.
        let bits = store.revalidate(id).unwrap();
        assert!(bits.is_empty());
        let repaired = store.get_record(id).unwrap().unwrap();
        assert!(matches!(repaired.loc, Loc::Sparse), "torn slab converts to sparse");
        assert!(!repaired.is_complete(), "converted record is refetchable");
        assert!(store.insert_bytes(id, Ns::Plain, &data, 3).unwrap(), "refetch lands");
        assert_eq!(store.read_bytes(id, 4).unwrap(), data);
    }

    #[test]
    fn insert_bytes_repairs_a_complete_broken_slab_and_preserves_owners() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let data = test_data(4_000);
        let id = ObjId::of(&data);
        assert!(store.insert_bytes(id, Ns::Plain, &data, 1).unwrap());
        assert!(store.claim_manifest(id).unwrap());
        let Loc::Slab { slab, .. } = store.required(id).unwrap().loc else {
            panic!("small insert must land in a slab");
        };
        std::fs::write(store.slab_path(slab), b"torn").unwrap();

        assert!(
            store.insert_bytes(id, Ns::Plain, &data, 2).unwrap(),
            "verified bytes repair a physically broken complete row"
        );
        assert_eq!(store.read_bytes(id, 3).unwrap(), data);
        assert_eq!(store.required(id).unwrap().refcount, 1);
        assert!(store.manifest_owned_ids().unwrap().contains(&id));
    }

    #[test]
    fn revalidate_converts_a_broken_owned_slab_to_refetchable_sparse() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let bytes = test_data(48_000);
        let id = ObjId::of(&bytes);
        store.insert_bytes(id, Ns::Plain, &bytes, 1).unwrap();
        store.claim_manifest(id).unwrap();
        store.claim_feed(id).unwrap();
        let record = store.get_record(id).unwrap().unwrap();
        let Loc::Slab { slab, .. } = record.loc else {
            panic!("insert did not use the slab");
        };
        std::fs::OpenOptions::new()
            .write(true)
            .open(store.slab_path(slab))
            .unwrap()
            .set_len(0)
            .unwrap();

        assert!(store.revalidate(id).unwrap().is_empty());
        let repaired = store.get_record(id).unwrap().unwrap();
        assert!(matches!(repaired.loc, Loc::Sparse));
        assert_eq!(repaired.refcount, 2);
        assert!(store.manifest_owned_ids().unwrap().contains(&id));
        assert!(!store.claim_feed(id).unwrap(), "feed marker was preserved");

        assert!(store.insert_bytes(id, Ns::Plain, &bytes, 2).unwrap());
        assert_eq!(store.get_record(id).unwrap().unwrap().refcount, 2);
        assert_eq!(store.read_bytes(id, 3).unwrap(), bytes);
    }

    #[test]
    fn manifest_release_deletes_only_when_no_independent_owner_remains() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let bytes = test_data(32_000);
        let id = ObjId::of(&bytes);
        store.insert_bytes(id, Ns::Plain, &bytes, 1).unwrap();
        store.claim_manifest(id).unwrap();
        store.claim_feed(id).unwrap();

        assert!(!store.release_manifest_and_delete_unowned(id).unwrap());
        assert!(store.contains(id).unwrap());
        assert_eq!(store.get_record(id).unwrap().unwrap().refcount, 1);
        assert!(store.release_feed(id).unwrap());

        let other = ObjId::of(b"manifest only");
        store.insert_bytes(other, Ns::Plain, b"manifest only", 2).unwrap();
        store.claim_manifest(other).unwrap();
        assert!(store.release_manifest_and_delete_unowned(other).unwrap());
        assert!(!store.contains(other).unwrap());
    }

    #[test]
    fn insert_bytes_replaces_an_incomplete_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // A fetch killed mid-write leaves a sparse record with a partial (or
        // empty) group set. Delivering the complete verified bytes later must
        // fill the object, not be discarded as a dedup hit - that discard
        // made a xite permanently uncloneable on the node.
        let data = test_data(50_000);
        let ob = OutboardBytes::from_slice(&data);
        let id = ob.root;
        store.ensure_sparse(id, Ns::Plain, ob.size, 1).unwrap();
        assert!(!store.is_complete(id).unwrap(), "sparse record starts incomplete");

        let wrote = store.insert_bytes(id, Ns::Plain, &data, 2).unwrap();
        assert!(wrote, "complete bytes must replace the stale incomplete record");
        assert!(store.is_complete(id).unwrap());
        assert_eq!(store.read_bytes(id, 3).unwrap(), data, "bytes readable after repair");

        // A COMPLETE record still dedups.
        assert!(!store.insert_bytes(id, Ns::Plain, &data, 4).unwrap());
    }

    #[test]
    fn ensure_sparse_repairs_an_empty_crash_row_and_wrong_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let data = test_data(50_000);
        let (id, size, slice) = slice_for(&data, &[0..data.len() as u64]);

        // Plant the first reservation with metadata that cannot describe this
        // object, then damage both backing files as a crash could.
        store.ensure_sparse(id, Ns::Shard, 17, 1).unwrap();
        std::fs::remove_file(store.sparse_path(id)).unwrap();
        std::fs::write(store.obao_path(id), b"torn").unwrap();

        store.ensure_sparse(id, Ns::Plain, size, 2).unwrap();
        let record = store.required(id).unwrap();
        assert_eq!(record.size, size);
        assert_eq!(record.ns, ns_to_u8(Ns::Plain));
        assert!(record.bits().is_empty());
        assert_eq!(std::fs::metadata(store.sparse_path(id)).unwrap().len(), size);
        assert_eq!(
            std::fs::metadata(store.obao_path(id)).unwrap().len(),
            outboard_size(size)
        );
        store
            .write_slice(id, &[0..data.len() as u64], &slice[..], 3)
            .unwrap();
        assert_eq!(store.read_bytes(id, 4).unwrap(), data);
    }

    #[test]
    fn revalidate_repairs_empty_and_claimed_sparse_backing_without_losing_owners() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let data = test_data(80_000);
        let held = 0..data.len() as u64;
        let (id, size, slice) = slice_for(&data, &[held.clone()]);

        store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
        std::fs::remove_file(store.sparse_path(id)).unwrap();
        assert!(store.revalidate(id).unwrap().is_empty());
        assert_eq!(std::fs::metadata(store.sparse_path(id)).unwrap().len(), size);

        store.write_slice(id, &[held], &slice[..], 2).unwrap();
        assert!(store.claim_manifest(id).unwrap());
        std::fs::write(store.obao_path(id), b"short outboard").unwrap();
        assert!(store.revalidate(id).unwrap().is_empty());
        let record = store.required(id).unwrap();
        assert_eq!(record.refcount, 1, "repair preserves typed ownership");
        assert!(store.manifest_owned_ids().unwrap().contains(&id));
        assert_eq!(std::fs::metadata(store.sparse_path(id)).unwrap().len(), size);
        assert_eq!(
            std::fs::metadata(store.obao_path(id)).unwrap().len(),
            outboard_size(size)
        );
    }

    #[test]
    fn serving_a_slice_does_not_revert_a_concurrent_write() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let data = test_data(200_000);
        let held = 0u64..16_384;
        let later = 49_152u64..65_536;
        let (id, size, held_slice) = slice_for(&data, &[held.clone()]);
        let (_, _, later_slice) = slice_for(&data, &[later.clone()]);

        store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
        store.write_slice(id, &[held.clone()], &held_slice[..], 2).unwrap();

        let later_ranges = [later.clone()];
        let mut sink =
            Meddler { store: &store, id, ranges: &later_ranges, slice: &later_slice, fired: false,
        };
        store.encode_slice(id, &[held.clone()], &mut sink, 3).unwrap();
        assert!(sink.fired, "the concurrent work must have run inside the encode");

        let bits = store.present_bits(id).unwrap();
        assert!(bits.contains_all(&groups_for_bytes(&held)), "served groups still present");
        assert!(bits.contains_all(&groups_for_bytes(&later)), "groups landed during the serve");
        assert_eq!(store.required(id).unwrap().refcount, 1, "pin taken during the serve");
    }

    #[test]
    fn ensure_sparse_rejects_a_size_over_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let id = ObjId::of(b"declared-by-a-hostile-manifest");
        let e = store.ensure_sparse(id, Ns::Plain, MAX_OBJECT_BYTES + 1, 1).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(!store.contains(id).unwrap(), "no record for a rejected reservation");
        assert!(!dir.path().join("sparse").join(id.to_string()).exists());
    }

    #[test]
    fn quota_charges_held_bytes_not_the_declared_size() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let real = test_data(40_000);
        let real_id = ObjId::of(&real);
        store.insert_bytes(real_id, Ns::Plain, &real, 1).unwrap();

        // What a hostile manifest can create: a huge declared size with no
        // peer having sent a byte. It must charge nothing, or enforcing the
        // quota wipes every other cached object to make room for a phantom.
        let phantom = ObjId::of(b"declared-but-never-sent");
        store.ensure_sparse(phantom, Ns::Plain, 4 << 30, 2).unwrap();

        assert_eq!(store.total_bytes().unwrap(), 40_000);
        assert_eq!(store.ns_bytes(Ns::Plain).unwrap(), 40_000);
        assert_eq!(store.enforce_quota(1 << 20).unwrap(), 0);
        assert!(store.contains(real_id).unwrap(), "the real cached object survives");
    }

    #[test]
    fn delete_if_unreferenced_leaves_a_pinned_object_alone() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let data = test_data(1_000);
        let id = ObjId::of(&data);
        store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();

        // Stands in for a pin committed after the eviction scan snapshotted
        // this object as unreferenced.
        store.pin(id).unwrap();
        assert!(store.delete_if_unreferenced(id).unwrap().is_none());
        assert!(store.contains(id).unwrap(), "a pinned object is never deleted");

        store.ref_delta(id, -1).unwrap();
        assert!(store.delete_if_unreferenced(id).unwrap().is_some());
        assert!(!store.contains(id).unwrap());
    }

    /// A completed download waiting on its materialize copy is refcount-0 -
    /// LRU's first pick at quota - so the fetch holds it. The hold must beat
    /// both quota passes, count overlapping holders, and release on drop so
    /// the object goes back to being ordinary evictable cache.
    #[test]
    fn an_eviction_hold_keeps_a_complete_object_until_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let data = test_data(50_000);
        let id = ObjId::of(&data);
        store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();
        let newer = test_data(51_000);
        let newer_id = ObjId::of(&newer);
        store.insert_bytes(newer_id, Ns::Plain, &newer, 2).unwrap();

        let hold = store.hold_eviction(id);
        let again = store.hold_eviction(id);
        // Quota 0: everything unheld must go; the held object survives even
        // though it is the LRU candidate.
        store.enforce_quota(0).unwrap();
        assert!(store.contains(id).unwrap(), "a held object outlives the quota pass");
        assert!(!store.contains(newer_id).unwrap(), "unheld cache is still evicted");

        drop(hold);
        store.enforce_quota(0).unwrap();
        assert!(store.contains(id).unwrap(), "still held by the second holder");

        drop(again);
        store.enforce_quota(0).unwrap();
        assert!(!store.contains(id).unwrap(), "released, it is ordinary cache again");
    }

    #[test]
    fn compaction_does_not_revert_pins_taken_while_it_runs() {
        let dir = tempfile::tempdir().unwrap();
        // Tiny slabs so slab 0 seals quickly and compaction has to move its
        // objects into a later one.
        let cfg = StoreConfig { slab_seal_bytes: 8 << 10, ..Default::default() };
        let store = Store::open_with(dir.path(), cfg).unwrap();

        let mut ids = Vec::new();
        for i in 0..40usize {
            let data = test_data(400 + i);
            let id = ObjId::of(&data);
            store.insert_bytes(id, Ns::Plain, &data, i as u64 + 1).unwrap();
            ids.push((id, data));
        }
        assert_ne!(store.open_slab.lock().unwrap().0, 0, "slab 0 must have sealed");
        let victims: Vec<ObjId> = ids
            .iter()
            .map(|(id, _)| *id)
            .filter(|id| matches!(store.required(*id).unwrap().loc, Loc::Slab { slab: 0, .. }))
            .collect();
        assert!(victims.len() > 4, "slab 0 holds several objects, got {}", victims.len());

        // Stands in for register_entry (or the feed pinner) pinning the
        // node's own content while a compaction pass that snapshotted those
        // records is still fsyncing its way through them. Compaction commits
        // one object per fsync, so the pins below land in the middle of it.
        let moved = |id: ObjId| match store.required(id) {
            Ok(r) => !matches!(r.loc, Loc::Slab { slab: 0, .. }),
            Err(_) => false,
        };
        std::thread::scope(|s| {
            s.spawn(|| {
                // Wait for the first move to commit: the snapshot is taken
                // before it, so every pin below lands after the snapshot.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                while !victims.iter().any(|id| moved(*id)) {
                    if std::time::Instant::now() > deadline {
                        break;
                    }
                    std::thread::yield_now();
                }
                for id in &victims {
                    store.pin(*id).unwrap();
                }
            });
            store.compact_slab(0).unwrap();
        });

        for id in &victims {
            let rec = store.required(*id).unwrap();
            assert_eq!(rec.refcount, 1, "compaction reverted the pin on {id}");
            assert!(!matches!(rec.loc, Loc::Slab { slab: 0, .. }), "{id} still in the victim");
        }
        for (id, data) in &ids {
            assert_eq!(&store.read_bytes(*id, 100).unwrap(), data, "object {id}");
        }
    }

    #[test]
    fn ensure_sparse_never_truncates_bytes_a_racer_already_landed() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let data = test_data(200_000);
        let held = 0u64..16_384;
        let (id, size, slice) = slice_for(&data, &[held.clone()]);
        store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
        store.write_slice(id, &[held.clone()], &slice[..], 2).unwrap();

        let data_path = store.sparse_path(id);
        let obao_path = store.obao_path(id);
        let data_before = fs::read(&data_path).unwrap();
        let obao_before = fs::read(&obao_path).unwrap();

        // Readahead and the foreground serve legitimately call ensure_sparse
        // for the same brand-new object. Stand in for the racer that passed
        // the "no record yet" check and was descheduled across a network RTT:
        // drop only the index row, leaving the files as the winner left them.
        {
            let txn = store.db.begin_write().unwrap();
            {
                let mut t = txn.open_table(OBJECTS).unwrap();
                t.remove(id.0.as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }

        store.ensure_sparse(id, Ns::Plain, size, 3).unwrap();

        assert_eq!(fs::read(&data_path).unwrap(), data_before, "verified bytes were truncated");
        assert_eq!(fs::read(&obao_path).unwrap(), obao_before, "the outboard was truncated");
    }

    /// A reader that announces its first read and then blocks until
    /// released, standing in for a decode caught mid-flight by a delete.
    struct GatedReader<'a> {
        inner: &'a [u8],
        started: Option<std::sync::mpsc::Sender<()>>,
        gate: std::sync::mpsc::Receiver<()>,
    }

    impl Read for GatedReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if let Some(tx) = self.started.take() {
                let _ = tx.send(());
                let _ = self.gate.recv();
            }
            self.inner.read(buf)
        }
    }

    /// A delete must never interleave with an in-flight sparse decode: the
    /// detached salvage path decodes with NO claim held, so without the
    /// writer registration a remove + re-ensure_sparse pair could recreate
    /// the record while the decode writes the unlinked files — and the
    /// decode's present-bits commit would then claim groups the fresh file
    /// never received. The delete is skipped and the decode's groups land
    /// on the surviving record.
    #[test]
    fn a_delete_never_interleaves_with_an_inflight_decode() {
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(Store::open(dir.path()).unwrap());

        let data = test_data(200_000);
        let held = 0u64..(GROUP_BYTES * 2);
        let (id, size, slice) = slice_for(&data, &[held.clone()]);
        store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (gate_tx, gate_rx) = std::sync::mpsc::channel();
        let writer = {
            let store = store.clone();
            let ranges = [held.clone()];
            std::thread::spawn(move || {
                let reader =
                    GatedReader { inner: &slice[..], started: Some(started_tx), gate: gate_rx,
                };
                store.write_slice_partial(id, &ranges, reader, 2)
            })
        };

        // The decode is registered and parked on its first read: a remove
        // now must leave the record (and its files) alone.
        started_rx.recv().unwrap();
        store.remove(id).unwrap();
        assert!(store.contains(id).unwrap(), "the record survives an in-flight decode");

        gate_tx.send(()).unwrap();
        let held_bytes = writer.join().unwrap().unwrap();
        assert_eq!(held_bytes, GROUP_BYTES * 2, "the decode committed its groups");
        assert!(!store.present_bits(id).unwrap().is_empty());
        let got = store.read_range(id, 0, GROUP_BYTES, 3).unwrap();
        assert_eq!(got, data[..GROUP_BYTES as usize], "committed bytes verify and read back");

        // With the decode finished, the delete goes through.
        store.remove(id).unwrap();
        assert!(!store.contains(id).unwrap(), "an idle object still deletes");
    }

    #[test]
    fn a_local_present_set_with_many_runs_is_never_emptied() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // A comb-shaped present set: one group held, one absent. Ranges that
        // split per holder can produce this on a multi-gigabyte object, and
        // the wire form costs two entries per run, so it crosses the cap the
        // peer-facing decoder applies. Locally persisted runs are our own
        // writes, so decoding them must not fall back to an empty set: the
        // next write_slice folds into whatever bits() returns and persists
        // it, which would discard every group the object holds.
        let mut bits = GroupBits::new();
        let mut g = 0u64;
        for _ in 0..(crate::bitfield::MAX_WIRE_RUNS / 2 + 1) {
            bits.add(g..g + 1);
            g += 2;
        }
        let wire = bits.to_wire();
        assert!(wire.len() > crate::bitfield::MAX_WIRE_RUNS, "{} entries", wire.len());
        assert_eq!(GroupBits::from_wire(&wire), None, "the peer decoder caps this");

        let id = ObjId::of(b"comb-shaped-present-set");
        let rec = ObjRecord {
            size: g * GROUP_BYTES,
            ns: ns_to_u8(Ns::Plain),
            loc: Loc::Sparse,
            present: wire,
            refcount: 0,
            last_access: 1,
        };
        store.put_record(id, &rec).unwrap();

        assert_eq!(store.present_bits(id).unwrap(), bits, "local bits must round-trip uncapped");
        assert_eq!(store.total_bytes().unwrap(), bits.count() * GROUP_BYTES);
    }

    #[test]
    fn the_reservation_bound_reclaims_stalled_phantoms() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // What a hostile manifest plus a colluding seeder can create: objects
        // declared at the size cap that are fed exactly one group each, so
        // drop_if_unfilled (which only drops records with no groups at all)
        // keeps them and the held-byte quota barely notices. The unfilled
        // part is real disk wherever a set_len'd file is really allocated, so
        // it has to be bounded on its own. Records are written directly here:
        // the point is the accounting, not 256 GiB of files.
        let mut ids = Vec::new();
        for i in 0..4u8 {
            let id = ObjId::of(&[b'p', i]);
            store
                .put_record(
                    id,
                    &ObjRecord {
                        size: MAX_OBJECT_BYTES,
                        ns: ns_to_u8(Ns::Plain),
                        loc: Loc::Sparse,
                        present: GroupBits::complete(GROUP_BYTES).to_wire(),
                        refcount: 0,
                        last_access: i as u64 + 1,
                    },
                )
                .unwrap();
            ids.push(id);
        }
        let real = test_data(40_000);
        let real_id = ObjId::of(&real);
        store.insert_bytes(real_id, Ns::Plain, &real, 99).unwrap();

        // Held bytes are nowhere near the quota, so the LRU pass alone would
        // never run.
        assert!(store.total_bytes().unwrap() < 1 << 20);
        store.enforce_quota(8 << 30).unwrap();

        let left = ids.iter().filter(|id| store.contains(**id).unwrap()).count() as u64;
        assert!(left * MAX_OBJECT_BYTES <= MAX_RESERVED_BYTES, "{left} reservations left");
        assert!(!store.contains(ids[0]).unwrap(), "the LRU phantom goes first");
        assert!(store.contains(real_id).unwrap(), "the real cached object survives");
    }
}
