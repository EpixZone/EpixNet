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

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Mutex;

use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::bitfield::{group_count, groups_for_bytes, GroupBits, GROUP_BYTES};
use crate::verified::{self, outboard_size, OutboardBytes};
use crate::{Ns, ObjId};

const OBJECTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("objects");
const SLABS: TableDefinition<u32, &[u8]> = TableDefinition::new("slabs");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");

const SCHEMA_VERSION: u64 = 1;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Loc {
    /// Its own (possibly partial) file pair under `sparse/`.
    Sparse,
    /// A byte range of a slab packfile; always complete.
    Slab { slab: u32, off: u64 },
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
            Loc::Slab { .. } => GroupBits::complete(self.size),
            Loc::Sparse => bits_from_local(&self.present),
        }
    }

    fn is_complete(&self) -> bool {
        matches!(self.loc, Loc::Slab { .. }) || self.bits().is_complete(self.size)
    }

    /// Bytes actually held on disk. The quota charges this and never
    /// `size`: `size` is a declared value from an untrusted manifest, so
    /// a record for an object nobody ever sent must charge nothing.
    fn held(&self) -> u64 {
        match self.loc {
            Loc::Slab { .. } => self.size,
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
#[derive(Clone, Copy, Debug)]
pub struct StoreConfig {
    /// A slab is sealed once it reaches this size and a new one opens.
    pub slab_seal_bytes: u64,
    /// A sealed slab with more than this fraction dead (in 1/256ths) is
    /// compacted on the next eviction pass.
    pub compact_dead_num: u64,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self { slab_seal_bytes: 1 << 30, compact_dead_num: 128 } // 1 GiB, 50%
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
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        Self::open_with(root, StoreConfig::default())
    }

    pub fn open_with(root: impl Into<PathBuf>, cfg: StoreConfig) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("sparse"))?;
        fs::create_dir_all(root.join("slabs"))?;
        let db = Database::create(root.join("index.redb")).map_err(db_err)?;

        let txn = db.begin_write().map_err(db_err)?;
        let open_slab;
        // (slab id, tracked len) for every slab, so torn appends that left
        // a slab file longer than its indexed len can be truncated back.
        let mut slab_lens: Vec<(u32, u64)> = Vec::new();
        {
            let mut meta = txn.open_table(META).map_err(db_err)?;
            let schema = meta.get("schema").map_err(db_err)?.map(|g| g.value());
            match schema {
                None => {
                    meta.insert("schema", SCHEMA_VERSION).map_err(db_err)?;
                }
                Some(SCHEMA_VERSION) => {}
                Some(v) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("store schema v{v}, this build speaks v{SCHEMA_VERSION}"),
                    ))
                }
            }
            let mut slabs = txn.open_table(SLABS).map_err(db_err)?;
            let newest_open = {
                let mut found = None;
                for row in slabs.iter().map_err(db_err)? {
                    let (k, v) = row.map_err(db_err)?;
                    let m: SlabMeta = dec(v.value())?;
                    slab_lens.push((k.value(), m.len));
                    if !m.sealed {
                        found = Some((k.value(), m.len));
                    }
                }
                found
            };
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
            // Make sure OBJECTS exists even in an empty store.
            txn.open_table(OBJECTS).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;

        // Reconcile physical slab files with the committed lengths. A write
        // that synced bytes but crashed before the index txn committed (or a
        // torn append) leaves the file longer than its tracked len; without
        // this every later O_APPEND insert is recorded at the tracked offset
        // but physically lands past the drift, so reads mis-address. Shrink
        // any over-long slab back to its tracked len. A file shorter than
        // its tracked len means lost committed bytes, so leave it be and let
        // reads fail loudly instead of silently extending with zeros.
        for (slab, len) in slab_lens {
            let path = root.join("slabs").join(format!("{slab}.slab"));
            match fs::metadata(&path) {
                Ok(m) if m.len() > len => {
                    let f = OpenOptions::new().write(true).open(&path)?;
                    f.set_len(len)?;
                    f.sync_all()?;
                }
                _ => {}
            }
        }

        Ok(Self {
            root,
            db,
            cfg,
            open_slab: Mutex::new(open_slab),
            sparse_writers: Mutex::new(HashMap::new()),
        })
    }

    fn sparse_path(&self, id: ObjId) -> PathBuf {
        self.root.join("sparse").join(id.to_string())
    }

    fn obao_path(&self, id: ObjId) -> PathBuf {
        self.root.join("sparse").join(format!("{id}.obao"))
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
                    return Err(io::Error::new(io::ErrorKind::NotFound, format!("object {id}")))
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
        if let Some(rec) = self.get_record(id)? {
            if rec.last_access < now {
                self.touch(id, now)?;
            }
            return Ok(false);
        }

        let mut open = self.open_slab.lock().expect("slab lock");
        let (slab, off) = (open.0, open.1);
        let mut f = OpenOptions::new().create(true).append(true).open(self.slab_path(slab))?;
        if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_data()) {
            // Torn append (e.g. disk full): shrink the slab back to the
            // pre-write offset so the next insert is not mis-addressed.
            let _ = f.set_len(off);
            let _ = f.sync_data();
            return Err(e);
        }
        let new_len = off + bytes.len() as u64;

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
            let rec = ObjRecord {
                size: bytes.len() as u64,
                ns: ns_to_u8(ns),
                loc: Loc::Slab { slab, off },
                present: Vec::new(),
                refcount: 0,
                last_access: now,
            };
            objects.insert(id.0.as_slice(), enc(&rec).as_slice()).map_err(db_err)?;

            let mut slabs = txn.open_table(SLABS).map_err(db_err)?;
            let mut m: SlabMeta = slabs
                .get(slab)
                .map_err(db_err)?
                .map(|g| dec(g.value()))
                .transpose()?
                .unwrap_or_default();
            m.len = new_len;
            if m.len >= self.cfg.slab_seal_bytes {
                m.sealed = true;
                slabs.insert(slab + 1, enc(&SlabMeta::default()).as_slice()).map_err(db_err)?;
                *open = (slab + 1, 0);
            } else {
                *open = (slab, new_len);
            }
            slabs.insert(slab, enc(&m).as_slice()).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        Ok(true)
    }

    /// Adopt a COMPLETE file already on disk (the migration pass: existing
    /// xite files become EDX objects with no re-download and no second
    /// copy). The data is hard-linked into the store when possible (one
    /// physical copy, two names) and copied only as a fallback; the
    /// outboard is computed by streaming the file. Returns false if the
    /// object is already in the store.
    ///
    /// If the original file is later edited in place, the linked object's
    /// bytes change under us — that is caught by validated serving and
    /// [`Self::revalidate`], never served silently. Re-signing a xite
    /// re-adopts under the file's new id.
    pub fn adopt_file(
        &self,
        id: ObjId,
        ns: Ns,
        path: &std::path::Path,
        now: u64,
    ) -> io::Result<bool> {
        if let Some(rec) = self.get_record(id)? {
            if rec.last_access < now {
                self.touch(id, now)?;
            }
            return Ok(false);
        }
        let size = fs::metadata(path)?.len();
        let dst = self.sparse_path(id);
        let _ = fs::remove_file(&dst);
        if fs::hard_link(path, &dst).is_err() {
            fs::copy(path, &dst)?;
        }
        let ob = OutboardBytes::from_reader(io::BufReader::new(File::open(&dst)?), size)?;
        if ob.root != id {
            let _ = fs::remove_file(&dst);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} does not hash to {id}", path.display()),
            ));
        }
        fs::write(self.obao_path(id), &ob.data)?;
        self.put_record(
            id,
            &ObjRecord {
                size,
                ns: ns_to_u8(ns),
                loc: Loc::Sparse,
                present: GroupBits::complete(size).to_wire(),
                refcount: 0,
                last_access: now,
            },
        )?;
        Ok(true)
    }

    /// Create the sparse file pair for an object we are about to fetch.
    /// Idempotent: an existing record (sparse or slab) is left alone.
    pub fn ensure_sparse(&self, id: ObjId, ns: Ns, size: u64, now: u64) -> io::Result<()> {
        if size > MAX_OBJECT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("declared size {size} exceeds the {MAX_OBJECT_BYTES} byte object cap"),
            ));
        }
        if self.get_record(id)?.is_some() {
            return Ok(());
        }
        // Never truncate: readahead and the foreground serve legitimately
        // call this for the same brand-new object, and the racer that gets
        // here second must not throw away bytes the first one has already
        // verified into the file.
        ensure_len(&self.sparse_path(id), size)?;
        ensure_len(&self.obao_path(id), outboard_size(size))?;
        // Claim the record with an insert-if-absent inside one write txn,
        // for the same reason: a blind put would clobber the present set a
        // racer committed between the check above and here.
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
            let taken = objects.get(id.0.as_slice()).map_err(db_err)?.is_some();
            if !taken {
                let rec = ObjRecord {
                    size,
                    ns: ns_to_u8(ns),
                    loc: Loc::Sparse,
                    present: Vec::new(),
                    refcount: 0,
                    last_access: now,
                };
                objects.insert(id.0.as_slice(), enc(&rec).as_slice()).map_err(db_err)?;
            }
        }
        txn.commit().map_err(db_err)
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
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "object is slab-complete"));
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
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "object is slab-complete"));
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
        let mut tracked = TrackWrites { inner: data, written: Vec::new() };
        let res = verified::decode_slice_into(encoded, id, rec.size, byte_ranges, &mut tracked, &mut obao);
        let TrackWrites { inner: data, written } = tracked;
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
            Loc::Sparse => {
                let data = File::open(self.sparse_path(id))?;
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
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("{id} incomplete")));
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
            Loc::Sparse => fs::read(self.sparse_path(id))?,
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
                let f = File::open(self.sparse_path(id))?;
                let mut buf = vec![0u8; (end - start) as usize];
                positioned_io::ReadAt::read_exact_at(&f, start, &mut buf)?;
                buf
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

    /// Drop an object unconditionally (tools/tests; normal flow evicts) —
    /// unless a sparse decode is mid-flight on it, in which case the
    /// delete is skipped: the writer's verified bytes matter more than the
    /// cleanup, which the next pass (or `drop_if_unfilled`'s next caller)
    /// can redo.
    pub fn remove(&self, id: ObjId) -> io::Result<()> {
        let Some(rec) = self.get_record(id)? else { return Ok(()) };
        self.delete_object(id, &rec)?;
        self.compact_if_worthwhile()
    }

    fn delete_object(&self, id: ObjId, rec: &ObjRecord) -> io::Result<()> {
        // Held across the record delete AND the unlink: a sparse decode
        // registering meanwhile blocks on this lock and then finds the
        // record gone (its decode aborts) instead of opening files this
        // delete is about to unlink; one already registered wins, and the
        // delete is skipped (see `sparse_writers`).
        let writers = self.sparse_writers.lock().expect("sparse_writers");
        if writers.contains_key(&id) {
            return Ok(());
        }
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut objects = txn.open_table(OBJECTS).map_err(db_err)?;
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
        }
        txn.commit().map_err(db_err)?;
        if let Loc::Sparse = rec.loc {
            let _ = fs::remove_file(self.sparse_path(id));
            let _ = fs::remove_file(self.obao_path(id));
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
        // Held across the delete + unlink, same as `delete_object`.
        let writers = self.sparse_writers.lock().expect("sparse_writers");
        if writers.contains_key(&id) {
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
                Some(rec) if rec.refcount == 0 => {
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
                    deleted = Some(rec);
                }
                _ => deleted = None,
            }
        }
        txn.commit().map_err(db_err)?;
        if let Some(rec) = &deleted {
            if let Loc::Sparse = rec.loc {
                let _ = fs::remove_file(self.sparse_path(id));
                let _ = fs::remove_file(self.obao_path(id));
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
                if rec.refcount == 0 {
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
            let Loc::Slab { off, .. } = rec.loc else { continue };
            let was = Loc::Slab { slab: victim, off };
            let bytes = self.read_slab(victim, off, rec.size)?;

            let mut open = self.open_slab.lock().expect("slab lock");
            let (slab, new_off) = (open.0, open.1);
            let mut f =
                OpenOptions::new().create(true).append(true).open(self.slab_path(slab))?;
            if let Err(e) = f.write_all(&bytes).and_then(|()| f.sync_data()) {
                // Torn append: shrink the slab back to the pre-write offset
                // so the next insert is not mis-addressed.
                let _ = f.set_len(new_off);
                let _ = f.sync_data();
                return Err(e);
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
                    *open = (slab + 1, 0);
                } else {
                    *open = (slab, new_len);
                }
                slabs.insert(slab, enc(&m).as_slice()).map_err(db_err)?;
            }
            txn.commit().map_err(db_err)?;
        }

        // All live objects moved; drop the victim slab.
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut slabs = txn.open_table(SLABS).map_err(db_err)?;
            slabs.remove(victim).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        let _ = fs::remove_file(self.slab_path(victim));
        Ok(())
    }

    /// Re-verify a sparse object's held bytes against its outboard and
    /// shrink the present set to what actually verifies (used after a
    /// crash or a failed serve — distrust, don't repair).
    pub fn revalidate(&self, id: ObjId) -> io::Result<GroupBits> {
        let rec = self.required(id)?;
        let Loc::Sparse = rec.loc else {
            return Ok(GroupBits::complete(rec.size));
        };
        let claimed = rec.bits();
        if claimed.is_empty() {
            return Ok(claimed);
        }
        let obao_bytes = fs::read(self.obao_path(id))?;
        let ob = OutboardBytes { root: id, size: rec.size, data: obao_bytes };
        let data = File::open(self.sparse_path(id))?;
        let valid = verified::valid_ranges(&ob, &data, &claimed.to_chunk_ranges_clamped(rec.size))?;

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

/// Create `path` if it is missing and grow it to `len`, never shrinking it.
/// `File::create` would truncate, which is wrong for a file another task may
/// already have written verified bytes into.
fn ensure_len(path: &std::path::Path, len: u64) -> io::Result<()> {
    let f = OpenOptions::new().create(true).write(true).truncate(false).open(path)?;
    if f.metadata()?.len() < len {
        f.set_len(len)?;
    }
    Ok(())
}

fn ns_to_u8(ns: Ns) -> u8 {
    match ns {
        Ns::Plain => 0,
        Ns::Shard => 1,
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
            Meddler { store: &store, id, ranges: &later_ranges, slice: &later_slice, fired: false };
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

    #[test]
    fn compaction_does_not_revert_pins_taken_while_it_runs() {
        let dir = tempfile::tempdir().unwrap();
        // Tiny slabs so slab 0 seals quickly and compaction has to move its
        // objects into a later one.
        let cfg = StoreConfig { slab_seal_bytes: 8 << 10, compact_dead_num: 128 };
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
                    GatedReader { inner: &slice[..], started: Some(started_tx), gate: gate_rx };
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
