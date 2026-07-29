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

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Mutex;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::bitfield::{groups_for_bytes, GroupBits};
use crate::verified::{self, outboard_size, OutboardBytes};
use crate::{Ns, ObjId};

const OBJECTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("objects");
const SLABS: TableDefinition<u32, &[u8]> = TableDefinition::new("slabs");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");

const SCHEMA_VERSION: u64 = 1;

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

impl ObjRecord {
    fn bits(&self) -> GroupBits {
        match self.loc {
            Loc::Slab { .. } => GroupBits::complete(self.size),
            Loc::Sparse => GroupBits::from_wire(&self.present).unwrap_or_default(),
        }
    }

    fn is_complete(&self) -> bool {
        matches!(self.loc, Loc::Slab { .. }) || self.bits().is_complete(self.size)
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

        Ok(Self { root, db, cfg, open_slab: Mutex::new(open_slab) })
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
        if let Some(mut rec) = self.get_record(id)? {
            rec.last_access = rec.last_access.max(now);
            self.put_record(id, &rec)?;
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
        if let Some(mut rec) = self.get_record(id)? {
            rec.last_access = rec.last_access.max(now);
            self.put_record(id, &rec)?;
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
        if self.get_record(id)?.is_some() {
            return Ok(());
        }
        let data = File::create(self.sparse_path(id))?;
        data.set_len(size)?;
        let obao = File::create(self.obao_path(id))?;
        obao.set_len(outboard_size(size))?;
        self.put_record(
            id,
            &ObjRecord {
                size,
                ns: ns_to_u8(ns),
                loc: Loc::Sparse,
                present: Vec::new(),
                refcount: 0,
                last_access: now,
            },
        )
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
        let mut rec = self.required(id)?;
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

        let mut bits = rec.bits();
        for r in byte_ranges {
            bits.add(groups_for_bytes(r));
        }
        rec.present = bits.to_wire();
        rec.last_access = rec.last_access.max(now);
        self.put_record(id, &rec)
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
        let mut rec = self.required(id)?;
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
        rec.last_access = rec.last_access.max(now);
        self.put_record(id, &rec)
    }

    /// Read a COMPLETE object's bytes (verified for slab objects by the
    /// caller's own use; sparse completeness comes from verified writes).
    pub fn read_bytes(&self, id: ObjId, now: u64) -> io::Result<Vec<u8>> {
        let mut rec = self.required(id)?;
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
        rec.last_access = rec.last_access.max(now);
        self.put_record(id, &rec)?;
        Ok(bytes)
    }

    /// Read the byte range `[start, start+len)` of an object, clamped to its
    /// size. Requires the covering chunk groups to be present (verified on
    /// write); errors `NotFound` otherwise. For a sparse object this reads
    /// only the range from disk, so a media seek never materializes the whole
    /// file.
    pub fn read_range(&self, id: ObjId, start: u64, len: u64, now: u64) -> io::Result<Vec<u8>> {
        let mut rec = self.required(id)?;
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
        rec.last_access = rec.last_access.max(now);
        self.put_record(id, &rec)?;
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
        let mut rec = self.required(id)?;
        rec.refcount = (rec.refcount as i64 + delta).max(0) as u32;
        self.put_record(id, &rec)?;
        Ok(rec.refcount)
    }

    /// Drop an object unconditionally (tools/tests; normal flow evicts).
    pub fn remove(&self, id: ObjId) -> io::Result<()> {
        let Some(rec) = self.get_record(id)? else { return Ok(()) };
        self.delete_object(id, &rec)?;
        self.compact_if_worthwhile()
    }

    fn delete_object(&self, id: ObjId, rec: &ObjRecord) -> io::Result<()> {
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

    /// Total logical bytes of all stored objects (the quota basis).
    pub fn total_bytes(&self) -> io::Result<u64> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(OBJECTS).map_err(db_err)?;
        let mut total = 0u64;
        for row in table.iter().map_err(db_err)? {
            let (_, v) = row.map_err(db_err)?;
            let rec: ObjRecord = dec(v.value())?;
            total = total.saturating_add(rec.size);
        }
        Ok(total)
    }

    /// Total logical bytes of all held objects in one namespace. Used as a
    /// volunteer's soft budget gate (stop pulling shards once `Ns::Shard`
    /// reaches its donated quota). Reads only `(ns, size)` per record - no
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
                total = total.saturating_add(rec.size);
            }
        }
        Ok(total)
    }

    /// Pin an object so eviction never reclaims it (the node's own content).
    /// Idempotent: raises refcount to at least 1, never higher, so repeated
    /// registration across restarts does not inflate it.
    pub fn pin(&self, id: ObjId) -> io::Result<()> {
        let mut rec = self.required(id)?;
        if rec.refcount == 0 {
            rec.refcount = 1;
            self.put_record(id, &rec)?;
        }
        Ok(())
    }

    /// Enforce a byte quota: if the store exceeds `quota`, evict LRU
    /// refcount-0 (unpinned, i.e. cached-from-others) objects down to it.
    /// Returns bytes freed. Pinned own content is never touched.
    pub fn enforce_quota(&self, quota: u64) -> io::Result<u64> {
        let total = self.total_bytes()?;
        if total <= quota {
            return Ok(0);
        }
        self.evict_lru(total - quota)
    }

    /// Evict least-recently-used refcount-0 objects until at least
    /// `bytes_needed` are freed (or candidates run out). Returns freed
    /// bytes. Sealed slabs past the dead threshold are compacted.
    pub fn evict_lru(&self, bytes_needed: u64) -> io::Result<u64> {
        let mut candidates: Vec<(u64, ObjId, u64)> = Vec::new();
        {
            let txn = self.db.begin_read().map_err(db_err)?;
            let table = txn.open_table(OBJECTS).map_err(db_err)?;
            for row in table.iter().map_err(db_err)? {
                let (k, v) = row.map_err(db_err)?;
                let rec: ObjRecord = dec(v.value())?;
                if rec.refcount == 0 {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(k.value());
                    candidates.push((rec.last_access, ObjId(id), rec.size));
                }
            }
        }
        candidates.sort();
        let mut freed = 0u64;
        for (_, id, size) in candidates {
            if freed >= bytes_needed {
                break;
            }
            if let Some(rec) = self.get_record(id)? {
                self.delete_object(id, &rec)?;
                freed += size;
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

        for (id, mut rec) in live {
            let Loc::Slab { off, .. } = rec.loc else { continue };
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
                rec.loc = Loc::Slab { slab, off: new_off };
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
        let mut rec = self.required(id)?;
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
        rec.present = kept.to_wire();
        self.put_record(id, &rec)?;
        Ok(kept)
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

fn ns_to_u8(ns: Ns) -> u8 {
    match ns {
        Ns::Plain => 0,
        Ns::Shard => 1,
    }
}
