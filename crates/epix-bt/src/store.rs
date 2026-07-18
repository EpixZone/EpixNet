//! Hash-verified, sparse on-disk store for the one file being streamed.
//!
//! The engine streams a single file out of a torrent (the largest - the video).
//! We back it with a sparse file of exactly that length: as pieces overlapping
//! the file arrive and verify, their bytes are written at the right offset, and
//! a per-piece `have` bitfield records which pieces are present so the engine
//! never refetches. Reads for the player come straight out of this file.
//!
//! Nothing is written until its piece's SHA-1 has been checked against the
//! metainfo (the engine does that before calling [`PieceStore::write_at`]), so
//! the file only ever holds verified bytes. The `have` bitfield is in-memory and
//! session-scoped: a fresh session refetches on demand rather than trusting
//! leftover disk bytes, which keeps correctness simple (every served byte was
//! verified this run).

use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store io: {0}")]
    Io(#[from] std::io::Error),
}

/// A sparse file plus a have-bitfield keyed by (global) piece index.
pub struct PieceStore {
    /// Positioned reads/writes are serialized through this lock - a tokio
    /// `File` cursor is shared, so concurrent seeks would race otherwise.
    file: Mutex<File>,
    len: u64,
    have: Vec<AtomicBool>,
    path: PathBuf,
}

impl PieceStore {
    /// Open (creating + truncating) the backing file at `path`, sized to `len`,
    /// with room to track `piece_count` pieces. Parent dirs must already exist.
    pub async fn open(path: &Path, len: u64, piece_count: usize) -> Result<PieceStore, StoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .await?;
        // Sparse-allocate: set_len makes a hole, no bytes actually written.
        file.set_len(len).await?;
        let have = (0..piece_count).map(|_| AtomicBool::new(false)).collect();
        Ok(PieceStore { file: Mutex::new(file), len, have, path: path.to_path_buf() })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether piece `index` has been verified and written this session.
    pub fn has(&self, index: usize) -> bool {
        self.have.get(index).map(|b| b.load(Ordering::Acquire)).unwrap_or(false)
    }

    /// Record that piece `index` is now present. Call only after its bytes have
    /// been verified and written.
    pub fn mark(&self, index: usize) {
        if let Some(b) = self.have.get(index) {
            b.store(true, Ordering::Release);
        }
    }

    /// Write `data` at byte `offset` into the file. `offset + data.len()` must
    /// be within `len` (the engine clips piece bytes to the file's span first).
    pub async fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), StoreError> {
        let mut f = self.file.lock().await;
        f.seek(SeekFrom::Start(offset)).await?;
        f.write_all(data).await?;
        Ok(())
    }

    /// Read `len` bytes starting at `offset`, clipped to the file end.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>, StoreError> {
        let avail = self.len.saturating_sub(offset).min(len as u64) as usize;
        let mut buf = vec![0u8; avail];
        if avail == 0 {
            return Ok(buf);
        }
        let mut f = self.file.lock().await;
        f.seek(SeekFrom::Start(offset)).await?;
        f.read_exact(&mut buf).await?;
        Ok(buf)
    }

    /// The backing file path (for cleanup / diagnostics).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_then_read_roundtrips_and_have_tracks() {
        let dir = std::env::temp_dir().join(format!("epixbt-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("clip.mp4");

        let store = PieceStore::open(&path, 10, 3).await.unwrap();
        assert_eq!(store.len(), 10);
        assert!(!store.has(0));

        store.write_at(2, b"hello").await.unwrap();
        store.mark(1);
        assert!(store.has(1));
        assert!(!store.has(0));

        // Read across the written region; the sparse hole reads back as zeros.
        let got = store.read_at(0, 8).await.unwrap();
        assert_eq!(&got, b"\0\0hello\0");

        // Read clipped at EOF returns only the available bytes.
        let tail = store.read_at(8, 10).await.unwrap();
        assert_eq!(tail.len(), 2);

        std::fs::remove_dir_all(&dir).ok();
    }
}
