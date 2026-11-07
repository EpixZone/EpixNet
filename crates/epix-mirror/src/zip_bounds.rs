//! Bound node ZIP metadata before the general ZIP parser allocates its index.
//! The node exporter writes one disk, no prefix, and no archive comment.
use anyhow::{ensure, Context, Result};
use std::io::{Read, Seek, SeekFrom};

fn u16_at(bytes: &[u8], offset: usize) -> u64 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()).into()
}
fn u32_at(bytes: &[u8], offset: usize) -> u64 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()).into()
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn read_at<const N: usize>(reader: &mut (impl Read + Seek), offset: u64) -> Result<[u8; N]> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut bytes = [0; N];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}
struct Directory {
    entries: u64,
    size: u64,
    offset: u64,
    end: u64,
}
fn directory(reader: &mut (impl Read + Seek), length: u64) -> Result<Directory> {
    let end = length.checked_sub(22).context("Truncated ZIP footer")?;
    let footer = read_at::<22>(reader, end)?;
    ensure!(
        &footer[..4] == b"PK\x05\x06" && u16_at(&footer, 20) == 0,
        "Expected a node ZIP without trailing bytes or archive comments"
    );
    ensure!(
        u16_at(&footer, 4) == 0 && u16_at(&footer, 6) == 0,
        "Multi-disk ZIP is not supported"
    );
    if end >= 20 {
        let locator = read_at::<20>(reader, end - 20)?;
        if &locator[..4] == b"PK\x06\x07" {
            return zip64_directory(reader, &locator, end - 20);
        }
    }
    ensure!(
        u16_at(&footer, 8) == u16_at(&footer, 10),
        "ZIP count mismatch"
    );
    Ok(Directory {
        entries: u16_at(&footer, 10),
        size: u32_at(&footer, 12),
        offset: u32_at(&footer, 16),
        end,
    })
}
fn zip64_directory(
    reader: &mut (impl Read + Seek),
    locator: &[u8; 20],
    locator_offset: u64,
) -> Result<Directory> {
    ensure!(
        u32_at(locator, 4) == 0 && u32_at(locator, 16) == 1,
        "Multi-disk ZIP64 is not supported"
    );
    let end = u64_at(locator, 8);
    let footer = read_at::<56>(reader, end)?;
    let size = u64_at(&footer, 4);
    ensure!(
        &footer[..4] == b"PK\x06\x06"
            && (44..=65_536).contains(&size)
            && end.checked_add(12 + size) == Some(locator_offset),
        "Invalid bounded ZIP64 footer"
    );
    ensure!(
        u32_at(&footer, 16) == 0
            && u32_at(&footer, 20) == 0
            && u64_at(&footer, 24) == u64_at(&footer, 32),
        "Invalid ZIP64 disk or count"
    );
    Ok(Directory {
        entries: u64_at(&footer, 32),
        size: u64_at(&footer, 40),
        offset: u64_at(&footer, 48),
        end,
    })
}
pub(crate) fn check(reader: &mut (impl Read + Seek)) -> Result<()> {
    let length = reader.seek(SeekFrom::End(0))?;
    ensure!(length <= crate::MAX_ARCHIVE, "ZIP exceeds archive limit");
    let directory = directory(reader, length)?;
    ensure!(directory.entries <= 65_536, "Too many ZIP entries");
    ensure!(
        directory.size <= 64 * 1024 * 1024
            && directory.offset.checked_add(directory.size) == Some(directory.end),
        "Invalid or oversized ZIP central directory"
    );
    let mut offset = directory.offset;
    for _ in 0..directory.entries {
        ensure!(offset + 46 <= directory.end, "Truncated ZIP index");
        let header = read_at::<46>(reader, offset)?;
        ensure!(&header[..4] == b"PK\x01\x02", "Invalid ZIP index entry");
        let name = u16_at(&header, 28);
        ensure!(name <= 900, "ZIP path exceeds limit");
        offset += 46 + name + u16_at(&header, 30) + u16_at(&header, 32);
        ensure!(offset <= directory.end, "ZIP index exceeds declared span");
    }
    ensure!(offset == directory.end, "ZIP index count differs from span");
    reader.seek(SeekFrom::Start(0))?;
    Ok(())
}
