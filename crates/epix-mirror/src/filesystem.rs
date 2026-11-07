use crate::{FileInfo, CHUNK, MAX_FILE};
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub fn safe_path(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 900,
        "Invalid snapshot path"
    );
    ensure!(
        !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*')),
        "Non-portable snapshot path"
    );
    for part in value.split('/') {
        ensure!(
            !part.is_empty() && !part.starts_with('.') && !part.ends_with(['.', ' ']),
            "Unsafe snapshot path"
        );
        let device = part
            .split('.')
            .next()
            .unwrap_or("")
            .trim_end_matches([' ', '.'])
            .to_ascii_uppercase();
        let numbered = device
            .strip_prefix("COM")
            .or_else(|| device.strip_prefix("LPT"));
        ensure!(
            !["CON", "PRN", "AUX", "NUL"].contains(&device.as_str())
                && !numbered.is_some_and(|suffix| (suffix.len() == 1
                    && suffix.as_bytes()[0].is_ascii_digit())
                    || ["¹", "²", "³"].contains(&suffix)),
            "Windows device path is not allowed"
        );
    }
    Ok(())
}
fn plain(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return false;
        }
    }
    !metadata.file_type().is_symlink()
}
pub fn regular(root: &Path, relative: &str) -> Result<PathBuf> {
    safe_path(relative)?;
    let mut path = root.to_path_buf();
    for part in relative.split('/') {
        path.push(part);
        ensure!(
            plain(&fs::symlink_metadata(&path)?),
            "Symlink/reparse point is not allowed"
        );
    }
    ensure!(path.is_file(), "Missing regular file");
    Ok(path)
}
#[cfg(unix)]
pub fn open_regular(root: &Path, relative: &str) -> Result<File> {
    use rustix::fs::{open, openat, Mode, OFlags};
    safe_path(relative)?;
    let mut directory = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut parts = relative.split('/').peekable();
    while let Some(part) = parts.next() {
        let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
        let descriptor = openat(
            &directory,
            part,
            if parts.peek().is_some() {
                flags | OFlags::DIRECTORY
            } else {
                flags
            },
            Mode::empty(),
        )?;
        if parts.peek().is_none() {
            let file = File::from(descriptor);
            ensure!(file.metadata()?.is_file(), "Not a regular file");
            return Ok(file);
        }
        directory = descriptor;
    }
    anyhow::bail!("Missing regular file")
}
#[cfg(windows)]
pub fn open_regular(root: &Path, relative: &str) -> Result<File> {
    safe_path(relative)?;
    Ok(epix_fs::open_regular_file_beneath(
        root,
        Path::new(relative),
    )?)
}
#[cfg(not(any(unix, windows)))]
pub fn open_regular(root: &Path, relative: &str) -> Result<File> {
    Ok(File::open(regular(root, relative)?)?)
}

pub(crate) fn read_bounded(mut source: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    source.by_ref().take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "Metadata exceeds configured limit"
    );
    Ok(bytes)
}
pub(crate) fn digest_stream(
    source: &mut impl Read,
    mut target: Option<&mut dyn Write>,
) -> Result<FileInfo> {
    let mut digest = Sha256::new();
    let mut length = 0;
    let mut buffer = vec![0; CHUNK];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        length += count as u64;
        ensure!(length <= MAX_FILE, "File exceeds 8 GiB");
        digest.update(&buffer[..count]);
        if let Some(writer) = target.as_mut() {
            writer.write_all(&buffer[..count])?;
        }
    }
    Ok(FileInfo {
        size: length,
        sha256: hex::encode(digest.finalize()),
    })
}
pub(crate) fn ensure_space(directory: &Path, required: u64) -> Result<()> {
    #[cfg(unix)]
    let free = {
        let stat = rustix::fs::statvfs(directory)?;
        stat.f_bavail.saturating_mul(stat.f_frsize)
    };
    #[cfg(windows)]
    let free = {
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        let path = epix_fs::verbatim_wide_null(directory)?;
        let mut available = 0;
        // The API writes one u64 to a live out pointer; the terminated path is
        // retained for the call and unused output pointers are explicitly null.
        let success = unsafe {
            GetDiskFreeSpaceExW(
                path.as_ptr(),
                &mut available,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        ensure!(success != 0, "Could not determine free disk space");
        available
    };
    #[cfg(not(any(unix, windows)))]
    let free = 0u64;
    ensure!(
        free >= required.saturating_add(64 * 1024 * 1024),
        "Not enough free disk space for this snapshot"
    );
    Ok(())
}

pub(crate) struct Pending {
    temporary: tempfile::TempDir,
    output: PathBuf,
}
impl Pending {
    pub fn new(output: &Path) -> Result<Self> {
        let output = std::path::absolute(output)?;
        ensure!(
            fs::symlink_metadata(&output).is_err(),
            "Output already exists; use a new immutable snapshot directory"
        );
        let parent = output.parent().context("Output has no parent")?;
        fs::create_dir_all(parent)?;
        let temporary = tempfile::Builder::new()
            .prefix(".epix-mirror-")
            .tempdir_in(parent)?;
        Ok(Self { temporary, output })
    }
    pub fn path(&self) -> &Path {
        self.temporary.path()
    }
    pub fn commit(self) -> Result<()> {
        #[cfg(unix)]
        {
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                self.path(),
                rustix::fs::CWD,
                &self.output,
                rustix::fs::RenameFlags::NOREPLACE,
            )?;
            File::open(self.output.parent().context("Missing output parent")?)?.sync_all()?;
        }
        #[cfg(windows)]
        {
            epix_fs::install_file_write_through(self.path(), &self.output)?;
        }
        #[cfg(not(any(unix, windows)))]
        {
            anyhow::bail!("Atomic snapshot publication is unsupported on this platform");
        }
        Ok(())
    }
}

pub(crate) fn walk(root: &Path) -> Result<Vec<String>> {
    let mut pending = vec![PathBuf::new()];
    let mut files = Vec::new();
    let mut count = 0;
    while let Some(relative) = pending.pop() {
        for entry in fs::read_dir(root.join(&relative))? {
            let entry = entry?;
            count += 1;
            ensure!(count <= crate::MAX_FILES * 2, "Too many source paths");
            let path = relative.join(entry.file_name());
            let name = path
                .to_str()
                .context("Source path is not UTF-8")?
                .replace('\\', "/");
            safe_path(&name)?;
            ensure!(
                !name.split('/').any(|p| p.eq_ignore_ascii_case("private")),
                "Private directories must not be staged"
            );
            let metadata = fs::symlink_metadata(entry.path())?;
            ensure!(plain(&metadata), "Source contains a symlink/reparse point");
            if metadata.is_dir() {
                pending.push(path);
            } else {
                ensure!(metadata.is_file(), "Source contains a non-regular file");
                files.push(name);
                ensure!(files.len() <= crate::MAX_FILES, "Too many source files");
            }
        }
    }
    files.sort();
    Ok(files)
}
