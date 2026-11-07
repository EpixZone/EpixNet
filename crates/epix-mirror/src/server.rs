use crate::{filesystem::digest_stream, fresh, open_regular, validate, Catalog, FileInfo, CHUNK};
use anyhow::{ensure, Context, Result};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime},
};

#[derive(PartialEq, Eq)]
struct Stamp {
    size: u64,
    modified: SystemTime,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64),
}
fn stamp(file: &File) -> Result<Stamp> {
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "Snapshot member is not a regular file");
    Ok(Stamp {
        size: metadata.len(),
        modified: metadata.modified()?,
        #[cfg(unix)]
        identity: {
            use std::os::unix::fs::MetadataExt;
            (
                metadata.dev(),
                metadata.ino(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        },
    })
}
/// Validate and rewind one descriptor. Never reopen the pathname after checking
/// bytes. Operator in-place writes after validation remain outside the guarantee.
pub fn checked_stream(root: &Path, relative: &str, expected: &FileInfo) -> Result<File> {
    let mut file = open_regular(root, relative)?;
    let before = stamp(&file)?;
    ensure!(before.size == expected.size, "Snapshot member size changed");
    ensure!(
        digest_stream(&mut file, None)? == *expected && stamp(&file)? == before,
        "Snapshot member changed"
    );
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

pub struct Server {
    listener: TcpListener,
    root: PathBuf,
    catalog: Catalog,
}
impl Server {
    pub fn bind(root: &Path, port: u16) -> Result<Self> {
        let root = root.canonicalize()?;
        let catalog = validate(&root)?;
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.set_reuse_address(true)?;
        socket.bind(&std::net::SocketAddr::from(([127, 0, 0, 1], port)).into())?;
        socket.listen(16)?;
        let listener: TcpListener = socket.into();
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            root,
            catalog,
        })
    }
    pub fn port(&self) -> u16 {
        self.listener
            .local_addr()
            .expect("bound listener address")
            .port()
    }
    pub fn run(self, stop: Arc<AtomicBool>) -> Result<()> {
        while !stop.load(Ordering::Acquire) {
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(60)))?;
                    let _ = self.reply(&mut stream);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
    fn reply(&self, stream: &mut TcpStream) -> Result<()> {
        let request = match Request::read(stream) {
            Ok(value) => value,
            Err(_) => return error(stream, 400, "Invalid bounded HTTP request"),
        };
        if request.headers.get("host") != Some(&format!("127.0.0.1:{}", self.port())) {
            return error(stream, 403, "Use the literal loopback address");
        }
        if !["GET", "HEAD"].contains(&request.method.as_str()) {
            return error(stream, 405, "Read-only snapshot server");
        }
        let relative = match self.route(&request.path) {
            Some(relative) => relative,
            None => return error(stream, 404, "Unknown snapshot member"),
        };
        let expected = self
            .catalog
            .files
            .get(&relative)
            .context("Catalog route is not a file")?;
        let mut file = match fresh(&self.catalog)
            .and_then(|()| checked_stream(&self.root, &format!("repo/{relative}"), expected))
        {
            Ok(file) => file,
            Err(_) => {
                return error(
                    stream,
                    409,
                    "Snapshot changed or expired; import a new signed snapshot",
                )
            }
        };
        let range = match byte_range(
            request.headers.get("range").map(String::as_str),
            expected.size,
        ) {
            Ok(range) => range,
            Err(_) => return error(stream, 416, "Invalid byte range"),
        };
        let status = if range.partial {
            "206 Partial Content"
        } else {
            "200 OK"
        };
        write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; sandbox\r\nConnection: close\r\n",range.length)?;
        if range.partial {
            write!(
                stream,
                "Content-Range: bytes {}-{}/{}\r\n",
                range.start,
                range.start + range.length - 1,
                expected.size
            )?;
        }
        stream.write_all(b"\r\n")?;
        if request.method == "GET" {
            file.seek(SeekFrom::Start(range.start))?;
            let mut remaining = range.length;
            let mut buffer = vec![0; CHUNK];
            while remaining > 0 {
                let count = file.read(&mut buffer[..CHUNK.min(remaining as usize)])?;
                ensure!(count > 0, "Snapshot changed during response");
                stream.write_all(&buffer[..count])?;
                remaining -= count as u64;
            }
        }
        Ok(())
    }
    fn route(&self, path: &str) -> Option<String> {
        if self.catalog.manager == "homebrew" {
            return self.catalog.routes.get(path).cloned();
        }
        if !path.starts_with('/') || path.contains('?') {
            return None;
        }
        let relative = percent_encoding::percent_decode_str(path.strip_prefix('/')?)
            .decode_utf8()
            .ok()?
            .into_owned();
        self.catalog
            .files
            .contains_key(&relative)
            .then_some(relative)
    }
}

struct Request {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
}
impl Request {
    fn read(stream: &mut TcpStream) -> Result<Self> {
        let mut reader = BufReader::new(stream);
        let mut total = 0;
        let first = read_line(&mut reader, &mut total)?;
        let mut parts = first.split_whitespace();
        let method = parts.next().context("Missing method")?.to_string();
        let path = parts.next().context("Missing target")?.to_string();
        ensure!(
            matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) && parts.next().is_none(),
            "Invalid request line"
        );
        let mut headers = BTreeMap::new();
        loop {
            let line = read_line(&mut reader, &mut total)?;
            if line.is_empty() {
                break;
            }
            let (key, value) = line.split_once(':').context("Invalid header")?;
            ensure!(
                !key.is_empty() && !key.bytes().any(|b| b <= 32 || b >= 127),
                "Invalid header name"
            );
            ensure!(
                headers
                    .insert(key.to_ascii_lowercase(), value.trim().to_string())
                    .is_none(),
                "Duplicate header"
            );
        }
        Ok(Self {
            method,
            path,
            headers,
        })
    }
}
fn read_line(reader: &mut impl BufRead, total: &mut usize) -> Result<String> {
    ensure!(*total < 32 * 1024, "Headers exceed limit");
    let mut bytes = Vec::new();
    let count = reader
        .take((32 * 1024 - *total + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    *total += count;
    ensure!(
        count > 0 && *total <= 32 * 1024 && bytes.ends_with(b"\r\n"),
        "Invalid or oversized HTTP line"
    );
    bytes.truncate(bytes.len() - 2);
    Ok(String::from_utf8(bytes)?)
}
struct ByteRange {
    start: u64,
    length: u64,
    partial: bool,
}
fn byte_range(header: Option<&str>, size: u64) -> Result<ByteRange> {
    let Some(header) = header else {
        return Ok(ByteRange {
            start: 0,
            length: size,
            partial: false,
        });
    };
    let (start, end) = header
        .strip_prefix("bytes=")
        .and_then(|v| v.split_once('-'))
        .context("Invalid range")?;
    ensure!(
        !start.is_empty()
            && start.len() <= 20
            && end.len() <= 20
            && start.bytes().chain(end.bytes()).all(|b| b.is_ascii_digit()),
        "Invalid range"
    );
    let start: u64 = start.parse()?;
    let end = if end.is_empty() {
        size.saturating_sub(1)
    } else {
        end.parse::<u64>()?.min(size.saturating_sub(1))
    };
    ensure!(start < size && start <= end, "Unsatisfiable range");
    Ok(ByteRange {
        start,
        length: end - start + 1,
        partial: true,
    })
}
fn error(stream: &mut TcpStream, status: u16, message: &str) -> Result<()> {
    write!(stream,"HTTP/1.1 {status} Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{message}",message.len())?;
    Ok(())
}
