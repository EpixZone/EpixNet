use crate::{
    catalog::{collision_key, valid_digest},
    decode, encode,
    filesystem::{digest_stream, ensure_space, read_bounded, Pending},
    safe_path, validate, Catalog, CATALOG, CHUNK, MAX_ARCHIVE, MAX_CATALOG,
};
use anyhow::{ensure, Context, Result};
use reqwest::{
    blocking::Client,
    header::{CONTENT_LENGTH, CONTENT_TYPE, COOKIE, ORIGIN, REFERER},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    net::SocketAddr,
    path::Path,
    time::Duration,
};

pub struct ExportOptions<'a> {
    pub node: &'a str,
    pub address: &'a str,
    pub output: &'a Path,
    pub cookie_file: Option<&'a Path>,
    pub expected_snapshot: Option<&'a str>,
}

pub fn node_origin(value: &str) -> Result<String> {
    let authority = value
        .strip_prefix("http://")
        .context("Node must be an HTTP loopback origin")?
        .strip_suffix('/')
        .unwrap_or_else(|| value.strip_prefix("http://").unwrap_or(""));
    let socket: SocketAddr = authority
        .parse()
        .context("Specify a literal loopback address and UI port")?;
    ensure!(
        socket.ip().is_loopback() && socket.port() != 0,
        "Only a local EpixNet node may verify an export"
    );
    Ok(format!("http://{socket}"))
}

fn cookies(path: Option<&Path>, origin: &str) -> Result<Option<String>> {
    let Some(path) = path else { return Ok(None) };
    let bytes = read_bounded(File::open(path)?, MAX_CATALOG)?;
    let text = std::str::from_utf8(&bytes)?;
    let url = reqwest::Url::parse(origin)?;
    let host = url.host_str().context("Missing node host")?;
    let now = chrono::Utc::now().timestamp();
    let mut values = Vec::new();
    for line in text.lines() {
        let line = line.strip_prefix("#HttpOnly_").unwrap_or(line);
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let columns: Vec<_> = line.split('\t').collect();
        ensure!(columns.len() == 7, "Invalid cookie file");
        let expiry: i64 = columns[4].parse().context("Invalid cookie expiry")?;
        if columns[0].trim_start_matches('.') != host
            || columns[3] != "FALSE"
            || (expiry != 0 && expiry <= now)
        {
            continue;
        }
        let path = columns[2];
        if path != "/"
            && path != "/EpixNet-Internal"
            && path != "/EpixNet-Internal/"
            && path != "/EpixNet-Internal/Zip"
        {
            continue;
        }
        ensure!(
            !columns[5].is_empty()
                && !columns[5]
                    .bytes()
                    .any(|b| b <= 32 || b >= 127 || b"()<>@,;:\\[]?={}\"".contains(&b)),
            "Invalid cookie name"
        );
        ensure!(
            !columns[6].bytes().any(|b| b < 32 || b == 127 || b == b';'),
            "Invalid cookie value"
        );
        values.push(format!("{}={}", columns[5], columns[6]));
    }
    Ok((!values.is_empty()).then(|| values.join("; ")))
}

pub fn export(options: ExportOptions<'_>) -> Result<Catalog> {
    let origin = node_origin(options.node)?;
    ensure!(
        epix_crypt::is_valid_address(options.address)
            && options.address == options.address.to_ascii_lowercase(),
        "Use a checksum-valid canonical epix1 address"
    );
    if let Some(expected) = options.expected_snapshot {
        ensure!(valid_digest(expected), "Invalid snapshot pin");
    }
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(300))
        .build()?;
    let mut request = client
        .get(format!("{origin}/EpixNet-Internal/Zip"))
        .query(&[("address", options.address)])
        .header(ORIGIN, &origin)
        .header(REFERER, format!("{origin}/{}/", options.address));
    if let Some(cookie) = cookies(options.cookie_file, &origin)? {
        request = request.header(COOKIE, cookie);
    }
    let mut response = request.send().context("Local node export request failed")?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "Node refused the verified ZIP; check availability and authentication"
    );
    ensure!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            == Some("application/zip"),
        "Node did not return a verified ZIP"
    );
    let length: u64 = response
        .headers()
        .get(CONTENT_LENGTH)
        .context("Export has no bounded length")?
        .to_str()?
        .parse()?;
    ensure!(length <= MAX_ARCHIVE, "Node export exceeds 16 GiB");
    let pending = Pending::new(options.output)?;
    ensure_space(pending.path(), length)?;
    let mut archive = tempfile::tempfile_in(pending.path())?;
    let mut received = 0;
    let mut buffer = vec![0; CHUNK];
    loop {
        let count = response.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        received += count as u64;
        ensure!(received <= length, "Export exceeds its declared length");
        archive.write_all(&buffer[..count])?;
    }
    ensure!(received == length, "Node export was truncated");
    archive.seek(SeekFrom::Start(0))?;
    let catalog = unpack(archive, pending.path(), options.address)?;
    if let Some(expected) = options.expected_snapshot {
        ensure!(
            catalog.snapshot == expected,
            "Snapshot does not match the operator's pinned digest"
        );
    }
    pending.commit()?;
    Ok(catalog)
}

fn small<R: Read + Seek>(archive: &mut zip::ZipArchive<R>, index: usize) -> Result<Vec<u8>> {
    let member = archive.by_index(index)?;
    ensure!(
        member.size() <= MAX_CATALOG,
        "Export metadata exceeds 8 MiB"
    );
    read_bounded(member, MAX_CATALOG)
}

pub fn unpack<R: Read + Seek>(mut reader: R, destination: &Path, address: &str) -> Result<Catalog> {
    crate::zip_bounds::check(&mut reader)?;
    let mut archive = zip::ZipArchive::with_config(
        zip::read::Config {
            archive_offset: zip::read::ArchiveOffset::Known(0),
        },
        reader,
    )?;
    ensure!(archive.len() <= 65_536, "Too many ZIP entries");
    let mut entries = BTreeMap::new();
    let mut folded = HashSet::new();
    let mut total = 0u64;
    for index in 0..archive.len() {
        let member = archive.by_index(index)?;
        let name = member.name()?.into_owned();
        safe_path(&name)?;
        let mode = member.unix_mode().unwrap_or(0) & 0o170000;
        ensure!(
            mode == 0 || mode == 0o100000,
            "ZIP member is not a regular file"
        );
        ensure!(
            folded.insert(collision_key(&name)),
            "Duplicate or colliding ZIP member"
        );
        total = total
            .checked_add(member.size())
            .context("ZIP size overflow")?;
        ensure!(
            total <= 16 * 1024 * 1024 * 1024,
            "Export exceeds ZIP byte limit"
        );
        entries.insert(name, (index, member.size()));
    }
    let manifest = small(
        &mut archive,
        entries
            .get("content.json")
            .context("Export has no signed root")?
            .0,
    )?;
    ensure!(
        decode(&manifest)?["address"] == address,
        "Node export address does not match requested xite"
    );
    let catalog_bytes = small(
        &mut archive,
        entries
            .get(CATALOG)
            .context("Export has no snapshot catalog")?
            .0,
    )?;
    let catalog: Catalog = serde_json::from_value(decode(&catalog_bytes)?)?;
    catalog.check()?;
    ensure_space(
        destination,
        catalog.files.values().map(|entry| entry.size).sum(),
    )?;
    for (relative, expected) in &catalog.files {
        let name = format!("repo/{relative}");
        let (index, size) = entries.get(&name).context("Incomplete repository export")?;
        ensure!(
            *size == expected.size,
            "Export member size differs from catalog"
        );
        let target = destination.join(&name);
        fs::create_dir_all(target.parent().context("Missing export parent")?)?;
        let mut output = File::create_new(target)?;
        let actual = digest_stream(&mut archive.by_index(*index)?, Some(&mut output))?;
        ensure!(actual == *expected, "Export checksum mismatch");
        output.sync_all()?;
    }
    fs::write(destination.join(CATALOG), catalog_bytes)?;
    fs::write(
        destination.join("epix-export.json"),
        encode(
            &json!({"address":address,"manifest_sha256":hex::encode(Sha256::digest(&manifest))}),
        )?,
    )?;
    validate(destination)?;
    Ok(catalog)
}
