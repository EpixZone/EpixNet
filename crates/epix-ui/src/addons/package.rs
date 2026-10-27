use super::{check_cancel, fail, AddonError, AddonErrorCode, Result, MAX_ARCHIVE_BYTES};
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize,
};
use serde_json::Value;
use std::{
    collections::HashSet,
    fmt,
    io::{Cursor, Read},
    sync::atomic::AtomicBool,
};

pub(crate) struct Package {
    pub id: String,
    pub version: String,
    pub name: String,
    pub manifest_version: u32,
    pub required: Vec<String>,
    pub optional: Vec<String>,
    pub hosts: Vec<String>,
    pub optional_hosts: Vec<String>,
}

// Parsing before signature verification must not accept last-key-wins JSON.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("Invalid number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut v = Vec::new();
                while let Some(x) = a.next_element::<Unique>()? {
                    v.push(x.0);
                }
                Ok(Unique(Value::Array(v)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut v = serde_json::Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if v.contains_key(&k) {
                        return Err(de::Error::custom("Duplicate JSON key"));
                    }
                    v.insert(k, a.next_value::<Unique>()?.0);
                }
                Ok(Unique(Value::Object(v)))
            }
        }
        d.deserialize_any(V)
    }
}
pub(crate) fn unique_json(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice::<Unique>(bytes)
        .map(|v| v.0)
        .map_err(|e| AddonError::new(AddonErrorCode::InvalidPackage, e.to_string()))
}

/// No normalization of ambiguous URL bytes: package identity is one exact path.
pub(crate) fn parse_source(source: &str) -> Result<(String, String)> {
    if source.len() > 4096 || source.chars().any(char::is_control) {
        return fail(AddonErrorCode::UnsupportedSource, "Invalid xite URL");
    }
    let rest = source
        .strip_prefix("https://")
        .or_else(|| source.strip_prefix("http://"))
        .or_else(|| source.strip_prefix("epix://"))
        .ok_or_else(|| AddonError::new(AddonErrorCode::UnsupportedSource, "Expected a xite URL"))?;
    let (host, path) = rest.split_once('/').ok_or_else(|| {
        AddonError::new(AddonErrorCode::UnsupportedSource, "Package URL has no path")
    })?;
    if host.is_empty()
        || host.len() > 255
        || host
            .bytes()
            .any(|b| !b.is_ascii_lowercase() && !b.is_ascii_digit() && b != b'.' && b != b'-')
        || !host.ends_with(".epix")
    {
        return fail(
            AddonErrorCode::UnsupportedSource,
            "Only .epix publisher URLs are accepted",
        );
    }
    if path.contains(['%', '?', '#', '\\'])
        || !epix_content::verify::is_valid_relative_path(path)
        || !path.ends_with(".xpi")
        || path.len() > 1024
    {
        return fail(
            AddonErrorCode::UnsupportedSource,
            "Package path must be an unambiguous relative .xpi path",
        );
    }
    Ok((host.into(), path.into()))
}

fn u16at(b: &[u8], p: usize) -> Result<u16> {
    let s = b
        .get(p..p + 2)
        .ok_or_else(|| AddonError::new(AddonErrorCode::InvalidPackage, "Truncated ZIP"))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
fn u32at(b: &[u8], p: usize) -> Result<u32> {
    let s = b
        .get(p..p + 4)
        .ok_or_else(|| AddonError::new(AddonErrorCode::InvalidPackage, "Truncated ZIP"))?;
    Ok(u32::from_le_bytes(s.try_into().unwrap()))
}
fn extent(start: usize, len: usize, max: usize) -> Result<usize> {
    start.checked_add(len).filter(|n| *n <= max).ok_or_else(|| {
        AddonError::new(AddonErrorCode::InvalidPackage, "ZIP extent outside archive")
    })
}

struct ZipDirectory {
    count: usize,
    size: usize,
    offset: usize,
    end: usize,
}

fn zip_directory(bytes: &[u8]) -> Result<ZipDirectory> {
    if bytes.len() < 22 || bytes.len() as u64 > MAX_ARCHIVE_BYTES {
        return fail(AddonErrorCode::LimitExceeded, "Archive size limit");
    }
    let end = (bytes.len().saturating_sub(65557)..=bytes.len() - 22)
        .rev()
        .find(|p| {
            bytes.get(*p..*p + 4) == Some(b"PK\x05\x06")
                && u16at(bytes, *p + 20).is_ok_and(|n| *p + 22 + n as usize == bytes.len())
        })
        .ok_or_else(|| AddonError::new(AddonErrorCode::InvalidPackage, "ZIP end record missing"))?;
    let count = u16at(bytes, end + 10)? as usize;
    let size = u32at(bytes, end + 12)? as usize;
    let offset = u32at(bytes, end + 16)? as usize;
    if count == 0
        || count > 8192
        || size > 4 * 1024 * 1024
        || u16at(bytes, end + 4)? != 0
        || u16at(bytes, end + 6)? != 0
        || u16at(bytes, end + 8)? as usize != count
        || extent(offset, size, end)? != end
    {
        return fail(
            AddonErrorCode::InvalidPackage,
            "Unsupported ZIP directory layout",
        );
    }
    Ok(ZipDirectory {
        count,
        size,
        offset,
        end,
    })
}

struct ZipEntry<'a> {
    flags: u16,
    method: u16,
    crc: u32,
    compressed: usize,
    unpacked: u64,
    name: &'a str,
}

fn local_span(
    bytes: &[u8],
    local: usize,
    offset: usize,
    entry: ZipEntry<'_>,
) -> Result<(usize, usize)> {
    let ZipEntry {
        flags,
        method,
        crc,
        compressed,
        unpacked,
        name,
    } = entry;
    let n = name.len();
    if bytes.get(local..local + 4) != Some(b"PK\x03\x04")
        || u16at(bytes, local + 6)? != flags
        || u16at(bytes, local + 8)? != method
    {
        return fail(AddonErrorCode::InvalidPackage, "ZIP local header mismatch");
    }
    let ln = u16at(bytes, local + 26)? as usize;
    let le = u16at(bytes, local + 28)? as usize;
    if ln != n || le > 4096 {
        return fail(
            AddonErrorCode::InvalidPackage,
            "ZIP local name/extra mismatch",
        );
    }
    let name_start = extent(local, 30, offset)?;
    let local_name_end = extent(name_start, ln, offset)?;
    if bytes.get(name_start..local_name_end) != Some(name.as_bytes()) {
        return fail(AddonErrorCode::InvalidPackage, "ZIP local name mismatch");
    }
    let data = extent(local_name_end, le, offset)?;
    let mut stop = extent(data, compressed, offset)?;
    if flags & 8 == 0 {
        if u32at(bytes, local + 14)? != crc
            || u32at(bytes, local + 18)? as usize != compressed
            || u32at(bytes, local + 22)? as u64 != unpacked
        {
            return fail(
                AddonErrorCode::InvalidPackage,
                "ZIP local size/CRC mismatch",
            );
        }
    } else {
        if bytes.get(stop..stop + 4) == Some(b"PK\x07\x08") {
            stop += 4;
        }
        if u32at(bytes, stop)? != crc
            || u32at(bytes, stop + 4)? as usize != compressed
            || u32at(bytes, stop + 8)? as u64 != unpacked
        {
            return fail(AddonErrorCode::InvalidPackage, "ZIP descriptor mismatch");
        }
        stop = extent(stop, 12, offset)?;
    }
    Ok((local, stop))
}

fn check_spans(mut spans: Vec<(usize, usize)>, offset: usize) -> Result<()> {
    spans.sort_unstable();
    let mut previous = 0;
    for (start, end) in spans {
        if start != previous {
            return fail(
                AddonErrorCode::InvalidPackage,
                "ZIP overlap, prefix or unexplained gap",
            );
        }
        previous = end;
    }
    if previous != offset {
        return fail(
            AddonErrorCode::InvalidPackage,
            "Unexpected data before ZIP directory",
        );
    }
    Ok(())
}

/// Check metadata allocation bounds and central/local agreement before zip opens
/// any entry. ZIP64, split/prefixed archives and overlapping data are excluded.
fn preflight(bytes: &[u8]) -> Result<usize> {
    let ZipDirectory {
        count,
        size,
        offset,
        end,
    } = zip_directory(bytes)?;
    let mut pos = offset;
    let mut spans = Vec::with_capacity(count);
    let mut names = HashSet::new();
    let mut total = 0u64;
    for _ in 0..count {
        if bytes.get(pos..pos + 4) != Some(b"PK\x01\x02") {
            return fail(AddonErrorCode::InvalidPackage, "Invalid central header");
        }
        let flags = u16at(bytes, pos + 8)?;
        let method = u16at(bytes, pos + 10)?;
        let crc = u32at(bytes, pos + 16)?;
        let compressed = u32at(bytes, pos + 20)? as usize;
        let unpacked = u32at(bytes, pos + 24)? as u64;
        let n = u16at(bytes, pos + 28)? as usize;
        let extra = u16at(bytes, pos + 30)? as usize;
        let comment = u16at(bytes, pos + 32)? as usize;
        if flags & !(0x0800 | 0x0008 | 0x0006) != 0
            || !matches!(method, 0 | 8)
            || u16at(bytes, pos + 34)? != 0
            || n == 0
            || n > 1024
            || extra > 4096
            || comment > 4096
            || compressed == u32::MAX as usize
            || unpacked > MAX_ARCHIVE_BYTES
        {
            return fail(AddonErrorCode::InvalidPackage, "Unsupported ZIP entry");
        }
        total = total
            .checked_add(unpacked)
            .filter(|n| *n <= 128 * 1024 * 1024)
            .ok_or_else(|| {
                AddonError::new(AddonErrorCode::LimitExceeded, "Unpacked archive size limit")
            })?;
        let name_end = extent(pos + 46, n, offset + size)?;
        let name = std::str::from_utf8(&bytes[pos + 46..name_end])
            .map_err(|_| AddonError::new(AddonErrorCode::InvalidPackage, "Non UTF-8 ZIP name"))?;
        let plain = name.strip_suffix('/').unwrap_or(name);
        if !epix_content::verify::is_valid_relative_path(plain)
            || plain.contains(['\\', ':'])
            || plain.chars().any(char::is_control)
        {
            return fail(AddonErrorCode::InvalidPackage, "Unsafe ZIP path");
        }
        let (lower, upper) = epix_content::verify::portable_path_case_keys(plain);
        if !names.insert(lower) || !names.insert(format!("U:{upper}")) {
            return fail(
                AddonErrorCode::InvalidPackage,
                "Duplicate or case-aliased ZIP path",
            );
        }
        let mode = u32at(bytes, pos + 38)? >> 16;
        let kind = mode & 0o170000;
        if kind != 0 && kind != 0o100000 && !(kind == 0o040000 && name.ends_with('/')) {
            return fail(AddonErrorCode::InvalidPackage, "Link or special ZIP entry");
        }
        let extra_end = extent(name_end, extra, offset + size)?;
        let mut e = name_end;
        while e < extra_end {
            let tag = u16at(bytes, e)?;
            let len = u16at(bytes, e + 2)? as usize;
            e = extent(e + 4, len, extra_end)?;
            if tag == 1 {
                return fail(AddonErrorCode::InvalidPackage, "ZIP64 is unsupported");
            }
        }
        let local = u32at(bytes, pos + 42)? as usize;
        let entry = ZipEntry {
            flags,
            method,
            crc,
            compressed,
            unpacked,
            name,
        };
        spans.push(local_span(bytes, local, offset, entry)?);
        pos = extent(extra_end, comment, offset + size)?;
    }
    if pos != end {
        return fail(
            AddonErrorCode::InvalidPackage,
            "ZIP directory size mismatch",
        );
    }
    check_spans(spans, offset)?;
    Ok(count)
}
fn text(value: &Value, key: &str, max: usize) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or_else(|| {
            AddonError::new(
                AddonErrorCode::InvalidPackage,
                format!("Invalid addon {key}"),
            )
        })
}
fn permissions(value: &Value, key: &str) -> Result<Vec<String>> {
    let Some(value) = value.get(key) else {
        return Ok(Vec::new());
    };
    let list = value.as_array().filter(|a| a.len() <= 256).ok_or_else(|| {
        AddonError::new(AddonErrorCode::InvalidPackage, "Invalid permission list")
    })?;
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for permission in list {
        let p = permission
            .as_str()
            .filter(|p| !p.is_empty() && p.len() <= 2048 && !p.chars().any(char::is_control))
            .ok_or_else(|| AddonError::new(AddonErrorCode::InvalidPackage, "Invalid permission"))?;
        if matches!(
            p,
            "nativeMessaging"
                | "nativeMessagingFromContent"
                | "nativeMessagingFromAddon"
                | "management"
                | "mozillaAddons"
                | "mozillaAddonsTheme"
                | "geckoViewAddons"
        ) || p.starts_with("experiments.")
        {
            return fail(
                AddonErrorCode::InvalidPackage,
                "Native or privileged addon permission is not allowed",
            );
        }
        if !seen.insert(p) {
            return fail(AddonErrorCode::InvalidPackage, "Duplicate permission");
        }
        out.push(p.into());
    }
    Ok(out)
}
pub(crate) fn inspect_package(bytes: &[u8], cancel: &AtomicBool) -> Result<Package> {
    check_cancel(cancel)?;
    let count = preflight(bytes)?;
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| AddonError::new(AddonErrorCode::InvalidPackage, e.to_string()))?;
    if archive.len() != count {
        return fail(AddonErrorCode::InvalidPackage, "ZIP entry count changed");
    }
    let mut manifest = None;
    let mut total = 0u64;
    for index in 0..count {
        check_cancel(cancel)?;
        let mut entry = archive
            .by_index(index)
            .map_err(|e| AddonError::new(AddonErrorCode::InvalidPackage, e.to_string()))?;
        let is_manifest = entry
            .name()
            .map_err(|e| AddonError::new(AddonErrorCode::InvalidPackage, e.to_string()))?
            == "manifest.json";
        let mut data = Vec::new();
        let mut actual = 0u64;
        let mut buffer = [0u8; 32768];
        loop {
            check_cancel(cancel)?;
            let n = entry
                .read(&mut buffer)
                .map_err(|e| AddonError::new(AddonErrorCode::InvalidPackage, e.to_string()))?;
            if n == 0 {
                break;
            }
            actual += n as u64;
            total += n as u64;
            if actual > MAX_ARCHIVE_BYTES
                || total > 128 * 1024 * 1024
                || (is_manifest && actual > 1024 * 1024)
            {
                return fail(
                    AddonErrorCode::LimitExceeded,
                    "Decompressed package size limit",
                );
            }
            if is_manifest {
                data.extend_from_slice(&buffer[..n]);
            }
        }
        if actual != entry.size() {
            return fail(AddonErrorCode::InvalidPackage, "ZIP actual size mismatch");
        }
        if is_manifest {
            manifest = Some(unique_json(&data)?);
        }
    }
    let m = manifest
        .ok_or_else(|| AddonError::new(AddonErrorCode::InvalidPackage, "Missing manifest.json"))?;
    if m.get("experiment_apis").is_some() || m.get("theme_experiment").is_some() {
        return fail(
            AddonErrorCode::InvalidPackage,
            "Privileged extension experiments are not allowed",
        );
    }
    let id1 = m
        .pointer("/browser_specific_settings/gecko/id")
        .and_then(Value::as_str);
    let id2 = m.pointer("/applications/gecko/id").and_then(Value::as_str);
    if id1.is_some() && id2.is_some() && id1 != id2 {
        return fail(
            AddonErrorCode::InvalidPackage,
            "Conflicting addon identities",
        );
    }
    let id = id1
        .or(id2)
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 255
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"@._-{}".contains(&b))
        })
        .ok_or_else(|| {
            AddonError::new(
                AddonErrorCode::InvalidPackage,
                "Explicit stable addon ID required",
            )
        })?;
    let lower = id.to_ascii_lowercase();
    if lower.ends_with("@epix.zone")
        || lower == "zone.epix.nmh"
        || lower.starts_with("epix-internal")
    {
        return fail(AddonErrorCode::InvalidPackage, "Reserved addon ID");
    }
    let manifest_version = m
        .get("manifest_version")
        .and_then(Value::as_u64)
        .filter(|n| matches!(n, 2 | 3))
        .ok_or_else(|| {
            AddonError::new(
                AddonErrorCode::InvalidPackage,
                "Unsupported manifest version",
            )
        })? as u32;
    let package = Package {
        id: id.into(),
        version: text(&m, "version", 128)?,
        name: text(&m, "name", 256)?,
        manifest_version,
        required: permissions(&m, "permissions")?,
        optional: permissions(&m, "optional_permissions")?,
        hosts: permissions(&m, "host_permissions")?,
        optional_hosts: permissions(&m, "optional_host_permissions")?,
    };
    if [
        &package.required,
        &package.optional,
        &package.hosts,
        &package.optional_hosts,
    ]
    .into_iter()
    .flatten()
    .map(String::len)
    .sum::<usize>()
        > 65536
    {
        return fail(
            AddonErrorCode::LimitExceeded,
            "Permission display size limit",
        );
    }
    Ok(package)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    pub(crate) fn archive(manifest: Value) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file("manifest.json", options).unwrap();
        writer
            .write_all(&serde_json::to_vec(&manifest).unwrap())
            .unwrap();
        writer.start_file("background.js", options).unwrap();
        writer.write_all(b"// public test package\n").unwrap();
        writer.finish().unwrap().into_inner()
    }
    pub(crate) fn manifest(version: &str) -> Value {
        serde_json::json!({"manifest_version":2,"name":"Public fixture","version":version,"browser_specific_settings":{"gecko":{"id":"fixture@example.test"}},"permissions":["storage"]})
    }
    #[test]
    fn ordinary_package_preserves_metadata() {
        let bytes = archive(manifest("1.0"));
        let p = inspect_package(&bytes, &AtomicBool::new(false)).unwrap();
        assert_eq!(p.id, "fixture@example.test");
        assert_eq!(p.required, ["storage"]);
    }
    #[test]
    fn native_permissions_and_reserved_ids_are_rejected() {
        for field in ["permissions", "optional_permissions"] {
            let mut m = manifest("1");
            m[field] = serde_json::json!(["nativeMessaging"]);
            assert!(inspect_package(&archive(m), &AtomicBool::new(false)).is_err());
        }
        let mut m = manifest("1");
        m["browser_specific_settings"]["gecko"]["id"] = "Wallet@Epix.Zone".into();
        assert!(inspect_package(&archive(m), &AtomicBool::new(false)).is_err());
    }
    #[test]
    fn duplicate_json_and_ambiguous_source_fail() {
        assert!(unique_json(br#"{"a":1,"a":2}"#).is_err());
        for url in [
            "file:///tmp/addon.xpi",
            "https://example.com/addon.xpi",
            "https://x.epix/a%2fb.xpi",
            "https://x.epix/../a.xpi",
            "https://x.epix/a.xpi#x",
            "https://user@x.epix/a.xpi",
            "https://x.epix/a.xpi?x",
        ] {
            assert!(parse_source(url).is_err(), "{url}");
        }
        assert!(parse_source("https://test.epix/addons/a.xpi").is_ok());
    }
    #[test]
    fn crc_header_and_zip64_mismatch_fail() {
        let bytes = archive(manifest("1"));
        let mut corrupted = bytes.clone();
        let body =
            30 + u16at(&corrupted, 26).unwrap() as usize + u16at(&corrupted, 28).unwrap() as usize;
        corrupted[body] ^= 1;
        assert!(inspect_package(&corrupted, &AtomicBool::new(false)).is_err());
        let mut local = bytes.clone();
        local[18] ^= 1;
        assert!(preflight(&local).is_err());
        let mut zipped = bytes;
        let end = zipped.len() - 22;
        zipped[end + 10] = 255;
        zipped[end + 11] = 255;
        assert!(preflight(&zipped).is_err());
    }
    #[test]
    fn duplicate_paths_and_expansion_budgets_fail() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let o = zip::write::SimpleFileOptions::default();
        writer.start_file("A.js", o).unwrap();
        writer.write_all(b"a").unwrap();
        writer.start_file("a.js", o).unwrap();
        writer.write_all(b"b").unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        assert!(preflight(&bytes).is_err());
        let mut bytes = archive(manifest("1"));
        let central = bytes.windows(4).position(|s| s == b"PK\x01\x02").unwrap();
        bytes[central + 24..central + 28]
            .copy_from_slice(&(MAX_ARCHIVE_BYTES as u32 + 1).to_le_bytes());
        assert!(preflight(&bytes).is_err());
    }
    #[test]
    fn cancellation_precedes_archive_processing() {
        assert_eq!(
            inspect_package(b"invalid", &AtomicBool::new(true))
                .err()
                .unwrap()
                .code,
            AddonErrorCode::Cancelled
        );
    }
}
