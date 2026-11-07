//! Verify repository closure without replacing native package signature checks.
use anyhow::{bail, ensure, Context, Result};
use roxmltree::{Document, Node, ParsingOptions};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

use crate::FileInfo;
const METADATA_LIMIT: u64 = 64 * 1024 * 1024;
const XML_NODE_LIMIT: u32 = 1_000_000;
type Fields = BTreeMap<String, String>;

pub fn validate(
    manager: &str,
    root: &Path,
    files: &BTreeMap<String, FileInfo>,
    expires: i64,
) -> Result<()> {
    match manager {
        "apt" => apt(root, files, expires),
        "dnf" => dnf(root, files),
        "homebrew" => Ok(()), // The pinned formula and explicit artifact map select the closure.
        "chocolatey" => {
            ensure!(
                !files.is_empty()
                    && files
                        .keys()
                        .all(|p| !p.contains('/') && p.to_ascii_lowercase().ends_with(".nupkg")),
                "Chocolatey source must contain only flat .nupkg files"
            );
            Ok(())
        }
        _ => bail!("Unsupported package manager: {manager}"),
    }
}

fn read_limited(reader: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    reader.take(limit + 1).read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 <= limit,
        "Expanded repository metadata exceeds its size limit"
    );
    Ok(data)
}

fn metadata(root: &Path, path: &str) -> Result<String> {
    let file = crate::open_regular(root, path)?;
    let bytes = if path.ends_with(".xz") {
        let size = file.metadata()?.len();
        let stream = liblzma::stream::Stream::new_stream_decoder(METADATA_LIMIT, 0)?;
        let mut decoder = liblzma::read::XzDecoder::new_stream(file, stream);
        let bytes = read_limited(&mut decoder, METADATA_LIMIT)?;
        ensure!(
            decoder.total_in() == size,
            "Trailing or concatenated xz metadata is not supported"
        );
        bytes
    } else if path.ends_with(".gz") {
        read_limited(flate2::read::MultiGzDecoder::new(file), METADATA_LIMIT)?
    } else {
        read_limited(file, METADATA_LIMIT)?
    };
    String::from_utf8(bytes).context("Repository metadata must be UTF-8")
}

fn paragraphs(text: &str) -> Result<Vec<Fields>> {
    let mut output = Vec::new();
    let mut fields = Fields::new();
    let mut key = None::<String>;
    for line in text.lines() {
        if line.trim().is_empty() {
            if !fields.is_empty() {
                output.push(std::mem::take(&mut fields));
            }
            key = None;
        } else if line.starts_with([' ', '\t']) {
            let field = key
                .as_ref()
                .context("Repository continuation has no field")?;
            let value = fields.get_mut(field).context("Missing repository field")?;
            value.push('\n');
            value.push_str(&line[1..]);
        } else {
            let (name, value) = line
                .split_once(':')
                .context("Malformed repository metadata")?;
            ensure!(
                !name.is_empty() && !fields.contains_key(name),
                "Duplicate or empty repository metadata field"
            );
            fields.insert(name.to_owned(), value.trim().to_owned());
            key = Some(name.to_owned());
        }
    }
    if !fields.is_empty() {
        output.push(fields);
    }
    Ok(output)
}

fn field<'a>(fields: &'a Fields, name: &str) -> Result<&'a str> {
    fields
        .get(name)
        .map(String::as_str)
        .with_context(|| format!("Missing repository metadata field: {name}"))
}

fn join_member(base: &str, relative: &str) -> Result<String> {
    crate::safe_path(relative)?;
    let path = if base.is_empty() {
        relative.to_owned()
    } else {
        format!("{base}/{relative}")
    };
    crate::safe_path(&path)?;
    Ok(path)
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(base, _)| base)
}
fn name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn expected(
    files: &BTreeMap<String, FileInfo>,
    path: &str,
    size: &str,
    digest: &str,
    algorithm: &str,
) -> Result<()> {
    ensure!(
        algorithm == "sha256",
        "Snapshot format requires SHA256 repository checksums"
    );
    crate::safe_path(path)?;
    let digest = digest.trim().to_ascii_lowercase();
    ensure!(
        digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid SHA256 repository checksum"
    );
    let expected_size = size
        .trim()
        .parse::<u64>()
        .context("Invalid repository member size")?;
    let entry = files
        .get(path)
        .with_context(|| format!("Missing repository member: {path}"))?;
    ensure!(
        entry.size == expected_size && entry.sha256 == digest,
        "Changed repository member: {path}"
    );
    Ok(())
}

fn release_body(text: &str) -> Result<String> {
    let mut lines = text.lines();
    ensure!(
        lines.next() == Some("-----BEGIN PGP SIGNED MESSAGE-----"),
        "Malformed InRelease"
    );
    ensure!(lines.by_ref().any(str::is_empty), "Missing InRelease body");
    let mut body = String::new();
    let mut signature = false;
    for line in lines.by_ref() {
        if line == "-----BEGIN PGP SIGNATURE-----" {
            signature = true;
            break;
        }
        body.push_str(line.strip_prefix("- ").unwrap_or(line));
        body.push('\n');
    }
    ensure!(
        signature && lines.any(|line| line == "-----END PGP SIGNATURE-----"),
        "Missing InRelease signature"
    );
    Ok(body)
}

fn expiry(release: &Fields, expires: i64) -> Result<()> {
    if let Some(value) = release.get("Valid-Until") {
        let date = value
            .strip_suffix(" UTC")
            .map(|v| format!("{v} +0000"))
            .unwrap_or_else(|| value.clone());
        let until = chrono::DateTime::parse_from_rfc2822(&date)
            .context("Invalid APT Valid-Until")?
            .timestamp();
        ensure!(
            until > chrono::Utc::now().timestamp(),
            "Upstream APT Release is expired"
        );
        ensure!(
            expires <= until,
            "Snapshot expiry exceeds upstream APT Valid-Until"
        );
    }
    Ok(())
}

fn release_members(
    base: &str,
    release: &Fields,
    files: &BTreeMap<String, FileInfo>,
) -> Result<BTreeSet<String>> {
    let checksums = field(release, "SHA256")?.trim();
    ensure!(!checksums.is_empty(), "APT Release needs SHA256 checksums");
    let mut indexes = BTreeSet::new();
    for line in checksums.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        ensure!(parts.len() == 3, "Malformed APT SHA256 entry");
        let member = join_member(base, parts[2])?;
        expected(files, &member, parts[1], parts[0], "sha256")?;
        if matches!(name(parts[2]), "Packages" | "Packages.gz" | "Packages.xz") {
            indexes.insert(member);
        }
    }
    Ok(indexes)
}

fn apt(root: &Path, files: &BTreeMap<String, FileInfo>, expires: i64) -> Result<()> {
    let releases: Vec<_> = files
        .keys()
        .filter(|path| {
            name(path) == "InRelease"
                || (name(path) == "Release"
                    && !files
                        .contains_key(&join_member(parent(path), "InRelease").unwrap_or_default()))
        })
        .collect();
    ensure!(
        !releases.is_empty(),
        "APT snapshot needs signed InRelease or Release + Release.gpg"
    );
    let mut indexes = BTreeSet::new();
    for path in releases {
        let text = metadata(root, path)?;
        let body = if name(path) == "InRelease" {
            release_body(&text)?
        } else {
            ensure!(
                files.contains_key(&format!("{path}.gpg")),
                "Release.gpg is required"
            );
            text
        };
        let paragraphs = paragraphs(&body)?;
        ensure!(
            paragraphs.len() == 1,
            "APT Release must have one metadata paragraph"
        );
        expiry(&paragraphs[0], expires)?;
        indexes.extend(release_members(parent(path), &paragraphs[0], files)?);
    }
    ensure!(
        !indexes.is_empty(),
        "APT snapshot has no supported binary Packages indexes"
    );
    for path in indexes {
        for package in paragraphs(&metadata(root, &path)?)? {
            expected(
                files,
                field(&package, "Filename")?,
                field(&package, "Size")?,
                field(&package, "SHA256")?,
                "sha256",
            )?;
        }
    }
    Ok(())
}

fn xml(text: &str) -> Result<Document<'_>> {
    let data = text.as_bytes();
    ensure!(
        !data
            .windows(9)
            .any(|s| s.eq_ignore_ascii_case(b"<!DOCTYPE"))
            && !data.windows(8).any(|s| s.eq_ignore_ascii_case(b"<!ENTITY")),
        "XML entities and DTDs are not allowed"
    );
    Document::parse_with_options(
        text,
        ParsingOptions {
            allow_dtd: false,
            nodes_limit: XML_NODE_LIMIT,
            entity_resolver: None,
        },
    )
    .context("Invalid or oversized repository XML")
}

fn child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Result<Node<'a, 'input>> {
    let mut matching = node
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == name);
    let found = matching
        .next()
        .with_context(|| format!("Missing XML {name}"))?;
    ensure!(matching.next().is_none(), "Duplicate XML {name}");
    Ok(found)
}
fn attribute<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Result<&'a str> {
    node.attribute(name)
        .with_context(|| format!("Missing XML attribute: {name}"))
}
fn xml_text<'a, 'input>(node: Node<'a, 'input>) -> Result<&'a str> {
    node.text().map(str::trim).context("Missing XML text")
}

fn location<'a, 'input>(node: Node<'a, 'input>) -> Result<&'a str> {
    ensure!(
        !node
            .ancestors()
            .any(|ancestor| ancestor.attributes().any(|a| a.name() == "base")),
        "External DNF locations are not a complete snapshot"
    );
    attribute(node, "href")
}

fn primary_path(root: &Path, path: &str, files: &BTreeMap<String, FileInfo>) -> Result<String> {
    let text = metadata(root, path)?;
    let document = xml(&text)?;
    ensure!(
        document.root_element().tag_name().name() == "repomd",
        "Expected DNF repomd XML"
    );
    let base = parent(parent(path));
    let mut primary = None;
    for entry in document
        .root_element()
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "data")
    {
        let member = join_member(base, location(child(entry, "location")?)?)?;
        let checksum = child(entry, "checksum")?;
        expected(
            files,
            &member,
            xml_text(child(entry, "size")?)?,
            xml_text(checksum)?,
            attribute(checksum, "type")?,
        )?;
        if attribute(entry, "type")? == "primary" {
            ensure!(primary.is_none(), "Multiple DNF primary indexes");
            primary = Some(member);
        }
    }
    let primary = primary.context("DNF needs an XML primary index")?;
    ensure!(
        [".xml", ".xml.gz", ".xml.xz"]
            .iter()
            .any(|suffix| primary.ends_with(suffix)),
        "Unsupported DNF primary index format"
    );
    Ok(primary)
}

fn dnf(root: &Path, files: &BTreeMap<String, FileInfo>) -> Result<()> {
    let repositories: Vec<_> = files
        .keys()
        .filter(|p| p.as_str() == "repodata/repomd.xml" || p.ends_with("/repodata/repomd.xml"))
        .collect();
    ensure!(
        !repositories.is_empty(),
        "DNF snapshot needs repodata/repomd.xml"
    );
    for path in repositories {
        ensure!(
            files.contains_key(&format!("{path}.asc")),
            "DNF repomd.xml.asc signature is required"
        );
        let primary = primary_path(root, path, files)?;
        let text = metadata(root, &primary)?;
        let document = xml(&text)?;
        ensure!(
            document.root_element().tag_name().name() == "metadata",
            "Expected DNF package metadata XML"
        );
        let base = parent(parent(path));
        for package in document
            .root_element()
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "package")
        {
            let member = join_member(base, location(child(package, "location")?)?)?;
            let checksum = child(package, "checksum")?;
            expected(
                files,
                &member,
                attribute(child(package, "size")?, "package")?,
                xml_text(checksum)?,
                attribute(checksum, "type")?,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Write;
    struct Fixture {
        dir: tempfile::TempDir,
        files: BTreeMap<String, FileInfo>,
    }
    impl Fixture {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
                files: BTreeMap::new(),
            }
        }
        fn add(&mut self, name: &str, bytes: &[u8]) {
            let path = self.dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
            self.files.insert(
                name.into(),
                FileInfo {
                    size: bytes.len() as u64,
                    sha256: hex::encode(Sha256::digest(bytes)),
                },
            );
        }
        fn apt(&mut self, valid_until: &str) {
            self.add("pool/a.deb", b"a package");
            let p = &self.files["pool/a.deb"];
            self.add(
                "dists/stable/main/Packages",
                format!(
                    "Package: a\nFilename: pool/a.deb\nSize: {}\nSHA256: {}\n",
                    p.size, p.sha256
                )
                .as_bytes(),
            );
            let p = &self.files["dists/stable/main/Packages"];
            self.add("dists/stable/InRelease", format!("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: fixture\n{valid_until}SHA256:\n {} {} main/Packages\n-----BEGIN PGP SIGNATURE-----\nfixture-only\n-----END PGP SIGNATURE-----\n", p.sha256, p.size).as_bytes());
        }
        fn dnf(&mut self, extra: &str) {
            self.add("Packages/a.rpm", b"a package");
            let p = &self.files["Packages/a.rpm"];
            self.add("repodata/primary.xml", format!("<metadata xmlns='http://linux.duke.edu/metadata/common'><package><location href='Packages/a.rpm' {extra}/><checksum type='sha256'>{}</checksum><size package='{}'/></package></metadata>",p.sha256,p.size).as_bytes());
            let p = &self.files["repodata/primary.xml"];
            self.add("repodata/repomd.xml", format!("<repomd xmlns='http://linux.duke.edu/metadata/repo'><data type='primary'><location href='repodata/primary.xml'/><checksum type='sha256'>{}</checksum><size>{}</size></data></repomd>",p.sha256,p.size).as_bytes());
            self.add(
                "repodata/repomd.xml.asc",
                b"signature fixture, native client verifies it",
            );
        }
    }
    #[test]
    fn apt_requires_complete_unchanged_package_closure() {
        let mut f = Fixture::new();
        f.apt("");
        validate("apt", f.dir.path(), &f.files, 1).unwrap();
        f.files.get_mut("pool/a.deb").unwrap().sha256 = "0".repeat(64);
        assert!(validate("apt", f.dir.path(), &f.files, 1).is_err());
        f.files.remove("pool/a.deb");
        assert!(validate("apt", f.dir.path(), &f.files, 1).is_err());
    }
    #[test]
    fn apt_rejects_expired_and_overlong_snapshot_lifetimes() {
        let mut f = Fixture::new();
        f.apt("Valid-Until: Fri, 01 Jan 2021 00:00:00 UTC\n");
        assert!(validate("apt", f.dir.path(), &f.files, 1).is_err());
        let future = chrono::Utc::now() + chrono::Duration::days(1);
        f.apt(&format!("Valid-Until: {}\n", future.to_rfc2822()));
        validate("apt", f.dir.path(), &f.files, future.timestamp() - 1).unwrap();
        assert!(validate("apt", f.dir.path(), &f.files, future.timestamp() + 1).is_err());
    }
    #[test]
    fn apt_detached_signature_presence_is_required() {
        let mut f = Fixture::new();
        f.apt("");
        let data = metadata(f.dir.path(), "dists/stable/InRelease").unwrap();
        f.files.remove("dists/stable/InRelease");
        f.add(
            "dists/stable/Release",
            release_body(&data).unwrap().as_bytes(),
        );
        assert!(validate("apt", f.dir.path(), &f.files, 1).is_err());
        f.add("dists/stable/Release.gpg", b"signature fixture");
        validate("apt", f.dir.path(), &f.files, 1).unwrap();
    }
    #[test]
    fn malformed_fields_signatures_and_paths_fail() {
        assert!(paragraphs("Size: 1\nSize: 2").is_err());
        assert!(paragraphs(" continuation").is_err());
        assert!(paragraphs("invalid").is_err());
        assert!(release_body("-----BEGIN PGP SIGNED MESSAGE-----\n\nOrigin: a").is_err());
        assert!(join_member("dists", "../pool/a").is_err());
        assert!(join_member("", "https://host/a").is_err());
    }
    #[test]
    fn dnf_verifies_indexes_packages_and_signature_presence() {
        let mut f = Fixture::new();
        f.dnf("");
        validate("dnf", f.dir.path(), &f.files, 1).unwrap();
        f.files.remove("repodata/repomd.xml.asc");
        assert!(validate("dnf", f.dir.path(), &f.files, 1).is_err());
        f.add("repodata/repomd.xml.asc", b"signature");
        f.files.get_mut("Packages/a.rpm").unwrap().size += 1;
        assert!(validate("dnf", f.dir.path(), &f.files, 1).is_err());
    }
    #[test]
    fn dnf_rejects_external_locations_and_xml_entities() {
        let mut f = Fixture::new();
        f.dnf("xml:base='https://example.invalid/'");
        assert!(validate("dnf", f.dir.path(), &f.files, 1).is_err());
        assert!(xml(
            "<!DOCTYPE metadata [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><metadata>&x;</metadata>"
        )
        .is_err());
        assert!(xml("<!DOCTYPE metadata><metadata/>").is_err());
        let doc =
            xml("<metadata xml:base='https://example.invalid'><location href='a'/></metadata>")
                .unwrap();
        assert!(location(child(doc.root_element(), "location").unwrap()).is_err());
    }
    #[test]
    fn metadata_decoders_bound_output_and_reject_broken_xz() {
        let mut f = Fixture::new();
        let bytes = b"Package: a\n";
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(bytes).unwrap();
        f.add("a.gz", &gzip.finish().unwrap());
        let mut xz = liblzma::write::XzEncoder::new(Vec::new(), 1);
        xz.write_all(bytes).unwrap();
        let compressed = xz.finish().unwrap();
        f.add("a.xz", &compressed);
        assert_eq!(metadata(f.dir.path(), "a.gz").unwrap().as_bytes(), bytes);
        assert_eq!(metadata(f.dir.path(), "a.xz").unwrap().as_bytes(), bytes);
        f.add("truncated.xz", &compressed[..compressed.len() - 1]);
        assert!(metadata(f.dir.path(), "truncated.xz").is_err());
        f.add(
            "trailing.xz",
            &[compressed.as_slice(), b"trailing"].concat(),
        );
        assert!(metadata(f.dir.path(), "trailing.xz").is_err());
        f.add(
            "concat.xz",
            &[compressed.as_slice(), compressed.as_slice()].concat(),
        );
        assert!(metadata(f.dir.path(), "concat.xz").is_err());
        assert!(read_limited(&b"five!"[..], 4).is_err());
        assert_eq!(read_limited(&b"four"[..], 4).unwrap(), b"four");
    }
    #[test]
    fn chocolatey_accepts_only_flat_packages() {
        let mut f = Fixture::new();
        assert!(validate("chocolatey", f.dir.path(), &f.files, 1).is_err());
        f.add("a.nupkg", b"package");
        validate("chocolatey", f.dir.path(), &f.files, 1).unwrap();
        f.add("dir/b.nupkg", b"package");
        assert!(validate("chocolatey", f.dir.path(), &f.files, 1).is_err());
        assert!(validate("unknown", f.dir.path(), &f.files, 1).is_err());
    }
}
