"""Check snapshot completeness; native clients still verify upstream signatures."""
import datetime as dt
import email.utils
import gzip
import lzma
import re
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath

METADATA_LIMIT = 64 * 1024 * 1024


def paragraphs(text):
    for paragraph in re.split(r"\n\s*\n", text.strip()):
        fields = {}
        key = None
        for line in paragraph.splitlines():
            if line.startswith((" ", "\t")) and key:
                fields[key] += "\n" + line[1:]
            elif ":" in line:
                key, value = line.split(":", 1)
                if key in fields:
                    raise ValueError("Duplicate repository metadata field")
                fields[key] = value.strip()
            elif line:
                raise ValueError("Malformed repository metadata")
        yield fields


def metadata(root, path):
    source = root / path
    if path.endswith(".xz"):
        return xz_metadata(source)
    opener = gzip.open if path.endswith(".gz") else open
    with opener(source, "rb") as handle:
        data = handle.read(METADATA_LIMIT + 1)
    if len(data) > METADATA_LIMIT:
        raise ValueError("Expanded repository metadata exceeds 64 MiB")
    return data


def xz_metadata(source):
    decoder = lzma.LZMADecompressor(memlimit=METADATA_LIMIT)
    result = bytearray()
    with source.open("rb") as reader:
        while not decoder.eof:
            chunk = reader.read(64 * 1024) if decoder.needs_input else b""
            if decoder.needs_input and not chunk:
                raise ValueError("Truncated xz metadata")
            result.extend(decoder.decompress(chunk, max_length=METADATA_LIMIT + 1 - len(result)))
            if len(result) > METADATA_LIMIT:
                raise ValueError("Expanded repository metadata exceeds 64 MiB")
        if decoder.unused_data or reader.read(1):
            raise ValueError("Trailing or concatenated xz metadata is not supported")
    return bytes(result)


def expected(files, path, size, digest, algorithm="sha256"):
    if algorithm != "sha256":
        raise ValueError("This snapshot format requires SHA256 repository checksums")
    entry = files.get(path)
    if entry is None or entry["size"] != int(size) or entry["sha256"] != digest.lower():
        raise ValueError(f"Missing or changed repository member: {path}")


def apt(root, files, expires):
    releases = [p for p in files if p == "InRelease" or p.endswith("/InRelease")]
    releases += [p for p in files if (p == "Release" or p.endswith("/Release"))
                 and str(PurePosixPath(p).with_name("InRelease")) not in files]
    if not releases:
        raise ValueError("APT snapshot needs signed InRelease or Release + Release.gpg")
    package_indexes = set()
    for path in releases:
        data = metadata(root, path).decode("utf-8")
        if path.endswith("InRelease"):
            if not data.startswith("-----BEGIN PGP SIGNED MESSAGE-----\n"):
                raise ValueError("Malformed InRelease")
            data = data.split("\n\n", 1)[1].split("-----BEGIN PGP SIGNATURE-----", 1)[0]
            data = "\n".join(line[2:] if line.startswith("- ") else line for line in data.splitlines())
        elif path + ".gpg" not in files:
            raise ValueError("Release.gpg is required")
        release = next(paragraphs(data))
        if "Valid-Until" in release:
            until = email.utils.parsedate_to_datetime(release["Valid-Until"]).timestamp()
            if until <= dt.datetime.now(dt.timezone.utc).timestamp():
                raise ValueError("Upstream APT Release is expired")
            if expires > until:
                raise ValueError("Snapshot expiry exceeds upstream APT Valid-Until")
        base = PurePosixPath(path).parent
        checksums = release.get("SHA256", "").strip().splitlines()
        if not checksums:
            raise ValueError("APT Release needs SHA256 checksums")
        for line in checksums:
            digest, size, relative = line.split()
            member = str(base / relative)
            expected(files, member, size, digest)
            if PurePosixPath(relative).name in ("Packages", "Packages.gz", "Packages.xz"):
                package_indexes.add(member)
    if not package_indexes:
        raise ValueError("APT snapshot has no supported binary Packages indexes")
    for path in package_indexes:
        for package in paragraphs(metadata(root, path).decode("utf-8")):
            expected(files, package["Filename"], package["Size"], package["SHA256"])


def xml(data):
    # ElementTree does not fetch external entities; reject entity expansion too.
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("XML entities are not allowed")
    return ET.fromstring(data)


def dnf(root, files, _expires):
    repos = [p for p in files if p == "repodata/repomd.xml" or p.endswith("/repodata/repomd.xml")]
    if not repos:
        raise ValueError("DNF snapshot needs repodata/repomd.xml")
    for path in repos:
        if path + ".asc" not in files:
            raise ValueError("DNF repomd.xml.asc signature is required")
        base = PurePosixPath(path).parent.parent
        primary = None
        for entry in xml(metadata(root, path)).findall("{*}data"):
            location = entry.find("{*}location")
            checksum = entry.find("{*}checksum")
            size = entry.find("{*}size")
            member = str(base / location.attrib["href"])
            expected(files, member, size.text, checksum.text, checksum.attrib["type"])
            if entry.attrib["type"] == "primary":
                primary = member
        if primary is None or not primary.endswith((".xml", ".xml.gz", ".xml.xz")):
            raise ValueError("DNF needs a supported XML primary index (.xml, .gz or .xz)")
        for package in xml(metadata(root, primary)).findall("{*}package"):
            location = package.find("{*}location")
            if any(key.endswith("base") for key in location.attrib):
                raise ValueError("External DNF package locations are not a complete snapshot")
            checksum = package.find("{*}checksum")
            expected(files, str(base / location.attrib["href"]),
                     package.find("{*}size").attrib["package"], checksum.text, checksum.attrib["type"])


def chocolatey(_root, files, _expires):
    if not files or any("/" in p or not p.lower().endswith(".nupkg") for p in files):
        raise ValueError("Chocolatey source must contain only flat .nupkg files")


def validate(manager, root, files, expires):
    if manager == "homebrew":
        return  # Artifact closure is selected by the pinned formula/tap, not a repository index.
    {"apt": apt, "dnf": dnf, "chocolatey": chocolatey}[manager](root, files, expires)
