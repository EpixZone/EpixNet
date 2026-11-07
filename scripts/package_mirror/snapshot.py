"""Immutable snapshots. Network import trusts only the node's verified ZIP exporter."""
import contextlib
import datetime as dt
import hashlib
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import urllib.parse
import urllib.request
import zipfile

from . import formats

CATALOG = "epix-mirror.json"
MAX_FILES = 60_000
MAX_BYTES = 15 * 1024**3
MAX_FILE = 8 * 1024**3
MAX_CATALOG = 8 * 1024**2
CHUNK = 128 * 1024
MANAGERS = ("apt", "dnf", "homebrew", "chocolatey")


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def decode(data):
    if len(data) > MAX_CATALOG:
        raise ValueError("Metadata exceeds 8 MiB")
    return json.loads(data, object_pairs_hook=unique)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"


def read_metadata(path):
    with Path(path).open("rb") as reader:
        data = reader.read(MAX_CATALOG + 1)
    if len(data) > MAX_CATALOG:
        raise ValueError("Metadata exceeds 8 MiB")
    return data


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Expiry must be an ISO8601 timestamp")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Expiry must include a timezone")
    return parsed.timestamp()


def fresh(catalog):
    if timestamp(catalog["expires"]) <= dt.datetime.now(dt.timezone.utc).timestamp():
        raise ValueError("Snapshot expired; obtain a fresh signed snapshot")


def safe_path(value):
    if not isinstance(value, str) or len(value) > 900:
        raise ValueError("Invalid snapshot path")
    parts = value.split("/")
    if not parts or any(not part or part in (".", "..") or part.startswith(".")
                        or part.endswith((".", " ")) for part in parts):
        raise ValueError(f"Unsafe snapshot path: {value}")
    if re.search(r'[\\:\x00-\x1f\x7f<>"|?*]', value):
        raise ValueError(f"Non-portable snapshot path: {value}")
    for part in parts:
        if part.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)),
                                           *(f"LPT{i}" for i in range(10))}:
            raise ValueError("Windows device path is not allowed")
    return value


def regular(root, relative):
    safe_path(relative)
    path = root
    for part in relative.split("/"):
        path /= part
        if path.is_symlink():
            raise ValueError(f"Symlink is not allowed: {relative}")
    if not path.is_file():
        raise ValueError(f"Missing regular file: {relative}")
    return path


def digest_stream(source, target=None):
    digest = hashlib.sha256()
    length = 0
    while chunk := source.read(CHUNK):
        length += len(chunk)
        if length > MAX_FILE:
            raise ValueError("File exceeds 8 GiB")
        digest.update(chunk)
        if target is not None:
            target.write(chunk)
    return {"size": length, "sha256": digest.hexdigest()}


def checksum(path):
    with path.open("rb") as source:
        return digest_stream(source)


def ensure_space(directory, required):
    if shutil.disk_usage(directory).free < required + 64 * 1024**2:
        raise ValueError("Not enough free disk space for this snapshot")


@contextlib.contextmanager
def pending(output):
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists; use a new immutable snapshot directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".epix-mirror-", dir=output.parent))
    try:
        yield temporary
        # Never replace an existing directory, including an empty one.
        if output.exists() or output.is_symlink():
            raise ValueError("Output appeared during import")
        temporary.rename(output)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def limits(files):
    if not isinstance(files, dict) or not files or len(files) > MAX_FILES:
        raise ValueError("Snapshot must contain 1 to 60,000 files")
    folded = set()
    total = 0
    for path, info in files.items():
        safe_path(path)
        if path.casefold() in folded:
            raise ValueError("Case-insensitive path collision")
        folded.add(path.casefold())
        if not isinstance(info, dict) or set(info) != {"size", "sha256"} or type(info["size"]) is not int or not 0 <= info["size"] <= MAX_FILE:
            raise ValueError("Invalid file metadata")
        if not isinstance(info["sha256"], str) or not re.fullmatch("[0-9a-f]{64}", info["sha256"]):
            raise ValueError("Invalid SHA256 digest")
        total += info["size"]
    if total > MAX_BYTES:
        raise ValueError("Snapshot exceeds 15 GiB")


def routes(mapping, files):
    if not isinstance(mapping, dict) or len(mapping) > MAX_FILES:
        raise ValueError("Invalid artifact URL map")
    for route, path in mapping.items():
        if not isinstance(path, str) or path not in files or not isinstance(route, str) or not route.startswith("/") or len(route) > 4096:
            raise ValueError("Invalid artifact route")
        if any(ord(c) < 32 or ord(c) == 127 for c in route) or "#" in route or "\\" in route:
            raise ValueError("Invalid artifact route characters")
        # Every request is an exact catalog lookup. These are names, never fetched URLs.
        if not (route.startswith("/https://") or route.startswith("/http://") or route.startswith("/v2/")):
            raise ValueError("Homebrew routes must be /https://..., /http://... or /v2/...")


def catalog_check(catalog):
    if not isinstance(catalog, dict) or set(catalog) != {"version", "manager", "expires", "files", "routes", "snapshot"} or catalog["version"] != 1:
        raise ValueError("Unsupported snapshot catalog")
    if catalog["manager"] not in MANAGERS:
        raise ValueError("Unsupported package manager")
    limits(catalog["files"])
    routes(catalog["routes"], catalog["files"])
    if catalog["manager"] != "homebrew" and catalog["routes"]:
        raise ValueError("Artifact routes are only for Homebrew")
    unsigned = {k: v for k, v in catalog.items() if k != "snapshot"}
    if catalog["snapshot"] != hashlib.sha256(encode(unsigned)).hexdigest():
        raise ValueError("Catalog snapshot digest mismatch")
    fresh(catalog)


def validate(root):
    root = Path(root)
    catalog = decode(read_metadata(regular(root, CATALOG)))
    catalog_check(catalog)
    for relative, expected in catalog["files"].items():
        if checksum(regular(root, "repo/" + relative)) != expected:
            raise ValueError(f"Snapshot file changed: {relative}")
    formats.validate(catalog["manager"], root / "repo", catalog["files"], timestamp(catalog["expires"]))
    return catalog


def stage(source, output, manager, expires, url_map=None):
    source = Path(source).resolve(strict=True)
    output = Path(output).absolute()
    if source == output or source in output.parents:
        raise ValueError("Output must be outside the public source directory")
    files = {}
    total = 0
    mapping = decode(read_metadata(url_map)) if url_map else {}
    with pending(output) as destination:
        for folder, directories, names in os.walk(source, followlinks=False):
            for name in directories + names:
                candidate = Path(folder) / name
                relative = candidate.relative_to(source).as_posix()
                safe_path(relative)
                if any(part.lower() == "private" for part in relative.split("/")):
                    raise ValueError("Private directories must not be staged as public repository files")
                if candidate.is_symlink():
                    raise ValueError("Source contains a symlink")
            for name in names:
                original = Path(folder) / name
                relative = original.relative_to(source).as_posix()
                if name.lower() in ("users.json", "content.json", "privatekey", "secring.gpg"):
                    raise ValueError("Source contains identity/signing data; select only public repository files")
                if not stat.S_ISREG(original.stat().st_mode):
                    raise ValueError("Source contains a non-regular file")
                size = original.stat().st_size
                if size > MAX_FILE or total + size > MAX_BYTES:
                    raise ValueError("Source exceeds snapshot byte limits")
                ensure_space(destination, size)
                target = destination / "repo" / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                with original.open("rb") as reader, target.open("xb") as writer:
                    files[relative] = digest_stream(reader, writer)
                total += files[relative]["size"]
                if len(files) > MAX_FILES or total > MAX_BYTES:
                    raise ValueError("Snapshot exceeds file count or total byte limit")
        catalog = {"version": 1, "manager": manager, "expires": expires, "files": files, "routes": mapping}
        catalog["snapshot"] = hashlib.sha256(encode(catalog)).hexdigest()
        (destination / CATALOG).write_bytes(encode(catalog))
        validate(destination)
    return catalog


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise ValueError("Node redirected export; refusing to forward credentials")


def node_origin(value):
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("Node must be an http:// loopback origin without credentials or path")
    # Literal addresses avoid DNS rebinding and local resolver/proxy surprises.
    if not ipaddress.ip_address(parsed.hostname).is_loopback:
        raise ValueError("Only a local EpixNet node may verify an export")
    if parsed.port is None:
        raise ValueError("Specify the node's UI port")
    return value.rstrip("/")


def unpack(archive, destination, address):
    with zipfile.ZipFile(archive) as zipped:
        infos = zipped.infolist()
        if len(infos) > 65_536 or sum(i.file_size for i in infos) > 16 * 1024**3:
            raise ValueError("Export exceeds supported ZIP limits")
        by_name = {}
        folded = set()
        for info in infos:
            safe_path(info.filename)
            if info.filename.casefold() in folded or stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError("Duplicate or symlink ZIP member")
            folded.add(info.filename.casefold())
            by_name[info.filename] = info
        def read_small(name):
            if by_name[name].file_size > MAX_CATALOG:
                raise ValueError("Export metadata exceeds 8 MiB")
            return zipped.read(name)
        manifest = decode(read_small("content.json"))
        if manifest.get("address") != address:
            raise ValueError("Node export address does not match requested xite")
        catalog_bytes = read_small(CATALOG)
        catalog = decode(catalog_bytes)
        catalog_check(catalog)
        ensure_space(destination, sum(info["size"] for info in catalog["files"].values()))
        for relative, expected in catalog["files"].items():
            name = "repo/" + relative
            info = by_name.get(name)
            if info is None or info.file_size != expected["size"]:
                raise ValueError(f"Incomplete export: {relative}")
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with zipped.open(info) as reader, target.open("xb") as writer:
                actual = digest_stream(reader, writer)
            if actual != expected:
                raise ValueError(f"Export checksum mismatch: {relative}")
        (destination / CATALOG).write_bytes(catalog_bytes)
        (destination / "epix-export.json").write_bytes(encode({"address": address,
            "manifest_sha256": hashlib.sha256(read_small("content.json")).hexdigest()}))
        validate(destination)
        return catalog


def export(node, address, output, cookie_file=None, expected_snapshot=None):
    origin = node_origin(node)
    if not re.fullmatch(r"epix1[023456789acdefghjklmnpqrstuvwxyz]{38}", address):
        raise ValueError("Use a canonical epix1 address; the node validates its checksum")
    cookies = http.cookiejar.MozillaCookieJar(cookie_file)
    if cookie_file:
        cookies.load(ignore_discard=True, ignore_expires=False)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                        urllib.request.HTTPCookieProcessor(cookies))
    request = urllib.request.Request(origin + "/EpixNet-Internal/Zip?" + urllib.parse.urlencode({"address": address}),
                                     headers={"Origin": origin, "Referer": origin + "/" + address + "/"})
    with pending(output) as destination:
        # Spool inside the selected destination filesystem, never into an unbounded memory buffer.
        with tempfile.TemporaryFile(dir=destination) as archive:
            with opener.open(request, timeout=300) as response:
                if response.status != 200 or response.headers.get_content_type() != "application/zip":
                    raise ValueError("Node did not return a verified ZIP; check xite availability and authentication")
                declared_length = int(response.headers.get("Content-Length", "-1"))
                if not 0 <= declared_length <= 16 * 1024**3 + 64 * 1024**2:
                    raise ValueError("Node export has an invalid length")
                ensure_space(destination, declared_length)
                length = 0
                while chunk := response.read(CHUNK):
                    length += len(chunk)
                    if length > 16 * 1024**3 + 64 * 1024**2:
                        raise ValueError("Node export exceeds 16 GiB")
                    archive.write(chunk)
                if length != declared_length:
                    raise ValueError("Node export was truncated or changed length")
            archive.seek(0)
            catalog = unpack(archive, destination, address)
        if expected_snapshot and catalog["snapshot"] != expected_snapshot:
            raise ValueError("Snapshot does not match the operator's pinned digest")
    return catalog
