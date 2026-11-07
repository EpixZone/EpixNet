#!/usr/bin/env python3
"""Snapshot and transport regressions. Native package-manager checks live alongside these."""
import datetime as dt
import gzip
import hashlib
import http.server
import io
import json
import lzma
from pathlib import Path
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
from types import SimpleNamespace
from unittest.mock import patch

from package_mirror import snapshot as mirror
from package_mirror import formats
from package_mirror.server import checked_stream, make_server

ADDRESS = "epix1avgz3gmc5rq7635z450gnlpq9cg64c34wg2wet"


def expiry(days=1):
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)).isoformat()


class Mirrors(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.destination = self.root / "staged"

    def put(self, name, data):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def stage(self, manager="homebrew", **args):
        return mirror.stage(self.source, self.destination, manager, expiry(), **args)

    def archive(self, alterations=None):
        stream = io.BytesIO()
        files = {p.relative_to(self.destination).as_posix(): p.read_bytes()
                 for p in self.destination.rglob("*") if p.is_file()}
        files["content.json"] = json.dumps({"address": ADDRESS}).encode()
        files.update(alterations or {})
        with zipfile.ZipFile(stream, "w") as archive:
            for name, value in files.items():
                if value is not None:
                    archive.writestr(name, value)
        stream.seek(0)
        return stream

    def serve(self):
        server = make_server(self.destination, 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}"

    def test_bytes_preserved_and_atomic_existing_output_untouched(self):
        original = self.put("artifact.bin", b"original\x00bytes")
        self.stage()
        self.assertEqual((self.destination / "repo/artifact.bin").read_bytes(), original.read_bytes())
        with self.assertRaisesRegex(ValueError, "exists"):
            self.stage()
        self.assertEqual((self.destination / "repo/artifact.bin").read_bytes(), original.read_bytes())

    def test_missing_package_rejects_without_partial_snapshot(self):
        index = b"Package: fixture\nVersion: 1\nFilename: pool/missing.deb\nSize: 4\nSHA256: " + b"a" * 64 + b"\n"
        self.put("dists/stable/main/binary-amd64/Packages", index)
        self.put("dists/stable/Release", b"SHA256:\n " + hashlib.sha256(index).hexdigest().encode()
                 + f" {len(index)} main/binary-amd64/Packages\n".encode())
        self.put("dists/stable/Release.gpg", b"native client verifies this signature")
        with self.assertRaisesRegex(ValueError, "Missing or changed"):
            self.stage("apt")
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".epix-mirror-*")), [])

    def test_expired_apt_release_not_renewed_by_new_catalog(self):
        self.put("Release", b"Valid-Until: Wed, 01 Jan 2020 00:00:00 UTC\nSHA256:\n abc 1 Packages\n")
        self.put("Release.gpg", b"signature")
        with self.assertRaisesRegex(ValueError, "expired"):
            self.stage("apt")

    def test_incomplete_dnf_rejected(self):
        self.put("repodata/repomd.xml", b'<repomd><data type="primary"><location href="repodata/missing.xml.gz"/>'
                 b'<checksum type="sha256">' + b"a" * 64 + b'</checksum><size>7</size></data></repomd>')
        self.put("repodata/repomd.xml.asc", b"signature")
        with self.assertRaisesRegex(ValueError, "Missing or changed"):
            self.stage("dnf")

    def test_source_paths_and_private_identity_rejected(self):
        for name in ("users.json", ".git/config", "con.txt", "bad:name", "nested/../escape"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    if name == "users.json":
                        self.put(name, b"private")
                        self.stage()
                        (self.source / name).unlink()
                    else:
                        mirror.safe_path(name)
        (self.source / "users.json").unlink(missing_ok=True)
        try:
            (self.source / "link").symlink_to(self.root, target_is_directory=True)
        except OSError:
            if os.name == "nt":
                return  # Some Windows runners do not grant symlink creation.
            raise
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.stage()

    def test_case_collision_and_duplicate_json_rejected(self):
        info = {"size": 1, "sha256": "a" * 64}
        with self.assertRaisesRegex(ValueError, "collision"):
            mirror.limits({"One": info, "one": info})
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            mirror.decode(b'{"files":{},"files":{}}')

    def test_serving_descriptor_is_not_reopened_after_validation(self):
        original = self.put("file", b"original")
        expected = mirror.checksum(original)
        with checked_stream(original, expected) as reader:
            if os.name != "nt":  # Windows itself refuses replacing this open file.
                replacement = self.put("replacement", b"replaced")
                replacement.replace(original)
            self.assertEqual(reader.read(), b"original")
        with patch("package_mirror.server.digest_stream", return_value=expected):
            with self.assertRaises(ValueError):
                checked_stream(original, {"size": 999, "sha256": expected["sha256"]})

    def test_catalog_reads_are_bounded_before_json_parse(self):
        self.put("file", b"data")
        self.stage()
        with (self.destination / mirror.CATALOG).open("wb") as writer:
            writer.truncate(mirror.MAX_CATALOG + 1)
        with self.assertRaisesRegex(ValueError, "8 MiB"):
            mirror.validate(self.destination)

    def test_expanded_metadata_and_xz_memory_are_bounded(self):
        payload = b"metadata" * 1000
        self.put("index.gz", gzip.compress(payload))
        self.put("index.xz", lzma.compress(payload))
        self.assertEqual(formats.metadata(self.source, "index.xz"), payload)
        with patch.object(formats, "METADATA_LIMIT", 1024):
            with self.assertRaises(ValueError):
                formats.metadata(self.source, "index.gz")
            with self.assertRaises(lzma.LZMAError):
                formats.metadata(self.source, "index.xz")

    def test_insufficient_disk_space_leaves_no_partial_output(self):
        self.put("file", b"public")
        with patch("package_mirror.snapshot.shutil.disk_usage", return_value=SimpleNamespace(free=1)):
            with self.assertRaisesRegex(ValueError, "disk space"):
                self.stage()
        self.assertFalse(self.destination.exists())

    def test_atomic_export_tampering_missing_member_and_traversal(self):
        self.put("artifact", b"right")
        self.stage()
        for changes in ({"repo/artifact": b"wrong"}, {"repo/artifact": None}, {"../outside": b"bad"},
                        {"content.json": b'{"address":"other"}'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                with mirror.pending(self.root / "exported") as target:
                    mirror.unpack(self.archive(changes), target, ADDRESS)
            self.assertFalse((self.root / "exported").exists())
        with mirror.pending(self.root / "exported") as target:
            mirror.unpack(self.archive(), target, ADDRESS)
        self.assertEqual((self.root / "exported/repo/artifact").read_bytes(), b"right")

    def test_export_http_contract_and_operator_pin(self):
        self.put("artifact", b"right")
        catalog = self.stage()
        payload = self.archive().getvalue()
        requests = []
        class Node(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.path, dict(self.headers)))
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            def log_message(self, *_args):
                pass
        node = http.server.HTTPServer(("127.0.0.1", 0), Node)
        thread = threading.Thread(target=node.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(node.server_close)
        self.addCleanup(node.shutdown)
        origin = f"http://127.0.0.1:{node.server_port}"
        with patch.dict(os.environ, {"http_proxy": "http://invalid.example:1"}):
            mirror.export(origin, ADDRESS, self.root / "received", expected_snapshot=catalog["snapshot"])
        self.assertEqual(requests[0][0], f"/EpixNet-Internal/Zip?address={ADDRESS}")
        self.assertEqual(requests[0][1]["Referer"], f"{origin}/{ADDRESS}/")
        self.assertEqual((self.root / "received/repo/artifact").read_bytes(), b"right")
        with self.assertRaisesRegex(ValueError, "pinned digest"):
            mirror.export(origin, ADDRESS, self.root / "rejected", expected_snapshot="0" * 64)
        self.assertFalse((self.root / "rejected").exists())

    def test_loopback_only_no_hostname_credentials_or_redirect(self):
        for value in ("https://127.0.0.1:1", "http://localhost:1", "http://example.com:1", "http://10.0.0.1:1",
                      "http://u:p@127.0.0.1:1", "http://127.0.0.1:1/path", "http://127.0.0.1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                mirror.node_origin(value)
        self.assertEqual(mirror.node_origin("http://[::1]:42222/"), "http://[::1]:42222")
        with self.assertRaises(ValueError):
            mirror.NoRedirect().redirect_request(None)

    def test_http_only_catalog_paths_host_gate_and_ranges(self):
        self.put("test.nupkg", b"0123456789")
        self.stage("chocolatey")
        url = self.serve()
        with urllib.request.urlopen(url + "/test.nupkg") as response:
            self.assertEqual(response.read(), b"0123456789")
            self.assertNotIn("Access-Control-Allow-Origin", response.headers)
        request = urllib.request.Request(url + "/test.nupkg", headers={"Range": "bytes=2-5"})
        with urllib.request.urlopen(request) as response:
            self.assertEqual((response.status, response.read()), (206, b"2345"))
        for path, headers, method, status in (("/", {}, "GET", 404), ("/../epix-mirror.json", {}, "GET", 404),
                ("/Config", {}, "GET", 404), ("/test.nupkg", {"Host": "evil.test"}, "GET", 403),
                ("/test.nupkg", {}, "POST", 501), ("/test.nupkg", {"Range": "bytes=100-"}, "GET", 416)):
            with self.subTest(path=path, method=method, headers=headers), self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(urllib.request.Request(url + path, headers=headers, method=method))
            self.assertEqual(error.exception.code, status)
            error.exception.close()
        (self.destination / "repo/test.nupkg").write_bytes(b"changed")
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(url + "/test.nupkg")
        self.assertEqual(error.exception.code, 409)
        error.exception.close()

    def test_homebrew_exact_url_and_oci_routes_never_proxy(self):
        self.put("source.tar.gz", b"archive")
        mapping = self.root / "map.json"
        mapping.write_text(json.dumps({"/https://upstream.example/app.tar.gz": "source.tar.gz",
                                       "/v2/homebrew/core/app/blobs/sha256:abcd": "source.tar.gz"}))
        self.stage(url_map=mapping)
        url = self.serve()
        for route in json.loads(mapping.read_text()):
            with urllib.request.urlopen(url + route) as response:
                self.assertEqual(response.read(), b"archive")
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(url + "/https://unlisted.example/secret")
        self.assertEqual(error.exception.code, 404)
        error.exception.close()

    def test_expired_catalog_refused_and_signature_not_fabricated(self):
        self.put("test.nupkg", b"package")
        catalog = self.stage("chocolatey")
        catalog["expires"] = expiry(-1)
        unsigned = {k: v for k, v in catalog.items() if k != "snapshot"}
        catalog["snapshot"] = hashlib.sha256(mirror.encode(unsigned)).hexdigest()
        (self.destination / mirror.CATALOG).write_bytes(mirror.encode(catalog))
        with self.assertRaisesRegex(ValueError, "expired"):
            mirror.validate(self.destination)
        self.assertFalse((self.destination / "content.json").exists())


if __name__ == "__main__":
    unittest.main()
