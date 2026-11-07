"""Read-only loopback transport for a validated immutable snapshot."""
import http.server
import mimetypes
import os
from pathlib import Path
import re
import stat
import urllib.parse

from .snapshot import CHUNK, digest_stream, fresh, regular, validate


def checked_stream(path, expected):
    # Use the same descriptor for validation and serving, even if the pathname
    # is replaced. Reject a leaf symlink where the OS provides O_NOFOLLOW.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    stream = os.fdopen(os.open(path, flags), "rb")
    try:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size != expected["size"]:
            raise ValueError("Snapshot member is not the expected regular file")
        actual = digest_stream(stream)
        after = os.fstat(stream.fileno())
        stamp = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if actual != expected or stamp(before) != stamp(after):
            raise ValueError("Snapshot member changed")
        stream.seek(0)
        return stream
    except BaseException:
        stream.close()
        raise


def handler(snapshot, catalog):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_HEAD(self):
            self.reply(False)

        def do_GET(self):
            self.reply(True)

        def reply(self, body):
            if self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}":
                self.send_error(403, "Use the literal loopback address")
                return
            route = self.path
            if catalog["manager"] == "homebrew":
                relative = catalog["routes"].get(route)
            else:
                parsed = urllib.parse.urlsplit(route)
                relative = urllib.parse.unquote(parsed.path).removeprefix("/") if not parsed.query else None
            if relative not in catalog["files"]:
                self.send_error(404)
                return
            try:
                fresh(catalog)
                path = regular(snapshot, "repo/" + relative)
                # Detect local mutation before returning any bytes. Package clients also
                # retain their own signature/checksum verification after transport.
                stream = checked_stream(path, catalog["files"][relative])
            except (ValueError, OSError):
                self.send_error(409, "Snapshot changed or expired; import a new signed snapshot")
                return
            with stream:
                size = catalog["files"][relative]["size"]
                start, end = 0, size - 1
                requested = self.headers.get("Range")
                if requested:
                    match = re.fullmatch(r"bytes=([0-9]{1,20})-([0-9]{0,20})", requested)
                    if match is None:
                        self.send_error(416)
                        return
                    start = int(match[1])
                    end = min(int(match[2]), size - 1) if match[2] else size - 1
                    if start > end or start >= size:
                        self.send_error(416)
                        return
                self.send_response(206 if requested else 200)
                self.send_header("Content-Type", mimetypes.guess_type(relative)[0] or "application/octet-stream")
                self.send_header("Content-Length", str(max(0, end - start + 1)))
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'none'; sandbox")
                if requested:
                    self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
                self.end_headers()
                if body:
                    stream.seek(start)
                    remaining = end - start + 1
                    while remaining > 0:
                        chunk = stream.read(min(CHUNK, remaining))
                        if not chunk:
                            self.close_connection = True
                            break
                        self.wfile.write(chunk)
                        remaining -= len(chunk)

        def log_message(self, *_args):
            pass  # Do not log URLs that might contain upstream query credentials.

    return Handler


class Server(http.server.HTTPServer):
    # Bound concurrency and memory. Native managers retry instead of accumulating workers.
    request_queue_size = 16

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(60)
        return connection, address


def make_server(snapshot, port):
    snapshot = Path(snapshot).resolve(strict=True)
    catalog = validate(snapshot)
    return Server(("127.0.0.1", port), handler(snapshot, catalog))
