#!/usr/bin/env python3
"""Stage, export and serve signed-xite package snapshots without changing system sources."""
import argparse
import http.client
import json
import lzma
import sys
import xml.etree.ElementTree as ET
import zipfile
from package_mirror import snapshot
from package_mirror.server import make_server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    stage = commands.add_parser("stage", help="copy a complete public repository without rewriting metadata")
    stage.add_argument("--source", required=True)
    stage.add_argument("--output", required=True)
    stage.add_argument("--manager", choices=snapshot.MANAGERS, required=True)
    stage.add_argument("--expires", required=True, help="operator-selected ISO8601 UTC expiry, never later than APT Valid-Until")
    stage.add_argument("--url-map", help="Homebrew-only JSON mapping exact request paths to source files")
    export = commands.add_parser("export", help="atomically export from the local node's verified public ZIP endpoint")
    export.add_argument("--node", default="http://127.0.0.1:42222")
    export.add_argument("--address", required=True)
    export.add_argument("--output", required=True)
    export.add_argument("--cookie-file", help="private Netscape-format cookie file for a password-protected node")
    export.add_argument("--expected-snapshot", help="require this operator-selected SHA256 snapshot digest")
    verify = commands.add_parser("verify", help="check snapshot completeness, hashes and expiry")
    verify.add_argument("--snapshot", required=True)
    serve = commands.add_parser("serve", help="read-only HTTP at 127.0.0.1, with no upstream fetching")
    serve.add_argument("--snapshot", required=True)
    serve.add_argument("--port", type=int, default=42700)
    args = vars(parser.parse_args())
    command = args.pop("command")
    if command == "serve":
        with make_server(args["snapshot"], args["port"]) as server:
            print(f"Serving verified snapshot at http://127.0.0.1:{server.server_port}", flush=True)
            server.serve_forever()
    else:
        result = snapshot.validate(args["snapshot"]) if command == "verify" else getattr(snapshot, command)(**args)
        print(json.dumps({key: result[key] for key in ("snapshot", "manager", "expires")}))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except (ValueError, OSError, KeyError, http.client.HTTPException, lzma.LZMAError, ET.ParseError, zipfile.BadZipFile) as error:
        print(f"Mirror unavailable: {error}", file=sys.stderr)
        raise SystemExit(1)
