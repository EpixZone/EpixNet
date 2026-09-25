#!/usr/bin/env python3
"""Run under Xvfb as a normal user; verify Firefox loads the HTTPS dashboard."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time


def browser_running(profile):
    # The test owns a unique profile, so no other user's Firefox can satisfy
    # this check. Reading cmdline avoids depending on ps/pgrep package names.
    for path in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            arguments = path.read_bytes().split(b"\0")
        except OSError:
            continue
        if os.fsencode(profile) in arguments and b"firefox" in arguments[0] and b"--headless" not in arguments:
            return True
    return False


def check_dashboard(port, check_sandbox=False):
    # Marionette is enabled only for this isolated test profile. Certificate
    # errors must fail navigation, not be accepted by WebDriver's test defaults.
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        connection.settimeout(45)

        def receive():
            header = b""
            while not header.endswith(b":"):
                chunk = connection.recv(1)
                if not chunk:
                    raise RuntimeError("Firefox closed the test connection")
                header += chunk
            length = int(header[:-1])
            content = b""
            while len(content) < length:
                chunk = connection.recv(length - len(content))
                if not chunk:
                    raise RuntimeError("Firefox closed the test response")
                content += chunk
            return json.loads(content)

        if receive().get("marionetteProtocol") != 3:
            raise RuntimeError("Unexpected Firefox test protocol")
        sequence = 0

        def command(name, arguments):
            nonlocal sequence
            sequence += 1
            body = json.dumps([0, sequence, name, arguments]).encode()
            connection.sendall(str(len(body)).encode() + b":" + body)
            response = receive()
            if response[:2] != [1, sequence] or response[2] is not None:
                raise RuntimeError(f"{name}: {response}")
            return response[3]

        session = command("WebDriver:NewSession", {"acceptInsecureCerts": False})
        if session["capabilities"]["acceptInsecureCerts"]:
            raise RuntimeError("Test must not bypass certificate verification")
        command("WebDriver:Navigate", {"url": "https://dashboard.epix/"})
        page = command("WebDriver:ExecuteScript", {
            "script": "return {uri:document.documentURI, title:document.title, secure:isSecureContext};",
            "args": [], "newSandbox": True, "sandbox": "default",
        })["value"]
        if (page["uri"] != "https://dashboard.epix/" or not page["secure"]
                or "Dashboard" not in page["title"]):
            raise RuntimeError(f"HTTPS dashboard did not load: {page}")
        print("PASS: HTTPS dashboard loads with certificate verification enabled")
        if check_sandbox:
            command("WebDriver:Navigate", {"url": "about:support"})
            # about:support gathers its platform diagnostics asynchronously.
            time.sleep(2)
            sandbox = command("WebDriver:ExecuteScript", {
                "script": "return document.querySelector('#sandbox-tbody')?.innerText || '';",
                "args": [], "newSandbox": True, "sandbox": "default",
            })["value"]
            if not re.search(r"User Namespaces\s+true", sandbox):
                raise RuntimeError(f"Firefox user-namespace sandbox is unavailable: {sandbox}")
            print("PASS: Firefox reports user-namespace sandbox support")
        command("WebDriver:DeleteSession", {})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("launcher", type=Path)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--check-quit", action="store_true",
                        help="also test tray IPC shutdown; requires a working desktop session bus")
    parser.add_argument("--check-sandbox", action="store_true",
                        help="also check Firefox user namespaces; run on the desktop host")
    parser.add_argument("--expect-sandbox-setup", choices=("requested", "skipped"),
                        help="assert whether this launch needed administrator approval")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="epix-package-smoke-") as directory:
        root = Path(directory)
        env = dict(os.environ, EPIX_DATA_DIR=str(root / "data"), HOME=str(root / "home"),
                   XDG_DATA_HOME=str(root / "share"), XDG_CONFIG_HOME=str(root / "config"),
                   XDG_CACHE_HOME=str(root / "cache"), EPIX_TOR="disable", MOZ_MARIONETTE="1")
        Path(env["HOME"]).mkdir()
        profile = root / "data/firefox-profile"
        profile.mkdir(parents=True)
        # Firefox chooses an unused port atomically and reports it in the log.
        (profile / "prefs.js").write_text('user_pref("marionette.port", 0);\n')
        log = root / "startup.log"
        with log.open("w") as output:
            process = subprocess.Popen([str(args.launcher.resolve())], env=env,
                                       stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"Launcher exited: {process.returncode}\n{log.read_text()}")
                if "launching Epix Browser" in log.read_text() and browser_running(profile):
                    time.sleep(4)
                    if process.poll() is None and browser_running(profile):
                        print("PASS: packaged EpixNet launched Firefox and kept it running")
                        break
                time.sleep(0.5)
            else:
                raise RuntimeError("Firefox did not remain open\n" + log.read_text())
            ports = re.findall(r"Marionette\s+INFO\s+Listening on port (\d+)", log.read_text())
            if not ports:
                raise RuntimeError("Firefox did not expose its test port")
            check_dashboard(int(ports[-1]), args.check_sandbox)
            if args.expect_sandbox_setup:
                requested = "requesting the one-time Firefox sandbox permission" in log.read_text()
                if requested != (args.expect_sandbox_setup == "requested"):
                    raise RuntimeError("Unexpected sandbox approval behavior\n" + log.read_text())
                print(f"PASS: sandbox approval {args.expect_sandbox_setup}")
            if args.check_quit:
                subprocess.run([str(args.launcher.resolve()), "--quit"], env=env, timeout=45, check=True)
                process.wait(timeout=20)
                if process.returncode != 0:
                    raise RuntimeError(f"Launcher shutdown failed: {process.returncode}")
        except Exception:
            print(log.read_text(), file=sys.stderr)
            raise
        finally:
            # The session contains only processes started by this test. Reap
            # any remaining browser children even after an assertion failed.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


if __name__ == "__main__":
    main()
