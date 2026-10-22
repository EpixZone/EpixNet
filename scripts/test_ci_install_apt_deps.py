#!/usr/bin/env python3
"""Run the real apt retry helper against temporary sources and fake commands."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("apt_helper", Path(__file__).with_name("ci_install_apt_deps.py"))
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
MIRRORS = (
    b"# GitHub runner mirrors\n"
    b"http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\n"
    b"https://archive.ubuntu.com/ubuntu/\tpriority:2\n"
    b"https://security.ubuntu.com/ubuntu/\tpriority:3\n"
)
FALLBACK = MIRRORS.replace(b"http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\n", b"")


class AptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.etc = self.root / "etc"
        (self.etc / "apt/sources.list.d").mkdir(parents=True)
        (self.etc / "os-release").write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
        self.modern = self.etc / "apt/sources.list.d/ubuntu.sources"
        self.modern.write_text(
            "Types: deb\nURIs: " + HELPER.MIRROR_URI + "\n"
            "Suites: noble noble-updates noble-security\nComponents: main universe\n"
            "Architectures: amd64\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n"
        )
        self.third_party = self.etc / "apt/sources.list.d/microsoft.sources"
        self.third_party.write_text("Types: deb\nURIs: https://packages.microsoft.com/ubuntu/24.04/prod\n")
        self.mirrors = self.etc / "apt/apt-mirrors.txt"
        self.mirrors.write_bytes(MIRRORS)
        self.mirrors.chmod(0o640)
        self.state = self.root / "fake-state.json"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.command("apt-get", '''import json,os,sys
from pathlib import Path
p=Path(os.environ["FAKE_STATE"]);s=json.loads(p.read_text())
s["calls"].append({"args":sys.argv[1:],"noninteractive":os.environ.get("DEBIAN_FRONTEND"),"mirrors":Path(os.environ["FAKE_MIRRORS"]).read_text() if Path(os.environ["FAKE_MIRRORS"]).exists() else None})
code=s["results"].pop(0);p.write_text(json.dumps(s));raise SystemExit(code)
''')
        self.command("timeout", '''import json,os,sys
from pathlib import Path
p=Path(os.environ["FAKE_STATE"]);s=json.loads(p.read_text());s["timeouts"].append(sys.argv[1:3]);p.write_text(json.dumps(s))
os.execvp(sys.argv[3],sys.argv[3:])
''')
        self.command("dpkg", 'import os\nprint(os.environ.get("FAKE_ARCH", "amd64"))\n')
        self.env = {
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            "FAKE_STATE": str(self.state), "FAKE_MIRRORS": str(self.mirrors), "FAKE_ARCH": "amd64",
        }

    def command(self, name, body):
        path = self.bin / name
        path.write_text("#!/usr/bin/env python3\n" + body)
        path.chmod(0o755)

    def run_install(self, results, packages=None):
        self.state.write_text(json.dumps({"results": results, "calls": [], "timeouts": []}))
        with patch.object(HELPER, "ETC", self.etc), patch.dict(os.environ, self.env), \
                patch.object(HELPER.time, "sleep") as sleep, contextlib.redirect_stdout(io.StringIO()):
            code = HELPER.install(packages or ["protobuf-compiler", "pkg-config"])
        state = json.loads(self.state.read_text())
        self.assertTrue(all(x == ["--kill-after=15s", "300"] for x in state["timeouts"]))
        self.assertTrue(all(x["noninteractive"] == "noninteractive" for x in state["calls"]))
        return code, state["calls"], sleep.call_count

    def test_success_does_not_change_sources_or_mirrors(self):
        before = {p: p.read_bytes() for p in self.etc.rglob("*") if p.is_file()}
        code, calls, sleeps = self.run_install([0, 0])
        self.assertEqual((code, len(calls), sleeps), (0, 2, 0))
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_install_timeout_removes_only_azure_before_retry(self):
        before = {p: p.read_bytes() for p in (self.modern, self.third_party, self.etc / "os-release")}
        code, calls, sleeps = self.run_install([0, 124, 0, 0])
        self.assertEqual((code, len(calls), sleeps), (0, 4, 1))
        self.assertEqual(calls[0]["mirrors"], MIRRORS.decode())
        self.assertEqual(calls[2]["mirrors"], FALLBACK.decode())
        self.assertEqual(self.mirrors.read_bytes(), FALLBACK)
        self.assertEqual(stat.S_IMODE(self.mirrors.stat().st_mode), 0o640)
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_legacy_ubuntu22_layout_and_package_args(self):
        self.modern.unlink()
        (self.etc / "os-release").write_text('ID="ubuntu"\nVERSION_ID="22.04"\n')
        legacy = self.etc / "apt/sources.list"
        text = "deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] " + HELPER.MIRROR_URI + " jammy main universe\n"
        legacy.write_text(text)
        packages = ["protobuf-compiler", "libgtk-3-dev", "libayatana-appindicator3-dev"]
        code, calls, _ = self.run_install([100, 0, 0], packages)
        self.assertEqual(code, 0)
        self.assertEqual(calls[-1]["args"], ["install", "-y", "--no-install-recommends", *packages])
        self.assertEqual(legacy.read_text(), text)
        self.assertEqual(self.mirrors.read_bytes(), FALLBACK)

    def test_final_install_failure_is_bounded_and_propagated(self):
        code, calls, sleeps = self.run_install([0, 124, 0, 100])
        self.assertEqual((code, len(calls), sleeps), (100, 4, 1))

    def test_final_update_failure_skips_install(self):
        code, calls, sleeps = self.run_install([124, 124])
        self.assertEqual((code, len(calls), sleeps), (124, 2, 1))
        self.assertEqual([c["args"] for c in calls], [["update"], ["update"]])

    def test_unsafe_or_unknown_setups_leave_mirrors_unchanged(self):
        cases = ["local", "self-hosted", "debian", "arm64", "missing-os", "missing-source",
                 "commented-source", "disabled-source", "no-official-fallback", "no-azure", "lookalike-azure"]
        original_source = self.modern.read_text()
        for case in cases:
            with self.subTest(case=case):
                self.env.update(GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted", FAKE_ARCH="amd64")
                (self.etc / "os-release").write_text("ID=ubuntu\n")
                self.modern.write_text(original_source)
                self.mirrors.write_bytes(MIRRORS)
                if case == "local": self.env["GITHUB_ACTIONS"] = "false"
                if case == "self-hosted": self.env["RUNNER_ENVIRONMENT"] = "self-hosted"
                if case == "debian": (self.etc / "os-release").write_text("ID=debian\n")
                if case == "arm64": self.env["FAKE_ARCH"] = "arm64"
                if case == "missing-os": (self.etc / "os-release").unlink()
                if case == "missing-source": self.modern.unlink()
                if case == "commented-source": self.modern.write_text("# URIs: " + HELPER.MIRROR_URI + "\n")
                if case == "disabled-source": self.modern.write_text(original_source + "Enabled: no\n")
                if case == "no-official-fallback": self.mirrors.write_bytes(MIRRORS.replace(b"https://archive.ubuntu.com/ubuntu/", b"https://mirror.invalid/ubuntu/"))
                if case == "no-azure": self.mirrors.write_bytes(FALLBACK)
                if case == "lookalike-azure": self.mirrors.write_bytes(MIRRORS.replace(b"azure.archive.ubuntu.com", b"azureXarchiveXubuntuXcom"))
                before = self.mirrors.read_bytes()
                code, calls, _ = self.run_install([100, 0, 0])
                self.assertEqual((code, len(calls)), (0, 3))
                self.assertEqual(self.mirrors.read_bytes(), before)

    def test_missing_or_symlink_mirror_list_is_not_rewritten(self):
        self.mirrors.unlink()
        self.assertEqual(self.run_install([100, 0, 0])[0], 0)
        self.assertFalse(self.mirrors.exists())
        target = self.root / "unrelated-mirrors"
        target.write_bytes(MIRRORS)
        self.mirrors.symlink_to(target)
        self.assertEqual(self.run_install([100, 0, 0])[0], 0)
        self.assertEqual(target.read_bytes(), MIRRORS)


if __name__ == "__main__":
    unittest.main()
