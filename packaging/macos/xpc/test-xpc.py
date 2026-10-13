#!/usr/bin/env python3
"""Exercise real signed XPC fixture peers. Does not enable EVX XPC execution."""

import json
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid

SOURCE = Path(__file__).resolve().parent
CLIENT_ID = "org.epixnet.evx.fixture.client"


def run(command, timeout=30):
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise AssertionError(f"{command[0]} exited {result.returncode}: {result.stderr}")
    return result.stdout


def sign(path, identifier, entitlements=None):
    run(["/usr/bin/codesign", "--force", "--sign", "-", "--identifier", identifier,
         *(["--entitlements", str(entitlements)] if entitlements else []), str(path)])


def cdhash(path):
    output = subprocess.run(["/usr/bin/codesign", "--display", "--verbose=4", str(path)],
                            capture_output=True, text=True, check=True).stderr
    found = re.search(r"^CDHash=([0-9a-f]{40})$", output, re.M)
    if not found:
        raise AssertionError("missing fixture code-directory hash")
    return found.group(1)


def requirement(identifier, digest):
    return f'identifier "{identifier}" and cdhash H"{digest}"'


@unittest.skipUnless(sys.platform == "darwin", "real macOS XPC required")
class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="evx-xpc-fixture-")
        cls.root = Path(cls.directory.name)
        cls.client = cls.root / "client"
        run(["/usr/bin/xcrun", "clang", "-std=c11", "-fblocks", "-Wall", "-Wextra",
             "-Werror", "-mmacosx-version-min=12.0", str(SOURCE / "client.c"),
             "-o", str(cls.client)])
        sign(cls.client, CLIENT_ID)
        cls.client_requirement = requirement(CLIENT_ID, cdhash(cls.client))
        cls.sandbox_child = cls.root / "sandbox-child"
        run(["/usr/bin/xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
             "-Wno-deprecated-declarations", "-mmacosx-version-min=12.0",
             str(SOURCE / "sandbox-child.c"), "-o", str(cls.sandbox_child)])
        sign(cls.sandbox_child, "org.epixnet.evx.fixture.probe")
        cls.sandbox_host_child = cls.root / "sandbox-host-child"
        run(["/usr/bin/xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
             "-Wno-deprecated-declarations", "-mmacosx-version-min=12.0", "-DEVX_FIXTURE_REEXEC_HOST=1",
             str(SOURCE / "sandbox-child.c"), "-o", str(cls.sandbox_host_child)])
        cls.authority = cls.root / "private-authority"
        cls.authority.mkdir(mode=0o700)
        cls.sandbox_entitlements = cls.root / "sandbox.plist"
        cls.inherit_entitlements = cls.root / "inherit.plist"
        for path, entitlements in (
                (cls.sandbox_entitlements, {"com.apple.security.app-sandbox": True}),
                (cls.inherit_entitlements, {"com.apple.security.app-sandbox": True,
                                           "com.apple.security.inherit": True})):
            with path.open("wb") as stream:
                plistlib.dump(entitlements, stream)
        cls.replacement_client = cls.root / "replacement-client"
        run(["/usr/bin/xcrun", "clang", "-std=c11", "-fblocks", "-Wall", "-Wextra",
             "-Werror", "-mmacosx-version-min=12.0", "-DEVX_FIXTURE_VARIANT=2",
             str(SOURCE / "client.c"), "-o", str(cls.replacement_client)])
        sign(cls.replacement_client, CLIENT_ID)
        cls.services = {}
        for role in ("guest", "compiler", "lifecycle", "sandbox", "sandbox-fd", "sandbox-host"):
            binary = cls.root / role
            run(["/usr/bin/xcrun", "clang", "-std=c11", "-fblocks", "-Wall", "-Wextra",
                 "-Werror", "-mmacosx-version-min=12.0",
                 *(["-DEVX_FIXTURE_SURVIVE_DISCONNECT=1"] if role == "lifecycle" else []),
                 *(["-DEVX_FIXTURE_INHERITED_SANDBOX=1", "-framework", "CoreFoundation"]
                   if role.startswith("sandbox") else []),
                 *(["-DEVX_FIXTURE_SCOPED_FD=1"] if role == "sandbox-fd" else []),
                 f"-DEVX_CLIENT_REQUIREMENT={json.dumps(cls.client_requirement)}",
                 f"-DEVX_SERVICE_ROLE={json.dumps(role)}", str(SOURCE / "service.c"),
                 "-o", str(binary)])
            cls.services[role] = binary

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def call(self, mode="echo", role="guest", wire_role=None,
             client_identity=None, server_identity=None, expected_server_identity=None,
             replacement_client=False, expect_client_rejection=False, replacement_service=False,
             scoped_path=None):
        # A distinct service ID prevents launchd from finding an earlier
        # fixture instance. This is a test technique, not production isolation.
        identifier = (f"org.epixnet.evx.fixture.inherited{role}" if role.startswith("sandbox")
                      else f"org.epixnet.evx.fixture.{uuid.uuid4().hex}")
        app = self.root / f"{identifier}.{uuid.uuid4().hex}.app"
        macos = app / "Contents" / "MacOS"
        macos.mkdir(parents=True)
        client = macos / "client"
        shutil.copy2(self.replacement_client if replacement_client else self.client, client)
        if client_identity:
            sign(client, client_identity)
        service = app / "Contents" / "XPCServices" / f"{identifier}.xpc"
        executable = service / "Contents" / "MacOS" / "service"
        executable.parent.mkdir(parents=True)
        shutil.copy2(self.services[role], executable)
        if role.startswith("sandbox"):
            child = executable.parent / "probe-child"
            shutil.copy2(self.sandbox_host_child if role == "sandbox-host" else self.sandbox_child, child)
            if role == "sandbox-host":
                shutil.copy2(client, executable.parent / "probe-host")
            sign(child, "org.epixnet.evx.fixture.probe", self.inherit_entitlements)
        for bundle, info in ((app, {
            "CFBundleIdentifier": CLIENT_ID, "CFBundleExecutable": "client",
            "CFBundlePackageType": "APPL", "CFBundleVersion": "1",
        }), (service, {
            "CFBundleIdentifier": identifier, "CFBundleExecutable": "service",
            **({"EVXFixtureAuthorityRoot": str(self.authority.resolve())} if role == "sandbox-host" else {}),
            "CFBundlePackageType": "XPC!", "CFBundleVersion": "1",
            "XPCService": {"ServiceType": "Application", "RunLoopType": "dispatch_main",
                           "JoinExistingSession": False},
        })):
            with (bundle / "Contents" / "Info.plist").open("wb") as stream:
                plistlib.dump(info, stream)
        sign(service, server_identity or identifier,
             self.sandbox_entitlements if role.startswith("sandbox") else None)
        service_digest = cdhash(executable)
        if replacement_service:
            info_path = service / "Contents" / "Info.plist"
            with info_path.open("rb") as stream:
                info = plistlib.load(stream)
            info["CFBundleVersion"] = "2"
            with info_path.open("wb") as stream:
                plistlib.dump(info, stream)
            sign(service, identifier)
            self.assertNotEqual(service_digest, cdhash(executable))
        # Re-signing the outer app changes the main executable's code directory
        # by binding its Info.plist. Preserve the pinned standalone signature in
        # this development fixture; production must pin a release team identity.
        trusted = requirement(expected_server_identity or identifier, service_digest)
        command = [str(client), identifier, trusted, wire_role or role, mode]
        if scoped_path:
            command.append(str(scoped_path))
        if expect_client_rejection:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            # Apple's listener requirement drops nonmatching requests. A peer
            # requirement error is not promised to the rejected caller.
            if result.returncode == 3:
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "fixture timed out\n")
            else:
                self.assertEqual(result.returncode, 0)
                self.assertIn(result.stdout, ("identity-denied\n", "connection-denied\n"))
                self.assertEqual(result.stderr, "")
            return None
        return run(command, timeout=15)

    def test_guest_bytes(self):
        self.assertEqual(self.call(), "accepted:1:17\n")

    def test_compiler_bytes(self):
        self.assertEqual(self.call(role="compiler"), "accepted:1:17\n")

    def test_maximum_frame(self):
        self.assertEqual(self.call("max-frame"), "accepted:1:131072\n")

    def test_oversize_denied(self):
        self.assertEqual(self.call("oversize"), "frame-denied:1\n")

    def test_wrong_role_denied(self):
        self.assertEqual(self.call(wire_role="file"), "frame-denied:1\n")

    def test_unknown_path_denied(self):
        self.assertEqual(self.call("extra-key"), "frame-denied:1\n")

    def test_workspace_descriptor_denied(self):
        self.assertEqual(self.call("descriptor"), "frame-denied:1\n")

    def test_object_type_denied(self):
        self.assertEqual(self.call("bad-type"), "frame-denied:1\n")

    def test_protocol_version_denied(self):
        self.assertEqual(self.call("bad-version"), "frame-denied:1\n")

    def test_replay_denied(self):
        self.assertEqual(self.call("replay"), "accepted:1:17\nframe-denied:2\n")

    def test_frame_count_denied(self):
        result = self.call("frame-budget").splitlines()
        self.assertEqual(len(result), 131)
        self.assertEqual(result[-2:], ["accepted:130:17", "frame-denied:131"])

    def test_cumulative_bytes_denied(self):
        self.assertEqual(self.call("byte-budget"),
                         "accepted:1:131072\naccepted:2:131072\nframe-denied:3\n")

    def test_wrong_client_identifier_denied(self):
        self.call(client_identity="org.epixnet.evx.fixture.wrong", expect_client_rejection=True)

    def test_replacement_client_same_identifier_denied(self):
        self.call(replacement_client=True, expect_client_rejection=True)

    def test_wrong_service_identifier_denied(self):
        self.assertEqual(self.call(expected_server_identity="org.epixnet.evx.fixture.wrong"),
                         "identity-denied\n")

    def test_replacement_service_denied(self):
        self.assertEqual(self.call(server_identity="org.epixnet.evx.fixture.replacement"),
                         "identity-denied\n")

    def test_replacement_service_same_identifier_denied(self):
        self.assertEqual(self.call(replacement_service=True), "identity-denied\n")

    def test_cancellation_is_not_exit_and_reaping_loses_measurement(self):
        self.assertEqual(self.call(mode="cancel-survival", role="lifecycle"),
                         "accepted:1:17\nconnection-cancelled:process-alive\n"
                         "kernel-usage:unavailable-after-exit\n")

    def test_unsandboxed_control_can_install_profile(self):
        self.assertEqual(run([str(self.sandbox_child), str(self.root / "control-write")]),
                         "write_denied=0;sandbox_init_denied=0;descendants_denied=1\n")

    def test_reexecuted_signed_host_cannot_mint_authority(self):
        self.assertEqual(run([str(self.client), "authority-probe", str(self.authority / "control")]),
                         "host_authority_denied=0\n")
        self.assertEqual(self.call(mode="sandbox-child", role="sandbox-host"), "host_authority_denied=1\n")

    def test_inherited_sandbox_rejects_additional_profile(self):
        self.assertEqual(self.call(mode="sandbox-child", role="sandbox"),
                         "write_denied=1;sandbox_init_denied=1;descendants_denied=1\n")

    def test_passed_directory_descriptor_is_not_a_path_grant(self):
        with tempfile.TemporaryDirectory(prefix="evx-xpc-fd-") as root:
            (Path(root) / "score.json").write_text("42")
            self.assertEqual(self.call(mode="sandbox-child", role="sandbox-fd", scoped_path=root),
                             "scoped_descriptor_read=0\n")

    def test_passed_file_descriptor_preserves_read_access(self):
        with tempfile.TemporaryDirectory(prefix="evx-xpc-fd-") as root:
            file = Path(root) / "score.json"
            file.write_text("42")
            self.assertEqual(self.call(mode="sandbox-child", role="sandbox-fd", scoped_path=file),
                             "scoped_descriptor_read=1\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
