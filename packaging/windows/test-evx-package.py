#!/usr/bin/env python3
"""Offline checks of the Windows EVX worker verifier. Fixture images are never executed."""

import importlib.util
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("verify_evx_worker", HERE / "verify-evx-worker.py")
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def pe_image(imports, machine=0x8664):
    """A minimal PE32+ image with one section holding an import directory."""
    section_rva, section_raw, section_size = 0x1000, 0x200, 0x400
    names = b"".join(name.encode() + b"\0" for name in imports)
    descriptors = b""
    name_offset = 20 * (len(imports) + 1)
    thunk_offset = name_offset + len(names)
    position = 0
    for index, name in enumerate(imports):
        thunk = section_rva + thunk_offset + 16 * index
        descriptors += struct.pack("<IIIII", 0, 0, 0, section_rva + name_offset + position, thunk)
        position += len(name) + 1
    descriptors += bytes(20)
    body = descriptors + names + bytes(16 * len(imports))
    section = body.ljust(section_size, b"\0")
    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    optional_size = 240
    file_header = struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, optional_size, 0x22)
    optional = bytearray(optional_size)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<II", optional, 112 + 8, section_rva, len(descriptors))
    section_header = b".idata\0\0" + struct.pack("<IIIIIIHHI", len(body), section_rva,
                                                   section_size, section_raw, 0, 0, 0, 0, 0x40000040)
    headers = bytes(dos) + b"PE\0\0" + file_header + bytes(optional) + section_header
    return headers.ljust(section_raw, b"\0") + section


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def image(self, name, imports, machine=0x8664):
        path = self.root / name
        path.write_bytes(pe_image(imports, machine))
        return path

    def test_imports_are_read_from_the_import_directory(self):
        machine, imports = verifier.pe_imports(pe_image(["KERNEL32.dll", "ntdll.dll"]))
        self.assertEqual(machine, 0x8664)
        self.assertEqual(imports, ["kernel32.dll", "ntdll.dll"])

    def test_clean_image_passes(self):
        sha256, imports = verifier.check_image(self.image("evx-worker.exe", ["kernel32.dll", "ntdll.dll"]))
        self.assertEqual(len(sha256), 64)
        self.assertEqual(imports, ["kernel32.dll", "ntdll.dll"])

    def test_host_only_imports_are_rejected(self):
        for dll in ("userenv.dll", "SHELL32.dll", "ole32.dll"):
            path = self.image("evx-worker.exe", ["kernel32.dll", dll])
            with self.assertRaisesRegex(ValueError, "host-only"):
                verifier.check_image(path)

    def test_wrong_machine_and_non_pe_images_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "AMD64"):
            verifier.check_image(self.image("evx-worker.exe", ["kernel32.dll"], machine=0x14C))
        junk = self.root / "junk.exe"
        junk.write_bytes(b"not an image")
        with self.assertRaisesRegex(ValueError, "PE"):
            verifier.check_image(junk)

    @unittest.skipUnless(os.name == "nt", "hard links need NTFS semantics")
    def test_hard_linked_worker_is_rejected(self):
        path = self.image("evx-worker.exe", ["kernel32.dll"])
        os.link(path, self.root / "alias.exe")
        with self.assertRaisesRegex(ValueError, "hard link"):
            verifier.check_image(path)

    def test_missing_worker_is_an_error(self):
        result = os.system(f'"{sys.executable}" "{HERE / "verify-evx-worker.py"}" "{self.root / "absent.exe"}"')
        self.assertNotEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
