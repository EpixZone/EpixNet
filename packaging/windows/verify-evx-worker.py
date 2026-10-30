#!/usr/bin/env python3
"""Check a built Windows EVX worker before it is staged or shipped.

This is a release/CI acceptance harness, not a node API. It reads the PE
headers itself, so it needs no Visual Studio tooling, and it starts the
worker once outside any AppContainer to confirm that the worker refuses to
run unconfined. Real confined compile, run and file operations are exercised
by the supervisor test suites and the native fixtures, which can create the
AppContainer this script deliberately does not.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys

IMAGE_FILE_MACHINE_AMD64 = 0x8664
# Host-only DLLs. A confined image that imported one of these would fail to
# load in the less-privileged AppContainer, or would carry shell and COM
# surface into it; the fixture workflow enforces the same list with dumpbin.
FORBIDDEN_IMPORTS = {"userenv.dll", "shell32.dll", "ole32.dll"}


def section_for(sections, rva):
    for virtual_address, virtual_size, raw_pointer, raw_size in sections:
        if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
            return raw_pointer + (rva - virtual_address)
    raise ValueError(f"RVA 0x{rva:x} is outside every section")


def read_c_string(data, offset):
    end = data.index(b"\0", offset)
    return data[offset:end].decode("ascii")


def pe_imports(data):
    """Return (machine, sorted import DLL names) of a PE32+ image."""
    if data[:2] != b"MZ":
        raise ValueError("not a PE image (no MZ header)")
    (pe_offset,) = struct.unpack_from("<I", data, 0x3C)
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("not a PE image (no PE signature)")
    machine, section_count, _, _, _, optional_size, _ = struct.unpack_from(
        "<HHIIIHH", data, pe_offset + 4)
    optional = pe_offset + 24
    (magic,) = struct.unpack_from("<H", data, optional)
    if magic != 0x20B:
        raise ValueError("not a PE32+ image")
    # Data directories start at offset 112 of the PE32+ optional header; the
    # import directory is entry 1.
    import_rva, import_size = struct.unpack_from("<II", data, optional + 112 + 8)
    sections = []
    cursor = optional + optional_size
    for _ in range(section_count):
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, cursor + 8)
        sections.append((virtual_address, virtual_size, raw_pointer, raw_size))
        cursor += 40
    names = set()
    if import_size:
        descriptor = section_for(sections, import_rva)
        while True:
            _, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", data, descriptor)
            if name_rva == 0 and first_thunk == 0:
                break
            names.add(read_c_string(data, section_for(sections, name_rva)).lower())
            descriptor += 20
    return machine, sorted(names)


def through_reparse_point(path):
    """Whether any existing component of `path` is a link, junction or other
    reparse point. Spellings are not compared: an 8.3 short name is not a
    link."""
    current = Path(path.anchor) if path.is_absolute() else Path()
    for part in path.absolute().parts[1:] if path.is_absolute() else path.parts:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return False
        attributes = getattr(info, "st_file_attributes", 0)
        if stat.S_ISLNK(info.st_mode) or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            return True
    return False


def check_image(worker):
    info = os.stat(worker)
    if getattr(info, "st_nlink", 1) != 1:
        raise ValueError("worker has more than one hard link")
    if through_reparse_point(worker):
        raise ValueError("worker path goes through a link or junction")
    data = worker.read_bytes()
    machine, imports = pe_imports(data)
    if machine != IMAGE_FILE_MACHINE_AMD64:
        raise ValueError(f"worker machine type 0x{machine:x} is not AMD64")
    forbidden = sorted(FORBIDDEN_IMPORTS.intersection(imports))
    if forbidden:
        raise ValueError(f"worker imports host-only DLLs: {', '.join(forbidden)}")
    return hashlib.sha256(data).hexdigest(), imports


REFUSAL = b"confinement verification failed"


def check_refusal(worker):
    """Outside an AppContainer every mode must refuse with its own verification
    message before reading input: the input offered here is junk a mode that
    parsed first would choke on differently."""
    junk = bytes(8) + (16).to_bytes(4, "big") + b"{" + b"x" * 15
    for mode in ("compile", "run", "file", "file-read"):
        result = subprocess.run([str(worker), mode], input=junk, capture_output=True,
                                timeout=20, env={"SystemRoot": os.environ.get("SystemRoot", r"C:\Windows")})
        if result.returncode != 1 or result.stdout or REFUSAL not in result.stderr:
            raise ValueError(f"{mode} mode did not refuse unconfined execution: exit {result.returncode}, "
                             f"stdout {result.stdout[:200]!r}, stderr {result.stderr[:200]!r}")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("worker", type=Path, help="Path to evx-worker.exe")
    parser.add_argument("--json", action="store_true", help="Print the evidence record")
    args = parser.parse_args()
    worker = args.worker
    if not worker.is_file():
        raise SystemExit(f"{worker}: missing worker")
    sha256, imports = check_image(worker)
    refused = check_refusal(worker)
    record = {"worker_sha256": sha256, "imports": imports, "unconfined_refused": refused}
    if args.json:
        print(json.dumps(record, indent=2))
    else:
        print(f"evx-worker ok: {len(imports)} imports, refuses unconfined execution, sha256 {sha256[:16]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
