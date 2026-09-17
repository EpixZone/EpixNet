#!/usr/bin/env python3
"""Validate all 64-bit ELF libraries in an APK, AAB or individual .so.

Checks PT_LOAD alignment and unsafe PT_GNU_RELRO page overlap. For APKs, also checks
the ZIP data alignment of uncompressed native libraries. AAB ZIP offsets are
not installable APK offsets; validate generated APKs separately as well.
"""
import argparse
import pathlib
import struct
import sys
import zipfile

PAGE = 16384


def elf_errors(data):
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        return ["expected a little-endian ELF64 library"]
    phoff = struct.unpack_from("<Q", data, 32)[0]
    entsize, count = struct.unpack_from("<HH", data, 54)
    if entsize < 56 or count == 0 or phoff + entsize * count > len(data):
        return ["invalid ELF program header table"]
    errors = []
    loads = 0
    writable = []
    relro = []
    for i in range(count):
        kind, flags, offset, address, _, size, memory, alignment = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + i * entsize)
        if kind == 1:
            loads += 1
            if alignment < PAGE or alignment & (alignment - 1):
                errors.append(f"PT_LOAD alignment {alignment} is not 16 KB compatible")
            if (offset - address) % PAGE:
                errors.append("PT_LOAD file/virtual offsets disagree at 16 KB granularity")
            if offset + size > len(data) or size > memory:
                errors.append("invalid PT_LOAD extent")
            if flags & 2:
                writable.append((address, address + memory))
        elif kind == 0x6474E552:
            relro.append((address, address + memory))
    # Bionic rounds RELRO protection outwards to whole pages. An unaligned
    # end is safe when the remaining bytes are unmapped padding (for example
    # a dedicated LOAD segment in GeckoView), but not when mutable data shares
    # that page. Checking end % PAGE alone incorrectly rejects the former.
    for start, end in relro:
        page_start, page_end = start // PAGE * PAGE, (end + PAGE - 1) // PAGE * PAGE
        for load_start, load_end in writable:
            if (max(page_start, load_start) < min(start, load_end)
                    or max(end, load_start) < min(page_end, load_end)):
                errors.append("PT_GNU_RELRO page protection overlaps writable data at 16 KB")
    if not loads:
        errors.append("no PT_LOAD segments")
    return errors


def inspect(path):
    if path.suffix == ".so":
        return [(path.name, elf_errors(path.read_bytes()))]
    if path.suffix not in (".apk", ".aab"):
        raise ValueError("expected .apk, .aab or .so")
    results = []
    with zipfile.ZipFile(path) as archive, path.open("rb") as raw:
        for info in archive.infolist():
            if not info.filename.endswith(".so"):
                continue
            # Inspect every supported 64-bit ABI, including dependency SDKs.
            if not any(f"/{abi}/" in "/" + info.filename for abi in ("arm64-v8a", "x86_64")):
                continue
            errors = elf_errors(archive.read(info))
            if path.suffix == ".apk" and info.compress_type == zipfile.ZIP_STORED:
                raw.seek(info.header_offset)
                header = raw.read(30)
                if len(header) != 30 or header[:4] != b"PK\x03\x04":
                    errors.append("invalid ZIP local header")
                else:
                    name_len, extra_len = struct.unpack_from("<HH", header, 26)
                    if (info.header_offset + 30 + name_len + extra_len) % PAGE:
                        errors.append("uncompressed APK library is not ZIP-aligned to 16 KB")
            results.append((info.filename, errors))
    if not results:
        raise ValueError("no 64-bit native libraries found")
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=pathlib.Path)
    parser.add_argument("--require", action="append", default=[], metavar="LIBRARY")
    args = parser.parse_args()
    failed = False
    for path in args.paths:
        try:
            results = inspect(path)
            missing = set(args.require) - {pathlib.PurePosixPath(n).name for n, _ in results}
            if missing:
                raise ValueError("missing required libraries: " + ", ".join(sorted(missing)))
            for name, errors in results:
                failed |= bool(errors)
                print(f"{'FAIL' if errors else 'PASS'} {path.name}: {name}" +
                      (": " + "; ".join(dict.fromkeys(errors)) if errors else ""))
        except (OSError, ValueError, struct.error, zipfile.BadZipFile) as error:
            failed = True
            print(f"FAIL {path}: {error}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
