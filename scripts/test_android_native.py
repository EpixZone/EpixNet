"""Synthetic ELF cases distinguish real 16 KB hazards from safe padding."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("native", Path(__file__).with_name("check-android-native.py"))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def elf(headers):
    data = bytearray(65536)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, len(headers))
    for i, (kind, flags, addr, memsize, align) in enumerate(headers):
        struct.pack_into("<IIQQQQQQ", data, 64 + i * 56,
                         kind, flags, addr, addr, 0, memsize, memsize, align)
    return data


class NativeTest(unittest.TestCase):
    def test_load_alignment(self):
        self.assertEqual(native.elf_errors(elf([(1, 5, 0, 4096, 16384)])), [])
        self.assertTrue(native.elf_errors(elf([(1, 5, 0, 4096, 4096)])))

    def test_relro_cannot_make_mutable_bytes_read_only(self):
        self.assertTrue(native.elf_errors(elf([
            (1, 6, 16384, 16384, 16384), (0x6474e552, 4, 16384, 4096, 1)])))

    def test_relro_padding_and_separate_data_segment_are_safe(self):
        self.assertEqual(native.elf_errors(elf([
            (1, 6, 16384, 4096, 16384), (1, 6, 32768, 4096, 16384),
            (0x6474e552, 4, 16384, 4096, 1)])), [])

    def test_relro_start_cannot_cover_mutable_prefix(self):
        self.assertTrue(native.elf_errors(elf([
            (1, 6, 16384, 16384, 16384), (0x6474e552, 4, 20480, 12288, 1)])))

    def test_malformed(self):
        for data in [b"", b"\x7fELF", bytes(64)]:
            self.assertTrue(native.elf_errors(data))

    def test_apk_checks_zip_offset_but_aab_does_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            for suffix, fails in [(".apk", True), (".aab", False)]:
                path = Path(tmp) / ("app" + suffix)
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("lib/arm64-v8a/libtest.so", elf([(1, 5, 0, 4096, 16384)]))
                self.assertEqual(bool(native.inspect(path)[0][1]), fails)


if __name__ == "__main__":
    unittest.main()
