#!/usr/bin/env python3
"""Exercise native adapter boundaries and export measured Sonar line coverage.

This unit profile controls OS service replies. The signed package and native
isolation suites remain separate, mandatory acceptance of real OS enforcement.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[3]
SOURCE = Path(__file__).resolve().parent
ADAPTERS = [ROOT / "crates/evx-supervisor/native" / name
            for name in ("apple_xpc.c", "apple_package.c")]


def run(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=30, **kwargs)


def coverage_report(lcov):
    coverage = ET.Element("coverage", version="1")
    files = {}
    current = None
    for line in lcov.splitlines():
        if line.startswith("SF:"):
            source = Path(line[3:]).resolve()
            current = files.setdefault(source, {}) if source in ADAPTERS else None
        elif line.startswith("DA:") and current is not None:
            number, count, *_ = line[3:].split(",")
            current[int(number)] = current.get(int(number), False) or int(count) > 0
        elif line == "end_of_record":
            current = None
    if set(files) != set(ADAPTERS) or any(not lines for lines in files.values()):
        raise ValueError("native coverage must contain both production adapters")
    covered = total = 0
    for source, lines in sorted(files.items()):
        element = ET.SubElement(coverage, "file", path=source.relative_to(ROOT).as_posix())
        for number, hit in sorted(lines.items()):
            ET.SubElement(element, "lineToCover", lineNumber=str(number), covered=str(hit).lower())
            covered += hit
            total += 1
    print(f"Native adapter line coverage: {covered}/{total} ({100 * covered / total:.2f}%)", flush=True)
    if covered / total < 0.80:
        raise ValueError("native adapter line coverage is below 80%")
    return coverage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="evx-native-coverage-") as directory:
        target = Path(directory)
        binaries = []
        for name in ("boundaries", "lifecycle"):
            binary = target / name
            run("xcrun", "clang", "-std=c11", "-fblocks", "-Wall", "-Wextra", "-Werror",
                "-mmacosx-version-min=12.0", "-fprofile-instr-generate", "-fcoverage-mapping",
                str(SOURCE / f"backend-{name}.c"), "-framework", "CoreFoundation", "-framework", "Security",
                "-o", str(binary))
            binaries.append(binary)
        cases = [(binaries[0], "")] + [(binaries[1], case) for case in (
            "idle", "stopped", "worker-binding", "stale", "observations", "termination", "interrupted-wait")]
        for binary, case in cases:
            env = dict(os.environ, LLVM_PROFILE_FILE=str(target / f"{binary.name}-{case}.profraw"))
            run(str(binary), *([case] if case else []), env=env)
        profile = target / "native.profdata"
        run("xcrun", "llvm-profdata", "merge", "-sparse", *map(str, target.glob("*.profraw")), "-o", str(profile))
        exported = run("xcrun", "llvm-cov", "export", str(binaries[0]), "-object", str(binaries[1]),
                       f"-instr-profile={profile}", "-format=lcov", *map(str, ADAPTERS), capture_output=True, text=True)
        report = coverage_report(exported.stdout)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        ET.indent(report)
        ET.ElementTree(report).write(args.output, encoding="utf-8", xml_declaration=True)


if __name__ == "__main__":
    main()
