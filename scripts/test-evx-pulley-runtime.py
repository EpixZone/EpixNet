#!/usr/bin/env python3
"""Prove trusted local Pulley artifacts run without a linked Wasm compiler.

Separate Cargo invocations prevent feature unification from hiding Cranelift.
The consumer only loads fixed fixtures generated in this process's private
scratch directory. This does not enable an iOS host or accept xite artifacts.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(*arguments, **kwargs):
    return subprocess.run(arguments, cwd=ROOT, check=True, **kwargs)


def main():
    graph = run("cargo", "tree", "--locked", "-p", "evx-runtime",
                "--no-default-features", "--features", "pulley",
                "--edges", "normal,build", "--prefix", "none", "--format", "{p}",
                capture_output=True, text=True).stdout
    packages = {line.split()[0] for line in graph.splitlines() if line.strip()}
    # Wasmtime's runtime reuses three compiler-independent collection crates.
    # The code generator, frontend and compiler integration must be absent.
    shared_collections = {"cranelift-bforest", "cranelift-bitset", "cranelift-entity"}
    forbidden = sorted(name for name in packages
                       if ("cranelift" in name and name not in shared_collections)
                       or name in {"wat", "wast", "wasmtime-internal-winch"})
    if forbidden:
        raise SystemExit(f"compiler-free profile links compiler/parser dependencies: {forbidden}")
    if not {"evx-runtime", "wasmtime", "pulley-interpreter"} <= packages:
        raise SystemExit("runtime-only graph is missing required interpreter dependencies")
    with tempfile.TemporaryDirectory(prefix="evx-trusted-pulley-") as scratch:
        run("cargo", "run", "-p", "evx-runtime", "--locked", "--example",
            "pulley_test_fixtures", "--features", "compiler,pulley", "--", scratch)
        env = dict(os.environ, EVX_TRUSTED_PULLEY_TEST_DIR=scratch)
        run("cargo", "test", "-p", "evx-runtime", "--locked", "--no-default-features",
            "--features", "pulley", "--test", "pulley_runtime_only", "--",
            "--ignored", "--exact", "compiler_free_pulley_preserves_execution_limits_and_broker_abi",
            env=env)
    print("Compiler-free Pulley: dependency boundary, score, fuel, deadline, memory and broker passed")


if __name__ == "__main__":
    main()
