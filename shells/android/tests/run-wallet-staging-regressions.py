#!/usr/bin/env python3
"""Run the actual wallet staging task without the Android SDK or native build.

Requires Java 17+ and uses this checkout's Gradle wrapper. GRADLE_USER_HOME may
point to a shared cache. Fixtures contain local pinned releases, so the task
never downloads a wallet or touches this checkout's staged assets.
"""
import json
import os
import pathlib
import re
import subprocess
import tempfile


android = pathlib.Path(__file__).resolve().parents[1]
source = (android / "app/build.gradle.kts").read_text()
staging = source[source.index("val walletRev ="):source.index('tasks.named("preBuild")')]

with tempfile.TemporaryDirectory(prefix="epix-wallet-staging-") as directory:
    root = pathlib.Path(directory)
    shells = root / "shells"
    project = shells / "android"
    app = project / "app"
    app.mkdir(parents=True)
    (project / "settings.gradle.kts").write_text('rootProject.name = "wallet-staging-test"\ninclude(":app")\n')
    (app / "build.gradle.kts").write_text("import java.security.MessageDigest\n" + staging)
    staged = shells / "wallet-ext"
    staged.mkdir()
    dest = app / "src/main/assets/extensions/wallet"
    dest.mkdir(parents=True)
    dest_stamp = dest.parent / "wallet.rev-stamp"
    manifest = {"manifest_version": 2, "version": "0.13.40", "permissions": ["storage"]}

    def pin(revision, script):
        (shells / "wallet-ext.rev").write_text(revision + "\n")
        (shells / "wallet-ext.rev-stamp").write_text(revision)
        (staged / "manifest.json").write_text(json.dumps(manifest))
        (staged / "background.js").write_text(script)

    def stage(override=None):
        env = os.environ.copy()
        env.pop("EPIX_WALLET_DIST", None)
        if override is not None:
            env["EPIX_WALLET_DIST"] = str(override)
        result = subprocess.run(
            [str(android / "gradlew"), "-p", str(project), ":app:stageWalletExt", "--console=plain"],
            env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if result.returncode:
            print(result.stdout)
            result.check_returncode()
        data = json.loads((dest / "manifest.json").read_text())
        assert re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){3}", data["version"])
        assert all(0 <= int(part) <= 65535 for part in data["version"].split("."))
        assert data["permissions"].count("geckoViewAddons") == 1
        assert "storage" in data["permissions"]
        return data["version"]

    first_pin = "123456789abc"
    pin(first_pin, "first pinned build")
    # An existing same-pin assets copy used the upstream version and old stamp.
    (dest / "manifest.json").write_text(json.dumps(manifest))
    (dest / "background.js").write_text("old cached asset")
    dest_stamp.write_text(first_pin)
    first_version = stage()
    assert first_version != manifest["version"], "legacy same-pin staging must be migrated"
    assert (dest / "background.js").read_text() == "first pinned build"
    assert stage() == first_version, "an unchanged pin must keep its version"

    pin("fedcba987654", "second pinned build")
    second_version = stage()
    assert second_version != first_version, "pin changes must refresh a same-version wallet"
    assert (dest / "background.js").read_text() == "second pinned build"
    assert json.loads((staged / "manifest.json").read_text())["version"] == "0.13.40"

    override = root / "local-wallet"
    override.mkdir()
    (override / "manifest.json").write_text(json.dumps(manifest))
    (override / "background.js").write_text("local build")
    local_version = stage(override)
    assert local_version != second_version, "local and pinned builds must have distinct versions"
    assert stage(override) == local_version, "unchanged local contents must keep their version"
    (override / "background.js").write_text("edited local build")
    assert stage(override) != local_version, "local edits must refresh the wallet"
    assert stage() == second_version, "removing an override must restore the pinned version"
    assert (dest / "background.js").read_text() == "second pinned build"

    pin(first_pin, "first pinned build")
    assert stage() == first_version, "rolling back a pin must restore its deterministic version"

    # The stamp is part of the task's outputs, so deleting it cannot leave an
    # apparently up-to-date task that skipped manifest patching.
    dest_stamp.unlink()
    assert stage() == first_version
    assert dest_stamp.is_file()

print("Wallet staging regressions passed: legacy cache migration, pin updates, stable versions, local edits, rollback and permission preservation.")
