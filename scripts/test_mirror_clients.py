#!/usr/bin/env python3
"""Real APT/DNF fixtures. Must run in a disposable, network-isolated container."""
import argparse
import datetime as dt
import email.utils
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tarfile
import threading

from package_mirror import snapshot
from package_mirror.server import make_server


def run(*arguments, **kwargs):
    print("+", " ".join(str(arg) for arg in arguments), flush=True)
    return subprocess.run([str(arg) for arg in arguments], check=True, **kwargs)


def gpg(root, *args, **kwargs):
    return run("gpg", "--batch", "--homedir", root / "keys", *args, **kwargs)


def generate(root):
    root.mkdir(parents=True, exist_ok=True)
    (root / "keys").mkdir(mode=0o700)
    gpg(root, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key",
        "Epix mirror disposable fixture <fixture@example.invalid>", "rsa2048", "sign", "1d")
    with (root / "upstream.gpg").open("wb") as output:
        gpg(root, "--export", stdout=output)
    with (root / "upstream.asc").open("wb") as output:
        gpg(root, "--armor", "--export", stdout=output)
    for version in ("1.0", "2.0"):
        apt_repo(root, version)
        rpm_repo(root, version)
    expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=12)).isoformat()
    for manager in ("apt", "dnf"):
        for version in ("1.0", "2.0"):
            snapshot.stage(root / f"{manager}-{version}", root / f"snapshot-{manager}-{version}", manager, expires)
        bad = root / f"{manager}-badsig"
        shutil.copytree(root / f"{manager}-2.0", bad)
        if manager == "apt":
            metadata = bad / "dists/stable/InRelease"
            metadata.write_bytes(metadata.read_bytes().replace(b"Origin: Epix fixture", b"Origin: Altered mirror"))
        else:
            metadata = bad / "repodata/repomd.xml"
            metadata.write_bytes(metadata.read_bytes() + b"\n<!-- unsigned modification -->\n")
        snapshot.stage(bad, root / f"snapshot-{manager}-badsig", manager, expires)
    for version in ("1.0", "2.0"):
        brew_artifact(root, version, expires)


def brew_artifact(root, version, expires):
    public = root / f"homebrew-{version}"
    public.mkdir()
    filename = f"epix-mirror-fixture-{version}.tar.gz"
    with tarfile.open(public / filename, "w:gz") as archive:
        data = f'#!/bin/sh\nprintf "{version}\\n"\n'.encode()
        member = tarfile.TarInfo(f"epix-mirror-fixture-{version}/epix-mirror-fixture")
        member.mode, member.size = 0o755, len(data)
        archive.addfile(member, io.BytesIO(data))
    digest = hashlib.sha256((public / filename).read_bytes()).hexdigest()
    mapping = root / f"brew-map-{version}.json"
    mapping.write_text(json.dumps({f"/v2/epix/fixture/blobs/sha256:{digest}": filename}))
    snapshot.stage(public, root / f"snapshot-homebrew-ghcr-{version}", "homebrew", expires, mapping)


def apt_repo(root, version):
    repo = root / f"apt-{version}"
    pool = repo / "pool/main"
    pool.mkdir(parents=True)
    for suffix in ("helper", "fixture"):
        name = "epix-mirror-" + suffix
        build = root / f"deb-{name}-{version}"
        control = build / "DEBIAN"
        control.mkdir(parents=True)
        dependency = f"Depends: epix-mirror-helper (= {version})\n" if suffix == "fixture" else ""
        (control / "control").write_text(f"Package: {name}\nVersion: {version}\nArchitecture: all\n"
            "Maintainer: Disposable fixture <fixture@example.invalid>\n" + dependency + "Description: Offline mirror test\n")
        payload = build / f"usr/share/{name}"
        payload.mkdir(parents=True)
        (payload / "version").write_text(version + "\n")
        if suffix == "fixture":
            post = control / "postinst"
            post.write_text("#!/bin/sh\nset -eu\nmkdir -p /var/lib/epix-mirror-fixture\n"
                            f"printf '%s\\n' '{version}' > /var/lib/epix-mirror-fixture/installed\n")
            post.chmod(0o755)
        run("dpkg-deb", "--root-owner-group", "--build", build, pool / f"{name}_{version}_all.deb")
    indexes = repo / "dists/stable/main/binary-amd64"
    indexes.mkdir(parents=True)
    with (indexes / "Packages").open("wb") as output:
        run("dpkg-scanpackages", "pool", "/dev/null", cwd=repo, stdout=output)
    release = repo / "dists/stable/Release"
    release_body = subprocess.check_output(["apt-ftparchive", "release", "."], cwd=release.parent)
    with release.open("wb") as output:
        output.write(b"Origin: Epix fixture\nLabel: Epix fixture\nSuite: stable\nCodename: stable\nArchitectures: amd64\nComponents: main\n")
        until = email.utils.format_datetime(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1))
        output.write(f"Valid-Until: {until}\n".encode())
        output.write(release_body)
    gpg(root, "--yes", "--detach-sign", "--output", str(release) + ".gpg", release)
    gpg(root, "--yes", "--clearsign", "--output", release.with_name("InRelease"), release)


def rpm_repo(root, version):
    repo = root / f"dnf-{version}"
    repo.mkdir()
    build = root / f"rpmbuild-{version}"
    for folder in ("SPECS", "BUILD", "BUILDROOT", "RPMS", "SOURCES", "SRPMS"):
        (build / folder).mkdir(parents=True)
    for suffix in ("helper", "fixture"):
        name = "epix-mirror-" + suffix
        dependency = f"Requires: epix-mirror-helper = {version}\n" if suffix == "fixture" else ""
        spec = build / "SPECS" / f"{name}.spec"
        spec.write_text(f"Name: {name}\nVersion: {version}\nRelease: 1\nSummary: Disposable mirror fixture\n"
            "License: MIT\nBuildArch: noarch\n" + dependency + "%description\nOffline mirror test\n"
            f"%install\nmkdir -p %{{buildroot}}/usr/share/{name}\nprintf '{version}\\n' > %{{buildroot}}/usr/share/{name}/version\n"
            f"%files\n/usr/share/{name}/version\n")
        run("rpmbuild", "--define", f"_topdir {build}", "-bb", spec)
    for package in (build / "RPMS/noarch").glob("*.rpm"):
        run("rpmsign", "--define", "__gpg /usr/bin/gpg", "--define", f"_gpg_path {root / 'keys'}",
            "--define", "_gpg_name fixture@example.invalid", "--addsign", package)
        shutil.copy2(package, repo / package.name)
    run("createrepo_c", "--checksum", "sha256", repo)
    gpg(root, "--yes", "--armor", "--detach-sign", "--output", repo / "repodata/repomd.xml.asc", repo / "repodata/repomd.xml")


def running(path, port=0):
    server = make_server(path, port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def native(root, manager):
    first = root / f"exported-{manager}-1.0"
    second = root / f"exported-{manager}-2.0"
    # These must be the result of the real node export, never a substituted stage directory.
    for path in (first, second):
        if not (path / "epix-export.json").exists():
            raise ValueError("Run verified EpixNet export before native client validation")
    server, thread = running(first)
    port = server.server_port
    url = f"http://127.0.0.1:{port}"
    try:
        if manager == "apt":
            sources = root / "fixture.sources.list"
            sources.write_text(f"deb [signed-by={root / 'upstream.gpg'}] {url} stable main\n")
            base = ["apt-get", "-o", f"Dir::Etc::sourcelist={sources}", "-o", "Dir::Etc::sourceparts=-",
                    "-o", "APT::Get::List-Cleanup=0", "-o", "Acquire::Retries=0"]
            run(*base, "update")
            run(*base, "install", "-y", "--no-install-recommends", "epix-mirror-fixture")
            assert Path("/usr/share/epix-mirror-fixture/version").read_text().strip() == "1.0"
            assert Path("/var/lib/epix-mirror-fixture/installed").read_text().strip() == "1.0"
        else:
            config = root / "dnf.conf"
            config.write_text(f"[main]\nreposdir=/nonexistent\nplugins=0\n[fixture]\nname=fixture\nbaseurl={url}\n"
                              f"gpgkey=file://{root / 'upstream.asc'}\ngpgcheck=1\nrepo_gpgcheck=1\nmetadata_expire=0\n")
            install = Path(tempfile.mkdtemp(prefix="epix-mirror-rpm-root-"))
            base = ["dnf", "-c", config, "--installroot", install, "--releasever", "1", "-y"]
            run(*base, "install", "epix-mirror-fixture")
            assert (install / "usr/share/epix-mirror-fixture/version").read_text().strip() == "1.0"
        server.shutdown()
        server.server_close()
        thread.join()
        server, thread = running(second, port)
        if manager == "apt":
            run(*base, "update")
            run(*base, "install", "-y", "--no-install-recommends", "epix-mirror-fixture")
            assert Path("/usr/share/epix-mirror-fixture/version").read_text().strip() == "2.0"
            assert Path("/usr/share/epix-mirror-helper/version").read_text().strip() == "2.0"
            assert Path("/var/lib/epix-mirror-fixture/installed").read_text().strip() == "2.0"
        else:
            run(*base, "--refresh", "upgrade", "epix-mirror-fixture")
            assert (install / "usr/share/epix-mirror-fixture/version").read_text().strip() == "2.0"
            assert (install / "usr/share/epix-mirror-helper/version").read_text().strip() == "2.0"
        server.shutdown()
        server.server_close()
        thread.join()
        bad = root / f"exported-{manager}-badsig"
        if not (bad / "epix-export.json").exists():
            raise ValueError("Bad-upstream-signature fixture must also pass through verified xite export")
        server, thread = running(bad, port)
        command = ([*base, "-o", "APT::Update::Error-Mode=any", "update"] if manager == "apt"
                   else [*base, "--refresh", "makecache"])
        rejected = subprocess.run([str(arg) for arg in command], capture_output=True, text=True)
        print(rejected.stdout + rejected.stderr, flush=True)
        assert rejected.returncode != 0, "native client accepted altered upstream metadata"
        assert ("BADSIG" in rejected.stdout + rejected.stderr if manager == "apt"
                else "signature" in (rejected.stdout + rejected.stderr).lower())
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    (root / f"{manager}-result.json").write_text(json.dumps({"manager": manager, "install": "1.0", "upgrade": "2.0",
        "dependency_installed_and_upgraded": True, "native_signature_verification": True,
        "altered_upstream_signature_rejected": True, "network": "container none"}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("generate", "apt", "dnf"))
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    if not Path("/run/.containerenv").exists() and not Path("/.dockerenv").exists():
        raise SystemExit("Refusing host installation: use a disposable container")
    # This suite needs only loopback. Fail before running any package scripts if a route exists.
    if any(line.split()[1] == "00000000" for line in Path("/proc/net/route").read_text().splitlines()[1:]):
        raise SystemExit("Use --network none for fixture generation and native installation")
    generate(args.root) if args.action == "generate" else native(args.root, args.action)
