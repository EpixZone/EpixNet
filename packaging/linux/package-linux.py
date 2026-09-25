#!/usr/bin/env python3
"""Package the validated Linux desktop tree. No root access is needed."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent
BINARIES = ("epix-browser", "epix-nmh", "epix-server")


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def elf_arch(path):
    with Path(path).open("rb") as stream:
        header = stream.read(20)
    if len(header) != 20 or header[:4] != b"\x7fELF" or header[5] != 1:
        raise ValueError(f"{path}: expected a little-endian ELF binary")
    machine = struct.unpack_from("<H", header, 18)[0]
    if header[4] != 2 or machine not in (62, 183):
        raise ValueError(f"{path}: expected 64-bit x86_64 or aarch64 ELF, got class={header[4]}, machine={machine}")
    return {62: "x86_64", 183: "aarch64"}[machine]


def check_firefox(directory, expected=None):
    directory = Path(directory)
    expected = expected or os.environ.get("EPIX_ARCH", platform.machine())
    expected = {"amd64": "x86_64", "arm64": "aarch64"}.get(expected, expected)
    for name in ("firefox", "libxul.so"):
        path = directory / name
        if not path.is_file():
            raise ValueError(f"Missing {path}; run packaging/fetch-firefox-esr.sh linux")
        actual = elf_arch(path)
        if actual != expected:
            raise ValueError(f"{path}: {actual} Firefox does not match {expected} EpixNet")
    if not os.access(directory / "firefox", os.X_OK):
        raise ValueError(f"{directory}/firefox is not executable")
    return expected


def validate_stage(stage):
    arch = elf_arch(stage / BINARIES[0])
    for binary in BINARIES:
        if elf_arch(stage / binary) != arch or not os.access(stage / binary, os.X_OK):
            raise ValueError(f"{binary}: architecture mismatch or missing executable permission")
    check_firefox(stage / "firefox", arch)
    if elf_arch(stage / "firefox/libepix-sandbox-probe.so") != arch:
        raise ValueError("Firefox sandbox probe architecture does not match the launcher")
    policies = json.loads((stage / "firefox/distribution/policies.json").read_text())
    if "epix-ca.pem" not in policies["policies"]["Certificates"]["Install"]:
        raise ValueError("Firefox is missing the packaged local-CA policy")
    for size in (48, 64, 128, 256, 512):
        if not (stage / f"icons/hicolor/{size}x{size}/apps/epix.png").is_file():
            raise ValueError(f"Missing {size}px desktop icon")
    return arch


def tool(name, cache):
    """Every downloaded build tool is pinned by SHA-256, including cache hits."""
    spec = json.loads((HERE / "tools.json").read_text())[name]
    cache.mkdir(parents=True, exist_ok=True)
    download = cache / (name + "-" + spec["sha256"] + ".download")
    if not download.exists():
        temporary = download.with_suffix(".partial")
        with urllib.request.urlopen(spec["url"], timeout=120) as response, temporary.open("wb") as dest:
            shutil.copyfileobj(response, dest)
        temporary.replace(download)
    if hashlib.sha256(download.read_bytes()).hexdigest() != spec["sha256"]:
        raise ValueError(f"Checksum mismatch for {name}; refresh packaging/linux/tools.json deliberately")
    executable = cache / name
    if "member" in spec:
        with tarfile.open(download) as archive:
            with archive.extractfile(spec["member"]) as source, executable.open("wb") as dest:
                shutil.copyfileobj(source, dest)
    else:
        shutil.copyfile(download, executable)
    executable.chmod(0o755)
    return executable


def elf_files(stage):
    result = []
    for path in stage.rglob("*"):
        if path.is_file() and not path.is_symlink():
            with path.open("rb") as stream:
                if stream.read(4) == b"\x7fELF":
                    result.append(path)
    return result


def glibc_requirement(files):
    versions = set()
    for path in files:
        output = run("readelf", "--version-info", path, capture_output=True, text=True).stdout
        versions.update(re.findall(r"\bGLIBC_(\d+\.\d+)(?:\D|$)", output))
    return max(versions, key=lambda v: tuple(map(int, v.split("."))), default="2.35")


def native_config(stage, version, arch, work, files):
    contents = [
        {"src": str(stage / binary), "dst": "/opt/epixnet/" + binary}
        for binary in BINARIES
    ]
    contents += [
        {"src": str(stage / "firefox") + "/", "dst": "/opt/epixnet/firefox", "type": "tree"},
        {"src": str(stage / "icons") + "/", "dst": "/usr/share/icons", "type": "tree"},
        {"src": str(HERE / "epix.desktop"), "dst": "/usr/share/applications/epix.desktop"},
        {"src": str(stage / "LICENSE"), "dst": "/usr/share/doc/epixnet/copyright"},
        {"src": str(HERE / "enable-sandbox.sh"), "dst": "/usr/share/epixnet/enable-sandbox.sh"},
    ]
    contents += [
        {"src": "/opt/epixnet/" + binary, "dst": "/usr/bin/" + binary, "type": "symlink"}
        for binary in BINARIES
    ]
    # Derive Debian library versions from the actual ELF inputs, so even a
    # developer building on a newer distro cannot publish false requirements.
    debian = work / "debian"
    debian.mkdir(exist_ok=True)
    (debian / "control").write_text("Source: epixnet\n\nPackage: epixnet\nArchitecture: any\n")
    dependencies = []
    diagnostics = []
    firefox_files = [path for path in files if path.is_relative_to(stage / "firefox")]
    native_files = [path for path in files if path not in firefox_files]
    # Mozilla ships its own NSS/NSPR. Using the builder's system symbols for
    # those private libraries invents a libnss3 >= 3.94 dependency and makes
    # the package impossible to install on Debian 12. Exclude those providers
    # only for Firefox; retain all requirements from our native executables.
    private_providers = ["-x" + provider for library, provider in
                         (("libnss3.so", "libnss3"), ("libnspr4.so", "libnspr4"))
                         if (stage / "firefox" / library).is_file()]
    for group, exclusions in ((native_files, []), (firefox_files, private_providers)):
        if not group:
            continue
        result = run("dpkg-shlibdeps", "-O", "--ignore-missing-info", "-l" + str(stage / "firefox"),
                     *exclusions, *("-e" + str(path) for path in group),
                     cwd=work, capture_output=True, text=True)
        diagnostics.append(result.stderr)
        dependencies.extend(result.stdout.strip().removeprefix("shlibs:Depends=").split(", "))
    (work / "shlibdeps.log").write_text("\n".join(diagnostics))
    if not dependencies or not dependencies[0]:
        raise ValueError("dpkg-shlibdeps returned no runtime dependencies")
    # Libraries loaded by Firefox/GTK at runtime, plus desktop registration.
    dependencies += ["libasound2 | libasound2t64", "libdbus-glib-1-2", "libgtk-3-0 | libgtk-3-0t64",
                     "libnss3", "libnspr4", "libgbm1", "libx11-xcb1", "libxt6 | libxt6t64",
                     "libnss3-tools", "xdg-utils", "desktop-file-utils"]
    # Fedora dependencies use library capabilities rather than Debian package
    # names. Private Mozilla libraries are provided by our own bundle.
    private = {path.name for path in files}
    needed = set()
    for path in files:
        dynamic = run("readelf", "-d", path, capture_output=True, text=True).stdout
        needed.update(re.findall(r"\(NEEDED\).*?\[(.*?)\]", dynamic))
    rpm_depends = [name + "()(64bit)" for name in sorted(needed - private)]
    rpm_depends += [f"libc.so.6(GLIBC_{glibc_requirement(files)})(64bit)",
                    "libasound.so.2()(64bit)", "libdbus-glib-1.so.2()(64bit)",
                    "libgbm.so.1()(64bit)", "libX11-xcb.so.1()(64bit)",
                    "/usr/bin/certutil", "xdg-utils", "desktop-file-utils"]
    return {
        "name": "epixnet", "arch": {"x86_64": "amd64", "aarch64": "arm64"}[arch],
        "platform": "linux", "version": version, "release": "1", "section": "net",
        "priority": "optional", "umask": 0o022,
        "maintainer": "EpixZone <44410798+MudDev@users.noreply.github.com>",
        "homepage": "https://epixnet.io", "license": "MIT AND MPL-2.0",
        "description": "EpixNet desktop browser and decentralized web node\nIncludes a managed Firefox ESR and the native messaging host.",
        "contents": contents,
        "scripts": {
            "preinstall": str(HERE / "check-not-running.sh"),
            "postinstall": str(HERE / "update-desktop.sh"),
            "postremove": str(HERE / "update-desktop.sh"),
        },
        "overrides": {
            "deb": {"depends": sorted(set(dependencies)), "recommends": ["libayatana-appindicator3-1"]},
            "rpm": {"depends": sorted(set(rpm_depends)),
                    "recommends": ["libayatana-appindicator3.so.1()(64bit)"]},
        },
    }


def appimage(stage, output, version, work, cache):
    deploy = tool("linuxdeploy-x86_64.AppImage", cache)
    tool("linuxdeploy-plugin-gtk.sh", cache)
    runtime = tool("runtime-x86_64", cache)
    appdir = work / "EpixNet.AppDir"
    if appdir.exists():
        shutil.rmtree(appdir)
    # Keep the browser, native host and Firefox adjacent, as the launcher
    # resolves both through current_exe(). The mounted tree stays read-only;
    # profiles and certificates continue to live in the user's data directory.
    bindir = appdir / "usr/bin"
    bindir.mkdir(parents=True)
    for binary in BINARIES:
        shutil.copy2(stage / binary, bindir / binary)
    shutil.copytree(stage / "firefox", bindir / "firefox", symlinks=True)
    shutil.copytree(stage / "icons", appdir / "usr/share/icons")
    licenses = appdir / "usr/share/doc/epixnet"
    licenses.mkdir(parents=True)
    shutil.copy2(stage / "LICENSE", licenses / "copyright")
    shutil.copy2(HERE / "enable-sandbox.sh", appdir / "enable-sandbox.sh")
    env = dict(os.environ, APPIMAGE_EXTRACT_AND_RUN="1", DEPLOY_GTK_VERSION="3",
               LDAI_OUTPUT=str(output / f"EpixNet-{version}-x86_64.AppImage"),
               LDAI_VERSION=version, LDAI_RUNTIME_FILE=str(runtime),
               LDAI_NO_APPSTREAM="1", NO_STRIP="1",
               PATH=str(cache) + os.pathsep + os.environ["PATH"])
    # tray-icon dlopens this library, so an ELF dependency walk cannot find it.
    tray_dir = run("pkg-config", "--variable=libdir", "ayatana-appindicator3-0.1",
                   capture_output=True, text=True).stdout.strip()
    # libxul refers to private Mozilla libraries without a normal ELF RPATH.
    # Supply their directory while collecting dependencies so the scan does
    # not skip libxul when it cannot resolve libmozsandbox.so.
    collect_env = dict(env, LD_LIBRARY_PATH=str(bindir / "firefox"))
    run(deploy, "--appdir", appdir, "--desktop-file", HERE / "epix.desktop",
        "--icon-file", stage / "icons/hicolor/256x256/apps/epix.png",
        # Firefox lives below usr/bin and is not part of linuxdeploy's default
        # executable scan. Collect its external dependencies, then restore
        # Mozilla's files: Firefox's custom ELF loader cannot tolerate every
        # patchelf rewrite (a rewritten libnspr4 segfaulted at startup).
        "--deploy-deps-only", bindir / "firefox",
        "--library", Path(tray_dir) / "libayatana-appindicator3.so.1",
        "--plugin", "gtk", env=collect_env)
    shutil.rmtree(bindir / "firefox")
    shutil.copytree(stage / "firefox", bindir / "firefox", symlinks=True)
    wrapper = bindir / "firefox/appimage-firefox"
    shutil.copy2(HERE / "firefox-wrapper.sh", wrapper)
    wrapper.chmod(0o755)
    # The first pass created a wrapped default AppRun. Remove both so the GTK
    # hook wraps our custom launcher rather than reusing that stale symlink.
    for name in ("AppRun", "AppRun.wrapped"):
        (appdir / name).unlink(missing_ok=True)
    # The second pass scans the normal bin/lib locations, not the private
    # Firefox directory. Its wrapper supplies the library search path.
    run(deploy, "--appdir", appdir, "--custom-apprun", HERE / "AppRun",
        "--output", "appimage", env=env)
    for source in elf_files(stage / "firefox"):
        packaged = bindir / "firefox" / source.relative_to(stage / "firefox")
        if hashlib.sha256(source.read_bytes()).digest() != hashlib.sha256(packaged.read_bytes()).digest():
            raise ValueError(f"AppImage assembly modified Mozilla binary {source.name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-firefox", type=Path)
    parser.add_argument("--stage", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--version")
    parser.add_argument("--formats", default="tar,deb,rpm,appimage")
    args = parser.parse_args()
    if args.check_firefox:
        print("Firefox architecture:", check_firefox(args.check_firefox))
        return
    if not args.stage or not args.output or not args.version:
        parser.error("--stage, --output and --version are required")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", args.version):
        parser.error("version must be a semantic version such as 0.5.14 or 0.5.14-dev.1")
    formats = set(args.formats.split(","))
    if not formats or formats - {"tar", "deb", "rpm", "appimage"}:
        parser.error("formats must be a comma-separated subset of tar,deb,rpm,appimage")
    stage, output = args.stage.resolve(), args.output.resolve()
    arch = validate_stage(stage)
    if formats - {"tar"} and (arch != "x86_64" or platform.machine() != "x86_64"):
        parser.error("native installers currently target x86_64; use --formats tar for other architectures")
    output.mkdir(parents=True, exist_ok=True)
    work = output / ".packaging"
    work.mkdir(exist_ok=True)
    cache = work / "tools"
    files = elf_files(stage)
    glibc = glibc_requirement(files)
    if os.environ.get("EPIX_RELEASE_BUILD") == "1" and tuple(map(int, glibc.split("."))) > (2, 35):
        raise ValueError(f"Release requires glibc {glibc}; build on Ubuntu 22.04 for the supported baseline")
    print(f"Packaging {args.version} ({arch}), minimum glibc {glibc}", flush=True)
    artifacts = []
    if "tar" in formats:
        artifact = output / f"epix-linux-{args.version}.tar.gz"
        run("tar", "-C", stage.parent, "-czf", artifact, stage.name)
        artifacts.append(artifact)
    if formats & {"deb", "rpm"}:
        config = native_config(stage, args.version, arch, work, files)
        config_path = work / "nfpm.json"
        config_path.write_text(json.dumps(config, indent=2) + "\n")
        nfpm = tool("nfpm", cache)
        for kind in ("deb", "rpm"):
            if kind in formats:
                artifact = output / (f"epixnet_{args.version}_amd64.deb" if kind == "deb"
                                     else f"epixnet-{args.version}.x86_64.rpm")
                run(nfpm, "package", "--config", config_path, "--packager", kind, "--target", artifact)
                artifacts.append(artifact)
    if "appimage" in formats:
        appimage(stage, output, args.version, work, cache)
        artifacts.append(output / f"EpixNet-{args.version}-x86_64.AppImage")
        helper = output / "enable-epixnet-sandbox.sh"
        shutil.copy2(HERE / "enable-sandbox.sh", helper)
        artifacts.append(helper)
    with (output / "SHA256SUMS").open("w") as manifest:
        for artifact in artifacts:
            digest = hashlib.sha256()
            with artifact.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            manifest.write(f"{digest.hexdigest()}  {artifact.name}\n")
    print("Packages ready in", output)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr)
        sys.exit(f"Linux packaging failed: {error}")
