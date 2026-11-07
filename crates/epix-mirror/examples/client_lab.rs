//! Disposable native-client verification. The program refuses package operations
//! outside a container with only loopback. Never run package fixtures on a host.
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This lab requires a disposable Linux container; use the Windows Chocolatey test on Windows.");
    std::process::exit(1);
}
#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = lab::run() {
        eprintln!("Mirror lab failed: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod lab {
    use anyhow::{ensure, Context, Result};
    use epix_mirror::{export, stage, ExportOptions, Server, StageOptions};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeMap,
        fs::{self, File},
        io::Write,
        net::TcpListener,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::{Child, Command, Output},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
        time::{Duration, Instant},
    };

    fn cmd(program: impl AsRef<std::ffi::OsStr>, args: &[&str]) -> Command {
        let mut command = Command::new(program);
        command.args(args);
        command
    }
    fn run_command(mut command: Command) -> Result<()> {
        println!("+ {:?}", command);
        ensure!(command.status()?.success(), "Native command failed");
        Ok(())
    }
    fn output(mut command: Command) -> Result<Vec<u8>> {
        let result = command.output()?;
        ensure!(
            result.status.success(),
            "Native command failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        Ok(result.stdout)
    }
    fn text(path: &Path, value: &str) -> Result<()> {
        fs::create_dir_all(path.parent().context("Missing fixture parent")?)?;
        fs::write(path, value)?;
        Ok(())
    }
    fn checksum(path: &Path) -> Result<String> {
        Ok(hex::encode(Sha256::digest(fs::read(path)?)))
    }
    fn gpg(root: &Path, args: &[&str]) -> Command {
        let mut command = cmd("gpg", &["--batch", "--homedir"]);
        command.arg(root.join("keys")).args(args);
        command
    }
    fn only_loopback() -> Result<()> {
        let bytes = output(cmd("ip", &["-o", "link", "show"]))?;
        let links = std::str::from_utf8(&bytes)?;
        ensure!(
            !links.is_empty()
                && links
                    .lines()
                    .all(|line| line.split_whitespace().nth(1) == Some("lo:")),
            "Use a private network namespace with only loopback"
        );
        Ok(())
    }
    fn container() -> Result<()> {
        ensure!(
            Path::new("/run/.containerenv").exists() || Path::new("/.dockerenv").exists(),
            "Refusing host package operations; use a disposable container"
        );
        only_loopback()
    }
    struct Serving {
        port: u16,
        stop: Arc<AtomicBool>,
        worker: Option<thread::JoinHandle<Result<()>>>,
    }
    impl Serving {
        fn new(path: &Path, port: u16) -> Result<Self> {
            let server = Server::bind(path, port)?;
            let port = server.port();
            let stop = Arc::new(AtomicBool::new(false));
            let signal = stop.clone();
            let worker = thread::spawn(move || server.run(signal));
            Ok(Self {
                port,
                stop,
                worker: Some(worker),
            })
        }
    }
    impl Drop for Serving {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }
    struct Node(Child);
    impl Drop for Node {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    pub fn run() -> Result<()> {
        let mut args = std::env::args().skip(1);
        let action = args
            .next()
            .context("Expected generate|apt|dnf|brew|export-node")?;
        let mut options = BTreeMap::new();
        while let Some(key) = args.next() {
            options.insert(key, args.next().context("Missing option value")?);
        }
        let root = PathBuf::from(options.get("--root").context("Missing --root")?);
        if action == "export-node" {
            return node_exports(
                &root,
                Path::new(
                    options
                        .get("--node-binary")
                        .context("Missing --node-binary")?,
                ),
                Path::new(options.get("--output").context("Missing --output")?),
            );
        }
        container()?;
        match action.as_str() {
            "generate" => generate(&root),
            "apt" | "dnf" => native(&root, &action),
            "brew" => brew(
                &root,
                Path::new(
                    options
                        .get("--prefix")
                        .map(String::as_str)
                        .unwrap_or("/home/linuxbrew/.linuxbrew"),
                ),
            ),
            _ => anyhow::bail!("Unknown lab action"),
        }
    }

    fn generate(root: &Path) -> Result<()> {
        ensure!(!root.exists(), "Fixture root must be new");
        fs::create_dir_all(root.join("keys"))?;
        fs::set_permissions(root.join("keys"), fs::Permissions::from_mode(0o700))?;
        run_command(gpg(
            root,
            &[
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "Epix mirror disposable fixture <fixture@example.invalid>",
                "rsa2048",
                "sign",
                "1d",
            ],
        ))?;
        fs::write(root.join("upstream.gpg"), output(gpg(root, &["--export"]))?)?;
        fs::write(
            root.join("upstream.asc"),
            output(gpg(root, &["--armor", "--export"]))?,
        )?;
        let expires = (chrono::Utc::now() + chrono::Duration::hours(12)).to_rfc3339();
        for version in ["1.0", "2.0"] {
            apt_repo(root, version)?;
            rpm_repo(root, version)?;
            brew_artifact(root, version, &expires)?;
        }
        for manager in ["apt", "dnf"] {
            for version in ["1.0", "2.0"] {
                stage(StageOptions {
                    source: &root.join(format!("{manager}-{version}")),
                    output: &root.join(format!("snapshot-{manager}-{version}")),
                    manager,
                    expires: &expires,
                    url_map: None,
                })?;
            }
            let bad = root.join(format!("{manager}-badsig"));
            copy_tree(&root.join(format!("{manager}-2.0")), &bad)?;
            if manager == "apt" {
                let path = bad.join("dists/stable/InRelease");
                fs::write(
                    &path,
                    fs::read_to_string(&path)?
                        .replace("Origin: Epix fixture", "Origin: Altered mirror"),
                )?;
            } else {
                let mut file = fs::OpenOptions::new()
                    .append(true)
                    .open(bad.join("repodata/repomd.xml"))?;
                writeln!(file, "\n<!-- unsigned modification -->")?;
            }
            stage(StageOptions {
                source: &bad,
                output: &root.join(format!("snapshot-{manager}-badsig")),
                manager,
                expires: &expires,
                url_map: None,
            })?;
        }
        Ok(())
    }
    fn copy_tree(source: &Path, target: &Path) -> Result<()> {
        fs::create_dir_all(target)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let to = target.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_tree(&entry.path(), &to)?;
            } else {
                fs::copy(entry.path(), to)?;
            }
        }
        Ok(())
    }
    fn apt_repo(root: &Path, version: &str) -> Result<()> {
        let repo = root.join(format!("apt-{version}"));
        let pool = repo.join("pool/main");
        fs::create_dir_all(&pool)?;
        for suffix in ["helper", "fixture"] {
            let name = format!("epix-mirror-{suffix}");
            let build = root.join(format!("deb-{name}-{version}"));
            let control = build.join("DEBIAN");
            let dependency = if suffix == "fixture" {
                format!("Depends: epix-mirror-helper (= {version})\n")
            } else {
                String::new()
            };
            text(&control.join("control"),&format!("Package: {name}\nVersion: {version}\nArchitecture: all\nMaintainer: Disposable fixture <fixture@example.invalid>\n{dependency}Description: Offline mirror test\n"))?;
            text(
                &build.join(format!("usr/share/{name}/version")),
                &format!("{version}\n"),
            )?;
            if suffix == "fixture" {
                let post = control.join("postinst");
                text(&post,&format!("#!/bin/sh\nset -eu\nmkdir -p /var/lib/epix-mirror-fixture\nprintf '%s\\n' '{version}' > /var/lib/epix-mirror-fixture/installed\n"))?;
                fs::set_permissions(post, fs::Permissions::from_mode(0o755))?;
            }
            let mut command = cmd("dpkg-deb", &["--root-owner-group", "--build"]);
            command
                .arg(&build)
                .arg(pool.join(format!("{name}_{version}_all.deb")));
            run_command(command)?;
        }
        let indexes = repo.join("dists/stable/main/binary-amd64");
        fs::create_dir_all(&indexes)?;
        let mut scan = cmd("dpkg-scanpackages", &["pool", "/dev/null"]);
        scan.current_dir(&repo);
        fs::write(indexes.join("Packages"), output(scan)?)?;
        let release = repo.join("dists/stable/Release");
        let mut list = cmd("apt-ftparchive", &["release", "."]);
        list.current_dir(release.parent().unwrap());
        let until = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc2822();
        let mut content=format!("Origin: Epix fixture\nLabel: Epix fixture\nSuite: stable\nCodename: stable\nArchitectures: amd64\nComponents: main\nValid-Until: {until}\n").into_bytes();
        content.extend(output(list)?);
        fs::write(&release, content)?;
        let mut detached = gpg(root, &["--yes", "--detach-sign", "--output"]);
        detached
            .arg(release.with_file_name("Release.gpg"))
            .arg(&release);
        run_command(detached)?;
        let mut inline = gpg(root, &["--yes", "--clearsign", "--output"]);
        inline
            .arg(release.with_file_name("InRelease"))
            .arg(&release);
        run_command(inline)
    }
    fn rpm_repo(root: &Path, version: &str) -> Result<()> {
        let repo = root.join(format!("dnf-{version}"));
        fs::create_dir_all(&repo)?;
        let build = root.join(format!("rpmbuild-{version}"));
        for folder in ["SPECS", "BUILD", "BUILDROOT", "RPMS", "SOURCES", "SRPMS"] {
            fs::create_dir_all(build.join(folder))?;
        }
        for suffix in ["helper", "fixture"] {
            let name = format!("epix-mirror-{suffix}");
            let dependency = if suffix == "fixture" {
                format!("Requires: epix-mirror-helper = {version}\n")
            } else {
                String::new()
            };
            let spec = build.join("SPECS").join(format!("{name}.spec"));
            text(&spec,&format!("Name: {name}\nVersion: {version}\nRelease: 1\nSummary: Disposable mirror fixture\nLicense: MIT\nBuildArch: noarch\n{dependency}%description\nOffline mirror test\n%install\nmkdir -p %{{buildroot}}/usr/share/{name}\nprintf '{version}\\n' > %{{buildroot}}/usr/share/{name}/version\n%files\n/usr/share/{name}/version\n"))?;
            let mut command = cmd("rpmbuild", &["--define"]);
            command
                .arg(format!("_topdir {}", build.display()))
                .arg("-bb")
                .arg(spec);
            run_command(command)?;
        }
        for package in fs::read_dir(build.join("RPMS/noarch"))? {
            let package = package?.path();
            let mut command = cmd("rpmsign", &["--define", "__gpg /usr/bin/gpg", "--define"]);
            command
                .arg(format!("_gpg_path {}", root.join("keys").display()))
                .args(["--define", "_gpg_name fixture@example.invalid", "--addsign"])
                .arg(&package);
            run_command(command)?;
            fs::copy(&package, repo.join(package.file_name().unwrap()))?;
        }
        let mut command = cmd("createrepo_c", &["--checksum", "sha256"]);
        command.arg(&repo);
        run_command(command)?;
        let mut sign = gpg(root, &["--yes", "--armor", "--detach-sign", "--output"]);
        sign.arg(repo.join("repodata/repomd.xml.asc"))
            .arg(repo.join("repodata/repomd.xml"));
        run_command(sign)
    }
    fn brew_artifact(root: &Path, version: &str, expires: &str) -> Result<()> {
        let public = root.join(format!("homebrew-{version}"));
        fs::create_dir_all(&public)?;
        let name = format!("epix-mirror-fixture-{version}.tar.gz");
        let compressed = flate2::write::GzEncoder::new(
            File::create(public.join(&name))?,
            flate2::Compression::default(),
        );
        let mut archive = tar::Builder::new(compressed);
        let body = format!("#!/bin/sh\nprintf '{version}\\n'\n");
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        archive.append_data(
            &mut header,
            format!("epix-mirror-fixture-{version}/epix-mirror-fixture"),
            body.as_bytes(),
        )?;
        archive.into_inner()?.finish()?;
        let digest = checksum(&public.join(&name))?;
        let map = root.join(format!("brew-map-{version}.json"));
        fs::write(
            &map,
            serde_json::to_vec(&json!({format!("/v2/epix/fixture/blobs/sha256:{digest}"):name}))?,
        )?;
        stage(StageOptions {
            source: &public,
            output: &root.join(format!("snapshot-homebrew-ghcr-{version}")),
            manager: "homebrew",
            expires,
            url_map: Some(&map),
        })?;
        Ok(())
    }

    fn native(root: &Path, manager: &str) -> Result<()> {
        let mut port = 0;
        let mut base: Vec<String> = Vec::new();
        let install = tempfile::tempdir()?;
        for version in ["1.0", "2.0", "badsig"] {
            let snapshot = root.join(format!("exported-{manager}-{version}"));
            ensure!(
                snapshot.join("epix-export.json").is_file(),
                "Use real node exports before native verification"
            );
            let serving = Serving::new(&snapshot, port)?;
            port = serving.port;
            let url = format!("http://127.0.0.1:{port}");
            if base.is_empty() {
                base = client_options(root, manager, &url, install.path())?;
            }
            if version == "badsig" {
                let mut args = base.clone();
                if manager == "apt" {
                    args.extend([
                        "-o".into(),
                        "APT::Update::Error-Mode=any".into(),
                        "update".into(),
                    ]);
                } else {
                    args.extend(["--refresh".into(), "makecache".into()]);
                }
                let result = Command::new(&args[0]).args(&args[1..]).output()?;
                let report = format!(
                    "{}{}",
                    String::from_utf8_lossy(&result.stdout),
                    String::from_utf8_lossy(&result.stderr)
                );
                println!("{report}");
                ensure!(
                    !result.status.success()
                        && if manager == "apt" {
                            report.contains("BADSIG")
                        } else {
                            report.to_lowercase().contains("signature")
                        },
                    "Native client accepted altered upstream metadata"
                );
                continue;
            }
            let invoke = |extra: &[&str]| {
                let mut command = Command::new(&base[0]);
                command.args(&base[1..]).args(extra);
                command
            };
            if manager == "apt" {
                run_command(invoke(&["update"]))?;
                run_command(invoke(&[
                    "install",
                    "-y",
                    "--no-install-recommends",
                    "epix-mirror-fixture",
                ]))?;
            } else {
                run_command(invoke(if version == "1.0" {
                    &["install", "epix-mirror-fixture"]
                } else {
                    &["--refresh", "upgrade", "epix-mirror-fixture"]
                }))?;
            }
            let installed = if manager == "apt" {
                Path::new("/")
            } else {
                install.path()
            };
            for suffix in ["fixture", "helper"] {
                ensure!(
                    fs::read_to_string(
                        installed.join(format!("usr/share/epix-mirror-{suffix}/version"))
                    )?
                    .trim()
                        == version,
                    "Incorrect installed version"
                );
            }
            if manager == "apt" {
                ensure!(
                    fs::read_to_string("/var/lib/epix-mirror-fixture/installed")?.trim() == version,
                    "Maintainer script did not run in disposable container"
                );
            }
            drop(serving);
        }
        fs::write(
            root.join(format!("{manager}-result.json")),
            serde_json::to_vec_pretty(
                &json!({"manager":manager,"install":"1.0","upgrade":"2.0","dependency_installed_and_upgraded":true,"altered_upstream_signature_rejected":true,"network":"container none","implementation":"Rust"}),
            )?,
        )?;
        Ok(())
    }
    fn client_options(
        root: &Path,
        manager: &str,
        url: &str,
        install: &Path,
    ) -> Result<Vec<String>> {
        if manager == "apt" {
            let sources = root.join("fixture.sources.list");
            text(
                &sources,
                &format!(
                    "deb [signed-by={}] {url} stable main\n",
                    root.join("upstream.gpg").display()
                ),
            )?;
            Ok(vec![
                "apt-get".into(),
                "-o".into(),
                format!("Dir::Etc::sourcelist={}", sources.display()),
                "-o".into(),
                "Dir::Etc::sourceparts=-".into(),
                "-o".into(),
                "APT::Get::List-Cleanup=0".into(),
                "-o".into(),
                "Acquire::Retries=0".into(),
            ])
        } else {
            let config = root.join("dnf.conf");
            text(&config,&format!("[main]\nreposdir=/nonexistent\nplugins=0\n[fixture]\nname=fixture\nbaseurl={url}\ngpgkey=file://{}\ngpgcheck=1\nrepo_gpgcheck=1\nmetadata_expire=0\n",root.join("upstream.asc").display()))?;
            Ok(vec![
                "dnf".into(),
                "-c".into(),
                config.display().to_string(),
                "--installroot".into(),
                install.display().to_string(),
                "--releasever".into(),
                "1".into(),
                "-y".into(),
            ])
        }
    }

    fn brew(root: &Path, prefix: &Path) -> Result<()> {
        ensure!(
            output(cmd("id", &["-u"]))? != b"0\n",
            "Use the disposable unprivileged Homebrew user"
        );
        let binary = prefix.join("bin/brew");
        let tap = prefix.join("Homebrew/Library/Taps/epix/homebrew-fixture");
        let formula = tap.join("Formula/epix-mirror-fixture.rb");
        fs::create_dir_all(formula.parent().unwrap())?;
        let mut init = cmd("git", &["init"]);
        init.arg(&tap);
        run_command(init)?;
        for version in ["1.0", "2.0"] {
            let snapshot = root.join(format!("exported-homebrew-ghcr-{version}"));
            ensure!(
                snapshot.join("epix-export.json").is_file(),
                "Use real node exported artifacts"
            );
            let digest = checksum(
                &snapshot
                    .join("repo")
                    .join(format!("epix-mirror-fixture-{version}.tar.gz")),
            )?;
            let content=format!("class EpixMirrorFixture < Formula\n  desc \"Disposable offline mirror fixture\"\n  homepage \"https://mirror-fixture.invalid/\"\n  url \"https://ghcr.io/v2/epix/fixture/blobs/sha256:{digest}\"\n  version \"{version}\"\n  sha256 \"{digest}\"\n  license \"MIT\"\n  env :std\n  def install\n    bin.install \"epix-mirror-fixture\"\n  end\nend\n");
            text(&formula, &content)?;
            let mut add = cmd("git", &["-C"]);
            add.arg(&tap).args(["add", "."]);
            run_command(add)?;
            let mut commit = cmd("git", &["-C"]);
            commit
                .arg(&tap)
                .args([
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "-m",
                ])
                .arg(format!("Fixture {version}"));
            run_command(commit)?;
            let serving = Serving::new(&snapshot, 0)?;
            let invoke = |args: &[&str]| {
                let mut command = cmd(&binary, args);
                for key in [
                    "HOMEBREW_NO_AUTO_UPDATE",
                    "HOMEBREW_NO_INSTALL_FROM_API",
                    "HOMEBREW_NO_ANALYTICS",
                    "HOMEBREW_NO_INSTALL_CLEANUP",
                    "HOMEBREW_NO_ENV_HINTS",
                    "HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK",
                ] {
                    command.env(key, "1");
                }
                command.env(
                    "HOMEBREW_ARTIFACT_DOMAIN",
                    format!("http://127.0.0.1:{}", serving.port),
                );
                command
            };
            run_command(invoke(&[
                if version == "1.0" {
                    "install"
                } else {
                    "upgrade"
                },
                "--build-from-source",
                "epix/fixture/epix-mirror-fixture",
            ]))?;
            ensure!(
                String::from_utf8(output(cmd(prefix.join("bin/epix-mirror-fixture"), &[]))?)?
                    .trim()
                    == version,
                "Incorrect Homebrew fixture version"
            );
            if version == "2.0" {
                text(
                    &formula,
                    &content.replace(
                        &format!("sha256 \"{digest}\""),
                        &format!("sha256 \"{}\"", "0".repeat(64)),
                    ),
                )?;
                let result =
                    invoke(&["fetch", "--force", "epix/fixture/epix-mirror-fixture"]).output()?;
                let report = format!(
                    "{}{}",
                    String::from_utf8_lossy(&result.stdout),
                    String::from_utf8_lossy(&result.stderr)
                );
                println!("{report}");
                ensure!(
                    !result.status.success() && report.to_lowercase().contains("checksum"),
                    "Homebrew accepted wrong formula checksum"
                );
            }
        }
        println!("Homebrew install1.0 upgrade2.0 and incorrect checksum rejection PASS");
        Ok(())
    }

    fn node_exports(fixtures: &Path, binary: &Path, output_root: &Path) -> Result<()> {
        only_loopback()?;
        run_command(cmd("ip", &["link", "set", "lo", "up"]))?;
        ensure!(!output_root.exists(), "Node fixture output must be new");
        fs::create_dir_all(output_root)?;
        let root = output_root.join("node");
        text(
            &root.join("private/config.json"),
            &serde_json::to_string(
                &json!({"open_browser":false,"fileserver_port":0,"trackers":[],"trackers_file":[],"tor":"disable","local_discovery":false,"mesh":false}),
            )?,
        )?;
        let port = TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port();
        let origin = format!("http://127.0.0.1:{port}");
        let invoke = |args: &[&str]| {
            let mut command = cmd(binary, args);
            command
                .env("EPIX_DATA_DIR", &root)
                .env("EPIX_HEADLESS", "1")
                .env("EPIX_TOR", "disable")
                .env("EPIX_UI_ADDR", format!("127.0.0.1:{port}"));
            command
        };
        let mut addresses = BTreeMap::new();
        let mut snapshots: Vec<_> = fs::read_dir(fixtures)?
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("snapshot-"))
            .collect();
        snapshots.sort_by_key(|entry| entry.file_name());
        for source in snapshots {
            let label = source
                .file_name()
                .to_string_lossy()
                .trim_start_matches("snapshot-")
                .to_string();
            // siteCreate prints the disposable owner key. Capture it in memory only.
            let result: Output = invoke(&["siteCreate"]).output()?;
            ensure!(result.status.success(), "Disposable siteCreate failed");
            let stdout = String::from_utf8(result.stdout)?;
            let address = stdout
                .lines()
                .find_map(|line| line.strip_prefix("Xite address:").map(str::trim))
                .context("No created address")?
                .to_string();
            ensure!(
                epix_crypt::is_valid_address(&address),
                "Invalid created fixture address"
            );
            let destination = root.join("data").join(&address);
            fs::copy(
                source.path().join("epix-mirror.json"),
                destination.join("epix-mirror.json"),
            )?;
            copy_tree(&source.path().join("repo"), &destination.join("repo"))?;
            let log = File::create(output_root.join(format!("sign-{label}.log")))?;
            let mut sign = invoke(&["siteSign", &address, "--full"]);
            sign.stdout(log.try_clone()?).stderr(log);
            run_command(sign)?;
            addresses.insert(label, address);
        }
        let first = addresses.values().next().context("No snapshots")?;
        let log = File::create(output_root.join("node.log"))?;
        let mut launch = invoke(&[first]);
        launch.stdout(log.try_clone()?).stderr(log);
        let mut node = Node(launch.spawn()?);
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(1))
            .build()?;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if client
                .get(format!("{origin}/StatsJson"))
                .send()
                .is_ok_and(|r| r.status().is_success())
            {
                break;
            }
            ensure!(
                node.0.try_wait()?.is_none() && Instant::now() < deadline,
                "Disposable node did not become ready"
            );
            thread::sleep(Duration::from_millis(100));
        }
        let mut results = BTreeMap::new();
        for (label, address) in addresses {
            let catalog = export(ExportOptions {
                node: &origin,
                address: &address,
                output: &fixtures.join(format!("exported-{label}")),
                cookie_file: None,
                expected_snapshot: None,
            })?;
            results.insert(
                label,
                json!({"address":address,"snapshot":catalog.snapshot,"files":catalog.files.len()}),
            );
        }
        fs::write(
            output_root.join("exports.json"),
            serde_json::to_vec_pretty(&results)?,
        )?;
        Ok(())
    }
}
