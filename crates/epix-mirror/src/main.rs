use anyhow::{bail, Context, Result};
use epix_mirror::{export, stage, validate, ExportOptions, Server, StageOptions};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{atomic::AtomicBool, Arc},
};

fn main() {
    if let Err(error) = run() {
        eprintln!("Mirror unavailable: {error:#}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args
        .next()
        .context("Usage: epix-mirror stage|export|verify|serve [--option value]")?;
    if matches!(command.as_str(), "--help" | "-h") {
        println!("epix-mirror stage --source DIR --output NEW --manager apt|dnf|homebrew|chocolatey --expires RFC3339 [--url-map JSON]\nepix-mirror export --node http://127.0.0.1:PORT --address epix1... --output NEW [--cookie-file FILE] [--expected-snapshot SHA256]\nepix-mirror verify --snapshot DIR\nepix-mirror serve --snapshot DIR [--port 42700]");
        return Ok(());
    }
    let mut options = BTreeMap::new();
    while let Some(key) = args.next() {
        if !key.starts_with("--") {
            bail!("Expected an option name");
        }
        let value = args.next().context("Missing option value")?;
        if options.insert(key, value).is_some() {
            bail!("Duplicate option");
        }
    }
    let allowed: &[&str] = match command.as_str() {
        "stage" => &[
            "--source",
            "--output",
            "--manager",
            "--expires",
            "--url-map",
        ],
        "export" => &[
            "--node",
            "--address",
            "--output",
            "--cookie-file",
            "--expected-snapshot",
        ],
        "verify" => &["--snapshot"],
        "serve" => &["--snapshot", "--port"],
        _ => bail!("Unknown mirror command"),
    };
    for key in options.keys() {
        if !allowed.contains(&key.as_str()) {
            bail!("Unknown option: {key}");
        }
    }
    let required = |key: &str| {
        options
            .get(key)
            .map(String::as_str)
            .with_context(|| format!("Missing {key}"))
    };
    let catalog = match command.as_str() {
        "stage" => stage(StageOptions {
            source: Path::new(required("--source")?),
            output: Path::new(required("--output")?),
            manager: required("--manager")?,
            expires: required("--expires")?,
            url_map: options.get("--url-map").map(Path::new),
        })?,
        "export" => export(ExportOptions {
            node: options
                .get("--node")
                .map(String::as_str)
                .unwrap_or("http://127.0.0.1:42222"),
            address: required("--address")?,
            output: Path::new(required("--output")?),
            cookie_file: options.get("--cookie-file").map(Path::new),
            expected_snapshot: options.get("--expected-snapshot").map(String::as_str),
        })?,
        "verify" => validate(Path::new(required("--snapshot")?))?,
        "serve" => {
            let port = options
                .get("--port")
                .map(|v| v.parse())
                .transpose()?
                .unwrap_or(42700);
            let server = Server::bind(Path::new(required("--snapshot")?), port)?;
            println!(
                "Serving verified snapshot at http://127.0.0.1:{}",
                server.port()
            );
            return server.run(Arc::new(AtomicBool::new(false)));
        }
        _ => unreachable!("validated command"),
    };
    println!("{}", catalog.summary());
    Ok(())
}
