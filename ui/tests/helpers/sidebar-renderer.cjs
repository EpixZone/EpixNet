// Compile the production rendering functions without building the node runtime.
// The browser fixture supplies data, never a second copy of the sidebar markup.
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

module.exports = function buildSidebarRenderer(repo, output) {
  const sidebar = fs.readFileSync(path.join(repo, "crates/epix-plugins/src/sidebar.rs"), "utf8");
  const start = sidebar.indexOf("fn esc(");
  const end = sidebar.indexOf("\n#[cfg(test)]", start);
  if (start < 0 || end < 0) throw new Error("Cannot locate the production sidebar rendering functions");
  const state = fs.readFileSync(path.join(repo, "crates/epix-ui/src/state.rs"), "utf8");
  const sizeLimit = state.match(/pub const DEFAULT_SIZE_LIMIT_MB: i64 = (\d+);/);
  if (!sizeLimit) throw new Error("Cannot locate the production default size limit");
  const directory = path.join(output, "renderer");
  fs.mkdirSync(path.join(directory, "src"), {recursive: true});
  fs.writeFileSync(path.join(directory, "Cargo.toml"), `[package]
name = "sidebar-properties-fixture"
version = "0.0.0"
edition = "2021"

[workspace]

[dependencies]
serde_json = "1"
`);
  fs.writeFileSync(path.join(directory, "src/main.rs"), `use serde_json::{json, Value};
use std::io::{self, Read};
#[derive(Clone, Copy, Default)]
struct PeerCounts { total: u64, connected: u64, connectable: u64, onion: u64, local: u64 }
mod epix_ui { pub const DEFAULT_SIZE_LIMIT_MB: i64 = ${sizeLimit[1]}; }
${sidebar.slice(start, end)}

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let fixture: Value = serde_json::from_str(&input).unwrap();
    let count = |key: &str| fixture["counts"][key].as_u64().unwrap_or(0);
    let counts = PeerCounts { total: count("total"), connected: count("connected"),
        connectable: count("connectable"), onion: count("onion"), local: count("local") };
    let includes: Vec<String> = fixture["includes"].as_array().unwrap().iter()
        .map(|value| value.as_str().unwrap().to_string()).collect();
    print!("{}", render_sidebar(fixture["address"].as_str().unwrap(), &fixture["info"], counts,
        fixture["received"].as_u64().unwrap_or(0), fixture["sent"].as_u64().unwrap_or(0),
        &includes, fixture["peer_map_open"].as_bool().unwrap_or(true)));
}
${sidebar.slice(end)}
`);
  execFileSync("cargo", ["build", "--quiet", "--offline", "--manifest-path", path.join(directory, "Cargo.toml"),
    "--target-dir", path.join(directory, "target")], {
    cwd: directory, stdio: ["ignore", "pipe", "pipe"], timeout: 120000,
  });
  const executable = path.join(directory, "target/debug/sidebar-properties-fixture" + (process.platform === "win32" ? ".exe" : ""));
  return fixture => execFileSync(executable, {input: JSON.stringify(fixture), encoding: "utf8", timeout: 5000});
};
