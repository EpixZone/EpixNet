// Exercise the actual generated PAC without building the browser's Rust core.
// Run: node --test crates/epix-browser/tests/pac-routing.test.cjs
// Requires Cargo and the workspace's locked url dependencies in its cache.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const vm = require("node:vm");
const { test } = require("node:test");
const { pathToFileURL, fileURLToPath } = require("node:url");

test("generated PAC URLs preserve native paths and route onion services through Tor", () => {
  const source = fs.readFileSync(path.join(__dirname, "../src/main.rs"), "utf8");
  const extract = (name) => {
    const start = source.indexOf(`fn ${name}(`);
    assert.ok(start >= 0, `missing production ${name}`);
    return source.slice(start, source.indexOf("\n}", start) + 2);
  };
  // Native resolution matches Rust's canonicalize, including Windows 8.3
  // aliases and macOS's /var symlink.
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "epix-pac-regressions-")));
  try {
    // Compile the production functions with the workspace's exact URL library,
    // without building the browser or reimplementing native path conversion.
    const lockfile = fs.readFileSync(path.join(__dirname, "../../../Cargo.lock"), "utf8");
    const urlVersion = lockfile.match(/\[\[package\]\]\r?\nname = "url"\r?\nversion = "([^"]+)"/)[1];
    fs.writeFileSync(path.join(root, "Cargo.toml"), `[package]
name = "epix-pac-regressions"
version = "0.0.0"
edition = "2021"
[dependencies]
url = "=${urlVersion}"
`);
    fs.writeFileSync(path.join(root, "Cargo.lock"), lockfile);
    fs.mkdirSync(path.join(root, "src"));
    fs.copyFileSync(path.join(__dirname, "../src/file_url_tests.rs"), path.join(root, "src/file_url_tests.rs"));
    const rust = `use std::{path::Path, net::SocketAddr, io::Write};
${source.match(/^const EEPSITE_PROXY_ADDR:.*$/m)[0]}
${extract("write_profile")}
${extract("file_url")}
#[cfg(test)]
mod file_url_tests;
fn main() {
    let root = std::fs::canonicalize(std::env::args().nth(1).unwrap()).unwrap();
    for enabled in [false, true] {
        write_profile(&root.join(enabled.to_string()),
            "127.0.0.1:43112".parse().unwrap(), "127.0.0.1:43111".parse().unwrap(),
            "dashboard.epix", true, enabled, true).unwrap();
    }
}`;
    fs.writeFileSync(path.join(root, "src/main.rs"), rust);
    const manifest = path.join(root, "Cargo.toml");
    const env = { ...process.env, CARGO_TARGET_DIR: path.join(root, "target"),
      CARGO_BUILD_JOBS: "2", CARGO_INCREMENTAL: "0", CARGO_PROFILE_DEV_DEBUG: "0", CARGO_PROFILE_TEST_DEBUG: "0" };
    const cargo = process.env.CARGO || "cargo";
    const options = { env, timeout: 180000, stdio: "pipe" };
    if (process.env.EPIX_TEST_FETCH_DEPS === "1") {
      execFileSync(cargo, ["fetch", "--manifest-path", manifest], options);
    }
    process.stdout.write(execFileSync(cargo, ["test", "--offline", "--manifest-path", manifest], options));
    const profileRoot = path.join(root, "First Last #100%20 Zoë 雪");
    fs.mkdirSync(profileRoot);
    execFileSync(cargo, ["run", "--quiet", "--offline", "--manifest-path", manifest, "--", profileRoot], options);

    for (const enabled of [false, true]) {
      const profile = path.join(profileRoot, String(enabled));
      const prefs = new Map();
      vm.runInNewContext(fs.readFileSync(path.join(profile, "user.js"), "utf8"), {
        user_pref: (key, value) => prefs.set(key, value),
      });
      const pacUrl = prefs.get("network.proxy.autoconfig_url");
      const pacPath = fs.realpathSync.native(path.join(profile, "epix.pac"));
      assert.equal(pacUrl, pathToFileURL(pacPath).href);
      assert.equal(new URL(pacUrl).search, "");
      assert.equal(new URL(pacUrl).hash, "");
      assert.equal(fileURLToPath(pacUrl), pacPath);
      const context = vm.createContext({
        shExpMatch: (host, pattern) => new RegExp(
          "^" + pattern.split("*").map(p => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$"
        ).test(host),
        dnsDomainLevels: host => host.split(".").length - 1,
      });
      vm.runInContext(fs.readFileSync(fileURLToPath(pacUrl), "utf8"), context);
      const route = host => context.FindProxyForURL(`http://${host}/`, host);
      assert.equal(route("a".repeat(56) + ".onion"), "SOCKS5 127.0.0.1:43111",
        `onion service must use Tor with clearnet routing ${enabled ? "on" : "off"}`);
      assert.equal(route("example.com"), enabled ? "SOCKS5 127.0.0.1:43111" : "DIRECT");
      assert.equal(route("pretend.onion.example.com"), enabled ? "SOCKS5 127.0.0.1:43111" : "DIRECT");
      assert.equal(route("dashboard.epix"), "PROXY 127.0.0.1:43112");
      assert.equal(route("example.i2p"), "PROXY 127.0.0.1:43113");
      assert.equal(route("rpc.epix.zone"), "DIRECT");
      assert.equal(route("127.0.0.1"), "DIRECT");
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
