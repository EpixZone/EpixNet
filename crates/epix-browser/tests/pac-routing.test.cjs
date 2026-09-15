// Exercise the actual generated PAC without building the browser's Rust core.
// Run: node --test crates/epix-browser/tests/pac-routing.test.cjs
// Requires rustc on PATH (or RUSTC=/path/to/rustc).
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const vm = require("node:vm");
const { test } = require("node:test");

test("the generated PAC always routes onion services through Tor", () => {
  const source = fs.readFileSync(path.join(__dirname, "../src/main.rs"), "utf8");
  const extract = (name) => {
    const start = source.indexOf(`fn ${name}(`);
    assert.ok(start >= 0, `missing production ${name}`);
    return source.slice(start, source.indexOf("\n}", start) + 2);
  };
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "epix-pac-regressions-"));
  try {
    // These standalone production functions use only std. Keep the source
    // rather than reimplementing the PAC generator in the test language.
    const rust = `use std::{path::Path, net::SocketAddr, io::Write};
${source.match(/^const EEPSITE_PROXY_ADDR:.*$/m)[0]}
${extract("write_profile")}
${extract("file_url")}
fn main() {
    let root = std::env::args().nth(1).unwrap();
    for enabled in [false, true] {
        write_profile(&Path::new(&root).join(enabled.to_string()),
            "127.0.0.1:43112".parse().unwrap(), "127.0.0.1:43111".parse().unwrap(),
            "dashboard.epix", true, enabled, true).unwrap();
    }
}`;
    fs.writeFileSync(path.join(root, "generate.rs"), rust);
    const binary = path.join(root, process.platform === "win32" ? "generate.exe" : "generate");
    execFileSync(process.env.RUSTC || "rustc", ["--edition=2024", path.join(root, "generate.rs"), "-o", binary]);
    execFileSync(binary, [root]);

    for (const enabled of [false, true]) {
      const context = vm.createContext({
        shExpMatch: (host, pattern) => new RegExp(
          "^" + pattern.split("*").map(p => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$"
        ).test(host),
        dnsDomainLevels: host => host.split(".").length - 1,
      });
      vm.runInContext(fs.readFileSync(path.join(root, String(enabled), "epix.pac"), "utf8"), context);
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
