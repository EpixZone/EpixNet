'use strict';

// macOS host check: production Swift endpoint validation/proxy policy and a
// real loopback refusing socket. Does not need an iOS simulator or native node.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'EpixBrowser/AppDelegate.swift'), 'utf8');
function method(name, isStatic = false) {
  const marker = `    private ${isStatic ? 'static ' : ''}func ${name}(`;
  const start = source.indexOf(marker);
  if (start < 0) throw new Error(`Missing production ${name}`);
  const end = source.indexOf('\n    }', start);
  if (end < 0) throw new Error(`Unclosed production ${name}`);
  return source.slice(start, end + 6).replace('private ', '');
}
const swift = `
import Darwin
import Foundation
import Network

final class ProxyConfiguration {
    let endpoint: NWEndpoint
    let kind: String
    var matchDomains: [String] = []
    var excludedDomains: [String] = []
    var allowFailover = true
    init(httpCONNECTProxy: NWEndpoint) { endpoint = httpCONNECTProxy; kind = "http" }
    init(socksv5Proxy: NWEndpoint) { endpoint = socksv5Proxy; kind = "socks" }
}
final class Store { var proxyConfigurations: [ProxyConfiguration] = [] }
final class Config { var websiteDataStore = Store() }
final class Web { var configuration = Config() }
struct Tab { var webView = Web() }
struct BrowserProxy { let port: UInt16 }
final class Shell {
    var torClearnet = true
    var browserProxy: BrowserProxy? = BrowserProxy(port: 42527)
    var nativeSocksPort: UInt16? = 42327
    var prebootSocksPort: UInt16?
    var tabs = [Tab(), Tab()]
    var walletWebView: Web? = Web()
    ${method('trustedNodeBase', true)}
    ${method('applyClearnetRouting')}
}
func verify(_ condition: @autoclosure () -> Bool, _ message: String) {
    precondition(condition(), message)
}
func port(_ proxy: ProxyConfiguration) -> UInt16 {
    guard case let .hostPort(host, port) = proxy.endpoint else { fatalError("Not a TCP proxy") }
    verify(String(describing: host) == "127.0.0.1", "proxy must stay on numeric loopback")
    return port.rawValue
}
for n in [1, 42222, 42223, 65535] {
    verify(Shell.trustedNodeBase("http://127.0.0.1:\\(n)/x?q=y#z") == "http://127.0.0.1:\\(n)", "owned endpoint rejected")
}
for url in [nil, "http://127.0.0.1/", "http://127.0.0.1:0/", "http://127.0.0.1:65536/",
    "https://127.0.0.1:42222/", "http://localhost:42222/", "http://[::1]:42222/",
    "http://user@127.0.0.1:42222/", "http://127.0.0.1.evil:42222/", "//127.0.0.1:42222/"] {
    verify(Shell.trustedNodeBase(url) == nil, "untrusted endpoint accepted")
}
let fallback = try RefusingTorProxy()
let shell = Shell()
shell.prebootSocksPort = fallback.port
shell.applyClearnetRouting()
for web in shell.tabs.map({ $0.webView }) + [shell.walletWebView!] {
    let routes = web.configuration.websiteDataStore.proxyConfigurations
    verify(routes.count == 2, "missing proxy route")
    verify(port(routes[0]) == 42527 && routes[0].matchDomains == ["epix"], "xite proxy changed")
    verify(port(routes[1]) == 42327 && !routes[1].allowFailover, "native SOCKS endpoint not selected")
}
shell.nativeSocksPort = nil
shell.applyClearnetRouting()
verify(port(shell.tabs[0].webView.configuration.websiteDataStore.proxyConfigurations[1]) == fallback.port,
    "missing native endpoint must select the owned refusal proxy")
let connection = socket(AF_INET, SOCK_STREAM, 0)
verify(connection >= 0, "test socket failed")
var address = sockaddr_in()
address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
address.sin_family = sa_family_t(AF_INET)
address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
address.sin_port = fallback.port.bigEndian
let connected = withUnsafePointer(to: &address) { pointer in
    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        Darwin.connect(connection, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
    }
}
verify(connected == 0, "owned refusal socket did not listen")
var timeout = timeval(tv_sec: 2, tv_usec: 0)
setsockopt(connection, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
var byte: UInt8 = 0
verify(recv(connection, &byte, 1, 0) == 0, "refusal endpoint did not close")
Darwin.close(connection)
let competing = socket(AF_INET, SOCK_STREAM, 0)
let rebound = withUnsafePointer(to: &address) { pointer in
    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        Darwin.bind(competing, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
    }
}
verify(rebound == -1, "fallback port was released")
Darwin.close(competing)
shell.nativeSocksPort = 42328
shell.applyClearnetRouting()
verify(port(shell.tabs[0].webView.configuration.websiteDataStore.proxyConfigurations[1]) == 42328,
    "new native endpoint not propagated")
shell.torClearnet = false
shell.applyClearnetRouting()
verify(shell.tabs[0].webView.configuration.websiteDataStore.proxyConfigurations.count == 1,
    "explicit direct mode must retain only the xite proxy")
print("PASS: iOS owned ports, preboot refusal, endpoint validation and routing")
`;
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'epix-ios-ports-'));
function run(command, args) {
  const result = spawnSync(command, args, { stdio: 'inherit', timeout: 90000 });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} failed: ${result.status ?? result.signal}`);
}
try {
  const main = path.join(temporary, 'main.swift');
  const binary = path.join(temporary, 'ports');
  fs.writeFileSync(main, swift);
  run('swiftc', [main, path.join(root, 'EpixBrowser/RefusingTorProxy.swift'), '-o', binary]);
  run(binary, []);
} finally {
  fs.rmSync(temporary, { recursive: true });
}
