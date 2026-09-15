#!/usr/bin/env python3
"""Run the actual Swift bridge/navigation methods with small WebKit test doubles.

Requires macOS Command Line Tools (swiftc), but no iOS SDK or simulator. This
checks host-side decisions, not WebKit rendering or iOS platform integration.
"""
import pathlib
import subprocess
import tempfile


SOURCE = pathlib.Path(__file__).resolve().parents[1] / "EpixBrowser/AppDelegate.swift"
source = SOURCE.read_text()


def method(name, optional=False):
    marker = "    func " + name + "("
    private_marker = "    private func " + name + "("
    start = source.find(marker)
    if start < 0:
        start = source.find(private_marker)
    if start < 0 and optional:
        return ""
    assert start >= 0, name
    # Each method's closing brace is indented once; nested Swift/string
    # contents use deeper indentation.
    end = source.index("\n    }", start) + len("\n    }")
    return source[start:end].replace("private func", "func", 1)


stub = r'''
import Foundation

final class WKWebView {
    var url: URL?
    var loaded: URL?
    var scripts: [String] = []
    init(_ url: String) { self.url = URL(string: url) }
    func load(_ request: URLRequest) { loaded = request.url }
    func evaluateJavaScript(_ script: String) { scripts.append(script) }
}
final class WKUserContentController {}
struct WKSecurityOrigin {
    var `protocol`: String
    var host: String
    var port: Int
}
struct WKFrameInfo {
    var isMainFrame: Bool
    var request: URLRequest
    var securityOrigin: WKSecurityOrigin
}
struct WKScriptMessage {
    var name: String
    var body: Any
    var webView: WKWebView?
    var frameInfo: WKFrameInfo
}
final class Shell {
    var nodeBase = "http://127.0.0.1:42222"
    var currentDisplay = "dashboard.epix"
    var webView: WKWebView? = WKWebView("about:blank")
    var walletWebView: WKWebView? = WKWebView("http://127.0.0.1:42222/EpixWallet/mobile.html")
    var walletStore: [String: String] = [:]
    var nativeCalls = 0
    var nativeReplies: [([String: Any]) -> Void] = []
    var closeCalls = 0
    func persistWalletStore() {}
    func handleNmh(_ message: [String: Any], reply: @escaping ([String: Any]) -> Void) {
        nativeCalls += 1
        nativeReplies.append(reply)
    }
    func dismissWallet() { closeCalls += 1 }
'''

checks = r'''
}

var failures = 0
func check(_ condition: Bool, _ message: String) {
    if !condition { failures += 1; print("FAIL: \(message)") }
}

let shell = Shell()
let wallet = shell.walletWebView!
let controller = WKUserContentController()
let trusted = "http://127.0.0.1:42222/EpixWallet/mobile.html"
let trustedOrigin = WKSecurityOrigin(protocol: "http", host: "127.0.0.1", port: 42222)

func send(_ name: String, url: String, mainFrame: Bool = true,
          web: WKWebView? = wallet, origin: WKSecurityOrigin = trustedOrigin) {
    shell.userContentController(controller, didReceive: WKScriptMessage(
        name: name, body: "{\"id\":1,\"op\":{\"cmd\":\"set\",\"key\":\"owned\",\"value\":\"yes\"},\"message\":{\"cmd\":\"setTorClearnet\",\"on\":false}}",
        webView: web, frameInfo: WKFrameInfo(isMainFrame: mainFrame,
            request: URLRequest(url: URL(string: url)!), securityOrigin: origin)))
}

for name in ["epixStore", "epixNmh", "epixClose"] {
    // A navigation changes the view's current URL as well as the message's
    // frame URL; test that case independently of stale-document rejection.
    for url in [
        "https://attacker.example/EpixWallet/mobile.html",
        "http://127.0.0.1:9999/EpixWallet/mobile.html",
        "http://127.0.0.1:42222/untrusted.epix/index.html",
        "http://127.0.0.1:42222/EpixWallet/../untrusted.epix/index.html",
        "http://127.0.0.1:42222/EpixWallet/%2e%2e/untrusted.epix/index.html",
        "http://127.0.0.1:42222/EpixWallet/%2E%2E%2Funtrusted.epix/index.html",
        "http://127.0.0.1:42222/EpixWallet/..%5Cuntrusted.epix/index.html",
    ] {
        wallet.url = URL(string: url)
        send(name, url: url)
    }
    wallet.url = URL(string: trusted)
    send(name, url: "https://attacker.example/", origin:
        WKSecurityOrigin(protocol: "https", host: "attacker.example", port: 443))
    send(name, url: "http://127.0.0.1:42222/untrusted.epix/index.html")
    send(name, url: "http://127.0.0.1:9999/EpixWallet/mobile.html")
    send(name, url: trusted, mainFrame: false)
    send(name, url: trusted, web: WKWebView(trusted))
    send(name, url: trusted, origin:
        WKSecurityOrigin(protocol: "https", host: "attacker.example", port: 443))
}
check(shell.walletStore.isEmpty, "untrusted documents must not access the wallet key/value store")
check(shell.nativeCalls == 0, "untrusted documents must not change native routing settings (\(shell.nativeCalls) accepted)")
check(shell.closeCalls == 0, "untrusted documents must not close the wallet (\(shell.closeCalls) accepted)")

shell.walletStore = [:]; shell.nativeCalls = 0; shell.closeCalls = 0
for name in ["epixStore", "epixNmh", "epixClose"] { send(name, url: trusted) }
check(shell.walletStore["owned"] == "yes" && shell.nativeCalls == 1 && shell.closeCalls == 1,
      "the wallet's own main frame retains all three bridge operations")

// A valid get is asynchronous. Navigating the sheet before its queued reply
// runs must not deliver the vault contents into the next document.
RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.01))
wallet.scripts = []
shell.walletStore["vault"] = "test-secret"
shell.userContentController(controller, didReceive: WKScriptMessage(
    name: "epixStore", body: "{\"id\":2,\"op\":{\"cmd\":\"get\",\"key\":\"vault\"}}",
    webView: wallet, frameInfo: WKFrameInfo(isMainFrame: true,
        request: URLRequest(url: URL(string: trusted)!), securityOrigin: trustedOrigin)))
wallet.url = URL(string: "https://attacker.example/")
RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.01))
check(wallet.scripts.isEmpty, "queued storage replies must not expose vault values after navigation")
wallet.url = URL(string: trusted)

// A replaced sheet uses the same URL, but must never receive another
// sheet's pending native-host reply.
let replacement = WKWebView(trusted)
shell.walletWebView = replacement
shell.nativeReplies.forEach { $0(["secret": "test-secret"]) }
RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.01))
check(replacement.scripts.isEmpty && wallet.scripts.isEmpty,
      "queued native replies must not cross into a replacement wallet sheet")
shell.walletWebView = wallet

// The wallet uses HashRouter: changing the fragment keeps the same document
// and must leave its bridge usable.
wallet.url = URL(string: trusted + "#/send")
shell.walletStore = [:]
send("epixStore", url: trusted)
check(shell.walletStore["owned"] == "yes", "wallet hash navigation retains native storage access")
RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.01))
check(wallet.scripts.count == 1, "the current trusted wallet receives its storage reply")
wallet.url = URL(string: trusted)

for address in ["epix://talk.epix/posts/42?sort=new#reply", "epix://talk.epix/a%20b?q=a%2Fb#c%20d"] {
    shell.navigate(address)
    let expected = address.replacingOccurrences(of: "epix://", with: shell.nodeBase + "/")
    check(shell.webView?.loaded?.absoluteString == expected,
          "typed deep link preserves path/query/fragment: \(address) -> \(shell.webView?.loaded?.absoluteString ?? "nil")")
    let target = shell.targetFrom(URL(string: address)!)!
    check(shell.nodeUrl(target) == expected, "external deep link preserves path/query/fragment: \(address)")
}
check(shell.xiteRewrite(URL(string: "https://example.com/path")!) == nil,
      "ordinary web URLs stay on the web")
check(shell.targetFrom(URL(string: "https://example.com")!) == nil,
      "external non-Epix URLs are rejected")
print("\(failures) regression failure(s)")
exit(failures == 0 ? 0 : 1)
'''

methods = ["userContentController", "handleStore", "replyStore", "navigate", "searchUrl", "nodeUrl", "targetFrom", "xiteRewrite"]
swift = stub + "\n".join(method(name) for name in methods)
swift += "\n" + method("isWalletFrame", optional=True)
swift += "\n" + method("acceptsWalletMessage", optional=True)
swift += "\n" + method("walletDocumentURL", optional=True) + checks
with tempfile.TemporaryDirectory(prefix="epix-ios-regressions-") as directory:
    root = pathlib.Path(directory)
    (root / "main.swift").write_text(swift)
    subprocess.run(["swiftc", "-module-cache-path", str(root / "cache"),
                    str(root / "main.swift"), "-o", str(root / "regressions")], check=True)
    result = subprocess.run([str(root / "regressions")])
    raise SystemExit(result.returncode)
