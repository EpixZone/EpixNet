#!/usr/bin/env python3
"""Compile production foreground/boot methods with queued Swift platform doubles.

Requires swiftc. This executes lifecycle ordering without UIKit, a native node,
network access, or an iOS simulator. Queued work is drained explicitly so both
orders of first activation and node readiness are deterministic.
"""
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
source = (root / "EpixBrowser/AppDelegate.swift").read_text()


def method(name):
    starts = [source.find("    " + prefix + name + "(") for prefix in ("func ", "private func ")]
    matches = [index for index in starts if index >= 0]
    assert matches, name
    start = min(matches)
    end = source.index("\n    }", start) + len("\n    }")
    return source[start:end].replace("private func", "func", 1)


swift = r'''
import Foundation

final class DispatchQueue {
    enum QoS { case utility, userInitiated }
    static let main = DispatchQueue("main")
    static let utility = DispatchQueue("utility")
    static let userInitiated = DispatchQueue("userInitiated")
    static var current = "main"
    let lane: String
    var jobs: [() -> Void] = []
    init(_ lane: String) { self.lane = lane }
    static func global(qos: QoS) -> DispatchQueue {
        qos == .utility ? utility : userInitiated
    }
    func async(_ body: @escaping () -> Void) { jobs.append(body) }
    func drain() {
        while !jobs.isEmpty {
            Self.current = lane
            jobs.removeFirst()()
            Self.current = "main"
        }
    }
}
final class UIApplication {
    enum State { case active, inactive, background }
    static let shared = UIApplication()
    var applicationState = State.inactive
}
final class View {
    var removed = false
    func viewWithTag(_ tag: Int) -> View? { self }
    func removeFromSuperview() { removed = true }
}
final class Controller { let view = View() }
final class Label { var text: String? }
// The extracted boot method may prepare storage. These doubles never write.
final class FileManager {
    enum Directory { case applicationSupportDirectory }
    enum Domain { case userDomainMask }
    static let `default` = FileManager()
    func urls(for directory: Directory, in domain: Domain) -> [URL] {
        [URL(fileURLWithPath: "/unused-foreground-fixture")]
    }
    func createDirectory(atPath: String, withIntermediateDirectories: Bool) throws {}
}
final class Bundle {
    static let main = Bundle()
    func object(forInfoDictionaryKey key: String) -> Any? { nil }
}
struct NodeConfig {
    let dataDir: String, target: String, uiAddr: String, torMode: String, version: String
}
enum NodeState { case idle, starting, serving, failed }
struct BootFailure: Error {}
final class Node {
    var lifecycle = NodeState.idle
    var wakes = 0, boots = 0, reads = 0
    var failStart = false
    func state() -> NodeState { reads += 1; return lifecycle }
    func networkChanged() {
        precondition(DispatchQueue.current == "utility", "wake must leave the UI thread")
        precondition(lifecycle == .serving)
        wakes += 1
    }
    func start(config: NodeConfig) throws {
        precondition(DispatchQueue.current == "userInitiated")
        boots += 1
        if failStart { lifecycle = .failed; throw BootFailure() }
        lifecycle = .serving
    }
    func lastError() -> String? { "failed" }
    func uiUrl() -> String? { "http://127.0.0.1:42222/dashboard.epix/" }
    func browserProxy() -> String? { "proxy" }
}
final class Shell {
    let node = Node()
    var walletVC: Controller? = Controller()
    var bootTarget = "dashboard.epix"
    var startupCompleted = 0
    var nodeBase = "http://127.0.0.1:42222"
    var browserProxy: String?
    var nodePageRequested = false
    var splashStatus: Label? = Label()
    var splashDetail: Label? = Label()
    var loaded = 0
    func stopStartupPolling() {}
    func startStartupPolling() {}
    func setStartupProgress(title: String, detail: String, completed: Int, total: Int) {}
    func writeBrowserSettings() {}
    func stageWalletUi(dataDir: String) {}
    func applyClearnetRouting() {}
    func load(display: String) { loaded += 1 }
    func showError(_ message: String) {}
'''
swift += "\n".join(method(name) for name in (
    "applicationDidBecomeActive", "wakeNodeForForeground", "bootNode"))
swift += r'''
}
var checks = 0
func check(_ condition: Bool, _ message: String) {
    checks += 1
    precondition(condition, message)
}
func completeBoot() {
    DispatchQueue.userInitiated.drain()
    DispatchQueue.main.drain()
    DispatchQueue.utility.drain()
}
let application = UIApplication.shared
application.applicationState = .active
let warm = Shell()
warm.node.lifecycle = .serving
warm.applicationDidBecomeActive(application)
check(warm.node.reads == 0 && warm.node.wakes == 0, "activation must enqueue FFI work")
DispatchQueue.utility.drain()
check(warm.node.wakes == 1 && warm.node.boots == 0, "same-network foreground wakes without boot")
check(warm.walletVC!.view.removed, "activation still removes the wallet privacy cover")
warm.applicationDidBecomeActive(application)
DispatchQueue.utility.drain()
check(warm.node.wakes == 2, "a later active callback also wakes")
for state in [NodeState.idle, .starting, .failed] {
    let shell = Shell()
    shell.node.lifecycle = state
    shell.applicationDidBecomeActive(application)
    DispatchQueue.utility.drain()
    check(shell.node.wakes == 0 && shell.node.boots == 0, "inactive node state must not wake or boot")
}
let cold = Shell()
cold.bootNode(target: "dashboard.epix")
cold.applicationDidBecomeActive(application)
DispatchQueue.utility.drain()
check(cold.node.wakes == 0, "activation before startup cannot wake yet")
completeBoot()
check(cold.node.wakes == 1 && cold.loaded == 1, "successful foreground boot retains the early wake")
for state in [UIApplication.State.inactive, .background] {
    application.applicationState = state
    let shell = Shell()
    shell.bootNode(target: "dashboard.epix")
    completeBoot()
    check(shell.node.wakes == 0, "boot while not active waits for activation")
    application.applicationState = .active
    shell.applicationDidBecomeActive(application)
    DispatchQueue.utility.drain()
    check(shell.node.wakes == 1, "activation after node readiness wakes")
}
let failed = Shell()
failed.node.failStart = true
failed.bootNode(target: "dashboard.epix")
completeBoot()
check(failed.node.wakes == 0, "failed startup cannot wake")
failed.node.failStart = false
failed.bootNode(target: "dashboard.epix")
completeBoot()
check(failed.node.wakes == 1 && failed.node.boots == 2, "successful explicit retry retains foreground wake")
print("\(checks) iOS foreground checks passed")
'''
with tempfile.TemporaryDirectory(prefix="epix-ios-foreground-") as directory:
    path = pathlib.Path(directory)
    (path / "main.swift").write_text(swift)
    subprocess.run(["swiftc", "-module-cache-path", str(path / "cache"),
                    str(path / "main.swift"), "-o", str(path / "regressions")], check=True)
    raise SystemExit(subprocess.run([str(path / "regressions")]).returncode)
