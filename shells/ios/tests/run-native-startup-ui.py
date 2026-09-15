#!/usr/bin/env python3
"""Run production startup widgets in UIKit, without Rust or release signing.

Requires Xcode and an installed iOS simulator runtime. Creates and deletes its
own iPhone simulator; never boots or changes an existing device. JSON checks,
compiler output, extracted Swift and simctl screenshots remain in --output.
This validates the native splash, not a complete node or WKWebView boot.

  python3 shells/ios/tests/run-native-startup-ui.py --output /tmp/epix-ios-ui
  python3 shells/ios/tests/run-native-startup-ui.py --prepare-only --output /tmp/epix-ios-ui
"""
import argparse
import hashlib
import json
import pathlib
import platform
import plistlib
import re
import shutil
import subprocess
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUNDLE_ID = "zone.epix.startupfixture"
METHODS = (
    "presentSplash", "setStartupProgress", "startStartupPolling",
    "stopStartupPolling", "pollStartupProgress", "hideSplash", "retryBoot", "pageSettled",
)

# Only the node boundary is doubled. UIView, labels, constraints, animation,
# progress, timers and window layout below all execute inside real UIKit.
SWIFT_PREFIX = r'''
import UIKit

enum StartupStage {
    case preparingData, loadingSettings, restoringXites, rebuildingDatabases, startingServices, prepared
}
enum NodeState { case idle, starting, serving, failed }
final class Node {
    var lifecycle = NodeState.starting
    var stage: StartupStage?
    func state() -> NodeState { lifecycle }
    func startupStage() -> StartupStage? { stage }
}
@MainActor final class Shell {
    let node = Node()
    var requestedTarget: String?
    func bootNode(target: String) { requestedTarget = target }
    func syncToolbar() {}
'''
SWIFT_CHECKS = r'''
}

@MainActor final class FixtureController: UIViewController {
    override var supportedInterfaceOrientations: UIInterfaceOrientationMask { .allButUpsideDown }
}

@MainActor final class FixtureScene: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    func scene(_ scene: UIScene, willConnectTo session: UISceneSession,
               options connectionOptions: UIScene.ConnectionOptions) {
        guard let scene = scene as? UIWindowScene,
              let app = UIApplication.shared.delegate as? FixtureApp else { return }
        window = app.connect(scene)
    }
}

@main final class FixtureApp: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    let shell = Shell()
    var checks: [[String: Any]] = []
    let scenario = ProcessInfo.processInfo.arguments.last ?? "portrait"

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        true
    }

    func application(_ application: UIApplication, configurationForConnecting session: UISceneSession,
                     options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        let configuration = UISceneConfiguration(name: "Fixture", sessionRole: session.role)
        configuration.delegateClass = FixtureScene.self
        return configuration
    }

    func connect(_ scene: UIWindowScene) -> UIWindow {
        let controller = FixtureController()
        let window = UIWindow(windowScene: scene)
        window.rootViewController = controller
        self.window = window
        window.makeKeyAndVisible()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            if self.scenario == "landscape" {
                window.windowScene?.requestGeometryUpdate(.iOS(interfaceOrientations: .landscapeRight)) {
                    self.check(false, "landscape request: \($0.localizedDescription)")
                }
            }
            self.awaitOrientation(remaining: 40)
        }
        return window
    }

    func check(_ passed: Bool, _ name: String) {
        checks.append(["name": name, "passed": passed])
        if !passed { print("FAIL: \(name)") }
    }

    func descendants(_ view: UIView) -> [UIView] {
        view.subviews.flatMap { [$0] + descendants($0) }
    }

    func awaitOrientation(remaining: Int) {
        guard let host = window?.rootViewController?.view else { return }
        let isLandscape = host.bounds.width > host.bounds.height
        if isLandscape != (scenario == "landscape") && remaining > 0 {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) {
                self.awaitOrientation(remaining: remaining - 1)
            }
            return
        }
        check(isLandscape == (scenario == "landscape"), "actual window orientation is \(scenario)")
        exerciseLifecycle(host)
    }

    func exerciseLifecycle(_ host: UIView) {
        shell.presentSplash(over: host)
        let initial = shell.splashView!
        shell.pageSettled()
        check(shell.splashView === initial, "blank page cannot dismiss startup")
        check(shell.splashProgress?.progress == 0, "startup begins at zero completed stages")
        shell.node.stage = .loadingSettings
        shell.pollStartupProgress()
        check(shell.splashProgress?.progress == Float(3) / 9, "actual stage drives native progress")
        shell.node.stage = .preparingData
        shell.pollStartupProgress()
        check(shell.splashStatus?.text == "Loading your settings", "stale earlier stage cannot regress status")
        shell.startStartupPolling()
        let timer = shell.startupTimer!
        check(timer.isValid && timer.timeInterval == 0.25, "active startup polls every 250ms")
        shell.nodePageRequested = true
        shell.setStartupProgress(title: "Opening Epix Browser", detail: "Waiting for the first page.",
                                 completed: 8, total: 9)
        timer.fire()
        check(shell.splashProgress?.progress == Float(8) / 9, "opening never reports completion early")
        shell.pageSettled()
        check(shell.splashView == nil && shell.splashProgress == nil, "page completion releases widgets")
        check(!timer.isValid && shell.startupTimer == nil, "page completion cancels polling")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) {
            self.check(initial.superview == nil, "completed overlay is removed after its fade")
            self.shell.retryBoot()
            self.check(self.shell.requestedTarget == "dashboard.epix", "retry retains launch target")
            self.check(self.shell.splashProgress?.progress == 0, "retry resets completed stages")
            self.shell.node.lifecycle = .failed
            self.shell.node.stage = .prepared
            self.shell.pollStartupProgress()
            self.check(self.shell.splashProgress?.progress == 0, "previous failed attempt cannot advance retry")
            self.shell.node.lifecycle = .starting
            self.shell.node.stage = .startingServices
            self.shell.pollStartupProgress()
            self.inspectLayout(host)
        }
    }

    func inspectLayout(_ host: UIView) {
        host.layoutIfNeeded()
        guard let overlay = shell.splashView, let status = shell.splashStatus,
              let detail = shell.splashDetail, let progress = shell.splashProgress,
              let mark = descendants(overlay).compactMap({ $0 as? UIImageView }).first else {
            check(false, "production splash contains all native controls")
            writeResult(host)
            return
        }
        check(overlay.bounds.size == host.bounds.size, "overlay covers the entire browser")
        check(overlay.backgroundColor == Shell.chromeBg, "startup uses the shared dark background")
        check(mark.image != nil, "existing white Epix mark is bundled and decoded")
        check(mark.bounds.width == 96 && mark.bounds.height == 96, "mark remains 96 points")
        check(status.text == "Starting network services", "native title describes actual node work")
        check(progress.progress == Float(6) / 9, "native progress shows six of nine completed stages")
        check(progress.accessibilityValue == "6 of 9 stages completed", "progress has a spoken stage count")
        for label in [status, detail] {
            let needed = label.sizeThatFits(CGSize(width: label.bounds.width,
                                                   height: CGFloat.greatestFiniteMagnitude))
            check(label.bounds.width > 0 && label.bounds.height + 1 >= needed.height,
                  "label fits its wrapped text: \(label.text ?? "")")
        }
        let spin = mark.layer.animation(forKey: "spin") as? CABasicAnimation
        check(spin?.duration == 1.2 && spin?.repeatCount == .infinity,
              "white mark rotates continuously every 1.2 seconds")
        check(abs((spin?.toValue as? Double ?? 0) - 2 * Double.pi) < 0.001,
              "animation performs a complete rotation")
        let markRect = mark.convert(mark.bounds, to: overlay)
        check(markRect.minX >= 0 && markRect.maxX <= overlay.bounds.width && markRect.minY >= 0,
              "mark is reachable at the top of the startup content")
        if let scroll = descendants(overlay).compactMap({ $0 as? UIScrollView }).first {
            check(scroll.contentSize.width <= scroll.bounds.width + 1, "startup has no horizontal overflow")
            scroll.setContentOffset(CGPoint(x: 0, y: max(0, scroll.contentSize.height - scroll.bounds.height)),
                                    animated: false)
            host.layoutIfNeeded()
        } else {
            check(false, "short screens retain scrollable startup content")
        }
        let progressRect = progress.convert(progress.bounds, to: overlay)
        check(progressRect.minY >= 0 && progressRect.maxY <= overlay.bounds.height + 1,
              "progress is reachable within the visible screen")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            let before = mark.layer.presentation()?.transform
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
                let after = mark.layer.presentation()?.transform
                self.check(before != nil && after != nil &&
                           !CATransform3DEqualToTransform(before!, after!),
                           "Core Animation visibly advances the mark")
                self.writeResult(host)
            }
        }
    }

    func writeResult(_ host: UIView) {
        let result: [String: Any] = [
            "scenario": scenario,
            "width": host.bounds.width, "height": host.bounds.height,
            "checks": checks, "passed": checks.allSatisfy { $0["passed"] as? Bool == true }
        ]
        let directory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        do {
            let data = try JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: directory.appendingPathComponent("\(scenario).json"), options: .atomic)
        } catch {
            print("Could not save native assertions: \(error)")
        }
    }
}
'''


def extract_method(source, name):
    match = re.search(r"^    (?:private )?func " + re.escape(name) + r"\(", source, re.MULTILINE)
    if not match:
        raise ValueError(f"Production startup method missing: {name}")
    end = source.index("\n    }", match.start()) + len("\n    }")
    return source[match.start():end].replace("private func", "func", 1)


def prepare(output):
    source_path = ROOT / "EpixBrowser/AppDelegate.swift"
    source = source_path.read_text()
    fields = []
    for name in ("splashView", "splashHost", "splashStatus", "splashDetail", "splashProgress",
                 "startupTimer", "startupCompleted", "nodePageRequested", "bootTarget", "chromeBg"):
        match = re.search(r"^    (?:static )?var " + name + r"\b[^\n]*|^    static let " + name + r"\b[^\n]*",
                          source, re.MULTILINE)
        if not match:
            raise ValueError(f"Production startup field missing: {name}")
        fields.append(match.group())
    generated = SWIFT_PREFIX + "\n".join(fields) + "\n"
    generated += "\n".join(extract_method(source, name) for name in METHODS) + SWIFT_CHECKS
    (output / "Fixture.swift").write_text(generated)
    app = output / "EpixStartupFixture.app"
    app.mkdir(exist_ok=True)
    shutil.copyfile(ROOT / "EpixBrowser/epix-mark-white.png", app / "epix-mark-white.png")
    info = {
        "CFBundleIdentifier": BUNDLE_ID, "CFBundleExecutable": "EpixStartupFixture",
        "CFBundleName": "Epix Startup Fixture", "CFBundlePackageType": "APPL",
        "CFBundleVersion": "1", "CFBundleShortVersionString": "1.0",
        "LSRequiresIPhoneOS": True, "MinimumOSVersion": "16.0", "UIDeviceFamily": [1],
        "UILaunchScreen": {},
        "UIApplicationSceneManifest": {"UIApplicationSupportsMultipleScenes": False},
        "UISupportedInterfaceOrientations": [
            "UIInterfaceOrientationPortrait", "UIInterfaceOrientationLandscapeLeft",
            "UIInterfaceOrientationLandscapeRight"],
    }
    (app / "Info.plist").write_bytes(plistlib.dumps(info))
    (output / "source.json").write_text(json.dumps({
        "source": str(source_path.relative_to(ROOT.parent.parent)),
        "sha256": hashlib.sha256(source.encode()).hexdigest(), "methods": METHODS,
        "scope": "Production UIKit startup methods; node lifecycle is a fixture double. No Rust or WebKit boot.",
    }, indent=2) + "\n")
    return app


def command(output, *args, timeout=120, check=True):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    with (output / "commands.log").open("a") as log:
        log.write(f"$ {' '.join(map(str, args))}\n{result.stdout}\n")
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(map(str, args))}\n{result.stdout}")
    return result.stdout.strip()


def select_device(output):
    inventory = json.loads(command(output, "xcrun", "simctl", "list", "--json"))
    runtimes = [r for r in inventory["runtimes"] if r.get("isAvailable") and ".iOS-" in r["identifier"]]
    runtimes.sort(key=lambda r: tuple(map(int, r["version"].split("."))), reverse=True)
    if not runtimes:
        raise RuntimeError("No available iOS simulator runtime. Install one in Xcode before running this fixture.")
    phones = [d for d in inventory["devicetypes"] if d["name"].startswith("iPhone")]
    # Prefer an SE-sized viewport; otherwise use an available ordinary iPhone.
    phones.sort(key=lambda d: ("SE (3rd" not in d["name"], "Pro" in d["name"], d["name"]))
    name = "Epix startup UI " + uuid.uuid4().hex[:8]
    for runtime in runtimes:
        for device in phones:
            try:
                udid = command(output, "xcrun", "simctl", "create", name, device["identifier"], runtime["identifier"])
                (output / "simulator.json").write_text(json.dumps({"udid": udid, "runtime": runtime,
                                                                  "device": device}, indent=2) + "\n")
                return udid
            except RuntimeError:
                # A recent runtime may no longer support an older device type.
                continue
    raise RuntimeError("No installed iOS runtime supports an available iPhone device type")


def run(output, app):
    sdk = command(output, "xcrun", "--sdk", "iphonesimulator", "--show-sdk-path")
    arch = "arm64" if platform.machine() == "arm64" else "x86_64"
    command(output, "xcrun", "--sdk", "iphonesimulator", "swiftc", "-swift-version", "5", "-parse-as-library",
            "-sdk", sdk, "-target", f"{arch}-apple-ios16.0-simulator", "-framework", "UIKit",
            "-module-cache-path", str(output / "module-cache"), str(output / "Fixture.swift"),
            "-o", str(app / "EpixStartupFixture"), timeout=180)
    udid = select_device(output)
    results = []
    try:
        command(output, "xcrun", "simctl", "boot", udid)
        command(output, "xcrun", "simctl", "bootstatus", udid, "-b", timeout=240)
        command(output, "xcrun", "simctl", "install", udid, str(app))
        for scenario in ("portrait", "landscape"):
            command(output, "xcrun", "simctl", "launch", "--terminate-running-process", udid, BUNDLE_ID, scenario)
            container = pathlib.Path(command(output, "xcrun", "simctl", "get_app_container", udid, BUNDLE_ID, "data"))
            result_path = container / "Documents" / f"{scenario}.json"
            deadline = time.monotonic() + 45
            while not result_path.exists() and time.monotonic() < deadline:
                time.sleep(0.25)
            command(output, "xcrun", "simctl", "io", udid, "screenshot", str(output / f"{scenario}.png"))
            if not result_path.exists():
                raise RuntimeError(f"Native {scenario} assertions did not finish; see screenshot and simulator log")
            result = json.loads(result_path.read_text())
            results.append(result)
            (output / f"{scenario}.json").write_text(json.dumps(result, indent=2) + "\n")
            print(f"{scenario}: {len(result['checks'])} native checks; passed={result['passed']}")
        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        if not all(result["passed"] for result in results):
            failures = [c["name"] for r in results for c in r["checks"] if not c["passed"]]
            raise RuntimeError("Native startup regressions:\n" + "\n".join(failures))
    finally:
        try:
            command(output, "xcrun", "simctl", "spawn", udid, "log", "show", "--last", "5m", "--style", "compact",
                    "--predicate", 'process == "EpixStartupFixture"', timeout=30, check=False)
        finally:
            try:
                command(output, "xcrun", "simctl", "shutdown", udid, timeout=30, check=False)
            finally:
                command(output, "xcrun", "simctl", "delete", udid, timeout=30, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--prepare-only", action="store_true", help="Extract Swift without needing Xcode or a simulator")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    app = prepare(output)
    if not args.prepare_only:
        run(output, app)
    print(f"Startup UI evidence: {output}")


if __name__ == "__main__":
    main()
