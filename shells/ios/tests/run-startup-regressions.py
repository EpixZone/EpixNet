#!/usr/bin/env python3
"""Compile the production iOS splash methods with small UIKit doubles.

This checks displayed progress state and cleanup on the host; it does not
replace UIKit rendering on an iOS simulator or device.
"""
import pathlib
import subprocess
import tempfile

source = (pathlib.Path(__file__).resolve().parents[1] / 'EpixBrowser/AppDelegate.swift').read_text()


def method(name, optional=False):
    candidates = [source.find('    ' + prefix + name + '(') for prefix in ('func ', 'private func ')]
    matches = [index for index in candidates if index >= 0]
    if not matches and optional:
        return ''
    assert matches, name
    start = min(matches)
    end = source.index('\n    }', start) + len('\n    }')
    return source[start:end].replace('private func', 'func', 1)


stub = r'''
import Foundation
import CoreGraphics

struct UIColor {
    static let white = UIColor()
    static let clear = UIColor()
    init() {}
    init(red: Double, green: Double, blue: Double, alpha: Double) {}
}
struct UIFontMetrics {
    enum TextStyle { case title2, subheadline }
    init(forTextStyle: TextStyle) {}
    func scaledFont(for font: UIFont) -> UIFont { font }
}
struct UIFont {
    enum Weight { case regular, medium, semibold, bold }
    static func systemFont(ofSize: Double, weight: Weight = .regular) -> UIFont { UIFont() }
}
struct UILayoutPriority: Equatable {
    let value: Int
    static let required = Self(value: 1000)
    static let defaultHigh = Self(value: 750)
    static let defaultLow = Self(value: 250)
}
class NSLayoutConstraint {
    enum Relation { case equal, atMost, atLeast }
    var priority = UILayoutPriority.required
    var relation = Relation.equal
    static var active: [NSLayoutConstraint] = []
    var first: Anchor?
    var second: Anchor?
    var constant: Double = 0
    init(first: Anchor? = nil, second: Anchor? = nil, constant: Double = 0,
         relation: Relation = .equal) {
        self.first = first; self.second = second; self.constant = constant; self.relation = relation
    }
    static func activate(_ constraints: [NSLayoutConstraint]) { active += constraints }
}
class Anchor {
    func constraint(equalTo: Anchor, constant: Double = 0) -> NSLayoutConstraint {
        NSLayoutConstraint(first: self, second: equalTo, constant: constant)
    }
    func constraint(equalToConstant: Double) -> NSLayoutConstraint {
        NSLayoutConstraint(first: self, constant: equalToConstant)
    }
    func constraint(lessThanOrEqualTo: Anchor, constant: Double = 0) -> NSLayoutConstraint {
        NSLayoutConstraint(first: self, second: lessThanOrEqualTo, constant: constant, relation: .atMost)
    }
    func constraint(greaterThanOrEqualTo: Anchor, constant: Double = 0) -> NSLayoutConstraint {
        NSLayoutConstraint(first: self, second: greaterThanOrEqualTo, constant: constant, relation: .atLeast)
    }
}
class CABasicAnimation {
    let keyPath: String
    var fromValue: Double = 0
    var toValue: Double = 0
    var duration: Double = 0
    var repeatCount: Float = 0
    init(keyPath: String) { self.keyPath = keyPath }
}
class CALayer {
    var animations: [String: CABasicAnimation] = [:]
    func add(_ animation: CABasicAnimation, forKey: String) { animations[forKey] = animation }
}
class UILayoutGuide {
    let topAnchor = Anchor(), bottomAnchor = Anchor()
    let leadingAnchor = Anchor(), trailingAnchor = Anchor()
    let widthAnchor = Anchor(), heightAnchor = Anchor()
}
class UIView {
    let safeAreaLayoutGuide = UILayoutGuide()
    enum AutoresizingMask { case flexibleWidth, flexibleHeight }
    enum ContentMode { case scaleAspectFit }
    var frame = CGRect.zero
    var bounds: CGRect { frame }
    var autoresizingMask: [AutoresizingMask] = []
    var backgroundColor: UIColor?
    var translatesAutoresizingMaskIntoConstraints = true
    var subviews: [UIView] = []
    var layer = CALayer()
    var alpha = 1.0
    var removed = false
    var isAccessibilityElement = false
    var accessibilityLabel: String?
    var accessibilityValue: String?
    let centerXAnchor = Anchor(), centerYAnchor = Anchor()
    let widthAnchor = Anchor(), heightAnchor = Anchor()
    let topAnchor = Anchor(), bottomAnchor = Anchor()
    let leadingAnchor = Anchor(), trailingAnchor = Anchor()
    init(frame: CGRect = .zero) { self.frame = frame }
    func addSubview(_ child: UIView) { subviews.append(child) }
    func removeFromSuperview() { removed = true }
    static func animate(withDuration: Double, animations: () -> Void, completion: ((Bool) -> Void)?) {
        animations(); completion?(true)
    }
}
class UIScrollView: UIView {
    let contentLayoutGuide = UILayoutGuide()
    let frameLayoutGuide = UILayoutGuide()
}
class UIStackView: UIView {
    enum Axis { case vertical }
    enum Alignment { case center }
    var axis = Axis.vertical
    var alignment = Alignment.center
    var spacing: Double = 0
    init(arrangedSubviews: [UIView]) {
        super.init()
        arrangedSubviews.forEach(addSubview)
    }
}
class UIImage { init?(contentsOfFile: String) {} }
class UIImageView: UIView {
    var image: UIImage?
    var contentMode = ContentMode.scaleAspectFit
}
class UILabel: UIView {
    enum Alignment { case center }
    var text: String?
    var textColor: UIColor?
    var font = UIFont()
    var numberOfLines = 1
    var adjustsFontForContentSizeCategory = false
    var textAlignment = Alignment.center
}
class UIProgressView: UIView {
    enum Style { case `default` }
    var progress: Float = 0
    var progressTintColor: UIColor?
    var trackTintColor: UIColor?
    init(progressViewStyle: Style) { super.init() }
    func setProgress(_ value: Float, animated: Bool) { progress = value }
}
enum StartupStage {
    case preparingData, loadingSettings, restoringXites, rebuildingDatabases, startingServices, prepared
}
enum NodeState { case idle, starting, serving, failed }
final class Node {
    var lifecycle = NodeState.starting
    func state() -> NodeState { lifecycle }
    var stage: StartupStage?
    func startupStage() -> StartupStage? { stage }
}
final class Shell {
    let node = Node()
    var nodePageRequested = false
    var bootTarget = "dashboard.epix"
    var requestedTarget: String?
    func bootNode(target: String) { requestedTarget = target }
    func syncToolbar() {}
    static let chromeBg = UIColor()
    var splashView: UIView?
    var splashHost: UIView?
    var splashStatus: UILabel?
    var splashDetail: UILabel?
    var splashProgress: UIProgressView?
    var startupTimer: Timer?
    var startupCompleted = 0
'''
checks = r'''
}
var failures = 0
var checks = 0
func descendants(_ view: UIView) -> [UIView] {
    view.subviews.flatMap { [$0] + descendants($0) }
}
func check(_ condition: Bool, _ message: String) {
    checks += 1
    if !condition { failures += 1; print("FAIL: \(message)") }
}
let shell = Shell()
let host = UIView(frame: CGRect(x: 0, y: 0, width: 390, height: 844))
shell.presentSplash(over: host)
var overlay = shell.splashView!
shell.pageSettled()
check(shell.splashView === overlay, "an initial blank navigation cannot dismiss startup")
let labels = descendants(overlay).compactMap { $0 as? UILabel }
check(labels.contains { $0.text == "Starting EpixNet" }, "startup splash must name the current work")
check(labels.contains { !($0.text ?? "").isEmpty && $0.text != "Starting EpixNet" }, "startup splash must explain the current stage")
check(descendants(overlay).contains { $0 is UIProgressView }, "startup splash must show real stage progress")
let mark = descendants(overlay).compactMap { $0 as? UIImageView }.first
check(mark?.layer.animations["spin"]?.duration == 1.2, "keep the shared 1.2 second mark rotation")
'''
extras = r'''
shell.setStartupProgress(title: "Restoring your xites", detail: "Loading saved content.", completed: 3, total: 8)
check(shell.splashStatus?.text == "Restoring your xites", "a new stage changes the status")
check(shell.splashDetail?.text == "Loading saved content.", "a new stage changes the explanation")
check(shell.splashProgress?.progress == 0.375, "progress represents completed stages")
shell.setStartupProgress(title: "Opening Epix Browser", detail: "Waiting for the first page.", completed: 7, total: 8)
check(shell.splashProgress?.progress == 0.875, "opening the browser must not claim the page is ready")
shell.hideSplash()
shell.presentSplash(over: host)
overlay = shell.splashView!
let expectedStages: [(StartupStage, String, Int)] = [
    (.preparingData, "Starting EpixNet", 2),
    (.loadingSettings, "Loading your settings", 3),
    (.restoringXites, "Restoring your xites", 4),
    (.rebuildingDatabases, "Preparing local databases", 5),
    (.startingServices, "Starting network services", 6),
    (.prepared, "Connecting your browser", 7),
]
for (stage, title, completed) in expectedStages {
    shell.node.stage = stage
    shell.pollStartupProgress()
    check(shell.splashStatus?.text == title && shell.splashProgress?.progress == Float(completed) / 9,
          "the actual node stage \(stage) updates status and completed steps")
}
shell.node.stage = nil
shell.pollStartupProgress()
check(shell.splashStatus?.text == "Connecting your browser", "no node stage leaves known progress intact")
shell.hideSplash()
shell.presentSplash(over: host)
overlay = shell.splashView!
shell.startStartupPolling()
let timer = shell.startupTimer!
check(timer.isValid && timer.timeInterval == 0.25, "poll active startup every 250 milliseconds")
shell.node.stage = .restoringXites
timer.fire()
check(shell.splashStatus?.text == "Restoring your xites", "the startup timer reads current FFI progress")
shell.nodePageRequested = true
shell.setStartupProgress(title: "Opening Epix Browser", detail: "Waiting for the page.", completed: 8, total: 9)
shell.node.stage = .prepared
timer.fire()
check(shell.splashStatus?.text == "Opening Epix Browser", "late node polling cannot replace first-page status")
shell.pageSettled()
check(!timer.isValid && shell.startupTimer == nil, "hiding the splash must stop startup polling")
check(shell.splashView == nil && overlay.removed, "a settled page removes the splash")
check(shell.splashStatus == nil && shell.splashDetail == nil && shell.splashProgress == nil,
      "finished startup releases progress controls")
shell.pollStartupProgress()
check(shell.splashStatus == nil, "late polling cannot recreate a dismissed splash")
shell.retryBoot()
check(!shell.nodePageRequested && shell.requestedTarget == "dashboard.epix",
      "error recovery resets navigation state and retries the original target")
check(shell.splashStatus?.text == "Starting EpixNet" && shell.splashProgress?.progress == 0,
      "retry starts with fresh status and progress")
shell.startStartupPolling()
let retryTimer = shell.startupTimer!
shell.startStartupPolling()
check(!retryTimer.isValid && shell.startupTimer?.isValid == true, "starting polling replaces an old timer")
shell.hideSplash()
shell.hideSplash()
check(shell.startupTimer == nil, "repeated completion leaves polling stopped")
'''
edge_checks = r'''
let retry = Shell()
retry.presentSplash(over: host)
retry.setStartupProgress(title: "Preparing your wallet", detail: "Wallet files.", completed: 1, total: 9)
for lifecycle in [NodeState.failed, .idle] {
    retry.node.lifecycle = lifecycle
    retry.node.stage = .loadingSettings
    retry.pollStartupProgress()
    check(retry.splashStatus?.text == "Preparing your wallet" && retry.splashProgress?.progress == 1.0 / 9,
          "a previous \(lifecycle) attempt cannot advance a new wallet-staging attempt")
}
retry.node.lifecycle = .starting
retry.node.stage = .preparingData
retry.pollStartupProgress()
check(retry.splashProgress?.progress == 2.0 / 9, "the new actual attempt starts reporting node work")
retry.node.stage = .loadingSettings
retry.pollStartupProgress()
retry.node.stage = .preparingData
retry.pollStartupProgress()
check(retry.splashStatus?.text == "Loading your settings" && retry.splashProgress?.progress == 3.0 / 9,
      "a repeated earlier stage cannot move current progress backward")
let landscape = Shell()
landscape.presentSplash(over: UIView(frame: CGRect(x: 0, y: 0, width: 640, height: 180)))
let landscapeOverlay = landscape.splashView!
let landscapeMark = descendants(landscapeOverlay).compactMap { $0 as? UIImageView }.first!
let fixedCenter = NSLayoutConstraint.active.first {
    $0.first === landscapeMark.centerYAnchor && $0.second === landscapeOverlay.centerYAnchor
}
if let fixedCenter = fixedCenter {
    let top = 180.0 / 2 + fixedCenter.constant - 96.0 / 2
    check(top >= 0, "short landscape clips the fixed-position mark: top=\(top)")
}
check(descendants(landscapeOverlay).contains { $0 is UIScrollView },
      "short landscape and large text need reachable scrollable startup content")
if let scroll = descendants(landscapeOverlay).compactMap({ $0 as? UIScrollView }).first {
    check(descendants(scroll).contains { $0 === landscapeMark }
          && descendants(scroll).contains { $0 === landscape.splashProgress },
          "both the animated mark and final progress line are in the scrollable content")
    check(NSLayoutConstraint.active.contains {
        $0.second === scroll.frameLayoutGuide.heightAnchor && $0.priority == .defaultLow
    }, "the content may grow beyond the short viewport")
    check(NSLayoutConstraint.active.contains {
        $0.second === scroll.contentLayoutGuide.bottomAnchor && $0.priority == .required
    }, "the scroll range includes the complete startup content")
}
let landscapeLabels = descendants(landscapeOverlay).compactMap { $0 as? UILabel }
check(landscapeLabels.allSatisfy { $0.numberOfLines == 0 && $0.adjustsFontForContentSizeCategory },
      "startup labels wrap without truncation and follow accessibility text size")
let markContainer = descendants(landscapeOverlay).first { $0.subviews.contains { $0 === landscapeMark } }!
check(NSLayoutConstraint.active.contains {
    $0.first === markContainer.heightAnchor && $0.second == nil && $0.constant >= 96 * sqrt(2)
}, "the spinning mark has room for its diagonal at every angle")
'''
methods = '\n'.join(method(name) for name in ('presentSplash', 'hideSplash', 'pageSettled', 'retryBoot'))
update = method('setStartupProgress', optional=True)
if update:
    methods += '\n' + '\n'.join(method(name) for name in (
        'startStartupPolling', 'stopStartupPolling', 'pollStartupProgress'))
body = stub + methods + '\n' + update + checks + (extras + edge_checks if update else '')
body += '\nprint("\\(checks) startup checks, \\(failures) failure(s)")\nexit(failures == 0 ? 0 : 1)\n'
with tempfile.TemporaryDirectory(prefix='epix-ios-startup-') as directory:
    path = pathlib.Path(directory)
    (path / 'main.swift').write_text(body)
    subprocess.run(['swiftc', '-module-cache-path', str(path / 'cache'), str(path / 'main.swift'),
                    '-o', str(path / 'regressions')], check=True)
    raise SystemExit(subprocess.run([str(path / 'regressions')]).returncode)
