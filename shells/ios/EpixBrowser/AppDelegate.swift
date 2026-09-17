import Network
import Security
import UIKit
import WebKit
// The node API (EpixNode, NodeConfig, TorStatus, NodeState) comes from the
// UniFFI-generated Generated/epix_ffi.swift, compiled into this target with
// its bridging header - no separate module (see ios/build-rust.sh).

/// The iOS shell: a browser over the embedded Epix node.
///
/// The Rust core is linked in as a staticlib and called through the generated
/// UniFFI Swift bindings. We boot the node, then drive a WKWebView.
///
/// The surface looks like a browser: an address bar (type `talk.epix`, an
/// `epix1…` address, or any URL) and, Brave-style, the Epix button next to it.
/// The button wears the Tor state as a badge (the desktop extension's colors:
/// gray off, amber connecting, purple ready, green when all traffic routes
/// through Tor) and opens the Epix panel - current xite, Tor status, our onion
/// address - when tapped.
///
/// Each xite has its own HTTPS origin through an in-process loopback proxy.
/// The per-install CA is trusted only for `.epix` within these browser views.
@main
class AppDelegate: UIResponder, UIApplicationDelegate, UITextFieldDelegate,
    WKScriptMessageHandler
{
    /// One open tab: its web view and the KVO subscription that keeps the
    /// address bar current while it is the visible tab.
    final class BrowserTab {
        let webView: WKWebView
        var urlObservation: NSKeyValueObservation?
        init(webView: WKWebView) { self.webView = webView }
    }

    var window: UIWindow?
    let node = EpixNode()
    /// Open tabs, in creation order. Never empty once the chrome is built.
    var tabs: [BrowserTab] = []
    var currentTabIndex = 0
    var currentTab: BrowserTab? {
        tabs.indices.contains(currentTabIndex) ? tabs[currentTabIndex] : nil
    }
    /// The visible tab's web view (the pre-tabs code paths all read this).
    var webView: WKWebView? { currentTab?.webView }
    /// The visible tab's web view fills this; switching tabs swaps the child.
    var webContainer: UIView?
    var backButton: UIButton?
    var forwardButton: UIButton?
    var tabsButton: UIButton?
    /// Scroll-away chrome: the address-bar top and toolbar bottom constraints
    /// slide off screen while the user scrolls down, back while scrolling up.
    var topBarConstraint: NSLayoutConstraint?
    var toolbarBottomConstraint: NSLayoutConstraint?
    var chromeHidden = false
    var panLastY: CGFloat = 0
    var panAccum: CGFloat = 0
    var addressBar: UITextField?
    var torBadge: UIView?
    var torTimer: Timer?
    var currentDisplay = ""
    /// Full-screen loading splash (spinning white Epix mark) shown over the
    /// chrome while the node boots and the first page paints; removed on the
    /// first navigation finish. Mirrors the desktop toolbar spin (PR #231).
    var splashView: UIView?
    /// The view the splash covers, kept so a boot retry can put it back.
    var splashHost: UIView?
    /// Set once the node page (or the shell's own error page) is requested,
    /// so an earlier navigation settling cannot drop the splash too early.
    var nodePageRequested = false
    /// The launch target, for the error page's "Try again".
    var bootTarget = "dashboard.epix"
    /// Network reachability, to wake the node when a connection returns.
    var pathMonitor: NWPathMonitor?
    /// Route clearnet browsing through the node's Tor SOCKS listener. Default
    /// on (opt-out), like the desktop extension. Persisted across launches.
    var torClearnet = true
    /// The running node's base URL. Starts at the default port; corrected
    /// from `uiUrl()` after boot (the simulator shares the Mac's loopback, so
    /// the app may fall back to an ephemeral port there).
    var nodeBase = "http://127.0.0.1:42222"
    var browserProxy: BrowserProxy?
    /// The wallet sheet (the forked Keplr web app served by the node).
    var walletVC: UIViewController?
    var walletWebView: WKWebView?
    lazy var walletUIDelegate: WalletUIDelegate = {
        let delegate = WalletUIDelegate()
        delegate.allowsCamera = { [weak self] web, frame in
            guard let self, web === self.walletWebView else { return false }
            return self.isWalletFrame(frame)
        }
        return delegate
    }()
    var dappRequest: (id: UUID, reply: (Any?, String?) -> Void)?


    // The node's local Tor SOCKS listener (epix-node boot: 43111).
    static let socksPort: UInt16 = 43111
    static let prefTorClearnet = "torClearnet"
    static let prefClearnetAllow = "clearnetAllow"

    // The dashboard's dark chrome + the desktop extension's icon colors.
    static let chromeBg = UIColor(red: 0x0B / 255.0, green: 0x0E / 255.0, blue: 0x14 / 255.0, alpha: 1)
    static let fieldBg = UIColor(red: 0x1E / 255.0, green: 0x29 / 255.0, blue: 0x3B / 255.0, alpha: 1)
    static let fieldText = UIColor(red: 0xCB / 255.0, green: 0xD5 / 255.0, blue: 0xE1 / 255.0, alpha: 1)
    static let torOff = UIColor(red: 0x64 / 255.0, green: 0x74 / 255.0, blue: 0x8B / 255.0, alpha: 1)
    static let torBoot = UIColor(red: 0xF5 / 255.0, green: 0xC4 / 255.0, blue: 0x50 / 255.0, alpha: 1)
    static let torReady = UIColor(red: 0xA7 / 255.0, green: 0x8B / 255.0, blue: 0xFA / 255.0, alpha: 1)
    static let torRouted = UIColor(red: 0x4A / 255.0, green: 0xDE / 255.0, blue: 0x80 / 255.0, alpha: 1)

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        if UserDefaults.standard.object(forKey: Self.prefTorClearnet) != nil {
            torClearnet = UserDefaults.standard.bool(forKey: Self.prefTorClearnet)
        }

        let window = UIWindow(frame: UIScreen.main.bounds)
        let controller = UIViewController()
        controller.view = buildBrowserChrome()
        window.rootViewController = controller
        window.makeKeyAndVisible()
        self.window = window
        presentSplash(over: controller.view)

        // The launch URL, if opened via an epix:// link.
        let target = (launchOptions?[.url] as? URL).flatMap(targetFrom) ?? "dashboard.epix"
        currentDisplay = target
        bootNode(target: target)
        watchConnectivity()

        // Reflect the Tor state in the button's badge, at the extension's cadence.
        torTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.pollTor()
        }
        pollTor()

        #if DEBUG
            // Test hook for the simulator (simctl cannot tap):
            //   xcrun simctl launch --terminate-running-process \
            //     booted zone.epix.EpixNet  # with SIMCTL_CHILD_EPIX_OPEN_WALLET=1
            // opens the wallet sheet as soon as the node serves.
            if ProcessInfo.processInfo.environment["EPIX_OPEN_WALLET"] == "1" {
                Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] t in
                    guard let self, self.node.state() == .serving else { return }
                    t.invalidate()
                    self.showWallet()
                }
            }
            // Same idea for navigation: SIMCTL_CHILD_EPIX_NAV=<input> runs the
            // input through navigate() (the address bar's path) once serving.
            if let nav = ProcessInfo.processInfo.environment["EPIX_NAV"], !nav.isEmpty {
                Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] t in
                    guard let self, self.node.state() == .serving else { return }
                    t.invalidate()
                    self.navigate(nav)
                }
            }
        #endif
        return true
    }

    /// The browser chrome: address bar + Epix button on top, the page below.
    private func buildBrowserChrome() -> UIView {
        let container = UIView(frame: UIScreen.main.bounds)
        container.backgroundColor = Self.chromeBg

        let field = UITextField()
        field.attributedPlaceholder = NSAttributedString(
            string: "Search or type a .epix name",
            attributes: [.foregroundColor: Self.torOff]
        )
        field.textColor = Self.fieldText
        field.font = .systemFont(ofSize: 14)
        field.backgroundColor = Self.fieldBg
        field.layer.cornerRadius = 18
        field.autocapitalizationType = .none
        field.autocorrectionType = .no
        field.keyboardType = .URL
        field.returnKeyType = .go
        field.clearButtonMode = .whileEditing
        field.leftView = UIView(frame: CGRect(x: 0, y: 0, width: 14, height: 1))
        field.leftViewMode = .always
        field.delegate = self
        field.translatesAutoresizingMaskIntoConstraints = false
        self.addressBar = field

        // The Epix button (Brave-style): the logo with the Tor state as a
        // badge; tapping opens the Epix panel. The logo is the white Epix mark
        // on a dark disc (the disc matches the chrome, so it reads as a clean
        // white mark) - the same reskin as the desktop toolbar (PR #231), and
        // ships as epix-badge-white.png in the bundle, with the system diamond
        // as a fallback if the resource wasn't packaged.
        let button = UIButton(type: .custom)
        if let path = Bundle.main.path(forResource: "epix-badge-white", ofType: "png"),
            let logo = UIImage(contentsOfFile: path) {
            let size = CGSize(width: 36, height: 36)
            let scaled = UIGraphicsImageRenderer(size: size).image { _ in
                logo.draw(in: CGRect(origin: .zero, size: size))
            }
            button.setImage(scaled.withRenderingMode(.alwaysOriginal), for: .normal)
        } else {
            button.setImage(UIImage(systemName: "diamond.fill"), for: .normal)
            button.tintColor = Self.torReady
        }
        // Tap opens the wallet (Brave-style); its shield carries the same
        // Tor/I2P panel. Long-press keeps the plain native panel.
        button.accessibilityLabel = "Epix wallet"
        button.addTarget(self, action: #selector(showWallet), for: .touchUpInside)
        button.addGestureRecognizer(
            UILongPressGestureRecognizer(target: self, action: #selector(epixButtonLongPress(_:)))
        )
        button.translatesAutoresizingMaskIntoConstraints = false
        let badge = UIView()
        badge.backgroundColor = Self.torOff
        badge.layer.cornerRadius = 6
        badge.layer.borderWidth = 2
        badge.layer.borderColor = Self.chromeBg.cgColor
        badge.isUserInteractionEnabled = false
        badge.translatesAutoresizingMaskIntoConstraints = false
        button.addSubview(badge)
        self.torBadge = badge

        let webContainer = UIView()
        webContainer.backgroundColor = Self.chromeBg
        webContainer.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(webContainer)
        self.webContainer = webContainer

        let toolbar = buildToolbar()
        toolbar.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(toolbar)
        container.addSubview(field)
        container.addSubview(button)

        // The first tab (also applies the saved clearnet-through-Tor routing).
        makeTab()

        // Scroll-away chrome, the way phone browsers give the page the whole
        // screen: dragging up hides the address bar and toolbar, dragging
        // down brings them back. Driven by the pan gesture rather than the
        // page's scroll position, because xites scroll inside the wrapper's
        // iframe (or their own panels) where the scroll view reports nothing.
        let pan = UIPanGestureRecognizer(target: self, action: #selector(handleChromePan(_:)))
        pan.cancelsTouchesInView = false
        pan.delegate = self
        webContainer.addGestureRecognizer(pan)

        let safe = container.safeAreaLayoutGuide
        let fieldTop = field.topAnchor.constraint(equalTo: safe.topAnchor, constant: 6)
        let toolbarBottom = toolbar.bottomAnchor.constraint(equalTo: safe.bottomAnchor)
        topBarConstraint = fieldTop
        toolbarBottomConstraint = toolbarBottom
        NSLayoutConstraint.activate([
            fieldTop,
            toolbarBottom,
            field.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 8),
            field.heightAnchor.constraint(equalToConstant: 36),
            button.leadingAnchor.constraint(equalTo: field.trailingAnchor, constant: 4),
            button.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -4),
            button.centerYAnchor.constraint(equalTo: field.centerYAnchor),
            button.widthAnchor.constraint(equalToConstant: 44),
            button.heightAnchor.constraint(equalToConstant: 44),
            badge.widthAnchor.constraint(equalToConstant: 12),
            badge.heightAnchor.constraint(equalToConstant: 12),
            badge.bottomAnchor.constraint(equalTo: button.bottomAnchor, constant: -5),
            badge.trailingAnchor.constraint(equalTo: button.trailingAnchor, constant: -5),
            webContainer.topAnchor.constraint(equalTo: field.bottomAnchor, constant: 6),
            webContainer.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            webContainer.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            webContainer.bottomAnchor.constraint(equalTo: toolbar.topAnchor),
            toolbar.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            toolbar.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            toolbar.heightAnchor.constraint(equalToConstant: 44),
        ])
        return container
    }

    /// Accumulate the drag; a direction flip starts a fresh measurement.
    @objc private func handleChromePan(_ g: UIPanGestureRecognizer) {
        switch g.state {
        case .began:
            panLastY = 0
            panAccum = 0
        case .changed:
            let y = g.translation(in: g.view).y
            let dy = y - panLastY
            panLastY = y
            if (dy < 0) != (panAccum < 0) { panAccum = 0 }
            panAccum += dy
            if panAccum < -48 {
                setChromeHidden(true)
                panAccum = 0
            } else if panAccum > 48 {
                setChromeHidden(false)
                panAccum = 0
            }
        default:
            break
        }
    }

    /// Slide the chrome off screen (or back); the page gets the freed space.
    func setChromeHidden(_ hidden: Bool) {
        guard hidden != chromeHidden, let root = window?.rootViewController?.view else { return }
        // Not while typing an address.
        if hidden && addressBar?.isFirstResponder == true { return }
        chromeHidden = hidden
        topBarConstraint?.constant = hidden ? -(root.safeAreaInsets.top + 48) : 6
        toolbarBottomConstraint?.constant = hidden ? 44 + root.safeAreaInsets.bottom : 0
        UIView.animate(withDuration: 0.2) { root.layoutIfNeeded() }
    }

    /// The bottom toolbar: back, forward, reload, and the tab switcher.
    private func buildToolbar() -> UIView {
        func glyphButton(_ symbol: String, _ label: String, _ action: Selector) -> UIButton {
            let b = UIButton(type: .system)
            b.setImage(UIImage(systemName: symbol), for: .normal)
            b.tintColor = Self.fieldText
            b.accessibilityLabel = label
            b.addTarget(self, action: action, for: .touchUpInside)
            return b
        }
        let back = glyphButton("chevron.backward", "Back", #selector(goBackTapped))
        let forward = glyphButton("chevron.forward", "Forward", #selector(goForwardTapped))
        let reload = glyphButton("arrow.clockwise", "Reload", #selector(reloadTapped))
        back.alpha = 0.35
        forward.alpha = 0.35
        backButton = back
        forwardButton = forward

        // The tab button: the open-tab count in a rounded square, like every
        // mobile browser's switcher button.
        let tabsB = UIButton(type: .system)
        tabsB.setTitle("1", for: .normal)
        tabsB.setTitleColor(Self.fieldText, for: .normal)
        tabsB.titleLabel?.font = .systemFont(ofSize: 13, weight: .semibold)
        tabsB.layer.borderColor = Self.fieldText.cgColor
        tabsB.layer.borderWidth = 2
        tabsB.layer.cornerRadius = 6
        tabsB.accessibilityLabel = "Tabs"
        tabsB.addTarget(self, action: #selector(showTabSwitcher), for: .touchUpInside)
        tabsButton = tabsB
        // A fixed-size square centered in its equal-width slot.
        let tabsHolder = UIView()
        tabsB.translatesAutoresizingMaskIntoConstraints = false
        tabsHolder.addSubview(tabsB)
        NSLayoutConstraint.activate([
            tabsB.centerXAnchor.constraint(equalTo: tabsHolder.centerXAnchor),
            tabsB.centerYAnchor.constraint(equalTo: tabsHolder.centerYAnchor),
            tabsB.widthAnchor.constraint(equalToConstant: 26),
            tabsB.heightAnchor.constraint(equalToConstant: 26),
        ])

        let bar = UIStackView(arrangedSubviews: [back, forward, reload, tabsHolder])
        bar.axis = .horizontal
        bar.distribution = .fillEqually
        bar.backgroundColor = Self.chromeBg
        return bar
    }

    @objc private func goBackTapped() { webView?.goBack() }
    @objc private func goForwardTapped() { webView?.goForward() }
    @objc private func reloadTapped() { webView?.reload() }

    /// Reflect the visible tab in the toolbar (history state, tab count).
    func syncToolbar() {
        backButton?.alpha = (webView?.canGoBack ?? false) ? 1 : 0.35
        forwardButton?.alpha = (webView?.canGoForward ?? false) ? 1 : 0.35
        tabsButton?.setTitle(String(tabs.count), for: .normal)
    }

    /// Create a tab, wire it up, and (by default) select it. Pass the
    /// configuration WebKit hands to createWebViewWith for target=_blank
    /// popups - those must be built from it.
    @discardableResult
    func makeTab(configuration: WKWebViewConfiguration? = nil, select: Bool = true) -> BrowserTab {
        let config = configuration ?? WKWebViewConfiguration()
        // Keep <video playsinline> in WebKit's own media path. The iPhone
        // default (false) hands playback to the fullscreen AVFoundation
        // player, whose loader treats the node's "bytes not here yet"
        // 503 on a cold seek as a fatal asset error with no retry.
        config.allowsInlineMediaPlayback = true
        config.mediaTypesRequiringUserActionForPlayback = []
        if configuration == nil,
            let path = Bundle.main.path(forResource: "mobileProvider.bundle", ofType: "js", inDirectory: "wallet-ext"),
            let provider = try? String(contentsOfFile: path, encoding: .utf8)
        {
            config.userContentController.addScriptMessageHandler(self, contentWorld: .page, name: "epixDapp")
            config.userContentController.addUserScript(WKUserScript(
                source: provider, injectionTime: .atDocumentStart, forMainFrameOnly: false))
        }
        let web = WKWebView(frame: .zero, configuration: config)
        web.navigationDelegate = self
        web.uiDelegate = self
        web.allowsBackForwardNavigationGestures = true
        // Dark behind the page: WKWebView paints white before content arrives
        // (the node may still be booting on a cold start).
        web.isOpaque = false
        web.backgroundColor = Self.chromeBg
        web.scrollView.backgroundColor = Self.chromeBg
        let tab = BrowserTab(webView: web)
        // Show `talk.epix/…` in the bar, not the local node plumbing.
        tab.urlObservation = web.observe(\.url, options: [.new]) { [weak self] wv, change in
            guard let self else { return }
            if self.currentTab?.webView === wv, self.addressBar?.isFirstResponder != true,
                let url = change.newValue ?? nil
            {
                self.addressBar?.text = self.friendlyUrl(url.absoluteString)
            }
            self.syncToolbar()
        }
        tabs.append(tab)
        applyClearnetRouting()
        if select {
            showTab(tabs.count - 1)
        } else {
            syncToolbar()
        }
        return tab
    }

    /// Put tab `index` on screen and sync the chrome to it.
    func showTab(_ index: Int) {
        guard tabs.indices.contains(index), let container = webContainer else { return }
        if index != currentTabIndex { cancelDappRequest("Request cancelled: browser tab changed") }
        currentTabIndex = index
        setChromeHidden(false)
        let web = tabs[index].webView
        container.subviews.forEach { $0.removeFromSuperview() }
        web.frame = container.bounds
        web.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        container.addSubview(web)
        if addressBar?.isFirstResponder != true {
            addressBar?.text = friendlyUrl(web.url?.absoluteString ?? "")
        }
        syncToolbar()
    }

    /// Close tab `index`. The browser always keeps at least one tab.
    func closeTab(_ index: Int) {
        guard tabs.indices.contains(index) else { return }
        if index == currentTabIndex { cancelDappRequest("Request cancelled: browser tab closed") }
        if tabs.count == 1 {
            // Last tab: reuse it for a fresh dashboard rather than going blank.
            currentDisplay = "dashboard.epix"
            load(display: currentDisplay)
            return
        }
        let tab = tabs.remove(at: index)
        tab.urlObservation = nil
        tab.webView.removeFromSuperview()
        let next = currentTabIndex >= index && currentTabIndex > 0
            ? currentTabIndex - 1 : currentTabIndex
        showTab(min(next, tabs.count - 1))
    }

    /// The tab's display name for the switcher: title, else `talk.epix/…`.
    private func tabName(_ tab: BrowserTab) -> String {
        if let t = tab.webView.title, !t.isEmpty { return t }
        var rest = tab.webView.url?.absoluteString ?? ""
        if rest.hasPrefix("\(nodeBase)/") { rest = String(rest.dropFirst(nodeBase.count + 1)) }
        while rest.hasSuffix("/") { rest = String(rest.dropLast()) }
        return rest.isEmpty ? "New tab" : rest
    }

    /// The tab list: pick a tab, open a new one, or close the current one.
    @objc private func showTabSwitcher() {
        let sheet = UIAlertController(title: "Tabs", message: nil, preferredStyle: .actionSheet)
        for (i, tab) in tabs.enumerated() {
            let name = tabName(tab)
            let title = i == currentTabIndex ? "● \(name)" : name
            sheet.addAction(UIAlertAction(title: title, style: .default) { [weak self] _ in
                self?.showTab(i)
            })
        }
        sheet.addAction(UIAlertAction(title: "New tab", style: .default) { [weak self] _ in
            guard let self else { return }
            self.makeTab()
            self.currentDisplay = "dashboard.epix"
            self.load(display: self.currentDisplay)
        })
        if tabs.count > 1 {
            sheet.addAction(UIAlertAction(title: "Close this tab", style: .destructive) { [weak self] _ in
                guard let self else { return }
                self.closeTab(self.currentTabIndex)
            })
        }
        sheet.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        if let pop = sheet.popoverPresentationController, let anchor = tabsButton {
            pop.sourceView = anchor
            pop.sourceRect = anchor.bounds
        }
        window?.rootViewController?.present(sheet, animated: true)
    }

    /// Go: turn what the user typed into somewhere to go.
    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        navigate(textField.text ?? "")
        textField.resignFirstResponder()
        return true
    }

    private func navigate(_ input: String) {
        let t = input.trimmingCharacters(in: .whitespaces)
        if t.isEmpty { return }
        let url: String
        if t.hasPrefix("?") {
            // A leading "?" always searches (the Firefox convention), even
            // for something that would otherwise parse as an address.
            url = searchUrl(String(t.dropFirst()))
        } else if t.hasPrefix("http://") || t.hasPrefix("https://") {
            url = t
        } else if let link = URL(string: t), let target = targetFrom(link) {
            currentDisplay = target
            url = nodeUrl(target)
        } else if t.hasPrefix("epix1") || t.hasSuffix(".epix") {
            // Only explicit xite addresses go to the resolver: epix1... or
            // something.epix. A bare word is a search, not an implied .epix.
            currentDisplay = t
            url = nodeUrl(t)
        } else if t.contains("."), !t.contains(" ") {
            // Looks like a clearnet domain: browse it over https.
            url = "https://\(t)"
        } else {
            // Everything else - bare words, phrases - searches DuckDuckGo.
            url = searchUrl(t)
        }
        if let u = URL(string: url) {
            webView?.load(URLRequest(url: u))
        }
    }

    /// A DuckDuckGo search for typed input that is not an address. Clearnet,
    /// so it follows the clearnet-through-Tor routing like any other
    /// non-.epix page.
    private func searchUrl(_ query: String) -> String {
        let trimmed = query.trimmingCharacters(in: .whitespaces)
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        let encoded = trimmed.addingPercentEncoding(withAllowedCharacters: allowed) ?? trimmed
        return "https://duckduckgo.com/?q=\(encoded)"
    }

    private func friendlyUrl(_ url: String) -> String {
        let prefix = "\(nodeBase)/"
        guard url.hasPrefix(prefix) else { return url }
        var rest = String(url.dropFirst(prefix.count))
        while rest.hasSuffix("/") { rest = String(rest.dropLast()) }
        if let first = rest.components(separatedBy: "/").first, !first.isEmpty {
            currentDisplay = first
        }
        return rest
    }

    /// A tapped epix:// link while running: navigate the web view.
    func application(
        _ app: UIApplication,
        open url: URL,
        options: [UIApplication.OpenURLOptionsKey: Any] = [:]
    ) -> Bool {
        guard let target = targetFrom(url) else { return false }
        currentDisplay = target
        load(display: target)
        return true
    }

    /// Mark the node data as browser-hosted: serverInfo reports `epix_browser`
    /// (and the clearnet-through-Tor state) from this file, and xite pages use
    /// that to know xite links can be followed instead of warning that the
    /// Epix Browser is missing (EpixTalk's link guard). The desktop native
    /// host writes the same file next to the node data.
    private func writeBrowserSettings() {
        let url = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("browser-settings.json")
        var obj =
            (try? Data(contentsOf: url))
            .flatMap { (try? JSONSerialization.jsonObject(with: $0)) as? [String: Any] } ?? [:]
        obj["tor_clearnet"] = torClearnet
        if let data = try? JSONSerialization.data(withJSONObject: obj) {
            try? data.write(to: url, options: .atomic)
        }
    }

    /// Boot the Rust node off the main thread, then load the local URL.
    /// Also the "Try again" path of the error page, so it is safe to run more
    /// than once: the FFI start() runs again after a failed boot.
    private func bootNode(target: String) {
        bootTarget = target
        DispatchQueue.global(qos: .userInitiated).async {
            let dataDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].path
            try? FileManager.default.createDirectory(
                atPath: dataDir, withIntermediateDirectories: true)
            self.writeBrowserSettings()
            self.stageWalletUi(dataDir: dataDir)
            let config = { (uiAddr: String) in
                NodeConfig(
                    dataDir: dataDir,
                    // The resolver takes only the xite name; the full target
                    // is retained below for navigation after the node starts.
                    target: target.components(separatedBy: "/")[0],
                    uiAddr: uiAddr,
                    torMode: "enable",
                    version: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.1.0"
                )
            }
            do {
                do {
                    try self.node.start(config: config("127.0.0.1:42222"))
                } catch {
                    // The default port can be taken - in the simulator the
                    // Mac's own desktop node shares this loopback. Let the
                    // OS pick a port; uiUrl() reports the real bind. Only for
                    // a bind failure: any other error is shown as-is instead
                    // of re-running the whole boot on an ephemeral port.
                    let text = self.node.lastError() ?? "\(error)"
                    guard text.contains("bind") else { throw error }
                    try self.node.start(config: config("127.0.0.1:0"))
                }
                if let ui = self.node.uiUrl(), let u = URL(string: ui),
                    let host = u.host, let port = u.port
                {
                    self.nodeBase = "http://\(host):\(port)"
                }
                DispatchQueue.main.async {
                    self.browserProxy = self.node.browserProxy()
                    self.applyClearnetRouting()
                    self.nodePageRequested = true
                    self.load(display: target)
                }
            } catch {
                // The FFI keeps the node's own message; the thrown value only
                // wraps it as an enum case.
                let message = self.node.lastError() ?? "\(error)"
                DispatchQueue.main.async {
                    self.nodePageRequested = true
                    self.showError(message)
                }
            }
        }
    }

    /// Stage the bundled wallet web app where the node serves it
    /// (`<dataDir>/wallet-ui` -> /EpixWallet/). Copied on every launch: the
    /// bundle contents change between builds without the manifest changing,
    /// and the copy is cheap next to the node boot it overlaps with.
    private func stageWalletUi(dataDir: String) {
        let fm = FileManager.default
        guard let res = Bundle.main.resourcePath else { return }
        let bundled = res + "/wallet-ext"
        guard fm.fileExists(atPath: bundled + "/manifest.json") else { return }
        let dest = dataDir + "/wallet-ui"
        try? fm.removeItem(atPath: dest)
        try? fm.copyItem(atPath: bundled, toPath: dest)
    }

    /// Same color language as the desktop extension's toolbar icon: green when
    /// Tor is on AND clearnet is routed through it, purple when Tor is ready but
    /// clearnet goes direct, amber connecting, gray off.
    private func colorFor(_ st: TorStatus) -> UIColor {
        if st.enabled { return torClearnet ? Self.torRouted : Self.torReady }
        if st.status == "Bootstrapping" { return Self.torBoot }
        return Self.torOff
    }

    /// Fetch the Tor state off the main thread (the call blocks) and tint the badge.
    private func pollTor() {
        DispatchQueue.global(qos: .utility).async {
            let st = self.node.torStatus()
            DispatchQueue.main.async {
                self.torBadge?.backgroundColor = self.colorFor(st)
            }
        }
    }

    /// The Epix panel: current xite, Tor status, our onion address, and the
    /// "route clearnet through Tor" switch (the desktop extension's popup).
    @objc private func showEpixPanel() {
        DispatchQueue.global(qos: .utility).async {
            let st = self.node.torStatus()
            let onion = self.node.onionAddress()
            var lines = [String]()
            if !self.currentDisplay.isEmpty {
                lines.append("Xite: \(self.currentDisplay)")
            }
            if st.enabled {
                lines.append(self.torClearnet
                    ? "Tor: on - clearnet routed through Tor"
                    : "Tor: ready - onion peers reachable")
            } else if st.status == "Bootstrapping" {
                lines.append("Tor: connecting…")
            } else if st.status == "Failed" {
                lines.append("Tor: failed to start")
            } else {
                lines.append("Tor: off")
            }
            if let onion = onion {
                lines.append("\nYour onion address:\n\(onion).onion")
            }
            DispatchQueue.main.async {
                self.presentEpixPanel(info: lines.joined(separator: "\n"))
            }
        }
    }

    /// A small sheet: the info text, then a "Route clearnet through Tor" switch.
    /// UIAlertController can't host a switch, so this is a plain presented
    /// controller with a stack view.
    private func presentEpixPanel(info: String) {
        let vc = UIViewController()
        vc.modalPresentationStyle = .formSheet
        vc.view.backgroundColor = .systemBackground
        vc.preferredContentSize = CGSize(width: 320, height: 260)

        let title = UILabel()
        title.text = "Epix"
        title.font = .boldSystemFont(ofSize: 20)

        let infoLabel = UILabel()
        infoLabel.text = info
        infoLabel.numberOfLines = 0
        infoLabel.font = .systemFont(ofSize: 14)

        let toggleLabel = UILabel()
        toggleLabel.text = "Route clearnet through Tor"
        toggleLabel.font = .systemFont(ofSize: 14)
        let toggle = UISwitch()
        toggle.isOn = torClearnet
        toggle.addTarget(self, action: #selector(torClearnetChanged(_:)), for: .valueChanged)
        let toggleRow = UIStackView(arrangedSubviews: [toggleLabel, toggle])
        toggleRow.axis = .horizontal
        toggleRow.spacing = 8

        let done = UIButton(type: .system)
        done.setTitle("OK", for: .normal)
        done.addTarget(self, action: #selector(dismissPanel), for: .touchUpInside)
        done.contentHorizontalAlignment = .trailing

        let stack = UIStackView(arrangedSubviews: [title, infoLabel, toggleRow, done])
        stack.axis = .vertical
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        vc.view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: vc.view.safeAreaLayoutGuide.topAnchor, constant: 20),
            stack.leadingAnchor.constraint(equalTo: vc.view.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: vc.view.trailingAnchor, constant: -20),
        ])
        window?.rootViewController?.present(vc, animated: true)
    }

    @objc private func dismissPanel() {
        window?.rootViewController?.presentedViewController?.dismiss(animated: true)
    }

    @objc private func epixButtonLongPress(_ g: UILongPressGestureRecognizer) {
        if g.state == .began {
            showEpixPanel()
        }
    }

    func applicationWillResignActive(_ application: UIApplication) {
        // Keep wallet balances/seed screens out of the app-switcher snapshot.
        if let view = walletVC?.view {
            let cover = UIView(frame: view.bounds)
            cover.backgroundColor = Self.chromeBg
            cover.autoresizingMask = [.flexibleWidth, .flexibleHeight]
            cover.tag = 73491
            view.addSubview(cover)
        }
    }

    func applicationDidBecomeActive(_ application: UIApplication) {
        walletVC?.view.viewWithTag(73491)?.removeFromSuperview()
    }

    func applicationDidEnterBackground(_ application: UIApplication) {
        // The mobile wallet background lives in its document. Destroy it when
        // backgrounded so decrypted keys and unfinished approvals don't linger.
        cancelDappRequest("Wallet locked because EpixNet moved to the background")
        walletVC?.dismiss(animated: false)
        walletVC = nil
        walletWebView?.removeFromSuperview()
        walletWebView?.configuration.userContentController.removeAllScriptMessageHandlers()
        walletWebView?.stopLoading()
        walletWebView = nil
    }

    // MARK: - The Epix Wallet sheet

    /// Open the wallet: the forked Keplr web app, served by the embedded node
    /// at /EpixWallet/ and shown in a sheet over the browser (the Android
    /// shell's dialog, done the iOS way). Falls back to the plain panel while
    /// the node is still booting.
    @objc private func showWallet() {
        if walletVC != nil {
            dismissWallet()
            return
        }
        guard node.state() == .serving,
            let url = URL(string: "\(nodeBase)/EpixWallet/mobile.html")
        else {
            showEpixPanel()
            return
        }

        let web = walletWebView ?? makeWalletWebView(url: url)
        web.removeFromSuperview()

        let vc = UIViewController()
        vc.view.backgroundColor = Self.chromeBg

        // A slim header with an explicit close control (parity with the
        // Android sheet): the sheet covers the browser, and the pull-down
        // gesture alone is not discoverable.
        let title = UILabel()
        title.text = "Epix Wallet"
        title.textColor = Self.fieldText
        title.font = .systemFont(ofSize: 15, weight: .semibold)
        title.translatesAutoresizingMaskIntoConstraints = false
        let close = UIButton(type: .system)
        close.setTitle("✕", for: .normal)
        close.setTitleColor(Self.fieldText, for: .normal)
        close.titleLabel?.font = .systemFont(ofSize: 17)
        close.accessibilityLabel = "Close wallet"
        close.addTarget(self, action: #selector(dismissWallet), for: .touchUpInside)
        close.translatesAutoresizingMaskIntoConstraints = false

        vc.view.addSubview(title)
        vc.view.addSubview(close)
        vc.view.addSubview(web)
        let safe = vc.view.safeAreaLayoutGuide
        NSLayoutConstraint.activate([
            title.topAnchor.constraint(equalTo: safe.topAnchor, constant: 10),
            title.leadingAnchor.constraint(equalTo: vc.view.leadingAnchor, constant: 16),
            close.centerYAnchor.constraint(equalTo: title.centerYAnchor),
            close.trailingAnchor.constraint(equalTo: vc.view.trailingAnchor, constant: -16),
            close.widthAnchor.constraint(equalToConstant: 44),
            close.heightAnchor.constraint(equalToConstant: 36),
            web.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 8),
            web.leadingAnchor.constraint(equalTo: vc.view.leadingAnchor),
            web.trailingAnchor.constraint(equalTo: vc.view.trailingAnchor),
            web.bottomAnchor.constraint(equalTo: vc.view.bottomAnchor),
        ])

        vc.modalPresentationStyle = .pageSheet
        vc.presentationController?.delegate = self
        walletVC = vc
        window?.rootViewController?.present(vc, animated: true)
    }

    private func makeWalletWebView(url: URL) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        config.userContentController.add(self, name: "epixDappUI")
        // The wallet page's shim bridges native-host commands (Tor/I2P
        // status, the clearnet toggle), persistent storage (the keyring
        // vault - WKWebView's localStorage is unreliable), and close
        // requests over these.
        config.userContentController.add(self, name: "epixNmh")
        config.userContentController.add(self, name: "epixStore")
        config.userContentController.add(self, name: "epixClose")
        #if DEBUG
            // Forward console.error / window.onerror to the app log so
            // failures inside the wallet UI are visible without an attached
            // Safari inspector.
            config.userContentController.add(self, name: "epixLog")
            let logHook = """
                (function () {
                  function fmt(a) {
                    if (a instanceof Error) {
                      return (a.message || "") + " | " + (a.stack || "");
                    }
                    if (a && typeof a === "object") {
                      var m = a.message || a.reason || "";
                      try { return (m ? m + " | " : "") + JSON.stringify(a); }
                      catch (_) { return m || String(a); }
                    }
                    return String(a);
                  }
                  function post(kind, args) {
                    try {
                      window.webkit.messageHandlers.epixLog.postMessage(
                        kind + ": " + args.map(fmt).join(" ")
                      );
                    } catch (_) {}
                  }
                  var e = console.error.bind(console);
                  console.error = function () { post("console.error", [].slice.call(arguments)); e.apply(null, arguments); };
                  window.addEventListener("error", function (ev) {
                    post("error", [ev.message, ev.filename + ":" + ev.lineno, ev.error]);
                  });
                  window.addEventListener("unhandledrejection", function (ev) {
                    post("unhandledrejection", [ev.reason]);
                  });
                })();
                """
            config.userContentController.addUserScript(
                WKUserScript(source: logHook, injectionTime: .atDocumentStart, forMainFrameOnly: false)
            )
        #endif
        // Keystone hardware-wallet pairing scans animated QR codes: let the
        // camera preview render inline, and answer the capture-permission ask
        // in walletUIDelegate below (the OS NSCameraUsageDescription prompt
        // still shows the first time).
        config.allowsInlineMediaPlayback = true
        let web = WKWebView(frame: .zero, configuration: config)
        #if DEBUG
        if #available(iOS 16.4, *) { web.isInspectable = true }
        #endif
        web.uiDelegate = walletUIDelegate
        web.translatesAutoresizingMaskIntoConstraints = false
        // Dark behind the wallet page until its inline splash paints; the
        // default white flashes while the bundles parse.
        web.isOpaque = false
        web.backgroundColor = Self.chromeBg
        web.scrollView.backgroundColor = Self.chromeBg
        walletWebView = web
        applyClearnetRouting()
        web.navigationDelegate = self
        web.load(URLRequest(url: url))
        return web

    }

    @objc private func dismissWallet() {
        walletWebView?.evaluateJavaScript("window.dispatchEvent(new Event('epix-wallet-closed'))")
        cancelDappRequest("Request rejected: wallet closed")
        walletVC?.dismiss(animated: true)
        walletVC = nil
    }

    /// The wallet shim's native bridge: `epixNmh` carries the desktop native
    /// host's commands as `{id, message}`; the reply goes back by resolving
    /// `window.__epixNmhReply(id, result)` in the wallet page. `epixClose` is
    /// tabs.remove - the wallet closing its own page.
    func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage
    ) {
        // Message handlers remain installed if this view navigates, and are
        // visible to subframes too. Only the wallet document may access its
        // vault and native settings, including after a sheet is replaced.
        guard acceptsWalletMessage(message) else { return }
        if message.name == "epixDappUI" {
            if walletVC == nil { showWallet() }
            return
        }
        if message.name == "epixClose" {
            dismissWallet()
            return
        }
        #if DEBUG
            if message.name == "epixLog" {
                NSLog("EpixWallet JS %@", message.body as? String ?? "")
                return
            }
        #endif
        if message.name == "epixStore" {
            handleStore(message)
            return
        }
        guard message.name == "epixNmh",
            let text = message.body as? String,
            let data = text.data(using: .utf8),
            let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
            let id = obj["id"] as? Int
        else { return }
        let msg = obj["message"] as? [String: Any] ?? [:]
        handleNmh(msg) { [weak self] result in
            guard let body = try? JSONSerialization.data(withJSONObject: result),
                let json = String(data: body, encoding: .utf8)
            else { return }
            DispatchQueue.main.async {
                guard let self, self.acceptsWalletMessage(message), let web = message.webView
                else { return }
                web.evaluateJavaScript("window.__epixNmhReply(\(id), \(json))")
            }
        }
    }

    private func acceptsWalletMessage(_ message: WKScriptMessage) -> Bool {
        guard let web = message.webView, web === walletWebView,
            walletDocumentURL(web.url) == walletDocumentURL(message.frameInfo.request.url)
        else { return false }
        return isWalletFrame(message.frameInfo)
    }

    private func walletDocumentURL(_ url: URL?) -> URL? {
        guard let url, var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        else { return nil }
        // HashRouter changes the fragment without changing the wallet document.
        components.fragment = nil
        return components.url
    }

    private func isWalletFrame(_ frame: WKFrameInfo) -> Bool {
        guard frame.isMainFrame,
            let base = URLComponents(string: nodeBase),
            let url = frame.request.url,
            let page = URLComponents(url: url, resolvingAgainstBaseURL: false),
            page.scheme == base.scheme, page.host == base.host, page.port == base.port,
            page.percentEncodedPath.hasPrefix("/EpixWallet/"),
            let path = page.percentEncodedPath.removingPercentEncoding,
            !path.contains("\\"),
            !path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." })
        else { return false }
        let origin = frame.securityOrigin
        return origin.protocol == base.scheme && origin.host == base.host
            && origin.port == (base.port ?? 80)
    }

    /// Answer one native-host command with the same JSON shapes as the
    /// desktop `epix-nmh` (and the Android shell's delegate).
    private func handleNmh(_ msg: [String: Any], reply: @escaping ([String: Any]) -> Void) {
        let cmd = msg["cmd"] as? String ?? ""
        switch cmd {
        case "status":
            guard let url = URL(string: "\(nodeBase)/EpixNet-Internal/Status") else {
                reply(["serving": false])
                return
            }
            let port = URL(string: nodeBase)?.port ?? 42222
            let torClearnet = self.torClearnet
            URLSession.shared.dataTask(with: url) { data, _, _ in
                var out: [String: Any] = ["serving": false]
                if let data = data,
                    let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
                {
                    // The shim's storage bridge rejects JSON null; absent
                    // keys read the same to the wallet.
                    out = obj.filter { !($0.value is NSNull) }
                }
                out["ui_port"] = port
                out["tor_clearnet"] = torClearnet
                reply(out)
            }.resume()
        case "getTorClearnet":
            reply(["on": torClearnet])
        case "setTorClearnet":
            let on = msg["on"] as? Bool ?? false
            DispatchQueue.main.async { self.setTorClearnet(on) }
            reply(["ok": true, "on": on])
        case "getClearnetAllow":
            let site = msg["site"] as? String ?? ""
            reply(["allow": allowedSites().contains(site)])
        case "setClearnetAllow":
            let site = msg["site"] as? String ?? ""
            var sites = allowedSites()
            if msg["allow"] as? Bool ?? false {
                if !sites.contains(site) { sites.append(site) }
            } else {
                sites.removeAll { $0 == site }
            }
            UserDefaults.standard.set(sites, forKey: Self.prefClearnetAllow)
            reply(["ok": true])
        case "listClearnetAllow":
            reply(["sites": allowedSites()])
        case "openConfig":
            // Close the wallet sheet and point the browser at the node's
            // config page (the dashboard's Config lives at the UI origin).
            DispatchQueue.main.async {
                self.dismissWallet()
                if let u = URL(string: "\(self.nodeBase)/Config") {
                    self.currentDisplay = "Config"
                    self.webView?.load(URLRequest(url: u))
                }
            }
            reply(["ok": true])
        default:
            reply(["error": "unknown command: \(cmd)"])
        }
    }

    /// Sites the user allowed to reach clearnet from a `.epix` page.
    private func allowedSites() -> [String] {
        UserDefaults.standard.stringArray(forKey: Self.prefClearnetAllow) ?? []
    }

    // MARK: - Wallet persistent storage (browser.storage.local)

    /// The wallet's storage.local, persisted for the shim: WKWebView's
    /// localStorage comes back null in this shell and the keyring vault must
    /// survive, so it is kept in a JSON file in the app's Application Support
    /// directory. Loaded once, written through on every set.
    private var walletStoreError: String?
    private lazy var walletStore: [String: String] = {
        do {
            let url = try walletStoreURL()
            guard FileManager.default.fileExists(atPath: url.path) else { return [:] }
            let data = try Data(contentsOf: url)
            guard let values = try JSONSerialization.jsonObject(with: data) as? [String: String]
            else { throw CocoaError(.fileReadCorruptFile) }
            try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
            return values
        } catch {
            // Refuse to overwrite an unreadable vault with an empty wallet.
            walletStoreError = "Wallet storage could not be opened. Unlock the device and retry. Your saved wallet has been kept."
            return [:]
        }
    }()

    private func walletStoreURL() throws -> URL {
        try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        ).appendingPathComponent("wallet-store.json")
    }

    private func persistWalletStore(_ next: [String: String]) throws {
        let url = try walletStoreURL()
        let data = try JSONSerialization.data(withJSONObject: next)
        try data.write(to: url, options: [.atomic, .completeFileProtection])
    }

    /// One storage op from the shim (`{id, op:{cmd, key?, value?}}`). Values
    /// are opaque JSON strings; the reply goes back through
    /// window.__epixStoreReply(id, result).
    private func handleStore(_ message: WKScriptMessage) {
        guard let text = message.body as? String,
            let data = text.data(using: .utf8),
            let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
            let id = obj["id"] as? Int,
            let op = obj["op"] as? [String: Any]
        else { return }
        _ = walletStore // Load and validate before checking a cached read error.
        if let error = walletStoreError {
            replyStore(id: id, result: NSNull(), error: error, to: message)
            return
        }
        let cmd = op["cmd"] as? String ?? ""
        var next = walletStore
        var changed = false
        var result: Any = NSNull()
        switch cmd {
        case "get":
            if let key = op["key"] as? String {
                result = walletStore[key] ?? NSNull()
            }
        case "set":
            if let key = op["key"] as? String, let value = op["value"] as? String {
                next[key] = value
                changed = true
            }
        case "remove":
            if let key = op["key"] as? String {
                next.removeValue(forKey: key)
                changed = true
            }
        case "keys":
            result = Array(walletStore.keys)
        default:
            break
        }
        if changed {
            do {
                try persistWalletStore(next)
                walletStore = next
            } catch {
                replyStore(id: id, result: NSNull(), error: "Wallet could not be saved. Check available storage and unlock the device, then retry.", to: message)
                return
            }
        }
        replyStore(id: id, result: result, to: message)
    }

    private func replyStore(id: Int, result: Any, error: String? = nil, to message: WKScriptMessage) {
        // A JSON string, a JSON array (keys), or null - all valid JS literals
        // for __epixStoreReply's second argument.
        let json: String
        if result is NSNull {
            json = "null"
        } else if let s = result as? String,
            let d = try? JSONSerialization.data(withJSONObject: [s]),
            let arr = String(data: d, encoding: .utf8)
        {
            // Wrap+unwrap to escape the string as a JS literal.
            json = String(arr.dropFirst().dropLast())
        } else if let d = try? JSONSerialization.data(withJSONObject: result),
            let s = String(data: d, encoding: .utf8)
        {
            json = s
        } else {
            json = "null"
        }
        let errorJSON = error.flatMap { try? JSONSerialization.data(withJSONObject: [$0]) }
            .flatMap { String(data: $0, encoding: .utf8) }.map { String($0.dropFirst().dropLast()) } ?? "null"
        DispatchQueue.main.async {
            guard self.acceptsWalletMessage(message), let web = message.webView else { return }
            web.evaluateJavaScript("window.__epixStoreReply(\(id), \(json), \(errorJSON))")
        }
    }

    @objc private func torClearnetChanged(_ sender: UISwitch) {
        setTorClearnet(sender.isOn)
    }

    /// Flip the clearnet-through-Tor routing, persist it, and apply it live.
    private func setTorClearnet(_ on: Bool) {
        if torClearnet == on { return }
        torClearnet = on
        UserDefaults.standard.set(on, forKey: Self.prefTorClearnet)
        DispatchQueue.global(qos: .utility).async { self.writeBrowserSettings() }
        applyClearnetRouting()
        torBadge?.backgroundColor = on ? Self.torRouted : Self.torReady
    }

    /// Separate TLS origins for xites; optionally route ordinary web traffic
    /// through Tor. Neither route falls back to a direct network connection.
    private func applyClearnetRouting() {
        guard #available(iOS 17.0, *) else { return }
        var proxies: [ProxyConfiguration] = []
        if let proxy = browserProxy {
            let endpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: proxy.port)!)
            var local = ProxyConfiguration(httpCONNECTProxy: endpoint)
            local.matchDomains = ["epix"]
            local.allowFailover = false
            proxies.append(local)
        }
        if torClearnet {
            let endpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: Self.socksPort)!)
            var tor = ProxyConfiguration(socksv5Proxy: endpoint)
            tor.excludedDomains = ["epix", "127.0.0.1", "localhost"]
            tor.allowFailover = false
            proxies.append(tor)
        }
        for tab in tabs {
            tab.webView.configuration.websiteDataStore.proxyConfigurations = proxies
        }
        walletWebView?.configuration.websiteDataStore.proxyConfigurations = proxies
    }

    private func load(display: String) {
        guard let url = URL(string: nodeUrl(display)) else { return }
        webView?.load(URLRequest(url: url))
    }

    private func nodeUrl(_ name: String) -> String {
        guard let url = URL(string: "epix://\(name)"), let rewritten = xiteRewrite(url)
        else { return "\(nodeBase)/" }
        return rewritten.absoluteString
    }

    /// Show the loading splash: the white Epix mark spinning on the dark chrome
    /// background, over `host`, until the first page paints. On a cold start the
    /// node bootstraps Tor for tens of seconds; this covers that wait (the
    /// desktop browser spins its toolbar icon, PR #231) instead of a blank
    /// dark screen.
    private func presentSplash(over host: UIView) {
        let overlay = UIView(frame: host.bounds)
        overlay.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        overlay.backgroundColor = Self.chromeBg

        let mark = UIImageView()
        if let path = Bundle.main.path(forResource: "epix-mark-white", ofType: "png") {
            mark.image = UIImage(contentsOfFile: path)
        }
        mark.contentMode = .scaleAspectFit
        mark.translatesAutoresizingMaskIntoConstraints = false
        overlay.addSubview(mark)
        NSLayoutConstraint.activate([
            mark.centerXAnchor.constraint(equalTo: overlay.centerXAnchor),
            mark.centerYAnchor.constraint(equalTo: overlay.centerYAnchor),
            mark.widthAnchor.constraint(equalToConstant: 96),
            mark.heightAnchor.constraint(equalToConstant: 96),
        ])

        // A steady continuous spin, one turn every 1.2s, for as long as the
        // node is coming up.
        let spin = CABasicAnimation(keyPath: "transform.rotation.z")
        spin.fromValue = 0
        spin.toValue = 2 * Double.pi
        spin.duration = 1.2
        spin.repeatCount = .infinity
        mark.layer.add(spin, forKey: "spin")

        host.addSubview(overlay)
        splashView = overlay
        splashHost = host
    }

    /// Tell the node when the network comes back, so it retries what was
    /// parked on it (the name registry check, a homepage waiting to resolve)
    /// instead of waiting out its backoff timers.
    private func watchConnectivity() {
        let monitor = NWPathMonitor()
        var wasOnline = true
        monitor.pathUpdateHandler = { [weak self] path in
            let online = path.status == .satisfied
            if online && !wasOnline {
                DispatchQueue.global(qos: .utility).async { self?.node.networkChanged() }
            }
            wasOnline = online
        }
        monitor.start(queue: DispatchQueue.global(qos: .utility))
        pathMonitor = monitor
    }

    /// Bring the splash back and boot again (the error page's "Try again").
    private func retryBoot() {
        nodePageRequested = false
        if splashView == nil, let host = splashHost {
            presentSplash(over: host)
        }
        bootNode(target: bootTarget)
    }

    /// Fade the loading splash out and remove it. Idempotent.
    func hideSplash() {
        guard let overlay = splashView else { return }
        splashView = nil
        UIView.animate(
            withDuration: 0.25,
            animations: { overlay.alpha = 0 },
            completion: { _ in overlay.removeFromSuperview() }
        )
    }

    /// The error page's "Try again" and "Reset settings" links; intercepted
    /// in decidePolicyFor.
    static let retryUrl = "epixshell://retry"
    static let resetUrl = "epixshell://reset-config"

    /// The error page's "Reset connection settings and try again". The settings
    /// page that would fix a bad settings file is served by the node, which is
    /// exactly what did not start, so the shell does this part: set the file
    /// aside (kept, never deleted) and boot with defaults.
    private func resetConfigAndRetry() {
        let dataDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let config = dataDir.appendingPathComponent("private/config.json")
        if FileManager.default.fileExists(atPath: config.path) {
            let stamp = Int(Date().timeIntervalSince1970)
            let aside = dataDir.appendingPathComponent("private/config.json.broken-\(stamp)")
            if (try? FileManager.default.moveItem(at: config, to: aside)) == nil {
                try? FileManager.default.removeItem(at: config)
            }
        }
        retryBoot()
    }

    /// An inline page for when the node could not start or stays unreachable -
    /// never a blank view or a bare error string. Carries the node's own
    /// message when there is one and a "Try again" that boots the node again
    /// without leaving the app.
    private func showError(_ message: String?) {
        var detail = ""
        if let message, !message.trimmingCharacters(in: .whitespaces).isEmpty {
            let escaped = message
                .replacingOccurrences(of: "&", with: "&amp;")
                .replacingOccurrences(of: "<", with: "&lt;")
                .replacingOccurrences(of: ">", with: "&gt;")
            detail = "<p style=\"font-family:monospace;font-size:13px;color:#94a3b8;text-align:left;"
                + "overflow-wrap:anywhere;background:#1e293b;padding:12px;border-radius:8px\">"
                + escaped + "</p>"
        }
        let html = """
            <html><head><meta name="viewport" content="width=device-width, initial-scale=1"></head>
            <body style="background:#0b0e14;color:#cbd5e1;font-family:-apple-system,sans-serif;margin:0;
                         display:flex;align-items:center;justify-content:center;min-height:100vh">
            <div style="text-align:center;padding:24px;max-width:26em">
              <h2 style="color:#e2e8f0">EpixNet could not start</h2>
              <p>The built-in node did not start. This is usually temporary.</p>
              \(detail)
              <p><a href="\(Self.retryUrl)" style="display:inline-block;padding:12px 24px;background:#8a4bdb;
                 color:#fff;border-radius:10px;text-decoration:none;font-weight:600">Try again</a></p>
              <p style="font-size:14px"><a href="\(Self.resetUrl)" style="color:#a78bfa;text-decoration:none;
                 display:inline-block;padding:10px 0">Reset connection settings and try again</a><br>
                 <span style="font-size:13px;color:#64748b">Starts with default settings. Your current
                 settings file is kept next to it, not deleted. You can change settings again from
                 the dashboard menu once EpixNet is running.</span></p>
              <p style="font-size:13px;color:#64748b">If this keeps happening, close the app fully and
                 reopen it, or report a bug at github.com/EpixZone/EpixNet.</p>
            </div></body></html>
            """
        webView?.loadHTMLString(html, baseURL: nil)
    }

    /// Keep the encoded path, query and fragment from external deep links.
    private func targetFrom(_ url: URL) -> String? {
        guard url.scheme?.lowercased() == "epix", let rewritten = xiteRewrite(url)
        else { return nil }
        return String(rewritten.absoluteString.dropFirst("https://".count))
    }
}

/// Drops the loading splash once the first page settles - whether it painted
/// (didFinish) or errored out (the node's own error page still shows). The
/// splash is idempotent, so extra navigations are harmless. Also intercepts
/// navigations only EpixNet can resolve and reroutes them to the local node.
extension AppDelegate: WKNavigationDelegate {
    /// Normalize links to the xite's distinct HTTPS origin. The local proxy
    /// serves these hosts; arbitrary websites retain ordinary system trust.
    func xiteRewrite(_ url: URL) -> URL? {
        let scheme = url.scheme?.lowercased() ?? ""
        var host: String?
        if scheme == "epix" {
            host = url.host ?? url.absoluteString
                .replacingOccurrences(of: "epix://", with: "")
                .components(separatedBy: "/").first
        } else if scheme == "http" || scheme == "https" {
            if let h = url.host?.lowercased(),
                h.hasSuffix(".epix")
                    || h.range(of: "^epix1[a-z0-9]{20,}$", options: .regularExpression) != nil
            {
                host = h
            }
        }
        guard var host = host?.lowercased(), !host.isEmpty,
            url.user == nil, url.password == nil, url.port == nil,
            host.range(of: "^[a-z0-9]+[a-z0-9.-]*$", options: .regularExpression) != nil
        else { return nil }
        if !host.hasSuffix(".epix") { host += ".epix" }
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        var path = comps?.percentEncodedPath ?? "/"
        if path.isEmpty { path = "/" }
        let query = (comps?.percentEncodedQuery).map { "?\($0)" } ?? ""
        let fragment = (comps?.percentEncodedFragment).map { "#\($0)" } ?? ""
        return URL(string: "https://\(host)\(path)\(query)\(fragment)")
    }

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
    ) {
        if webView === walletWebView, let url = navigationAction.request.url {
            let base = URLComponents(string: nodeBase)
            let page = URLComponents(url: url, resolvingAgainstBaseURL: false)
            let allowed = page?.scheme == base?.scheme && page?.host == base?.host
                && page?.port == base?.port
                && ["/EpixWallet/mobile.html", "/EpixWallet/mobile-register.html"].contains(page?.path ?? "")
            if !allowed {
                decisionHandler(.cancel)
                if ["https", "http", "epix"].contains(url.scheme ?? "") {
                    makeTab().webView.load(URLRequest(url: xiteRewrite(url) ?? url))
                }
                return
            }
            if let old = webView.url, walletDocumentURL(old) != walletDocumentURL(url) {
                cancelDappRequest("Wallet page changed; finish setup and connect again")
            }
            decisionHandler(.allow)
            return
        }
        if webView === currentTab?.webView,
            navigationAction.targetFrame?.isMainFrame == true,
            let old = webView.url, let next = navigationAction.request.url,
            walletDocumentURL(old) != walletDocumentURL(next) {
            cancelDappRequest("Request cancelled: browser page changed")
        }
        // The error page's "Try again": boot the node again in-process.
        if navigationAction.request.url?.absoluteString == Self.retryUrl {
            decisionHandler(.cancel)
            retryBoot()
            return
        }
        if navigationAction.request.url?.absoluteString == Self.resetUrl {
            decisionHandler(.cancel)
            resetConfigAndRetry()
            return
        }
        if let url = navigationAction.request.url, let rewritten = xiteRewrite(url), rewritten != url {
            decisionHandler(.cancel)
            // Load top-level even when the click came from the wrapper's
            // content iframe: another xite is a page change.
            webView.load(URLRequest(url: rewritten))
            return
        }
        decisionHandler(.allow)
    }

    func webView(
        _ webView: WKWebView,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        let space = challenge.protectionSpace
        guard space.authenticationMethod == NSURLAuthenticationMethodServerTrust,
            space.host.lowercased().hasSuffix(".epix")
        else { completionHandler(.performDefaultHandling, nil); return }
        guard tabs.contains(where: { $0.webView === webView }),
            let der = browserProxy?.caDer,
            let ca = SecCertificateCreateWithData(nil, Data(der) as CFData),
            let trust = space.serverTrust
        else {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }
        // Evaluate a separate trust object. Mutating WebKit's challenge trust
        // changes the credential it passes back to the networking process.
        var localTrust: SecTrust?
        guard let chain = SecTrustCopyCertificateChain(trust),
            SecTrustCreateWithCertificates(chain, SecPolicyCreateSSL(true, space.host as CFString), &localTrust) == errSecSuccess,
            let localTrust
        else { completionHandler(.cancelAuthenticationChallenge, nil); return }
        SecTrustSetAnchorCertificates(localTrust, [ca] as CFArray)
        SecTrustSetAnchorCertificatesOnly(localTrust, true)
        // This is a private CA; do not send its certificate/hosts to network
        // revocation responders or fetch any other certificates.
        SecTrustSetNetworkFetchAllowed(localTrust, false)
        var trustError: CFError?
        if SecTrustEvaluateWithError(localTrust, &trustError) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            #if DEBUG
            NSLog("Local xite TLS validation failed: %@", String(describing: trustError))
            #endif
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    /// The splash comes down only once a page we asked for has settled: the
    /// node's page, or the shell's own error page. Anything earlier (the
    /// initial blank view) must not drop it onto an empty screen.
    private func pageSettled() {
        if nodePageRequested { hideSplash() }
        syncToolbar()
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        pageSettled()
    }

    func webView(
        _ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error
    ) {
        pageSettled()
    }

    func webView(
        _ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!,
        withError error: Error
    ) {
        if (error as NSError).code == NSURLErrorCancelled { return }
        // A request to the node that never connected renders as nothing in
        // WKWebView. Show the shell's page with a retry instead of a blank
        // view (Android has the same fallback after its port wait).
        let failed = (error as NSError).userInfo[NSURLErrorFailingURLStringErrorKey] as? String ?? ""
        if failed.hasPrefix(nodeBase) {
            nodePageRequested = true
            showError(node.lastError() ?? "The node is not answering on \(nodeBase).")
            return
        }
        if webView !== walletWebView {
            func escape(_ text: String) -> String {
                text.replacingOccurrences(of: "&", with: "&amp;")
                    .replacingOccurrences(of: "<", with: "&lt;")
                    .replacingOccurrences(of: ">", with: "&gt;")
                    .replacingOccurrences(of: "\"", with: "&quot;")
            }
            let target = URL(string: failed)
            let retry = ["https", "http"].contains(target?.scheme ?? "")
                ? "<p><a href=\"\(escape(failed))\">Try again</a></p>" : ""
            let html = """
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <body style="background:#0b0e14;color:#cbd5e1;font:17px -apple-system;padding:36px">
                <h2>Page could not load</h2><p>\(escape(error.localizedDescription))</p>
                \(retry)<p>You can also enter another address above.</p></body>
                """
            webView.loadHTMLString(html, baseURL: nil)
            nodePageRequested = true
        }
        pageSettled()
    }
}

/// The chrome pan must observe alongside the web view's own scrolling, not
/// steal from it.
extension AppDelegate: UIGestureRecognizerDelegate {
    func gestureRecognizer(
        _ gestureRecognizer: UIGestureRecognizer,
        shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer
    ) -> Bool {
        true
    }
}

/// Browser-tab popups: target=_blank / window.open become new tabs, and a
/// script closing its own window closes that tab. (The wallet sheet has its
/// own WalletUIDelegate; this delegate serves only the browser tabs.)
extension AppDelegate: WKUIDelegate {
    func webView(
        _ webView: WKWebView,
        createWebViewWith configuration: WKWebViewConfiguration,
        for navigationAction: WKNavigationAction,
        windowFeatures: WKWindowFeatures
    ) -> WKWebView? {
        makeTab(configuration: configuration).webView
    }

    func webViewDidClose(_ webView: WKWebView) {
        if let i = tabs.firstIndex(where: { $0.webView === webView }) {
            closeTab(i)
        }
    }
}

/// UI delegate for the wallet sheet: answers the camera capture ask from the
/// Keystone QR scanner. Grants camera only, and only to our own wallet pages
/// on the node's loopback origin; everything else is denied. The OS-level
/// camera prompt (NSCameraUsageDescription) still shows once per install.
final class WalletUIDelegate: NSObject, WKUIDelegate {
    var allowsCamera: ((WKWebView, WKFrameInfo) -> Bool)?
    @available(iOS 15.0, *)
    func webView(
        _ webView: WKWebView,
        requestMediaCapturePermissionFor origin: WKSecurityOrigin,
        initiatedByFrame frame: WKFrameInfo,
        type: WKMediaCaptureType,
        decisionHandler: @escaping (WKPermissionDecision) -> Void
    ) {
        decisionHandler(type == .camera && allowsCamera?(webView, frame) == true ? .prompt : .deny)
    }
}

extension AppDelegate: WKScriptMessageHandlerWithReply, UIAdaptivePresentationControllerDelegate {
    /// WebKit's security origin identifies the caller. Paths and values in
    /// JavaScript messages never establish wallet identity. Restrict iframes
    /// to the visible tab's origin so embedded third parties cannot ask.
    func dappOrigin(_ message: WKScriptMessage) -> String? {
        guard let web = message.webView, web === currentTab?.webView,
            let top = web.url, let frameURL = message.frameInfo.request.url,
            top.scheme == "https", frameURL.scheme == "https",
            let host = frameURL.host?.lowercased(), host == top.host?.lowercased(),
            !["localhost", "127.0.0.1", "::1"].contains(host),
            (frameURL.port ?? 443) == (top.port ?? 443),
            message.frameInfo.securityOrigin.protocol == "https",
            message.frameInfo.securityOrigin.host.lowercased() == host,
            (message.frameInfo.securityOrigin.port == 0 ? 443 : message.frameInfo.securityOrigin.port) == (frameURL.port ?? 443)
        else { return nil }
        return "https://\(host)" + (frameURL.port.map { $0 == 443 ? "" : ":\($0)" } ?? "")
    }

    func cancelDappRequest(_ reason: String) {
        let request = dappRequest
        dappRequest = nil
        if request != nil {
            walletWebView?.evaluateJavaScript("window.dispatchEvent(new Event('epix-wallet-closed'))")
        }
        request?.reply(nil, reason)
    }

    func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage,
        replyHandler: @escaping (Any?, String?) -> Void
    ) {
        guard message.name == "epixDapp", node.state() == .serving,
            let origin = dappOrigin(message),
            var payload = message.body as? [String: Any],
            payload["port"] as? String == "background",
            var body = payload["msg"] as? [String: Any],
            let bytes = try? JSONSerialization.data(withJSONObject: payload), bytes.count <= 262144
        else { replyHandler(nil, "Wallet request from this document is not allowed"); return }
        guard dappRequest == nil else {
            replyHandler(nil, "Another wallet request is pending"); return
        }
        guard let url = URL(string: "\(nodeBase)/EpixWallet/mobile.html") else {
            replyHandler(nil, "Wallet is unavailable"); return
        }
        // Ignore page-supplied origin, extension identity and router metadata.
        body["origin"] = origin
        body["routerMeta"] = [:]
        payload["msg"] = body
        let wallet = walletWebView ?? makeWalletWebView(url: url)
        let id = UUID()
        dappRequest = (id, replyHandler)
        let script = """
            for (let i = 0; i < 100 && !window.__epixMobileBackgroundReady; i++) {
                await new Promise(resolve => setTimeout(resolve, 100));
            }
            if (!window.__epixMobileBackgroundReady || !window.__epixDappReceive) {
                throw new Error('Open Epix Wallet and finish setup before connecting');
            }
            return await window.__epixDappReceive(payload, {url: origin + '/'});
            """
        wallet.callAsyncJavaScript(script, arguments: ["payload": payload, "origin": origin],
                                  in: nil, in: .page) { [weak self] result in
            guard let self, self.dappRequest?.id == id else { return }
            self.dappRequest = nil
            guard self.dappOrigin(message) == origin else {
                replyHandler(nil, "The requesting tab changed"); return
            }
            switch result {
            case .success(let response): replyHandler(response, nil)
            case .failure: replyHandler(nil, "Wallet request failed. Open Epix Wallet, finish setup or unlock, then try again.")
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 180) { [weak self] in
            guard let self, self.dappRequest?.id == id else { return }
            self.walletWebView?.evaluateJavaScript("window.dispatchEvent(new Event('epix-wallet-closed'))")
            self.cancelDappRequest("Wallet request expired")
        }
    }

    func presentationControllerDidDismiss(_ presentationController: UIPresentationController) {
        if presentationController.presentedViewController === walletVC { dismissWallet() }
    }
}
