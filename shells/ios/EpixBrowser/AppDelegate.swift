import Network
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
/// KNOWN SPIKE (Phase 8b #1): custom-scheme pages in WKWebView are NOT secure
/// contexts (no service workers, no crypto.subtle). This scaffold loads the
/// loopback `http://127.0.0.1` origin directly, which sidesteps the custom
/// scheme but exposes the port. The three escapes to evaluate - the
/// com.apple.developer.web-browser entitlement, iOS 17 proxyConfigurations, or
/// accepting degraded xites - are tracked in PLAN.md (Workstream C correction).
@main
class AppDelegate: UIResponder, UIApplicationDelegate, UITextFieldDelegate,
    WKScriptMessageHandler
{
    var window: UIWindow?
    let node = EpixNode()
    var webView: WKWebView?
    var addressBar: UITextField?
    var torBadge: UIView?
    var torTimer: Timer?
    var urlObservation: NSKeyValueObservation?
    var currentDisplay = ""
    /// Full-screen loading splash (spinning white Epix mark) shown over the
    /// chrome while the node boots and the first page paints; removed on the
    /// first navigation finish. Mirrors the desktop toolbar spin (PR #231).
    var splashView: UIView?
    /// Route clearnet browsing through the node's Tor SOCKS listener. Default
    /// on (opt-out), like the desktop extension. Persisted across launches.
    var torClearnet = true
    /// The running node's base URL. Starts at the default port; corrected
    /// from `uiUrl()` after boot (the simulator shares the Mac's loopback, so
    /// the app may fall back to an ephemeral port there).
    var nodeBase = "http://127.0.0.1:42222"
    /// The wallet sheet (the forked Keplr web app served by the node).
    var walletVC: UIViewController?
    var walletWebView: WKWebView?
    let walletUIDelegate = WalletUIDelegate()

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

        let webView = WKWebView(frame: .zero, configuration: WKWebViewConfiguration())
        webView.navigationDelegate = self
        webView.translatesAutoresizingMaskIntoConstraints = false
        // Dark behind the page: WKWebView paints white before content arrives
        // (the node may still be booting on a cold start).
        webView.isOpaque = false
        webView.backgroundColor = Self.chromeBg
        webView.scrollView.backgroundColor = Self.chromeBg
        container.addSubview(webView)
        container.addSubview(field)
        container.addSubview(button)
        self.webView = webView
        // Apply the saved clearnet-through-Tor routing before the first load.
        applyClearnetRouting()

        // Show `talk.epix/…` in the bar, not the local node plumbing.
        urlObservation = webView.observe(\.url, options: [.new]) { [weak self] _, change in
            guard let self, let url = change.newValue ?? nil else { return }
            if self.addressBar?.isFirstResponder != true {
                self.addressBar?.text = self.friendlyUrl(url.absoluteString)
            }
        }

        let safe = container.safeAreaLayoutGuide
        NSLayoutConstraint.activate([
            field.topAnchor.constraint(equalTo: safe.topAnchor, constant: 6),
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
            webView.topAnchor.constraint(equalTo: field.bottomAnchor, constant: 6),
            webView.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            webView.bottomAnchor.constraint(equalTo: container.bottomAnchor),
        ])
        return container
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
        } else if t.hasPrefix("epix://") {
            let host = String(t.dropFirst("epix://".count)).components(separatedBy: "/")[0]
            currentDisplay = host
            url = nodeUrl(host)
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

    /// Boot the Rust node off the main thread, then load the local URL.
    private func bootNode(target: String) {
        DispatchQueue.global(qos: .userInitiated).async {
            let dataDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].path
            self.stageWalletUi(dataDir: dataDir)
            let config = { (uiAddr: String) in
                NodeConfig(
                    dataDir: dataDir,
                    target: target,
                    uiAddr: uiAddr,
                    torMode: "enable",
                    version: "0.1.0"
                )
            }
            do {
                do {
                    try self.node.start(config: config("127.0.0.1:42222"))
                } catch {
                    // The default port can be taken - in the simulator the
                    // Mac's own desktop node shares this loopback. Let the
                    // OS pick a port; uiUrl() reports the real bind.
                    try self.node.start(config: config("127.0.0.1:0"))
                }
                if let ui = self.node.uiUrl(), let u = URL(string: ui),
                    let host = u.host, let port = u.port
                {
                    self.nodeBase = "http://\(host):\(port)"
                }
                DispatchQueue.main.async { self.load(display: target) }
            } catch {
                DispatchQueue.main.async { self.showError("\(error)") }
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

        let config = WKWebViewConfiguration()
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
        if #available(iOS 16.4, *) { web.isInspectable = true }
        web.uiDelegate = walletUIDelegate
        web.translatesAutoresizingMaskIntoConstraints = false
        // Dark behind the wallet page until its inline splash paints; the
        // default white flashes while the bundles parse.
        web.isOpaque = false
        web.backgroundColor = Self.chromeBg
        web.scrollView.backgroundColor = Self.chromeBg
        walletWebView = web

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
        vc.presentationController?.delegate = nil
        walletVC = vc
        window?.rootViewController?.present(vc, animated: true)
        web.load(URLRequest(url: url))
    }

    @objc private func dismissWallet() {
        walletVC?.dismiss(animated: true)
        walletVC = nil
        walletWebView = nil
    }

    /// The wallet shim's native bridge: `epixNmh` carries the desktop native
    /// host's commands as `{id, message}`; the reply goes back by resolving
    /// `window.__epixNmhReply(id, result)` in the wallet page. `epixClose` is
    /// tabs.remove - the wallet closing its own page.
    func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage
    ) {
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
            guard let self, let web = self.walletWebView,
                let body = try? JSONSerialization.data(withJSONObject: result),
                let json = String(data: body, encoding: .utf8)
            else { return }
            DispatchQueue.main.async {
                web.evaluateJavaScript("window.__epixNmhReply(\(id), \(json))")
            }
        }
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
    private var walletStore: [String: String] = {
        guard
            let url = try? FileManager.default.url(
                for: .applicationSupportDirectory, in: .userDomainMask,
                appropriateFor: nil, create: true
            ).appendingPathComponent("wallet-store.json"),
            let data = try? Data(contentsOf: url),
            let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: String]
        else { return [:] }
        return obj
    }()

    private func walletStoreURL() -> URL? {
        try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        ).appendingPathComponent("wallet-store.json")
    }

    private func persistWalletStore() {
        guard let url = walletStoreURL(),
            let data = try? JSONSerialization.data(withJSONObject: walletStore)
        else { return }
        try? data.write(to: url, options: .atomic)
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
        let cmd = op["cmd"] as? String ?? ""
        var result: Any = NSNull()
        switch cmd {
        case "get":
            if let key = op["key"] as? String {
                result = walletStore[key] ?? NSNull()
            }
        case "set":
            if let key = op["key"] as? String, let value = op["value"] as? String {
                walletStore[key] = value
                persistWalletStore()
            }
        case "remove":
            if let key = op["key"] as? String {
                walletStore.removeValue(forKey: key)
                persistWalletStore()
            }
        case "keys":
            result = Array(walletStore.keys)
        default:
            break
        }
        replyStore(id: id, result: result)
    }

    private func replyStore(id: Int, result: Any) {
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
        DispatchQueue.main.async {
            self.walletWebView?.evaluateJavaScript("window.__epixStoreReply(\(id), \(json))")
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
        applyClearnetRouting()
        torBadge?.backgroundColor = on ? Self.torRouted : Self.torReady
    }

    /// Point the web view's proxy at the node's Tor SOCKS listener (or clear
    /// it). When on, clearnet requests go through Tor; the node's own loopback
    /// - the UI and every `.epix` page served from 127.0.0.1 - is excluded, so
    /// xites keep loading directly. This is the runtime equivalent of the
    /// desktop launcher's file PAC. iOS 17+ only (WKWebsiteDataStore proxy).
    private func applyClearnetRouting() {
        guard #available(iOS 17.0, *), let store = webView?.configuration.websiteDataStore else {
            return
        }
        if torClearnet {
            let endpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: Self.socksPort)!)
            var config = ProxyConfiguration(socksv5Proxy: endpoint)
            // Never proxy the node's own loopback: the UI and .epix pages load
            // from 127.0.0.1 and Tor would refuse a private address anyway.
            config.excludedDomains = ["127.0.0.1", "localhost"]
            store.proxyConfigurations = [config]
        } else {
            store.proxyConfigurations = []
        }
    }

    private func load(display: String) {
        guard let url = URL(string: nodeUrl(display)) else { return }
        webView?.load(URLRequest(url: url))
    }

    private func nodeUrl(_ name: String) -> String {
        "\(nodeBase)/\(name)/"
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

    private func showError(_ message: String) {
        let html = "<body style='font:16px system-ui;padding:2rem;color:#f87171'>Could not start Epix: \(message)</body>"
        webView?.loadHTMLString(html, baseURL: nil)
    }

    /// Pull the xite host out of an `epix://host/path` URL.
    private func targetFrom(_ url: URL) -> String? {
        guard url.scheme == "epix" else { return nil }
        return url.host ?? url.absoluteString
            .replacingOccurrences(of: "epix://", with: "")
            .components(separatedBy: "/").first
    }
}

/// Drops the loading splash once the first page settles - whether it painted
/// (didFinish) or errored out (the node's own error page still shows). The
/// splash is idempotent, so extra navigations are harmless.
extension AppDelegate: WKNavigationDelegate {
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        hideSplash()
    }

    func webView(
        _ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error
    ) {
        hideSplash()
    }

    func webView(
        _ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!,
        withError error: Error
    ) {
        hideSplash()
    }
}

/// UI delegate for the wallet sheet: answers the camera capture ask from the
/// Keystone QR scanner. Grants camera only, and only to our own wallet pages
/// on the node's loopback origin; everything else is denied. The OS-level
/// camera prompt (NSCameraUsageDescription) still shows once per install.
final class WalletUIDelegate: NSObject, WKUIDelegate {
    @available(iOS 15.0, *)
    func webView(
        _ webView: WKWebView,
        requestMediaCapturePermissionFor origin: WKSecurityOrigin,
        initiatedByFrame frame: WKFrameInfo,
        type: WKMediaCaptureType,
        decisionHandler: @escaping (WKPermissionDecision) -> Void
    ) {
        let isLoopback = origin.host == "127.0.0.1" || origin.host == "localhost"
        decisionHandler(type == .camera && isLoopback ? .grant : .deny)
    }
}
