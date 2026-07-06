import SwiftUI
import WebKit

@main
struct EpixApp: App {
    @StateObject private var model = NodeModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
                .onChange(of: scenePhase) { phase in
                    if phase == .active {
                        model.onForeground()
                    }
                }
        }
    }
}

/// Boots and owns the embedded Epix node. One per app process; the node keeps
/// serving until iOS suspends the process.
final class NodeModel: ObservableObject {
    enum Phase {
        case starting
        case serving(URL)
        case failed(String)
    }

    @Published var phase: Phase = .starting

    private let node = EpixNode()
    /// Not the desktop defaults (43110/26552): the simulator shares the Mac's
    /// network namespace, where a desktop node may already hold those ports.
    private let uiBind = "127.0.0.1:43210"
    private let fileserverPort = 26553
    private let homeXite = "dashboard.epix"

    init() {
        start()
    }

    func start() {
        phase = .starting
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let dataDir = try self.prepareDataDir()
                try self.node.start(config: NodeConfig(
                    dataDir: dataDir,
                    target: self.homeXite,
                    uiAddr: self.uiBind,
                    torMode: "enable",
                    version: appVersion()))
                // The bind + resolved display, from the running node.
                guard let ui = self.node.uiUrl(), let url = URL(string: ui) else {
                    throw ShellError.noUiUrl
                }
                DispatchQueue.main.async { self.phase = .serving(url) }
            } catch {
                DispatchQueue.main.async {
                    self.phase = .failed(String(describing: error))
                }
            }
        }
    }

    /// Re-check the node when the app returns to the foreground: iOS may have
    /// suspended us mid-anything; a live node needs no action, a failed one
    /// gets a restart.
    func onForeground() {
        if case .failed = phase {
            start()
        }
    }

    private func prepareDataDir() throws -> String {
        let dir = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("EpixNet")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        // Seed the node config once so the fileserver port stays off the
        // desktop default (see uiBind note above). The node keeps its config
        // in private/ (the Python EpixNet layout).
        let privateDir = dir.appendingPathComponent("private")
        try FileManager.default.createDirectory(at: privateDir, withIntermediateDirectories: true)
        let config = privateDir.appendingPathComponent("config.json")
        if !FileManager.default.fileExists(atPath: config.path) {
            let seed = "{\n  \"fileserver_port\": \(fileserverPort)\n}\n"
            try seed.write(to: config, atomically: true, encoding: .utf8)
        }
        return dir.path
    }
}

enum ShellError: Error {
    case noUiUrl
}

private func appVersion() -> String {
    let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"
    return "\(v)-ios"
}

struct ContentView: View {
    @ObservedObject var model: NodeModel

    var body: some View {
        switch model.phase {
        case .starting:
            VStack(spacing: 14) {
                ProgressView()
                Text("Starting Epix node…")
                    .font(.callout)
                    .foregroundColor(.secondary)
            }
        case .serving(let url):
            WebView(url: url)
                .ignoresSafeArea(edges: .bottom)
        case .failed(let message):
            VStack(spacing: 14) {
                Image(systemName: "exclamationmark.triangle")
                    .font(.largeTitle)
                    .foregroundColor(.orange)
                Text("The node failed to start")
                    .font(.headline)
                Text(message)
                    .font(.footnote)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
                Button("Try again") { model.start() }
                    .buttonStyle(.borderedProminent)
            }
        }
    }
}

struct WebView: UIViewRepresentable {
    let url: URL

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeUIView(context: Context) -> WKWebView {
        let view = WKWebView(frame: .zero, configuration: WKWebViewConfiguration())
        view.navigationDelegate = context.coordinator
        view.load(URLRequest(url: url))
        return view
    }

    func updateUIView(_ view: WKWebView, context: Context) {}

    final class Coordinator: NSObject, WKNavigationDelegate {
        /// WebKit kills its content process under memory pressure or after a
        /// long suspension; without this the user sees a blank view forever.
        func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
            webView.reload()
        }
    }
}
