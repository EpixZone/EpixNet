import Darwin
import ExtensionFoundation
import Foundation
import SwiftUI
import XPC

@main
struct FixtureApp: App {
    @StateObject private var model = FixtureModel()
    @Environment(\.scenePhase) private var scenePhase
    var body: some Scene {
        WindowGroup {
            VStack {
                Text("Disposable enhanced-security game fixture. EVX is disabled.")
                Text(model.status)
                Button("Run fixed fixture once") { Task { await model.run() } }.disabled(model.used)
            }.padding().onChange(of: scenePhase) { _, phase in
                if phase != .active { model.stop("App left foreground; admission retained") }
            }
        }
    }
}

@MainActor
private final class FixtureModel: ObservableObject {
    @Published var status = "No execution admitted"
    @Published var used = false
    private var observation = HostObservation()
    private var process: AppExtensionProcess?
    private var session: XPCSession?
    private var deadline: Task<Void, Never>?

    func run() async {
        guard !used else { return }; used = true
        let request = GameRequest(magic: 0x45565831, version: 1,
            nonceHigh: UInt64.random(in: 1...UInt64.max), nonceLow: UInt64.random(in: 1...UInt64.max), level: 0, coins: 42)
        do {
            try persistAdmission(request)
            try observation.admit(request)
            deadline = Task { [weak self] in
                try? await Task.sleep(for: .seconds(3))
                guard !Task.isCancelled else { return }
                self?.stop("Deadline reached; no confirmed termination or reuse")
            }
            let monitor = try await AppExtensionPoint.Monitor(appExtensionPoint: .evxGameFixture)
            let matches = monitor.identities.filter { $0.bundleIdentifier == "zone.epix.evxfixture.helper" }
            guard matches.count == 1 else { throw FixtureError.invalidMessage }
            let launched = try await AppExtensionProcess(configuration: .init(appExtensionIdentity: matches[0], onInterruption: { [weak self] in
                Task { @MainActor in
                    self?.observation.interruptionObserved()
                    self?.status = "OS interruption observed. Bounded death, accounting and reuse remain unverified."
                }
            }))
            process = launched
            guard observation.phase == .admitted else { launched.invalidate(); return }
            let channel = try launched.makeXPCSession()
            session = channel
            try channel.activate()
            try channel.send(request) { [weak self] result in
                let reply: GameReply?
                switch result {
                case .success(let message): reply = try? message.decode(as: GameReply.self)
                case .failure: reply = nil
                }
                Task { @MainActor in self?.receive(reply) }
            }
        } catch { stop("Launch refused; durable admission retained") }
    }
    private func receive(_ reply: GameReply?) {
        do {
            guard let reply else { throw FixtureError.invalidMessage }
            try observation.reply(reply)
            stop("Score 42 received. Connection closed; no process-death claim.")
        } catch { stop("Invalid or stale reply; admission retained") }
    }
    func stop(_ reason: String) {
        observation.stopRequested(); status = reason
        session?.cancel(reason: "fixture stopping")
        process?.invalidate()
        // These calls close connections. They do not establish bounded death.
        // Retain the admission marker; there is no reset or production fallback.
        deadline?.cancel()
    }
    private func persistAdmission(_ request: GameRequest) throws {
        let parent = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let marker = parent.appendingPathComponent("evx-fixture-admitted")
        let descriptor = open(marker.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw FixtureError.alreadyUsed }
        defer { close(descriptor) }
        let bytes = Array("\(request.nonceHigh):\(request.nonceLow)".utf8)
        let written = bytes.withUnsafeBytes { write(descriptor, $0.baseAddress, $0.count) }
        guard written == bytes.count, fsync(descriptor) == 0 else { throw FixtureError.invalidMessage }
        let directory = open(parent.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw FixtureError.invalidMessage }
        defer { close(directory) }
        guard fsync(directory) == 0 else { throw FixtureError.invalidMessage }
    }
}
