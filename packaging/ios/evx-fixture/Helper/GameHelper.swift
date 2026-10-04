import ExtensionFoundation
import Foundation
import XPC

@main
struct GameHelper: AppExtension {
    @AppExtensionPoint.Bind
    var boundExtensionPoint: AppExtensionPoint {
        AppExtensionPoint.Identifier(host: "zone.epix.evxfixture", name: "evxGameFixture")
    }
    var configuration: some AppExtensionConfiguration {
        ConnectionHandler(onSessionRequest: { request in
            guard FixtureConnection.claim() else { return request.reject(reason: "one connection per fixture process") }
            return request.accept { _ in GameHandler() }
        })
    }
}

private enum FixtureConnection {
    static let gate = OneShotGame()
    static func claim() -> Bool {
        (try? gate.calculate(GameRequest(magic: 0x45565831, version: 1, nonceHigh: 1, nonceLow: 1, level: 0, coins: 0))) != nil
    }
}

private struct GameHandler: XPCPeerHandler, Sendable {
    private let game = OneShotGame()
    func handleIncomingRequest(_ input: GameRequest) -> (any Encodable)? {
        try? game.calculate(input)
    }
}
