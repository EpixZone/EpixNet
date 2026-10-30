import Foundation

struct GameRequest: Codable, Sendable {
    let magic: UInt32
    let version: UInt32
    let nonceHigh: UInt64
    let nonceLow: UInt64
    let level: UInt32
    let coins: UInt32

    func score() throws -> UInt32 {
        guard magic == 0x45565831, version == 1,
              nonceHigh != 0 || nonceLow != 0, level <= 100, coins <= 1000 else {
            throw FixtureError.invalidMessage
        }
        return level * 100 + coins
    }
}

struct GameReply: Codable, Sendable {
    let nonceHigh: UInt64
    let nonceLow: UInt64
    let score: UInt32
}

enum FixtureError: Error { case invalidMessage, alreadyUsed, staleReply }

/// Mutable state is exclusively protected by the lock, including all reads.
final class OneShotGame: @unchecked Sendable {
    private let lock = NSLock()
    private var consumed = false
    func calculate(_ request: GameRequest) throws -> GameReply {
        let score = try request.score()
        lock.lock(); defer { lock.unlock() }
        guard !consumed else { throw FixtureError.alreadyUsed }
        consumed = true
        return GameReply(nonceHigh: request.nonceHigh, nonceLow: request.nonceLow, score: score)
    }
}

/// Connection invalidation and a reply do not establish process death.
struct HostObservation {
    enum Phase { case new, admitted, replied, stopRequested, interrupted }
    private(set) var phase = Phase.new
    private var nonce: (UInt64, UInt64)?
    mutating func admit(_ request: GameRequest) throws {
        guard phase == .new else { throw FixtureError.alreadyUsed }
        _ = try request.score()
        nonce = (request.nonceHigh, request.nonceLow); phase = .admitted
    }
    mutating func reply(_ value: GameReply) throws {
        guard phase == .admitted, nonce?.0 == value.nonceHigh,
              nonce?.1 == value.nonceLow, value.score == 42 else { throw FixtureError.staleReply }
        phase = .replied
    }
    mutating func stopRequested() { if phase != .new && phase != .interrupted { phase = .stopRequested } }
    mutating func interruptionObserved() { if phase != .new { phase = .interrupted } }
    var productionAdmissionAllowed: Bool { false }
}
