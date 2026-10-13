import Foundation
import Dispatch

var checks = 0
@MainActor func check(_ condition: Bool) { checks += 1; precondition(condition) }
@MainActor func refuses(_ operation: () throws -> Void) {
    do { try operation(); preconditionFailure("expected refusal") } catch { checks += 1 }
}
func request(_ high: UInt64 = 1, _ coins: UInt32 = 42, level: UInt32 = 0) -> GameRequest {
    GameRequest(magic: 0x45565831, version: 1, nonceHigh: high, nonceLow: 0, level: level, coins: coins)
}
check(try request().score() == 42)
check(try request(1, 1000, level: 100).score() == 11000)
refuses { _ = try request(0).score() }
refuses { _ = try GameRequest(magic: 0, version: 1, nonceHigh: 1, nonceLow: 1, level: 0, coins: 42).score() }
refuses { _ = try GameRequest(magic: 0x45565831, version: 2, nonceHigh: 1, nonceLow: 1, level: 0, coins: 42).score() }
refuses { _ = try request(1, 1001).score() }
refuses { _ = try request(1, 1, level: UInt32.max).score() }
let game = OneShotGame()
let reply = try game.calculate(request())
check(reply.score == 42)
refuses { _ = try game.calculate(request()) }
var host = HostObservation()
refuses { try host.reply(reply) }
try host.admit(request())
refuses { try host.admit(request()) }
refuses { try host.reply(GameReply(nonceHigh: 2, nonceLow: 0, score: 42)) }
try host.reply(reply)
check(host.phase == .replied)
refuses { try host.reply(reply) }
host.stopRequested(); check(host.phase == .stopRequested)
check(!host.productionAdmissionAllowed)
host.interruptionObserved(); check(host.phase == .interrupted)
check(!host.productionAdmissionAllowed)
var expired = HostObservation(); try expired.admit(request()); expired.stopRequested()
refuses { try expired.reply(reply) }
final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func increment() { lock.lock(); count += 1; lock.unlock() }
    func value() -> Int { lock.lock(); defer { lock.unlock() }; return count }
}
let concurrentGame = OneShotGame()
let successes = Counter()
DispatchQueue.concurrentPerform(iterations: 32) { index in
    if (try? concurrentGame.calculate(request(UInt64(index + 1)))) != nil { successes.increment() }
}
check(successes.value() == 1)
print("PASS \(checks) protocol/lifecycle assertions; no iOS execution claim")
