#!/usr/bin/env python3
"""Exercise the production session result gate across queued Gecko consumers.

The engine boundary models Gecko155's map-to-virtual-then dispatch. A device
probe against the actual library checks that boundary separately.
"""
import os
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
double = r'''
package org.mozilla.geckoview
class GeckoSession
open class GeckoResult<T> {
    fun interface OnValueListener<T, U> { fun onValue(value: T?): GeckoResult<U>? }
    fun interface OnExceptionListener<U> { fun onException(error: Throwable?): GeckoResult<U>? }
    var value: T? = null
    var failure: Throwable? = null
    fun complete(value: T) { this.value = value }
    open fun <U> then(onValue: OnValueListener<T, U>?, onException: OnExceptionListener<U>?): GeckoResult<U> {
        val result = GeckoResult<U>()
        queued.add {
            try { onValue?.onValue(value) } catch (error: Throwable) {
                result.failure = error
                onException?.onException(error)
            }
        }
        return result
    }
    fun <U> map(callback: (T?) -> U): GeckoResult<U> = then(OnValueListener {
        GeckoResult<U>().also { result -> result.complete(callback(it)) }
    }, null)
    companion object {
        val queued = java.util.ArrayDeque<() -> Unit>()
        fun drain() { while (queued.isNotEmpty()) queued.removeFirst()() }
    }
}
'''
tests = r'''
package zone.epix.app
import org.mozilla.geckoview.GeckoResult
import org.mozilla.geckoview.GeckoSession
fun main() {
    val session = GeckoSession()
    var active = true
    var opens = 0
    val valid = guardedSessionResult(session) { active }.map { check(it === session); opens++ }
    check(opens == 0)
    GeckoResult.drain()
    check(opens == 1 && valid.failure == null)

    val late = guardedSessionResult(session) { active }.map { opens++ }
    active = false
    GeckoResult.drain()
    check(opens == 1 && late.failure is IllegalStateException)

    val alreadyClosed = guardedSessionResult(session) { false }.map { opens++ }
    GeckoResult.drain()
    check(opens == 1 && alreadyClosed.failure is IllegalStateException)

    var consumerFailure = false
    val failing = guardedSessionResult(session) { true }.then<Unit>(
        GeckoResult.OnValueListener { throw IllegalArgumentException("engine failure") },
        GeckoResult.OnExceptionListener { consumerFailure = it is IllegalArgumentException; null },
    )
    GeckoResult.drain()
    check(consumerFailure && failing.failure is IllegalArgumentException)
    check(GeckoResult.queued.isEmpty())
    println("Guarded session regressions: live admission, queued disposal, detached admission, and engine failure passed")
}
'''
with tempfile.TemporaryDirectory(prefix="epix-session-gate-tests-") as directory:
    temp = pathlib.Path(directory)
    (temp / "Gecko.kt").write_text(double)
    (temp / "Tests.kt").write_text(tests)
    jar = temp / "tests.jar"
    subprocess.run([
        os.environ["KOTLINC"], str(root / "app/src/main/java/zone/epix/app/GuardedSessionResult.kt"),
        str(temp / "Gecko.kt"), str(temp / "Tests.kt"), "-include-runtime", "-d", str(jar),
    ], check=True, timeout=90)
    subprocess.run([str(pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java"), "-jar", str(jar)], check=True, timeout=20)
