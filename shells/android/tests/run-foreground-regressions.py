#!/usr/bin/env python3
"""Execute production foreground/boot callbacks with a queued Kotlin scheduler.

Set KOTLINC and JAVA_HOME. The node and platform are doubles; lifecycle methods
and their startup ordering come from MainActivity, without Gradle or a device.
"""
import os
import pathlib
import re
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
source = (root / "app/src/main/java/zone/epix/app/MainActivity.kt").read_text()


def method(name):
    match = re.search(r"    (?:private |override )?fun " + name + r"\(.*?\n    }", source, re.S)
    assert match, name
    return match[0].replace("private fun", "fun", 1)


kotlin = r'''
import kotlin.coroutines.*

object Dispatchers { const val IO = "IO" }
object Scheduler {
    var lane = "MAIN"
    val jobs = mutableListOf<Pair<String, suspend () -> Unit>>()
    fun drain() {
        while (jobs.isNotEmpty()) {
            val (next, body) = jobs.removeAt(0)
            lane = next
            body.startCoroutine(object : Continuation<Unit> {
                override val context = EmptyCoroutineContext
                override fun resumeWith(result: Result<Unit>) { result.getOrThrow() }
            })
            lane = "MAIN"
        }
    }
}
class Scope {
    fun launch(lane: String = "MAIN", body: suspend () -> Unit) {
        Scheduler.jobs.add(lane to body)
    }
}
enum class NodeState { IDLE, STARTING, SERVING, FAILED }
class Node {
    var lifecycle = NodeState.IDLE
    var wakes = 0
    var reads = 0
    fun state(): NodeState { reads++; return lifecycle }
    fun networkChanged() {
        check(Scheduler.lane == "IO") { "foreground wake must leave the UI thread" }
        check(lifecycle == NodeState.SERVING)
        wakes++
    }
    fun lastError(): String? = "failed"
}
class Mark { fun clearAnimation() {} }
class Presentation { fun reset() {} }
enum class SplashStage { PREPARING, CONNECTING, OPENING }
class Tab { val session = Any() }
open class Activity {
    open fun onResume() {}
    open fun onPause() {}
}
class Shell : Activity() {
    val node = Node()
    val scope = Scope()
    var splashAnimationsActive = false
    var splashMark: Mark? = null
    var startupGeneration = 0
    var startupSession: Any? = null
    var startupPageUrl: String? = null
    var startupPageStarted = false
    val startupPresentation = Presentation()
    var currentDisplay = ""
    val currentTab = Tab()
    var boots = 0
    var loaded = 0
    var pendingBoot: Continuation<String?>? = null
    fun animateSplashMark() {}
    fun showSplash() {}
    fun updateSplash(stage: SplashStage) {}
    fun observeStartup(generation: Int) {}
    fun applyClearnetRouting() {}
    fun showStartupError(message: String) {}
    fun errorPage(message: String?) = "error"
    fun nodeUrl(display: String) = display
    fun loadStartupPage(session: Any, page: String) { loaded++ }
    suspend fun awaitUiPort() = true
    suspend fun bootNode(target: String): String? = suspendCoroutine { continuation ->
        boots++
        node.lifecycle = NodeState.STARTING
        pendingBoot = continuation
    }
    fun completeBoot(state: NodeState) {
        node.lifecycle = state
        val continuation = pendingBoot!!
        pendingBoot = null
        continuation.resume(if (state == NodeState.SERVING) "dashboard.epix" else null)
    }
'''
kotlin += "\n".join(method(name) for name in (
    "onResume", "onPause", "wakeNodeForForeground", "bootAndOpen"))
kotlin += r'''
}
fun main() {
    var checks = 0
    fun verify(condition: Boolean, message: String) {
        checks++
        check(condition) { message }
    }
    val warm = Shell().apply { node.lifecycle = NodeState.SERVING }
    warm.onResume()
    verify(warm.node.reads == 0 && warm.node.wakes == 0, "resume must enqueue FFI work")
    Scheduler.drain()
    verify(warm.node.wakes == 1 && warm.boots == 0, "same-network foreground wakes without boot")
    warm.onPause(); warm.onResume(); Scheduler.drain()
    verify(warm.node.wakes == 2, "a later foreground return also wakes")
    for (state in listOf(NodeState.IDLE, NodeState.STARTING, NodeState.FAILED)) {
        val shell = Shell().apply { node.lifecycle = state }
        shell.onResume(); Scheduler.drain()
        verify(shell.node.wakes == 0 && shell.boots == 0, "$state must not wake or start a node")
    }
    val cold = Shell()
    cold.bootAndOpen("dashboard.epix"); Scheduler.drain()
    cold.onResume(); Scheduler.drain()
    verify(cold.node.wakes == 0, "an early resume cannot wake a starting node")
    cold.completeBoot(NodeState.SERVING); Scheduler.drain()
    verify(cold.node.wakes == 1 && cold.loaded == 1, "successful foreground boot retains the early wake")
    val background = Shell()
    background.bootAndOpen("dashboard.epix"); Scheduler.drain()
    background.onResume(); Scheduler.drain(); background.onPause()
    background.completeBoot(NodeState.SERVING); Scheduler.drain()
    verify(background.node.wakes == 0, "background boot completion waits for foreground")
    background.onResume(); Scheduler.drain()
    verify(background.node.wakes == 1, "foreground after background boot wakes")
    val failed = Shell()
    failed.bootAndOpen("dashboard.epix"); Scheduler.drain()
    failed.onResume(); Scheduler.drain()
    failed.completeBoot(NodeState.FAILED); Scheduler.drain()
    verify(failed.node.wakes == 0, "a failed startup completion cannot wake")
    failed.bootAndOpen("dashboard.epix"); Scheduler.drain()
    failed.completeBoot(NodeState.SERVING); Scheduler.drain()
    verify(failed.node.wakes == 1 && failed.boots == 2, "successful explicit retry retains foreground wake")
    val stale = Shell()
    stale.bootAndOpen("dashboard.epix"); Scheduler.drain()
    stale.onResume(); Scheduler.drain(); stale.startupGeneration++
    stale.completeBoot(NodeState.SERVING); Scheduler.drain()
    verify(stale.node.wakes == 0 && stale.loaded == 0, "an obsolete boot cannot wake or navigate")
    println("$checks Android foreground checks passed")
}
'''
with tempfile.TemporaryDirectory(prefix="epix-android-foreground-") as directory:
    test = pathlib.Path(directory)
    (test / "ForegroundRegressions.kt").write_text(kotlin)
    subprocess.run([os.environ["KOTLINC"], str(test / "ForegroundRegressions.kt"),
                    "-no-reflect", "-include-runtime", "-d", str(test / "tests.jar")], check=True)
    raise SystemExit(subprocess.run([
        str(pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java"), "-jar", str(test / "tests.jar")]).returncode)
