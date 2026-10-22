#!/usr/bin/env python3
"""Execute the actual startup callbacks with Kotlin session/view test doubles.

Set KOTLINC, JAVA_HOME and COROUTINES_JAR (coroutines 1.9.0). This checks
navigation ownership and startup state; native rendering and GeckoView are
exercised separately in an emulator.
"""
import os
import pathlib
import re
import subprocess
import sys
import tempfile


root = pathlib.Path(__file__).resolve().parents[1]
source = (root / "app/src/main/java/zone/epix/app/MainActivity.kt").read_text()


def callback(name):
    matches = re.findall(r"            override fun " + name + r"\([^\n]*\) \{.*?\n            }", source, re.S)
    if len(matches) != 1:
        raise SystemExit(f"Expected one production callback: {name}")
    return matches[0].replace("override fun", "fun", 1)


ownership = re.search(r"^    private fun ownsSession\([^\n]+$", source, re.M)
if ownership is None:
    raise SystemExit("Missing production session ownership check")


kotlin = r'''
package zone.epix.app
class GeckoSession
internal class Shell {
    var disposed = false
    val ownedSessions = mutableSetOf<GeckoSession>()
    var nodeLoadRetries = 2
    var nodePageRequested = true
    var startupSession: GeckoSession? = null
    var startupPageUrl: String? = null
    var startupPageStarted = false
    var hidden = false
    val startupPresentation = StartupPresentation()
    fun hideSplash() { hidden = true }
    fun updateSplash(stage: SplashStage) { startupPresentation.advance(stage) }
'''
kotlin += ownership[0].replace("private fun", "fun", 1) + "\n"
kotlin += callback("onPageStart") + "\n" + callback("onPageStop")
kotlin += r'''
}
fun main() {
    var failures = 0
    fun verify(condition: Boolean, message: String) {
        if (!condition) { failures++; println("FAIL: $message") }
    }
    val requested = GeckoSession()
    val background = GeckoSession()
    fun fixture() = Shell().apply {
        ownedSessions.addAll(listOf(requested, background))
        startupSession = requested
        startupPageUrl = "http://127.0.0.1:42222/dashboard.epix/"
    }
    val otherTab = fixture().apply { startupPageStarted = true }
    otherTab.onPageStop(background, true)
    verify(!otherTab.hidden, "another tab cannot finish startup")
    val initialBlank = fixture()
    initialBlank.onPageStart(requested, "about:blank")
    initialBlank.onPageStop(requested, true)
    verify(!initialBlank.hidden, "initial about:blank cannot finish a requested page before it starts")
    val retrying = fixture().apply { startupPageStarted = true }
    retrying.onPageStop(requested, false)
    verify(!retrying.hidden, "a failed load awaiting automatic retry cannot finish startup")
    val ready = fixture().apply { startupPageStarted = true }
    ready.onPageStop(requested, true)
    verify(ready.hidden, "the requested loaded page finishes startup")
    verify(ready.nodeLoadRetries == 0, "successful loads reset the connection retry budget")
    verify(ready.startupSession == null && !ready.startupPageStarted,
        "completed startup releases its session completion gate")
    verify(ready.startupPresentation.completed == ready.startupPresentation.total,
        "completion reaches the final real startup milestone")
    val started = fixture()
    started.onPageStart(background, started.startupPageUrl!!)
    verify(!started.startupPageStarted, "page-start ownership also excludes other sessions")
    started.onPageStart(requested, started.startupPageUrl!!)
    verify(started.startupPageStarted, "the requested document starts its own completion gate")
    val disposed = fixture().apply { disposed = true }
    disposed.onPageStart(requested, disposed.startupPageUrl!!)
    disposed.onPageStop(requested, true)
    verify(!disposed.startupPageStarted && !disposed.hidden && disposed.nodeLoadRetries == 2,
        "queued progress callbacks cannot mutate a disposed Activity")
    val closed = fixture().apply { ownedSessions.remove(requested) }
    closed.onPageStart(requested, closed.startupPageUrl!!)
    closed.onPageStop(requested, true)
    verify(!closed.startupPageStarted && !closed.hidden && closed.nodeLoadRetries == 2,
        "a closed session cannot change startup or the retry budget")
    val recovery = fixture().apply {
        startupPresentation.advance(SplashStage.CONNECTING)
        startupPresentation.fail("Could not open the data folder.")
        startupPageUrl = "data:text/html;base64,recovery"
    }
    recovery.onPageStart(requested, recovery.startupPageUrl!!)
    recovery.onPageStop(requested, true)
    verify(recovery.hidden, "the loaded recovery page replaces the failed splash")
    verify(recovery.startupPresentation.completed < recovery.startupPresentation.total,
        "showing an error page is not successful startup")
    val progress = StartupPresentation()
    progress.advance(SplashStage.DATABASES)
    repeat(100) { progress.advance(SplashStage.DATABASES) }
    verify(progress.completed == SplashStage.DATABASES.ordinal, "polling does not invent progress")
    progress.advance(SplashStage.SETTINGS)
    verify(progress.stage == SplashStage.DATABASES, "late stage snapshots cannot move backwards")
    progress.fail("Settings are unavailable.")
    progress.advance(SplashStage.READY)
    verify(progress.failed && progress.detail == "Settings are unavailable.", "late progress preserves failure")
    progress.reset()
    verify(!progress.failed && progress.completed == 0, "a new attempt starts at zero")
    println("$failures Android startup regression failure(s)")
    check(failures == 0)
}
'''
with tempfile.TemporaryDirectory(prefix="epix-android-startup-tests-") as directory:
    test = pathlib.Path(directory)
    (test / "StartupRegressions.kt").write_text(kotlin)
    subprocess.run([os.environ["KOTLINC"], str(test / "StartupRegressions.kt"),
                    str(root / "app/src/main/java/zone/epix/app/StartupPresentation.kt"),
                    "-no-reflect", "-include-runtime", "-d", str(test / "tests.jar")], check=True, timeout=120)
    result = subprocess.run([str(pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java"),
                             "-jar", str(test / "tests.jar")], timeout=20)
    result.check_returncode()
    raise SystemExit(subprocess.run([
        sys.executable, str(root / "tests/run-foreground-regressions.py")]).returncode)
