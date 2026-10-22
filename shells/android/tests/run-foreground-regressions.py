#!/usr/bin/env python3
"""Execute production foreground/boot callbacks using real coroutine jobs.

Set KOTLINC, JAVA_HOME, and COROUTINES_JAR (kotlinx-coroutines-core-jvm 1.9.0).
Deterministic Main/IO dispatchers expose ordering and cancellation without an
Android runtime. Native boot and views are doubles, not a second coordinator.
"""
import os
import pathlib
import re
import subprocess
import tempfile
import zipfile

root = pathlib.Path(__file__).resolve().parents[1]
source = (root / "app/src/main/java/zone/epix/app/MainActivity.kt").read_text()
coroutines = pathlib.Path(os.environ["COROUTINES_JAR"])
with zipfile.ZipFile(coroutines) as archive:
    version = archive.read("META-INF/kotlinx_coroutines_core.version").decode().strip()
if version != "1.9.0":
    raise SystemExit(f"Expected declared coroutines 1.9.0, found {version}")


def method(name):
    expression = re.findall(r"^    private fun " + re.escape(name)
                            + r"\([^\n]*\)(?:: [^=\n]+)? =\n        [^\n]+$", source, re.M)
    if len(expression) == 1:
        return expression[0].replace("private fun", "fun", 1)
    single = re.findall(r"^    private fun " + re.escape(name)
                        + r"\([^\n]*\)(?:: [^=\n]+)? = [^\n]+$", source, re.M)
    if len(single) == 1:
        return single[0].replace("private fun", "fun", 1)
    matches = re.findall(r"^    (?:private |override )?fun " + re.escape(name)
                         + r"\(.*?^    }", source, re.M | re.S)
    if len(matches) != 1:
        raise SystemExit(f"Expected one production method: {name}")
    return matches[0].replace("private fun", "fun", 1)


def declaration(name):
    matches = re.findall(r"^    private val " + re.escape(name) + r"[^\n]+$", source, re.M)
    if len(matches) != 1:
        raise SystemExit(f"Expected one production declaration: {name}")
    return matches[0].replace("private val", "val", 1)


kotlin = r'''
package zone.epix.app
import java.io.File
import java.util.ArrayDeque
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

object Scheduler {
    var lane = "MAIN"
        private set
    private val queued = ArrayDeque<Pair<String, Runnable>>()
    private fun dispatcher(name: String) = object : CoroutineDispatcher() {
        override fun dispatch(context: CoroutineContext, block: Runnable) {
            queued.addLast(name to block)
        }
    }
    val main = dispatcher("MAIN")
    val io = dispatcher("IO")
    fun drain() {
        var steps = 0
        while (queued.isNotEmpty()) {
            check(++steps < 1000) { "unexpected unbounded coroutine work" }
            val (next, body) = queued.removeFirst()
            lane = next
            try { body.run() } finally { lane = "MAIN" }
        }
    }
    val empty get() = queued.isEmpty()
}
object Dispatchers { val IO = Scheduler.io }
enum class NodeState { IDLE, STARTING, SERVING, FAILED }
class Node {
    var lifecycle = NodeState.IDLE
    var wakes = 0
    var reads = 0
    fun state(): NodeState { check(Scheduler.lane == "IO"); reads++; return lifecycle }
    fun networkChanged() {
        check(Scheduler.lane == "IO") { "foreground wake must leave the UI thread" }
        check(lifecycle == NodeState.SERVING)
        wakes++
    }
}
data class StartupRequest(val dataDir: String, val target: String, val version: String,
                          val torClearnet: Boolean, val uiPort: Int)
data class BootResult(val attemptId: Long, val state: NodeState?, val error: String?, val succeeded: Boolean)
object EmbeddedNodeHost {
    data class Pending(val request: StartupRequest, val retryOf: Long?, val resetConfig: Boolean,
                       val result: CompletableDeferred<BootResult> = CompletableDeferred())
    var node: Node? = Node()
    val requests = mutableListOf<Pending>()
    suspend fun ensureStarted(request: StartupRequest, retryOf: Long?, resetConfig: Boolean): BootResult {
        val pending = Pending(request, retryOf, resetConfig)
        requests.add(pending)
        if (node?.lifecycle != NodeState.SERVING) node?.lifecycle = NodeState.STARTING
        return pending.result.await()
    }
    fun complete(state: NodeState, succeeded: Boolean = state == NodeState.SERVING,
                 error: String? = if (succeeded) null else "failed", index: Int = requests.lastIndex) {
        node?.lifecycle = state
        requests[index].result.complete(BootResult(index.toLong() + 1, state, error, succeeded))
    }
    fun reset() {
        requests.forEach { it.result.cancel() }
        requests.clear()
        node = Node()
    }
}
object BuildConfig { const val VERSION_NAME = "test" }
class Mark { fun clearAnimation() {} }
class Presentation { fun reset() {} }
enum class SplashStage { PREPARING, CONNECTING, OPENING }
class GeckoSession {
    var opened = false
    val urls = mutableListOf<String>()
    var onLoad: ((String) -> Unit)? = null
    fun open(runtime: Any) { opened = true }
    fun loadUri(url: String) { urls.add(url); onLoad?.invoke(url) }
}
class Tab(val session: GeckoSession = GeckoSession()) { var url = "" }
class Bundle {
    val values = mutableMapOf<String, Any>()
    fun putStringArrayList(key: String, value: ArrayList<String>) { values[key] = value }
    fun putInt(key: String, value: Int) { values[key] = value }
    fun putString(key: String, value: String) { values[key] = value }
    fun putBoolean(key: String, value: Boolean) { values[key] = value }
    @Suppress("UNCHECKED_CAST")
    fun urls() = values["browser.urls"] as List<String>
    fun selected() = values["browser.selected"] as Int
}
// Only well-formed URI inputs are used here. Android URI parsing itself is
// exercised by run-url-regressions.py; this boundary preserves encoded fields.
class Uri private constructor(private val value: String) {
    private val parsed = java.net.URI(value)
    val scheme get() = parsed.scheme
    val host get() = parsed.host
    val encodedPath get() = parsed.rawPath
    val encodedQuery get() = parsed.rawQuery
    val encodedFragment get() = parsed.rawFragment
    override fun toString() = value
    companion object { fun parse(value: String) = Uri(value) }
}
class Intent(val data: Uri?)
open class Activity {
    open fun onResume() {}
    open fun onPause() {}
    open fun onNewIntent(intent: Intent) {}
    open fun onSaveInstanceState(outState: Bundle) {}
    var currentIntent: Intent? = null
    fun setIntent(intent: Intent) { currentIntent = intent }
}
class Shell : Activity() {
    val node get() = EmbeddedNodeHost.node
    val activityJob = SupervisorJob()
    val scope = CoroutineScope(activityJob + Scheduler.main)
    var disposed = false
    var splashAnimationsActive = false
    var splashMark: Mark? = null
    var startupGeneration = 0
    var startupSession: GeckoSession? = null
    var startupPageUrl: String? = null
    var startupPageStarted = false
    val startupPresentation = Presentation()
    var currentDisplay = ""
    var pendingTarget = "dashboard.epix"
    var bootResult: BootResult? = null
    var bootJob: Job? = null
    var restoredUrls: List<String>? = null
    var restoredSelection = 0
    var walletUserEngaged = false
    val tabs = mutableListOf(Tab())
    val ownedSessions = mutableSetOf<GeckoSession>()
    var currentTabIndex = 0
    val currentTab get() = tabs[currentTabIndex]
    val runtime = Any()
    val filesDir = File("fixture-node")
    var torClearnet = true
    val UI_PORT = 42222
    val NODE_BASE = "http://127.0.0.1:$UI_PORT"
    val XITE_ADDRESS = Regex("^epix1[a-z0-9]{20,}$")
    var nodeLoadRetries = 3
    var portProbes = 0
    var portReady = true
    var holdPort = false
    val portResult = CompletableDeferred<Boolean>()
    var multicastAcquisitions = 0
    var splashes = 0
    var splashOverlay: Any? = null
    val errors = mutableListOf<String>()
    val startupLoads = mutableListOf<Pair<GeckoSession, String>>()
    init { watchSession(tabs.first().session) }
    fun watchSession(session: GeckoSession) {
        ownedSessions.add(session)
        session.onLoad = { url ->
            check(Scheduler.lane == "MAIN")
            if (session === startupSession && url == startupPageUrl) startupLoads.add(session to url)
        }
    }
    fun animateSplashMark() {}
    fun showSplash() { splashes++; splashOverlay = Any() }
    fun updateSplash(stage: SplashStage) {}
    fun observeStartup(generation: Int) {}
    fun showStartupError(message: String) { errors.add(message) }
    fun errorPage(message: String?) = "error:" + (message ?: "unavailable")
    fun acquireMulticastLockIfDiscovering() {
        check(Scheduler.lane == "MAIN")
        check(!disposed)
        multicastAcquisitions++
    }
    suspend fun awaitUiPort(): Boolean {
        portProbes++
        return if (holdPort) portResult.await() else portReady
    }
    fun newTab(session: GeckoSession, select: Boolean): Tab {
        watchSession(session)
        val tab = Tab(session)
        tabs.add(tab)
        if (select) currentTabIndex = tabs.lastIndex
        return tab
    }
    fun showTab(index: Int) { currentTabIndex = index }
    fun dispose() {
        disposed = true
        startupGeneration++
        activityJob.cancel()
    }
'''
kotlin += declaration("localUiReady") + "\n"
kotlin += "\n".join(method(name) for name in (
    "onResume", "onPause", "wakeNodeForForeground", "bootAndOpen", "retryBoot", "resetConfigAndRetry",
    "onNewIntent", "intentTarget", "xiteRewrite", "nodeUrl", "onSaveInstanceState", "restorableUrl",
    "loadStartupPage", "ownsSession"))
kotlin += r'''
}
fun main() {
    var checks = 0
    fun verify(condition: Boolean, message: String) { checks++; check(condition) { message } }
    fun scenario(body: (Shell) -> Unit) {
        EmbeddedNodeHost.reset()
        val shell = Shell()
        try { body(shell) } finally {
            shell.dispose()
            Scheduler.drain()
            verify(shell.activityJob.children.none(), "fixture leaves no activity jobs")
            EmbeddedNodeHost.reset()
            Scheduler.drain()
            verify(Scheduler.empty, "fixture drains every queued continuation")
        }
    }
    scenario { warm ->
        warm.node!!.lifecycle = NodeState.SERVING
        warm.onResume()
        verify(warm.node!!.reads == 0 && warm.node!!.wakes == 0, "resume enqueues FFI work")
        Scheduler.drain()
        verify(warm.node!!.wakes == 1 && EmbeddedNodeHost.requests.isEmpty(), "same-network foreground wakes without boot")
        warm.onPause(); warm.onResume(); Scheduler.drain()
        verify(warm.node!!.wakes == 2, "later foreground return also wakes")
    }
    for (state in listOf(NodeState.IDLE, NodeState.STARTING, NodeState.FAILED)) scenario { shell ->
        shell.node!!.lifecycle = state
        shell.onResume(); Scheduler.drain()
        verify(shell.node!!.wakes == 0 && EmbeddedNodeHost.requests.isEmpty(), "$state neither wakes nor boots")
    }
    scenario { shell ->
        EmbeddedNodeHost.node = null
        shell.onResume(); Scheduler.drain()
        verify(EmbeddedNodeHost.requests.isEmpty(), "foreground before native handle creation does not create one")
    }
    scenario { cold ->
        cold.bootAndOpen("dashboard.epix"); Scheduler.drain()
        cold.onResume(); Scheduler.drain()
        verify(cold.node!!.wakes == 0, "early resume cannot wake a starting node")
        EmbeddedNodeHost.complete(NodeState.SERVING); Scheduler.drain()
        verify(cold.node!!.wakes == 1 && cold.startupLoads.size == 1, "foreground boot retains early wake and navigation")
        verify(cold.portProbes == 1 && cold.multicastAcquisitions == 1, "successful boot reaches readiness and activity lock acquisition")
        val request = EmbeddedNodeHost.requests.single().request
        verify(request.target == "dashboard.epix" && request.torClearnet && request.uiPort == 42222,
            "shared boot receives target, saved routing and expected port")
    }
    scenario { background ->
        background.bootAndOpen("dashboard.epix"); Scheduler.drain()
        background.onResume(); Scheduler.drain(); background.onPause()
        EmbeddedNodeHost.complete(NodeState.SERVING); Scheduler.drain()
        verify(background.node!!.wakes == 0, "background boot completion waits for foreground")
        background.onResume(); Scheduler.drain()
        verify(background.node!!.wakes == 1, "foreground after background boot wakes")
    }
    scenario { failed ->
        failed.bootAndOpen("dashboard.epix"); Scheduler.drain()
        failed.onResume(); Scheduler.drain()
        EmbeddedNodeHost.complete(NodeState.FAILED); Scheduler.drain()
        verify(failed.node!!.wakes == 0 && failed.portProbes == 0 && failed.multicastAcquisitions == 0,
            "failed boot neither wakes, probes a port nor acquires multicast")
        verify(failed.errors.single() == "failed" && failed.startupLoads.single().second == "error:failed",
            "failed boot loads only its recovery page")
        val observed = failed.bootResult!!.attemptId
        failed.retryBoot(); Scheduler.drain()
        verify(EmbeddedNodeHost.requests.last().retryOf == observed && !EmbeddedNodeHost.requests.last().resetConfig,
            "explicit retry names the failure observed by this Activity")
        EmbeddedNodeHost.complete(NodeState.SERVING); Scheduler.drain()
        verify(failed.node!!.wakes == 1 && EmbeddedNodeHost.requests.size == 2, "successful retry retains foreground wake")
    }
    scenario { mismatch ->
        mismatch.bootAndOpen("dashboard.epix"); Scheduler.drain()
        mismatch.onResume(); Scheduler.drain()
        EmbeddedNodeHost.complete(NodeState.SERVING, succeeded = false, error = "wrong local origin")
        Scheduler.drain()
        verify(mismatch.portProbes == 0 && mismatch.multicastAcquisitions == 0 && mismatch.node!!.wakes == 0,
            "serving node with failed origin validation must not probe or load the assumed port")
        verify(mismatch.startupLoads.single().second == "error:wrong local origin", "origin failure is explicit recovery UI")
    }
    scenario { reset ->
        reset.bootAndOpen("dashboard.epix"); Scheduler.drain()
        EmbeddedNodeHost.complete(NodeState.FAILED); Scheduler.drain()
        val observed = reset.bootResult!!.attemptId
        reset.resetConfigAndRetry(); Scheduler.drain()
        verify(EmbeddedNodeHost.requests.last().retryOf == observed && EmbeddedNodeHost.requests.last().resetConfig,
            "reset request carries the exact failed attempt to the process coordinator")
    }
    scenario { stale ->
        stale.bootAndOpen("dashboard.epix"); Scheduler.drain()
        stale.onResume(); Scheduler.drain(); stale.startupGeneration++
        EmbeddedNodeHost.complete(NodeState.SERVING); Scheduler.drain()
        verify(stale.node!!.wakes == 0 && stale.startupLoads.isEmpty() && stale.portProbes == 0 && stale.multicastAcquisitions == 0,
            "obsolete boot cannot wake, acquire, probe or navigate")
    }
    scenario { disposed ->
        disposed.bootAndOpen("dashboard.epix"); Scheduler.drain()
        disposed.disposed = true // Keep waiter live to exercise the explicit late-result guard.
        EmbeddedNodeHost.complete(NodeState.SERVING); Scheduler.drain()
        verify(disposed.startupLoads.isEmpty() && disposed.portProbes == 0 && disposed.multicastAcquisitions == 0,
            "late completion cannot mutate disposed UI even without cancellation")
    }
    scenario { cancelled ->
        cancelled.bootAndOpen("dashboard.epix"); Scheduler.drain()
        val processResult = EmbeddedNodeHost.requests.single().result
        cancelled.dispose(); Scheduler.drain()
        verify(processResult.isActive, "cancelling Activity waiter does not cancel process-owned completion")
        EmbeddedNodeHost.complete(NodeState.SERVING); Scheduler.drain()
        verify(cancelled.startupLoads.isEmpty() && cancelled.portProbes == 0, "cancelled waiter does not resume UI work")
    }
    scenario { queued ->
        queued.node!!.lifecycle = NodeState.SERVING
        queued.onResume(); queued.dispose(); Scheduler.drain()
        verify(queued.node!!.reads == 0 && queued.node!!.wakes == 0, "disposing cancels an IO wake queued before execution")
        queued.wakeNodeForForeground(); queued.bootAndOpen("new.epix"); queued.retryBoot(); Scheduler.drain()
        verify(EmbeddedNodeHost.requests.isEmpty() && queued.splashes == 0, "disposed direct calls cannot schedule startup")
    }
    for (dispose in listOf(false, true)) scenario { waiting ->
        waiting.holdPort = true
        waiting.bootAndOpen("dashboard.epix"); Scheduler.drain()
        EmbeddedNodeHost.complete(NodeState.SERVING); Scheduler.drain()
        verify(waiting.portProbes == 1 && waiting.startupLoads.isEmpty(), "page waits for UI readiness")
        if (dispose) waiting.disposed = true else waiting.startupGeneration++
        waiting.portResult.complete(true); Scheduler.drain()
        verify(waiting.startupLoads.isEmpty(), "late readiness cannot navigate after disposal or generation change")
    }
    scenario { unavailable ->
        unavailable.portReady = false
        unavailable.bootAndOpen("dashboard.epix"); Scheduler.drain()
        EmbeddedNodeHost.complete(NodeState.SERVING); Scheduler.drain()
        verify(unavailable.portProbes == 1 && unavailable.startupLoads.single().second == "error:unavailable",
            "readiness failure loads recovery instead of the node page")
    }
    scenario { restored ->
        val urls = listOf("http://127.0.0.1:42222/site.epix/%E2%9C%93?q=a%2Fb#part", "https://example.test/path?a=1#two")
        restored.restoredUrls = urls; restored.restoredSelection = 1
        restored.bootAndOpen("dashboard.epix"); Scheduler.drain()
        EmbeddedNodeHost.complete(NodeState.SERVING); Scheduler.drain()
        verify(restored.tabs.map { it.session.urls.single() } == urls, "restored URL data preserves path, query and fragment")
        verify(restored.currentTabIndex == 1 && restored.startupLoads.single().first === restored.currentTab.session,
            "selected restored tab owns startup completion")
        verify(restored.restoredUrls == null && restored.tabs[1].session.opened, "restoration is consumed once using a new open session")
        val immediateSave = Bundle()
        restored.onSaveInstanceState(immediateSave)
        verify(immediateSave.urls() == urls && immediateSave.selected() == 1,
            "save immediately after restored loads preserves all URLs and selection before location callbacks")
    }
    scenario { target ->
        target.bootAndOpen("old.epix"); Scheduler.drain()
        target.pendingTarget = "latest.epix/path?q=value#part"
        EmbeddedNodeHost.complete(NodeState.SERVING); Scheduler.drain()
        verify(target.startupLoads.single().second == target.nodeUrl(target.pendingTarget), "latest queued target wins at boot completion")
    }
    val encodedTarget = "talk.epix/%E2%9C%93/a%20b?q=a%2Fb#part%20two"
    val encodedIntent = Intent(Uri.parse("epix://$encodedTarget"))
    val encodedUrl = "http://127.0.0.1:42222/$encodedTarget"
    val restoredUrls = listOf(encodedUrl, "https://example.test/a%20b?first=x%2Fy#second")
    var pendingState: Bundle? = null
    repeat(3) { generation -> scenario { restored ->
        restored.restoredUrls = pendingState?.urls() ?: restoredUrls
        restored.restoredSelection = pendingState?.selected() ?: 1
        restored.walletUserEngaged = true
        restored.bootAndOpen("dashboard.epix"); Scheduler.drain()
        verify(restored.tabs.single().url.isEmpty() && restored.startupLoads.isEmpty(),
            "recreation $generation is saved while boot and tab location are pending")
        val saved = Bundle()
        restored.onSaveInstanceState(saved)
        verify(saved.urls() == restoredUrls && saved.selected() == 1,
            "recreation $generation preserves pending restored URLs and selection")
        verify(saved.values["browser.target"] == "dashboard.epix" && saved.values["wallet.engaged"] == true,
            "saved state preserves target and wallet engagement while boot waits")
        pendingState = saved
    } }
    scenario { restored ->
        val savedPending = checkNotNull(pendingState)
        restored.restoredUrls = savedPending.urls()
        restored.restoredSelection = savedPending.selected()
        restored.bootAndOpen("dashboard.epix"); Scheduler.drain()
        EmbeddedNodeHost.complete(NodeState.SERVING); Scheduler.drain()
        val saved = Bundle()
        restored.onSaveInstanceState(saved)
        verify(saved.urls() == restoredUrls && saved.selected() == 1 && restored.currentTabIndex == 1,
            "eventual boot after repeated recreation restores both encoded links and selected tab")
    }
    scenario { early ->
        early.bootAndOpen("old.epix"); Scheduler.drain()
        early.restoredUrls = listOf("https://old.example.test/")
        val previousJob = early.bootJob!!
        val processResult = EmbeddedNodeHost.requests.single().result
        early.onNewIntent(encodedIntent); Scheduler.drain()
        verify(previousJob.isCancelled && processResult.isActive,
            "second intent cancels only the replaced Activity waiter")
        verify(early.currentIntent === encodedIntent && early.pendingTarget == encodedTarget && early.restoredUrls == null,
            "second intent becomes saved target and supersedes restored tabs")
        EmbeddedNodeHost.complete(NodeState.SERVING, index = 0); Scheduler.drain()
        verify(early.portProbes == 0 && early.startupLoads.isEmpty(),
            "cancelled first waiter cannot probe or navigate on late completion")
        EmbeddedNodeHost.complete(NodeState.SERVING, index = 1); Scheduler.drain()
        verify(early.portProbes == 1 && early.startupLoads.single().second == encodedUrl,
            "intent before boot completes preserves encoded path, query and fragment")
        val saved = Bundle()
        early.onSaveInstanceState(saved)
        verify(saved.urls() == listOf(encodedUrl) && saved.selected() == 0,
            "explicit new intent supersedes saved tabs even before its location callback")
        verify(saved.values["browser.target"] == encodedTarget,
            "explicit intent becomes the saved target for another recreation")
    }
    scenario { waiting ->
        waiting.holdPort = true
        waiting.bootAndOpen("old.epix"); Scheduler.drain()
        EmbeddedNodeHost.complete(NodeState.SERVING); Scheduler.drain()
        val previousJob = waiting.bootJob!!
        waiting.onNewIntent(encodedIntent); Scheduler.drain()
        verify(previousJob.isCancelled && waiting.portResult.isActive,
            "new intent cancels obsolete port waiter without cancelling readiness source")
        EmbeddedNodeHost.complete(NodeState.SERVING); Scheduler.drain()
        waiting.portResult.complete(true); Scheduler.drain()
        verify(waiting.startupLoads.single().second == encodedUrl,
            "new intent while port probe is pending produces only latest navigation")
    }
    scenario { page ->
        page.bootAndOpen("old.epix"); Scheduler.drain()
        EmbeddedNodeHost.complete(NodeState.SERVING); Scheduler.drain()
        verify(page.localUiReady && page.splashOverlay != null && page.startupLoads.size == 1,
            "native ready while page completion is pending retains splash")
        page.onNewIntent(encodedIntent); Scheduler.drain()
        EmbeddedNodeHost.complete(NodeState.SERVING); Scheduler.drain()
        verify(page.startupLoads.map { it.second } == listOf(page.nodeUrl("old.epix"), encodedUrl),
            "second intent while first page loads replaces startup navigation")
        verify(page.currentDisplay == encodedTarget, "latest full target remains visible after shared startup returns")
    }
    scenario { ready ->
        ready.bootAndOpen("old.epix"); Scheduler.drain()
        EmbeddedNodeHost.complete(NodeState.SERVING); Scheduler.drain()
        ready.splashOverlay = null
        val calls = EmbeddedNodeHost.requests.size
        val probes = ready.portProbes
        ready.onNewIntent(encodedIntent); Scheduler.drain()
        verify(EmbeddedNodeHost.requests.size == calls && ready.portProbes == probes,
            "ready new intent navigates directly without a startup or readiness repeat")
        verify(ready.currentTab.session.urls.last() == encodedUrl && ready.currentIntent === encodedIntent,
            "ready intent preserves the complete encoded link and Activity intent")
    }
    scenario { rejected ->
        rejected.bootAndOpen("old.epix"); Scheduler.drain()
        EmbeddedNodeHost.complete(NodeState.SERVING, succeeded = false, error = "wrong local origin"); Scheduler.drain()
        rejected.splashOverlay = null
        rejected.onNewIntent(encodedIntent); Scheduler.drain()
        verify(!rejected.localUiReady && rejected.portProbes == 0 && rejected.currentTab.session.urls.size == 1,
            "failed origin cannot navigate directly through a new intent")
        EmbeddedNodeHost.complete(NodeState.SERVING, succeeded = false, error = "wrong local origin"); Scheduler.drain()
        verify(rejected.portProbes == 0 && rejected.currentTab.session.urls.all { it == "error:wrong local origin" },
            "repeated origin failure still neither probes nor loads a local node URL")
    }
    scenario { inactive ->
        inactive.onNewIntent(Intent(Uri.parse("https://example.test/ignored?q=1#part")))
        inactive.onNewIntent(Intent(null)); Scheduler.drain()
        verify(inactive.pendingTarget == "dashboard.epix" && EmbeddedNodeHost.requests.isEmpty(),
            "missing and non-Epix intent data do not start the node")
        inactive.dispose()
        inactive.onNewIntent(encodedIntent); Scheduler.drain()
        verify(!inactive.localUiReady && inactive.pendingTarget == "dashboard.epix" && EmbeddedNodeHost.requests.isEmpty(),
            "disposed Activity ignores valid navigation intents")
    }
    scenario { filtered ->
        filtered.currentTab.url = "data:text/html;base64,recovery"
        filtered.newTab(GeckoSession(), select = true).url = encodedUrl
        filtered.newTab(GeckoSession(), select = false).url = "about:blank"
        val saved = Bundle()
        filtered.onSaveInstanceState(saved)
        verify(saved.urls() == listOf(encodedUrl) && saved.selected() == 0,
            "saved selection follows filtered tabs without persisting recovery or blank pages")
        filtered.showTab(0)
        val recoverySelected = Bundle()
        filtered.onSaveInstanceState(recoverySelected)
        verify(recoverySelected.selected() == 0, "excluded selected recovery page falls back to first saved tab")
    }
    println("$checks Android foreground/lifetime checks passed with real coroutines 1.9.0")
}
'''
with tempfile.TemporaryDirectory(prefix="epix-android-foreground-") as directory:
    test = pathlib.Path(directory)
    (test / "ForegroundRegressions.kt").write_text(kotlin)
    jar = test / "tests.jar"
    subprocess.run([
        os.environ["KOTLINC"], str(test / "ForegroundRegressions.kt"),
        "-cp", str(coroutines), "-no-reflect", "-include-runtime", "-d", str(jar),
    ], check=True, timeout=120)
    subprocess.run([
        str(pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java"),
        "-cp", os.pathsep.join((str(jar), str(coroutines))), "zone.epix.app.ForegroundRegressionsKt",
    ], check=True, timeout=20)
