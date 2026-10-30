package zone.epix.app

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.io.File
import java.util.ArrayDeque
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.resume
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Delay
import kotlinx.coroutines.DisposableHandle
import kotlinx.coroutines.InternalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Real coroutine scheduling and cancellation, with all time controlled by tests. */
@OptIn(InternalCoroutinesApi::class)
internal object Scheduler {
    private data class Work(val lane: String, val action: () -> Unit)
    private class Timer(val due: Long, val action: () -> Unit)
    private val work = ArrayDeque<Work>()
    private val timers = mutableListOf<Timer>()
    var lane = "MAIN"
        private set
    var now = 0L
        private set
    private fun dispatcher(name: String): CoroutineDispatcher = object : CoroutineDispatcher(), Delay {
        override fun dispatch(context: CoroutineContext, block: Runnable) {
            work.addLast(Work(name, block::run))
        }
        override fun scheduleResumeAfterDelay(timeMillis: Long, continuation: CancellableContinuation<Unit>) {
            val timer = Timer(now + timeMillis) { continuation.resume(Unit) }
            timers.add(timer)
            continuation.invokeOnCancellation { timers.remove(timer) }
        }
        override fun invokeOnTimeout(timeMillis: Long, block: Runnable, context: CoroutineContext): DisposableHandle {
            val timer = Timer(now + timeMillis, block::run)
            timers.add(timer)
            return object : DisposableHandle { override fun dispose() { timers.remove(timer) } }
        }
    }
    val main = dispatcher("MAIN")
    val io = dispatcher("IO")
    fun postMain(action: () -> Unit) { work.addLast(Work("MAIN", action)) }
    fun runOne(): Boolean {
        val next = work.pollFirst() ?: return false
        lane = next.lane
        try { next.action() } finally { lane = "MAIN" }
        return true
    }
    fun drain() {
        var steps = 0
        while (work.isNotEmpty()) {
            check(++steps <= 1000) { "unbounded immediate coroutine work" }
            runOne()
        }
    }
    fun advanceBy(milliseconds: Long) {
        check(milliseconds >= 0)
        val target = now + milliseconds
        var steps = 0
        while (true) {
            val next = timers.minByOrNull { it.due } ?: break
            if (next.due > target) break
            check(++steps <= 1000) { "unbounded virtual timer work" }
            now = next.due
            timers.remove(next)
            next.action()
            drain()
        }
        now = target
        drain()
    }
    val queued get() = work.size
    val delayed get() = timers.size
}
internal object Dispatchers { val Main = Scheduler.main; val IO = Scheduler.io }
internal object Context { const val CONNECTIVITY_SERVICE = "connectivity" }
internal class Node {
    var calls = 0
    fun networkChanged() { check(Scheduler.lane == "IO"); calls++ }
}
internal class Mark { var clears = 0; fun clearAnimation() { clears++ } }
internal class Overlay {
    var cancels = 0
    fun animate() = this
    fun cancel() { cancels++ }
}
internal class Badge { var updates = 0; fun setColor(color: Int) { updates++ } }
internal class Lock { var releases = 0; fun release() { releases++ } }
internal class GeckoResult<T> {
    var completions = 0
    var failure: Throwable? = null
    fun complete(value: T) { check(++completions == 1) { "result completed more than once" } }
    fun completeExceptionally(error: Throwable) {
        check(++completions == 1) { "result completed more than once" }
        failure = error
    }
}
internal class GeckoSession {
    var navigationDelegate: Any? = Any()
    var progressDelegate: Any? = Any()
    var contentDelegate: Any? = Any()
    var promptDelegate: Any? = Any()
    var permissionDelegate: Any? = Any()
    val webExtensionController = ExtensionController()
    var closes = 0
    val isOpen get() = closes == 0
    fun close() { check(++closes == 1) { "session closed more than once" } }
    class ExtensionController {
        var cleared = 0
        fun setTabDelegate(extension: Any, delegate: Any?) { check(delegate == null); cleared++ }
    }
    class PromptDelegate {
        open class BasePrompt {
            var isComplete = false
            var dismissals = 0
            fun dismiss(): PromptResponse {
                check(!isComplete)
                isComplete = true
                dismissals++
                return PromptResponse()
            }
        }
        class FilePrompt : BasePrompt()
        class PromptResponse
    }
    class PermissionDelegate {
        class Callback { var rejections = 0; fun reject() { check(++rejections == 1) } }
    }
}
internal class GeckoView(var session: GeckoSession? = null) {
    var releases = 0
    fun releaseSession() { check(session != null); session = null; releases++ }
}
internal class AlertDialog {
    private var listener: (() -> Unit)? = null
    var showing = false
    var dismissals = 0
    fun setOnDismissListener(action: () -> Unit) { listener = action }
    fun show() { showing = true }
    fun dismiss() {
        if (!showing) return
        showing = false
        dismissals++
        listener?.invoke()
    }
}
internal class Tab(val session: GeckoSession)
internal object EmbeddedBrowserHost {
    val detached = mutableListOf<Long>()
    fun detach(token: Long) { detached.add(token) }
}
internal object VerifiedAddonManager {
    val detached = mutableListOf<Long>()
    val unbound = mutableListOf<GeckoSession>()
    fun detach(token: Long) { detached.add(token) }
    fun unbindSession(session: GeckoSession) { unbound.add(session) }
}
internal object FileDisposal {
    val paths = mutableListOf<File>()
}
internal fun discardPickedFiles(path: File) { FileDisposal.paths.add(path) }
internal open class Activity {
    var baseDestroyCalls = 0
    open fun onDestroy() { baseDestroyCalls++ }
}

internal class Shell(private val manager: ConnectivityManager?) : Activity() {
    private fun leaveFullScreen(session: GeckoSession) {}
    val node = Node()
    private var disposed = false
    private var connectivityRegistration: Pair<ConnectivityManager, ConnectivityManager.NetworkCallback>? = null
    private var browserAttachment: Long? = null
    private var addonAttachment: Long? = null
    private var addonDialogContent: Any? = null
    private var addonDialog: AlertDialog? = null
    private val addonPopups = mutableMapOf<String, AlertDialog>()
    private val ownedSessions = mutableSetOf<GeckoSession>()
    private val popupViews = mutableMapOf<GeckoSession, GeckoView>()
    private val dialogs = mutableMapOf<AlertDialog, GeckoSession?>()
    private val pendingOperations = PendingOperations()
    private val promptOperations = mutableMapOf<GeckoSession.PromptDelegate.BasePrompt, PendingOperations.Operation>()
    private var pendingGeckoPermission: GeckoSession.PermissionDelegate.Callback? = null
    private var permissionSession: GeckoSession? = null
    private var permissionRequestCode: Int? = null
    private var pendingFilePrompt: GeckoSession.PromptDelegate.FilePrompt? = null
    private var pendingFileResult: GeckoResult<GeckoSession.PromptDelegate.PromptResponse>? = null
    private var pendingFileCopyJob: Job? = null
    private var fileRequestCode: Int? = null
    private val pickedDirectories = mutableSetOf<File>()
    private val tabs = mutableListOf<Tab>()
    private var wallet: Any? = null
    private var walletDialog: AlertDialog? = null
    private lateinit var geckoView: GeckoView
    private var multicastLock: Lock? = null
    private var startupGeneration = 0
    private var startupSession: GeckoSession? = null
    private var startupProgressJob: Job? = null
    private var splashAnimationsActive = true
    private var splashMark: Mark? = null
    private var splashOverlay: Overlay? = null
    private var splashStatus: Any? = Any()
    private var splashDetail: Any? = Any()
    private var splashProgress: Any? = Any()
    private var splashProgressLabel: Any? = Any()
    private val torBadge = Badge()
    private var networkOnline = true
    var refreshes = 0
        private set
    var polls = 0
        private set
    var holdTor = false
    val torResult = CompletableDeferred<Int>()
    val bootResult = CompletableDeferred<Unit>()
    val fileCopyResult = CompletableDeferred<Unit>()
    var bootTouches = 0
    var fileCopyTouches = 0
    var replyCancellations = 0
    var lateReplyCompletions = 0
    val sessions = mutableListOf<GeckoSession>()
    val views = mutableListOf<GeckoView>()
    val shownDialogs = mutableListOf<AlertDialog>()
    val replies = mutableListOf<GeckoResult<GeckoSession.PromptDelegate.PromptResponse>>()
    val prompts = mutableListOf<GeckoSession.PromptDelegate.BasePrompt>()
    val operations = mutableListOf<PendingOperations.Operation>()
    val permission = GeckoSession.PermissionDelegate.Callback()
    val mark = Mark()
    val overlay = Overlay()
    val lock = Lock()
    private val jobSnapshots = mutableListOf<Job>()

// INSERT_PRODUCTION_DECLARATIONS

    fun getSystemService(name: String): Any? { check(name == Context.CONNECTIVITY_SERVICE); return manager }
    fun runOnUiThread(action: () -> Unit) { Scheduler.postMain(action) }
    fun refreshOfflineBanner() { check(Scheduler.lane == "MAIN"); refreshes++ }
    suspend fun torStatus(): Int? { polls++; return if (holdTor) torResult.await() else 1 }
    fun colorFor(status: Int) = status
    fun start() {
        watchConnectivity()
// INSERT_PRODUCTION_TOR_POLLER
    }
    fun populate(id: Long) {
        browserAttachment = id
        addonAttachment = id
        addonDialogContent = Any()
        wallet = Any()
        val main = GeckoSession()
        val popup = GeckoSession()
        sessions.addAll(listOf(main, popup))
        ownedSessions.addAll(sessions)
        tabs.add(Tab(main))
        geckoView = GeckoView(main)
        val popupView = GeckoView(popup)
        views.addAll(listOf(geckoView, popupView))
        popupViews[popup] = popupView
        startupSession = main
        splashMark = mark
        splashOverlay = overlay
        multicastLock = lock
        pendingGeckoPermission = permission
        permissionSession = popup
        permissionRequestCode = 41
        pickedDirectories.add(File("fixture-picked-$id"))
        val ordinary = AlertDialog()
        val popupDialog = AlertDialog()
        shownDialogs.addAll(listOf(ordinary, popupDialog))
        showOwnedDialog(ordinary)
        showOwnedDialog(popupDialog, popup) { disposeSession(popup) }
        walletDialog = popupDialog
        val generic = GeckoSession.PromptDelegate.BasePrompt()
        val file = GeckoSession.PromptDelegate.FilePrompt()
        for (prompt in listOf(generic, file)) {
            val result = GeckoResult<GeckoSession.PromptDelegate.PromptResponse>()
            registerPrompt(main, prompt, result)
            prompts.add(prompt)
            replies.add(result)
        }
        pendingFilePrompt = file
        pendingFileResult = replies.last()
        fileRequestCode = 42
        operations.add(pendingOperations.register { replyCancellations++ })
        operations.add(pendingOperations.register(popup) { replyCancellations++ })
        startupProgressJob = scope.launch { while (true) delay(250) }
        scope.launch { bootResult.await(); bootTouches++ }
    }
    fun snapshotJobs() { jobSnapshots.addAll(activityJob.children.toList()) }
    fun startFileCopy(): Job = scope.launch {
        fileCopyResult.await()
        fileCopyTouches++
    }.also { pendingFileCopyJob = it }
    fun closePickerOwner() { disposeSession(sessions.first()) }
    fun dismissPicker() { dismissFilePrompt() }
    val pickerCleared get() = pendingFilePrompt == null && pendingFileResult == null &&
        fileRequestCode == null && pendingFileCopyJob == null
    fun lateReply() { operations.forEach { it.complete { lateReplyCompletions++ } } }
    fun lateRegistration(): PendingOperations.Operation = pendingOperations.register { replyCancellations++ }
    fun assertClean(verify: (Boolean, String) -> Unit) {
        verify(disposed && connectivityRegistration == null && browserAttachment == null && addonAttachment == null, "destroy drops registrations and attachment")
        verify(addonDialogContent == null && addonDialog == null && addonPopups.isEmpty(), "extension UI references are cleared")
        verify(activityJob.isCompleted && activityJob.children.none(), "real Activity job is completed without children")
        verify(ownedSessions.isEmpty() && popupViews.isEmpty() && tabs.isEmpty(), "all Activity session collections are empty")
        verify(sessions.none { it.isOpen } && sessions.all { it.closes == 1 }, "all open sessions close exactly once")
        verify(views.all { it.session == null && it.releases == 1 }, "main and popup views release sessions exactly once")
        verify(sessions.all { it.navigationDelegate == null && it.progressDelegate == null && it.contentDelegate == null &&
            it.promptDelegate == null && it.permissionDelegate == null && it.webExtensionController.cleared == 1 },
            "closed sessions retain no Activity or wallet delegates")
        verify(dialogs.isEmpty() && shownDialogs.none { it.showing } && shownDialogs.all { it.dismissals == 1 }, "all dialogs are dismissed once")
        verify(promptOperations.isEmpty() && operations.none { it.pending } && replies.all { it.completions == 1 } &&
            prompts.all { it.isComplete && it.dismissals == 1 }, "all queued Gecko and wallet replies settle once")
        verify(pickerCleared, "picker response and copy-job ownership are cleared")
        verify(pendingGeckoPermission == null && permissionSession == null && permissionRequestCode == null && permission.rejections == 1,
            "parked Android permission rejects once and drops ownership")
        verify(pickedDirectories.isEmpty(), "picked-file directories are handed to disposal and forgotten")
        verify(wallet == null && walletDialog == null && startupSession == null && startupProgressJob == null, "session UI references are cleared")
        verify(!splashAnimationsActive && splashMark == null && splashOverlay == null && splashStatus == null && splashDetail == null &&
            splashProgress == null && splashProgressLabel == null && mark.clears == 1 && overlay.cancels == 1, "splash animation and views are released")
        verify(multicastLock == null && lock.releases == 1, "Activity multicast lock is released once")
        verify(baseDestroyCalls == 1 && startupGeneration == 1, "destruction advances generation and invokes base once")
    }
    fun joinJobs(): Job = CoroutineScope(Dispatchers.Main).launch {
        jobSnapshots.forEach { it.join() }
        activityJob.join()
    }
    val badgeUpdates get() = torBadge.updates
    val liveJobs get() = activityJob.children.count { it.isActive }
    fun cleanupFixture() { activityJob.cancel() }

// INSERT_PRODUCTION_METHODS
}

fun main() {
    var checks = 0
    fun verify(condition: Boolean, message: String) { checks++; check(condition) { message } }
    val manager = ConnectivityManager()
    val shells = mutableListOf<Shell>()
    try {
        repeat(3) { index ->
            val shell = Shell(manager)
            shells.add(shell)
            shell.populate(index.toLong() + 1)
            shell.start()
            Scheduler.drain()
            verify(shell.polls == 1 && shell.badgeUpdates == 1 && shell.liveJobs == 3, "created Activity owns Tor, progress and boot jobs")
            verify(manager.callbacks.size == 1, "only current Activity is registered")
            val callback = manager.registrations.last()
            // Run an offline/online transition while alive, proving the wake
            // path works before checking that exactly the same callbacks stop.
            manager.online = false
            callback.onLost(manager.activeNetwork)
            Scheduler.drain()
            callback.onAvailable(manager.activeNetwork)
            Scheduler.drain()
            verify(shell.node.calls == 1, "live offline-to-online transition wakes native node on IO")
            Scheduler.advanceBy(5_000)
            verify(shell.polls == 2 && shell.badgeUpdates == 2, "virtual five-second timer executes actual Tor poll loop")
            shell.snapshotJobs()
            // Android may already have posted callbacks when unregistration
            // succeeds. They remain queued across destruction deliberately.
            manager.online = false
            callback.onLost(manager.activeNetwork)
            callback.onAvailable(manager.activeNetwork)
            callback.onCapabilitiesChanged(manager.activeNetwork, NetworkCapabilities(true))
            val refreshes = shell.refreshes
            val calls = shell.node.calls
            val polls = shell.polls
            shell.onDestroy()
            Scheduler.drain()
            shell.assertClean(::verify)
            verify(manager.callbacks.isEmpty() && manager.removals.last() === callback, "destroy unregisters exact callback instance")
            verify(shell.refreshes == refreshes && shell.node.calls == calls, "already-queued callbacks cannot update dead UI or native node")
            // Saved callback references can also arrive after destruction.
            callback.onLost(manager.activeNetwork)
            callback.onAvailable(manager.activeNetwork)
            callback.onCapabilitiesChanged(manager.activeNetwork, NetworkCapabilities(false))
            shell.bootResult.complete(Unit)
            shell.lateReply()
            Scheduler.advanceBy(15_000)
            verify(shell.refreshes == refreshes && shell.node.calls == calls && shell.polls == polls,
                "late callbacks and future polling ticks have no destroyed-Activity effects")
            verify(shell.bootTouches == 0 && shell.lateReplyCompletions == 0 && shell.replyCancellations == 2,
                "late boot and reply completion cannot revive destroyed work")
            val join = shell.joinJobs()
            Scheduler.drain()
            verify(join.isCompleted && !join.isCancelled, "all captured real coroutine jobs join without waiting")
            verify(Scheduler.queued == 0 && Scheduler.delayed == 0, "destroy leaves no queued coroutine work or virtual timers")
            manager.online = true
        }
        verify(manager.registrations.size == 3 && manager.removals.size == 3 && manager.callbacks.isEmpty(),
            "three recreations leave zero registered callbacks")
        verify(shells.sumOf { it.liveJobs } == 0 && shells.flatMap { it.sessions }.none { it.isOpen },
            "three destroyed activities leave zero jobs or open sessions")
        verify(EmbeddedBrowserHost.detached == listOf(1L, 2L, 3L), "each destroyed Activity detaches its own browser token")
        verify(VerifiedAddonManager.detached == listOf(1L, 2L, 3L), "each destroyed Activity detaches its own extension token")
        verify(VerifiedAddonManager.unbound.toSet() == shells.flatMap { it.sessions }.toSet() && VerifiedAddonManager.unbound.size == 6,
            "each owned session drops extension delegates exactly once")
        verify(FileDisposal.paths.map { it.name } == listOf("fixture-picked-1", "fixture-picked-2", "fixture-picked-3"),
            "each Activity schedules disposal of its own picked files")
        val late = shells.last().lateRegistration()
        verify(!late.pending && shells.last().replyCancellations == 3, "registration after shutdown settles immediately")

        val held = Shell(ConnectivityManager())
        shells.add(held)
        held.holdTor = true
        held.start(); Scheduler.drain(); held.snapshotJobs()
        verify(held.polls == 1 && held.badgeUpdates == 0, "Tor poll may be suspended awaiting status")
        held.onDestroy(); Scheduler.drain()
        verify(held.torResult.isActive, "Activity cancellation does not cancel external Tor result")
        held.torResult.complete(1); Scheduler.drain()
        verify(held.badgeUpdates == 0 && held.liveJobs == 0, "late Tor result cannot paint a destroyed badge")
        val heldJoin = held.joinJobs(); Scheduler.drain()
        verify(heldJoin.isCompleted, "suspended Tor poll joins after destruction")

        val unavailable = ConnectivityManager().apply { failRegistration = true }
        val failed = Shell(unavailable)
        shells.add(failed)
        failed.start(); Scheduler.drain(); failed.snapshotJobs()
        failed.onDestroy(); Scheduler.drain()
        verify(unavailable.callbacks.isEmpty() && unavailable.removals.isEmpty() && android.util.Log.failures.size == 1,
            "failed registration creates no stale unregister obligation")
        val failedJoin = failed.joinJobs(); Scheduler.drain()
        verify(failedJoin.isCompleted, "registration failure still disposes every coroutine")

        val missing = Shell(null)
        shells.add(missing)
        missing.start(); Scheduler.drain(); missing.snapshotJobs()
        missing.onDestroy(); Scheduler.drain()
        val missingJoin = missing.joinJobs(); Scheduler.drain()
        verify(missingJoin.isCompleted && missing.refreshes == 0, "missing manager still has bounded Activity cleanup")
        verify(Scheduler.queued == 0 && Scheduler.delayed == 0, "all scenarios leave no work or timer behind")
        for (closeOwner in listOf(false, true)) {
            val picker = Shell(ConnectivityManager())
            shells.add(picker)
            picker.populate(if (closeOwner) 5 else 4)
            picker.start()
            val copy = picker.startFileCopy()
            Scheduler.drain(); picker.snapshotJobs()
            verify(picker.liveJobs == 4 && !picker.pickerCleared && copy.isActive,
                "pending file response and copy are owned while Activity is live")
            if (closeOwner) picker.closePickerOwner() else picker.dismissPicker()
            Scheduler.drain()
            verify(picker.pickerCleared && copy.isCancelled && copy.isCompleted,
                "closing the owner or dismissing picker clears prompt, result, code and cancels copy")
            verify(picker.replies.last().completions == 1 && picker.prompts.last().dismissals == 1,
                "cancelled file selection settles its Gecko response exactly once")
            verify(picker.liveJobs == 3 && picker.fileCopyResult.isActive,
                "picker cancellation leaves unrelated Activity work and external copy source intact")
            picker.fileCopyResult.complete(Unit); Scheduler.drain()
            verify(picker.fileCopyTouches == 0, "late copy result cannot resume cancelled picker work")
            picker.onDestroy(); Scheduler.drain()
            picker.assertClean(::verify)
            val pickerJoin = picker.joinJobs(); Scheduler.drain()
            verify(pickerJoin.isCompleted && Scheduler.queued == 0 && Scheduler.delayed == 0,
                "picker and remaining Activity jobs all join after destruction")
        }
        println("$checks Android Activity lifecycle checks passed with real coroutines 1.9.0 and virtual time")
        println("3 destroyed Activities: 0 callbacks, 0 jobs, 0 open sessions, 0 dialogs, 0 pending replies")
    } finally {
        shells.forEach { it.cleanupFixture() }
        Scheduler.drain()
        check(Scheduler.queued == 0 && Scheduler.delayed == 0)
    }
}
