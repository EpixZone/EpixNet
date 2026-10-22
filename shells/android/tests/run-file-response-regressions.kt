package zone.epix.app

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.ArrayDeque
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.*

private var checks = 0
private fun verify(value: Boolean, message: String) {
    checks++
    check(value) { message }
}

/** Every real coroutine dispatch is driven by the test; no sleeps or workers. */
internal object Scheduler {
    private data class Work(val lane: String, val block: Runnable)
    private val work = ArrayDeque<Work>()
    var lane = "MAIN"
        private set
    fun dispatcher(name: String) = object : CoroutineDispatcher() {
        override fun dispatch(context: CoroutineContext, block: Runnable) {
            work.addLast(Work(name, block))
        }
    }
    fun drain() {
        var steps = 0
        while (work.isNotEmpty()) {
            check(++steps < 1000) { "unbounded immediate coroutine work" }
            val next = work.removeFirst()
            lane = next.lane
            try { next.block.run() } finally { lane = "MAIN" }
        }
    }
}
internal object Dispatchers {
    val Main = Scheduler.dispatcher("MAIN")
    val IO = Scheduler.dispatcher("IO")
}
internal data class Uri(val path: String) {
    companion object { fun fromFile(file: File) = Uri(file.absolutePath) }
}
internal class ClipData(private val uris: List<Uri>) {
    class Item(val uri: Uri)
    val itemCount get() = uris.size
    fun getItemAt(index: Int) = Item(uris[index])
}
internal class Intent(val action: String = "") {
    var type = ""
    var clipData: ClipData? = null
    var data: Uri? = null
    fun addCategory(category: String) {}
    fun putExtra(name: String, value: Boolean) {}
    companion object {
        const val ACTION_GET_CONTENT = "get-content"
        const val CATEGORY_OPENABLE = "openable"
        const val EXTRA_ALLOW_MULTIPLE = "multiple"
    }
}
internal class GeckoResult<T> {
    var completions = 0
    var value: T? = null
    var error: Throwable? = null
    fun complete(value: T) { check(++completions == 1); this.value = value }
    fun completeExceptionally(error: Throwable) { check(++completions == 1); this.error = error }
}
internal class GeckoSession {
    class PromptDelegate {
        class PromptResponse(val files: List<File> = emptyList())
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
        class FilePrompt(val type: Int = Type.SINGLE) : BasePrompt() {
            object Type { const val SINGLE = 1; const val MULTIPLE = 2 }
            var confirmations = 0
            var failConfirm = false
            fun confirm(context: Context, uri: Uri) = confirm(context, arrayOf(uri))
            fun confirm(context: Context, uris: Array<Uri>): PromptResponse {
                check(Scheduler.lane == "MAIN")
                check(!isComplete)
                // Gecko 155 rejects an array with more than one URI for SINGLE.
                require(type == Type.MULTIPLE || uris.size == 1)
                if (failConfirm) throw IllegalStateException("prompt confirmation failed")
                isComplete = true
                confirmations++
                return PromptResponse(uris.map { File(it.path) })
            }
        }
    }
    class PermissionDelegate { class Callback { fun reject() {} } }
}
internal class Context(val cacheDir: File, val copier: CopyControl)
internal class CopyControl {
    var hold = false
    var fail = false
    var empty = false
    val gate = CompletableDeferred<Unit>()
    val calls = mutableListOf<List<Uri>>()
    val directories = mutableListOf<File>()
    var canceled = 0
    suspend fun copy(uris: List<Uri>, directory: File): List<File> {
        check(Scheduler.lane == "IO")
        calls.add(uris.toList())
        directories.add(directory)
        check(directory.mkdirs())
        val files = uris.mapIndexed { index, uri ->
            File(directory, "$index.bin").apply { writeText(uri.path) }
        }
        try {
            if (hold) gate.await()
            if (fail) throw IOException("provider read failed")
            return if (empty) emptyList() else files
        } catch (error: CancellationException) {
            canceled++
            throw error
        }
    }
}
internal suspend fun copyPickedFiles(context: Context, uris: List<Uri>, directory: File) =
    context.copier.copy(uris, directory)
private val cleanupJob = SupervisorJob()
private val cleanupScope = CoroutineScope(cleanupJob + Dispatchers.IO)
internal fun discardPickedFiles(directory: File) {
    cleanupScope.launch { directory.deleteRecursively() }
}
internal open class Activity {
    open fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {}
    companion object { const val RESULT_OK = -1 }
}
internal class Shell(val applicationContext: Context) : Activity() {
    private var disposed = false
    private val owned = mutableSetOf<GeckoSession>()
    private var pendingGeckoPermission: GeckoSession.PermissionDelegate.Callback? = null
    private var permissionSession: GeckoSession? = null
    private var permissionRequestCode: Int? = null
    val requests = mutableListOf<Int>()
    var failLaunch = false
    private val jobs = mutableListOf<Job>()
// INSERT_DECLARATIONS
    private fun ownsSession(session: GeckoSession) = !disposed && session in owned
    fun startActivityForResult(intent: Intent, requestCode: Int) {
        if (failLaunch) throw IllegalStateException("picker unavailable")
        requests.add(requestCode)
    }
    fun newSession() = GeckoSession().also { owned.add(it) }
    fun close(session: GeckoSession) { owned.remove(session); pendingOperations.cancelOwner(session) }
    fun reply(code: Int, vararg names: String, resultCode: Int = RESULT_OK) {
        onActivityResult(code, resultCode, Intent().apply { clipData = ClipData(names.map(::Uri)) })
        pendingFileCopyJob?.let { jobs.add(it) }
    }
    fun currentPrompt() = pendingFilePrompt
    fun currentJob() = pendingFileCopyJob
    fun currentCode() = fileRequestCode
    fun registered() = promptOperations.size
    fun directories() = pickedDirectories.toList()
    fun destroy() {
        disposed = true
// INSERT_TEARDOWN
    }
    suspend fun joined() {
        jobs.forEach { it.join() }
        activityJob.join()
    }
// INSERT_CALLBACKS
    companion object {
// INSERT_COUNTER
    }
}

private data class Fixture(val directory: File, val copy: CopyControl, val shell: Shell)
private suspend fun fixture(block: suspend (Fixture) -> Unit) {
    val directory = Files.createTempDirectory("epix-file-response-").toFile()
    val copy = CopyControl()
    val shell = Shell(Context(directory, copy))
    try { block(Fixture(directory, copy, shell)) }
    finally {
        shell.destroy()
        copy.gate.complete(Unit)
        Scheduler.drain()
        shell.joined()
        directory.deleteRecursively()
    }
}

private suspend fun successfulAndMalformedSelections() = fixture { f ->
    val session = f.shell.newSession()
    val single = GeckoSession.PromptDelegate.FilePrompt()
    val result = f.shell.onFilePrompt(session, single)
    f.shell.reply(f.shell.requests.last(), "first", "unexpected-second")
    Scheduler.drain()
    verify(f.copy.calls.single() == listOf(Uri("first")), "single prompt copies only one provider item")
    verify(result.completions == 1 && single.confirmations == 1 && single.dismissals == 0,
        "malformed multi-item SINGLE response confirms once")
    val original = result.value!!.files.single()
    verify(original.readText() == "first", "accepted file remains readable after response")
    verify(f.shell.currentPrompt() == null && f.shell.currentJob() == null && f.shell.registered() == 0,
        "successful response releases prompt and job ownership")

    val multiple = GeckoSession.PromptDelegate.FilePrompt(GeckoSession.PromptDelegate.FilePrompt.Type.MULTIPLE)
    val next = f.shell.onFilePrompt(session, multiple)
    f.shell.reply(f.shell.requests.last(), "one", "two")
    Scheduler.drain()
    verify(next.value!!.files.map { it.readText() } == listOf("one", "two"), "multiple prompt preserves every file")
    verify(original.readText() == "first", "later response preserves previously accepted paths")
}

private suspend fun failedResponses() = fixture { f ->
    val session = f.shell.newSession()
    val accepted = GeckoSession.PromptDelegate.FilePrompt()
    val acceptedResult = f.shell.onFilePrompt(session, accepted)
    f.shell.reply(f.shell.requests.last(), "earlier-upload")
    Scheduler.drain()
    val preserved = acceptedResult.value!!.files.single()
    val prompt = GeckoSession.PromptDelegate.FilePrompt().apply { failConfirm = true }
    val result = f.shell.onFilePrompt(session, prompt)
    f.shell.reply(f.shell.requests.last(), "confirm-failure")
    Scheduler.drain()
    verify(result.completions == 1 && prompt.dismissals == 1 && prompt.confirmations == 0,
        "confirmation failure still dismisses the parked result")
    verify(f.copy.directories.drop(1).none { it.exists() } && f.shell.registered() == 0,
        "confirmation failure cleans partial files and registry")

    f.copy.fail = true
    val failed = GeckoSession.PromptDelegate.FilePrompt()
    val failedResult = f.shell.onFilePrompt(session, failed)
    f.shell.reply(f.shell.requests.last(), "read-failure")
    Scheduler.drain()
    verify(failedResult.completions == 1 && failed.dismissals == 1,
        "provider failure dismisses once")
    verify(f.copy.directories.drop(1).none { it.exists() }, "provider failure removes its partial directory")
    f.copy.fail = false
    f.copy.empty = true
    val empty = GeckoSession.PromptDelegate.FilePrompt()
    val emptyResult = f.shell.onFilePrompt(session, empty)
    f.shell.reply(f.shell.requests.last(), "unreadable")
    Scheduler.drain()
    verify(emptyResult.completions == 1 && empty.dismissals == 1 && f.copy.directories.drop(1).none { it.exists() },
        "zero readable files dismiss once and remove the response directory")
    verify(preserved.readText() == "earlier-upload", "failed response cleanup preserves earlier accepted paths")
}

private suspend fun stalePickerResults() = fixture { f ->
    val session = f.shell.newSession()
    val a = GeckoSession.PromptDelegate.FilePrompt()
    val ar = f.shell.onFilePrompt(session, a)
    val ac = f.shell.requests.last()
    val b = GeckoSession.PromptDelegate.FilePrompt()
    val br = f.shell.onFilePrompt(session, b)
    val bc = f.shell.requests.last()
    verify(ac != bc && ar.completions == 1 && a.dismissals == 1, "replacement dismisses A and uses a fresh request code")
    f.shell.reply(ac, "stale-a")
    Scheduler.drain()
    verify(br.completions == 0 && f.copy.calls.isEmpty() && f.shell.currentPrompt() === b,
        "late A result cannot copy files or settle B")
    f.shell.reply(bc, "current-b")
    Scheduler.drain()
    f.shell.reply(bc, "duplicate-b")
    Scheduler.drain()
    verify(br.completions == 1 && b.confirmations == 1 && f.copy.calls.size == 1,
        "current B result confirms once and ignores duplicate delivery")
}

private suspend fun cancellationDuringCopy(replace: Boolean) = fixture { f ->
    val session = f.shell.newSession()
    f.copy.hold = true
    val a = GeckoSession.PromptDelegate.FilePrompt()
    val ar = f.shell.onFilePrompt(session, a)
    f.shell.reply(f.shell.requests.last(), "partial-a")
    val oldJob = f.shell.currentJob()!!
    Scheduler.drain()
    val partial = f.copy.directories.single()
    verify(partial.exists() && !oldJob.isCompleted && ar.completions == 0,
        "copy suspends with real partial files and an outstanding reply")
    val b = GeckoSession.PromptDelegate.FilePrompt()
    val br = if (replace) f.shell.onFilePrompt(session, b) else null
    if (!replace) f.shell.close(session)
    verify(ar.completions == 1 && a.dismissals == 1 && oldJob.isCancelled,
        "closing or replacing a prompt cancels its copy and settles exactly once")
    Scheduler.drain()
    oldJob.join()
    verify(!partial.exists() && f.copy.canceled == 1, "canceled copy removes partial output and finishes")
    if (replace) {
        verify(f.shell.currentPrompt() === b && br!!.completions == 0 && f.shell.currentCode() == f.shell.requests.last(),
            "old finally does not clear the replacement picker")
        f.copy.hold = false
        f.shell.reply(f.shell.requests.last(), "accepted-b")
        Scheduler.drain()
        verify(br!!.completions == 1 && b.confirmations == 1 && br.value!!.files.single().readText() == "accepted-b",
            "replacement copy succeeds after old cleanup")
    } else {
        verify(f.shell.currentPrompt() == null && f.shell.currentJob() == null && f.shell.currentCode() == null,
            "session close clears all parked picker ownership")
    }
}

private suspend fun destructionBeforeDispatch() = fixture { f ->
    val session = f.shell.newSession()
    val prompt = GeckoSession.PromptDelegate.FilePrompt()
    val result = f.shell.onFilePrompt(session, prompt)
    f.shell.reply(f.shell.requests.last(), "never-copied")
    val job = f.shell.currentJob()!!
    val directory = f.shell.directories().single()
    f.shell.destroy()
    Scheduler.drain()
    job.join()
    verify(result.completions == 1 && prompt.dismissals == 1 && f.copy.calls.isEmpty(),
        "destroy before dispatch dismisses once without starting IO")
    verify(!directory.exists() && job.isCompleted && f.shell.directories().isEmpty(),
        "destroy before dispatch releases the registered directory and job")
}

private suspend fun destructionDuringCopy() = fixture { f ->
    val session = f.shell.newSession()
    f.copy.hold = true
    val prompt = GeckoSession.PromptDelegate.FilePrompt()
    val result = f.shell.onFilePrompt(session, prompt)
    f.shell.reply(f.shell.requests.last(), "partial-before-destroy")
    val job = f.shell.currentJob()!!
    Scheduler.drain()
    val directory = f.copy.directories.single()
    verify(directory.exists() && result.completions == 0, "destroy case reaches suspended IO with partial bytes")
    f.shell.destroy()
    Scheduler.drain()
    job.join()
    verify(result.completions == 1 && prompt.dismissals == 1 && prompt.confirmations == 0,
        "destruction during IO dismisses once and never confirms")
    verify(job.isCompleted && f.copy.canceled == 1 && !directory.exists(),
        "destruction joins canceled IO and removes its partial directory")
}

private suspend fun sessionCloseBeforeDispatch() = fixture { f ->
    val session = f.shell.newSession()
    val prompt = GeckoSession.PromptDelegate.FilePrompt()
    val result = f.shell.onFilePrompt(session, prompt)
    f.shell.reply(f.shell.requests.last(), "never-copied")
    val job = f.shell.currentJob()!!
    val directory = f.shell.directories().single()
    f.shell.close(session)
    Scheduler.drain()
    job.join()
    verify(result.completions == 1 && prompt.dismissals == 1 && f.copy.calls.isEmpty(),
        "session close before dispatch cancels the unstarted copy and dismisses once")
    verify(job.isCompleted && !directory.exists() && f.shell.currentPrompt() == null,
        "session close before dispatch leaves no active picker or partial files")
}

private suspend fun pickerLaunchAndCancel() = fixture { f ->
    val session = f.shell.newSession()
    f.shell.failLaunch = true
    val failed = GeckoSession.PromptDelegate.FilePrompt()
    val failedResult = f.shell.onFilePrompt(session, failed)
    verify(failedResult.completions == 1 && failed.dismissals == 1 && f.shell.currentCode() == null,
        "system picker launch failure dismisses and clears the request")
    f.shell.failLaunch = false
    val canceled = GeckoSession.PromptDelegate.FilePrompt()
    val result = f.shell.onFilePrompt(session, canceled)
    f.shell.reply(f.shell.requests.last(), resultCode = 0)
    verify(result.completions == 1 && canceled.dismissals == 1 && f.copy.calls.isEmpty(),
        "system picker cancellation dismisses without IO")
}

fun main() = runBlocking {
    try {
        successfulAndMalformedSelections()
        failedResponses()
        stalePickerResults()
        cancellationDuringCopy(replace = false)
        cancellationDuringCopy(replace = true)
        destructionBeforeDispatch()
        destructionDuringCopy()
        sessionCloseBeforeDispatch()
        pickerLaunchAndCancel()
        println("PASS: $checks Android file-response lifecycle regression checks")
    } finally {
        cleanupJob.cancel()
        Scheduler.drain()
        cleanupJob.join()
    }
}
