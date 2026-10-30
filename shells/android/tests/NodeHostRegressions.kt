package zone.epix.app

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import uniffi.epix_ffi.NodeState

private class FakeNode {
    @Volatile var state = NodeState.IDLE
    @Volatile var stateFailure: Throwable? = null
    @Volatile var url: String? = "http://127.0.0.1:42222/dashboard.epix/"
}

private class Fixture {
    val directory = Files.createTempDirectory("epix-node-host-").toFile()
    val factories = AtomicInteger()
    val starts = AtomicInteger()
    val settingsWrites = AtomicInteger()
    val fake = FakeNode()
    val request = StartupRequest(directory.path, "dashboard.epix/path?q=a#b", "test", true, 42222)
    val releases = mutableListOf<CountDownLatch>()
    private val executor = Executors.newFixedThreadPool(2)
    private val dispatcher = executor.asCoroutineDispatcher()
    private val callerThread = Thread.currentThread()
    private val ownerJob = SupervisorJob()
    private val owner = CoroutineScope(ownerJob + dispatcher)
    @Volatile var factoryError: Throwable? = null
    @Volatile var onStart: (FakeNode, StartupRequest) -> Unit = { node, _ -> node.state = NodeState.SERVING }
    @Volatile var onSettings: (StartupRequest) -> Unit = {}
    val coordinator = StartupCoordinator(
        scope = owner,
        createNode = {
            check(Thread.currentThread() !== callerThread) { "native constructor ran on the caller thread" }
            factories.incrementAndGet()
            factoryError?.let { throw it }
            fake
        },
        state = { node -> node.stateFailure?.let { throw it }; node.state },
        start = { node, request ->
            starts.incrementAndGet()
            node.state = NodeState.STARTING
            onStart(node, request)
        },
        uiUrl = { it.url },
        lastError = { "fake native startup failed" },
        writeSettings = { settingsWrites.incrementAndGet(); onSettings(it) },
    )

    fun blockStart(fail: Boolean = false): Pair<CompletableDeferred<Unit>, CountDownLatch> {
        val entered = CompletableDeferred<Unit>()
        val release = CountDownLatch(1)
        releases.add(release)
        onStart = { node, _ ->
            entered.complete(Unit)
            check(release.await(10, TimeUnit.SECONDS)) { "fake native start was not released" }
            node.state = if (fail) NodeState.FAILED else NodeState.SERVING
            if (fail) throw IOException("fake native startup failed")
        }
        return entered to release
    }

    fun failStart() {
        onStart = { node, _ ->
            node.state = NodeState.FAILED
            throw IOException("fake native startup failed")
        }
    }

    suspend fun close() = withContext(NonCancellable) {
        releases.forEach { it.countDown() }
        try {
            withTimeout(5_000) { ownerJob.cancelAndJoin() }
        } finally {
            dispatcher.close()
            check(executor.awaitTermination(5, TimeUnit.SECONDS)) { "owner worker did not terminate" }
            directory.deleteRecursively()
        }
    }
}

private suspend fun fixture(body: suspend CoroutineScope.(Fixture) -> Unit) {
    val fixture = Fixture()
    try {
        coroutineScope { body(fixture) }
    } finally {
        fixture.close()
    }
}

private suspend fun canceledWaiterSharesBoot() = fixture { f ->
    check(f.coordinator.node == null && f.factories.get() == 0) { "reading node initialized it" }
    val (entered, release) = f.blockStart()
    val activityA = async(start = CoroutineStart.UNDISPATCHED) { f.coordinator.ensureStarted(f.request) }
    entered.await()
    val activityB = async(start = CoroutineStart.UNDISPATCHED) {
        f.coordinator.ensureStarted(f.request.copy(target = "later.epix/new"))
    }
    activityA.cancelAndJoin()
    check(activityA.isCancelled && !activityB.isCompleted)
    check(f.factories.get() == 1 && f.starts.get() == 1 && f.coordinator.node === f.fake)
    release.countDown()
    val result = activityB.await()
    check(result.succeeded && result.attemptId == 1L)
    check(f.coordinator.ensureStarted(f.request.copy(target = "third.epix/")) == result)
    check(f.coordinator.ensureStarted(f.request, result.attemptId, resetConfig = true) == result)
    check(f.factories.get() == 1 && f.starts.get() == 1 && f.settingsWrites.get() == 1)
}

private suspend fun failedRetryIsFenced() = fixture { f ->
    f.failStart()
    val first = f.coordinator.ensureStarted(f.request)
    check(!first.succeeded && first.state == NodeState.FAILED)
    check(f.coordinator.ensureStarted(f.request) == first)
    check(f.coordinator.ensureStarted(f.request, retryOf = 99) == first)
    val (entered, release) = f.blockStart(fail = true)
    val retryA = async(start = CoroutineStart.UNDISPATCHED) {
        f.coordinator.ensureStarted(f.request, retryOf = first.attemptId)
    }
    entered.await()
    val retryB = async(start = CoroutineStart.UNDISPATCHED) {
        f.coordinator.ensureStarted(f.request, retryOf = first.attemptId)
    }
    release.countDown()
    val second = retryA.await()
    check(second == retryB.await() && second.attemptId == 2L && !second.succeeded)
    // A queued old retry still cannot launch another attempt after a fast failure.
    check(f.coordinator.ensureStarted(f.request, first.attemptId) == second)
    check(f.starts.get() == 2 && f.factories.get() == 1)
    f.onStart = { node, _ -> node.state = NodeState.SERVING }
    val third = f.coordinator.ensureStarted(f.request, second.attemptId)
    check(third.succeeded && third.attemptId == 3L && f.starts.get() == 3)
}

private suspend fun resetOnlyTheSelectedFailure() = fixture { f ->
    val config = File(f.directory, "private/config.json")
    config.parentFile.mkdirs()
    config.writeText("original settings")
    val (initialEntered, initialRelease) = f.blockStart(fail = true)
    val initial = async(start = CoroutineStart.UNDISPATCHED) {
        // A reset flag without a selected failed attempt cannot mutate files.
        f.coordinator.ensureStarted(f.request, resetConfig = true)
    }
    initialEntered.await()
    val prematureReset = async(start = CoroutineStart.UNDISPATCHED) {
        f.coordinator.ensureStarted(f.request, retryOf = 1, resetConfig = true)
    }
    check(config.readText() == "original settings")
    initialRelease.countDown()
    val first = initial.await()
    check(prematureReset.await() == first && config.isFile)
    val (retryEntered, retryRelease) = f.blockStart(fail = true)
    val retry = async(start = CoroutineStart.UNDISPATCHED) {
        f.coordinator.ensureStarted(f.request, first.attemptId)
    }
    retryEntered.await()
    val lateReset = async(start = CoroutineStart.UNDISPATCHED) {
        f.coordinator.ensureStarted(f.request, first.attemptId, resetConfig = true)
    }
    check(config.readText() == "original settings")
    retryRelease.countDown()
    val second = retry.await()
    check(lateReset.await() == second)
    check(f.coordinator.ensureStarted(f.request, first.attemptId, true) == second)
    check(config.readText() == "original settings")
    f.onSettings = { check(!config.exists()) { "reset must precede preparation and native start" } }
    f.onStart = { node, _ -> node.state = NodeState.SERVING }
    val third = f.coordinator.ensureStarted(f.request, second.attemptId, resetConfig = true)
    check(third.succeeded && f.starts.get() == 3 && !config.exists())
    val backups = config.parentFile.listFiles()!!.filter { it.name.startsWith("config.json.broken-") }
    check(backups.size == 1 && backups.single().readText() == "original settings")
}

private suspend fun resetFailurePreservesDataAndCanRetry() = fixture { f ->
    val config = File(f.directory, "private/config.json")
    config.mkdirs()
    val retained = File(config, "retained").apply { writeText("keep") }
    f.failStart()
    val first = f.coordinator.ensureStarted(f.request)
    val second = f.coordinator.ensureStarted(f.request, first.attemptId, resetConfig = true)
    check(!second.succeeded && second.error != null && second.attemptId == 2L)
    check(retained.readText() == "keep" && f.starts.get() == 1 && f.settingsWrites.get() == 1)
    check(f.coordinator.ensureStarted(f.request, first.attemptId, true) == second)
    retained.delete()
    config.delete()
    f.onStart = { node, _ -> node.state = NodeState.SERVING }
    val third = f.coordinator.ensureStarted(f.request, second.attemptId, resetConfig = true)
    check(third.succeeded && f.factories.get() == 1 && f.starts.get() == 2)
}

private suspend fun servingEndpointFailureNeverRestarts() = fixture { f ->
    val config = File(f.directory, "private/config.json")
    config.parentFile.mkdirs()
    config.writeText("keep serving settings")
    f.fake.url = "http://127.0.0.1:42223/dashboard.epix/"
    val first = f.coordinator.ensureStarted(f.request)
    check(!first.succeeded && first.state == NodeState.SERVING && first.error != null)
    check(f.coordinator.ensureStarted(f.request, first.attemptId, resetConfig = true) == first)
    check(config.readText() == "keep serving settings" && f.starts.get() == 1)
    check(f.coordinator.ensureStarted(f.request.copy(uiPort = 42223, target = "new.epix")) == first)
}

private suspend fun failedFactoryIsNotRecreated() = fixture { f ->
    f.factoryError = IOException("native constructor failed")
    val first = f.coordinator.ensureStarted(f.request)
    check(!first.succeeded && first.state == null && first.error == "native constructor failed")
    val second = f.coordinator.ensureStarted(f.request, first.attemptId)
    check(second.attemptId == 2L && !second.succeeded)
    check(f.factories.get() == 1 && f.starts.get() == 0 && f.coordinator.node == null)
}

private suspend fun linkageErrorsAreReportedWithoutCatchingVmErrors() {
    for (failure in listOf(
        UnsatisfiedLinkError("missing native library"),
        ExceptionInInitializerError(IllegalStateException("binding contract mismatch")),
        NoClassDefFoundError("native binding initialization failed"),
    )) fixture { f ->
        f.factoryError = failure
        val first = f.coordinator.ensureStarted(f.request)
        check(!first.succeeded && first.state == null && first.error != null)
        check(f.coordinator.ensureStarted(f.request) == first)
        val retry = f.coordinator.ensureStarted(f.request, first.attemptId)
        check(!retry.succeeded && f.factories.get() == 1 && f.starts.get() == 0)
    }
    for (failure in listOf(OutOfMemoryError("simulated VM failure"), CancellationException("canceled owner"))) {
        fixture { f ->
            f.factoryError = failure
            val actual = runCatching { f.coordinator.ensureStarted(f.request) }.exceptionOrNull()
            check(actual === failure) { "VM errors and cancellation must propagate" }
        }
    }
    fixture { f ->
        val fatal = OutOfMemoryError("simulated status failure")
        f.onStart = { node, _ ->
            node.stateFailure = fatal
            throw IOException("original native failure")
        }
        check(runCatching { f.coordinator.ensureStarted(f.request) }.exceptionOrNull() === fatal) {
            "error-state inspection swallowed a VM error"
        }
    }
}

private suspend fun failedStartingStateCannotRetryOrReset() = fixture { f ->
    val config = File(f.directory, "private/config.json")
    config.parentFile.mkdirs()
    config.writeText("keep settings")
    f.onStart = { node, _ ->
        node.state = NodeState.STARTING
        throw IOException("native panic left start in progress")
    }
    val first = f.coordinator.ensureStarted(f.request)
    check(!first.succeeded && first.state == NodeState.STARTING)
    check(f.coordinator.ensureStarted(f.request, first.attemptId, resetConfig = true) == first)
    check(f.coordinator.ensureStarted(f.request.copy(target = "later.epix"), first.attemptId) == first)
    check(f.starts.get() == 1 && f.settingsWrites.get() == 1 && config.readText() == "keep settings")
}

private fun parsedOriginValidation() {
    for (url in listOf(
        "http://127.0.0.1:42222/dashboard.epix/", "HTTP://127.0.0.1:42222/a?b=c#d",
    )) check(matchesUiOrigin(url, 42222)) { "valid origin rejected: $url" }
    for (url in listOf(
        null, "", "not a URL", "http://127.0.0.1:42223/", "http://127.0.0.1/",
        "https://127.0.0.1:42222/", "http://127.0.0.1.evil:42222/",
        "http://127.0.0.1:42222@elsewhere/", "http://user@127.0.0.1:42222/",
        "http://localhost:42222/", "//127.0.0.1:42222/",
    )) check(!matchesUiOrigin(url, 42222)) { "invalid origin accepted: $url" }
    check(matchesUiOrigin("http://127.0.0.1/path", 80))
}

fun main() = runBlocking {
    withTimeout(30_000) {
        canceledWaiterSharesBoot()
        failedRetryIsFenced()
        resetOnlyTheSelectedFailure()
        resetFailurePreservesDataAndCanRetry()
        servingEndpointFailureNeverRestarts()
        failedFactoryIsNotRecreated()
        linkageErrorsAreReportedWithoutCatchingVmErrors()
        failedStartingStateCannotRetryOrReset()
        parsedOriginValidation()
    }
    println("PASS: 9 Android node-host regression groups (real coroutines)")
}
