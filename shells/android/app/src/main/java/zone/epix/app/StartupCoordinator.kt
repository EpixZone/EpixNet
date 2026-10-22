package zone.epix.app

import java.io.File
import java.io.IOException
import java.net.URI
import java.net.URISyntaxException
import java.nio.file.Files
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import uniffi.epix_ffi.NodeState

internal data class StartupRequest(
    val dataDir: String,
    val target: String,
    val version: String,
    val torClearnet: Boolean,
    val uiPort: Int,
)

internal data class BootResult(
    val attemptId: Long,
    val state: NodeState?,
    val error: String?,
    val succeeded: Boolean,
)

/** The scope and native handle belong to the process, never to an activity waiter. */
internal class StartupCoordinator<N : Any>(
    private val scope: CoroutineScope,
    createNode: () -> N,
    private val state: (N) -> NodeState,
    private val start: (N, StartupRequest) -> Unit,
    private val uiUrl: (N) -> String?,
    private val lastError: (N) -> String?,
    private val writeSettings: (StartupRequest) -> Unit,
) {
    @Volatile
    var node: N? = null
        private set

    private val native = scope.async(start = CoroutineStart.LAZY) {
        createNode().also { node = it }
    }
    private val selection = Mutex()
    private var nextAttemptId = 0L
    private var current: Attempt? = null

    private class Attempt(val id: Long) {
        lateinit var work: Deferred<BootResult>
        @Volatile var result: BootResult? = null
    }

    suspend fun ensureStarted(
        request: StartupRequest,
        retryOf: Long? = null,
        resetConfig: Boolean = false,
    ): BootResult {
        val work = selection.withLock {
            val previous = current
            val result = previous?.result
            val retry = previous != null && previous.work.isCompleted &&
                result != null && !result.succeeded &&
                result.state != NodeState.SERVING && result.state != NodeState.STARTING &&
                retryOf == previous.id
            if (previous != null && !retry) {
                previous.work
            } else {
                val attempt = Attempt(++nextAttemptId)
                attempt.work = scope.async {
                    boot(attempt.id, request, resetConfig && retry).also { attempt.result = it }
                }
                current = attempt
                attempt.work
            }
        }
        // Cancellation stops this caller's wait without canceling the owner's deferred.
        return work.await()
    }

    private suspend fun boot(id: Long, request: StartupRequest, resetConfig: Boolean): BootResult {
        try {
            val handle = native.await()
            if (state(handle) != NodeState.SERVING) {
                if (resetConfig) preserveConfigForRetry(request.dataDir)
                writeSettings(request)
                start(handle, request)
            }
            val lifecycle = state(handle)
            if (lifecycle != NodeState.SERVING) {
                return BootResult(id, lifecycle, lastError(handle) ?: "The built-in node did not start.", false)
            }
            if (!matchesUiOrigin(uiUrl(handle), request.uiPort)) {
                return BootResult(
                    id, lifecycle,
                    "The built-in node did not report the expected local browser address.", false,
                )
            }
            return BootResult(id, lifecycle, null, true)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            return failure(id, error)
        } catch (error: LinkageError) {
            // JNI loading and generated binding initialization can fail before a handle exists.
            return failure(id, error)
        }
    }

    private fun failure(id: Long, error: Throwable): BootResult {
        val lifecycle = try {
            node?.let(state)
        } catch (canceled: CancellationException) {
            throw canceled
        } catch (_: Exception) {
            null
        } catch (_: LinkageError) {
            null
        }
        return BootResult(id, lifecycle, error.message ?: "The built-in node did not start.", false)
    }
}

/** Match the actual listener origin without accepting lookalike hosts or credentials. */
internal fun matchesUiOrigin(url: String?, expectedPort: Int): Boolean {
    if (url == null) return false
    val uri = try {
        URI(url)
    } catch (_: URISyntaxException) {
        return false
    }
    val port = if (uri.port == -1) 80 else uri.port
    return uri.scheme.equals("http", ignoreCase = true) && uri.host == "127.0.0.1" &&
        uri.rawUserInfo == null && port == expectedPort
}

/** Preserve the failed settings file; a failed move must never become deletion. */
internal fun preserveConfigForRetry(dataDir: String) {
    val config = File(dataDir, "private/config.json")
    if (!config.exists()) return
    if (!config.isFile) throw IOException("Connection settings could not be preserved for retry.")
    val backup = File(config.parentFile, "config.json.broken-${System.currentTimeMillis()}-${UUID.randomUUID()}")
    Files.move(config.toPath(), backup.toPath())
}
