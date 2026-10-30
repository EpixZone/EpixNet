package zone.epix.app

import java.io.File
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONObject
import uniffi.epix_ffi.EpixNode
import uniffi.epix_ffi.NodeConfig

/** One native runtime and startup operation for this app process. */
internal object EmbeddedNodeHost {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val browserSettings = BrowserSettingsStore(
        enqueue = { work -> scope.launch { work() } },
        persist = ::persistBrowserSettings,
    )
    private val coordinator = StartupCoordinator(
        scope = scope,
        createNode = {
            System.loadLibrary("epix_ffi")
            EpixNode()
        },
        state = { it.state() },
        start = { node, request ->
            node.start(
                NodeConfig(
                    dataDir = request.dataDir,
                    target = request.target.substringBefore('/'),
                    uiAddr = "127.0.0.1:${request.uiPort}",
                    torMode = "enable",
                    version = request.version,
                ),
            )
        },
        uiUrl = { it.uiUrl() },
        lastError = { it.lastError() },
        writeSettings = { writeBrowserSettings(it.dataDir, it.torClearnet) },
    )

    /** Reading progress must not construct a native runtime on the UI thread. */
    val node: EpixNode? get() = coordinator.node

    suspend fun ensureStarted(
        request: StartupRequest,
        retryOf: Long? = null,
        resetConfig: Boolean = false,
    ): BootResult = coordinator.ensureStarted(request, retryOf, resetConfig)

    /** Record the preference before dispatch; this write survives Activity destruction. */
    fun updateBrowserSettings(dataDir: String, torClearnet: Boolean) {
        browserSettings.update(dataDir, torClearnet)
    }

    /** Startup may carry an older snapshot than the latest live preference. */
    fun writeBrowserSettings(dataDir: String, torClearnet: Boolean) {
        browserSettings.writeLatest(dataDir, torClearnet)
    }

    /** Keep the existing best-effort browser marker and preserve unrelated settings. */
    private fun persistBrowserSettings(dataDir: String, torClearnet: Boolean) {
        try {
            val file = File(dataDir, "browser-settings.json")
            val current = try {
                JSONObject(file.readText())
            } catch (canceled: CancellationException) {
                throw canceled
            } catch (_: Exception) {
                JSONObject()
            }
            current.put("tor_clearnet", torClearnet)
            file.writeText(current.toString())
        } catch (canceled: CancellationException) {
            throw canceled
        } catch (_: Exception) {
            // Failure to write the browser marker does not stop native startup.
        }
    }
}

/** Serialize disk writes while preference updates never wait for disk IO. */
internal class BrowserSettingsStore(
    private val enqueue: (() -> Unit) -> Unit,
    private val persist: (String, Boolean) -> Unit,
) {
    private val writeLock = Any()
    private val latest = ConcurrentHashMap<String, Boolean>()

    fun update(dataDir: String, torClearnet: Boolean) {
        latest[dataDir] = torClearnet
        enqueue { writeLatest(dataDir, torClearnet) }
    }

    fun writeLatest(dataDir: String, fallback: Boolean) {
        synchronized(writeLock) {
            persist(dataDir, latest[dataDir] ?: fallback)
        }
    }
}
