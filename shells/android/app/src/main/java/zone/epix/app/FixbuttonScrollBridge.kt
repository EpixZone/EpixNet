package zone.epix.app

import android.os.Handler
import android.os.Looper
import android.util.Log
import java.net.URI
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import org.json.JSONObject
import org.mozilla.geckoview.GeckoRuntime
import org.mozilla.geckoview.GeckoSession
import org.mozilla.geckoview.WebExtension

/** Sends native chrome visibility to our local wrapper. Pages cannot issue native commands. */
internal class FixbuttonScrollBridge {
    private val sessions = mutableSetOf<GeckoSession>()
    private val locations = mutableMapOf<GeckoSession, String>()
    private val ports = mutableMapOf<GeckoSession, WebExtension.Port>()
    private var extension: WebExtension? = null
    private var selected: GeckoSession? = null
    private var nodeBase: String? = null
    private var enabled = false
    private var chromeHidden = false
    private var closed = false

    suspend fun install(runtime: GeckoRuntime) {
        try {
            val installed = withTimeoutOrNull(10_000) {
                suspendCancellableCoroutine<WebExtension> { continuation ->
                    val result = runtime.webExtensionController.ensureBuiltIn(
                        "resource://android/assets/browser-controls/", EXTENSION_ID,
                    )
                    val main = Handler(Looper.getMainLooper())
                    result.withHandler(main).accept({ value ->
                        if (continuation.isActive) {
                            if (value != null) continuation.resume(value)
                            else continuation.resumeWithException(IllegalStateException("Browser controls extension is unavailable"))
                        }
                    }, { error ->
                        if (continuation.isActive) continuation.resumeWithException(
                            error ?: IllegalStateException("Browser controls extension could not be installed"),
                        )
                    })
                    continuation.invokeOnCancellation { main.post { result.cancel() } }
                }
            } ?: throw IllegalStateException("Browser controls extension installation timed out")
            if (closed) return
            extension = installed
            sessions.forEach(::bindDelegate)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            Log.w("EpixBrowser", "Could not install scroll controls", error)
        }
    }

    fun bindSession(session: GeckoSession) {
        if (closed) return
        sessions.add(session)
        bindDelegate(session)
    }

    private fun bindDelegate(session: GeckoSession) {
        extension?.let { session.webExtensionController.setMessageDelegate(it, delegate, NATIVE_APP) }
    }

    fun unbindSession(session: GeckoSession) {
        ports.remove(session)?.let(::disconnect)
        locations.remove(session)
        sessions.remove(session)
        if (selected === session) selected = null
        extension?.let { session.webExtensionController.setMessageDelegate(it, null, NATIVE_APP) }
    }

    fun onLocationChanged(session: GeckoSession, url: String) {
        if (session !in sessions) return
        locations[session] = url
        if (!sameNodeOrigin(nodeBase, url)) ports.remove(session)?.let(::disconnect)
    }

    fun setNodeBase(base: String) {
        nodeBase = base
        ports.entries.toList().forEach { (session, port) ->
            if (!sameNodeOrigin(base, port.sender.url)) {
                ports.remove(session)
                disconnect(port)
            }
        }
        refresh()
    }

    fun setEnabled(value: Boolean) { enabled = value; refresh() }
    fun setChromeHidden(value: Boolean) { chromeHidden = value; refresh() }
    fun selectSession(session: GeckoSession) { selected = session.takeIf { it in sessions }; refresh() }

    fun close() {
        closed = true
        sessions.toList().forEach(::unbindSession)
        extension = null
        selected = null
    }

    private fun refresh() { ports.values.toList().forEach(::send) }

    private fun send(port: WebExtension.Port) {
        val session = port.sender.session
        val hidden = enabled && chromeHidden && session === selected && session in sessions &&
            sameNodeOrigin(nodeBase, locations[session])
        runCatching { port.postMessage(JSONObject().put("hidden", hidden)) }
            .onFailure {
                if (ports[session] === port) ports.remove(session)
                runCatching { port.disconnect() }
            }
    }

    private fun disconnect(port: WebExtension.Port) {
        runCatching { port.postMessage(JSONObject().put("hidden", false)) }
        runCatching { port.disconnect() }
    }

    private val portDelegate = object : WebExtension.PortDelegate {
        override fun onDisconnect(port: WebExtension.Port) {
            if (ports[port.sender.session] === port) ports.remove(port.sender.session)
        }
    }

    private val delegate = object : WebExtension.MessageDelegate {
        override fun onConnect(port: WebExtension.Port) {
            val sender = port.sender
            val session = sender.session
            if (closed || session == null || session !in sessions || port.name != NATIVE_APP ||
                sender.webExtension.id != EXTENSION_ID ||
                sender.environmentType != WebExtension.MessageSender.ENV_TYPE_CONTENT_SCRIPT ||
                !sender.isTopLevel || !sameNodeOrigin(nodeBase, sender.url) ||
                !sameNodeOrigin(nodeBase, locations[session])) {
                port.disconnect()
                return
            }
            ports.remove(session)?.let(::disconnect)
            ports[session] = port
            port.setDelegate(portDelegate)
            send(port)
        }
    }

    companion object {
        private const val EXTENSION_ID = "browser-ext@epix.zone"
        private const val NATIVE_APP = "epix_browser_controls"

        internal fun sameNodeOrigin(base: String?, url: String?): Boolean = try {
            val expected = URI(base ?: "")
            val actual = URI(url ?: "")
            expected.scheme == "http" && expected.host == "127.0.0.1" && expected.port in 1..65535 &&
                expected.rawUserInfo == null && expected.rawQuery == null && expected.rawFragment == null &&
                expected.rawPath.orEmpty() in listOf("", "/") &&
                actual.scheme == expected.scheme && actual.host == expected.host &&
                actual.port == expected.port && actual.rawUserInfo == null
        } catch (_: Exception) { false }
    }
}
