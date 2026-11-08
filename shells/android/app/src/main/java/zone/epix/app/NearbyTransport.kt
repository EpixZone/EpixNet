package zone.epix.app

import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicBoolean

internal enum class NearbyKind { BLE, WIFI_AWARE }

internal enum class NearbyState {
    STOPPED, STARTING, DISCOVERING, UNSUPPORTED, UNAVAILABLE, PERMISSION_REQUIRED, FAILED
}

internal data class NearbyStatus(val state: NearbyState, val detail: String)

/** Hardware/API capability only. A supported transport can still need permission or be unavailable. */
internal data class NearbyCapability(val supported: Boolean, val detail: String)

/**
 * An untrusted, temporary bearer. Neither its label nor its ID identifies a Reticulum peer.
 * The recipient owns stream pumping and must close the connection in its pump's finally block.
 * Transport stop also closes it. Read, write and close belong on IO workers, never the UI thread.
 */
internal class NearbyConnection(
    val id: String,
    val kind: NearbyKind,
    val label: String,
    val input: InputStream,
    val output: OutputStream,
    private val closeTransport: () -> Unit,
) : Closeable {
    private val closed = AtomicBoolean(false)

    override fun close() {
        if (closed.compareAndSet(false, true)) closeTransport()
    }
}

/**
 * The coordinator owns opt-in and permission prompts. Implementations never enable radios.
 * start/stop are safe from any thread. Listener callbacks run on the Android main thread.
 * stop invalidates pending callbacks immediately and schedules resource closure off the main thread.
 */
internal interface NearbyTransport {
    val kind: NearbyKind
    fun capability(): NearbyCapability
    fun start(listener: Listener)
    fun stop()

    interface Listener {
        fun onStatus(kind: NearbyKind, status: NearbyStatus)
        fun onConnection(connection: NearbyConnection)
    }
}
