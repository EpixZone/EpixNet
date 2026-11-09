package zone.epix.app

import java.io.Closeable
import java.io.EOFException
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

internal data class NearbyRead(val data: ByteArray, val closed: Boolean)

internal interface NativeNearbyStream : Closeable {
    fun write(bytes: ByteArray, timeoutMs: Int)
    fun read(maxBytes: Int, timeoutMs: Int): NearbyRead
}

/** Platform sockets are untrusted byte bearers; Rust owns framing and peer authentication. */
internal suspend fun pumpNearby(connection: NearbyConnection, native: NativeNearbyStream, chunkSize: Int = 4096) {
    val closed = AtomicBoolean(false)
    suspend fun closeStreams() = withContext(NonCancellable + Dispatchers.IO) {
        if (closed.compareAndSet(false, true)) {
            runCatching { connection.close() }
            runCatching { native.close() }
        }
    }
    try {
        require(chunkSize in 1..4096)
        withContext(Dispatchers.IO) {
            coroutineScope {
                // Either direction can block inside a platform stream. This child
                // can close them even while both pump workers cannot resume.
                val cancellation = launch(Dispatchers.IO, start = CoroutineStart.UNDISPATCHED) {
                    try { awaitCancellation() } finally { closeStreams() }
                }
                val reader = launch(Dispatchers.IO) {
                    val buffer = ByteArray(chunkSize)
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val count = connection.input.read(buffer)
                        // Closure during normal shutdown must not turn EOF into
                        // a new failure after this child was already cancelled.
                        currentCoroutineContext().ensureActive()
                        if (count < 0) throw EOFException("Nearby connection closed")
                        if (count > 0) native.write(buffer.copyOf(count), 5000)
                    }
                }
                try {
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val next = native.read(chunkSize, 500)
                        if (next.data.size > chunkSize) throw IOException("Native radio chunk exceeds limit")
                        if (next.data.isNotEmpty()) connection.output.write(next.data)
                        if (next.closed) break
                    }
                } finally {
                    reader.cancel()
                    cancellation.cancel()
                    // Close before coroutineScope joins the blocked reader.
                    closeStreams()
                }
            }
        }
    } finally {
        // Also covers cancellation before withContext starts either pump.
        closeStreams()
    }
}
