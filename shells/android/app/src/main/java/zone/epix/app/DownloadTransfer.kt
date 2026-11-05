package zone.epix.app

import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.CancellationException
import java.util.concurrent.atomic.AtomicBoolean

/** Owns Gecko's response body. Saving never makes a second network request. */
internal class DownloadTransfer(private val body: InputStream) {
    private val lock = Any()
    private val closed = AtomicBoolean(false)
    private var cancelled = false
    private var completed = false

    val isComplete: Boolean get() = synchronized(lock) { completed }

    fun cancel() {
        synchronized(lock) {
            if (completed) return
            cancelled = true
        }
        closeBody()
    }

    private fun checkActive() = synchronized(lock) {
        if (cancelled) throw CancellationException("Download cancelled")
    }

    private fun closeBody() {
        if (closed.compareAndSet(false, true)) runCatching { body.close() }
    }

    /** Caller provides the user-selected destination on IO; both streams are always closed. */
    fun save(openOutput: () -> OutputStream): Long {
        try {
            checkActive()
            var total = 0L
            openOutput().use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    checkActive()
                    val count = body.read(buffer)
                    if (count < 0) break
                    checkActive()
                    output.write(buffer, 0, count)
                    total += count
                }
                output.flush()
            }
            synchronized(lock) {
                checkActive()
                completed = true
            }
            return total
        } finally {
            closeBody()
        }
    }
}

/** The suggested title is untrusted metadata, never a path in our filesystem. */
internal fun safeDownloadName(suggested: String): String = suggested
    .replace('\\', '/')
    .substringAfterLast('/')
    .filter { it >= ' ' && it != '\u007f' && it !in '\u202a'..'\u202e' && it !in '\u2066'..'\u2069' }
    .trim().take(180)
    .takeUnless { it.isBlank() || it == "." || it == ".." }
    ?: "download"
