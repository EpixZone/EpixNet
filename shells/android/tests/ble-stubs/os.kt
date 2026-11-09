package android.os

import java.util.UUID
import java.util.concurrent.ConcurrentLinkedQueue

object Build { object VERSION { @JvmField var SDK_INT = 37 } }
class Looper { companion object { fun getMainLooper() = Looper() } }
class Handler(@Suppress("UNUSED_PARAMETER") looper: Looper) {
    fun post(task: Runnable): Boolean { queue.add(task); return true }
    companion object {
        private val queue = ConcurrentLinkedQueue<Runnable>()
        fun drain() { while (true) (queue.poll() ?: return).run() }
    }
}
data class ParcelUuid(val uuid: UUID)
object SystemClock { fun elapsedRealtime() = System.nanoTime() / 1_000_000 }
