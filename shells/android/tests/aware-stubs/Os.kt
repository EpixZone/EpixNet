package android.os

object Build { object VERSION { var SDK_INT = 37 } }
class Looper { companion object { fun getMainLooper() = Looper() } }
object SystemClock { fun uptimeMillis() = TestMain.now }
object TestMain {
    data class Pending(val action: Runnable, val token: Any?, val due: Long)
    private val queue = mutableListOf<Pending>()
    var now = 0L
    @Synchronized fun add(action: Runnable, token: Any?, due: Long) { queue.add(Pending(action, token, due)) }
    @Synchronized fun remove(token: Any) { queue.removeAll { it.token === token } }
    fun drain() {
        repeat(1000) {
            val item = synchronized(this) {
                queue.indexOfFirst { it.due <= now }.takeIf { it >= 0 }?.let(queue::removeAt)
            } ?: return
            item.action.run()
        }
        error("unbounded main callbacks")
    }
    fun advance(millis: Long) { now += millis; drain() }
}
class Handler(looper: Looper) {
    fun post(action: Runnable): Boolean { TestMain.add(action, null, TestMain.now); return true }
    fun postAtTime(action: Runnable, token: Any, due: Long): Boolean { TestMain.add(action, token, due); return true }
    fun removeCallbacksAndMessages(token: Any) { TestMain.remove(token) }
}
