package zone.epix.app

/** Main-thread replies: register before dispatch and settle exactly once. */
internal class PendingOperations {
    private val operations = mutableSetOf<Operation>()
    private var closed = false

    inner class Operation internal constructor(
        internal val owner: Any?,
        private var onCancel: (() -> Unit)?,
    ) {
        var pending = true
            private set

        fun complete(action: () -> Unit) {
            if (!pending) return
            pending = false
            operations.remove(this)
            onCancel = null
            runCatching(action)
        }

        fun cancel() {
            val action = onCancel ?: return
            complete(action)
        }
    }

    fun register(owner: Any? = null, onCancel: () -> Unit): Operation {
        val operation = Operation(owner, onCancel)
        operations.add(operation)
        if (closed) operation.cancel()
        return operation
    }

    fun cancelOwner(owner: Any) {
        operations.filter { it.owner === owner }.forEach { it.cancel() }
    }

    fun cancelAll() {
        closed = true
        operations.toList().forEach { it.cancel() }
    }
}
