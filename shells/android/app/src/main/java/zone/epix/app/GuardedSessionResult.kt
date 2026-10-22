package zone.epix.app

import org.mozilla.geckoview.GeckoResult
import org.mozilla.geckoview.GeckoSession

/** Check ownership when Gecko consumes the result, including after it was completed. */
internal fun guardedSessionResult(
    session: GeckoSession,
    isActive: () -> Boolean,
): GeckoResult<GeckoSession> = GuardedSessionResult(session, isActive)

private class GuardedSessionResult(
    session: GeckoSession,
    private val isActive: () -> Boolean,
) : GeckoResult<GeckoSession>() {
    init {
        complete(session)
    }

    // Gecko's map() delegates to this overload. Its handler posts the consumer,
    // so checking only before complete() would allow a disposed owner to open a tab.
    override fun <U> then(
        onValue: OnValueListener<GeckoSession, U>?,
        onException: OnExceptionListener<U>?,
    ): GeckoResult<U> {
        val guarded = onValue?.let { consumer ->
            OnValueListener<GeckoSession, U> { value ->
                check(isActive()) { "The session owner has been disposed" }
                consumer.onValue(value)
            }
        }
        return super.then(guarded, onException)
    }
}
