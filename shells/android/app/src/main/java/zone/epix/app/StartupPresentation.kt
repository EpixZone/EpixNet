package zone.epix.app

/** Completed lifecycle stages, never an estimate of time or network progress. */
internal enum class SplashStage(val status: String, val detail: String) {
    PREPARING("Starting EpixNet", "Getting your local workspace ready."),
    SETTINGS("Loading your settings", "Loading your saved preferences and identities."),
    XITES("Restoring your xites", "Checking the xites saved on this device."),
    DATABASES("Preparing local databases", "Preparing your saved content for browsing."),
    SERVICES("Starting network services", "Peers connect in the background."),
    CONNECTING("Connecting your browser", "Checking that the local browser connection is ready."),
    OPENING("Opening Epix Browser", "Waiting for your first page to appear."),
    READY("Epix Browser is ready", "Enjoy browsing EpixNet."),
}

internal class StartupPresentation {
    var stage = SplashStage.PREPARING
        private set
    private var error: String? = null
    val failed: Boolean get() = error != null
    val status: String get() = if (failed) "EpixNet couldn’t start" else stage.status
    val detail: String get() = error ?: stage.detail
    val completed: Int get() = stage.ordinal
    val total: Int get() = SplashStage.READY.ordinal

    fun reset() {
        stage = SplashStage.PREPARING
        error = null
    }

    fun advance(next: SplashStage) {
        if (!failed && next > stage) stage = next
    }

    fun fail(message: String) {
        error = message.ifBlank { "The local browser connection did not become ready." }
    }
}
