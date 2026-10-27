package zone.epix.app

import java.net.URI
import java.util.Locale

/** Native installer policy. A xite or extension cannot grant itself these capabilities. */
internal object AddonPolicy {
    private val reservedIds = setOf(
        "wallet@epix.zone", "theme@epix.zone", "browser-ext@epix.zone", "installer@epix.zone",
    )
    private val nativePermissions = setOf(
        "nativemessaging", "nativemessagingfromcontent", "geckoviewaddons", "experiment_apis",
    )

    fun reserved(id: String): Boolean = id.lowercase(Locale.ROOT) in reservedIds

    fun permits(id: String, required: List<String>, optional: List<String>): Boolean =
        id.isNotBlank() && id.length <= 255 && !reserved(id) &&
            (required + optional).none { it.lowercase(Locale.ROOT) in nativePermissions }

    /** Extension-created UI may open its own pages or ordinary web pages, never another extension. */
    fun permitsNavigation(extensionBase: String, target: String?): Boolean {
        if (target == null || target == "about:blank") return true
        return try {
            val uri = URI(target)
            if (uri.rawUserInfo != null || uri.host.isNullOrEmpty()) return false
            when (uri.scheme?.lowercase(Locale.ROOT)) {
                "http", "https" -> true
                "moz-extension" -> {
                    val base = URI(extensionBase)
                    base.scheme == "moz-extension" && uri.host == base.host && uri.port == base.port
                }
                else -> false
            }
        } catch (_: Exception) {
            false
        }
    }
}

/** A single native request remains bound to the Activity that initiated it. */
internal class AddonLifecycle {
    enum class Phase { PREPARING, CHECKING_ENGINE, CONSENT, APPROVED, RECONCILING }
    data class Request(
        val serial: Long,
        val attachment: Long,
        var phase: Phase = Phase.PREPARING,
        var operationId: String? = null,
        var addonId: String? = null,
        var version: String? = null,
        var expiry: Long = 0,
    )
    private var serial = 0L
    private var attachment = 0L
    private var attached = false
    var pending: Request? = null
        private set

    fun attach(): Long {
        attachment += 1
        attached = true
        return attachment
    }

    fun attached(token: Long): Boolean = attached && token == attachment

    fun detach(token: Long): Request? {
        if (!attached(token)) return null
        attached = false
        return pending?.takeIf { it.attachment == token }?.also { it.phase = Phase.RECONCILING }
    }

    fun begin(): Request {
        check(attached) { "Extension UI is not attached" }
        check(pending == null) { "Another extension operation is still pending" }
        return Request(++serial, attachment).also { pending = it }
    }

    fun live(request: Request): Boolean =
        attached && attachment == request.attachment && pending === request &&
            request.phase != Phase.RECONCILING

    fun prepared(request: Request, operationId: String, addonId: String, version: String, expiry: Long): Boolean {
        if (!live(request) || request.phase != Phase.PREPARING) return false
        request.operationId = operationId
        request.addonId = addonId
        request.version = version
        request.expiry = expiry
        request.phase = Phase.CHECKING_ENGINE
        return true
    }

    fun prompt(request: Request, addonId: String, version: String, now: Long): Boolean {
        if (!matches(request, addonId, version, now) || request.phase != Phase.CHECKING_ENGINE) return false
        request.phase = Phase.CONSENT
        return true
    }

    fun approve(request: Request, now: Long): Boolean {
        if (!live(request) || request.phase != Phase.CONSENT || now >= request.expiry) return false
        request.phase = Phase.APPROVED
        return true
    }

    fun mayComplete(request: Request, addonId: String, version: String): Boolean =
        live(request) && request.phase == Phase.APPROVED &&
            request.addonId == addonId && request.version == version

    fun reconcile(request: Request) {
        if (pending === request) request.phase = Phase.RECONCILING
    }

    /** Never let a callback from an older install release a newer request. */
    fun finish(request: Request): Boolean {
        if (pending !== request) return false
        pending = null
        return true
    }

    private fun matches(request: Request, addonId: String, version: String, now: Long): Boolean =
        live(request) && request.addonId == addonId && request.version == version && now < request.expiry
}
