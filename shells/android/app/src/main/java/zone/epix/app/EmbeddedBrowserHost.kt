package zone.epix.app

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.lang.ref.WeakReference
import org.mozilla.geckoview.GeckoResult
import org.mozilla.geckoview.GeckoRuntime
import org.mozilla.geckoview.GeckoRuntimeSettings
import org.mozilla.geckoview.GeckoSession
import org.mozilla.geckoview.WebExtension

/** Activity-owned wallet work. Pending results remain the Activity's responsibility. */
internal interface WalletHost {
    val walletHostActive: Boolean
    fun onWalletInstalled(extension: WebExtension)
    fun onWalletMessage(
        nativeApp: String,
        message: Any,
        sender: WebExtension.MessageSender,
    ): GeckoResult<Any>?
    fun onWalletTogglePopup(
        extension: WebExtension,
        action: WebExtension.Action,
    ): GeckoResult<GeckoSession>?
    fun onWalletOpenPopup(
        extension: WebExtension,
        action: WebExtension.Action,
    ): GeckoResult<GeckoSession>?
    fun onWalletNewTab(
        source: WebExtension,
        details: WebExtension.CreateTabDetails,
    ): GeckoResult<GeckoSession>?
}

/**
 * Process-owned runtime and wallet installation. All access runs on Main.
 *
 * Activities own their sessions, dialogs, and pending results. The process
 * delegates resolve a weak attachment for each call and never retain an
 * Activity callback. Apply routing preferences before installing or loading
 * anything through this runtime.
 */
internal object EmbeddedBrowserHost {
    private var browserRuntime: GeckoRuntime? = null
    private var wallet: WebExtension? = null
    private var activity: WeakReference<WalletHost>? = null
    private var attachmentToken = 0L
    private var installationToken = 0L
    private var pendingInstallation: Long? = null
    private var walletIdentity: Pair<String, String>? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    fun runtime(context: Context): GeckoRuntime {
        requireMainThread()
        return browserRuntime ?: GeckoRuntime.create(
            context.applicationContext,
            GeckoRuntimeSettings.Builder()
                // Gecko's media permission observer runs in child processes.
                .extensionsProcessEnabled(true)
                .build(),
        ).also { browserRuntime = it }
    }

    /** Replaces the UI attachment without reinstalling or rebinding delegates. */
    fun attach(host: WalletHost): Long {
        requireMainThread()
        val token = ++attachmentToken
        activity = WeakReference(host)
        wallet?.let { currentHost()?.onWalletInstalled(it) }
        return token
    }

    /** A destroyed Activity cannot detach a replacement that attached later. */
    fun detach(token: Long) {
        requireMainThread()
        if (token != attachmentToken) return
        activity?.clear()
        activity = null
    }

    /** Coalesces an in-flight install; a failed install can retry on the next call. */
    fun ensureWallet(extensionId: String, nativeApp: String) {
        requireMainThread()
        val runtime = checkNotNull(browserRuntime) { "Initialize the browser runtime first" }
        val identity = extensionId to nativeApp
        require(extensionId.isNotBlank() && nativeApp.isNotBlank()) { "Wallet identity is required" }
        check(walletIdentity == null || walletIdentity == identity) { "Wallet identity cannot change within a process" }
        walletIdentity = identity
        if (wallet != null || pendingInstallation != null) return

        val token = ++installationToken
        pendingInstallation = token
        val installation = try {
            runtime.webExtensionController.ensureBuiltIn(
                "resource://android/assets/extensions/wallet/", extensionId,
            )
        } catch (error: Exception) {
            installFailed(token, error)
            return
        }
        // GeckoResult can finish after the initiating Activity is gone. Its
        // callbacks capture only process state and resolve the current host.
        installation.withHandler(mainHandler).accept({ extension ->
            requireMainThread()
            if (pendingInstallation != token) return@accept
            if (extension == null) {
                installFailed(token, IllegalStateException("Wallet installation returned no extension"))
                return@accept
            }
            try {
                extension.setMessageDelegate(messageDelegate, nativeApp)
                extension.setActionDelegate(actionDelegate)
                extension.tabDelegate = tabDelegate
            } catch (error: Exception) {
                installFailed(token, error)
                return@accept
            }
            wallet = extension
            pendingInstallation = null
            currentHost()?.onWalletInstalled(extension)
        }, { error ->
            installFailed(token, error ?: IllegalStateException("Wallet installation failed"))
        })
    }

    private fun installFailed(token: Long, error: Throwable) {
        requireMainThread()
        if (pendingInstallation != token) return
        pendingInstallation = null
        Log.w("EpixWallet", "wallet install failed", error)
    }

    private fun currentHost(): WalletHost? {
        requireMainThread()
        return activity?.get()?.takeIf { it.walletHostActive }
    }

    private fun requireMainThread() {
        check(Looper.myLooper() === Looper.getMainLooper()) { "Browser host access must run on Main" }
    }

    private val messageDelegate = object : WebExtension.MessageDelegate {
        override fun onMessage(
            nativeApp: String,
            message: Any,
            sender: WebExtension.MessageSender,
        ): GeckoResult<Any>? {
            val host = currentHost() ?: return GeckoResult.fromException(
                IllegalStateException("Wallet UI is not attached"),
            )
            return host.onWalletMessage(nativeApp, message, sender)
        }
    }

    private val actionDelegate = object : WebExtension.ActionDelegate {
        override fun onTogglePopup(
            extension: WebExtension,
            action: WebExtension.Action,
        ): GeckoResult<GeckoSession>? = currentHost()?.onWalletTogglePopup(extension, action)

        override fun onOpenPopup(
            extension: WebExtension,
            action: WebExtension.Action,
        ): GeckoResult<GeckoSession>? = currentHost()?.onWalletOpenPopup(extension, action)
    }

    private val tabDelegate = object : WebExtension.TabDelegate {
        override fun onNewTab(
            source: WebExtension,
            details: WebExtension.CreateTabDetails,
        ): GeckoResult<GeckoSession>? = currentHost()?.onWalletNewTab(source, details)
    }
}
