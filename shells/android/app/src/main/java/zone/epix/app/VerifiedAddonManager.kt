package zone.epix.app

import android.net.Uri
import android.os.Handler
import android.os.Looper
import java.io.File
import java.lang.ref.WeakReference
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.mozilla.geckoview.AllowOrDeny
import org.mozilla.geckoview.GeckoResult
import org.mozilla.geckoview.GeckoRuntime
import org.mozilla.geckoview.GeckoSession
import org.mozilla.geckoview.WebExtension
import org.mozilla.geckoview.WebExtensionController
import uniffi.epix_ffi.AddonAction
import uniffi.epix_ffi.AddonCandidate
import uniffi.epix_ffi.AddonEngine
import uniffi.epix_ffi.AddonErrorCode
import uniffi.epix_ffi.AddonFailure
import uniffi.epix_ffi.AddonEngineOutcome
import uniffi.epix_ffi.AddonInstalled
import uniffi.epix_ffi.AddonInventory
import uniffi.epix_ffi.AddonPhase
import uniffi.epix_ffi.AddonSession
import uniffi.epix_ffi.EpixNode

internal interface AddonHost {
    val addonHostActive: Boolean
    fun onAddonsChanged()
    fun askAddonPermission(title: String, message: String, answer: (Boolean) -> Unit)
    fun onAddonNewTab(source: WebExtension, details: WebExtension.CreateTabDetails): GeckoResult<GeckoSession>?
    fun onAddonPopup(source: WebExtension, action: WebExtension.Action): GeckoResult<GeckoSession>?
    fun onAddonOptions(source: WebExtension)
    fun onAddonCloseTab(session: GeckoSession): Boolean
    fun onAddonSelectTab(session: GeckoSession): Boolean
}

/** Process-owned ordinary extensions. It never installs wallet delegates or a native message host. */
internal object VerifiedAddonManager {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val main = Handler(Looper.getMainLooper())
    private val lifecycle = AddonLifecycle()
    private var host = WeakReference<AddonHost>(null)
    private var runtime: GeckoRuntime? = null
    private var profile: AddonProfile? = null
    private val startupMutex = Mutex()
    private var snapshot: AddonSession? = null
    private var sessionNode: EpixNode? = null
    private var refreshing = false
    private var maintenance = false
    private var operationFailure: String? = null
    private var installResult: GeckoResult<WebExtension>? = null
    private var candidate: AddonCandidate? = null
    private var stageUri: String? = null
    private var updateId: String? = null
    private var pendingConsent: (() -> Unit)? = null
    private val optionalDenials = mutableSetOf<() -> Unit>()
    private val sessions = mutableSetOf<GeckoSession>()
    private val actions = mutableMapOf<String, WebExtension.Action>()
    private val pageActions = mutableMapOf<Pair<String, GeckoSession>, WebExtension.Action>()
    var extensions: List<WebExtension> = emptyList()
        private set
    var message: String = "Start the node to manage extensions."
        private set
    val busy: Boolean get() = refreshing || maintenance || lifecycle.pending != null
    val ownership get() = snapshot?.managed.orEmpty()
    val canInstall: Boolean get() = !busy && snapshot?.needsReconciliation == false

    suspend fun prepareProfile(files: File): AddonProfile = startupMutex.withLock {
        if (runtime != null) checkNotNull(profile)
        else withContext(Dispatchers.IO) { AddonProfile.prepare(files) }.also { profile = it }
    }

    fun initialize(value: GeckoRuntime, preparedProfile: AddonProfile) {
        checkMain()
        check(runtime == null || runtime === value)
        runtime = value; profile = preparedProfile
        value.webExtensionController.setPromptDelegate(promptDelegate)
    }

    fun attach(value: AddonHost): Long {
        checkMain()
        lifecycle.pending?.let(::cancel)
        pendingConsent?.invoke(); pendingConsent = null
        optionalDenials.toList().forEach { it() }; optionalDenials.clear()
        host = WeakReference(value)
        return lifecycle.attach()
    }

    fun detach(token: Long) {
        checkMain()
        if (!lifecycle.attached(token)) return
        val request = lifecycle.detach(token)
        if (request != null) cancel(request)
        pendingConsent?.invoke(); pendingConsent = null
        optionalDenials.toList().forEach { it() }
        optionalDenials.clear()
        host.clear()
    }

    fun refresh() {
        checkMain()
        if (busy) return
        operationFailure = null
        scope.launch { refreshNow() }
    }

    private suspend fun refreshNow() {
        if (refreshing || runtime == null || lifecycle.pending != null) return
        refreshing = true; changed()
        try {
            val node = checkNotNull(EmbeddedNodeHost.node) { "Start the node to manage extensions." }
            val storage = checkNotNull(profile)
            val engine = checkNotNull(runtime).webExtensionController.list().await().filterNot { it.isBuiltIn }
            val state = withContext(Dispatchers.IO) {
                val opened = if (sessionNode !== node || snapshot == null) node.addonOpenSession(storage.profileId, AddonEngine.GECKO) else checkNotNull(snapshot)
                val native = storage.ledger()
                val inventory = engine.map { ext ->
                    AddonInstalled(ext.id, ext.metaData.version, storage.approvedHash(ext.id, ext.metaData.version, native), ext.metaData.enabled)
                }
                node.addonReconcile(opened.sessionId, AddonInventory(inventory, storage.hasStagedPackages()))
            }
            sessionNode = node; snapshot = state; extensions = engine
            // A complete engine inventory is authoritative only after the core has reconciled it.
            if (!state.needsReconciliation) withContext(Dispatchers.IO) {
                val native = storage.ledger()
                native.pending?.let { pending ->
                    val accepted = state.managed.any { it.addonId == pending.addonId && it.version == pending.version && it.archiveSha256 == pending.sha256 }
                    if (accepted) storage.finishInstall(pending) else storage.clearPending()
                }
                native.confirmed.filter { record -> state.managed.none { it.addonId == record.addonId } }.forEach { storage.removed(it.addonId) }
            }
            engine.forEach { ext -> if (managed(ext)) bind(ext) }
            message = operationFailure ?: when {
                state.operation?.phase == AddonPhase.STAGED -> "A verified update is staged. Restart the app to finish installing it."
                state.needsReconciliation -> "An interrupted or changed extension needs review before another install."
                else -> "Extensions are ready."
            }
        } catch (error: Exception) {
            snapshot = null
            message = error.message ?: "Extension state is unavailable."
        } finally { refreshing = false; changed() }
    }

    fun install(source: String, updateId: String? = null) {
        checkMain()
        if (!canInstall || currentHost() == null) return
        operationFailure = null
        val request = lifecycle.begin()
        val session = checkNotNull(snapshot)
        val node = checkNotNull(sessionNode)
        message = "Verifying the xite publisher and package…"; changed()
        scope.launch {
            try {
                val prepared = withContext(Dispatchers.IO) {
                    node.addonPrepare(session.sessionId, source, if (updateId == null) AddonAction.Install else AddonAction.Update(updateId))
                }
                check(AddonPolicy.permits(prepared.addonId, prepared.requiredPermissions, prepared.optionalPermissions)) { "This extension requests a reserved capability." }
                check(lifecycle.prepared(request, prepared.operationId, prepared.addonId, prepared.version, prepared.expiresAtMs.toLong())) { "The extension request was cancelled." }
                candidate = prepared
                this@VerifiedAddonManager.updateId = updateId
                verifyCurrentEngine(prepared, updateId)
                val staged = withContext(Dispatchers.IO) { node.addonStage(session.sessionId, prepared.operationId, prepared.archiveSha256) }
                check(lifecycle.live(request)) { "The extension request was cancelled." }
                stageUri = Uri.fromFile(File(staged.path)).toString()
                message = "Checking the Mozilla signature…"; changed()
                scope.launch {
                    delay((prepared.expiresAtMs.toLong() - System.currentTimeMillis()).coerceAtLeast(0))
                    if (lifecycle.pending === request && request.phase != AddonLifecycle.Phase.APPROVED) cancel(request)
                }
                val result = checkNotNull(runtime).webExtensionController.install(checkNotNull(stageUri))
                installResult = result
                val installed = result.await()
                check(lifecycle.mayComplete(request, installed.id, installed.metaData.version) && permitted(installed)) { "Installation finished after its approval was cancelled or changed." }
                val receipt = receipt(prepared)
                withContext(Dispatchers.IO) {
                    check(checkNotNull(profile).installedHash(installed.id) == prepared.archiveSha256) { "Installed archive differs from the verified package." }
                    node.addonReport(session.sessionId, prepared.operationId, AddonEngineOutcome.Installed(installed.id, installed.metaData.version, prepared.archiveSha256))
                    checkNotNull(profile).finishInstall(receipt)
                }
                message = "${prepared.name} installed."
            } catch (error: Exception) {
                val prepared = candidate?.takeIf { it.operationId == request.operationId }
                val postponed = error is WebExtension.InstallException && error.code == WebExtension.InstallException.ErrorCodes.ERROR_POSTPONED
                val recorded = if (postponed && prepared != null && lifecycle.mayComplete(request, prepared.addonId, prepared.version)) {
                    withContext(Dispatchers.IO) {
                        runCatching {
                            val storage = checkNotNull(profile)
                            check(storage.ledger().pending == receipt(prepared) && storage.stagedHash(prepared.addonId) == prepared.archiveSha256) { "The staged archive differs from approval." }
                            node.addonReport(session.sessionId, prepared.operationId, AddonEngineOutcome.Staged(prepared.addonId, prepared.version, prepared.archiveSha256))
                        }.isSuccess
                    }
                } else false
                if (recorded) message = "The verified update is staged. Restart the app to finish installing it."
                else {
                    rememberFailure(error, "Extension installation failed.")
                    withContext(Dispatchers.IO) { runCatching { node.addonCancel(session.sessionId, request.operationId) } }
                }
            } finally {
                pendingConsent?.invoke(); pendingConsent = null
                if (lifecycle.finish(request)) { installResult = null; candidate = null; stageUri = null; this@VerifiedAddonManager.updateId = null }
                changed(); refreshNow()
            }
        }
    }

    fun cancel() { lifecycle.pending?.let(::cancel) }
    private fun cancel(request: AddonLifecycle.Request) {
        lifecycle.reconcile(request)
        pendingConsent?.invoke(); pendingConsent = null
        installResult?.cancel()
        val session = snapshot ?: return
        scope.launch(Dispatchers.IO) { runCatching { sessionNode?.addonCancel(session.sessionId, request.operationId) } }
    }

    fun setEnabled(extension: WebExtension, enabled: Boolean) {
        if (busy || !managed(extension) || !permitted(extension)) return
        operationFailure = null
        maintenance = true; changed()
        scope.launch {
            try {
                val controller = checkNotNull(runtime).webExtensionController
                if (enabled) {
                    val current = controller.list().await().singleOrNull { it.id == extension.id }
                    val owned = ownership.singleOrNull { it.addonId == extension.id }
                    check(current != null && owned != null && managed(current) && permitted(current)) { "The installed extension changed." }
                    check(withContext(Dispatchers.IO) { checkNotNull(profile).installedHash(current.id) } == owned.archiveSha256) { "The installed extension archive changed." }
                    controller.enable(current, WebExtensionController.EnableSource.USER).await()
                }
                else controller.disable(extension, WebExtensionController.EnableSource.USER).await()
            } catch (error: Exception) { rememberFailure(error, "Unable to change extension state.") }
            finally { maintenance = false; refreshNow() }
        }
    }

    fun uninstall(extension: WebExtension) {
        if (busy || AddonPolicy.reserved(extension.id) || extension.isBuiltIn) return
        val session = snapshot ?: return
        val node = sessionNode ?: return
        operationFailure = null
        maintenance = true; changed()
        scope.launch {
            try {
                val operation = if (managed(extension)) withContext(Dispatchers.IO) { node.addonBeginUninstall(session.sessionId, extension.id) } else null
                checkNotNull(runtime).webExtensionController.uninstall(extension).awaitVoid()
                withContext(Dispatchers.IO) {
                    if (operation != null) node.addonReport(session.sessionId, operation.operationId, AddonEngineOutcome.Uninstalled(extension.id))
                    checkNotNull(profile).removed(extension.id)
                }
            } catch (error: Exception) { rememberFailure(error, "Unable to remove extension.") }
            finally { maintenance = false; refreshNow() }
        }
    }

    fun clickAction(extension: WebExtension, session: GeckoSession) {
        if (!managed(extension) || !extension.metaData.enabled || busy) return
        checkNotNull(runtime).webExtensionController.setTabActive(session, true)
        val action = pageActions[extension.id to session]?.let { override -> actions[extension.id]?.let { override.withDefault(it) } ?: override } ?: actions[extension.id]
        if (action != null) action.takeUnless { it.enabled == false }?.click()
        else currentHost()?.onAddonOptions(extension)
    }

    fun bindSession(session: GeckoSession) {
        sessions.add(session)
        extensions.filter(::managed).forEach { bindSession(it, session) }
    }
    fun unbindSession(session: GeckoSession) {
        sessions.remove(session)
        pageActions.keys.filter { it.second === session }.forEach { pageActions.remove(it) }
        extensions.forEach { session.webExtensionController.setTabDelegate(it, null); session.webExtensionController.setActionDelegate(it, null) }
    }
    fun selectSession(session: GeckoSession) { sessions.forEach { runtime?.webExtensionController?.setTabActive(it, it === session) } }

    private fun bind(extension: WebExtension) {
        if (!permitted(extension)) return
        extension.setActionDelegate(actionDelegate)
        extension.tabDelegate = tabDelegate
        sessions.forEach { bindSession(extension, it) }
    }
    private fun bindSession(extension: WebExtension, session: GeckoSession) {
        session.webExtensionController.setActionDelegate(extension, actionDelegate)
        session.webExtensionController.setTabDelegate(extension, object : WebExtension.SessionTabDelegate {
            override fun onCloseTab(source: WebExtension?, value: GeckoSession): GeckoResult<AllowOrDeny> =
                if (source?.id == extension.id && managed(extension) && currentHost()?.onAddonCloseTab(value) == true) GeckoResult.allow() else GeckoResult.deny()
            override fun onUpdateTab(source: WebExtension, value: GeckoSession, details: WebExtension.UpdateTabDetails): GeckoResult<AllowOrDeny> {
                if (source.id != extension.id || value !in sessions || !managed(extension) ||
                    !AddonPolicy.permitsNavigation(extension.metaData.baseUrl, details.url)) return GeckoResult.deny()
                if (details.active == true && currentHost()?.onAddonSelectTab(value) != true) return GeckoResult.deny()
                return GeckoResult.allow()
            }
        })
    }
    private val actionDelegate = object : WebExtension.ActionDelegate {
        override fun onBrowserAction(extension: WebExtension, session: GeckoSession?, action: WebExtension.Action) {
            if (!managed(extension)) return
            if (session == null) actions[extension.id] = action else if (session in sessions) pageActions[extension.id to session] = action
            changed()
        }
        override fun onPageAction(extension: WebExtension, session: GeckoSession?, action: WebExtension.Action) = onBrowserAction(extension, session, action)
        override fun onTogglePopup(extension: WebExtension, action: WebExtension.Action): GeckoResult<GeckoSession>? =
            if (managed(extension)) currentHost()?.onAddonPopup(extension, action) else null
        override fun onOpenPopup(extension: WebExtension, action: WebExtension.Action): GeckoResult<GeckoSession>? = onTogglePopup(extension, action)
    }
    private val tabDelegate = object : WebExtension.TabDelegate {
        override fun onOpenOptionsPage(source: WebExtension) {
            if (managed(source)) currentHost()?.onAddonOptions(source)
        }
        override fun onNewTab(source: WebExtension, details: WebExtension.CreateTabDetails): GeckoResult<GeckoSession>? =
            if (managed(source) && AddonPolicy.permitsNavigation(source.metaData.baseUrl, details.url)) currentHost()?.onAddonNewTab(source, details) else null
    }
    private val promptDelegate = object : WebExtensionController.PromptDelegate {
        override fun onInstallPromptRequest(extension: WebExtension, permissions: Array<String>, origins: Array<String>, dataCollectionPermissions: Array<String>): GeckoResult<WebExtension.PermissionPromptResponse> {
            val result = GeckoResult<WebExtension.PermissionPromptResponse>()
            val denied = WebExtension.PermissionPromptResponse(false, false, false)
            val request = lifecycle.pending
            val prepared = candidate
            if (request == null || prepared == null || !permitted(extension) || extension.metaData.downloadUrl != stageUri ||
                !lifecycle.prompt(request, extension.id, extension.metaData.version, System.currentTimeMillis())) return GeckoResult.fromValue(denied)
            val host = currentHost() ?: return GeckoResult.fromValue(denied)
            var settled = false
            fun deny() { if (!settled) { settled = true; result.complete(denied) } }
            pendingConsent = ::deny
            val text = "Publisher: ${prepared.publisher}\nPackage: ${prepared.innerPath}\nExtension: ${extension.id}\nVersion: ${extension.metaData.version}\n\nMozilla signature verified.\n\nRequired permissions and host access:\n${(prepared.requiredPermissions + prepared.hostPermissions + permissions.toList() + origins.toList()).distinct().joinToString("\n").ifEmpty { "None" }}\n\nData collection:\n${dataCollectionPermissions.joinToString("\n").ifEmpty { "None" }}\n\nXites share this browser's loopback host. Host access can cover multiple xites, not just the publisher."
            host.askAddonPermission("Install ${extension.metaData.name ?: prepared.name}?", text) { allowed ->
                if (!allowed || settled || !lifecycle.live(request)) { deny(); return@askAddonPermission }
                scope.launch {
                    try {
                        verifyCurrentEngine(prepared, updateId)
                        check(!settled && lifecycle.approve(request, System.currentTimeMillis())) { "The approval expired or was cancelled." }
                        withContext(Dispatchers.IO) { checkNotNull(profile).beginInstall(receipt(prepared)) }
                        if (!settled && lifecycle.live(request)) {
                            settled = true; result.complete(WebExtension.PermissionPromptResponse(true, false, false))
                        } else deny()
                    } catch (_: Exception) { deny() }
                }
            }
            return result
        }
        override fun onUpdatePrompt(extension: WebExtension, newPermissions: Array<String>, newOrigins: Array<String>, newDataCollectionPermissions: Array<String>): GeckoResult<AllowOrDeny> = GeckoResult.deny()
        override fun onOptionalPrompt(extension: WebExtension, permissions: Array<String>, origins: Array<String>, dataCollectionPermissions: Array<String>): GeckoResult<AllowOrDeny> {
            if (busy || !managed(extension) || !permitted(extension) || !AddonPolicy.permits(extension.id, permissions.toList(), emptyList())) return GeckoResult.deny()
            val owner = ownership.singleOrNull { it.addonId == extension.id } ?: return GeckoResult.deny()
            val host = currentHost() ?: return GeckoResult.deny()
            val result = GeckoResult<AllowOrDeny>(); var settled = false
            lateinit var deny: () -> Unit
            fun answer(allowed: Boolean) {
                if (settled) return
                settled = true; optionalDenials.remove(deny)
                result.complete(if (allowed && !busy && currentHost() === host && owner in ownership && managed(extension)) AllowOrDeny.ALLOW else AllowOrDeny.DENY)
            }
            deny = { answer(false) }; optionalDenials.add(deny)
            host.askAddonPermission("Additional extension permissions", "${extension.metaData.name ?: extension.id}\n\n${(permissions.toList() + origins.toList() + dataCollectionPermissions.toList()).joinToString("\n")}\n\nLoopback host access may cover multiple xites.", ::answer)
            return result
        }
    }

    private suspend fun verifyCurrentEngine(value: AddonCandidate, updating: String?) {
        val current = checkNotNull(runtime).webExtensionController.list().await()
        val existing = current.filter { it.id == value.addonId }
        val storage = checkNotNull(profile)
        val expected = snapshot?.managed?.firstOrNull { it.addonId == updating }
        if (updating == null) {
            check(existing.isEmpty()) { "This extension ID was installed outside this request." }
            check(withContext(Dispatchers.IO) { storage.installedHash(value.addonId) } == null) { "This extension ID already has a profile archive." }
        } else {
            check(updating == value.addonId && expected != null && existing.size == 1 && existing.single().metaData.version == expected.version && permitted(existing.single())) { "The installed extension changed while verifying its update." }
            check(withContext(Dispatchers.IO) { storage.installedHash(updating) } == expected.archiveSha256) { "The installed extension archive changed." }
        }
        check(!withContext(Dispatchers.IO) { storage.hasStagedPackages() }) { "Another extension update is staged." }
    }

    private fun rememberFailure(error: Exception, fallback: String) {
        operationFailure = when {
            error is AddonFailure.Rejected && error.code == AddonErrorCode.CANCELLED -> null
            error is AddonFailure.Rejected -> error.detail.ifBlank { fallback }
            error is WebExtension.InstallException -> when (error.code) {
                WebExtension.InstallException.ErrorCodes.ERROR_USER_CANCELED -> null
                WebExtension.InstallException.ErrorCodes.ERROR_SIGNEDSTATE_REQUIRED -> "The package has no valid Mozilla signature."
                WebExtension.InstallException.ErrorCodes.ERROR_CORRUPT_FILE -> "Gecko rejected the package because it is corrupt or its Mozilla signature is invalid."
                else -> error.message ?: fallback
            }
            else -> error.message ?: fallback
        }
        message = operationFailure ?: "Extension installation cancelled."
    }

    private fun receipt(value: AddonCandidate) = AddonProfile.Receipt(value.addonId, value.version, value.archiveSha256)
    private fun permitted(extension: WebExtension): Boolean = !extension.isBuiltIn && !extension.metaData.temporary &&
        extension.metaData.signedState == WebExtension.SignedStateFlags.SIGNED &&
        extension.metaData.blocklistState == WebExtension.BlocklistStateFlags.NOT_BLOCKED &&
        AddonPolicy.permits(extension.id, extension.metaData.requiredPermissions.toList(), extension.metaData.optionalPermissions.toList())
    private fun managed(extension: WebExtension): Boolean = snapshot?.managed?.any { it.addonId == extension.id && it.version == extension.metaData.version } == true
    private fun currentHost(): AddonHost? = host.get()?.takeIf { it.addonHostActive }
    private fun changed() { currentHost()?.onAddonsChanged() }
    private fun checkMain() = check(Looper.myLooper() === Looper.getMainLooper())
    private suspend fun <T : Any> GeckoResult<T>.await(): T = suspendCancellableCoroutine { continuation ->
        withHandler(main).accept({ value ->
            if (continuation.isActive) { if (value != null) continuation.resume(value) else continuation.resumeWithException(IllegalStateException("Gecko returned no result")) }
        }, { error -> if (continuation.isActive) continuation.resumeWithException(error ?: IllegalStateException("Gecko operation failed")) })
        continuation.invokeOnCancellation { main.post { cancel() } }
    }
    private suspend fun GeckoResult<Void>.awaitVoid(): Unit = suspendCancellableCoroutine { continuation ->
        withHandler(main).accept({ if (continuation.isActive) continuation.resume(Unit) }, { error -> if (continuation.isActive) continuation.resumeWithException(error ?: IllegalStateException("Gecko operation failed")) })
    }
}
