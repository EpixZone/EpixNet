package zone.epix.app

import android.content.Context
import android.os.Looper
import android.util.Log
import java.lang.ref.WeakReference
import java.util.concurrent.atomic.AtomicReference
import org.mozilla.geckoview.GeckoResult
import org.mozilla.geckoview.GeckoRuntime
import org.mozilla.geckoview.GeckoSession
import org.mozilla.geckoview.WebExtension

private var checks = 0
private fun verify(value: Boolean, message: String) {
    checks++
    check(value) { message }
}

private class ActivityContext(override val applicationContext: Context) : Context()

private class Host : WalletHost {
    override var walletHostActive = true
    val installed = mutableListOf<WebExtension>()
    val messages = mutableListOf<Triple<String, Any, WebExtension.MessageSender>>()
    val actions = mutableListOf<Pair<String, WebExtension>>()
    val details = mutableListOf<WebExtension.CreateTabDetails>()
    val messageResult = GeckoResult.fromValue<Any>(Any())
    val sessionResult = GeckoResult.fromValue(GeckoSession())
    override fun onWalletInstalled(extension: WebExtension) { installed.add(extension) }
    override fun onWalletMessage(nativeApp: String, message: Any, sender: WebExtension.MessageSender): GeckoResult<Any> {
        messages.add(Triple(nativeApp, message, sender))
        return messageResult
    }
    override fun onWalletTogglePopup(extension: WebExtension, action: WebExtension.Action): GeckoResult<GeckoSession> {
        actions.add("toggle" to extension)
        return sessionResult
    }
    override fun onWalletOpenPopup(extension: WebExtension, action: WebExtension.Action): GeckoResult<GeckoSession> {
        actions.add("open" to extension)
        return sessionResult
    }
    override fun onWalletNewTab(source: WebExtension, details: WebExtension.CreateTabDetails): GeckoResult<GeckoSession> {
        actions.add("new" to source)
        this.details.add(details)
        return sessionResult
    }
}

private fun noHost(extension: WebExtension) {
    val reply = extension.boundMessage!!.onMessage("test.native", Any(), WebExtension.MessageSender())
    verify(reply != null && reply.settled, "no-host native message is settled")
    verify(reply!!.error is IllegalStateException, "no-host native message has a defined error")
    verify(extension.boundAction!!.onTogglePopup(extension, WebExtension.Action()) == null, "no-host toggle returns no session")
    verify(extension.boundAction!!.onOpenPopup(extension, WebExtension.Action()) == null, "no-host popup returns no session")
    verify(extension.tabDelegate!!.onNewTab(extension, WebExtension.CreateTabDetails()) == null, "no-host new tab returns no session")
}

private fun forwardsTo(extension: WebExtension, host: Host) {
    val message = Any()
    val sender = WebExtension.MessageSender()
    val details = WebExtension.CreateTabDetails()
    verify(extension.boundMessage!!.onMessage("test.native", message, sender) === host.messageResult, "native message result identity is preserved")
    val forwarded = host.messages.last()
    verify(forwarded.first == "test.native" && forwarded.second === message && forwarded.third === sender, "native message arguments preserve identity")
    verify(extension.boundAction!!.onTogglePopup(extension, WebExtension.Action()) === host.sessionResult, "toggle forwards to current host")
    verify(extension.boundAction!!.onOpenPopup(extension, WebExtension.Action()) === host.sessionResult, "popup forwards to current host")
    verify(extension.tabDelegate!!.onNewTab(extension, details) === host.sessionResult, "new tab forwards to current host")
    verify(host.details.last() === details, "new tab details preserve identity")
    verify(host.actions.takeLast(3) == listOf("toggle" to extension, "open" to extension, "new" to extension), "all UI hooks receive the extension")
}

private fun rejectedOffMain(action: () -> Unit) {
    val failure = AtomicReference<Throwable?>()
    val thread = Thread {
        try { action() } catch (error: Throwable) { failure.set(error) }
    }
    thread.start()
    thread.join(2_000)
    verify(!thread.isAlive, "off-main test worker finished")
    verify(failure.get() is IllegalStateException && failure.get()!!.message!!.contains("Main"), "off-main access fails before mutating ownership")
}

private fun runtime(): GeckoRuntime {
    val application = Context()
    val firstActivity = ActivityContext(application)
    val runtime = EmbeddedBrowserHost.runtime(firstActivity)
    verify(runtime.context === application, "runtime retains application context")
    verify(runtime.context !== firstActivity, "runtime does not retain initiating Activity context")
    verify(runtime.settings.extensionsProcessEnabled, "extension child process setting is preserved")
    verify(EmbeddedBrowserHost.runtime(ActivityContext(application)) === runtime, "replacement shares process runtime")
    verify(GeckoRuntime.creations == 1, "one runtime is created")
    return runtime
}

private fun replacement() {
    val runtime = runtime()
    val controller = runtime.webExtensionController
    val a = Host()
    val aToken = EmbeddedBrowserHost.attach(a)
    controller.synchronousFailure = IllegalStateException("synchronous install failure")
    EmbeddedBrowserHost.ensureWallet("wallet@test", "test.native")
    verify(controller.calls == 1 && Log.failures.size == 1, "synchronous failure is settled and logged")
    EmbeddedBrowserHost.ensureWallet("wallet@test", "test.native")
    EmbeddedBrowserHost.ensureWallet("wallet@test", "test.native")
    verify(controller.calls == 2, "duplicate pending install is coalesced")
    controller.installs.last().completeExceptionally(IllegalStateException("asynchronous install failure"))
    Looper.drain()
    verify(a.installed.isEmpty() && Log.failures.size == 2, "failed install does not attach an extension")
    EmbeddedBrowserHost.ensureWallet("wallet@test", "test.native")
    verify(controller.calls == 3, "failed asynchronous install retries")
    controller.installs.last().complete(null)
    Looper.drain()
    verify(Log.failures.size == 3 && a.installed.isEmpty(), "null install result is retryable failure")
    EmbeddedBrowserHost.ensureWallet("wallet@test", "test.native")
    EmbeddedBrowserHost.ensureWallet("wallet@test", "test.native")
    verify(controller.calls == 4, "retry after null result remains coalesced")
    val b = Host()
    val bToken = EmbeddedBrowserHost.attach(b)
    verify(aToken != bToken, "attachments have distinct identities")
    a.walletHostActive = false
    EmbeddedBrowserHost.detach(aToken)
    val extension = WebExtension()
    val completion = Thread { controller.installs.last().complete(extension) }
    completion.start()
    completion.join(2_000)
    verify(!completion.isAlive, "install completion worker finished")
    verify(a.installed.isEmpty() && b.installed.isEmpty(), "completion waits for Main before forwarding")
    Looper.drain()
    verify(a.installed.isEmpty() && b.installed.single() === extension, "late A installation delivers only to current B")
    verify(extension.messageBindings == 1 && extension.actionBindings == 1 && extension.tabBindings == 1, "delegates bind once after successful install")
    verify(extension.boundNativeApp == "test.native", "native messaging identity is preserved")
    forwardsTo(extension, b)
    verify(a.messages.isEmpty() && a.actions.isEmpty(), "old Activity receives no callbacks")
    val messageDelegate = extension.boundMessage
    val actionDelegate = extension.boundAction
    val tabDelegate = extension.tabDelegate
    EmbeddedBrowserHost.ensureWallet("wallet@test", "test.native")
    verify(controller.calls == 4 && b.installed.size == 1, "successful installation is retained without duplicate notification")
    EmbeddedBrowserHost.detach(bToken)
    EmbeddedBrowserHost.detach(bToken)
    noHost(extension)
    val c = Host()
    val cToken = EmbeddedBrowserHost.attach(c)
    verify(c.installed.single() === extension, "new attachment immediately receives cached extension")
    EmbeddedBrowserHost.detach(bToken)
    forwardsTo(extension, c)
    verify(extension.boundMessage === messageDelegate && extension.boundAction === actionDelegate && extension.tabDelegate === tabDelegate, "replacement does not replace stable process delegates")
    verify(extension.messageBindings == 1 && extension.actionBindings == 1 && extension.tabBindings == 1, "old detach does not erase or rebind delegates")
    c.walletHostActive = false
    noHost(extension)
    verify(c.messages.size == 1 && c.actions.size == 3, "inactive attached Activity receives no UI work")
    EmbeddedBrowserHost.detach(cToken)
    val d = Host()
    val dToken = EmbeddedBrowserHost.attach(d)
    val fields = EmbeddedBrowserHost.javaClass.declaredFields.map { field -> field.isAccessible = true; field.get(EmbeddedBrowserHost) }
    verify(fields.none { it is WalletHost }, "process owner has no strong WalletHost field")
    val weak = fields.filterIsInstance<WeakReference<*>>().single()
    verify(weak.get() === d, "current attachment is held weakly")
    weak.clear() // Deterministically model collection; never depend on GC timing.
    noHost(extension)
    EmbeddedBrowserHost.detach(dToken)
    val e = Host()
    val eToken = EmbeddedBrowserHost.attach(e)
    rejectedOffMain { EmbeddedBrowserHost.runtime(Context()) }
    rejectedOffMain { EmbeddedBrowserHost.attach(Host()) }
    rejectedOffMain { EmbeddedBrowserHost.detach(eToken) }
    rejectedOffMain { EmbeddedBrowserHost.ensureWallet("wallet@test", "test.native") }
    rejectedOffMain { extension.boundMessage!!.onMessage("test.native", Any(), WebExtension.MessageSender()) }
    verify(GeckoRuntime.creations == 1 && controller.calls == 4, "rejected background access did not create runtime or install")
    forwardsTo(extension, e)
    EmbeddedBrowserHost.detach(eToken)
    noHost(extension)
}

private fun detachedInstall() {
    val runtime = runtime()
    val a = Host()
    val token = EmbeddedBrowserHost.attach(a)
    EmbeddedBrowserHost.ensureWallet("wallet@test", "test.native")
    a.walletHostActive = false
    EmbeddedBrowserHost.detach(token)
    val extension = WebExtension()
    runtime.webExtensionController.installs.single().complete(extension)
    Looper.drain()
    verify(a.installed.isEmpty(), "installation with no current host does not revive old Activity")
    noHost(extension)
    val b = Host()
    val bToken = EmbeddedBrowserHost.attach(b)
    verify(b.installed.single() === extension, "installation completed without a host is retained")
    EmbeddedBrowserHost.detach(token)
    forwardsTo(extension, b)
    EmbeddedBrowserHost.ensureWallet("wallet@test", "test.native")
    verify(runtime.webExtensionController.calls == 1, "recreation after detached install does not reinstall")
    EmbeddedBrowserHost.detach(bToken)
    noHost(extension)
}

fun main(args: Array<String>) {
    Looper.getMainLooper()
    when (args.single()) {
        "replacement" -> replacement()
        "detached-install" -> detachedInstall()
        else -> error("unknown scenario")
    }
    println("0 Android browser-host regression failures, $checks checks (${args.single()})")
}
