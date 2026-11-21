package zone.epix.app

import kotlinx.coroutines.*
import org.mozilla.geckoview.*

fun main() = runBlocking {
    var checks = 0
    fun verify(value: Boolean, detail: String) { checks++; check(value) { detail } }
    val base = "http://127.0.0.1:42222"
    for (url in listOf("$base/xite/", "$base/?query=1", "$base/xite/#hash")) {
        verify(FixbuttonScrollBridge.sameNodeOrigin(base, url), "local wrapper: $url")
    }
    for (url in listOf(null, "", "not a URI", "https://127.0.0.1:42222/", "http://127.0.0.1:1/",
        "http://localhost:42222/", "http://127.0.0.1.evil.test:42222/", "http://127.0.0.1:42222@evil.test/",
        "http://user@127.0.0.1:42222/", "file:///wrapper", "data:text/html,", "about:blank")) {
        verify(!FixbuttonScrollBridge.sameNodeOrigin(base, url), "reject untrusted origin: $url")
    }
    for (invalidBase in listOf(null, "http://remote.test:42222", "$base/path", "$base?x=1", "$base#hash",
        "http://user@127.0.0.1:42222", "http://127.0.0.1:0", "http://127.0.0.1:65536")) {
        verify(!FixbuttonScrollBridge.sameNodeOrigin(invalidBase, "$base/xite/"), "reject invalid node origin")
    }
    val bridge = FixbuttonScrollBridge()
    val runtime = GeckoRuntime()
    runtime.webExtensionController.result.complete(WebExtension())
    bridge.install(runtime)
    bridge.setNodeBase(base)
    val first = GeckoSession(); val second = GeckoSession()
    bridge.bindSession(first); bridge.bindSession(second)
    bridge.onLocationChanged(first, "$base/first/"); bridge.onLocationChanged(second, "$base/second/")
    bridge.selectSession(first)
    fun connect(session: GeckoSession, sender: WebExtension.MessageSender = WebExtension.MessageSender(session, "$base/xite/"),
        app: String = "epix_browser_controls"): WebExtension.Port = WebExtension.Port(sender, app).also {
        checkNotNull(session.webExtensionController.delegate).onConnect(it)
    }
    fun hidden(port: WebExtension.Port) = port.messages.last().values["hidden"]
    val firstPort = connect(first); val secondPort = connect(second)
    bridge.setChromeHidden(true)
    verify(hidden(firstPort) == false, "off by default")
    bridge.setEnabled(true)
    verify(hidden(firstPort) == true && hidden(secondPort) == false, "only active tab hides")
    bridge.selectSession(second)
    verify(hidden(firstPort) == false && hidden(secondPort) == true, "tab selection resynchronizes both ports")
    bridge.setEnabled(false)
    verify(hidden(secondPort) == false, "disabling restores a hidden button immediately")
    bridge.setEnabled(true); bridge.setChromeHidden(false)
    verify(hidden(secondPort) == false, "scroll up restores button")
    for (sender in listOf(
        WebExtension.MessageSender(first, "$base/xite/", isTopLevel = false),
        WebExtension.MessageSender(first, "$base/xite/", environmentType = 0),
        WebExtension.MessageSender(first, "$base/xite/", webExtension = WebExtension("other@extension")),
        WebExtension.MessageSender(null, "$base/xite/"),
        WebExtension.MessageSender(GeckoSession(), "$base/xite/"),
        WebExtension.MessageSender(first, "http://127.0.0.1:42/xite/"),
    )) {
        val rejected = connect(first, sender)
        verify(rejected.disconnected && rejected.messages.isEmpty(), "reject iframe, foreign, stale, or extension sender")
    }
    verify(connect(first, app = "another_app").disconnected, "reject another native app")
    val replacement = connect(first)
    verify(firstPort.disconnected && hidden(firstPort) == false, "new document releases previous port visibly")
    bridge.onLocationChanged(first, "https://example.org/")
    verify(replacement.disconnected && hidden(replacement) == false, "leaving the local node releases port")
    verify(connect(first).disconnected, "stale local sender cannot survive remote navigation")
    bridge.onLocationChanged(first, "$base/first/")
    val beforePortChange = connect(first)
    bridge.setNodeBase("http://127.0.0.1:42223")
    verify(beforePortChange.disconnected && secondPort.disconnected, "node port change drops old origin")
    verify(connect(first).disconnected, "old origin cannot reconnect")
    bridge.setNodeBase(base)
    val brokenPort = connect(first)
    brokenPort.failPosts = true
    bridge.setEnabled(false)
    verify(brokenPort.disconnected, "failed delivery disconnects the unusable port")
    val finalPort = connect(first)
    bridge.unbindSession(first)
    verify(finalPort.disconnected && first.webExtensionController.delegate == null, "closed tab releases delegate and port")
    bridge.close()
    verify(second.webExtensionController.delegate == null, "Activity destruction releases remaining delegates")
    bridge.bindSession(first)
    verify(first.webExtensionController.delegate == null, "destroyed bridge cannot be reattached")

    val pending = FixbuttonScrollBridge(); val pendingRuntime = GeckoRuntime()
    val installing = launch(start = CoroutineStart.UNDISPATCHED) { pending.install(pendingRuntime) }
    installing.cancelAndJoin()
    verify(pendingRuntime.webExtensionController.result.cancelled, "cancelled Activity cancels installation")
    pending.close()
    pendingRuntime.webExtensionController.result.complete(WebExtension())
    pending.bindSession(first)
    verify(first.webExtensionController.delegate == null, "late installation cannot revive destroyed bridge")
    val failed = FixbuttonScrollBridge(); val failedRuntime = GeckoRuntime()
    failedRuntime.webExtensionController.result.completeExceptionally(IllegalStateException("fixture install failure"))
    failed.install(failedRuntime)
    failed.bindSession(first)
    verify(first.webExtensionController.delegate == null, "optional installation failure does not prevent browser startup")
    failed.close()
    val timedOut = FixbuttonScrollBridge(); val timedRuntime = GeckoRuntime()
    timedOut.install(timedRuntime)
    verify(timedRuntime.webExtensionController.result.cancelled, "optional installation has a nonfatal timeout")
    timedOut.close()
    println("$checks native fixbutton visibility and trust-boundary checks passed")
}
