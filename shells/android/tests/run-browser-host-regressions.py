#!/usr/bin/env python3
"""Compile the real process browser host with narrow Android/Gecko doubles.

Set KOTLINC and JAVA_HOME. These deterministic JVM tests check ownership and
callback ordering; they do not substitute for Gecko/device lifecycle testing.
"""
import argparse
import os
import pathlib
import subprocess
import tempfile

here = pathlib.Path(__file__).resolve()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--android-root", type=pathlib.Path, default=here.parents[1])
root = parser.parse_args().android_root
production = root / "app/src/main/java/zone/epix/app/EmbeddedBrowserHost.kt"
tests = root / "tests/run-browser-host-regressions.kt"

doubles = {
    "Context.kt": r'''
package android.content
open class Context { open val applicationContext: Context get() = this }
''',
    "Looper.kt": r'''
package android.os
import java.util.ArrayDeque
class Looper private constructor(private val thread: Thread) {
    companion object {
        private val main = Looper(Thread.currentThread())
        private val pending = ArrayDeque<() -> Unit>()
        @JvmStatic fun getMainLooper(): Looper = main
        @JvmStatic fun myLooper(): Looper? = if (Thread.currentThread() === main.thread) main else null
        fun enqueue(action: () -> Unit) { synchronized(pending) { pending.addLast(action) } }
        fun drain() {
            check(myLooper() === main)
            while (true) {
                val action = synchronized(pending) { pending.pollFirst() } ?: break
                action()
            }
        }
    }
}
class Handler(val looper: Looper) {
    fun post(action: () -> Unit) { check(looper === Looper.getMainLooper()); Looper.enqueue(action) }
}
''',
    "Log.kt": r'''
package android.util
object Log {
    val failures = mutableListOf<Throwable>()
    @JvmStatic fun w(tag: String, message: String, error: Throwable): Int {
        check(tag == "EpixWallet" && message == "wallet install failed")
        failures.add(error)
        return 0
    }
}
''',
    "Gecko.kt": r'''
package org.mozilla.geckoview
import android.content.Context
import android.os.Handler

class GeckoResult<T>(private val handler: Handler? = null) {
    var settled = false
        private set
    var error: Throwable? = null
        private set
    private var value: T? = null
    private val listeners = mutableListOf<Pair<(T?) -> Unit, (Throwable?) -> Unit>>()
    fun accept(success: (T?) -> Unit, failure: (Throwable?) -> Unit) {
        listeners.add(success to failure)
        if (settled) dispatch(success to failure)
    }
    fun complete(value: T?) {
        check(!settled)
        this.value = value
        settled = true
        listeners.toList().forEach(::dispatch)
    }
    fun completeExceptionally(error: Throwable) {
        check(!settled)
        this.error = error
        settled = true
        listeners.toList().forEach(::dispatch)
    }
    fun withHandler(handler: Handler): GeckoResult<T> {
        val forwarded = GeckoResult<T>(handler)
        accept(forwarded::complete, { forwarded.completeExceptionally(checkNotNull(it)) })
        return forwarded
    }
    private fun dispatch(listener: Pair<(T?) -> Unit, (Throwable?) -> Unit>) {
        val action = { error?.let(listener.second) ?: listener.first(value) }
        if (handler == null) action() else handler.post(action)
    }
    fun poll(): T? { check(settled); error?.let { throw it }; return value }
    companion object {
        @JvmStatic fun <T> fromValue(value: T): GeckoResult<T> = GeckoResult<T>().also { it.complete(value) }
        @JvmStatic fun <T> fromException(error: Throwable): GeckoResult<T> = GeckoResult<T>().also { it.completeExceptionally(error) }
    }
}
class GeckoSession
class GeckoRuntimeSettings(val extensionsProcessEnabled: Boolean) {
    class Builder {
        private var extensions = false
        fun extensionsProcessEnabled(enabled: Boolean): Builder { extensions = enabled; return this }
        fun arguments(args: Array<String>): Builder { check(args.size == 2 && args[0] == "-profile"); return this }
        fun configFilePath(path: String): Builder { check(path.isNotBlank()); return this }
        fun build() = GeckoRuntimeSettings(extensions)
    }
}
class GeckoRuntime private constructor(val context: Context, val settings: GeckoRuntimeSettings) {
    val webExtensionController = WebExtensionController()
    companion object {
        var creations = 0
        @JvmStatic fun create(context: Context, settings: GeckoRuntimeSettings): GeckoRuntime {
            creations++
            return GeckoRuntime(context, settings)
        }
    }
}
class WebExtensionController {
    val installs = mutableListOf<GeckoResult<WebExtension>>()
    var synchronousFailure: Throwable? = null
    var calls = 0
    fun ensureBuiltIn(location: String, id: String): GeckoResult<WebExtension> {
        check(location == "resource://android/assets/extensions/wallet/" && id == "wallet@test")
        calls++
        synchronousFailure?.let { synchronousFailure = null; throw it }
        return GeckoResult<WebExtension>().also { installs.add(it) }
    }
}
class WebExtension {
    class Action
    class MessageSender
    class CreateTabDetails
    interface MessageDelegate {
        fun onMessage(nativeApp: String, message: Any, sender: MessageSender): GeckoResult<Any>?
    }
    interface ActionDelegate {
        fun onTogglePopup(extension: WebExtension, action: Action): GeckoResult<GeckoSession>?
        fun onOpenPopup(extension: WebExtension, action: Action): GeckoResult<GeckoSession>?
    }
    interface TabDelegate {
        fun onNewTab(source: WebExtension, details: CreateTabDetails): GeckoResult<GeckoSession>?
    }
    var boundMessage: MessageDelegate? = null
    var boundAction: ActionDelegate? = null
    var boundNativeApp: String? = null
    var messageBindings = 0
    var actionBindings = 0
    var tabBindings = 0
    var tabDelegate: TabDelegate? = null
        set(value) { field = value; tabBindings++ }
    fun setMessageDelegate(delegate: MessageDelegate, nativeApp: String) {
        boundMessage = delegate; boundNativeApp = nativeApp; messageBindings++
    }
    fun setActionDelegate(delegate: ActionDelegate) {
        boundAction = delegate; actionBindings++
    }
}
''',
}

with tempfile.TemporaryDirectory(prefix="epix-browser-host-tests-") as directory:
    temporary = pathlib.Path(directory)
    sources = []
    for name, source in doubles.items():
        path = temporary / name
        path.write_text(source)
        sources.append(str(path))
    jar = temporary / "tests.jar"
    subprocess.run([
        os.environ["KOTLINC"], *sources, str(production), str(tests),
        "-no-reflect", "-include-runtime", "-d", str(jar),
    ], check=True, timeout=120)
    java = str(pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java")
    for scenario in ("replacement", "detached-install"):
        subprocess.run([java, "-jar", str(jar), scenario], check=True, timeout=20)
