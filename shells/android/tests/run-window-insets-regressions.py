#!/usr/bin/env python3
"""Compile the production window-insets router with Android and Gecko doubles.

The doubles model GeckoView 155's Activity-root listener replacement. Real IME,
window normalization and compositor behavior require the emulator checks.
"""
import argparse
import os
import pathlib
import shutil
import subprocess
import tempfile

here = pathlib.Path(__file__).resolve()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--android-root', type=pathlib.Path, default=here.parents[1])
root = parser.parse_args().android_root
source = root / 'app/src/main/java/zone/epix/app/WindowGeckoView.kt'
activity = (source.parent / 'MainActivity.kt').read_text()
assert activity.count('WindowGeckoView(this, geckoInsets)') == 2, 'Route both main and wallet views'
assert ' = GeckoView(this)' not in activity, 'Stock views would overwrite the shared root listener'

files = {
    'Context.kt': r'''
package android.content
import android.view.View
open class Context(val activityRoot: View)
''',
    'View.kt': r'''
package android.view
data class WindowInsets(val keyboard: Int)
open class View {
    fun interface OnApplyWindowInsetsListener {
        fun onApplyWindowInsets(view: View, insets: WindowInsets): WindowInsets
    }
    var rootView: View = this
    var requests = 0
    var normalizations = 0
    var normalize: (WindowInsets) -> WindowInsets = { it }
    open fun onApplyWindowInsets(insets: WindowInsets): WindowInsets {
        normalizations++
        return normalize(insets)
    }
}
''',
    'Compat.kt': r'''
package androidx.core.view
import android.view.View
import android.view.WindowInsets
import java.util.IdentityHashMap
class WindowInsetsCompat(private val platform: WindowInsets?) {
    val keyboard get() = platform?.keyboard ?: 0
    fun toWindowInsets() = platform
    companion object {
        fun toWindowInsetsCompat(value: WindowInsets) = WindowInsetsCompat(value)
    }
}
fun interface OnApplyWindowInsetsListener {
    fun onApplyWindowInsets(view: View, insets: WindowInsetsCompat): WindowInsetsCompat
}
object ViewCompat {
    val installed = IdentityHashMap<View, OnApplyWindowInsetsListener>()
    fun setOnApplyWindowInsetsListener(root: View, listener: OnApplyWindowInsetsListener?) {
        if (listener == null) installed.remove(root) else installed[root] = listener
    }
    fun requestApplyInsets(root: View) { root.requests++ }
    fun dispatch(root: View, keyboard: Int): WindowInsetsCompat {
        val value = WindowInsetsCompat(WindowInsets(keyboard))
        return installed[root]?.onApplyWindowInsets(root, value) ?: value
    }
}
''',
    'Gecko.kt': r'''
package org.mozilla.geckoview
import android.content.Context
import android.view.View
import androidx.core.view.OnApplyWindowInsetsListener as CompatInsetsListener
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
class GeckoSession { val keyboard = mutableListOf<Int>() }
open class GeckoView(private val context: Context) : View() {
    private val upstreamListeners = linkedMapOf<String, CompatInsetsListener?>()
    private var currentSession: GeckoSession? = null
    var attachCalls = 0
    var detachCalls = 0
    var focusCalls = 0
    var failDetach = false
    open fun addWindowInsetsListener(key: String, listener: CompatInsetsListener?) {
        upstreamListeners[key] = listener
    }
    open fun removeWindowInsetsListener(key: String) { upstreamListeners.remove(key) }
    open fun onAttachedToWindow() {
        attachCalls++
        addWindowInsetsListener("keyboard") { _, insets ->
            currentSession?.keyboard?.add(insets.keyboard)
            insets
        }
        // This is GeckoView 155's problematic Activity-root ownership.
        ViewCompat.setOnApplyWindowInsetsListener(context.activityRoot) { root, insets ->
            var result = WindowInsetsCompat.toWindowInsetsCompat(root.onApplyWindowInsets(insets.toWindowInsets()!!))
            upstreamListeners.values.forEach { result = it!!.onApplyWindowInsets(root, result) }
            result
        }
    }
    open fun onDetachedFromWindow() {
        detachCalls++
        removeWindowInsetsListener("keyboard")
        if (upstreamListeners.isEmpty()) ViewCompat.setOnApplyWindowInsetsListener(context.activityRoot, null)
        if (failDetach) error("display release failed")
    }
    open fun setSession(session: GeckoSession) { currentSession = session }
    open fun onWindowFocusChanged(hasWindowFocus: Boolean) { focusCalls++ }
}
''',
    'Tests.kt': r'''
package zone.epix.app
import android.content.Context
import android.view.View
import android.view.WindowInsets
import androidx.core.view.OnApplyWindowInsetsListener
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import org.mozilla.geckoview.GeckoSession

private var checks = 0
private fun expect(condition: Boolean, description: String) {
    check(condition) { description }
    checks++
}
private fun view(context: Context, registry: GeckoViewInsets, root: View, session: GeckoSession): WindowGeckoView =
    WindowGeckoView(context, registry).apply {
        rootView = root
        setSession(session)
        onAttachedToWindow()
    }
fun main() {
    val mainRoot = View()
    val popupRoot = View()
    val context = Context(mainRoot)
    val registry = GeckoViewInsets()
    val mainSession = GeckoSession()
    val main = view(context, registry, mainRoot, mainSession)
    expect(main.attachCalls == 1 && mainRoot.requests > 0, "Attachment keeps superclass lifecycle and requests fresh insets")
    mainRoot.normalize = { WindowInsets(it.keyboard.coerceAtMost(30)) }
    ViewCompat.dispatch(mainRoot, 70)
    expect(mainSession.keyboard == listOf(30), "Platform root normalization precedes the Gecko listener")
    expect(mainRoot.normalizations == 1, "Root onApplyWindowInsets runs exactly once")
    val popupSession = GeckoSession()
    val popup = view(context, registry, popupRoot, popupSession)
    ViewCompat.dispatch(mainRoot, 20)
    expect(mainSession.keyboard.last() == 20 && popupSession.keyboard.isEmpty(), "Popup attachment repairs Activity root and isolates its keyboard state")
    ViewCompat.dispatch(popupRoot, 223)
    ViewCompat.dispatch(popupRoot, 0)
    expect(popupSession.keyboard == listOf(223, 0), "Popup receives keyboard show and hide from its own window")
    expect(mainSession.keyboard == listOf(30, 20), "Popup insets never reach the main session")
    popup.onDetachedFromWindow()
    expect(popup.detachCalls == 1 && !ViewCompat.installed.containsKey(popupRoot), "Last popup detach releases only its actual root")
    ViewCompat.dispatch(mainRoot, 0)
    expect(mainSession.keyboard.last() == 0, "Main root survives superclass listener clearing during popup detach")
    val mainRequests = mainRoot.requests
    main.onWindowFocusChanged(false)
    expect(mainRoot.requests == mainRequests, "Focus loss does not request obsolete insets")
    main.onWindowFocusChanged(true)
    expect(mainRoot.requests == mainRequests + 1 && main.focusCalls == 2, "Focus gain requests current window state after superclass callback")
    val next = GeckoSession()
    main.setSession(next)
    expect(mainRoot.requests == mainRequests + 2, "New session requests insets even when values are unchanged")
    ViewCompat.dispatch(mainRoot, 0)
    expect(next.keyboard == listOf(0), "New session receives current zero keyboard height")

    val values = mutableListOf<Int>()
    main.addWindowInsetsListener("first") { _, insets ->
        values.add(insets.keyboard)
        WindowInsetsCompat(WindowInsets(3))
    }
    main.addWindowInsetsListener("second") { _, insets -> values.add(insets.keyboard); insets }
    val normalized = ViewCompat.dispatch(mainRoot, 12)
    expect(values == listOf(12, 3) && normalized.keyboard == 3, "Local listener order and returned inset transformations are preserved")
    main.addWindowInsetsListener("first", null)
    main.removeWindowInsetsListener("second")
    values.clear()
    ViewCompat.dispatch(mainRoot, 9)
    expect(values.isEmpty(), "Nullable registration removes its key and explicit removal stays local")

    var oldCalls = 0
    var newCalls = 0
    val replacement = OnApplyWindowInsetsListener { _, insets -> newCalls++; insets }
    main.addWindowInsetsListener("replace-first") { _, insets ->
        main.addWindowInsetsListener("replace-later", replacement)
        insets
    }
    main.addWindowInsetsListener("replace-later") { _, insets -> oldCalls++; insets }
    ViewCompat.dispatch(mainRoot, 1)
    expect(oldCalls == 0 && newCalls == 0, "Replaced callback from a dispatch snapshot is skipped")
    ViewCompat.dispatch(mainRoot, 1)
    expect(oldCalls == 0 && newCalls == 1, "Replacement participates in the next dispatch")
    main.removeWindowInsetsListener("replace-first")
    main.removeWindowInsetsListener("replace-later")

    val peerSession = GeckoSession()
    val peer = view(context, registry, mainRoot, peerSession)
    val beforeNormalization = mainRoot.normalizations
    ViewCompat.dispatch(mainRoot, 10)
    expect(next.keyboard.last() == 10 && peerSession.keyboard.last() == 10, "Two views sharing a root both receive its insets")
    expect(mainRoot.normalizations == beforeNormalization + 1, "A shared root still preprocesses each dispatch only once")
    var detachPeer = true
    main.addWindowInsetsListener("detach-peer") { _, insets ->
        if (detachPeer) { detachPeer = false; peer.onDetachedFromWindow(); peer.onAttachedToWindow() }
        insets
    }
    val peerCount = peerSession.keyboard.size
    ViewCompat.dispatch(mainRoot, 4)
    expect(peerSession.keyboard.size == peerCount, "Reattached view does not receive its old registration's pending event")
    ViewCompat.dispatch(mainRoot, 5)
    expect(peerSession.keyboard.last() == 5, "Reattached view participates in a fresh dispatch")
    main.removeWindowInsetsListener("detach-peer")
    peer.failDetach = true
    try { peer.onDetachedFromWindow() } catch (_: IllegalStateException) { }
    ViewCompat.dispatch(mainRoot, 6)
    expect(next.keyboard.last() == 6, "Detach failure still removes the owner and restores surviving root listeners")
    expect(peerSession.keyboard.last() == 5, "Failed-detach owner cannot receive later root events")

    var reattachSelf = true
    var persistentCalls = 0
    main.addWindowInsetsListener("reattach-self") { _, insets ->
        if (reattachSelf) { reattachSelf = false; main.onDetachedFromWindow(); main.onAttachedToWindow() }
        insets
    }
    main.addWindowInsetsListener("persistent-later") { _, insets -> persistentCalls++; insets }
    ViewCompat.dispatch(mainRoot, 8)
    expect(persistentCalls == 0, "Same-view reattachment stops callbacks belonging to its old attachment")
    ViewCompat.dispatch(mainRoot, 9)
    expect(persistentCalls == 1, "Unchanged custom listener participates in the new attachment's next event")
    main.removeWindowInsetsListener("reattach-self")
    main.removeWindowInsetsListener("persistent-later")

    val unrelated = View()
    val unrelatedListener = OnApplyWindowInsetsListener { _, insets -> insets }
    ViewCompat.setOnApplyWindowInsetsListener(unrelated, unrelatedListener)
    main.rootView = unrelated
    main.onDetachedFromWindow()
    expect(!ViewCompat.installed.containsKey(mainRoot), "Detach cleans the captured attached root, not a detached view's current root")
    expect(ViewCompat.installed[unrelated] === unrelatedListener, "Registry never clears an unowned root")
    val afterDetach = mainRoot.requests
    main.onWindowFocusChanged(true)
    main.setSession(GeckoSession())
    expect(mainRoot.requests == afterDetach, "Detached focus and session changes do not request stale window insets")

    val otherRoot = View()
    val otherSession = GeckoSession()
    val other = view(Context(otherRoot), GeckoViewInsets(), otherRoot, otherSession)
    ViewCompat.dispatch(otherRoot, 7)
    expect(otherSession.keyboard == listOf(7), "Separate Activity registries remain independent")
    other.onDetachedFromWindow()
    expect(!ViewCompat.installed.containsKey(otherRoot), "Final Activity owner releases its dispatcher")
    println("Window insets regressions passed: $checks checks")
}
''',
}
compiler = os.environ.get('KOTLINC') or shutil.which('kotlinc')
if not compiler:
    raise SystemExit('Set KOTLINC to the Kotlin compiler')
java = pathlib.Path(os.environ['JAVA_HOME']) / 'bin/java' if os.environ.get('JAVA_HOME') else 'java'
with tempfile.TemporaryDirectory(prefix='window-insets-regressions-') as directory:
    output = pathlib.Path(directory)
    for name, content in files.items():
        (output / name).write_text(content)
    jar = output / 'tests.jar'
    subprocess.run([compiler, str(source), *map(str, output.glob('*.kt')), '-include-runtime', '-d', str(jar)], check=True)
    subprocess.run([str(java), '-jar', str(jar)], check=True)
