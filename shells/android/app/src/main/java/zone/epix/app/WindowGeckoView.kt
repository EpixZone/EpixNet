package zone.epix.app

import android.content.Context
import android.view.View
import androidx.core.view.OnApplyWindowInsetsListener as CompatInsetsListener
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import java.util.IdentityHashMap
import org.mozilla.geckoview.GeckoSession
import org.mozilla.geckoview.GeckoView

/** Routes Gecko's keyboard listeners through the window that contains each view. */
internal class GeckoViewInsets {
    private val roots = IdentityHashMap<View, LinkedHashMap<WindowGeckoView, Any>>()

    fun attach(view: WindowGeckoView, root: View) {
        roots.getOrPut(root) { linkedMapOf() }[view] = Any()
        restoreDispatchers()
    }

    fun detach(view: WindowGeckoView, root: View?) {
        root?.let {
            roots[it]?.let { owners ->
                owners.remove(view)
                if (owners.isEmpty()) {
                    roots.remove(it)
                    ViewCompat.setOnApplyWindowInsetsListener(it, null)
                }
            }
        }
        restoreDispatchers()
    }

    private fun restoreDispatchers() {
        // GeckoView 155 attaches and clears its listener on the Activity root,
        // even for a dialog. Repair every owned window after either operation.
        val currentRoots = roots.keys.toList()
        currentRoots.forEach { root ->
            ViewCompat.setOnApplyWindowInsetsListener(root) { _, insets ->
                val platformInsets = insets.toWindowInsets()
                var result = if (platformInsets == null) insets else {
                    WindowInsetsCompat.toWindowInsetsCompat(root.onApplyWindowInsets(platformInsets))
                }
                val owners = roots[root]?.toList().orEmpty()
                for ((view, registration) in owners) {
                    if (roots[root]?.get(view) === registration) {
                        result = view.applyOwnedInsets(root, result)
                    }
                }
                result
            }
        }
        currentRoots.forEach(ViewCompat::requestApplyInsets)
    }
}

/** Keeps each GeckoView's inset listeners local to its actual attached window. */
internal class WindowGeckoView(
    context: Context,
    private val insets: GeckoViewInsets,
) : GeckoView(context) {
    private val listeners = linkedMapOf<String, CompatInsetsListener>()
    private var insetsRoot: View? = null
    private var attachment: Any? = null

    override fun addWindowInsetsListener(key: String, listener: CompatInsetsListener?) {
        if (listener == null) listeners.remove(key) else listeners[key] = listener
    }

    override fun removeWindowInsetsListener(key: String) {
        listeners.remove(key)
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        val root = rootView
        insetsRoot = root
        attachment = Any()
        insets.attach(this, root)
    }

    override fun onDetachedFromWindow() {
        val root = insetsRoot
        try {
            super.onDetachedFromWindow()
        } finally {
            insetsRoot = null
            attachment = null
            insets.detach(this, root)
        }
    }

    override fun setSession(session: GeckoSession) {
        super.setSession(session)
        requestOwnedInsets()
    }

    override fun onWindowFocusChanged(hasWindowFocus: Boolean) {
        super.onWindowFocusChanged(hasWindowFocus)
        if (hasWindowFocus) requestOwnedInsets()
    }

    private fun requestOwnedInsets() {
        insetsRoot?.let(ViewCompat::requestApplyInsets)
    }

    internal fun applyOwnedInsets(root: View, initial: WindowInsetsCompat): WindowInsetsCompat {
        val currentAttachment = attachment ?: return initial
        var result = initial
        for ((key, listener) in listeners.toList()) {
            if (insetsRoot !== root || attachment !== currentAttachment) break
            if (listeners[key] === listener) {
                result = listener.onApplyWindowInsets(root, result)
            }
        }
        return result
    }
}
