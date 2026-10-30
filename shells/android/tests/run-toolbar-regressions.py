#!/usr/bin/env python3
"""Run production toolbar placement methods with Kotlin view test doubles.

Set KOTLINC and JAVA_HOME. The enum and Activity methods are compiled directly
from production source. Real Android focus, IME, and Gecko rendering require
the separate emulator checks.
"""
import argparse
import os
import pathlib
import re
import subprocess
import tempfile


here = pathlib.Path(__file__).resolve()
installed_root = here.parents[1]
default_root = (installed_root if (installed_root / "app/src/main").is_dir()
                else here.parent / "EpixNet/shells/android")
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--android-root", type=pathlib.Path, default=default_root)
root = parser.parse_args().android_root
package = root / "app/src/main/java/zone/epix/app"
source = (package / "MainActivity.kt").read_text()


def method(name):
    pattern = (r"^    (?:private|override) fun " + re.escape(name)
               + r"\([^\n]*\) \{.*?^    }")
    matches = re.findall(pattern, source, re.MULTILINE | re.DOTALL)
    if len(matches) != 1:
        raise SystemExit(f"Expected one production method: {name}")
    return matches[0].replace("private fun", "fun", 1)


constant = re.search(
    r"^        private const val PREF_BROWSER_CONTROLS_POSITION = .+$",
    source, re.MULTILINE,
)
if constant is None:
    raise SystemExit("Missing production browser-controls preference key")

kotlin = r'''
package zone.epix.app

class Configuration(var orientation: Int) {
    companion object {
        const val ORIENTATION_UNDEFINED = 0
        const val ORIENTATION_PORTRAIT = 1
        const val ORIENTATION_LANDSCAPE = 2
    }
}
class Resources(val configuration: Configuration)
object Context { const val MODE_PRIVATE = 0 }
class Preferences {
    val values = mutableMapOf<String, String>()
    var writes = 0
    fun edit() = Editor(this)
    class Editor(private val owner: Preferences) {
        private val pending = mutableMapOf<String, String>()
        fun putString(key: String, value: String): Editor {
            pending[key] = value
            return this
        }
        fun apply() { owner.values.putAll(pending); owner.writes++ }
    }
}
open class View(val name: String) {
    var parent: LinearLayout? = null
    val layoutParams = Any()
    var visibility = 0
    var detachCount = 0
}
class LinearLayout {
    private val children = mutableListOf<View>()
    val childCount get() = children.size
    var moves = 0
    var transitionWrites = 0
    var animatedMoves = 0
    var layoutTransition: Any? = Any()
        set(value) { field = value; transitionWrites++ }
    fun getChildAt(index: Int): View? = children.getOrNull(index)
    fun addView(child: View) {
        check(child.parent == null)
        children.add(child)
        child.parent = this
    }
    fun bringChildToFront(child: View) {
        check(child.parent === this)
        check(children.remove(child))
        children.add(child)
        moves++
        if (layoutTransition != null) animatedMoves++
    }
    fun removeView(child: View) {
        check(children.remove(child))
        child.parent = null
        child.detachCount++
    }
    fun removeAllViews() { children.toList().forEach(::removeView) }
}
open class ActivityDouble {
    val resources = Resources(Configuration(Configuration.ORIENTATION_PORTRAIT))
    var configurationCallbacks = 0
    open fun onConfigurationChanged(newConfig: Configuration) {
        configurationCallbacks++
        resources.configuration.orientation = newConfig.orientation
    }
}
internal class Shell(val preferences: Preferences = Preferences(), initialize: Boolean = true) : ActivityDouble() {
    lateinit var browserChrome: LinearLayout
    private var browserControlsPosition = BrowserControlsPosition.AUTOMATIC
    val pageFrame = View("page")
    val topBar = View("address")
    val offlineBanner = View("offline")
    val bottomBar = View("navigation")
    var fullScreenSession: Any? = null
    fun applyFullScreenPresentation() {}
    fun getPreferences(mode: Int): Preferences {
        check(mode == Context.MODE_PRIVATE)
        return preferences
    }
    init {
        if (initialize) {
            browserChrome = LinearLayout()
            listOf(topBar, offlineBanner, pageFrame, bottomBar).forEach(browserChrome::addView)
        }
    }
'''
kotlin += "\n".join(method(name) for name in (
    "applyBrowserControlsPosition", "setBrowserControlsPosition", "onConfigurationChanged",
))
kotlin += "\n    companion object {\n"
kotlin += constant[0].replace("private ", "", 1)
kotlin += r'''
    }
}

fun main() {
    var failures = 0
    var checks = 0
    fun verify(condition: Boolean, message: String) {
        checks++
        if (!condition) { failures++; println("FAIL: $message") }
    }
    fun expectOrder(shell: Shell, expected: List<View>, message: String) {
        verify(shell.browserChrome.childCount == expected.size, "$message: child count")
        expected.forEachIndexed { index, child ->
            verify(shell.browserChrome.getChildAt(index) === child, "$message: identity at $index")
            verify(child.parent === shell.browserChrome, "$message: original parent for ${child.name}")
            verify(child.detachCount == 0, "$message: ${child.name} was never detached")
        }
    }
    for ((stored, expected) in listOf(
        null to BrowserControlsPosition.AUTOMATIC,
        "" to BrowserControlsPosition.AUTOMATIC,
        "future-option" to BrowserControlsPosition.AUTOMATIC,
        "auto" to BrowserControlsPosition.AUTOMATIC,
        "top" to BrowserControlsPosition.TOP,
        "bottom" to BrowserControlsPosition.BOTTOM,
    )) {
        verify(BrowserControlsPosition.fromStored(stored) == expected, "stored preference: $stored")
    }
    val uninitialized = Shell(initialize = false)
    uninitialized.applyBrowserControlsPosition()
    verify(uninitialized.preferences.writes == 0, "a pre-layout callback does not persist a choice")

    for (position in BrowserControlsPosition.entries) {
        val shell = Shell()
        val transition = shell.browserChrome.layoutTransition
        shell.setBrowserControlsPosition(position)
        expectOrder(shell, if (position == BrowserControlsPosition.TOP)
            listOf(shell.topBar, shell.offlineBanner, shell.bottomBar, shell.pageFrame)
        else listOf(shell.pageFrame, shell.topBar, shell.offlineBanner, shell.bottomBar),
            "$position applies immediately when selected")
        verify(shell.preferences.values["browserControlsPosition"] == position.preferenceValue,
            "$position is persisted using the stable preference key")
        verify(shell.preferences.writes == 1, "$position writes once when selected")
        val recreated = BrowserControlsPosition.fromStored(shell.preferences.values["browserControlsPosition"])
        verify(recreated == position, "$position survives a preference round trip")
        val rows = listOf(shell.pageFrame, shell.topBar, shell.offlineBanner, shell.bottomBar)
        val params = rows.map { it.layoutParams }
        for (orientation in listOf(Configuration.ORIENTATION_PORTRAIT,
                                   Configuration.ORIENTATION_LANDSCAPE,
                                   Configuration.ORIENTATION_PORTRAIT)) {
            shell.onConfigurationChanged(Configuration(orientation))
            val expected = when (position) {
                BrowserControlsPosition.TOP -> listOf(shell.topBar, shell.offlineBanner, shell.bottomBar, shell.pageFrame)
                BrowserControlsPosition.BOTTOM -> listOf(shell.pageFrame, shell.topBar, shell.offlineBanner, shell.bottomBar)
                BrowserControlsPosition.AUTOMATIC -> if (orientation == Configuration.ORIENTATION_LANDSCAPE)
                    listOf(shell.topBar, shell.offlineBanner, shell.bottomBar, shell.pageFrame)
                else listOf(shell.pageFrame, shell.topBar, shell.offlineBanner, shell.bottomBar)
            }
            expectOrder(shell, expected, "$position / orientation $orientation")
            verify(rows.indices.all { rows[it].layoutParams === params[it] }, "existing layout weights/params survive")
            verify(shell.browserChrome.layoutTransition === transition, "scroll-away transition is restored")
            verify(shell.browserChrome.animatedMoves == 0, "reordering does not animate the page across the screen")
            val moves = shell.browserChrome.moves
            val transitionWrites = shell.browserChrome.transitionWrites
            shell.applyBrowserControlsPosition()
            verify(shell.browserChrome.moves == moves, "already correct order is a no-op")
            verify(shell.browserChrome.transitionWrites == transitionWrites, "no-op preserves transition without writes")
        }
        verify(shell.configurationCallbacks == 3, "configuration callback delegates to the Activity")
        verify(shell.preferences.writes == 1, "rotation never changes the persisted preference")
    }

    val hidden = Shell()
    listOf(hidden.topBar, hidden.offlineBanner, hidden.bottomBar).forEach { it.visibility = 8 }
    hidden.applyBrowserControlsPosition()
    hidden.onConfigurationChanged(Configuration(Configuration.ORIENTATION_LANDSCAPE))
    verify(listOf(hidden.topBar, hidden.offlineBanner, hidden.bottomBar).all { it.visibility == 8 },
        "rotation preserves hidden chrome and offline-banner visibility")
    verify(hidden.pageFrame.visibility == 0, "the page remains visible")
    expectOrder(hidden, listOf(hidden.topBar, hidden.offlineBanner, hidden.bottomBar, hidden.pageFrame),
        "hidden landscape controls")
    hidden.onConfigurationChanged(Configuration(Configuration.ORIENTATION_UNDEFINED))
    expectOrder(hidden, listOf(hidden.pageFrame, hidden.topBar, hidden.offlineBanner, hidden.bottomBar),
        "undefined orientation uses the Automatic portrait fallback")
    println("$failures Android toolbar regression failure(s), $checks checks")
    check(failures == 0)
}
'''
with tempfile.TemporaryDirectory(prefix="epix-android-toolbar-tests-") as directory:
    test = pathlib.Path(directory)
    (test / "ToolbarRegressions.kt").write_text(kotlin)
    subprocess.run([
        os.environ["KOTLINC"], str(test / "ToolbarRegressions.kt"),
        str(package / "BrowserControlsPosition.kt"), "-no-reflect", "-include-runtime",
        "-d", str(test / "tests.jar"),
    ], check=True)
    result = subprocess.run([
        str(pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java"), "-jar", str(test / "tests.jar"),
    ])
    raise SystemExit(result.returncode)
