#!/usr/bin/env python3
"""Exercise production fullscreen ownership and navigation with native UI doubles."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "app/src/main/java/zone/epix/app/MainActivity.kt").read_text()


def method(name, indent=4):
    spaces = " " * indent
    found = re.findall(r"^" + spaces + r"(?:private |override )?fun " + name
                       + r"\(.*?^" + spaces + r"}", source, re.M | re.S)
    if len(found) != 1:
        raise SystemExit(f"Expected one production method: {name}")
    return found[0].replace("private fun", "fun", 1).replace("override fun", "fun", 1)


kotlin = r'''
package zone.epix.app

class View {
    var visibility = VISIBLE
    var alpha = 1f
    @JvmField var text = ""
    fun setText(value: String) { text = value }
    fun hasFocus() = false
    companion object { const val GONE = 8; const val VISIBLE = 0 }
}
class GeckoSession {
    var isOpen = true
    var exits = 0
    var backs = 0
    val loads = mutableListOf<String>()
    fun exitFullScreen() { check(isOpen); exits++ }
    fun goBack() { backs++ }
    fun loadUri(url: String) { loads.add(url) }
}
class GeckoView(private var attached: GeckoSession?) {
    val session get() = attached
    fun releaseSession() { attached = null }
    fun setSession(value: GeckoSession) { attached = value }
}
class Tab(val session: GeckoSession, var canGoBack: Boolean = false, var canGoForward: Boolean = false, var url: String = "fixture")
class Dialog(var isShowing: Boolean)
class Window { val decorView = View(); var fits = true; val controller = WindowInsetsControllerCompat() }
class WindowInsetsControllerCompat {
    var systemBarsBehavior = BEHAVIOR_DEFAULT
    var hidden = false
    var hides = 0
    var shows = 0
    fun hide(types: Int) { check(types == 3); hidden = true; hides++ }
    fun show(types: Int) { check(types == 3); hidden = false; shows++ }
    companion object { const val BEHAVIOR_DEFAULT = 1; const val BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE = 2 }
}
object WindowCompat {
    fun setDecorFitsSystemWindows(window: Window, value: Boolean) { window.fits = value }
    fun getInsetsController(window: Window, view: View) = window.controller
}
object WindowInsetsCompat { object Type { fun systemBars() = 3 } }
object ViewCompat { var insetRequests = 0; fun requestApplyInsets(view: View) { insetRequests++ } }
class BackCallback { var isEnabled = false }
class Configuration
open class Activity {
    var configurationChanges = 0
    var focusChanges = 0
    open fun onConfigurationChanged(newConfig: Configuration) { configurationChanges++ }
    open fun onWindowFocusChanged(hasFocus: Boolean) { focusChanges++ }
    open fun dispatchTouchEvent(ev: android.view.MotionEvent) = false
}
class Shell : Activity() {
    var disposed = false
    val ownedSessions = mutableSetOf<GeckoSession>()
    val tabs = mutableListOf<Tab>()
    var currentTabIndex = 0
    val currentTab get() = tabs[currentTabIndex]
    var fullScreenSession: GeckoSession? = null
    var walletDialog: Dialog? = null
    val window = Window()
    val browserChrome = View()
    val topBar = View()
    val bottomBar = View()
    val backButton = View()
    val forwardButton = View()
    val tabCountView = View()
    val addressBar = View()
    val browserBackCallback = BackCallback()
    val geckoView = GeckoView(null)
    @JvmField var chromeHidden = false
    var editingLeaves = 0
    var positionUpdates = 0
    var currentDisplay = "fixture"
    var startupSession: GeckoSession? = null
    var startupPageUrl = ""
    var startupPageStarted = false
    var splashOverlay: Any? = null
    var lastTouchY = 0f
    var touchAccum = 0f
    val DISABLED_ALPHA = .3f
    fun ownsSession(session: GeckoSession) = !disposed && session in ownedSessions
    fun leaveAddressEditing() { editingLeaves++ }
    fun refreshOfflineBanner() {}
    fun applyBrowserControlsPosition() { positionUpdates++ }
    fun friendlyUrl(url: String) = url
    fun nodeUrl(url: String) = "local/$url"
    fun disposeSession(session: GeckoSession) { leaveFullScreen(session); ownedSessions.remove(session); session.isOpen = false }
    fun dp(value: Int) = value
    fun add(): GeckoSession { val session=GeckoSession(); ownedSessions.add(session); tabs.add(Tab(session)); return session }
'''
names = ("handleFullScreen", "leaveFullScreen", "applyFullScreenPresentation", "setChromeHidden",
         "refreshBackNavigation", "goBackInCurrentTab", "showTab", "closeTab",
         "onConfigurationChanged", "onWindowFocusChanged", "dispatchTouchEvent")
for name in names:
    body = method(name)
    if name in ("onConfigurationChanged", "onWindowFocusChanged", "dispatchTouchEvent"):
        body = body.replace("fun " + name, "override fun " + name, 1)
    kotlin += body + "\n"
kotlin += "\n".join(method(name, 12) for name in ("onFullScreen", "onPageStart", "onCrash", "onKill")) + "\n}\n"
kotlin += r'''
fun main() {
    var checks=0
    fun verify(value: Boolean, message: String) { checks++; check(value) { message } }
    val shell=Shell();val first=shell.add();val second=shell.add();shell.showTab(0)
    shell.onFullScreen(first,true)
    verify(shell.fullScreenSession===first,"visible tab owns fullscreen")
    verify(shell.chromeHidden && shell.topBar.visibility==View.GONE && shell.bottomBar.visibility==View.GONE,"both browser rows hide")
    verify(shell.window.controller.hidden && !shell.window.fits,"system bars hide and viewport uses their space")
    verify(shell.window.controller.systemBarsBehavior==WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE,"system bars remain available by swipe")
    verify(shell.browserBackCallback.isEnabled,"Back is enabled without page history")
    shell.dispatchTouchEvent(android.view.MotionEvent(0,0f));shell.dispatchTouchEvent(android.view.MotionEvent(2,200f))
    verify(shell.chromeHidden,"scroll gestures cannot reveal app controls in fullscreen")
    shell.goBackInCurrentTab()
    verify(first.exits==1 && first.backs==0,"Back exits fullscreen before navigating")
    verify(shell.fullScreenSession==null && !shell.chromeHidden && !shell.window.controller.hidden && shell.window.fits,"Back restores browser chrome, bars and insets")
    verify(!shell.browserBackCallback.isEnabled,"no-history Back returns to Android after fullscreen")
    shell.onFullScreen(first,false)
    verify(first.exits==1,"late DOM exit does not send another exit")
    shell.currentTab.canGoBack=true;shell.refreshBackNavigation();shell.goBackInCurrentTab()
    verify(first.backs==1 && shell.editingLeaves>0,"normal history Back still works")
    shell.onFullScreen(second,true)
    verify(second.exits==1 && shell.fullScreenSession==null && !shell.chromeHidden,"background request is rejected without taking the display")
    shell.onFullScreen(first,true);shell.onFullScreen(second,false)
    verify(shell.fullScreenSession===first,"background exit cannot dismiss selected fullscreen")
    val hides=shell.window.controller.hides
    shell.onConfigurationChanged(Configuration());shell.onWindowFocusChanged(false);shell.onWindowFocusChanged(true)
    verify(shell.window.controller.hides==hides+2 && shell.chromeHidden,"rotation and focus return reapply fullscreen")
    verify(shell.configurationChanges==1 && shell.focusChanges==2 && shell.positionUpdates==1,"native lifecycle and toolbar placement still run")
    shell.showTab(1)
    verify(shell.fullScreenSession==null && first.exits==2 && !shell.chromeHidden,"tab switch exits old fullscreen and restores controls")
    shell.onFullScreen(first,false)
    verify(shell.currentTab.session===second && !shell.chromeHidden,"late callback from old tab cannot hide new chrome")
    shell.onFullScreen(second,true);shell.onPageStart(second,"next")
    verify(shell.fullScreenSession==null && second.exits==2 && !shell.chromeHidden,"navigation clears fullscreen")
    shell.onFullScreen(second,true);shell.closeTab(1)
    verify(!second.isOpen && shell.fullScreenSession==null && !shell.chromeHidden,"closing the owning tab restores display before disposal")
    shell.onFullScreen(first,true);shell.closeTab(0)
    verify(first.isOpen && first.loads.last()=="local/dashboard.epix" && shell.fullScreenSession==null,"closing last tab exits fullscreen before dashboard reuse")
    shell.walletDialog=Dialog(true);val exits=first.exits;shell.onFullScreen(first,true)
    verify(first.exits==exits+1 && !shell.chromeHidden,"wallet prompt keeps its native exit path")
    shell.walletDialog=null;shell.onFullScreen(first,true);shell.leaveFullScreen()
    verify(shell.fullScreenSession==null && !shell.chromeHidden,"opening wallet can exit the current fullscreen owner")
    shell.disposed=true;val before=first.exits;shell.onFullScreen(first,true)
    verify(first.exits==before && shell.fullScreenSession==null,"destroyed activity ignores late fullscreen callbacks")
    val crashed=Shell();val owner=crashed.add();val background=crashed.add();crashed.showTab(0)
    crashed.onFullScreen(owner,true);background.isOpen=false;crashed.onCrash(background)
    verify(crashed.fullScreenSession===owner && crashed.chromeHidden,"background crash cannot dismiss selected fullscreen")
    owner.isOpen=false;crashed.onCrash(owner)
    verify(crashed.fullScreenSession==null && !crashed.chromeHidden && !crashed.window.controller.hidden && owner.exits==0,"owner crash restores the display without calling the closed session")
    val killed=Shell();val killedOwner=killed.add();killed.showTab(0);killed.onFullScreen(killedOwner,true)
    killedOwner.isOpen=false;killed.onKill(killedOwner)
    verify(killed.fullScreenSession==null && !killed.chromeHidden && killedOwner.exits==0,"owner kill releases fullscreen without a DOM exit event")
    println("$checks Android fullscreen regression checks passed")
}
'''
motion = """package android.view
class MotionEvent(val actionMasked: Int, val rawY: Float) {
 companion object { const val ACTION_DOWN=0; const val ACTION_MOVE=2 }
}
"""
popup = re.search(r"private fun openPopupSession\(.*?\): GeckoSession \{\s*leaveFullScreen\(\)", source, re.S)
if popup is None or "leaveFullScreen(session)" not in method("disposeSession"):
    raise SystemExit("Wallet and session disposal must release fullscreen ownership")
with tempfile.TemporaryDirectory(prefix="epix-fullscreen-") as directory:
    path=Path(directory);(path/'Fullscreen.kt').write_text(kotlin);(path/'MotionEvent.kt').write_text(motion)
    subprocess.run([os.environ['KOTLINC'],str(path/'Fullscreen.kt'),str(path/'MotionEvent.kt'),'-no-reflect','-include-runtime','-d',str(path/'tests.jar')],check=True)
    subprocess.run([str(Path(os.environ['JAVA_HOME'])/'bin/java'),'-jar',str(path/'tests.jar')],check=True)
