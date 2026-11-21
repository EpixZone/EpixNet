#!/usr/bin/env python3
"""Exercise native fixbutton routing with production Kotlin and narrow Gecko doubles."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
coroutines = Path(os.environ["COROUTINES_JAR"])
doubles = {
    "Android.kt": '''package android.os
class Looper { companion object { fun getMainLooper() = Looper() } }
class Handler(looper: Looper) { fun post(action: () -> Unit) { action() } }
''',
    "Log.kt": '''package android.util
object Log { fun w(tag: String, message: String, error: Throwable) = 0 }
''',
    "Json.kt": '''package org.json
class JSONObject { val values=mutableMapOf<String,Any>(); fun put(key:String,value:Any):JSONObject { values[key]=value;return this } }
''',
    "Gecko.kt": '''package org.mozilla.geckoview
import android.os.Handler
import org.json.JSONObject
class GeckoResult<T> {
 var cancelled=false
 private var done=false; private var value:T?=null; private var failure:Throwable?=null
 private var success:((T?)->Unit)?=null; private var error:((Throwable?)->Unit)?=null
 fun withHandler(handler:Handler)=this
 fun accept(ok:(T?)->Unit,bad:(Throwable?)->Unit) {success=ok;error=bad;dispatch()}
 fun complete(v:T) {value=v;done=true;dispatch()}
 fun completeExceptionally(e:Throwable) {failure=e;done=true;dispatch()}
 fun cancel() {cancelled=true}
 private fun dispatch() {if(done) {if(failure!=null)error?.invoke(failure) else success?.invoke(value)}}
}
class GeckoRuntime {val webExtensionController=Controller()}
class Controller {
 val result=GeckoResult<WebExtension>()
 fun ensureBuiltIn(uri:String,id:String):GeckoResult<WebExtension> {
  check(uri=="resource://android/assets/browser-controls/" && id=="browser-ext@epix.zone")
  return result
 }
}
class GeckoSession {val webExtensionController=SessionController()}
class SessionController {
 var delegate:WebExtension.MessageDelegate?=null
 fun setMessageDelegate(extension:WebExtension, delegate:WebExtension.MessageDelegate?, app:String) {
  check(app=="epix_browser_controls");this.delegate=delegate
 }
}
class WebExtension(val id:String="browser-ext@epix.zone") {
 class MessageSender(val session:GeckoSession?,val url:String,val isTopLevel:Boolean=true,
  val environmentType:Int=ENV_TYPE_CONTENT_SCRIPT,val webExtension:WebExtension=WebExtension()) {
  companion object {const val ENV_TYPE_CONTENT_SCRIPT=1}
 }
 interface MessageDelegate {fun onConnect(port:Port) {}}
 interface PortDelegate {fun onDisconnect(port:Port) {}}
 class Port(val sender:MessageSender,val name:String="epix_browser_controls") {
  var disconnected=false; var failPosts=false;var delegate:PortDelegate?=null
  val messages=mutableListOf<JSONObject>()
  fun postMessage(message:JSONObject) {check(!disconnected && !failPosts);messages.add(message)}
  fun disconnect() {disconnected=true;delegate?.onDisconnect(this)}
  @JvmName("assignDelegate") fun setDelegate(value:PortDelegate?) {delegate=value}
 }
}
''',
}
with tempfile.TemporaryDirectory(prefix="epix-fixbutton-scroll-") as directory:
    temporary = Path(directory)
    for name, source in doubles.items():
        (temporary / name).write_text(source)
    jar = temporary / "checks.jar"
    subprocess.run([os.environ.get("KOTLINC", "kotlinc"),
                    str(root / "app/src/main/java/zone/epix/app/FixbuttonScrollBridge.kt"),
                    str(root / "tests/FixbuttonScrollTests.kt"),
                    *map(str, temporary.glob("*.kt")), "-cp", str(coroutines),
                    "-include-runtime", "-d", str(jar)], check=True)
    java = Path(os.environ["JAVA_HOME"]) / "bin/java"
    subprocess.run([str(java), "-cp", os.pathsep.join([str(jar), str(coroutines)]),
                    "zone.epix.app.FixbuttonScrollTestsKt"], check=True)
