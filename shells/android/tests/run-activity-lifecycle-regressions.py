#!/usr/bin/env python3
"""Execute Activity cleanup/connectivity source with real coroutines and virtual time.

Set KOTLINC, JAVA_HOME and COROUTINES_JAR (coroutines 1.9.0). Android/Gecko,
views and file disposal are narrow doubles. No device, native node, engine,
real timer, background worker or filesystem deletion is used by the fixture.
"""
import os
import pathlib
import re
import subprocess
import tempfile
import zipfile

root = pathlib.Path(__file__).resolve().parents[1]
source = (root / "app/src/main/java/zone/epix/app/MainActivity.kt").read_text()
coroutines = pathlib.Path(os.environ["COROUTINES_JAR"])
with zipfile.ZipFile(coroutines) as archive:
    version = archive.read("META-INF/kotlinx_coroutines_core.version").decode().strip()
if version != "1.9.0":
    raise SystemExit(f"Expected declared coroutines 1.9.0, found {version}")


def method(name):
    matches = re.findall(r"^    (?:private |override )?fun " + re.escape(name)
                         + r"\(.*?^    }", source, re.M | re.S)
    if len(matches) != 1:
        raise SystemExit(f"Expected one production method: {name}")
    return matches[0]


def declaration(name):
    matches = re.findall(r"^    private (?:val|fun) " + re.escape(name) + r"[^\n]+$", source, re.M)
    if len(matches) != 1:
        raise SystemExit(f"Expected one production declaration: {name}")
    return matches[0]


polls = re.findall(r"        // Reflect the Tor state[^\n]*\n(        scope.launch \{.*?^        })", source, re.M | re.S)
if len(polls) != 1:
    raise SystemExit("Expected one production Tor-status poller")
replacements = {
    "// INSERT_PRODUCTION_DECLARATIONS": "\n".join(declaration(name) for name in (
        "activityJob", "scope", "ownsSession")),
    "// INSERT_PRODUCTION_METHODS": "\n".join(method(name) for name in (
        "watchConnectivity", "onDestroy", "disposeSession", "showOwnedDialog",
        "registerPrompt", "dismissFilePrompt")),
    "// INSERT_PRODUCTION_TOR_POLLER": polls[0],
}
kotlin = (root / "tests/run-activity-lifecycle-regressions.kt").read_text()
for marker, body in replacements.items():
    if kotlin.count(marker) != 1:
        raise SystemExit(f"Expected one fixture marker: {marker}")
    kotlin = kotlin.replace(marker, body)

network = r'''
package android.net
class Network
class NetworkCapabilities(val online: Boolean) {
    fun hasCapability(capability: Int): Boolean {
        check(capability == NET_CAPABILITY_INTERNET)
        return online
    }
    companion object { const val NET_CAPABILITY_INTERNET = 12 }
}
class ConnectivityManager {
    open class NetworkCallback {
        open fun onAvailable(network: Network) {}
        open fun onLost(network: Network) {}
        open fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {}
    }
    val activeNetwork = Network()
    var online = true
    var failRegistration = false
    val callbacks = mutableSetOf<NetworkCallback>()
    val registrations = mutableListOf<NetworkCallback>()
    val removals = mutableListOf<NetworkCallback>()
    fun getNetworkCapabilities(network: Network?): NetworkCapabilities? =
        if (network == null) null else NetworkCapabilities(online)
    fun registerDefaultNetworkCallback(callback: NetworkCallback) {
        if (failRegistration) throw IllegalStateException("registration unavailable")
        check(callbacks.add(callback))
        registrations.add(callback)
    }
    fun unregisterNetworkCallback(callback: NetworkCallback) {
        check(callbacks.remove(callback)) { "unregister must use the exact registered callback" }
        removals.add(callback)
    }
}
'''
log = r'''
package android.util
object Log {
    val failures = mutableListOf<Throwable>()
    fun w(tag: String, text: String, error: Throwable) {
        check(tag == "EpixNode" && text == "connectivity callback unavailable")
        failures.add(error)
    }
}
'''
with tempfile.TemporaryDirectory(prefix="epix-android-activity-lifecycle-") as directory:
    test = pathlib.Path(directory)
    for name, text in (("ActivityLifecycleRegressions.kt", kotlin), ("Network.kt", network), ("Log.kt", log)):
        (test / name).write_text(text)
    jar = test / "tests.jar"
    subprocess.run([
        os.environ["KOTLINC"], str(test / "ActivityLifecycleRegressions.kt"),
        str(test / "Network.kt"), str(test / "Log.kt"),
        str(root / "app/src/main/java/zone/epix/app/PendingOperations.kt"),
        "-cp", str(coroutines), "-no-reflect", "-include-runtime", "-d", str(jar),
    ], check=True, timeout=120)
    subprocess.run([
        str(pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java"),
        "-cp", os.pathsep.join((str(jar), str(coroutines))),
        "zone.epix.app.ActivityLifecycleRegressionsKt",
    ], check=True, timeout=20)
