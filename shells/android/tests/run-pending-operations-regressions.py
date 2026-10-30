#!/usr/bin/env python3
"""Execute the production pending registry and Android permission callbacks.

Set KOTLINC and JAVA_HOME. Platform doubles provide request delivery and session
ownership; the callback ordering and registry implementation come from source.
"""
import os
import pathlib
import re
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
package = root / "app/src/main/java/zone/epix/app"
source = (package / "MainActivity.kt").read_text()


def method(name, indent):
    pattern = rf"^ {{{indent}}}(?:private|override) fun {name}\(.*?^ {{{indent}}}}}"
    matches = re.findall(pattern, source, re.M | re.S)
    if len(matches) != 1:
        raise SystemExit(f"Expected exactly one production callback: {name}")
    return matches[0].replace("private fun", "fun", 1).replace("override fun", "fun", 1)


counter = re.search(r"^        private var externalRequestCode = .+$", source, re.M)
if counter is None:
    raise SystemExit("Missing process-wide external request counter")

platform = r'''
package zone.epix.app
object PackageManager { const val PERMISSION_GRANTED = 0 }
class GeckoSession {
    interface PermissionDelegate {
        interface Callback { fun grant(); fun reject() }
    }
}
open class Activity {
    fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {}
}
class PermissionShell : Activity() {
    val owned = mutableSetOf<GeckoSession>()
    val requests = mutableListOf<Int>()
    var pendingGeckoPermission: GeckoSession.PermissionDelegate.Callback? = null
    var permissionSession: GeckoSession? = null
    var permissionRequestCode: Int? = null
    var failRequest = false
    fun ownsSession(session: GeckoSession) = session in owned
    fun checkSelfPermission(permission: String) = -1
    fun requestPermissions(permissions: Array<String>, requestCode: Int) {
        if (failRequest) throw IllegalStateException("system permission UI unavailable")
        requests.add(requestCode)
    }
'''
platform += method("onAndroidPermissionsRequest", 8) + "\n"
platform += method("onRequestPermissionsResult", 4).replace("fun onRequestPermissionsResult", "override fun onRequestPermissionsResult", 1) + "\n"
platform += "companion object {\n" + counter[0] + "\n" + method("nextExternalRequestCode", 8) + "\n}\n}\n"
platform = platform.replace("    fun onRequestPermissionsResult(requestCode:", "    open fun onRequestPermissionsResult(requestCode:", 1)

with tempfile.TemporaryDirectory(prefix="epix-pending-tests-") as directory:
    temporary = pathlib.Path(directory)
    doubles = temporary / "Permissions.kt"
    doubles.write_text(platform)
    jar = temporary / "tests.jar"
    subprocess.run([
        os.environ["KOTLINC"], str(package / "PendingOperations.kt"),
        str(root / "tests/run-pending-operations-regressions.kt"), str(doubles),
        "-no-reflect", "-include-runtime", "-d", str(jar),
    ], check=True, timeout=90)
    subprocess.run([
        str(pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java"), "-jar", str(jar),
    ], check=True, timeout=20)
