#!/usr/bin/env python3
"""Execute the production Gecko proxy preferences with a recording controller.

Set KOTLINC and JAVA_HOME. The host-filter double follows Gecko 155's
LoadHostFilters/CanUseProxy domain rules, including leading-dot suffixes:
https://github.com/mozilla-firefox/firefox/blob/FIREFOX_155_0_RELEASE/netwerk/base/nsProtocolProxyService.cpp
Actual Gecko routing is also checked in the Android emulator.
"""
import argparse
import os
import pathlib
import re
import subprocess
import tempfile


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--android-root", type=pathlib.Path,
                    default=pathlib.Path(__file__).resolve().parents[1])
root = parser.parse_args().android_root
source = (root / "app/src/main/java/zone/epix/app/MainActivity.kt").read_text()
methods = re.findall(r"^    private fun applyClearnetRouting\(\) \{.*?^    }",
                     source, re.MULTILINE | re.DOTALL)
assert len(methods) == 1, "Expected one production proxy configuration method"
port = re.search(r"private const val SOCKS_PORT = (\d+)", source)
assert port, "Missing production SOCKS port"

kotlin = r'''
package zone.epix.app

object GeckoPreferenceController {
    const val PREF_BRANCH_USER = 1
    val values = mutableMapOf<String, Any>()
    fun setGeckoPref(name: String, value: Any, branch: Int) {
        check(branch == PREF_BRANCH_USER)
        values[name] = value
    }
}
class Shell(var torClearnet: Boolean) {
    private val SOCKS_PORT = __SOCKS_PORT__
    PRODUCTION_METHOD
}

// Independent model of Gecko 155's domain filters. A leading dot must not
// match the apex or a lookalike suffix. The existing IP entry is exact.
fun bypasses(host: String): Boolean {
    val filters = GeckoPreferenceController.values["network.proxy.no_proxies_on"] as String
    return filters.split(',').any {
        val filter = it.trim().removePrefix("*")
        when {
            filter == "127.0.0.1" -> host == filter
            filter.startsWith('.') -> host.endsWith(filter, ignoreCase = true)
            else -> host.equals(filter, ignoreCase = true) ||
                host.endsWith(".$filter", ignoreCase = true)
        }
    }
}

fun main() {
    var checks = 0
    var failures = 0
    fun verify(value: Boolean, description: String) {
        checks++
        if (!value) { failures++; println("FAIL: $description") }
    }
    val shell = Shell(true)
    // Exercise first startup and a later switch back from direct browsing.
    repeat(2) {
        shell.torClearnet = true
        shell.applyClearnetRouting()
        val prefs = GeckoPreferenceController.values
        verify(prefs["network.proxy.type"] == 1, "Tor browsing uses manual proxy")
        verify(prefs["network.proxy.socks"] == "127.0.0.1", "SOCKS stays on loopback")
        verify(prefs["network.proxy.socks_port"] == 43111, "Node SOCKS port is unchanged")
        verify(prefs["network.proxy.socks_version"] == 5, "SOCKS5 stays enabled")
        verify(prefs["network.proxy.socks_remote_dns"] == true, "General DNS stays inside Tor")
        verify(prefs["network.proxy.allow_hijacking_localhost"] == false, "Loopback cannot be hijacked")
        for (host in listOf("localhost", "127.0.0.1", "api.epix.zone", "rpc.epix.zone",
                            "evmrpc.epix.zone", "explorer.epix.zone", "nested.rpc.epix.zone",
                            "API.EPIX.ZONE")) {
            verify(bypasses(host), "$host keeps its dedicated direct route")
        }
        for (host in listOf("example.com", "epix.zone", "notepix.zone", "epix.zone.evil.test",
                            "api.epix.zone.evil.test", "evil-epix.zone", "evmrpc.epixzone",
                            "api.epix-zone", "onion.onion", "example.i2p", "192.0.2.1")) {
            verify(!bypasses(host), "$host does not bypass Tor")
        }
        shell.torClearnet = false
        shell.applyClearnetRouting()
        verify(prefs["network.proxy.type"] == 0, "User can still select direct browsing")
    }
    println("$failures Android proxy regression failure(s), $checks checks")
    check(failures == 0)
}
'''.replace("__SOCKS_PORT__", port.group(1)).replace(
    "PRODUCTION_METHOD", methods[0].replace("private fun", "fun", 1))

with tempfile.TemporaryDirectory(prefix="epix-android-proxy-tests-") as directory:
    temporary = pathlib.Path(directory)
    production = temporary / "ProxyRegressions.kt"
    production.write_text(kotlin)
    jar = temporary / "tests.jar"
    subprocess.run([os.environ["KOTLINC"], str(production), "-no-reflect",
                    "-include-runtime", "-d", str(jar)], check=True, timeout=90)
    subprocess.run([str(pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java"),
                    "-jar", str(jar)], check=True, timeout=20)
