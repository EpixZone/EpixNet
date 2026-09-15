#!/usr/bin/env python3
"""Compile the shell's URL methods and test them on a connected Android emulator.

Set ANDROID_HOME, JAVA_HOME and KOTLINC (the kotlinc executable). D8_JAR can
override the SDK's dex compiler (Kotlin 2.3 needs R8/D8 8.13.19+). Tests use real
Android Uri/Intent implementations; browser widgets are small test doubles.
The shared Rust core and GeckoView rendering are not exercised by this script.
"""
import os
import pathlib
import re
import subprocess
import tempfile


source = (pathlib.Path(__file__).resolve().parents[1]
          / "app/src/main/java/zone/epix/app/MainActivity.kt").read_text()
sdk = pathlib.Path(os.environ["ANDROID_HOME"])
android_jar = sdk / "platforms/android-36/android.jar"
adb = str(sdk / "platform-tools/adb")


def method(name):
    start = source.index("    private fun " + name + "(")
    if name in {"searchUrl", "nodeUrl"}:
        end = source.index("\n\n", start)
    else:
        end = source.index("\n    }", start) + len("\n    }")
    return source[start:end].replace("private fun", "fun", 1)


def constant(name):
    return re.search(r"^        private (?:const )?val " + name + r" = .+$",
                     source, re.MULTILINE)[0].replace("private ", "", 1)


stub = r'''
import android.content.Intent
import android.net.Uri

object Context { const val INPUT_METHOD_SERVICE = "input" }
class InputMethodManager { fun hideSoftInputFromWindow(token: Any, flags: Int) {} }
class AddressBar { val windowToken = Any(); fun clearFocus() {} }
class Session { var url = ""; fun loadUri(value: String) { url = value } }
class Tab { val session = Session() }
class Shell {
    var currentDisplay = "dashboard.epix"
    val currentTab = Tab()
    val addressBar = AddressBar()
    fun getSystemService(name: String): Any = InputMethodManager()
'''
checks = r'''
}
fun main() {
    val shell = Shell()
    var failures = 0
    fun verify(condition: Boolean, message: String) {
        if (!condition) { failures++; println("FAIL: $message") }
    }
    val base = "http://127.0.0.1:42222/"
    for (link in listOf(
        "epix://talk.epix/posts/42?sort=new#reply",
        "epix://talk.epix/a%20b?q=a%2Fb#c%20d",
        "epix://dashboard.epix?review=path#section",
    )) {
        val uri = Uri.parse(link)
        val path = uri.encodedPath.orEmpty().ifEmpty { "/" }
        val query = uri.encodedQuery?.let { "?$it" }.orEmpty()
        val fragment = uri.encodedFragment?.let { "#$it" }.orEmpty()
        val expected = base + uri.host + path + query + fragment
        shell.navigate(link)
        verify(shell.currentTab.session.url == expected,
            "typed link lost path/query/fragment: $link -> ${shell.currentTab.session.url}")
        val target = shell.intentTarget(Intent(Intent.ACTION_VIEW, uri))!!
        verify(shell.nodeUrl(target) == expected,
            "external link lost path/query/fragment: $link -> ${shell.nodeUrl(target)}")
    }
    verify(shell.nodeUrl("dashboard.epix") == base + "dashboard.epix/", "bare xite still opens its root")
    verify(shell.xiteRewrite("https://example.com/path") == null, "ordinary HTTPS URL is unchanged")
    verify(shell.intentTarget(Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com"))) == null,
        "non-Epix external URLs are rejected")
    shell.navigate("two words")
    verify(shell.currentTab.session.url == "https://duckduckgo.com/?q=two+words", "search still works")
    println("$failures Android URL regression failure(s)")
    check(failures == 0)
}
'''

methods = ["navigate", "searchUrl", "xiteRewrite", "nodeUrl", "intentTarget"]
kotlin = stub + "\n".join(method(name) for name in methods)
kotlin += "\n    companion object {\n"
kotlin += "\n".join(constant(name) for name in ["UI_PORT", "NODE_BASE", "XITE_ADDRESS", "BARE_XITE_NAME", "SEARCH_BASE"])
kotlin += "\n    }\n" + checks
with tempfile.TemporaryDirectory(prefix="epix-android-regressions-") as directory:
    root = pathlib.Path(directory)
    (root / "UrlRegressions.kt").write_text(kotlin)
    subprocess.run([os.environ["KOTLINC"], str(root / "UrlRegressions.kt"),
                    "-classpath", str(android_jar), "-no-reflect", "-include-runtime",
                    "-d", str(root / "tests.jar")], check=True)
    d8_command = ([str(pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java"),
                   "-cp", os.environ["D8_JAR"], "com.android.tools.r8.D8"]
                  if "D8_JAR" in os.environ else [str(sdk / "build-tools/36.0.0/d8")])
    d8 = subprocess.run(d8_command + ["--lib", str(android_jar), "--min-api", "26", "--output", str(root),
                                    str(root / "tests.jar")], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if d8.returncode:
        print(d8.stdout[-8000:])
        d8.check_returncode()
    elif "Warning:" in d8.stdout:
        print("D8 emitted Kotlin metadata compatibility warnings; runtime tests follow.")
    remote = "/data/local/tmp/epix-url-regressions.dex"
    subprocess.run([adb, "-e", "push", str(root / "classes.dex"), remote], check=True)
    result = subprocess.run([adb, "-e", "shell", "CLASSPATH=" + remote,
                             "app_process", "/system/bin", "UrlRegressionsKt"])
    raise SystemExit(result.returncode)
