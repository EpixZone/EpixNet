#!/usr/bin/env python3
"""Execute production file-prompt callbacks with real, controlled coroutines.

Set KOTLINC, JAVA_HOME and COROUTINES_JAR (1.9.0). The copy seam writes real
temporary partial files and can suspend on IO. The separate picked-file runner
tests the production provider-copy helper. No Android device or workers run.
"""
import os
import pathlib
import re
import subprocess
import tempfile
import zipfile

root = pathlib.Path(__file__).resolve().parents[1]
package = root / "app/src/main/java/zone/epix/app"
source = (package / "MainActivity.kt").read_text()
coroutines = pathlib.Path(os.environ["COROUTINES_JAR"])
with zipfile.ZipFile(coroutines) as archive:
    version = archive.read("META-INF/kotlinx_coroutines_core.version").decode().strip()
if version != "1.9.0":
    raise SystemExit(f"Expected declared coroutines 1.9.0, found {version}")


def method(name, indent=4):
    matches = re.findall(rf"^ {{{indent}}}(?:private |override )?fun {name}\(.*?^ {{{indent}}}}}",
                         source, re.M | re.S)
    if len(matches) != 1:
        raise SystemExit(f"Expected exactly one production callback: {name}")
    return matches[0]


def declaration(name):
    matches = re.findall(rf"^    private (?:val|var) {name}[^\n]*$", source, re.M)
    if len(matches) != 1:
        raise SystemExit(f"Expected exactly one production declaration: {name}")
    return matches[0]


teardown = re.findall(r"^        activityJob.cancel\(\).*?^        pickedDirectories.clear\(\)",
                      method("onDestroy"), re.M | re.S)
counter = re.findall(r"^        private var externalRequestCode = .+$", source, re.M)
if len(teardown) != 1 or len(counter) != 1:
    raise SystemExit("Missing production file teardown or external request counter")
replacements = {
    "// INSERT_DECLARATIONS": "\n".join(declaration(name) for name in (
        "activityJob", "scope", "pendingOperations", "promptOperations", "fileRequestCode",
        "pickedDirectories", "pendingFilePrompt", "pendingFileResult", "pendingFileCopyJob")),
    "// INSERT_CALLBACKS": "\n".join(method(name) for name in (
        "registerPrompt", "dismissFilePrompt", "onActivityResult")) + "\n"
        + method("onFilePrompt", 8).replace("override fun", "fun", 1),
    "// INSERT_TEARDOWN": teardown[0],
    "// INSERT_COUNTER": counter[0] + "\n" + method("nextExternalRequestCode", 8),
}
kotlin = (root / "tests/run-file-response-regressions.kt").read_text()
for marker, body in replacements.items():
    if kotlin.count(marker) != 1:
        raise SystemExit(f"Expected one fixture marker: {marker}")
    kotlin = kotlin.replace(marker, body)

log = '''package android.util
object Log {
    val failures = mutableListOf<Throwable>()
    fun w(tag: String, message: String, error: Throwable) { failures.add(error) }
}
'''
with tempfile.TemporaryDirectory(prefix="epix-file-response-tests-") as directory:
    temporary = pathlib.Path(directory)
    (temporary / "FileResponseRegressions.kt").write_text(kotlin)
    (temporary / "Log.kt").write_text(log)
    jar = temporary / "tests.jar"
    subprocess.run([
        os.environ["KOTLINC"], str(package / "PendingOperations.kt"),
        str(temporary / "FileResponseRegressions.kt"), str(temporary / "Log.kt"),
        "-classpath", str(coroutines), "-no-reflect", "-include-runtime", "-d", str(jar),
    ], check=True, timeout=90)
    subprocess.run([
        str(pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java"), "-cp",
        os.pathsep.join((str(jar), str(coroutines))), "zone.epix.app.FileResponseRegressionsKt",
    ], check=True, timeout=20)
