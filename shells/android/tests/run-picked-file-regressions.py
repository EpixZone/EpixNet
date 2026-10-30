#!/usr/bin/env python3
"""Run production picked-file IO with real coroutines and narrow resolver doubles."""
import os
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
sources = {
    "Context.kt": r'''
package android.content
import android.net.Uri
import java.io.File
import java.io.InputStream
open class Context(val cacheDir: File, val contentResolver: Resolver)
class Cursor(val name: String?) : AutoCloseable {
    fun getColumnIndex(column: String) = 0
    fun moveToFirst() = name != null
    fun getString(index: Int) = name
    override fun close() {}
}
class Resolver {
    val entries = mutableMapOf<String, Pair<String?, () -> InputStream?>>()
    fun query(uri: Uri, a: Any?, b: Any?, c: Any?, d: Any?) = Cursor(entries.getValue(uri.value).first)
    fun openInputStream(uri: Uri) = entries.getValue(uri.value).second()
}
''',
    "Uri.kt": "package android.net\ndata class Uri(val value: String)\n",
    "Columns.kt": 'package android.provider\nobject OpenableColumns { const val DISPLAY_NAME = "name" }\n',
    "Tests.kt": r'''
package zone.epix.app
import android.content.*
import android.net.Uri
import java.io.*
import java.nio.file.Files
import kotlinx.coroutines.*

fun main() = runBlocking {
    val root = Files.createTempDirectory("epix-picked-tests-").toFile()
    val resolver = Resolver()
    val context = Context(root, resolver)
    try {
        resolver.entries["a"] = "same.txt" to { ByteArrayInputStream("first".toByteArray()) }
        resolver.entries["b"] = "same.txt" to { ByteArrayInputStream("second".toByteArray()) }
        val files = copyPickedFiles(context, listOf(Uri("a"), Uri("b")), File(root, "duplicates"))
        check(files.size == 2 && files[0] != files[1])
        check(files.map { it.readText() } == listOf("first", "second"))

        resolver.entries["traversal"] = "../../outside.txt" to { ByteArrayInputStream(byteArrayOf(1)) }
        resolver.entries["dot"] = ".." to { ByteArrayInputStream(byteArrayOf(2)) }
        val safe = copyPickedFiles(context, listOf(Uri("traversal"), Uri("dot")), File(root, "safe"))
        check(safe.all { it.canonicalPath.startsWith(File(root, "safe").canonicalPath + File.separator) })
        check(safe[1].name == "upload.bin")

        var closed = false
        resolver.entries["error"] = "broken.bin" to { object : InputStream() {
            override fun read(): Int = throw IOException("provider failure")
            override fun close() { closed = true }
        } }
        val partial = copyPickedFiles(context, listOf(Uri("error"), Uri("a")), File(root, "partial"))
        check(closed && partial.size == 1 && partial.single().readText() == "first")
        check(!File(root, "partial/0/broken.bin").exists())

        val copyJob = SupervisorJob()
        var cancellationClosed = false
        resolver.entries["cancel"] = "large.bin" to { object : InputStream() {
            var reads = 0
            override fun read(): Int = error("bulk read required")
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                if (++reads == 1) { buffer[offset] = 7; return 1 }
                copyJob.cancel()
                return 0
            }
            override fun close() { cancellationClosed = true }
        } }
        val cancelDir = File(root, "cancel")
        val owner = CoroutineScope(copyJob + Dispatchers.Unconfined)
        val canceled = owner.async { copyPickedFiles(context, listOf(Uri("cancel")), cancelDir) }
        try { canceled.await(); error("copy should cancel") } catch (_: CancellationException) { }
        copyJob.join()
        check(cancellationClosed && !cancelDir.exists())

        val beforeDir = File(root, "before")
        val alreadyCanceled = SupervisorJob().apply { cancel() }
        val skipped = CoroutineScope(alreadyCanceled + Dispatchers.Unconfined).async {
            copyPickedFiles(context, listOf(Uri("a")), beforeDir)
        }
        try { skipped.await(); error("copy should not start") } catch (_: CancellationException) { }
        alreadyCanceled.join()
        check(!beforeDir.exists())
        check(files[0].readText() == "first")
        println("Picked file regressions: duplicate names, path containment, partial IO failure, mid-copy cancellation, and canceled dispatch passed")
    } finally { root.deleteRecursively() }
}
''',
}
with tempfile.TemporaryDirectory(prefix="epix-picked-file-tests-") as directory:
    temp = pathlib.Path(directory)
    for name, content in sources.items():
        (temp / name).write_text(content)
    jar = temp / "tests.jar"
    coroutines = pathlib.Path(os.environ["COROUTINES_JAR"])
    subprocess.run([
        os.environ["KOTLINC"], str(root / "app/src/main/java/zone/epix/app/PickedFiles.kt"),
        *(str(temp / name) for name in sources), "-classpath", str(coroutines),
        "-include-runtime", "-d", str(jar),
    ], check=True, timeout=90)
    subprocess.run([
        str(pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java"), "-cp",
        os.pathsep.join((str(jar), str(coroutines))), "zone.epix.app.TestsKt",
    ], check=True, timeout=30)
