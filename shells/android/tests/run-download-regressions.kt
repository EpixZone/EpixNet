package zone.epix.app

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

private class Body(bytes: ByteArray) : ByteArrayInputStream(bytes) {
    var closes = 0
    override fun close() { closes++; super.close() }
}

fun main() {
    val bytes = ByteArray(100_001) { (it % 251).toByte() }
    val body = Body(bytes)
    val transfer = DownloadTransfer(body)
    val saved = ByteArrayOutputStream()
    check(transfer.save({ saved }) == bytes.size.toLong())
    check(saved.toByteArray().contentEquals(bytes))
    check(transfer.isComplete && body.closes == 1)
    transfer.cancel()
    check(body.closes == 1)

    // Provider failure after partial output closes both streams. The provider
    // may have returned an existing document, so the caller must not delete it.
    val failedBody = Body(bytes)
    var outputCloses = 0
    val output = object : OutputStream() {
        override fun write(b: Int) { throw IOException("Provider out of space") }
        override fun close() { outputCloses++ }
    }
    val failed = DownloadTransfer(failedBody)
    check(runCatching { failed.save({ output }) }.isFailure)
    check(!failed.isComplete && outputCloses == 1 && failedBody.closes == 1)

    // A picker provider may return an existing document. Neither cancellation
    // before opening nor an open failure can delete or alter its old bytes.
    val original = java.nio.file.Files.createTempFile("epix-existing", ".bin").toFile()
    original.writeBytes(bytes)
    val untouched = DownloadTransfer(Body(byteArrayOf(1, 2)))
    untouched.cancel()
    check(runCatching { untouched.save({ original.outputStream() }) }.isFailure)
    check(original.readBytes().contentEquals(bytes))
    val refused = DownloadTransfer(Body(byteArrayOf(3, 4)))
    check(runCatching { refused.save({ throw IOException("Read-only document") }) }.isFailure)
    check(original.readBytes().contentEquals(bytes))
    original.delete()

    val unopenedBody = Body(bytes)
    val unopened = DownloadTransfer(unopenedBody)
    unopened.cancel()
    check(runCatching { unopened.save({ error("Must not open a cancelled download") }) }.isFailure)
    check(unopenedBody.closes == 1)

    val openingBody = Body(bytes)
    check(runCatching { DownloadTransfer(openingBody).save({ throw IOException("No provider") }) }.isFailure)
    check(openingBody.closes == 1)

    // Session/Activity cancellation must close a blocked response, unblock IO,
    // without another URL request or deleting the selected destination.
    val reading = CountDownLatch(1)
    val closed = CountDownLatch(1)
    val finished = CountDownLatch(1)
    val blocking = object : InputStream() {
        override fun read(): Int {
            reading.countDown()
            check(closed.await(3, TimeUnit.SECONDS))
            throw IOException("Stream closed")
        }
        override fun close() { closed.countDown() }
    }
    val cancelled = DownloadTransfer(blocking)
    thread {
        check(runCatching { cancelled.save({ ByteArrayOutputStream() }) }.isFailure)
        finished.countDown()
    }
    check(reading.await(3, TimeUnit.SECONDS))
    cancelled.cancel()
    check(finished.await(3, TimeUnit.SECONDS))
    check(!cancelled.isComplete)

    // Names stay a single harmless title even with paths/control characters.
    check(safeDownloadName("../../track.flac") == "track.flac")
    check(safeDownloadName("C:\\music\\track.flac") == "track.flac")
    check(safeDownloadName("..") == "download")
    check(safeDownloadName("a\u0000\u202eb.flac") == "ab.flac")
    check(safeDownloadName("x".repeat(400)).length == 180)
    println("Download stream, provider failure, cancellation and filename regressions passed")
}
