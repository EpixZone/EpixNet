package zone.epix.app

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kotlinx.coroutines.*

class Uri(val scheme: String)
class Intent(val data: Uri?)
class Resolver {
    var opens = 0
    val output = ByteArrayOutputStream()
    fun openOutputStream(uri: Uri, mode: String): java.io.OutputStream {
        check(uri.scheme == "content" && mode == "wt")
        opens++
        return output
    }
}
class Context { val contentResolver = Resolver() }
class TrackedBody : ByteArrayInputStream(byteArrayOf(1, 2, 3)) {
    var closed = false
    override fun close() { closed = true; super.close() }
}
internal class DownloadShell {
    val applicationContext = Context()
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
    var disposed = false
    var downloadPickerOutstanding = true
    val notices = mutableListOf<String>()
    private val pendingOperations = PendingOperations()
    class DownloadSave(val transfer: DownloadTransfer) {
        lateinit var operation: PendingOperations.Operation
        var job: Job? = null
    }
    var pendingDownload: DownloadSave? = null
    fun prepare(body: TrackedBody): DownloadSave {
        val request = DownloadSave(DownloadTransfer(body))
        request.operation = pendingOperations.register {
            request.transfer.cancel()
            request.job?.cancel()
        }
        pendingDownload = request
        return request
    }
    fun downloadNotice(message: String) { notices.add(message) }
    companion object { const val RESULT_OK = -1; const val DOWNLOAD_REQUEST_CODE = 0x3000 }
// INSERT_HANDLER
}

fun main() = runBlocking {
    val shell = DownloadShell()
    val body = TrackedBody()
    shell.prepare(body)
    check(shell.handleDownloadResult(0x3000, -1, Intent(Uri("file"))))
    check(body.closed && shell.applicationContext.contentResolver.opens == 0)
    check(shell.pendingDownload == null && !shell.downloadPickerOutstanding)

    // An orphan response after recreation never opens the provider document.
    check(shell.handleDownloadResult(0x3000, -1, Intent(Uri("content"))))
    check(shell.applicationContext.contentResolver.opens == 0)

    val cancelledBody = TrackedBody()
    shell.prepare(cancelledBody)
    check(shell.handleDownloadResult(0x3000, 0, Intent(Uri("content"))))
    check(cancelledBody.closed && shell.applicationContext.contentResolver.opens == 0)

    val goodBody = TrackedBody()
    val request = shell.prepare(goodBody)
    check(shell.handleDownloadResult(0x3000, -1, Intent(Uri("content"))))
    request.job!!.join()
    check(goodBody.closed && request.transfer.isComplete)
    check(shell.applicationContext.contentResolver.opens == 1)
    check(shell.applicationContext.contentResolver.output.toByteArray().contentEquals(byteArrayOf(1, 2, 3)))
    check(shell.notices == listOf("Download saved."))
    check(!shell.handleDownloadResult(0x4001, -1, Intent(Uri("content"))))
    println("Download result rejects file URIs, cancellation and orphan replies; content save passes")
}
