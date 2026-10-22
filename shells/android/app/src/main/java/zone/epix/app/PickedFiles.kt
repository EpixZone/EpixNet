package zone.epix.app

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import java.io.File
import kotlin.coroutines.coroutineContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.ensureActive

/** Uses only the application context, with a separate directory per picker response. */
internal suspend fun copyPickedFiles(context: Context, uris: List<Uri>, dir: File): List<File> {
    val resolver = context.contentResolver
    coroutineContext.ensureActive()
    check(dir.mkdirs()) { "Could not prepare the selected files" }
    try {
        return uris.mapIndexedNotNull { index, uri ->
            coroutineContext.ensureActive()
            val name = runCatching {
                resolver.query(uri, null, null, null, null)?.use { cursor ->
                    val column = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (column >= 0 && cursor.moveToFirst()) cursor.getString(column) else null
                }
            }.getOrNull()?.replace('/', '_')?.replace('\\', '_')
                ?.takeUnless { it == "." || it == ".." || it.isBlank() } ?: "upload.bin"
            val itemDir = File(dir, index.toString()).apply { mkdirs() }
            val file = File(itemDir, name)
            try {
                resolver.openInputStream(uri)?.use { input ->
                    file.outputStream().use { output ->
                        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                        while (true) {
                            coroutineContext.ensureActive()
                            val count = input.read(buffer)
                            if (count < 0) break
                            output.write(buffer, 0, count)
                        }
                    }
                } ?: return@mapIndexedNotNull null
                file
            } catch (error: CancellationException) {
                throw error
            } catch (_: Exception) {
                file.delete()
                null
            }
        }
    } catch (error: Exception) {
        dir.deleteRecursively()
        throw error
    }
}

/** Cleanup outlives the destroyed activity and retains only its unique cache path. */
private val pickedFileCleanup = CoroutineScope(SupervisorJob() + Dispatchers.IO)
internal fun discardPickedFiles(directory: File) {
    pickedFileCleanup.launch { directory.deleteRecursively() }
}
