package zone.epix.app

import java.io.File
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS

/** Read-only checks for the pinned GeckoView155 extension database/startup cache. */
internal object AddonEngineFiles {
    fun check(profile: File, receipts: AddonProfile.Ledger) {
        val managed = receipts.confirmed.map { it.addonId }.toSet() + listOfNotNull(receipts.pending?.addonId)
        val versions = (receipts.confirmed + listOfNotNull(receipts.pending)).groupBy { it.addonId }
        // Android and Gecko can spell the same app profile as /data/user/0 or /data/data.
        // Resolve identity only at the profile root; every managed suffix remains exact.
        fun profilePath(path: File, suffix: String): Boolean {
            if (!path.isAbsolute || path.path.split('/').any { it == "." || it == ".." }) return false
            var ancestor = path
            for (part in suffix.split('/').asReversed()) {
                if (ancestor.name != part) return false
                ancestor = ancestor.parentFile ?: return false
            }
            return Files.isSameFile(ancestor.toPath(), profile.toPath())
        }
        fun record(id: String, data: Map<String, Any?>, location: String, base: String?, cache: Boolean) {
            if (id !in managed) return
            check(location == "app-profile") { "Managed extension has an unsupported engine location" }
            val path = data["path"] as? String ?: error("Managed extension path is absent")
            val actual = if (File(path).isAbsolute) File(path) else File(checkNotNull(base), path)
            check(profilePath(actual, "extensions/$id.xpi")) { "Managed extension engine path changed" }
            check(data["version"] in versions[id].orEmpty().map { it.version }) { "Managed extension engine version changed" }
            check(data["signedState"] == JsonNumber("2")) { "Managed extension has no ordinary Mozilla signature" }
            check(data["type"] == null || data["type"] == "extension") { "Managed package is not an extension" }
            if (cache) check(base != null && profilePath(File(base), "extensions")) { "Managed extension location changed" }
            if (cache || data.containsKey("rootURI")) {
                val root = data["rootURI"] as? String ?: error("Managed extension root URI is absent")
                check(root.startsWith("jar:file:") && root.endsWith("!/")) { "Unsupported managed extension root URI" }
                val uri = URI(root.removePrefix("jar:").removeSuffix("!/"))
                check(uri.scheme == "file" && uri.rawAuthority == null && uri.rawQuery == null && uri.rawFragment == null &&
                    !Regex("(?i)%2f|%5c").containsMatchIn(uri.rawPath.orEmpty())) { "Unsupported managed extension file URI" }
                check(profilePath(File(uri), "extensions/$id.xpi")) { "Managed extension root URI changed" }
            }
        }
        val database = File(profile, "extensions.json")
        if (Files.exists(database.toPath(), NOFOLLOW_LINKS)) {
            val root = StrictAddonJson.parse(utf8(AddonProfile.readRegular(database, 4 * 1024 * 1024))).objectValue()
            check(root["schemaVersion"] == JsonNumber("37")) { "Unsupported Gecko extension database schema" }
            val rows = root["addons"] as? List<*> ?: error("Invalid Gecko extension database")
            check(rows.size <= 4096)
            val seen = mutableSetOf<String>()
            for (row in rows) {
                val data = row.objectValue(); val id = data["id"] as? String ?: error("Missing engine extension ID")
                if (id in managed) check(seen.add(id)) { "Conflicting managed extension records" }
                record(id, data, data["location"] as? String ?: "", null, false)
            }
        }
        val seen = mutableSetOf<String>()
        for ((location, value) in startup(profile)) {
            val data = value.objectValue()
            val addons = (data["addons"] ?: emptyMap<String, Any?>()).objectValue()
            check(addons.size <= 4096)
            for ((id, entry) in addons) {
                if (id in managed) check(seen.add(id)) { "Conflicting managed startup records" }
                record(id, entry.objectValue(), location, data["path"] as? String, true)
            }
            val staged = (data["staged"] ?: emptyMap<String, Any?>()).objectValue()
            check(staged.size <= 128)
            for ((id, _) in staged) if (id in managed) {
                check(location == "app-profile" && receipts.pending?.addonId == id) { "Unapproved managed extension is staged" }
            }
        }
    }

    fun pendingIds(profile: File): Set<String> = startup(profile).values.flatMap {
        (it.objectValue()["staged"] ?: emptyMap<String, Any?>()).objectValue().keys
    }.toSet()

    fun profilePendingIds(profile: File): Set<String> = startup(profile)["app-profile"]?.objectValue()?.let {
        (it["staged"] ?: emptyMap<String, Any?>()).objectValue().keys
    } ?: emptySet()

    private fun startup(profile: File): Map<String, Any?> {
        val file = File(profile, "addonStartup.json.lz4")
        if (!Files.exists(file.toPath(), NOFOLLOW_LINKS)) return emptyMap()
        return StrictAddonJson.parse(utf8(mozLz4(AddonProfile.readRegular(file, 4 * 1024 * 1024)))).objectValue()
    }

    /** Mozilla's bounded LZ4 block container, not a general-purpose decompressor. */
    fun mozLz4(input: ByteArray): ByteArray {
        val header = byteArrayOf(109, 111, 122, 76, 122, 52, 48, 0)
        check(input.size >= 12 && input.copyOfRange(0, 8).contentEquals(header)) { "Invalid Gecko startup cache header" }
        val length = (8..11).fold(0L) { n, i -> n or ((input[i].toLong() and 255) shl ((i - 8) * 8)) }
        check(length in 2..(4L * 1024 * 1024)) { "Gecko startup cache exceeds its limit" }
        val output = ByteArray(length.toInt()); var read = 12; var written = 0
        fun extended(initial: Int): Int {
            var size = initial
            if (initial == 15) do {
                check(read < input.size) { "Truncated Gecko startup cache" }
                val extra = input[read++].toInt() and 255
                size += extra; check(size <= output.size) { "Gecko startup cache length overflow" }
            } while (extra == 255)
            return size
        }
        while (read < input.size) {
            val token = input[read++].toInt() and 255
            val literals = extended(token ushr 4)
            check(literals <= input.size - read && literals <= output.size - written) { "Invalid Gecko startup literal length" }
            input.copyInto(output, written, read, read + literals); read += literals; written += literals
            if (read == input.size) break
            check(read + 2 <= input.size) { "Truncated Gecko startup offset" }
            val offset = (input[read].toInt() and 255) or ((input[read + 1].toInt() and 255) shl 8); read += 2
            check(offset > 0 && offset <= written) { "Invalid Gecko startup offset" }
            val matched = extended(token and 15) + 4
            check(matched <= output.size - written) { "Invalid Gecko startup match length" }
            repeat(matched) { output[written] = output[written - offset]; written++ }
        }
        check(written == output.size && read == input.size) { "Truncated Gecko startup data" }
        return output
    }

    private fun utf8(bytes: ByteArray): String = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
}

internal data class JsonNumber(val value: String)
@Suppress("UNCHECKED_CAST")
private fun Any?.objectValue(): Map<String, Any?> = this as? Map<String, Any?> ?: error("Invalid Gecko extension metadata object")

/** Strict bounded JSON, retaining exact numbers and rejecting duplicate object keys. */
internal object StrictAddonJson {
    private val number = Regex("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
    fun parse(text: String): Any? = Reader(text).run { val value = value(0); space(); check(offset == text.length); value }
    private class Reader(val text: String) {
        var offset = 0; var nodes = 0
        fun space() { while (offset < text.length && text[offset] in " \t\r\n") offset++ }
        fun take(c: Char): Boolean { space(); return (offset < text.length && text[offset] == c).also { if (it) offset++ } }
        fun value(depth: Int): Any? {
            check(depth <= 64 && ++nodes <= 200000) { "Gecko metadata nesting exceeds its limit" }
            space(); check(offset < text.length)
            return when (text[offset]) {
                '{' -> {
                    offset++; val map = linkedMapOf<String, Any?>()
                    if (!take('}')) do {
                        val key = string(); check(!map.containsKey(key)) { "Duplicate Gecko metadata key" }; check(take(':'))
                        map[key] = value(depth + 1)
                        if (take('}')) break
                        check(take(','))
                    } while (true)
                    map
                }
                '[' -> {
                    offset++; val list = mutableListOf<Any?>()
                    if (!take(']')) do {
                        list.add(value(depth + 1)); if (take(']')) break; check(take(','))
                    } while (true)
                    list
                }
                '"' -> string()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> {
                    val match = number.find(text, offset)
                    check(match != null && match.range.first == offset) { "Invalid Gecko metadata value" }
                    offset = match.range.last + 1; JsonNumber(match.value)
                }
            }
        }
        private fun literal(word: String, result: Any?): Any? { check(text.startsWith(word, offset)); offset += word.length; return result }
        private fun string(): String {
            check(take('"')); val out = StringBuilder()
            while (offset < text.length) {
                val c = text[offset++]
                if (c == '"') return out.toString()
                check(c.code >= 32)
                if (c != '\\') { out.append(c); continue }
                check(offset < text.length)
                out.append(when (val escaped = text[offset++]) {
                    '"', '\\', '/' -> escaped
                    'b' -> '\b'; 'f' -> '\u000c'; 'n' -> '\n'; 'r' -> '\r'; 't' -> '\t'
                    'u' -> { check(offset + 4 <= text.length); text.substring(offset, offset + 4).toInt(16).toChar().also { offset += 4 } }
                    else -> error("Invalid Gecko metadata escape")
                })
            }
            error("Unclosed Gecko metadata string")
        }
    }
}
