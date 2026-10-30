package zone.epix.app

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.security.SecureRandom

/** Pinned GeckoView155 profile layout. Unsupported layouts stop before Gecko activation. */
internal class AddonProfile private constructor(val directory: File, val profileId: String) {
    data class Receipt(val addonId: String, val version: String, val sha256: String)
    data class Ledger(val confirmed: List<Receipt>, val pending: Receipt?)
    val configFile: File get() = File(directory, CONFIG_FILE)

    fun ledger(): Ledger {
        val file = File(directory, LEDGER_FILE)
        check(file.exists()) { "Extension ownership receipts are missing" }
        val input = DataInputStream(ByteArrayInputStream(readRegular(file, 128 * 1024)))
        check(input.readUTF() == "epix-gecko-addons-1") { "Unsupported extension receipt format" }
        check(input.readUTF() == profileId) { "Extension receipts belong to a different profile" }
        fun receipt(): Receipt = Receipt(input.readUTF(), input.readUTF(), input.readUTF()).also {
            check(validId(it.addonId) && it.version.isNotBlank() && it.version.length <= 128 && hex64(it.sha256)) {
                "Invalid extension receipt"
            }
        }
        val count = input.readInt()
        check(count in 0..128) { "Too many extension receipts" }
        val confirmed = List(count) { receipt() }
        check(confirmed.map { it.addonId }.distinct().size == count) { "Duplicate extension receipt" }
        val pending = if (input.readBoolean()) receipt() else null
        check(input.available() == 0) { "Unexpected extension receipt data" }
        return Ledger(confirmed, pending)
    }

    /** Call only before engine handoff, while no install is in progress. */
    fun beginInstall(receipt: Receipt) {
        val old = ledger()
        check(old.pending == null) { "An earlier extension install needs reconciliation" }
        writeLedger(old.copy(pending = receipt))
    }

    fun finishInstall(receipt: Receipt) {
        val old = ledger()
        check(old.pending == receipt) { "Extension receipt changed during installation" }
        check(installedHash(receipt.addonId) == receipt.sha256) { "Installed extension bytes do not match approval" }
        writeLedger(Ledger(old.confirmed.filterNot { it.addonId == receipt.addonId } + receipt, null))
    }

    fun clearPending() { writeLedger(ledger().copy(pending = null)) }
    fun removed(id: String) { writeLedger(ledger().let { it.copy(confirmed = it.confirmed.filterNot { r -> r.addonId == id }) }) }

    fun installedHash(id: String): String? {
        check(validId(id)) { "Invalid extension ID" }
        val extensions = File(directory, "extensions")
        if (!extensions.exists()) return null
        requireDirectory(extensions)
        val archive = File(extensions, "$id.xpi")
        check(!Files.exists(File(extensions, id).toPath(), NOFOLLOW_LINKS)) { "Unpacked managed extensions are not supported" }
        if (!Files.exists(archive.toPath(), NOFOLLOW_LINKS)) return null
        return sha256(archive)
    }

    /** Unknown engine IDs are still inventoried, but never serve as native approval receipts. */
    fun approvedHash(id: String, version: String, receipts: Ledger): String? {
        val matching = (receipts.confirmed + listOfNotNull(receipts.pending)).filter { it.addonId == id && it.version == version }
        if (matching.isEmpty()) return null
        val digest = installedHash(id)
        return digest?.takeIf { value -> matching.any { it.sha256 == value } }
    }

    fun stagedHash(id: String): String? {
        check(validId(id)) { "Invalid extension ID" }
        val staged = File(directory, "extensions/staged")
        if (!Files.exists(staged.toPath(), NOFOLLOW_LINKS)) return null
        requireDirectory(File(directory, "extensions")); requireDirectory(staged)
        val archive = File(staged, "$id.xpi")
        if (!Files.exists(archive.toPath(), NOFOLLOW_LINKS)) return null
        return sha256(archive)
    }

    fun hasStagedPackages(): Boolean {
        val staged = File(directory, "extensions/staged")
        if (!staged.exists()) return AddonEngineFiles.pendingIds(directory).isNotEmpty()
        requireDirectory(File(directory, "extensions"))
        requireDirectory(staged)
        return Files.newDirectoryStream(staged.toPath()).use { it.iterator().hasNext() } || AddonEngineFiles.pendingIds(directory).isNotEmpty()
    }

    /** Validate approved bytes before Gecko may consume its staged directory. */
    private fun checkActivation() {
        check(readRegular(configFile, 4096).decodeToString(throwOnInvalidSequence = true) == CONFIG) { "Extension startup policy is missing or changed" }
        for (name in listOf("prefs.js", "user.js")) {
            val file = File(directory, name)
            if (file.exists()) GeckoAddonPrefs.check(readRegular(file, 4 * 1024 * 1024).decodeToString(throwOnInvalidSequence = true))
        }
        val state = ledger()
        for (receipt in state.confirmed) {
            val digest = installedHash(receipt.addonId)
            val approvedReplacement = state.pending?.takeIf { it.addonId == receipt.addonId }
            check(digest == null || digest == receipt.sha256 || digest == approvedReplacement?.sha256) {
                "A managed extension changed without a verified xite approval"
            }
        }
        state.pending?.let { pending ->
            val digest = installedHash(pending.addonId)
            val previous = state.confirmed.firstOrNull { it.addonId == pending.addonId }
            check(digest == null || digest == pending.sha256 || digest == previous?.sha256) {
                "Pending extension bytes do not match an approved receipt"
            }
        }
        AddonEngineFiles.check(directory, state)
        val staged = File(directory, "extensions/staged")
        if (Files.exists(staged.toPath(), NOFOLLOW_LINKS)) {
            requireDirectory(File(directory, "extensions")); requireDirectory(staged)
            val known = AddonEngineFiles.profilePendingIds(directory)
            val managed = state.confirmed.map { it.addonId }.toSet() + listOfNotNull(state.pending?.addonId)
            Files.newDirectoryStream(staged.toPath()).use { stream ->
                val entries = stream.take(129).toList()
                check(entries.size <= 128) { "Too many staged extensions" }
                for (entry in entries) {
                    val name = entry.fileName.toString()
                    check(name.endsWith(".xpi")) { "Unsupported staged extension layout" }
                    val id = name.removeSuffix(".xpi")
                    check(validId(id)) { "Reserved or invalid extension is staged in the profile" }
                    val pending = state.pending?.takeIf { it.addonId == id }
                    if (id in managed) {
                        check(pending != null && sha256(entry.toFile()) == pending.sha256) { "Staged extension differs from approval" }
                    } else {
                        check(id in known && Files.isRegularFile(entry, NOFOLLOW_LINKS)) { "Unknown staged extension layout" }
                    }
                }
            }
        }
    }

    private fun writeLedger(ledger: Ledger) {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
            out.writeUTF("epix-gecko-addons-1"); out.writeUTF(profileId)
            fun receipt(r: Receipt) { out.writeUTF(r.addonId); out.writeUTF(r.version); out.writeUTF(r.sha256) }
            out.writeInt(ledger.confirmed.size); ledger.confirmed.forEach(::receipt)
            out.writeBoolean(ledger.pending != null); ledger.pending?.let(::receipt)
        }
        atomicWrite(File(directory, LEDGER_FILE), bytes.toByteArray())
    }

    companion object {
        private const val CONFIG_FILE = "epix-addon-runtime.yaml"
        private const val LEDGER_FILE = "epix-addon-receipts.bin"
        private const val ID_FILE = "epix-addon-profile-id"
        private const val PIN_FILE = "epix-gecko-profile-path"
        private const val MAX_ARCHIVE = 32L * 1024 * 1024
        const val CONFIG = "prefs:\n  extensions.update.enabled: false\n  extensions.update.autoUpdateDefault: false\n  xpinstall.signatures.required: true\n  xpinstall.signatures.dev-root: false\n  xpinstall.signatures.weakSignaturesTemporarilyAllowed: false\n"
        fun hex64(value: String): Boolean = value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }
        fun validId(id: String): Boolean = id.length in 1..255 && id != "." && id != ".." &&
            id.all { it.code >= 33 && it != '/' && it != '\\' && it != ':' } && !AddonPolicy.reserved(id)

        /** Runs on IO before GeckoRuntime.create. Reuses the existing wallet's exact profile. */
        fun prepare(files: File): AddonProfile {
            requireDirectory(files)
            val pin = File(files, PIN_FILE)
            val selected = if (pin.exists()) {
                val relative = readRegular(pin, 4096).decodeToString(throwOnInvalidSequence = true)
                check(relative.matches(Regex("mozilla/[A-Za-z0-9._-]+")) && relative.substringAfter('/') !in listOf(".", "..")) { "Unsupported pinned Gecko profile" }
                File(files, relative).also(::requireDirectory)
            } else {
                val mozilla = File(files, "mozilla")
                if (!mozilla.exists()) Files.createDirectory(mozilla.toPath(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
                requireDirectory(mozilla)
                val ini = File(mozilla, "profiles.ini")
                val profile = if (ini.exists()) {
                    val selected = selectProfile(readRegular(ini, 64 * 1024).decodeToString(throwOnInvalidSequence = true))
                    File(mozilla, selected).also(::requireDirectory)
                } else {
                    check(Files.newDirectoryStream(mozilla.toPath()).use { !it.iterator().hasNext() }) { "Gecko profile selection is ambiguous" }
                    File(mozilla, "epix.default").also {
                        Files.createDirectory(it.toPath(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
                    }
                }
                atomicWrite(pin, "mozilla/${profile.name}".toByteArray())
                profile
            }
            requireDirectory(checkNotNull(selected.parentFile))
            val idFile = File(selected, ID_FILE)
            val existing = idFile.exists()
            val id = if (existing) readRegular(idFile, 128).decodeToString(throwOnInvalidSequence = true).also { check(hex64(it)) } else {
                check(!File(selected, LEDGER_FILE).exists()) { "Extension profile identity is missing" }
                ByteArray(32).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }.also {
                    atomicWrite(File(selected, CONFIG_FILE), CONFIG.toByteArray())
                    AddonProfile(selected, it).writeLedger(Ledger(emptyList(), null))
                    atomicWrite(idFile, it.toByteArray())
                }
            }
            return AddonProfile(selected, id).also { it.checkActivation() }
        }

        /** Android's ordinary default-profile INI only. Dedicated/multi-default profiles fail closed. */
        fun selectProfile(text: String): String {
            val sections = linkedMapOf<String, MutableMap<String, String>>()
            var section: MutableMap<String, String>? = null
            for (raw in text.lineSequence()) {
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith(';') || line.startsWith('#')) continue
                if (line.startsWith('[') && line.endsWith(']')) {
                    val name = line.substring(1, line.length - 1)
                    check(!sections.containsKey(name)) { "Duplicate Gecko profile section" }
                    section = linkedMapOf<String, String>().also { sections[name] = it }
                } else {
                    val parts = line.split('=', limit = 2)
                    check(parts.size == 2 && section != null && !section.containsKey(parts[0])) { "Invalid Gecko profile selection" }
                    section[parts[0]] = parts[1]
                }
            }
            check(sections.keys.none { it.startsWith("Install") }) { "Dedicated Gecko profiles are not supported" }
            val profiles = sections.filterKeys { it.matches(Regex("Profile[0-9]+")) }.values
            val candidates = profiles.filter { it["Default"] == "1" }.ifEmpty { if (profiles.size == 1) profiles.toList() else emptyList() }
            check(candidates.size == 1) { "Gecko profile selection is ambiguous" }
            val chosen = candidates.single()
            check(chosen["IsRelative"] == "1") { "External Gecko profiles are not supported" }
            return checkNotNull(chosen["Path"]).also { check(it.matches(Regex("[A-Za-z0-9._-]+")) && it !in listOf(".", "..")) }
        }

        private fun requireDirectory(file: File) {
            check(Files.isDirectory(file.toPath(), NOFOLLOW_LINKS)) { "Gecko profile path is not a regular directory" }
        }
        internal fun readRegular(file: File, max: Int): ByteArray {
            check(Files.isRegularFile(file.toPath(), NOFOLLOW_LINKS)) { "Gecko profile file is missing or linked" }
            Files.newByteChannel(file.toPath(), setOf(READ, NOFOLLOW_LINKS)).use { channel ->
                check(channel.size() <= max) { "Gecko profile file exceeds its limit" }
                val data = ByteBuffer.allocate(max + 1)
                while (data.hasRemaining() && channel.read(data) >= 0) Unit
                check(data.position() <= max) { "Gecko profile file grew beyond its limit" }
                return data.array().copyOf(data.position())
            }
        }
        private fun sha256(file: File): String {
            check(Files.isRegularFile(file.toPath(), NOFOLLOW_LINKS)) { "Installed extension is missing or linked" }
            Files.newByteChannel(file.toPath(), setOf(READ, NOFOLLOW_LINKS)).use { channel ->
                check(channel.size() in 1..MAX_ARCHIVE) { "Installed extension exceeds the package limit" }
                val hash = MessageDigest.getInstance("SHA-256"); val data = ByteBuffer.allocate(64 * 1024)
                var size = 0L
                while (true) {
                    val read = channel.read(data); if (read < 0) break
                    size += read; check(size <= MAX_ARCHIVE); data.flip(); hash.update(data); data.clear()
                }
                return hash.digest().joinToString("") { "%02x".format(it) }
            }
        }
        private fun atomicWrite(file: File, data: ByteArray) {
            val parent = checkNotNull(file.parentFile)
            requireDirectory(parent)
            if (Files.exists(file.toPath(), NOFOLLOW_LINKS)) check(Files.isRegularFile(file.toPath(), NOFOLLOW_LINKS)) { "Linked extension state file" }
            val temporary = Files.createTempFile(parent.toPath(), ".epix-addon-", ".tmp", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            try {
                FileChannel.open(temporary, WRITE).use { channel ->
                    val buffer = ByteBuffer.wrap(data); while (buffer.hasRemaining()) channel.write(buffer); channel.force(true)
                }
                Files.move(temporary, file.toPath(), ATOMIC_MOVE, REPLACE_EXISTING)
                FileChannel.open(parent.toPath(), READ).use { it.force(true) }
            } finally { Files.deleteIfExists(temporary) }
        }
    }
}

/** Parse Gecko's persisted user_pref grammar without evaluating JavaScript. */
internal object GeckoAddonPrefs {
    private val protected = mapOf(
        "extensions.update.enabled" to false,
        "extensions.update.autoUpdateDefault" to false,
        "xpinstall.signatures.required" to true,
        "xpinstall.signatures.dev-root" to false,
        "xpinstall.signatures.weakSignaturesTemporarilyAllowed" to false,
    )
    fun check(text: String) {
        val reader = Reader(text)
        val seen = mutableSetOf<String>()
        while (!reader.done()) {
            reader.word("user_pref"); reader.word("(")
            val name = reader.string(); reader.word(",")
            val value = reader.value(); reader.word(")"); reader.word(";")
            if (name in protected) {
                check(seen.add(name) && value == protected[name]) { "Managed extension startup policy was overridden" }
            }
        }
    }
    private class Reader(val text: String) {
        var offset = 0
        fun space() {
            while (offset < text.length) {
                if (text[offset].isWhitespace()) { offset++; continue }
                if (text.startsWith("//", offset)) { offset = text.indexOf('\n', offset).let { if (it < 0) text.length else it + 1 }; continue }
                if (text.startsWith("/*", offset)) {
                    val end = text.indexOf("*/", offset + 2); check(end >= 0) { "Unclosed Gecko preference comment" }; offset = end + 2; continue
                }
                break
            }
        }
        fun done(): Boolean { space(); return offset == text.length }
        fun word(word: String) { space(); check(text.startsWith(word, offset)) { "Unsupported Gecko preference syntax" }; offset += word.length }
        fun string(): String {
            word("\""); val out = StringBuilder()
            while (offset < text.length) {
                val c = text[offset++]
                if (c == '"') return out.toString()
                check(c.code >= 32) { "Invalid Gecko preference string" }
                if (c != '\\') { out.append(c); continue }
                check(offset < text.length)
                out.append(when (val escaped = text[offset++]) {
                    '"', '\\', '/' -> escaped
                    'n' -> '\n'; 'r' -> '\r'; 't' -> '\t'; 'b' -> '\b'; 'f' -> '\u000c'
                    'u' -> { check(offset + 4 <= text.length); text.substring(offset, offset + 4).toInt(16).toChar().also { offset += 4 } }
                    else -> error("Unsupported Gecko preference escape")
                })
            }
            error("Unclosed Gecko preference string")
        }
        fun value(): Any {
            space(); check(offset < text.length)
            if (text[offset] == '"') return string()
            for ((literal, value) in listOf("true" to true, "false" to false)) {
                if (text.startsWith(literal, offset)) { offset += literal.length; return value }
            }
            val start = offset
            if (text[offset] == '-') offset++
            while (offset < text.length && text[offset] in '0'..'9') offset++
            check(offset > start) { "Unsupported Gecko preference value" }
            return text.substring(start, offset).toLong()
        }
    }
}
