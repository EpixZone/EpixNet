package zone.epix.app

import java.io.File
import java.nio.file.Files

// A literal-only LZ4 block is useful for exact fixture mutations without a decoder dependency.
private fun startupBlock(bytes: ByteArray): ByteArray {
    val output = java.io.ByteArrayOutputStream()
    output.write(byteArrayOf(109,111,122,76,122,52,48,0))
    repeat(4) { output.write((bytes.size ushr (it * 8)) and 255) }
    output.write(minOf(bytes.size,15) shl 4)
    if (bytes.size >= 15) {
        var rest = bytes.size - 15
        while (rest >= 255) { output.write(255); rest -= 255 }
        output.write(rest)
    }
    output.write(bytes)
    return output.toByteArray()
}

internal fun engineFileRegressions(expect: (Boolean) -> Unit) {
    for (text in listOf("{}", "[]", "{\"value\":[true,false,null,1,-2,1.0,1e2,\"a\\n\"]}")) {
        expect(runCatching { StrictAddonJson.parse(text) }.isSuccess)
        expect(AddonEngineFiles.mozLz4(startupBlock(text.toByteArray())).decodeToString() == text)
    }
    for (text in listOf("{\"x\":1,\"x\":2}", "{\"x\":1,\"\\u0078\":2}", "{}[]", "[1,]", "{\"x\":1,}", "[01]", "[NaN]", "[1e]", "[\"\\q\"]", "[\"\u0000\"]", "[".repeat(66) + "0" + "]".repeat(66))) {
        expect(runCatching { StrictAddonJson.parse(text) }.isFailure)
    }
    val valid = startupBlock("{}".toByteArray())
    for (bytes in listOf(valid.copyOf(10), valid.copyOf(valid.size - 1), valid + 0, valid.clone().also { it[0]=0 }, valid.clone().also { it[11]=127 })) {
        expect(runCatching { AddonEngineFiles.mozLz4(bytes) }.isFailure)
    }
    // One literal plus an overlapping four-byte match. A zero offset is invalid.
    val repeated = valid.copyOf(12) + byteArrayOf(0x10, 97, 1, 0)
    repeated[8] = 5
    expect(AddonEngineFiles.mozLz4(repeated).decodeToString() == "aaaaa")
    expect(runCatching { AddonEngineFiles.mozLz4(repeated.clone().also { it[14] = 0 }) }.isFailure)
    val folder = Files.createTempDirectory("epix-addon-engine-test-").toFile()
    try {
        val profile = AddonProfile.prepare(folder)
        val extensions = File(profile.directory,"extensions").apply { mkdir() }
        val id = "test@example.invalid"
        val archive = File(extensions,"$id.xpi").apply { writeText("approved archive") }
        val receipt = AddonProfile.Receipt(id,"1",checkNotNull(profile.installedHash(id)))
        profile.beginInstall(receipt); profile.finishInstall(receipt)
        val cache = File(profile.directory,"addonStartup.json.lz4")
        val db = File(profile.directory,"extensions.json")
        fun record(path: String = archive.absolutePath, root: String = "jar:${archive.toURI()}!/", version: String = "1") =
            "\"path\":\"$path\",\"rootURI\":\"$root\",\"version\":\"$version\",\"signedState\":2"
        fun cacheJson(location: String = "app-profile", entry: String = record("$id.xpi"), staged: String = "{}") =
            "{\"$location\":{\"path\":\"${extensions.absolutePath}\",\"addons\":{\"$id\":{$entry}},\"staged\":$staged}}"
        fun writeCache(text: String) { cache.writeBytes(startupBlock(text.toByteArray())) }
        db.writeText("{\"schemaVersion\":37,\"addons\":[{\"id\":\"$id\",\"location\":\"app-profile\",${record()}}]}")
        writeCache(cacheJson())
        expect(runCatching { AddonProfile.prepare(folder) }.isSuccess)
        for (text in listOf(
            cacheJson(entry=record("elsewhere.xpi")),
            cacheJson(entry=record("$id.xpi","jar:file:/elsewhere.xpi!/")),
            cacheJson(entry=record("$id.xpi", "jar:${archive.toURI().toASCIIString().replace("extensions/", "extensions%2f")}!/")),
            cacheJson(entry=record("$id.xpi", "jar:${archive.toURI().toASCIIString().replace("extensions/", "extensions%5c")}!/")),
            cacheJson(entry=record("$id.xpi", "jar:${archive.toURI()}?ignored!/")),
            cacheJson(entry=record("$id.xpi", "jar:${archive.toURI()}#ignored!/")),
            cacheJson(entry=record("$id.xpi", "jar:file://localhost${archive.absolutePath}!/")),
            cacheJson(entry=record("$id.xpi", "jar:${archive.toURI().toASCIIString().replace("extensions/", "extensions/%2e/")}!/")),
            cacheJson(entry=record("../extensions/$id.xpi")),
            cacheJson(entry=record("$id.xpi",version="2")),
            cacheJson(location="app-system-addons"),
            cacheJson(entry=record("$id.xpi").replace("\"signedState\":2", "\"signedState\":0")),
            cacheJson().replace(extensions.absolutePath,"/other/location"),
        )) {
            writeCache(text); expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
        }
        writeCache(cacheJson())
        val originalDb = db.readText()
        // Gecko on Android persists /data/data while Context exposes /data/user/0.
        // An alias above the profile is valid, but no alias within its managed suffix is.
        val profileAlias = File(folder, "android-profile-alias")
        Files.createSymbolicLink(profileAlias.toPath(), profile.directory.toPath())
        val aliasExtensions = File(profileAlias, "extensions")
        val aliasArchive = File(aliasExtensions, "$id.xpi")
        db.writeText(originalDb.replace(archive.absolutePath, aliasArchive.absolutePath))
        writeCache(cacheJson().replace(extensions.absolutePath, aliasExtensions.absolutePath))
        expect(runCatching { AddonProfile.prepare(folder) }.isSuccess)
        val otherProfile = File(folder, "other-profile").apply { mkdir() }
        Files.delete(profileAlias.toPath()); Files.createSymbolicLink(profileAlias.toPath(), otherProfile.toPath())
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
        Files.delete(profileAlias.toPath()); Files.createSymbolicLink(profileAlias.toPath(), profile.directory.toPath())
        val internalAlias = File(profile.directory, "alternate-extensions")
        Files.createSymbolicLink(internalAlias.toPath(), extensions.toPath())
        db.writeText(originalDb.replace(extensions.absolutePath, internalAlias.absolutePath))
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
        db.writeText(originalDb)
        writeCache(cacheJson().replace(extensions.absolutePath, aliasExtensions.absolutePath).replace("$id.xpi", "../extensions/$id.xpi"))
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
        Files.delete(internalAlias.toPath()); Files.delete(profileAlias.toPath())
        writeCache(cacheJson())
        db.writeText(originalDb.replace(archive.absolutePath,"/other/addon.xpi"))
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
        db.writeText(originalDb.replace("\"schemaVersion\":37", "\"schemaVersion\":38"))
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
        db.writeText(originalDb)
        File(extensions,id).mkdir()
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
        File(extensions,id).delete()
        archive.delete(); Files.createSymbolicLink(archive.toPath(), File(extensions,"missing").toPath())
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
        Files.delete(archive.toPath()); archive.writeText("approved archive")
        val staged = File(extensions,"staged").apply { mkdir() }
        File(staged,"$id.xpi").writeText("approved archive")
        writeCache(cacheJson(staged="{\"$id\":{}}"))
        expect(profile.hasStagedPackages())
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
        profile.beginInstall(receipt)
        expect(runCatching { AddonProfile.prepare(folder) }.isSuccess)
        File(staged,"$id.xpi").writeText("different archive")
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
        File(staged,"$id.xpi").delete(); profile.clearPending()
        writeCache(cacheJson(staged="{\"$id\":{}}"))
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
        // Ordinary unrelated engine work is untouched, but cannot be enrolled during pending work.
        File(staged,"other@example.invalid.xpi").writeText("unrelated engine archive")
        writeCache(cacheJson(staged="{\"other@example.invalid\":{}}"))
        expect(runCatching { AddonProfile.prepare(folder) }.isSuccess)
        expect(profile.hasStagedPackages())
        File(staged,"wallet@epix.zone.xpi").writeText("not a built-in package")
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
        File(staged,"wallet@epix.zone.xpi").delete(); File(staged,"other@example.invalid.xpi").delete()
        writeCache("{\"app-builtin\":{\"addons\":{},\"staged\":{\"wallet@epix.zone\":{}}}}")
        expect(runCatching { AddonProfile.prepare(folder) }.isSuccess)
        expect(profile.hasStagedPackages())
        cache.writeBytes(startupBlock(byteArrayOf(123,34,0xc0.toByte(),0xaf.toByte(),34,58,48,125)))
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
    } finally { folder.deleteRecursively() }
}
