package zone.epix.app

fun main() {
    var checks = 0
    fun expect(value: Boolean) { check(value); checks++ }
    for (id in listOf("wallet@epix.zone", "THEME@EPIX.ZONE", "browser-ext@epix.zone", "installer@epix.zone")) {
        expect(!AddonPolicy.permits(id, emptyList(), emptyList()))
    }
    for (permission in listOf("nativeMessaging", "nativeMessagingFromContent", "geckoViewAddons", "experiment_apis")) {
        expect(!AddonPolicy.permits("extension@example.invalid", listOf(permission), emptyList()))
        expect(!AddonPolicy.permits("extension@example.invalid", emptyList(), listOf(permission)))
    }
    expect(AddonPolicy.permits("extension@example.invalid", listOf("tabs", "storage"), listOf("bookmarks")))
    val base = "moz-extension://test-extension/"
    for (url in listOf("https://example.com/", "http://127.0.0.1:43110/site/", "$base/options.html", "about:blank")) {
        expect(AddonPolicy.permitsNavigation(base, url))
    }
    for (url in listOf("moz-extension://wallet-extension/popup.html", "file:///data/private", "javascript:alert(1)", "resource://android/assets/", "chrome://geckoview/", "https://name:secret@example.com/", "not a URL")) {
        expect(!AddonPolicy.permitsNavigation(base, url))
    }
    val state = AddonLifecycle()
    val firstAttachment = state.attach()
    val first = state.begin()
    expect(!state.approve(first, 0))
    expect(state.prepared(first, "operation-one", "extension@example.invalid", "1", 100))
    expect(!state.prompt(first, "wallet@epix.zone", "1", 1))
    expect(!state.prompt(first, "extension@example.invalid", "2", 1))
    expect(!state.prompt(first, "extension@example.invalid", "1", 100))
    expect(state.prompt(first, "extension@example.invalid", "1", 99))
    expect(!state.prompt(first, "extension@example.invalid", "1", 99))
    expect(!state.approve(first, 100))
    expect(state.approve(first, 99))
    expect(state.mayComplete(first, "extension@example.invalid", "1"))
    expect(!state.mayComplete(first, "extension@example.invalid", "2"))
    expect(state.detach(firstAttachment) === first)
    expect(!state.mayComplete(first, "extension@example.invalid", "1"))
    val nextAttachment = state.attach()
    expect(!state.attached(firstAttachment))
    expect(state.attached(nextAttachment))
    expect(state.detach(firstAttachment) == null)
    expect(!state.live(first))
    expect(runCatching { state.begin() }.isFailure)
    expect(state.finish(first))
    val second = state.begin()
    expect(!state.finish(first))
    expect(state.pending === second)
    expect(state.prepared(second, "operation-two", "other@example.invalid", "3", 200))
    expect(state.prompt(second, "other@example.invalid", "3", 150))
    state.reconcile(second)
    expect(!state.approve(second, 151))
    expect(state.detach(nextAttachment) === second)
    expect(state.finish(second))
    expect(runCatching { state.begin() }.isFailure)
    for (text in listOf(
        "// normal generated prefs\nuser_pref(\"unrelated\", 42);\nuser_pref(\"extensions.update.enabled\", false);",
        "user_pref(\"xpinstall.signatures.required\", true); user_pref(\"xpinstall.signatures.dev-root\",false);",
        "user_pref(\"unrelated\", \"line\\nquote\\\"\"); /*comment*/ user_pref(\"extensions.update.autoUpdateDefault\",false);",
    )) expect(runCatching { GeckoAddonPrefs.check(text) }.isSuccess)
    for (text in listOf(
        "user_pref(\"extensions.update.enabled\",true);",
        "user_pref(\"xpinstall.signatures.required\",false);",
        "user_pref(\"xpinstall.signatures.dev-root\",true);",
        "user_pref(\"xpinstall.signatures.weakSignaturesTemporarilyAllowed\",true);",
        "user_pref(\"extensions.update.enabled\",false);user_pref(\"extensions.update.enabled\",true);",
        "user_pref(\"extensions.\\u0075pdate.enabled\",true);",
        "user_pref(\"extensions.update.autoUpdateDefault\",\"false\");",
        "/* never closed", "user_pref(\"x\",false);exec();", "user_pref(\"x\", 1.5);",
    )) expect(runCatching { GeckoAddonPrefs.check(text) }.isFailure)
    expect(AddonProfile.selectProfile("[General]\nStartWithLastProfile=1\n[Profile0]\nName=default\nIsRelative=1\nPath=abc.default\nDefault=1") == "abc.default")
    for (text in listOf(
        "[Profile0]\nIsRelative=1\nPath=../../other", "[Profile0]\nIsRelative=0\nPath=/tmp/other",
        "[Profile0]\nIsRelative=1\nPath=.", "[Profile0]\nIsRelative=1\nPath=..",
        "[Profile0]\nIsRelative=1\nPath=a\n[Profile1]\nIsRelative=1\nPath=b",
        "[Profile0]\nIsRelative=1\nPath=a\n[InstallFoo]\nDefault=a",
    )) expect(runCatching { AddonProfile.selectProfile(text) }.isFailure)
    val folder = java.nio.file.Files.createTempDirectory("epix-addon-profile-test-").toFile()
    try {
        val profile = AddonProfile.prepare(folder)
        expect(AddonProfile.hex64(profile.profileId))
        expect(AddonProfile.prepare(folder).profileId == profile.profileId)
        val pin = java.io.File(folder, "epix-gecko-profile-path")
        val pinned = pin.readBytes()
        for (invalid in listOf("mozilla/.", "mozilla/..")) {
            pin.writeText(invalid)
            expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
            expect(!java.io.File(folder, invalid + "/epix-addon-profile-id").exists())
        }
        pin.writeBytes(pinned)
        expect(AddonProfile.prepare(folder).profileId == profile.profileId)
        java.io.File(profile.directory, "extensions").mkdir()
        val archive = java.io.File(profile.directory, "extensions/test@example.invalid.xpi")
        archive.writeText("fixture archive")
        val hash = java.security.MessageDigest.getInstance("SHA-256").digest(archive.readBytes()).joinToString("") { "%02x".format(it) }
        val receipt = AddonProfile.Receipt("test@example.invalid", "1", hash)
        expect(profile.approvedHash(receipt.addonId, receipt.version, profile.ledger()) == null)
        profile.beginInstall(receipt)
        expect(profile.approvedHash(receipt.addonId, receipt.version, profile.ledger()) == hash)
        expect(profile.approvedHash(receipt.addonId, "2", profile.ledger()) == null)
        expect(AddonProfile.prepare(folder).ledger().pending == receipt)
        profile.finishInstall(receipt)
        expect(AddonProfile.prepare(folder).ledger().confirmed == listOf(receipt))
        val ledgerFile = java.io.File(profile.directory, "epix-addon-receipts.bin")
        val ledgerBytes = ledgerFile.readBytes()
        ledgerFile.delete()
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
        ledgerFile.writeBytes(ledgerBytes)
        archive.writeText("unapproved replacement")
        expect(profile.approvedHash(receipt.addonId, receipt.version, profile.ledger()) == null)
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
        archive.writeText("fixture archive")
        profile.configFile.delete()
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
        profile.configFile.writeText(AddonProfile.CONFIG)
        java.io.File(profile.directory, "prefs.js").writeText("user_pref(\"extensions.update.enabled\", true);")
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
        java.io.File(profile.directory, "prefs.js").delete()
        val staged = java.io.File(profile.directory, "extensions/staged").apply { mkdir() }
        java.io.File(staged,"test@example.invalid.xpi").writeText("fixture archive")
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
        profile.beginInstall(receipt)
        expect(runCatching { AddonProfile.prepare(folder) }.isSuccess)
        java.io.File(staged,"other@example.invalid.xpi").writeText("foreign")
        expect(runCatching { AddonProfile.prepare(folder) }.isFailure)
    } finally { folder.deleteRecursively() }
    engineFileRegressions(::expect)
    println("Addon policy/lifecycle/profile: $checks checks passed")
}
