import java.io.FileInputStream
import java.util.Properties
import java.security.MessageDigest

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Release signing config lives outside the repo. Put the key details in
// shells/android/keystore.properties (gitignored; copy keystore.properties.example)
// or the EPIX_KEYSTORE_* env vars. When neither is present, `assembleRelease`
// still builds but is left unsigned, and debug builds are unaffected. See
// shells/android/RELEASE-SIGNING.md for the one-time keystore setup.
val keystorePropsFile = rootProject.file("keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) {
        FileInputStream(keystorePropsFile).use { load(it) }
    }
}

// Version from the release tag (EPIX_VERSION, set by CI), else a dev default.
// versionCode must be a monotonically increasing integer for the Play Store,
// so derive it from the semver: major*1_000_000 + minor*1_000 + patch (a
// higher versionName always yields a higher code). BuildConfig.VERSION_NAME
// carries the name into the app so the node reports the tagged version too.
val epixVersion = System.getenv("EPIX_VERSION")?.takeIf { it.isNotBlank() } ?: "0.3.0"
val epixVersionCode = System.getenv("EPIX_VERSION_CODE")?.let { value ->
    value.toIntOrNull()?.takeIf { it in 1..2_100_000_000 }
        ?: throw GradleException("EPIX_VERSION_CODE must be an integer from 1 to 2100000000")
} ?: run {
    val n = Regex("""\d+""").findAll(epixVersion).map { it.value.toIntOrNull() ?: 0 }.toList()
    (n.getOrElse(0) { 0 }) * 1_000_000 + (n.getOrElse(1) { 0 }) * 1_000 + (n.getOrElse(2) { 0 })
}

// Play uploads must never silently use an unsigned bundle or a debug key.
val validatePlaySigning by tasks.registering {
    doLast {
        val cfg = android.signingConfigs.getByName("release")
        if (cfg.storeFile?.isFile != true || cfg.storePassword.isNullOrBlank() ||
            cfg.keyAlias.isNullOrBlank() || cfg.keyPassword.isNullOrBlank()) {
            throw GradleException("Configure release signing before building a Play bundle; see RELEASE-SIGNING.md")
        }
        if (epixVersionCode !in 1..2_100_000_000) {
            throw GradleException("Set a valid, increasing EPIX_VERSION_CODE for the Play upload")
        }
    }
}

android {
    namespace = "zone.epix.app"
    compileSdk = 37

    buildFeatures {
        buildConfig = true
    }

    defaultConfig {
        applicationId = "zone.epix.app"
        minSdk = 26
        targetSdk = 36
        versionCode = epixVersionCode
        versionName = epixVersion
        // The Rust core is prebuilt per-ABI into src/main/jniLibs by cargo-ndk.
        ndk { abiFilters += listOf("arm64-v8a") }
    }

    signingConfigs {
        create("release") {
            val storeFilePath =
                keystoreProps.getProperty("storeFile") ?: System.getenv("EPIX_KEYSTORE_FILE")
            if (!storeFilePath.isNullOrBlank()) {
                storeFile = file(storeFilePath)
                storePassword =
                    keystoreProps.getProperty("storePassword") ?: System.getenv("EPIX_KEYSTORE_PASSWORD")
                keyAlias =
                    keystoreProps.getProperty("keyAlias") ?: System.getenv("EPIX_KEY_ALIAS")
                keyPassword =
                    keystoreProps.getProperty("keyPassword") ?: System.getenv("EPIX_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Only sign when the keystore is actually configured; otherwise the
            // release APK is unsigned rather than failing the build.
            signingConfigs.getByName("release").let { cfg ->
                if (cfg.storeFile != null) {
                    signingConfig = cfg
                }
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    packaging {
        // JNA ships its own per-ABI natives; keep only what we target.
        jniLibs.keepDebugSymbols += "**/libepix_ffi.so"
    }
}

// Stage the Epix Wallet WebExtension (the forked Keplr's Firefox build) into
// assets so MainActivity can installBuiltIn it. The wallet build is pinned by
// shells/wallet-ext.rev (an epix-wallet commit); this stages that build's
// versioned wallet-<rev> release, matching the desktop build (build.rs). It
// prefers the repo staging dir shells/wallet-ext when that already holds the
// pinned rev (populated by build.rs or a local wallet build), else downloads
// the release. A pin bump re-stages; an unchanged pin reuses the staged copy.
// GeckoView additionally needs the geckoViewAddons permission for native
// messaging, which the desktop manifest does not carry, so it is patched in.
val walletRev =
    layout.projectDirectory.file("../../wallet-ext.rev").asFile
        .takeIf { it.exists() }?.readText()?.trim().orEmpty()

fun walletDistUrl(rev: String) =
    "https://github.com/EpixZone/epix-wallet/releases/download/wallet-$rev/epix-wallet-firefox.zip"

val stageWalletExt by tasks.registering {
    val dest = layout.projectDirectory.dir("src/main/assets/extensions/wallet").asFile
    val staged = layout.projectDirectory.dir("../../wallet-ext").asFile
    val stagedStamp = layout.projectDirectory.file("../../wallet-ext.rev-stamp").asFile
    // The rev this assets copy was staged from (assets/extensions is gitignored).
    val destStamp = File(dest.parentFile, "wallet.rev-stamp")
    outputs.dir(dest)
    inputs.property("walletRev", walletRev)
    doLast {
        if (walletRev.isEmpty())
            throw GradleException("wallet pin ../../wallet-ext.rev is missing or empty")
        val manifest = File(dest, "manifest.json")
        val current = destStamp.takeIf { it.exists() }?.readText()?.trim()
        if (manifest.exists() && current == walletRev) return@doLast

        dest.deleteRecursively()
        dest.mkdirs()
        // Reuse shells/wallet-ext only when it already holds the pinned rev.
        val stagedOk = File(staged, "manifest.json").exists() &&
            stagedStamp.takeIf { it.exists() }?.readText()?.trim() == walletRev
        if (stagedOk) {
            staged.copyRecursively(dest, overwrite = true)
            File(dest, "README.md").delete()
        } else {
            val zip = File.createTempFile("epix-wallet", ".zip")
            uri(walletDistUrl(walletRev)).toURL().openStream().use { input ->
                zip.outputStream().use { input.copyTo(it) }
            }
            val checksumFile = layout.projectDirectory.file("../../wallet-ext.sha256").asFile
            val expected = checksumFile.readLines().firstOrNull {
                it.trim().endsWith("epix-wallet-firefox.zip")
            }?.trim()?.substringBefore(' ')
            val actual = MessageDigest.getInstance("SHA-256")
                .digest(zip.readBytes()).joinToString("") { "%02x".format(it) }
            if (expected == null || actual != expected) {
                zip.delete()
                throw GradleException("Wallet archive does not match shells/wallet-ext.sha256")
            }
            copy {
                from(zipTree(zip))
                into(dest)
            }
            zip.delete()
        }
        // Native messaging from a built-in extension needs geckoViewAddons.
        @Suppress("UNCHECKED_CAST")
        val json = groovy.json.JsonSlurper().parse(manifest) as MutableMap<String, Any>
        val perms = (json["permissions"] as MutableList<String>)
        if (!perms.contains("geckoViewAddons")) {
            perms.add("geckoViewAddons")
            manifest.writeText(groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(json)))
        }
        destStamp.writeText(walletRev)
    }
}
tasks.named("preBuild") { dependsOn(stageWalletExt) }
val validateStoreWallet by tasks.registering(Exec::class) {
    dependsOn(stageWalletExt)
    commandLine("python3", "../../../scripts/check-mobile-wallet.py",
        "src/main/assets/extensions/wallet", "--release")
    workingDir(layout.projectDirectory)
}
tasks.matching { it.name == "bundleRelease" }.configureEach {
    dependsOn(validatePlaySigning, validateStoreWallet)
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    // The browser surface (Firefox engine as a library).
    implementation("org.mozilla.geckoview:geckoview:155.0.20260903215306")
    // The UniFFI-generated Kotlin bindings load the core through JNA.
    implementation("net.java.dev.jna:jna:5.19.1@aar")
}
