plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "zone.epix.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "zone.epix.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        // The Rust core is prebuilt per-ABI into src/main/jniLibs by cargo-ndk.
        ndk { abiFilters += listOf("arm64-v8a") }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
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
// assets so MainActivity can installBuiltIn it. Prefers the repo staging dir
// shells/wallet-ext (populated by epix-browser's build.rs or a local wallet
// build); otherwise downloads the prebuilt artifact from the epix-wallet
// repo's rolling wallet-dist release. GeckoView additionally needs the
// geckoViewAddons permission for native messaging, which the desktop manifest
// does not carry, so it is patched in here. Delete the assets dir to re-stage.
val walletDistUrl =
    "https://github.com/EpixZone/epix-wallet/releases/download/wallet-dist/epix-wallet-firefox.zip"

val stageWalletExt by tasks.registering {
    val dest = layout.projectDirectory.dir("src/main/assets/extensions/wallet").asFile
    val staged = layout.projectDirectory.dir("../../wallet-ext").asFile
    outputs.dir(dest)
    doLast {
        val manifest = File(dest, "manifest.json")
        if (manifest.exists()) return@doLast
        dest.mkdirs()
        if (File(staged, "manifest.json").exists()) {
            staged.copyRecursively(dest, overwrite = true)
            File(dest, "README.md").delete()
        } else {
            val zip = File.createTempFile("epix-wallet", ".zip")
            uri(walletDistUrl).toURL().openStream().use { input ->
                zip.outputStream().use { input.copyTo(it) }
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
    }
}
tasks.named("preBuild") { dependsOn(stageWalletExt) }

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    // The browser surface (Firefox engine as a library).
    implementation("org.mozilla.geckoview:geckoview:152.0.20260629141727")
    // The UniFFI-generated Kotlin bindings load the core through JNA.
    implementation("net.java.dev.jna:jna:5.15.0@aar")
}
