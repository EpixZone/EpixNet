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

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    // The browser surface (Firefox engine as a library).
    implementation("org.mozilla.geckoview:geckoview:152.0.20260629141727")
    // The UniFFI-generated Kotlin bindings load the core through JNA.
    implementation("net.java.dev.jna:jna:5.15.0@aar")
}
