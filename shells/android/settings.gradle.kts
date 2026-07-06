pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        // GeckoView is published on Mozilla's own maven.
        maven { url = uri("https://maven.mozilla.org/maven2") }
    }
}

rootProject.name = "epix-android"
include(":app")
