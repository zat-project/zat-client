// pluginManagement lets this module build STANDALONE (e.g. `./gradlew testDebugUnitTest`
// in isolation, for fast unit-test iteration). It is IGNORED when the module is built
// inside the Telegram root, which supplies the Android Gradle Plugin on its own
// buildscript classpath — so this can never affect the app build. Versions mirror that
// root (AGP 8.6.1 / Kotlin 1.9.20) so the two builds stay identical.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    plugins {
        id("com.android.library") version "8.6.1"
        id("org.jetbrains.kotlin.android") version "1.9.20"
    }
}

rootProject.name = "zat-connection-manager"
