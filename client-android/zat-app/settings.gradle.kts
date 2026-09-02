// Standalone build for the ZAT one-button app — so it is buildable from a clean checkout WITHOUT
// the (gitignored) Telegram test host. The app IS the root project; the zat-connection-manager
// library is included as a sibling subproject. `pluginManagement` mirrors the Telegram/library
// toolchain (AGP 8.6.1 / Kotlin 1.9.20) so the two builds stay identical.
//
// Precondition (same as the library today): the native libs it merges — `libbox.so` /
// `libmeshoprf.so` — are built separately and are gitignored; see zat-app/README.md + the library's
// build. A fully-hermetic clean-clone build (auto-building those .so from source) is P3 packaging.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    plugins {
        id("com.android.application") version "8.6.1"
        id("com.android.library") version "8.6.1"
        id("org.jetbrains.kotlin.android") version "1.9.20"
    }
}

rootProject.name = "zat-app"

include(":zat-connection-manager")
project(":zat-connection-manager").projectDir = file("../zat-connection-manager")
