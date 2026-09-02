// The Kotlin serialization Gradle plugin is a separate artifact from kotlin-gradle-plugin
// and is not on Telegram's root buildscript classpath. We declare it here in the subproject's
// own buildscript block so it can be applied via apply() below without modifying the root
// build.gradle.
buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-serialization:1.9.20")
    }
}

plugins {
    id("com.android.library")
    kotlin("android")
}

// Apply serialization plugin from the subproject buildscript classpath above.
apply(plugin = "org.jetbrains.kotlin.plugin.serialization")

group = "zat.manager"
version = "0.1.0"

android {
    testOptions {
        unitTests {
            // android.util.Log is a stub in unit tests and THROWS unless this is set. Without it a
            // test that merely logs a warning fails with "not mocked", which masks the real assertion
            // — exactly what happened when these decoding tests were added.
            isReturnDefaultValues = true
        }
    }

    namespace = "zat.manager"
    compileSdk = 35

    defaultConfig {
        minSdk = 21
        consumerProguardFiles("proguard-rules-zat.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    kotlinOptions {
        jvmTarget = "21"
    }

    // The Rust mesh VOPRF native lib (libmeshoprf.so, B1a.1) — built by
    // ../mesh-oprf-rs/build.sh into its own jniLibs and merged alongside libbox.so.
    // Rust has no global runtime, so it coexists with libbox's Go runtime in-process
    // (two gomobile .aars cannot). Gitignored + reproducible (see mesh-oprf-rs/README.md).
    sourceSets["main"].jniLibs.srcDir("../mesh-oprf-rs/jniLibs")
}

repositories {
    mavenCentral()
    google()
}

dependencies {
    // sing-box engine (Reality / Hysteria2 / Shadowsocks-2022 / …) — JNI binding
    // classes. The native core ships separately as src/main/jniLibs/<abi>/libbox.so
    // (auto-merged into the consuming APK). Both are built reproducibly via
    // ../sing-box-libbox/Dockerfile and are gitignored (~100 MB).
    implementation(files("libs/libbox.jar"))

    // HTTP client: OkHttp 4
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // Brotli decoder (Google's reference implementation, pure Java, ~100 KB). Needed because the
    // bootstrap resolver sets `Accept-Encoding` BY HAND to mimic a browser, and OkHttp only
    // decompresses transparently for the header IT adds. NB: `okhttp-brotli` is the obvious pick and
    // is the WRONG one here — its BrotliInterceptor no-ops when the caller already set the header
    // (verified in okhttp 4.12.0 source), and the `br,gzip` it would send is not a browser
    // fingerprint. So we decode ourselves in `BootstrapResolver.decodeBody`.
    implementation("org.brotli:dec:0.1.2")

    // Ed25519 signature verification (pure Java, works on all API levels)
    implementation("net.i2p.crypto:eddsa:0.3.0")

    // JSON serialisation: kotlinx-serialization-json (zero-reflection, strict)
    // Pinned to 1.6.3: last release compatible with Kotlin 1.9.20 (Telegram classpath).
    // 1.7.0+ requires Kotlin 2.0.0-RC1+.
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")

    // Coroutines for the observable connection state (StateFlow the UI collects).
    // 1.7.3 is the last line compatible with Kotlin 1.9.20 (the Telegram classpath).
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")

    // JUnit 5 for unit testing
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.11.3")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.11.3")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.11.3")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
