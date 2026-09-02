// The ZAT one-button user app — a thin UI over the standalone `zat-connection-manager` library.
// Builds STANDALONE via its own `settings.gradle.kts` + gradle wrapper (independent of the gitignored
// Telegram test host): `zat-app/gradlew assembleDebug`. It also still builds inside the Telegram
// gradle project when that include is present. The only remaining clean-clone gap is the native libs
// (`libbox.so`/`libmeshoprf.so`, gitignored + built separately) — see README + docs/ONE_BUTTON_APP_v0.1.md.
plugins {
    id("com.android.application")
    kotlin("android")
}

// Release-signing credentials, resolved from EITHER a gradle property (put them in
// ~/.gradle/gradle.properties — outside the repo, NEVER committed) OR an env var. Nothing secret is
// committed; when none are present the release build is simply left unsigned (CI/dev + R8 still work).
//   gradle.properties: zatKeystore / zatKeystorePassword / zatKeyAlias / zatKeyPassword
//   env:               ZAT_KEYSTORE / ZAT_KEYSTORE_PASSWORD / ZAT_KEY_ALIAS / ZAT_KEY_PASSWORD
/**
 * P1.1 · the commit this artifact was built from, for BuildConfig.GIT_COMMIT.
 *
 * Order: an explicit `-PzatGitCommit=` / `ZAT_GIT_COMMIT` (how a source-tarball or CI build states its
 * provenance) → `git rev-parse` when a repository is present → "unknown". It must never fail the
 * build: the published GPL corresponding-source bundle ships without `.git`, and a recipient building
 * from it is exactly the person we least want to hand a broken build to.
 */
val zatGitCommit: String = (findProperty("zatGitCommit") as String?)
    ?: System.getenv("ZAT_GIT_COMMIT")
    ?: runCatching {
        val p = ProcessBuilder("git", "rev-parse", "--short=12", "HEAD")
            .directory(rootDir)
            .redirectErrorStream(true)
            .start()
        val out = p.inputStream.bufferedReader().readText().trim()
        if (p.waitFor() == 0 && out.isNotEmpty()) out else null
    }.getOrNull()
    ?: "unknown"

val zatKeystorePath = (findProperty("zatKeystore") as String?) ?: System.getenv("ZAT_KEYSTORE")
val zatKeystorePass = (findProperty("zatKeystorePassword") as String?) ?: System.getenv("ZAT_KEYSTORE_PASSWORD")
val zatKeyAliasName = (findProperty("zatKeyAlias") as String?) ?: System.getenv("ZAT_KEY_ALIAS")
val zatKeyPass = (findProperty("zatKeyPassword") as String?) ?: System.getenv("ZAT_KEY_PASSWORD")

android {
    namespace = "cloud.zat.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "cloud.zat.app" // ZAT brand (D4). Stable public id — change only deliberately.
        minSdk = 21
        // P1 targets 33 to keep the foreground-service model simple (the library's VpnService has no
        // foregroundServiceType); API 34+ hardening (service type + POST_NOTIFICATIONS flow) is P2/P3.
        targetSdk = 33
        versionCode = 1
        versionName = "0.1.0"

        // P1.1 · BUILD PROVENANCE. Without this there is no way to tell which source an APK came
        // from, and that is not theoretical: the signed release artifacts sat for nine days looking
        // current while missing every client fix in that window — including the one where four of the
        // six bootstrap channels were dead. A user would have received a build running on two
        // channels. A stamp makes "is this artifact current?" a question with an answer.
        //
        // `.git` is deliberately optional: the published GPL corresponding-source bundle is a tarball
        // with no repository, and a recipient building from it must not hit a build failure. It falls
        // back to "unknown", which is honest — that build genuinely has no commit to name.
        buildConfigField("String", "GIT_COMMIT", "\"$zatGitCommit\"")
    }

    signingConfigs {
        create("release") {
            // Signs the release build ONLY when the credentials above are present (gradle property or
            // env); otherwise this stays empty and the build is left unsigned.
            zatKeystorePath?.let { ksPath ->
                storeFile = file(ksPath)
                storePassword = zatKeystorePass
                keyAlias = zatKeyAliasName
                keyPassword = zatKeyPass
            }
        }
    }

    buildFeatures {
        buildConfig = true // for GIT_COMMIT above
    }

    buildTypes {
        getByName("release") {
            // R8: shrink + optimize + obfuscate. Keep-rules for the JNI bridges (libbox, meshoprf)
            // and the kotlinx-serialization models ride in from zat-connection-manager's
            // consumerProguardFiles (proguard-rules-zat.pro); proguard-rules.pro holds app-level keeps.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            // Sign ONLY when a keystore is supplied (gradle property or env, above); else the release
            // APK/AAB is left unsigned (assembleRelease still validates R8). Keystore supplied out of band.
            if (zatKeystorePath != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    // F3 — ship an Android App Bundle (`bundleRelease` → .aab). The .aab carries ALL 4 ABIs of both
    // native libs (libbox + libmeshoprf); a bundletool distributor (Play, or `bundletool build-apks`)
    // then generates per-device APKs that each carry ONLY that device's ABI + density + language — so a
    // user downloads one ABI's ~15 MB of native code, not four. These splits are on by default; set
    // explicitly to document the delivery model.
    bundle {
        abi { enableSplit = true }
        density { enableSplit = true }
        language { enableSplit = true }
    }

    // F3 (sideload) — split `assembleRelease` into per-ABI APKs so a direct/sideload download carries
    // only one ABI's native libs (~20 MB) instead of all four (~71 MB). Play may be blocked in target
    // regions, so sideload is likely the PRIMARY channel; a mirror serves the device's ABI, and the
    // universal APK (all 4 ABIs) is the "if unsure" fallback. NOTE: these share one versionCode — fine
    // for sideload (separate files); if the splits were ever Play-distributed they would need per-ABI
    // versionCode offsets. (Play itself is served by the .aab, which needs no splits here.)
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
            isUniversalApk = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    kotlinOptions {
        jvmTarget = "21"
    }
}

repositories {
    mavenCentral()
    google()
}

dependencies {
    implementation(project(":zat-connection-manager"))
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.activity:activity-ktx:1.8.2")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("com.google.android.material:material:1.11.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
}
