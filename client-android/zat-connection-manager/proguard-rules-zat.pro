# ============================================================================
# ZAT Connection Manager — R8/ProGuard Rules (Phase 13)
# ============================================================================
# These rules are applied automatically via consumerProguardFiles when the
# zat-connection-manager module is consumed by the app module — so the STANDALONE
# `zat-app` release build (R8 minify on) inherits them with no extra wiring.
# Obfuscation + optimization happen by default under R8 in the standalone app (there is
# no Telegram-host `-dontobfuscate`/`-dontoptimize` in that build path).
# ============================================================================

# --- kotlinx-serialization: Keep @Serializable data classes ---
# R8 must not remove or rename fields used by the serialization compiler plugin.
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt

-keepclassmembers @kotlinx.serialization.Serializable class zat.manager.** {
    # Lookup for companion field for the serializer.
    static ** Companion;
    <fields>;
}

-keepclasseswithmembers class zat.manager.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# Keep serializer() static methods on companions.
-keepclassmembers class zat.manager.**$Companion {
    kotlinx.serialization.KSerializer serializer(...);
}

# --- net.i2p.crypto:eddsa — Ed25519 crypto library ---
# Pure Java library, some classes are loaded by name in the spec table.
-keep class net.i2p.crypto.eddsa.** { *; }
-dontwarn net.i2p.crypto.eddsa.**

# --- sing-box / libbox (gomobile JNI bridge) ---
# The native libbox.so resolves these classes AND their methods by name over JNI
# (e.g. go.Seq.getRef, and the PlatformInterface callbacks invoked from Go). R8
# must not rename or strip them, or the Go<->Java bridge aborts at runtime with
# "failed to find method Seq.getRef" (SIGABRT). Also keep our PlatformInterface
# implementation, whose overrides libbox calls back into.
-keep class go.** { *; }
-keep class io.nekohasekai.libbox.** { *; }
-keep class zat.manager.vpn.engine.reality.** { *; }
-dontwarn go.**
-dontwarn io.nekohasekai.libbox.**

# --- OkHttp CertificatePinner ---
-keepnames class okhttp3.internal.publicsuffix.PublicSuffixDatabase

# (Removed: the ZatVpnJni + OpenVpnEngine.protectSocket keep-rules — both classes were deleted when
# the OpenVPN engine was dropped in favour of SstpEngine (pure-Kotlin, no JNI). The live native
# bridges are libbox `go.**`/`io.nekohasekai.libbox.**` and `cloud.zat.meshoprf.MeshOprf`, kept above.)

# --- StealthConfig + BootstrapResolver ---
# These classes are NOT accessed via reflection and CAN be obfuscated.
# No -keep rule is needed for them — R8 should rename and inline freely.
# The only requirement is that their code is not removed as unreachable.
# Since BootstrapResolver.resolveFirstRoute() is called from VpnConnectionManager,
# R8 will retain the reachable call chain automatically.

# --- Log stripping (debug/verbose logs removed from release builds) ---
# R8 optimizes by default in the standalone release build, so -assumenosideeffects takes effect and
# these low-value logs are stripped. (`Log.i/w/e` are kept — they carry operational signal.)
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
}

# --- General safety ---
-dontwarn javax.annotation.**
-dontwarn org.checkerframework.**

# --- mesh-oprf-rs (Rust VOPRF JNI bridge, B1a.1) ---
# libmeshoprf.so resolves cloud.zat.meshoprf.MeshOprf's native methods by name over
# JNI; R8 must not rename or strip them, or the Rust<->Kotlin bridge aborts at runtime.
-keep class cloud.zat.meshoprf.MeshOprf { *; }
-keepclasseswithmembernames class cloud.zat.meshoprf.MeshOprf {
    native <methods>;
}
