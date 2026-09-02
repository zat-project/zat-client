# zat-app — the ZAT one-button user app

The product: a Psiphon-style single-button Android VPN app, a thin UI over the standalone
`zat-connection-manager` library. See `docs/ONE_BUTTON_APP_v0.1.md` for the design.

## Status

P1 skeleton: one screen, one button (`MainActivity`) wired to the library's high-level API
(`VpnManager.prepareVpn → fetchRouteAndStartVpn / stopVpn`), with the button label + status driven
by `ZatConnectionState`. Assembles a full standalone VPN APK (the library's sing-box + mesh native
libs merge in).

## Building — STANDALONE (default)

The app builds on its own via its tracked `settings.gradle.kts` (which includes the
`../zat-connection-manager` library as a subproject) + its own Gradle wrapper — independent of the
gitignored Telegram test host:

```
cd client-android/zat-app && ./gradlew assembleDebug
# APK → client-android/zat-app/build/outputs/apk/debug/zat-app-debug.apk
```

(JBR JDK 21 + `ANDROID_HOME`. Toolchain mirrors the library: AGP 8.6.1 / Kotlin 1.9.20 / Gradle 8.10.2.)

It ALSO still builds inside the Telegram gradle project when that include is present (that include
lives in the gitignored `Telegram/settings.gradle`, so it is untracked).

## Native libs — building from source (hermetic, reproducible)

The build needs the library's two native libs — `libbox.so` (the vendored sing-box engine) and
`libmeshoprf.so` (the Rust mesh OPRF) — in the library dir. They are **gitignored (~100 MB)** and
built reproducibly from PINNED source, so the app is verifiable from source (no opaque blobs). From a
clean clone:

```
# 1. libbox — sing-box's Android lib, built in a pinned Linux image + split into the parts gradle
#    wants (libs/libbox.jar + src/main/jniLibs/<abi>/libbox.so). Needs Docker + unzip only.
cd client-android/sing-box-libbox && SINGBOX_TAG=v1.13.13 ./build.sh

# 2. libmeshoprf — the Rust VOPRF, one .so per ABI via cargo-ndk (NDK r27).
#    (one-time: rustup targets + `cargo install cargo-ndk`; export ANDROID_NDK_HOME)
cd ../mesh-oprf-rs && ./build.sh          # → mesh-oprf-rs/jniLibs/<abi>/libmeshoprf.so

# 3. the app (debug or release).
cd ../zat-app && ./gradlew assembleRelease
```

`libbox` is pinned to sing-box `v1.13.13` (bump deliberately in the Dockerfile + `build.sh`). The
release `libmeshoprf.so` carries NO server-side OPRF (the `self_test` diagnostic is Cargo-feature-gated
OFF; `MESHOPRF_SELF_TEST=1` compiles it in for a dev build only).

**Remaining release-readiness** (tracked as Tier F in `docs/TECH_DEBT.md`): F1 R8/release build (done),
F3 libbox ABI shipping strategy (the `.aar` carries all 4 ABIs — pick universal-APK vs per-ABI
splits/AAB), F4 release signing (keystore supplied out of band), and D4 name/icon/brand (rebrand).
