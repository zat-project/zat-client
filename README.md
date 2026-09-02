# ZAT Android client — corresponding source (GPL-3.0-or-later)

This repository is the **corresponding source** (GNU GPL v3 §6) for the ZAT Android
client binaries. Anyone who receives a ZAT client `.apk`/`.aab` is entitled to this
source. It contains **only** the code that ships inside the client binary.

> **These binaries:** <https://github.com/zat-project/zat-client/releases>
>
> This snapshot corresponds to release **v0.1.0**, built from commit `29b833de0b5f`.
> Every published `.apk` carries that commit in `BuildConfig.GIT_COMMIT`, and the release page
> lists a SHA-256 for each file and the signing certificate fingerprint, so you can tie an exact
> binary to this exact source.

## License map

| Path | License |
|------|---------|
| `client-android/zat-app`, `client-android/zat-connection-manager` | **GPL-3.0-or-later** (see `client-android/COPYING`) |
| `client-android/mesh-oprf-rs`, `zat-oprf-client`, `zat-threshold-oprf` | **MIT** (see `LICENSE-MIT`) |
| `client-android/sing-box-libbox` | build recipe for sing-box/`libbox` (GPL-3.0-or-later, © SagerNet) |

The client links **sing-box / `libbox`** (GPL-3.0-or-later) in-process (JNI), which makes
the distributed client a combined work under the GPL — so `zat-app` and
`zat-connection-manager` are GPL-3.0-or-later. The shared crypto crates are MIT and are
GPL-compatible. Full rationale: `docs/LICENSING_v0.1.md`. Third-party notices:
`client-android/NOTICE`.

### What is deliberately NOT here
The ZAT **broker** and **volunteer** apps are separate network services / desktop programs
that are **not distributed** inside the client APK, so the GPL does not require their source.
Only what ships in the client binary is included.

## Building

The two native libraries are built from source, then assembled into the app:

1. **`libbox.so`** (sing-box) — run `client-android/sing-box-libbox/build.sh`. It builds
   `libbox.so` for all four ABIs hermetically in Docker from a pinned upstream sing-box tag
   (see the Dockerfile). Because it is reproducible, you can verify the shipped `libbox.so`.
2. **`libmeshoprf.so`** (the MIT crypto) — build `client-android/mesh-oprf-rs` for Android
   with `cargo-ndk` (it path-depends on `zat-oprf-client` → `zat-threshold-oprf`, both here).
3. Place the resulting `.so` files under the app's `jniLibs/<abi>/`
   (see `client-android/zat-app/README.md`).
4. `cd client-android/zat-app && ./gradlew assembleRelease`  (or `bundleRelease` for an AAB).

## sing-box attribution

sing-box is © the SagerNet contributors, GPL-3.0-or-later,
<https://github.com/SagerNet/sing-box>, vendored **unmodified** from a pinned tag. ZAT is not
affiliated with, endorsed by, or a product of the sing-box project, and does not use its name
or branding beyond this required attribution.
