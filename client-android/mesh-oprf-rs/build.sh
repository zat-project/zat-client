#!/usr/bin/env bash
# Build libmeshoprf.so for all Android ABIs (B1a.1 — the client mesh VOPRF).
#
# This is the Rust counterpart to sing-box-libbox: a native library the Android app
# loads. Unlike gomobile, Rust has no global runtime, so libmeshoprf.so coexists with
# libbox's Go runtime in the same process (two gomobile .aars cannot — that's why the
# OPRF is Rust, not CIRCL/gomobile).
#
# One-time setup:
#   rustup target add aarch64-linux-android armv7-linux-androideabi \
#                     i686-linux-android x86_64-linux-android
#   cargo install cargo-ndk
#   export ANDROID_NDK_HOME=.../Android/Sdk/ndk/27.2.12479018   # NDK r27
#
# Output: ./jniLibs/<abi>/libmeshoprf.so  (gitignored; copied into the app at build).
#
# E2: the SHIPPED library carries NO server-side OPRF — the `self_test` diagnostic (which pulls in
# `VoprfServer`) is feature-gated OFF by default. For an on-device diagnostic build, set
# `MESHOPRF_SELF_TEST=1` to compile it in (`--features self-test`).
set -euo pipefail
: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to your Android NDK (r27), e.g. .../Android/Sdk/ndk/27.2.12479018}"

FEATURES=()
if [ "${MESHOPRF_SELF_TEST:-0}" = "1" ]; then
  FEATURES=(--features self-test)
  echo "NOTE: building WITH the self-test diagnostic (server-side VoprfServer) — dev only, not for release."
fi

cargo ndk \
  -t arm64-v8a -t armeabi-v7a -t x86 -t x86_64 \
  -o ./jniLibs \
  build --release "${FEATURES[@]}"

echo "OK — built jniLibs/<abi>/libmeshoprf.so"
