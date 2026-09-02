#!/usr/bin/env bash
#
# Build libbox reproducibly AND place the artifacts the zat-connection-manager build consumes.
#
# The Dockerfile builds sing-box's Android library (libbox.aar) from a PINNED sing-box tag inside
# Linux (so the host toolchain is irrelevant + the artifact is reproducible/auditable). But the app
# does not consume a raw .aar — the gradle module wants the split parts:
#   - libs/libbox.jar                        (the JNI bridge classes; `implementation(files(...))`)
#   - src/main/jniLibs/<abi>/libbox.so       (the native Go core; per ABI)
# This script does BOTH: the Docker build, then the split into the right paths. (The Dockerfile's
# header references this script — keep them in sync.)
#
# Usage:   ./build.sh                 # default SINGBOX_TAG below
#          SINGBOX_TAG=v1.13.13 ./build.sh
# Needs:   Docker (BuildKit) + unzip. No host Go/NDK — those live inside the image.
set -euo pipefail

SINGBOX_TAG="${SINGBOX_TAG:-v1.13.13}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CM="$(cd "$HERE/../zat-connection-manager" && pwd)" # the consuming library module

echo ">> building libbox.aar (sing-box ${SINGBOX_TAG}) via Docker → $HERE/out/"
docker build --output "type=local,dest=$HERE/out" --build-arg "SINGBOX_TAG=${SINGBOX_TAG}" "$HERE"

AAR="$HERE/out/libbox.aar"
[ -f "$AAR" ] || { echo "ERROR: the Docker build produced no $AAR" >&2; exit 1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
unzip -q -o "$AAR" -d "$WORK"

echo ">> split: classes.jar → $CM/libs/libbox.jar"
mkdir -p "$CM/libs"
[ -f "$WORK/classes.jar" ] || { echo "ERROR: no classes.jar in the .aar" >&2; exit 1; }
cp "$WORK/classes.jar" "$CM/libs/libbox.jar"

echo ">> split: jni/<abi>/*.so → $CM/src/main/jniLibs/<abi>/"
shopt -s nullglob
found_so=0
for abidir in "$WORK"/jni/*/; do
  abi="$(basename "$abidir")"
  mkdir -p "$CM/src/main/jniLibs/$abi"
  for so in "$abidir"*.so; do cp "$so" "$CM/src/main/jniLibs/$abi/"; found_so=1; done
done
[ "$found_so" = 1 ] || { echo "ERROR: no jni/<abi>/*.so in the .aar" >&2; exit 1; }

echo ">> done. libbox artifacts in place:"
ls -la "$CM/libs/libbox.jar"; ls -la "$CM"/src/main/jniLibs/*/libbox.so 2>/dev/null
echo ">> next: build libmeshoprf (../mesh-oprf-rs/build.sh), then cd ../zat-app && ./gradlew assembleRelease"
