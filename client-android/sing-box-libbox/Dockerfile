# Reproducible build of sing-box's Android library (libbox.aar).
#
# Why: ZAT's Stage-2 anti-DPI transport (Reality / Hysteria2) is provided by the
# sing-box engine. Rather than hand-roll a censor-targeted transport, we vendor
# the maintained engine as a gomobile .aar (decision R-1, see
# docs/STAGE2_DEDICATED_AND_VOLUNTEER_v0.1.md). This image builds that .aar from a
# *pinned* sing-box source tag inside Linux, so the Windows/NDK host toolchain is
# irrelevant and the artifact is reproducible + auditable.
#
# Build (BuildKit, extracts the .aar to ./out/):
#   docker build -t zat-libbox --build-arg SINGBOX_TAG=v1.13.13 .
#   # then extract — or use build.sh which does both:
#   docker build --output type=local,dest=./out --build-arg SINGBOX_TAG=v1.13.13 .
#
# Pin the exact tag so the artifact is reproducible. Bump deliberately: SINGBOX_TAG and
# SINGBOX_COMMIT move together (a tag can be moved; the commit check fails the build if it was),
# and the four library hashes this build records in out/libbox.sha256 change with them.
# Reproducibility is measured, not assumed: this file rebuilt all four libbox.so of the published
# v0.1.0 byte for byte (docs/evidence/R123/).

# ---- builder ---------------------------------------------------------------
# The base image by digest (golang:1.24-bookworm as resolved for R123), so the Go toolchain cannot
# drift under a floating tag. What apt-get fetches below still floats (TECH_DEBT G28).
FROM golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        git wget unzip openjdk-17-jdk-headless ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Android SDK command-line tools + a pinned NDK (gomobile bind needs the NDK).
ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_SDK_ROOT=${ANDROID_HOME}
ENV NDK_VERSION=27.2.12479018
RUN mkdir -p ${ANDROID_HOME}/cmdline-tools \
    && wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O /tmp/cmdline.zip \
    && unzip -q /tmp/cmdline.zip -d ${ANDROID_HOME}/cmdline-tools \
    && mv ${ANDROID_HOME}/cmdline-tools/cmdline-tools ${ANDROID_HOME}/cmdline-tools/latest \
    && rm /tmp/cmdline.zip
ENV PATH=${PATH}:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools
RUN yes | sdkmanager --licenses >/dev/null \
    && sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0" "ndk;${NDK_VERSION}" >/dev/null
ENV ANDROID_NDK_HOME=${ANDROID_HOME}/ndk/${NDK_VERSION}
ENV NDK_HOME=${ANDROID_NDK_HOME}

# Pinned sing-box source: the tag, and the commit it must resolve to.
ARG SINGBOX_TAG=v1.13.13
ARG SINGBOX_COMMIT=78b2e12fbdd85e6ec956647d6f79cf0bba85c6ba
RUN git clone --depth 1 --branch ${SINGBOX_TAG} https://github.com/SagerNet/sing-box.git /src \
    && test "$(git -C /src rev-parse HEAD)" = "${SINGBOX_COMMIT}" \
    || { echo "sing-box ${SINGBOX_TAG} is not commit ${SINGBOX_COMMIT}" >&2; exit 1; }
WORKDIR /src

# Install sing-box's gomobile fork, then build the Android library.
# `make lib_android` runs `go run ./cmd/internal/build_libbox -target android`.
RUN make lib_install

# Drop the Naive outbound from the shared build tags: `with_naive_outbound` pulls
# a *prebuilt* cronet (Chromium) static lib (libcronet.a) that fails to link with
# NDK r27 ("unknown relocation 315") AND bloats the .aar by tens of MB. ZAT's
# transports are Reality / Hysteria2 / Shadowsocks — none need cronet. (sing-box's
# own "legacy" variant already excludes it; we drop it from the main build too.)
RUN sed -i 's/"with_naive_outbound", //' cmd/internal/build_libbox/main.go \
    && grep -q 'with_naive_outbound' cmd/internal/build_libbox/main.go && echo "note: naive still referenced (filterTags arg, harmless)" || true

# ---- the local patch to sing-tun (patches/README.md says what, why and when) ----
# The pinned image has no `patch`. The hash is of the file with any CR removed, so a CRLF checkout
# (Windows, core.autocrlf) still verifies and applies the same bytes. Every step fails the build.
RUN apt-get update && apt-get install -y --no-install-recommends patch && rm -rf /var/lib/apt/lists/*
ARG PATCH_SHA256=232d133212fe46e29524aa42ecc4536ffb0a93a96010c5f9ba6dd7ba840e1a96
COPY patches/0001-sing-tun-pass-nil-attach.patch /patches/
RUN tr -d '\r' < /patches/0001-sing-tun-pass-nil-attach.patch > /tmp/0001.patch \
    && echo "${PATCH_SHA256}  /tmp/0001.patch" | sha256sum -c - \
    && go mod download github.com/sagernet/sing-tun \
    && cp -r "$(go list -m -f '{{.Dir}}' github.com/sagernet/sing-tun)" /sing-tun \
    && { patch -p1 --fuzz=0 -d /sing-tun < /tmp/0001.patch > /tmp/patch.out 2>&1; st=$?; cat /tmp/patch.out; test $st -eq 0; } \
    && ! grep -qi 'offset\|fuzz' /tmp/patch.out \
    && grep -q 'if dispatcher == nil' /sing-tun/stack_gvisor_filter.go \
    && go mod edit -replace github.com/sagernet/sing-tun=/sing-tun \
    && go list -m -f '{{.Path}} {{.Version}} => {{.Replace}}' github.com/sagernet/sing-tun | tee /tmp/replace.out \
    && grep -q '=> /sing-tun' /tmp/replace.out

RUN export PATH="${PATH}:$(go env GOPATH)/bin" \
    && gomobile init || true \
    && make lib_android

# Collect the API-21 variant BY NAME. build_libbox produces two: libbox.aar (API 23) and
# libbox-legacy.aar (API 21); the app's minSdk is 21, and the old `find … | head -1` picked whichever
# came first. Fail unless it holds exactly the four ABIs, each built with the patched sing-tun (the
# check reads the library, not the build's inputs). Also record what was built, so a build can be
# compared with another (out/*.sha256, go version -m per library, the Go version, the sing-box commit).
RUN mkdir -p /out \
    && cp /src/libbox-legacy.aar /out/libbox.aar \
    && unzip -p /out/libbox.aar AndroidManifest.xml | grep -q 'minSdkVersion="21"' \
    && mkdir -p /tmp/aar && cd /tmp/aar && unzip -q /out/libbox.aar \
    && test "$(ls jni | tr '\n' ' ')" = "arm64-v8a armeabi-v7a x86 x86_64 " \
    && for a in arm64-v8a armeabi-v7a x86 x86_64; do \
         go version -m "jni/$a/libbox.so" 2>&1 | grep -q "=>	/sing-tun" \
         || { echo "jni/$a/libbox.so was not built with the patched sing-tun" >&2; exit 1; }; \
       done \
    && sha256sum jni/*/libbox.so > /out/libbox.sha256 \
    && sha256sum classes.jar > /out/classes.jar.sha256 \
    && for a in jni/*/; do go version -m "$a/libbox.so" > "/out/buildinfo-$(basename "$a").txt" 2>&1 || true; done \
    && go version > /out/go-version.txt \
    && git -C /src rev-parse HEAD > /out/sing-box-commit.txt \
    && cp /tmp/patch.out /tmp/replace.out /out/ \
    && ls -la /out/

# ---- export (BuildKit --output) -------------------------------------------
FROM scratch AS export
COPY --from=builder /out/ /
