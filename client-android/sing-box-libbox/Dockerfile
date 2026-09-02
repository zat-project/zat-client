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
# Pin the exact tag so the artifact is reproducible. Bump deliberately.

# ---- builder ---------------------------------------------------------------
FROM golang:1.24-bookworm AS builder

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

# Pinned sing-box source.
ARG SINGBOX_TAG=v1.13.13
RUN git clone --depth 1 --branch ${SINGBOX_TAG} https://github.com/SagerNet/sing-box.git /src
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

RUN export PATH="${PATH}:$(go env GOPATH)/bin" \
    && gomobile init || true \
    && make lib_android

# Collect the produced .aar (path can vary between sing-box versions).
RUN mkdir -p /out \
    && cp "$(find / -name 'libbox*.aar' -o -name 'box*.aar' 2>/dev/null | grep -iE 'libbox|box' | head -1)" /out/libbox.aar \
    && ls -la /out/

# ---- export (BuildKit --output) -------------------------------------------
FROM scratch AS export
COPY --from=builder /out/libbox.aar /libbox.aar
