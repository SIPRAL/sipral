# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# Everything the Android half of this binding builds with, and nothing it
# ships: the pinned Rust toolchain with the three Android targets and
# cargo-ndk (Apache-2.0 OR MIT) for libsipral_ffi.so, the NDK for that and
# for linking the JNI shim, the Android SDK's command-line tools, one
# platform and its build tools for the Gradle build, a JDK, the Kotlin
# compiler scripts/package/aar.sh compiles the binding's classes with, the
# kotlinx-coroutines jar those classes compile against, and a Gradle
# distribution to generate the wrapper from. scripts/package/android.sh
# builds this image and runs the whole build inside it.
#
# THE ANDROID SDK LICENCE. sdkmanager will not install a package until its
# licence has been accepted, and accepting it is a decision for whoever
# builds this image, not for this file: the build refuses to run unless
# ANDROID_SDK_LICENSE_ACCEPTED=yes is passed as a build argument, which
# scripts/package/android.sh only does when it is given
# --accept-android-sdk-licenses. The terms are at
# developer.android.com/studio/terms and are printed by `sdkmanager
# --licenses` itself.
#
# Every download is pinned and checked: the command-line tools and the
# Gradle and Kotlin distributions against a SHA-256 below, and every SDK
# package sdkmanager installs against the checksum Google's own repository
# manifest lists for it. Versions checked 2026-09-23 against
# dl.google.com/android/repository/repository2-3.xml (NDK r30 is the current
# LTS), services.gradle.org and the Kotlin releases.

FROM rust:1.99-trixie

ARG ANDROID_SDK_LICENSE_ACCEPTED=no
RUN if [ "$ANDROID_SDK_LICENSE_ACCEPTED" != "yes" ]; then \
        echo "The Android SDK packages this image installs are under the Android SDK licence."; \
        echo "Read it (developer.android.com/studio/terms) and build with"; \
        echo "--build-arg ANDROID_SDK_LICENSE_ACCEPTED=yes, or run"; \
        echo "scripts/package/android.sh --accept-android-sdk-licenses."; \
        exit 1; \
    fi

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openjdk-21-jdk-headless unzip zip cmake binutils file \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

# rust-toolchain.toml's own components, so the first cargo call inside does
# not fetch them into a container that is thrown away afterwards.
RUN rustup component add clippy rustfmt \
    && rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

ARG CARGO_NDK_VERSION=4.1.2
RUN cargo install cargo-ndk --version "$CARGO_NDK_VERSION" --locked \
    && rm -rf /usr/local/cargo/registry

ENV ANDROID_HOME=/opt/android-sdk
# cmdline-tools 22.0, one release behind the newest (23.0, build 16111833),
# on purpose: 23.0's sdkmanager is no longer the SDK manager but a launcher
# that downloads whatever binary dl.google.com/android/cli/latest/ serves at
# that moment -- unpinned, unchecked -- runs it, and uploads usage metrics
# from inside the build. 22.0's sdkmanager is still the SDK manager itself:
# it installs from Google's repository manifest and checks each package
# against it, and fetches nothing else.
ARG CMDLINE_TOOLS_BUILD=15859902
ARG CMDLINE_TOOLS_SHA256=4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583
RUN mkdir -p "$ANDROID_HOME/cmdline-tools" \
    && cd /tmp \
    && curl -fsSL -o clt.zip "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_BUILD}_latest.zip" \
    && echo "$CMDLINE_TOOLS_SHA256  clt.zip" | sha256sum -c - \
    && unzip -q clt.zip \
    && mv cmdline-tools "$ANDROID_HOME/cmdline-tools/latest" \
    && rm clt.zip

ENV PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"

ARG ANDROID_PLATFORM=android-37.0
ARG ANDROID_BUILD_TOOLS=37.0.0
ARG ANDROID_NDK=30.0.16248370
RUN yes | sdkmanager --licenses >/dev/null \
    && sdkmanager --install \
        "platform-tools" \
        "platforms;${ANDROID_PLATFORM}" \
        "build-tools;${ANDROID_BUILD_TOOLS}" \
        "ndk;${ANDROID_NDK}" \
    >/tmp/sdkmanager.log \
    && rm /tmp/sdkmanager.log \
    && if [ -e /root/.android/bin/android-cli ]; then \
        echo "sdkmanager fetched the unpinned Android CLI: see CMDLINE_TOOLS_BUILD above"; \
        exit 1; \
    fi

ENV ANDROID_NDK_HOME=$ANDROID_HOME/ndk/$ANDROID_NDK

ARG KOTLIN_VERSION=2.4.20
ARG KOTLIN_SHA256=59e9ca74c7904ef2c122b12114937673ccce68de820a663f0ed66ccf8799e0b7
RUN cd /tmp \
    && curl -fsSL -o kotlin.zip "https://github.com/JetBrains/kotlin/releases/download/v${KOTLIN_VERSION}/kotlin-compiler-${KOTLIN_VERSION}.zip" \
    && echo "$KOTLIN_SHA256  kotlin.zip" | sha256sum -c - \
    && unzip -q kotlin.zip -d /opt \
    && rm kotlin.zip

ARG GRADLE_VERSION=9.8.0
ARG GRADLE_SHA256=bafd5ce9cfaea0fbccfdc8439a1ac42fbd4cd9c89dc9a988228d8a2639a58e6c
RUN cd /tmp \
    && curl -fsSL -o gradle.zip "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
    && echo "$GRADLE_SHA256  gradle.zip" | sha256sum -c - \
    && unzip -q gradle.zip -d /opt \
    && mv "/opt/gradle-${GRADLE_VERSION}" /opt/gradle \
    && rm gradle.zip

ENV PATH="/opt/kotlinc/bin:/opt/gradle/bin:$PATH"

# The same jar, at the same path and with the same checksum, that
# scripts/check.sh and scripts/package/aar.sh look for on a workstation.
ARG COROUTINES_VERSION=1.11.0
ARG COROUTINES_SHA256=d1d75aa01dffbb4d1c520e67e4c4e7f5f6174718e7cb4632412503f2f0e604fa
RUN dir="/root/.cache/sipral/maven/org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/${COROUTINES_VERSION}" \
    && mkdir -p "$dir" \
    && curl -fsSL -o "$dir/kotlinx-coroutines-core-jvm-${COROUTINES_VERSION}.jar" \
        "https://repo1.maven.org/maven2/org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/${COROUTINES_VERSION}/kotlinx-coroutines-core-jvm-${COROUTINES_VERSION}.jar" \
    && echo "$COROUTINES_SHA256  $dir/kotlinx-coroutines-core-jvm-${COROUTINES_VERSION}.jar" | sha256sum -c -

WORKDIR /work
