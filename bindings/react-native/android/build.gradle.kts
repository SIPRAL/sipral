// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The Android half of sipral-react-native, included through autolinking.
// The React Native plugin runs codegen over ../src/NativeSipral.ts and adds
// the generated NativeSipralSpec; AGP compiles the Kotlin.
//
// Versions come from the app (its React Native pins react-android, its
// build names the plugins). Standalone, this builds through
// settings.gradle.kts, as scripts/check.sh does.

plugins {
    id("com.android.library")
    id("com.facebook.react")
}

// the wrapped binding has this package's version, read from package.json
val sipralVersion: String = Regex("\"version\"\\s*:\\s*\"([^\"]+)\"")
    .find(projectDir.resolve("../package.json").readText())!!
    .groupValues[1]

android {
    namespace = "org.sipral.reactnative"
    compileSdk = 37

    defaultConfig {
        // React Native's floor; the library opens phone audio from API 28 and
        // says so on anything older
        minSdk = 24
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("com.facebook.react:react-android")
    implementation("org.sipral:sipral:$sipralVersion")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
}
