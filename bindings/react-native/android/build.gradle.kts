// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The Android half of sipral-react-native: a library an application's
// Gradle build includes through autolinking. The React Native plugin runs
// codegen over ../src/NativeSipral.ts and adds the NativeSipralSpec it
// writes to the sources; the Android Gradle Plugin compiles the Kotlin.
//
// Versions come from the application: its React Native pins react-android,
// and its build names the plugins. On its own this directory builds through
// settings.gradle.kts beside it, which is how scripts/check.sh compiles it.

plugins {
    id("com.android.library")
    id("com.facebook.react")
}

// The binding this wraps is the one of the same version as this package,
// read from package.json rather than written a second time here.
val sipralVersion: String = Regex("\"version\"\\s*:\\s*\"([^\"]+)\"")
    .find(projectDir.resolve("../package.json").readText())!!
    .groupValues[1]

android {
    namespace = "org.sipral.reactnative"
    compileSdk = 37

    defaultConfig {
        // React Native's own floor. The library opens a phone's audio from
        // API level 28, and says so when opened on anything older.
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
