// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The skeleton sample: registration, a call, hold, DTMF and audio routes,
// through the ConnectionService helper. Not a product. The AndroidX and
// Compose versions were the newest stable releases on Google's Maven on
// 2026-09-23.

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.sipral.sample"
    compileSdk = 37

    defaultConfig {
        applicationId = "org.sipral.sample"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "sample"
        // The ABIs sipral.aar carries. Without this, a dependency that ships
        // natives for x86 as well would make the APK claim x86, and an x86
        // device would install it and find no libsipral_jni.so to load.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":telecom"))
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
}
