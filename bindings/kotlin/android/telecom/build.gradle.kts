// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// The ConnectionService helper: org.sipral.telecom's TelecomBridge (inside
// sipral.aar, and tested on a plain JVM by scripts/check.sh) put behind
// android.telecom -- a self-managed PhoneAccount, a ConnectionService, and a
// Connection per call.

plugins {
    id("com.android.library")
}

// The one version this workspace has, read where it is kept rather than
// written again here.
val sipralVersion: String = rootDir.resolve("../../../Cargo.toml").readLines()
    .dropWhile { it.trim() != "[workspace.package]" }
    .first { it.trim().startsWith("version") }
    .substringAfter('"').substringBefore('"')

android {
    namespace = "org.sipral.android.telecom"
    compileSdk = 37

    defaultConfig {
        // Self-managed connections (PhoneAccount.CAPABILITY_SELF_MANAGED)
        // exist from Android 8.0.
        minSdk = 26
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    api("org.sipral:sipral:$sipralVersion")
    api("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
}
