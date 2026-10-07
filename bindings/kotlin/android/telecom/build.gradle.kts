// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The ConnectionService helper: TelecomBridge (in sipral.aar, tested on a
// plain JVM) behind android.telecom, with a self-managed PhoneAccount, a
// ConnectionService and a Connection per call.

plugins {
    id("com.android.library")
}

// the workspace's single version, read from where it is kept
val sipralVersion: String = rootDir.resolve("../../../Cargo.toml").readLines()
    .dropWhile { it.trim() != "[workspace.package]" }
    .first { it.trim().startsWith("version") }
    .substringAfter('"').substringBefore('"')

android {
    namespace = "org.sipral.android.telecom"
    compileSdk = 37

    defaultConfig {
        // self-managed connections exist from Android 8.0
        minSdk = 26
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // The connection's callbacks on the JVM against the stub jar, every method
    // returning its default. TestNG rather than JUnit, whose EPL licence this
    // repository does not accept.
    testOptions {
        unitTests {
            isReturnDefaultValues = true
            all { it.useTestNG() }
        }
    }
}

dependencies {
    api("org.sipral:sipral:$sipralVersion")
    api("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    // newest stable on Maven Central, checked 2026-09-23; test only
    testImplementation("org.testng:testng:7.12.0")
}
