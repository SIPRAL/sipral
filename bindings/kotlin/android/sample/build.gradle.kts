// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The skeleton sample: registration, a call, hold, DTMF and audio routes,
// through the ConnectionService helper, with what a store build needs
// around it (the call's foreground service, the readiness screen, the
// passwords in the Keystore, a diagnostics bundle). Not a product. The
// AndroidX and Compose versions were the newest stable releases on Google's
// Maven on 2026-09-23, androidx.core on 2026-10-21.
//
// The variant and the version code come from scripts/package/android.sh:
// -Psipral.variant=opus for the build whose natives carry libopus, and
// -Psipral.versionCode=N for a store upload that needs a code higher than
// the last one uploaded.

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// the workspace's single version, read from where it is kept
val sipralVersion: String = rootDir.resolve("../../../Cargo.toml").readLines()
    .dropWhile { it.trim() != "[workspace.package]" }
    .first { it.trim().startsWith("version") }
    .substringAfter('"').substringBefore('"')
val withOpus: Boolean = providers.gradleProperty("sipral.variant").orNull == "opus"

// 1.2.3 is 10203, times ten, plus one for the variant with Opus: the two
// variants of one release never share a code.
val derivedVersionCode: Int = sipralVersion.split('.').map { it.takeWhile(Char::isDigit).toInt() }
    .let { (major, minor, patch) -> ((major * 100 + minor) * 100 + patch) * 10 + if (withOpus) 1 else 0 }

android {
    namespace = "org.sipral.sample"
    compileSdk = 37

    defaultConfig {
        applicationId = "org.sipral.sample"
        minSdk = 26
        // the newest stable API level, checked 2026-10-21 against Google's SDK
        // repository: Android 17, API 37 (37.2 is a minor release of it)
        targetSdk = 37
        versionCode = providers.gradleProperty("sipral.versionCode").orNull?.toInt() ?: derivedVersionCode
        versionName = sipralVersion + if (withOpus) "-opus" else ""
        // The ABIs sipral.aar carries. Without this, a dependency that ships
        // natives for x86 as well would make the APK claim x86, and an x86
        // device would install it and find no libsipral_jni.so to load.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    buildTypes {
        // Signed afterwards, on the machine that holds the key
        // (scripts/package/android-sign.sh), so the key never enters the
        // build image. Not shrunk: the natives look three listener classes
        // up by name, and a sample is read more than it is downloaded.
        release {
            isMinifyEnabled = false
        }
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // The sample's own logic on the JVM against the stub jar (TestNG, as in
    // :telecom, rather than JUnit's EPL).
    testOptions {
        unitTests {
            isReturnDefaultValues = true
            all { it.useTestNG() }
        }
    }
}

dependencies {
    implementation(project(":telecom"))
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core:1.19.1")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    testImplementation("org.testng:testng:7.12.0")
}
