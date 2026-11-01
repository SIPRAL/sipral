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
//
// The push build: given a Firebase project's google-services.json
// (-Psipral.googleServices=FILE, or the file beside this one, never
// committed), Firebase Cloud Messaging is compiled in from src/fcm, its
// project read into the resources Firebase initialises itself from, with
// no Google Services plugin. Without the file nothing of Firebase is
// resolved and the build is the one android.sh checks; Firebase's Play
// services libraries come under Google's own terms, not deny.toml's
// licences (THIRD-PARTY-NOTICES.md).

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

val googleServices: File? = (providers.gradleProperty("sipral.googleServices").orNull?.let(::File)
    ?: file("google-services.json")).takeIf { it.isFile }

// The values the Google Services plugin would write, for this application's
// client in the file (developers.google.com/android/guides/google-services-plugin).
val firebase: Map<String, String>? = googleServices?.let { json ->
    val root = groovy.json.JsonSlurper().parse(json) as Map<*, *>
    val project = root["project_info"] as Map<*, *>
    val client = (root["client"] as List<*>).map { it as Map<*, *> }.firstOrNull {
        ((it["client_info"] as Map<*, *>)["android_client_info"] as Map<*, *>)["package_name"] == "org.sipral.sample"
    } ?: throw GradleException("$json has no Android application org.sipral.sample")
    mapOf(
        "google_app_id" to (client["client_info"] as Map<*, *>)["mobilesdk_app_id"] as String,
        "google_api_key" to ((client["api_key"] as List<*>).first() as Map<*, *>)["current_key"] as String,
        "gcm_defaultSenderId" to project["project_number"] as String,
        "project_id" to project["project_id"] as String,
    )
}

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
        firebase?.forEach { (name, value) -> resValue("string", name, value) }
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
        resValues = firebase != null
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

if (firebase != null) {
    androidComponents {
        onVariants { variant ->
            variant.sources.kotlin?.addStaticSourceDirectory("src/fcm/kotlin")
            variant.sources.manifests.addStaticManifestFile("src/fcm/AndroidManifest.xml")
        }
    }
}

dependencies {
    if (firebase != null) {
        // the newest Firebase BoM on Google's Maven on 2026-11-01
        implementation(platform("com.google.firebase:firebase-bom:35.1.0"))
        implementation("com.google.firebase:firebase-messaging")
    }
    implementation(project(":telecom"))
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core:1.19.1")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    testImplementation("org.testng:testng:7.12.0")
}
