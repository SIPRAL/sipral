// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// The Android half of the Kotlin binding: the ConnectionService helper as an
// Android library (:telecom) and a Compose sample over it (:sample). Built by
// scripts/package/android.sh inside the image bindings/kotlin/android/
// Dockerfile describes; the binding itself, sipral.aar, is built first by
// scripts/package/aar.sh and read from a local Maven repository.

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

// Where scripts/package/android.sh put sipral.aar and its POM. A different
// place is named with -Psipral.repo=DIR.
val sipralRepo: File = settingsDir.resolve(
    providers.gradleProperty("sipral.repo").getOrElse("../../../target/android/maven"),
)

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven {
            url = sipralRepo.toURI()
            content { includeGroup("org.sipral") }
        }
        google()
        mavenCentral()
    }
}

rootProject.name = "sipral-android"
include(":telecom", ":sample")
