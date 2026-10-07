// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Builds this directory on its own, as scripts/check.sh does to prove the
// Android half compiles; an app linking the package never reads it, since
// Gradle uses an included project's build script, not its settings.
//
// Supplies what an app would: the React Native plugin from node_modules,
// react-android matching the installed react-native, and org.sipral:sipral
// from a local Maven repository (-Psipral.repo=DIR, written by
// scripts/package/android.sh).
//
// Versions checked 2026-09-30, deliberately not the newest: React Native
// 0.87.1's own pair, AGP 9.2.1 under Gradle 9.4.1. Its Gradle plugin is
// compiled by Kotlin 2.2, which cannot read the Kotlin 2.4 stdlib in Gradle
// 9.7+, and AGP 9.4 needs Gradle 9.6+.

pluginManagement {
    includeBuild("../node_modules/@react-native/gradle-plugin")
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    plugins {
        id("com.android.library") version "9.2.1"
    }
}

val sipralRepo: File = settingsDir.resolve(
    providers.gradleProperty("sipral.repo").getOrElse("../../../target/android/maven"),
)

val reactNativeVersion: String = Regex("\"version\"\\s*:\\s*\"([^\"]+)\"")
    .find(settingsDir.resolve("../node_modules/react-native/package.json").readText())!!
    .groupValues[1]

dependencyResolutionManagement {
    repositories {
        maven {
            url = sipralRepo.toURI()
            content { includeGroup("org.sipral") }
        }
        google()
        mavenCentral()
    }
}

gradle.beforeProject {
    configurations.configureEach {
        resolutionStrategy.eachDependency {
            if (requested.group == "com.facebook.react" && requested.version.isNullOrEmpty()) {
                useVersion(reactNativeVersion)
            }
        }
    }
}

rootProject.name = "sipral-react-native"
