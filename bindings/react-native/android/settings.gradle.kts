// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// This directory built on its own, which is what scripts/check.sh does to
// prove the Android half compiles: an application that links the package
// never reads this file, since Gradle takes an included project's build
// script and not its settings.
//
// What an application would have supplied, supplied here: the React Native
// plugin out of node_modules, react-android at the version the installed
// react-native is, and org.sipral:sipral from a local Maven repository
// (-Psipral.repo=DIR; scripts/package/android.sh writes one).
//
// Versions checked 2026-09-30, and not the newest on purpose: React Native
// 0.87.1's own pair, the Android Gradle Plugin 9.2.1 under Gradle 9.4.1
// (gradle/wrapper). Its Gradle plugin, built here from node_modules, is
// compiled by Kotlin 2.2, which cannot read the Kotlin 2.4 standard library
// Gradle 9.7 and later carry, and the Android Gradle Plugin 9.4 asks for
// Gradle 9.6 or later.

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
