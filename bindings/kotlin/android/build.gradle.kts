// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// Versions checked 2026-09-23: the Android Gradle Plugin's newest stable
// release on Google's Maven, and the Kotlin release the image's kotlinc is,
// so that the classes in sipral.aar and the ones compiled here come from
// one compiler version. The Android Gradle Plugin 9 compiles Kotlin itself;
// the Kotlin plugin is named here only to pin which compiler that is.

plugins {
    id("com.android.application") version "9.4.1" apply false
    id("com.android.library") version "9.4.1" apply false
    id("org.jetbrains.kotlin.android") version "2.4.20" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.20" apply false
}
