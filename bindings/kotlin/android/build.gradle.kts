// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Versions checked 2026-09-23: the newest stable AGP, and the Kotlin
// release matching the image's kotlinc, so sipral.aar and this build share
// one compiler. AGP 9 compiles Kotlin itself; the Kotlin plugin is named
// only to pin that compiler.

plugins {
    id("com.android.application") version "9.4.1" apply false
    id("com.android.library") version "9.4.1" apply false
    id("org.jetbrains.kotlin.android") version "2.4.20" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.20" apply false
}
