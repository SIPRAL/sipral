// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.sample

import android.content.Context

/** The release build takes its account from the screen only; the debug
 * build's `AccountImport` also reads one handed over by a test run. */
object AccountImport {
    @Suppress("UNUSED_PARAMETER")
    fun take(context: Context): AccountSettings? = null
}
