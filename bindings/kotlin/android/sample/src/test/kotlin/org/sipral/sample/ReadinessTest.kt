// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The readiness screen from what the phone allows: each refusal is shown
// with the one action that undoes it, a setting the release does not have
// is not shown at all, and battery optimisation is reported and never
// counted against the phone, since the application does not ask to be
// exempted from it.

package org.sipral.sample

import org.testng.Assert.assertEquals
import org.testng.Assert.assertFalse
import org.testng.Assert.assertTrue
import org.testng.annotations.Test

class ReadinessTest {
    private val android14Allowed = ReadinessFacts(
        sdk = 34,
        microphone = true,
        notifications = true,
        fullScreenIntent = true,
        batteryUnrestricted = false,
        backgroundRestricted = false,
        standbyBucket = 10,
    )

    @Test
    fun everythingAllowedIsReady() {
        val items = readinessOf(android14Allowed)
        assertTrue(items.all { it.ready }, items.toString())
        assertEquals(
            items.map { it.title },
            listOf("Microphone", "Notifications", "Calls over the lock screen", "Battery optimisation", "App standby: active"),
        )
        assertEquals(items.single { it.title == "Battery optimisation" }.action, ReadinessAction.BATTERY_SETTINGS)
    }

    @Test
    fun eachRefusalCarriesItsAction() {
        val items = readinessOf(
            android14Allowed.copy(
                microphone = false,
                notifications = false,
                fullScreenIntent = false,
                backgroundRestricted = true,
                standbyBucket = 45,
            ),
        ).associateBy { it.title }
        assertEquals(items.getValue("Microphone").action, ReadinessAction.ASK_MICROPHONE)
        assertEquals(items.getValue("Notifications").action, ReadinessAction.ASK_NOTIFICATIONS)
        val fullScreen = items.getValue("Calls over the lock screen")
        assertFalse(fullScreen.ready)
        assertEquals(fullScreen.action, ReadinessAction.FULL_SCREEN_SETTINGS)
        assertTrue(fullScreen.explanation.contains("notification at the top of the screen"))
        assertEquals(items.getValue("Background use").action, ReadinessAction.APP_SETTINGS)
        assertFalse(items.getValue("App standby: restricted").ready)
    }

    @Test
    fun anOldReleaseShowsOnlyWhatItHas() {
        val items = readinessOf(
            ReadinessFacts(
                sdk = 26,
                microphone = true,
                notifications = null,
                fullScreenIntent = null,
                batteryUnrestricted = true,
                backgroundRestricted = null,
                standbyBucket = null,
            ),
        )
        assertEquals(items.map { it.title }, listOf("Microphone", "Battery optimisation"))
        assertTrue(items.last().explanation.startsWith("Turned off for this application"))
    }
}
