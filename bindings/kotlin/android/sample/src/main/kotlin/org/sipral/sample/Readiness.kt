// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.sample

/**
 * What the phone allows this application, read when the readiness screen is
 * shown. Null where the release has no such setting.
 */
data class ReadinessFacts(
    val sdk: Int,
    val microphone: Boolean,
    /** POST_NOTIFICATIONS, from Android 13; null before, where it is not a
     * runtime permission. */
    val notifications: Boolean?,
    /** `NotificationManager.canUseFullScreenIntent`, from Android 14. */
    val fullScreenIntent: Boolean?,
    /** `PowerManager.isIgnoringBatteryOptimizations`. */
    val batteryUnrestricted: Boolean,
    /** `ActivityManager.isBackgroundRestricted`, from Android 9. */
    val backgroundRestricted: Boolean?,
    /** `UsageStatsManager.getAppStandbyBucket`, from Android 9: 10 active,
     * 20 working set, 30 frequent, 40 rare, 45 restricted, 5 exempt. */
    val standbyBucket: Int?,
)

enum class ReadinessAction { ASK_MICROPHONE, ASK_NOTIFICATIONS, FULL_SCREEN_SETTINGS, BATTERY_SETTINGS, APP_SETTINGS }

/** One line of the readiness screen: whether it is in order, what it means
 * for a call, and the one thing the user can do about it. */
data class ReadinessItem(val title: String, val ready: Boolean, val explanation: String, val action: ReadinessAction?)

/** The readiness screen, in the order a user meets the problems. */
fun readinessOf(facts: ReadinessFacts): List<ReadinessItem> = buildList {
    add(
        if (facts.microphone) {
            ReadinessItem("Microphone", true, "Allowed: the far end hears you.", null)
        } else {
            ReadinessItem(
                "Microphone",
                false,
                "Not allowed: calls connect, and the far end hears silence.",
                ReadinessAction.ASK_MICROPHONE,
            )
        },
    )
    facts.notifications?.let { allowed ->
        add(
            if (allowed) {
                ReadinessItem("Notifications", true, "Allowed: an incoming call is announced.", null)
            } else {
                ReadinessItem(
                    "Notifications",
                    false,
                    "Not allowed: a call that arrives while this screen is closed rings with nothing shown.",
                    ReadinessAction.ASK_NOTIFICATIONS,
                )
            },
        )
    }
    facts.fullScreenIntent?.let { allowed ->
        add(
            if (allowed) {
                ReadinessItem("Calls over the lock screen", true, "Allowed: a call wakes the screen and shows itself.", null)
            } else {
                ReadinessItem(
                    "Calls over the lock screen",
                    false,
                    "Not allowed: an incoming call shows as a notification at the top of the screen, and on a " +
                        "locked phone the screen stays dark until it is touched. Installed from Google Play as a " +
                        "calling application, this is allowed without asking.",
                    ReadinessAction.FULL_SCREEN_SETTINGS,
                )
            },
        )
    }
    if (facts.backgroundRestricted == true) {
        add(
            ReadinessItem(
                "Background use",
                false,
                "Restricted: while it is not on screen this application has no network, so it cannot stay " +
                    "registered or ring.",
                ReadinessAction.APP_SETTINGS,
            ),
        )
    }
    add(
        ReadinessItem(
            "Battery optimisation",
            true,
            if (facts.batteryUnrestricted) {
                "Turned off for this application by the user: it keeps the network while the phone sleeps."
            } else {
                "On, as Android sets it. While the phone is asleep (Doze) this application has no network: the " +
                    "registration is not refreshed and a call sent to it is not received until the phone wakes " +
                    "or a push wakes the application. This application does not ask to be exempted; the " +
                    "battery settings let you choose."
            },
            ReadinessAction.BATTERY_SETTINGS,
        ),
    )
    facts.standbyBucket?.let { bucket ->
        val (name, ready) = when {
            bucket <= 10 -> "active" to true
            bucket <= 20 -> "working set" to true
            bucket <= 30 -> "frequent" to true
            bucket <= 40 -> "rare" to false
            else -> "restricted" to false
        }
        add(
            ReadinessItem(
                "App standby: $name",
                ready,
                if (ready) {
                    "Android runs this application's background work without delay."
                } else {
                    "Android has put this application aside for not being opened: its background work and " +
                        "network are held back, and only a push brings it back quickly."
                },
                null,
            ),
        )
    }
}
