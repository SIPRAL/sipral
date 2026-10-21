// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.android.telecom

import kotlinx.coroutines.flow.StateFlow
import org.sipral.telecom.AudioRoute

/**
 * One call's audio routes and mute, as the telecom framework reports them,
 * whichever adapter carries the call: a [SipralConnection] under the
 * self-managed `ConnectionService`, a [SipralCoreCall] under Core-Telecom.
 * [SipralTelecom.callRoutes] holds every live one by call id;
 * [SipralCallAudio] follows them with the call's device.
 */
interface SipralCallRoutes {
    /** The id the [org.sipral.telecom.TelecomBridge] knows the call by. */
    val id: String

    /** The routes the platform currently offers for this call. */
    val routes: StateFlow<List<AudioRoute>>

    /** The route the platform is currently using. */
    val route: StateFlow<AudioRoute?>

    /** Whether the platform muted this call, e.g. from a Bluetooth headset or
     * car control, which reach the call only through the framework. */
    val muted: StateFlow<Boolean>

    /** Ask the platform for [route], one of [routes]. The platform may
     * refuse; [route] says what it settled on. */
    fun requestRoute(route: AudioRoute)
}

/** Which of the two adapters puts calls in front of the telecom framework. */
enum class SipralTelecomAdapter {
    /** The self-managed `ConnectionService` ([SipralConnectionService],
     * [AndroidTelecomPlatform]), on every release from Android 8. */
    CONNECTION_SERVICE,

    /** Jetpack Core-Telecom's `CallsManager` ([CoreTelecomPlatform]): on
     * Android 14 and later the platform's transactional call API, below
     * that a `ConnectionService` of the library's own. */
    CORE_TELECOM,
    ;

    companion object {
        /**
         * The adapter for a phone on API level [sdk]: Core-Telecom from
         * Android 14 (API 34), where it drives the transactional API the
         * platform points VoIP applications to (`CAPABILITY_SELF_MANAGED` is
         * deprecated from API 37); the `ConnectionService` below that, where
         * Core-Telecom would only run a `ConnectionService` of its own in
         * place of this library's. `docs/15-mobile.md` says why.
         */
        fun preferred(sdk: Int): SipralTelecomAdapter =
            if (sdk >= CORE_TELECOM_FROM) CORE_TELECOM else CONNECTION_SERVICE

        /** Android 14, the first release with the transactional call API. */
        const val CORE_TELECOM_FROM: Int = 34
    }
}
