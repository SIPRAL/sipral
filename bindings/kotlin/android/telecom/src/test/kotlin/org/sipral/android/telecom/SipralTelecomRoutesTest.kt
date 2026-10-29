// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// SipralTelecom.callRoutes while calls come and go on many threads at once,
// as Core-Telecom adds and ends them on whatever threads its scope runs: a
// call that is live has its routes in the map, whatever the others do, and
// one that ended has none.

package org.sipral.android.telecom

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.MutableStateFlow
import org.sipral.telecom.AudioRoute
import org.testng.Assert.assertSame
import org.testng.Assert.assertTrue
import org.testng.annotations.Test

class SipralTelecomRoutesTest {
    private class Routes(override val id: String) : SipralCallRoutes {
        override val routes = MutableStateFlow<List<AudioRoute>>(emptyList())
        override val route = MutableStateFlow<AudioRoute?>(null)
        override val muted = MutableStateFlow(false)

        override fun requestRoute(route: AudioRoute) {
            this.route.value = route
        }
    }

    @Test
    fun aLiveCallsRoutesAreNeverMissingWhileOthersComeAndGo() {
        val kept = Routes("routes-kept")
        SipralTelecom.routesCreated(kept.id, kept)
        val pool = Executors.newFixedThreadPool(THREADS)
        val start = CountDownLatch(1)
        try {
            val work = (0 until THREADS).map { thread ->
                pool.submit {
                    start.await()
                    repeat(ROUNDS) { round ->
                        val call = Routes("routes-$thread-$round")
                        SipralTelecom.routesCreated(call.id, call)
                        val created = SipralTelecom.callRoutes.value
                        assertSame(created[call.id], call, "a call just created has no routes")
                        assertSame(created[kept.id], kept, "the live call's routes went missing")
                        SipralTelecom.routesDestroyed(call.id)
                        assertSame(SipralTelecom.callRoutes.value[kept.id], kept, "the live call's routes went missing")
                    }
                }
            }
            start.countDown()
            work.forEach { it.get(30, TimeUnit.SECONDS) }

            val left = SipralTelecom.callRoutes.value
            assertSame(left[kept.id], kept)
            assertTrue(left.keys.none { it.startsWith("routes-") && it != kept.id }, "an ended call kept its routes: $left")
        } finally {
            pool.shutdownNow()
            SipralTelecom.routesDestroyed(kept.id)
        }
    }

    private companion object {
        const val THREADS = 8
        const val ROUNDS = 2000
    }
}
