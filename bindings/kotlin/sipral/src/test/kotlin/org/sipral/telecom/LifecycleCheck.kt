// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// SipralLifecycle and wakeForPush on a plain JVM, over real stacks and the
// loopback registrar of ReachabilityCheck.kt, with only the telecom
// framework faked: a process that registered, wrote its registration down
// on every acceptance and on the way into the background, and told the
// stack it was suspending; then a new process woken by a push, which shows
// the call ringing before anything is sent, carries the binding on with
// the same Call-ID, and is ready a measured time after its cold start. The
// lifecycle entry points the idiomatic layer adds are called on a live
// client. Run by TelecomCheck.kt's main, under -Xcheck:jni.

package org.sipral.telecom

import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.sipral.SipralRegistrationState
import org.sipral.idiomatic.DatagramRegistrar
import org.sipral.idiomatic.SipralAccount
import org.sipral.idiomatic.SipralAudioMode
import org.sipral.idiomatic.SipralClient
import org.sipral.idiomatic.SipralLifecycle
import org.sipral.idiomatic.SipralSnapshotStore

private class MemoryStore : SipralSnapshotStore {
    val records = ConcurrentHashMap<String, ByteArray>()
    var writes = 0

    override fun write(key: String, record: ByteArray) {
        writes++
        records[key] = record
    }

    override fun read(key: String): ByteArray? = records[key]

    override fun remove(key: String) {
        records.remove(key)
    }
}

private fun callIdOf(message: String): String? =
    message.split("\r\n").firstOrNull { it.lowercase().startsWith("call-id:") }?.substringAfter(':')?.trim()

private suspend fun until(what: String, condition: () -> Boolean) {
    repeat(400) {
        if (condition()) return
        delay(25)
    }
    throw AssertionError("timed out waiting for $what")
}

private suspend fun reaches(account: SipralAccount, state: SipralRegistrationState) =
    until("the account to read $state, it reads ${account.registrationState}") { account.registrationState == state }

internal suspend fun lifecycleChecks(): String {
    val aor = "sip:alice@example.com"
    val store = MemoryStore()
    var wall = 1_760_000_000_000L
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    try {
        DatagramRegistrar().use { registrar ->
            // the first process
            val first = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1")
            val lifecycle = SipralLifecycle(store) { wall }
            lifecycle.attach(first, scope)
            val account = first.addAccount(aor, registrar.address, registrar = "sip:example.com")
            assertNull(account.pushEcho, "an account that asked for no push has no echo")
            lifecycle.keep(account, aor)
            account.register()
            reaches(account, SipralRegistrationState.REGISTERED)
            until("the accepted registration to be written down") { store.records.isNotEmpty() }
            val onAcceptance = store.writes
            wall += 60_000
            val suspended = assertNotNull(lifecycle.enteredBackground())
            assertEquals(1L, suspended.unverified, "the one binding stopped counting as live")
            assertEquals(onAcceptance + 1, store.writes, "written once more on the way into the background")
            val firstCallId = callIdOf(registrar.registers.last())
            assertEquals(SipralRegistrationState.UNVERIFIED, account.registrationState)
            // back in the foreground the binding is proved again, and the
            // acceptance written down: the record is never behind the
            // sequence number the registrar last saw
            val beforeResume = store.writes
            lifecycle.enteredForeground()
            reaches(account, SipralRegistrationState.REGISTERED)
            until("the proof to be written down") { store.writes > beforeResume }
            first.interfaceLost()
            first.nameResolutionLost()
            lifecycle.attach(null, null)
            first.close()
            val sentBefore = registrar.registers.size

            // the process the system started again for a push, ten minutes on
            wall += 600_000
            val second = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1")
            try {
                val woken = SipralLifecycle(store) { wall }
                woken.attach(second, scope)
                val log = Log()
                val platform = FakePlatform(log)
                val added = second.addAccount(aor, registrar.address, registrar = "sip:example.com")
                val bridge = TelecomBridge(platform, IdiomaticSipCalls(second, listOf(added)))
                platform.bridge = bridge
                bridge.collect(scope, second.events)
                val wake = wakeForPush(second, added, bridge, woken, aor, "sip:bob@example.com", "Bob")
                assertTrue(wake.restored, "the registration was carried on")
                assertEquals(0, log.indexOf("report ${wake.id}"), "the call was shown before anything else: ${log.snapshot()}")
                reaches(added, SipralRegistrationState.REGISTERED)
                val refresh = registrar.registers.drop(sentBefore)
                assertEquals(1, refresh.size, "one REGISTER, the announce's refresh: $refresh")
                assertEquals(firstCallId, callIdOf(refresh.first()), "it continues the first process's binding")
                val ready = assertNotNull(added.timeToReadyMs)
                assertTrue(ready in 0..10_000, "ready $ready ms after the cold start")
                assertEquals(TelecomPhase.RINGING, bridge.calls.value.single().phase)
                bridge.reject(wake.id)
                woken.forget(aor)
                assertTrue(store.records.isEmpty(), "forgotten")

                // a third process with nothing written down registers from the
                // beginning, and still shows the call first
                val third = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1")
                try {
                    val fresh = third.addAccount(aor, registrar.address, registrar = "sip:example.com")
                    val thirdLog = Log()
                    val thirdPlatform = FakePlatform(thirdLog)
                    val thirdBridge = TelecomBridge(thirdPlatform, IdiomaticSipCalls(third, listOf(fresh)))
                    thirdPlatform.bridge = thirdBridge
                    thirdBridge.collect(scope, third.events)
                    val cold = wakeForPush(third, fresh, thirdBridge, SipralLifecycle(store) { wall }, aor, "sip:bob@example.com")
                    assertFalse(cold.restored)
                    reaches(fresh, SipralRegistrationState.REGISTERED)
                    assertTrue(callIdOf(registrar.registers.last()) != firstCallId, "a new binding")
                    thirdBridge.reject(cold.id)
                } finally {
                    third.close()
                }
                return "a registration written down on acceptance and on the way into the background " +
                    "(suspending: ${suspended.unverified} unverified), a process woken by a push ten minutes " +
                    "later showed the call first, carried the binding on its Call-ID with one REGISTER and was " +
                    "ready $ready ms after its cold start; with nothing written down, a new binding"
            } finally {
                second.close()
            }
        }
    } finally {
        scope.cancel()
    }
}
