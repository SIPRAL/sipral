// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// A blind transfer through org.sipral.idiomatic: Alice calls Bob, asks him
// with SipralCall.transfer to call Carol instead, Bob's application reads
// the request with transferOf and takes it with acceptReferral, Carol's
// phone rings, and Alice hears how it went; and an attended one, consulted
// with SipralCall.consult and handed over with SipralCall.transferTo. Three
// clients on loopback, run by IdiomaticCheck.kt's main, under -Xcheck:jni.

package org.sipral.idiomatic

import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.sipral.SipralCallState
import org.sipral.SipralEventKind

private suspend fun blindTransfer(): String {
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { alice ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { bob ->
            SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { carol ->
                val aliceLine = alice.addAccount(aor = "sip:alice@sipral.invalid", registrarAddress = bob.bindAddress)
                bob.addAccount(aor = "sip:bob@sipral.invalid", registrarAddress = carol.bindAddress)
                carol.addAccount(aor = "sip:carol@sipral.invalid", registrarAddress = bob.bindAddress)

                val (toBob, incoming) = bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
                    alice.placeCall(aliceLine, target = "sip:bob@${bob.bindAddress}")
                }
                toBob.use {
                    bob.answerCall(incoming).use {
                        toBob.waitConfirmed()

                        val target = "sip:carol@${carol.bindAddress}"
                        val (_, asked) = bob.events.awaitNext(SipralEventKind.TRANSFER_REQUESTED, timeoutMs = 10_000) {
                            toBob.transfer(target)
                        }
                        val request = assertNotNull(transferOf(asked), "TRANSFER_REQUESTED carried no transfer payload")
                        assertEquals(target, request.target, "Bob was asked to call somebody else")
                        assertEquals(0L, request.attended, "a blind transfer names no dialog to replace")

                        // subscribed before Bob accepts (see awaitNext): Alice's report can arrive
                        // while Carol is still answering
                        val outcome = coroutineScope {
                            val done = async(start = CoroutineStart.UNDISPATCHED) {
                                withTimeout(15_000) {
                                    toBob.events.first { it.kind == SipralEventKind.TRANSFER_DONE.value.toLong() }
                                }
                            }
                            val (placed, ringing) = carol.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 10_000) {
                                bob.acceptReferral(asked)
                            }
                            placed.use {
                                carol.answerCall(ringing).use {
                                    placed.waitConfirmed()
                                    assertNotNull(transferOf(done.await()), "TRANSFER_DONE carried no transfer payload")
                                }
                            }
                        }
                        assertTrue(outcome.statusCode in 200L..299L, "the transfer ended ${outcome.statusCode}")
                        return "a blind transfer asked of Bob rang Carol and reported ${outcome.statusCode} to Alice"
                    }
                }
            }
        }
    }
}

/**
 * An attended transfer: Alice consults Carol from the line her call with Bob
 * is on, then hands Bob over with SipralCall.transferTo. Bob is asked to call
 * Carol with `Replaces`; Carol takes such an INVITE only from her call's own
 * far end (RFC 3891 §3, the stack's default), so on loopback she answers
 * 403, Alice hears it, and her call with Bob stays up.
 */
private suspend fun attendedTransfer(): String {
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { alice ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { bob ->
            SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { carol ->
                val aliceLine = alice.addAccount(aor = "sip:alice@sipral.invalid", registrarAddress = bob.bindAddress)
                // Bob's transfer INVITE goes to Carol, not back to Alice
                bob.addAccount(aor = "sip:bob@sipral.invalid", registrarAddress = carol.bindAddress)
                carol.addAccount(aor = "sip:carol@sipral.invalid", registrarAddress = alice.bindAddress)

                val (toBob, incoming) = bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
                    alice.placeCall(aliceLine, target = "sip:bob@${bob.bindAddress}")
                }
                toBob.use {
                    bob.answerCall(incoming).use {
                        toBob.waitConfirmed()
                        toBob.hold()

                        val target = "sip:carol@${carol.bindAddress}"
                        val (toCarol, consulted) = carol.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 10_000) {
                            toBob.consult(target, destination = carol.bindAddress)
                        }
                        toCarol.use {
                            assertTrue(toCarol.handle != toBob.handle, "the consultation is a call of its own")
                            assertEquals(
                                "sip:alice@sipral.invalid", consulted.payload.call.fromUri?.toString(Charsets.UTF_8),
                                "the consultation left from another line",
                            )
                            carol.answerCall(consulted).use {
                                toCarol.waitConfirmed()
                                assertEquals(SipralCallState.CONSULTING, toCarol.state, "the stack knows it consults")

                                val (_, asked) = bob.events.awaitNext(SipralEventKind.TRANSFER_REQUESTED, timeoutMs = 10_000) {
                                    toBob.transferTo(toCarol)
                                }
                                val request = assertNotNull(transferOf(asked), "TRANSFER_REQUESTED carried no transfer payload")
                                assertEquals(1L, request.attended, "an attended transfer names the dialog to replace")
                                assertEquals(target, request.target)

                                val (placed, done) = toBob.events.awaitNext(SipralEventKind.TRANSFER_DONE, timeoutMs = 15_000) {
                                    bob.acceptReferral(asked)
                                }
                                placed.use {
                                    val outcome = assertNotNull(transferOf(done), "TRANSFER_DONE carried no transfer payload")
                                    assertEquals(403L, outcome.statusCode)
                                    assertEquals(SipralCallState.CONFIRMED, toBob.state, "a failed transfer lost the call")
                                    return "an attended transfer consulted Carol from Alice's line and named " +
                                        "the consultation to Bob, refused ${outcome.statusCode} on loopback"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/** Everything above, for IdiomaticCheck.kt's main. */
internal suspend fun transferChecks(): String = blindTransfer() + "; " + attendedTransfer()
