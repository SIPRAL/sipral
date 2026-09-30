// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// The same loopback call as LoopbackCallKotlinIT, from plain Java: the
// idiomatic layer's classes used directly where their methods are plain,
// SipralJava where they are suspend functions, defaults or flows. Run by
// failsafe against the packaged jar.

package org.sipral.jvm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Test;
import org.sipral.SipralCallState;
import org.sipral.SipralEventKind;
import org.sipral.idiomatic.SipralAccount;
import org.sipral.idiomatic.SipralCall;
import org.sipral.idiomatic.SipralClient;
import org.sipral.idiomatic.SipralMedia;

class LoopbackCallJavaIT {
    private static final long WAIT_MS = 15_000;

    @Test
    void aCallBetweenTwoStacksOnLoopback() throws Exception {
        try (SipralClient alice = SipralJava.open("127.0.0.1");
             SipralClient bob = SipralJava.open("127.0.0.1", 0, "sipral-jvm-test")) {
            assertEquals(SipralNatives.currentPlatform(), SipralNatives.loaded());

            SipralAccount fromAlice = SipralJava.addAccount(alice, "sip:alice@example.invalid", bob.getBindAddress());
            SipralJava.addAccount(bob, "sip:bob@example.invalid", alice.getBindAddress());

            SipralAwaited<SipralCall> placed = SipralJava.awaitNext(
                bob.getEvents(), EnumSet.of(SipralEventKind.INCOMING_CALL), WAIT_MS,
                () -> SipralJava.placeCall(alice, fromAlice, "sip:bob@example.invalid"));
            try (SipralCall callA = placed.getResult();
                 SipralCall callB = SipralJava.answerCall(bob, placed.getEvent())) {
                CompletableFuture<Void> confirmedA = SipralJava.confirmed(callA, WAIT_MS);
                SipralJava.waitConfirmed(callB, WAIT_MS);
                confirmedA.get(WAIT_MS, TimeUnit.MILLISECONDS);
                assertSame(SipralCallState.CONFIRMED, callA.getState());
                assertSame(SipralCallState.CONFIRMED, callB.getState());

                SipralMedia mediaA = until(() -> callA.getMedia());
                SipralMedia mediaB = until(() -> callB.getMedia());
                until(() -> mediaA.statistics().getPacketsReceived() > 0 ? Boolean.TRUE : null);
                until(() -> mediaB.statistics().getPacketsReceived() > 0 ? Boolean.TRUE : null);
                assertTrue(mediaA.statistics().getPacketsSent() > 0, "alice sent no RTP");
                assertTrue(mediaB.statistics().getPacketsSent() > 0, "bob sent no RTP");

                List<Character> digits = new ArrayList<>();
                try (AutoCloseable listening = SipralJava.subscribe(callB.getDigits(), event -> {
                    Character digit = SipralJava.digitOf(event);
                    if (digit != null) {
                        synchronized (digits) {
                            digits.add(digit);
                        }
                    }
                })) {
                    SipralJava.sendDtmf(callA, "7*9");
                    until(() -> {
                        synchronized (digits) {
                            return digits.size() >= 3 ? Boolean.TRUE : null;
                        }
                    });
                }
                synchronized (digits) {
                    assertEquals(List.of('7', '*', '9'), digits);
                }

                callB.hangup();
                SipralJava.waitEnded(callA, WAIT_MS);
                SipralJava.ended(callB, WAIT_MS).get(WAIT_MS, TimeUnit.MILLISECONDS);
                assertTrue(callA.getEnded() && callB.getEnded());

                ExecutionException late = assertThrows(ExecutionException.class,
                    () -> SipralJava.confirmed(callA, 50).get(WAIT_MS, TimeUnit.MILLISECONDS));
                assertTrue(late.getCause() instanceof IllegalStateException, "a call already ended is never confirmed");
            }
            assertThrows(TimeoutException.class, () -> SipralJava.awaitNext(
                bob.getEvents(), EnumSet.of(SipralEventKind.INCOMING_CALL), 100, () -> null));
        }
    }

    private interface Probe<T> {
        T get() throws Exception;
    }

    /** What {@code probe} answers once it answers anything, polled until then. */
    private static <T> T until(Probe<T> probe) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(WAIT_MS);
        while (true) {
            T value = probe.get();
            if (value != null) {
                return value;
            }
            if (System.nanoTime() > deadline) {
                throw new TimeoutException("nothing within " + WAIT_MS + " ms");
            }
            Thread.sleep(20);
        }
    }
}
