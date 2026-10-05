// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
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

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Test;
import org.sipral.Sipral;
import org.sipral.SipralAbiVersion;
import org.sipral.SipralCallState;
import org.sipral.SipralEventKind;
import org.sipral.SipralException;
import org.sipral.SipralStatus;
import org.sipral.SipralTransport;
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

    /** An account on a TCP connection of its own, beside one on the client's
     * UDP socket, added from Java: its REGISTER reaches a registrar that
     * takes TCP alone, over a connection the client opened. */
    @Test
    void theCeilingsAServerRaisesReachTheLibrary() throws Exception {
        try (SipralClient plain = SipralJava.open("127.0.0.1");
             SipralClient roomy = SipralJava.open("127.0.0.1", 0, null, 1_000L, 3_256L)) {
            assertEquals(128L, plain.settings().getMaxDialogs());
            assertEquals(256L, plain.settings().getMaxServerTransactions());
            assertEquals(1_000L, roomy.settings().getMaxDialogs());
            assertEquals(3_256L, roomy.settings().getMaxServerTransactions());
        }
    }

    @Test
    void anAccountOnAConnectionOfItsOwnRegistersOverTcp() throws Exception {
        try (ServerSocket registrar = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
             SipralClient client = SipralJava.open("127.0.0.1")) {
            String address = "127.0.0.1:" + registrar.getLocalPort();
            CompletableFuture<String> register = CompletableFuture.supplyAsync(() -> {
                try (Socket connection = registrar.accept()) {
                    connection.setSoTimeout((int) WAIT_MS);
                    StringBuilder held = new StringBuilder();
                    byte[] buffer = new byte[65536];
                    while (held.indexOf("\r\n\r\n") < 0) {
                        int read = connection.getInputStream().read(buffer);
                        if (read < 0) {
                            break;
                        }
                        held.append(new String(buffer, 0, read, StandardCharsets.UTF_8));
                    }
                    return held.toString();
                } catch (Exception failed) {
                    throw new IllegalStateException(failed);
                }
            });
            SipralAccount account = SipralJava.addAccount(
                client, "sip:alice@example.invalid", address, "sip:example.invalid", null, null, SipralTransport.TCP);
            assertSame(SipralTransport.TCP, account.getStreamProtocol());
            account.register();
            String message = register.get(WAIT_MS, TimeUnit.MILLISECONDS);
            assertTrue(message.startsWith("REGISTER "), message);
            assertTrue(message.contains("Via: SIP/2.0/TCP "), message);
            assertTrue(message.contains(";transport=tcp"), message);
        }
    }

    /** The realms an account names reach the library one per line from
     * Java: a realm with a comma of its own is one realm, and one with a
     * control byte is refused there. */
    @Test
    void theRealmsAnAccountNamesReachTheLibrary() throws Exception {
        try (SipralClient client = SipralJava.open("127.0.0.1")) {
            SipralJava.addAccount(client, "sip:alice@example.invalid", "127.0.0.1:5060", null, "alice", "open sesame",
                null, null, List.of("registrar.example", "sbc, inc."));
            SipralException refused = assertThrows(SipralException.class, () -> SipralJava.addAccount(
                client, "sip:bob@example.invalid", "127.0.0.1:5060", null, null, null, null, null,
                List.of("registrar.example", "sbc\texample")));
            assertSame(SipralStatus.INVALID_ARGUMENT, refused.getStatus());
        }
    }

    /** The rate a call's frames cross at, chosen from Java: at 24 kHz a
     * 20 ms frame is 480 samples whatever the codec and the call still
     * carries RTP both ways, a rate outside the four is refused and changes
     * nothing, and 0 is the codec's own again. */
    @Test
    void theApplicationChoosesTheRateOfItsFrames() throws Exception {
        try (SipralClient alice = SipralJava.open("127.0.0.1");
             SipralClient bob = SipralJava.open("127.0.0.1")) {
            SipralAccount fromAlice = SipralJava.addAccount(alice, "sip:alice@example.invalid", bob.getBindAddress());
            SipralJava.addAccount(bob, "sip:bob@example.invalid", alice.getBindAddress());
            SipralAwaited<SipralCall> placed = SipralJava.awaitNext(
                bob.getEvents(), EnumSet.of(SipralEventKind.INCOMING_CALL), WAIT_MS,
                () -> SipralJava.placeCall(alice, fromAlice, "sip:bob@example.invalid"));
            try (SipralCall callA = placed.getResult();
                 SipralCall callB = SipralJava.answerCall(bob, placed.getEvent())) {
                SipralJava.waitConfirmed(callA, WAIT_MS);
                SipralJava.waitConfirmed(callB, WAIT_MS);
                SipralMedia mediaA = until(() -> callA.getMedia());
                SipralMedia mediaB = until(() -> callB.getMedia());
                int codecRate = mediaB.getSampleRate();

                for (SipralMedia media : List.of(mediaA, mediaB)) {
                    media.setAppRate(24_000);
                    assertEquals(24_000, media.getSampleRate());
                    assertEquals(480, media.getFrameSamples());
                    assertEquals(24_000L, media.info().getSampleRate());
                }
                SipralException refused = assertThrows(SipralException.class, () -> mediaB.setAppRate(44_100));
                assertSame(SipralStatus.INVALID_ARGUMENT, refused.getStatus());
                assertEquals(480, mediaB.getFrameSamples());

                long before = mediaB.statistics().getPacketsReceived();
                short[] tone = new short[480 * 5];
                java.util.Arrays.fill(tone, (short) 4_096);
                mediaA.sendAudio(tone);
                until(() -> mediaB.statistics().getPacketsReceived() > before + 5 ? Boolean.TRUE : null);

                mediaB.setAppRate(0);
                assertEquals(codecRate, mediaB.getSampleRate());
            }
        }
    }

    /** The check the binding makes at load, asked from Java about other
     * versions than its own: within this major every minor up to the
     * library's own is served -- a binding the library is newer than --
     * and a later minor, another major or any 0.x is refused, naming the
     * caller's version. */
    @Test
    void theAbiCheckKeepsTheOneXRule() {
        SipralAbiVersion library = Sipral.INSTANCE.abiVersion();
        assertEquals(Sipral.ABI_VERSION_MAJOR, library.getMajor());
        assertTrue(library.getMinor() >= Sipral.ABI_VERSION_MINOR, "library minor " + library.getMinor());
        for (long minor = 0; minor <= library.getMinor(); minor++) {
            Sipral.INSTANCE.abiCheck(library.getMajor(), minor);
        }
        long[][] refusedVersions = {
            {library.getMajor(), library.getMinor() + 1},
            {library.getMajor() + 1, 0},
            {0, 36},
        };
        for (long[] version : refusedVersions) {
            SipralException refused = assertThrows(SipralException.class,
                () -> Sipral.INSTANCE.abiCheck(version[0], version[1]));
            assertSame(SipralStatus.UNSUPPORTED_VERSION, refused.getStatus());
            String named = version[0] + "." + version[1];
            assertTrue(refused.getMessage().contains(named), refused.getMessage());
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
