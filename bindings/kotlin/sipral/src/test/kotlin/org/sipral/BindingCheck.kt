// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// What a Kotlin integrator does on the first afternoon, compiled and run by
// scripts/check.sh against the shared library: load the binding and have it
// check the ABI, build a stack out of a class, hear its first event on a
// thread the JVM did not make, hear a poll's worth of incoming calls without
// the shim holding on to what it handed over for any of them, throw from a
// listener, and destroy a stack from inside its own listener.
//
// A program rather than a test runner's test, because the gate has a compiler
// and a JVM and no build tool; kotlin.test's assertions throw without one.

package org.sipral

import java.lang.ref.WeakReference
import java.security.SecureRandom
import kotlin.system.exitProcess
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Polls a stack on a thread of its own making, which no JVM has seen. */
internal object NativeThread {
    init {
        System.loadLibrary("sipral_jni_check")
    }

    external fun poll(stack: Long, nowMs: Long): Int
}

private const val BOUND = "192.0.2.10:5060"
private const val REGISTRAR = "203.0.113.5:5060"

/**
 * Where call `index` comes from: a caller of its own each time, because the
 * user agent limits how fast any one address may dial, and a poll's worth of
 * calls from one address is a scanner rather than a busy morning.
 */
private fun caller(index: Int): String = "198.51.100.${index + 1}:5060"

/** Read, not written down, for the reason bindings/c/smoke.c gives. */
private fun drawn(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

private fun configured(listener: SipralEventListener?) = SipralStackConfig(
    eventListener = listener,
    transport = SipralTransport.UDP.value.toLong(),
    bindAddress = BOUND,
    entropy = drawn(),
    mediaSeed = drawn(),
)

/** An INVITE from somebody else, addressed here, a different call each time. */
private fun invitation(index: Int): ByteArray =
    (
        "INVITE sip:alice@$BOUND SIP/2.0\r\n" +
            "Via: SIP/2.0/UDP ${caller(index)};branch=z9hG4bK-kotlin-$index\r\n" +
            "Max-Forwards: 70\r\n" +
            "From: <sip:caller$index@example.com>;tag=far-$index\r\n" +
            "To: <sip:alice@example.com>\r\n" +
            "Call-ID: kotlin-$index@example.com\r\n" +
            "CSeq: 1 INVITE\r\n" +
            "Contact: <sip:caller$index@${caller(index)}>\r\n" +
            "Content-Length: 0\r\n\r\n"
        ).toByteArray(Charsets.US_ASCII)

/**
 * What a listener heard, kept without holding on to anything it was handed:
 * a message held here would keep its array alive, and the one thing this
 * check wants to know about those arrays is whether the shim did.
 */
private class Heard : SipralEventListener {
    val kinds = mutableListOf<Long>()
    val stacks = mutableListOf<Long>()
    val sizes = mutableListOf<Long>()
    val threads = mutableListOf<Thread>()
    val openings = mutableListOf<String>()

    /** How many events arrived while the message before them was traceable. */
    var looked = 0

    /** And how many of those found it still reachable. */
    var survived = 0

    private var previous: WeakReference<ByteArray>? = null

    override fun onEvent(event: SipralEvent) {
        kinds.add(event.kind)
        stacks.add(event.stack)
        sizes.add(event.size)
        threads.add(Thread.currentThread())
        val message = event.message
        openings.add(message?.let { String(it, 0, minOf(it.size, 6), Charsets.US_ASCII) } ?: "")
        // A local reference the shim did not delete for the event before
        // keeps that event's array reachable until the poll returns; nothing
        // in Kotlin holds one. So after a collection the weak reference is
        // empty exactly when the shim let go.
        val before = previous
        if (before != null) {
            System.gc()
            looked += 1
            if (before.get() != null) {
                survived += 1
            }
        }
        previous = message?.let { WeakReference(it) }
    }
}

fun main() {
    val said = try {
        everything()
    } catch (failure: Throwable) {
        failure.printStackTrace()
        exitProcess(1)
    }
    println("kotlin binding: $said")
    // exitProcess rather than returning: a native thread the shim attached and
    // never detached is a live non-daemon thread, and a JVM that waited for it
    // would never exit
    exitProcess(0)
}

private fun everything(): String {
    // Touching SipralNative ran its check against the version it was printed
    // from, or this line would be an ExceptionInInitializerError. The same
    // check asked about a minor this library does not have says so, with
    // both versions named.
    val newer = Sipral.ABI_VERSION_MINOR + 1
    val refused = assertFailsWith<SipralException> {
        SipralNative.agree(Sipral.ABI_VERSION_MAJOR, newer)
    }
    assertEquals(SipralStatus.UNSUPPORTED_VERSION, refused.status)
    val sentence = assertNotNull(refused.message)
    assertTrue(sentence.contains("${Sipral.ABI_VERSION_MAJOR}.$newer"), sentence)

    // A stack built out of a class. The bind address is text and the two
    // seeds are arrays, so a member copied wrong is a refusal here.
    val heard = Heard()
    val stack = Sipral.stackCreate(configured(heard))
    assertNotEquals(Sipral.HANDLE_NONE, stack)

    // Its first event, on a thread no JVM made.
    assertEquals(SipralStatus.OK.value, NativeThread.poll(stack, 0))
    assertTrue(heard.kinds.isNotEmpty(), "the first poll delivered nothing to the listener")
    assertEquals(SipralEventKind.STARTED.value.toLong(), heard.kinds.first())
    assertEquals(stack, heard.stacks.first())
    assertTrue(heard.sizes.first() > 0, "an event that says it is zero bytes long")
    val foreign = heard.threads.first()
    assertNotEquals(Thread.currentThread(), foreign, "the event arrived on the thread that polled from Kotlin")
    // a thread still attached is a live java.lang.Thread, and the native one
    // has been joined, so this is false only if the shim detached it
    assertFalse(foreign.isAlive, "the thread the shim attached is attached still")

    // A poll's worth of events that each carry a message.
    Sipral.accountAdd(
        stack,
        SipralAccountConfig(
            aor = "sip:alice@example.com",
            registrar = "sip:example.com",
            contact = "sip:alice@$BOUND",
            registrarAddress = REGISTRAR,
        ),
    )
    val calls = 24
    for (index in 0 until calls) {
        Sipral.stackReceiveDatagram(stack, Sipral.TRANSPORT_MAIN, invitation(index), caller(index), BOUND, 10)
    }
    val already = heard.kinds.size
    val polled = Sipral.stackPoll(stack, 20)
    val arrived = heard.kinds.size - already
    assertEquals(polled.eventsDelivered, arrived.toLong(), "the poll and the listener disagree on how many events there were")
    val incoming = (already until heard.kinds.size).filter {
        heard.kinds[it] == SipralEventKind.INCOMING_CALL.value.toLong()
    }
    assertEquals(calls, incoming.size, "$calls INVITEs went in and ${incoming.size} incoming calls came out")
    for (index in incoming) {
        assertEquals("INVITE", heard.openings[index], "an incoming call handed over a message that is not its INVITE")
        assertEquals(Thread.currentThread(), heard.threads[index])
    }
    // a check that looked at nothing has not checked
    assertTrue(heard.looked >= calls - 1, "only ${heard.looked} messages were looked for after their event")
    assertEquals(0, heard.survived, "${heard.survived} messages were still held by the shim when the next event arrived")

    // A listener that throws hands its exception to the thread's handler and
    // does not stop the poll; destroying the stack from inside it is the one
    // call the contract allows there, and the handle is stale afterwards.
    val caught = mutableListOf<Throwable>()
    val here = Thread.currentThread()
    val handler = here.uncaughtExceptionHandler
    here.uncaughtExceptionHandler = Thread.UncaughtExceptionHandler { _, failure -> caught.add(failure) }
    val doomed = Sipral.stackCreate(
        configured(
            SipralEventListener { event ->
                Sipral.stackDestroy(event.stack)
                throw IllegalStateException("thrown from inside a listener")
            },
        ),
    )
    try {
        Sipral.stackPoll(doomed, 0)
    } finally {
        here.uncaughtExceptionHandler = handler
    }
    assertEquals(1, caught.size, "a listener that threw once was reported ${caught.size} times")
    assertEquals("thrown from inside a listener", caught.single().message)
    val stale = assertFailsWith<SipralException> { Sipral.stackPoll(doomed, 1) }
    assertEquals(SipralStatus.STALE_HANDLE, stale.status)

    // What a class leaves out is what a zeroed C struct leaves out, and is
    // refused the same way: no listener is no callback.
    val deaf = assertFailsWith<SipralException> { Sipral.stackCreate(configured(null)) }
    assertEquals(SipralStatus.INVALID_ARGUMENT, deaf.status)
    // and the two arrays arrive as the bytes they are: the same draw twice is
    // the one thing only sipral_stack_create can see
    val once = drawn()
    val twice = assertFailsWith<SipralException> {
        Sipral.stackCreate(
            SipralStackConfig(
                eventListener = SipralEventListener { },
                transport = SipralTransport.UDP.value.toLong(),
                bindAddress = BOUND,
                entropy = once,
                mediaSeed = once.copyOf(),
            ),
        )
    }
    assertTrue(assertNotNull(twice.message).contains("media_seed"), twice.message)

    Sipral.stackDestroy(stack)
    return "a stack built from a class, ${heard.kinds.size} events heard, the first on a thread " +
        "the shim attached and let go of, $calls messages none of which it held past its event"
}
