// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// What a Kotlin integrator does on the first afternoon, compiled and run by
// scripts/check.sh against the shared library: load the binding and have it
// check the ABI, build a stack out of a class, hear its first event on a
// thread the JVM did not make, hear a poll's worth of incoming calls without
// the shim holding on to what it handed over for any of them, put header
// fields of its own on a call in a list and find them in what went out, throw
// from a listener, and destroy a stack from inside its own listener.
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

    /** The next datagram a stack wants sent, or null when it wants none sent. */
    external fun transmitted(stack: Long): ByteArray?
}

private const val BOUND = "192.0.2.10:5060"
private const val REGISTRAR = "203.0.113.5:5060"

/** A description to place a call with. */
private const val OFFER =
    "v=0\r\n" +
        "o=alice 1 1 IN IP4 192.0.2.10\r\n" +
        "s=-\r\n" +
        "c=IN IP4 192.0.2.10\r\n" +
        "t=0 0\r\n" +
        "m=audio 41000 RTP/AVP 0\r\n" +
        "a=rtpmap:0 PCMU/8000\r\n" +
        "a=sendrecv\r\n"

/** Everything a stack wants sent, in the order it wants it sent. */
private fun drained(stack: Long): List<ByteArray> {
    val out = mutableListOf<ByteArray>()
    while (true) {
        out.add(NativeThread.transmitted(stack) ?: return out)
    }
}

/** Whether a message starts with the text given. */
private fun opens(message: ByteArray, opening: String): Boolean =
    String(message, 0, minOf(message.size, opening.length), Charsets.US_ASCII) == opening

/** The first line of a header field, read out of a message through the binding. */
private fun fieldIn(message: ByteArray, name: String): String? {
    if (Sipral.messageHeaderCount(message, name) == 0L) {
        return null
    }
    val (offset, len) = Sipral.messageHeader(message, name, 0)
    return String(message, offset.toInt(), len.toInt(), Charsets.UTF_8)
}

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
    val calls = mutableListOf<Long>()
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
        calls.add(event.call)
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
    // check asked about other versions keeps the 1.x rule: within this
    // major every minor up to the library's own is served -- a binding the
    // library is newer than -- and a later minor, another major or any 0.x
    // is refused with the caller's version named.
    val library = Sipral.abiVersion()
    assertEquals(Sipral.ABI_VERSION_MAJOR, library.major)
    assertTrue(library.minor >= Sipral.ABI_VERSION_MINOR, "library minor ${library.minor}")
    for (minor in 0L..library.minor) {
        SipralNative.agree(library.major, minor)
    }
    for ((major, minor) in listOf(library.major to library.minor + 1, library.major + 1 to 0L, 0L to 36L)) {
        val refused = assertFailsWith<SipralException>("$major.$minor was served") {
            SipralNative.agree(major, minor)
        }
        assertEquals(SipralStatus.UNSUPPORTED_VERSION, refused.status)
        val sentence = assertNotNull(refused.message)
        assertTrue(sentence.contains("$major.$minor"), sentence)
    }

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
    val account = Sipral.accountAdd(
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

    // Header fields of the application's own, handed over in a list: two on
    // a call's configuration, found in the INVITE it went out in, and two set
    // on a call that came in, found in the refusal it went out on. Two rather
    // than one, because one is what a binding that hands over a single struct
    // also gets right.
    drained(stack)
    val placed = Sipral.callPlace(
        stack,
        account,
        SipralCallConfig(
            target = "sip:bob@example.com",
            sdp = OFFER.toByteArray(Charsets.US_ASCII),
            headers = listOf(
                SipralHeader("X-Conversation-Id", "kotlin-placed"),
                SipralHeader("X-Second-Field", "the second of two"),
            ),
        ),
        30,
    )
    assertNotEquals(Sipral.HANDLE_NONE, placed)
    val invite = assertNotNull(
        drained(stack).firstOrNull { opens(it, "INVITE ") },
        "no INVITE went out for the call placed with header fields",
    )
    assertEquals("kotlin-placed", fieldIn(invite, "X-Conversation-Id"))
    assertEquals("the second of two", fieldIn(invite, "X-Second-Field"))

    val ringing = heard.calls[incoming.first()]
    // The second element is where a binding that read one struct would have
    // read past it, so it is the one the stack is made to refuse by name.
    val owned = assertFailsWith<SipralException> {
        Sipral.callSetHeaders(
            stack,
            ringing,
            listOf(
                SipralHeader("X-Conversation-Id", "kotlin-refused"),
                SipralHeader("Call-ID", "somebody-elses@example.net"),
            ),
        )
    }
    assertEquals(SipralStatus.INVALID_ARGUMENT, owned.status)
    assertTrue(assertNotNull(owned.message).contains("headers[1]"), owned.message)
    Sipral.callSetHeaders(
        stack,
        ringing,
        listOf(
            SipralHeader("X-Conversation-Id", "kotlin-refusal"),
            SipralHeader("X-Second-Field", "on the refusal"),
        ),
    )

    // What the shim is handed is what SipralHeader.packed makes, and it checks
    // it anyway, before it points into any of it. None of these reaches the
    // library, which the refusal below shows by carrying the fields set above.
    val text = "X-Conversation-Id".toByteArray(Charsets.US_ASCII)
    val whole = text.size.toLong()
    for ((what, bytes, lengths) in listOf(
        Triple("a value one byte past the end", text, longArrayOf(whole, 1)),
        Triple("a value as long as a Long can say", text, longArrayOf(whole, Long.MAX_VALUE)),
        Triple("a negative name", text, longArrayOf(-1, whole + 1)),
        Triple("a length that is half an element", text, longArrayOf(whole)),
        Triple("bytes no length accounts for", text, longArrayOf(1, 1)),
        Triple("lengths with no bytes behind them", null, longArrayOf(whole, 0)),
        Triple("bytes with no lengths at all", text, longArrayOf()),
        Triple("bytes with no array of lengths", text, null),
    )) {
        assertFailsWith<IllegalArgumentException>(what) {
            SipralNative.sipral_call_set_headers(stack, ringing, bytes, lengths)
        }
    }

    drained(stack)
    Sipral.callReject(stack, ringing, 486, 40)
    val refusal = assertNotNull(
        drained(stack).firstOrNull { opens(it, "SIP/2.0 486") },
        "no 486 went out for the call refused with header fields",
    )
    assertEquals("kotlin-refusal", fieldIn(refusal, "X-Conversation-Id"))
    assertEquals("on the refusal", fieldIn(refusal, "X-Second-Field"))

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

    // A string the binding hands over empty is a real pointer and a length
    // of zero, which is how C says the address a datagram arrived on is
    // left out: it was refused as an address that was empty.
    Sipral.stackReceiveDatagram(stack, Sipral.TRANSPORT_MAIN, invitation(calls), caller(calls), "", 30)

    Sipral.stackDestroy(stack)
    val layouts = layoutsHold()
    return "a stack built from a class, ${heard.kinds.size} events heard, the first on a thread " +
        "the shim attached and let go of, $calls messages none of which it held past its event, " +
        "two header fields in a list on a call placed and two on a call refused, " +
        "$layouts records as long as the layout says"
}

/**
 * Every record's length on the layout this JVM runs on, as tools/abi-gen
 * worked it out, against the library's own answer: this binding lays nothing
 * out itself, and bindings/c/abi-layout.c holds a C compiler to the same
 * table on the layouts this machine cannot run.
 */
private fun layoutsHold(): Int {
    val wide = System.getProperty("sun.arch.data.model") != "32"
    val arch = System.getProperty("os.arch").lowercase()
    val windows = System.getProperty("os.name").lowercase().startsWith("windows")
    // 32-bit x86 aligns a 64-bit integer to four inside a struct on every
    // system but Windows, which aligns it to eight like ARM does
    val column = when {
        wide -> 0
        arch in setOf("x86", "i386", "i686") && !windows -> 1
        else -> 2
    }
    assertTrue(Sipral.recordLayouts.size > 50, "${Sipral.recordLayouts.size} records")
    for ((name, lengths) in Sipral.recordLayouts) {
        assertEquals(lengths[column].toLong(), Sipral.abiStructSize(name), name)
    }
    return Sipral.recordLayouts.size
}
