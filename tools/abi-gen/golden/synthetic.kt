// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// Printed from the declarations in crates/sipral-ffi by tools/abi-gen.
// Do not edit: `cargo run -p sipral-abi-gen` writes it again, and
// `scripts/check.sh` fails when what is committed is not what came out.

package org.sipral

/**
 * What a call across the boundary answered.
 *
 * Numbers already spent on features this build does not have:
 * - 9: video
 */
enum class SipralStatus(val value: Int) {
    /**
     * It worked.
     */
    OK(0),
    /**
     * Something handed in was not usable.
     */
    INVALID_ARGUMENT(1),
    /**
     * A panic was caught before it reached C.
     */
    PANIC(2),
    /**
     * A word three of the four languages will not take plain.
     */
    DEFAULT(3),
    ;

    companion object {
        fun of(value: Int): SipralStatus? = entries.firstOrNull { it.value == value }
    }
}

/**
 * On or off, where C has no bool worth relying on.
 */
enum class SipralToggle(val value: Int) {
    OFF(0),
    ON(1),
    ;

    companion object {
        fun of(value: Int): SipralToggle? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a stack has done since it was made.
 */
data class SipralCounters(
    val size: Long,
    /**
     * How many went out.
     */
    val requestsSent: Long,
    /**
     * The fraction lost, which crosses JNI as its own bits.
     */
    val loss: Float,
) {
    internal companion object {
        const val SLOTS: Int = 3

        fun of(slots: LongArray): SipralCounters = SipralCounters(
            slots[0],
            slots[1],
            Float.fromBits(slots[2].toInt()),
        )
    }
}

/**
 * What a stack is made with.
 *
 * Holds buffers of the caller's and the library only reads it, so it
 * crosses behind a `const` pointer as a struct going in.
 *
 * Built here and copied into the C struct by the JNI shim, which sets the
 * size member itself: a field left at its default is the zero the struct
 * would have held.
 */
class SipralStackConfig(
    /**
     * Called for every event, from inside the poll.
     */
    val eventListener: SipralEventListener? = null,
    /**
     * Where to listen, as UTF-8.
     */
    val bindAddress: String? = null,
    val echo: Long = 0,
)

/**
 * One thing that happened, as the callback is handed it.
 *
 * `payload` is not carried here. Which of its arms the library wrote is named
 * by another member, and nothing in the declarations says which value names
 * which arm, so this binding does not guess.
 */
class SipralEvent(
    val size: Long,
    /**
     * Which stack it came from.
     */
    val stack: Long,
    /**
     * Which of them, from SipralStatus.
     */
    val kind: Long,
    /**
     * The message behind it, or null. It is the library's, and
     * it lives as long as SipralStatus.OK is being reported
     * -- see sipral_stack_create for who owns what.
     */
    val message: ByteArray?,
)

/**
 * What the library calls when something happens.
 *
 * In Kotlin it is this interface, called on the thread that polls. The JNI
 * shim attaches that thread to the JVM for the length of the call when it
 * is not attached already. What a listener throws goes to that thread's
 * uncaught exception handler, and the poll carries on once the handler
 * returns. Android's default handler does not return: it ends the process.
 */
fun interface SipralEventListener {
    fun onEvent(event: SipralEvent)
}

/**
 * Every SipralEventListener a live handle was made with, under the key the JNI
 * shim hands back with each event. The native side holds no reference
 * to a listener at all: an event for a handle already destroyed finds
 * nothing here and goes nowhere.
 */
internal object SipralEventListeners {
    private val listening = HashMap<Long, SipralEventListener>()
    private val handles = HashMap<Long, Long>()
    private var last = 0L

    /** Keep a listener, and say what key the shim will hand it back under: zero for none. */
    fun register(listener: SipralEventListener?): Long {
        if (listener == null) {
            return 0
        }
        synchronized(this) {
            // the key crosses as a C pointer, which is 32 bits wide on half of Android
            check(last < Int.MAX_VALUE) { "every key a listener can be kept under has been handed out" }
            last += 1
            listening[last] = listener
            return last
        }
    }

    /** Tie a kept listener to the handle the call made, or let it go when the call failed. */
    fun made(key: Long, status: Int, handle: Long) {
        if (key == 0L) {
            return
        }
        synchronized(this) {
            if (status == SipralStatus.OK.value) {
                handles[handle] = key
            } else {
                listening.remove(key)
            }
        }
    }

    /** Let go of the listener a destroyed handle was made with. */
    fun gone(handle: Long) {
        synchronized(this) {
            val key = handles.remove(handle) ?: return
            listening.remove(key)
        }
    }

    /** Called by the JNI shim, once per event, on the thread that polls. */
    @JvmStatic
    fun deliver(key: Long, size: Long, stack: Long, kind: Long, message: ByteArray?) {
        val listener = synchronized(this) { listening[key] } ?: return
        try {
            listener.onEvent(SipralEvent(size, stack, kind, message))
        } catch (failure: Throwable) {
            val thread = Thread.currentThread()
            thread.uncaughtExceptionHandler.uncaughtException(thread, failure)
        }
    }
}

/**
 * What a call across the boundary answered, when it did not answer
 * OK. The message is the calling thread's last error, read before
 * anything else on this thread could replace it.
 */
class SipralException(val status: SipralStatus?, message: String) :
    RuntimeException(if (message.isEmpty()) status.toString() else "$status: $message")

/**
 * The ABI as JNI declares it. Every integer crosses as a Long, every
 * struct the library fills in comes back in a LongArray, and every
 * struct a caller builds crosses one field at a time, so nothing here
 * depends on a field offset that the two Android pointer widths would
 * disagree about.
 */
internal object SipralNative {
    init {
        System.loadLibrary("sipral_jni")
        agree(0, 8)
    }

    /**
     * Throw unless the library that loaded serves a binding printed
     * against major.minor. Called once, as this object is initialised,
     * with the version this file was printed from, so a package whose
     * native library came from another build fails here with both
     * versions named rather than in whichever call first disagrees.
     */
    fun agree(major: Long, minor: Long) {
        val status = sipral_abi_check(major, minor)
        if (status != SipralStatus.OK.value) {
            throw SipralException(SipralStatus.of(status), Sipral.lastErrorMessage())
        }
    }

    external fun sipral_abi_check(major: Long, minor: Long): Int
    external fun sipral_last_error_message(buffer: ByteArray, needed: LongArray): Int
    external fun sipral_status_name(code: Long): String?
    external fun sipral_stack_create(configEventCallback: Long, configBindAddress: ByteArray?, configEcho: Long, stack: LongArray): Int
    external fun sipral_stack_counters(stack: Long, counters: LongArray): Int
    external fun sipral_stack_send(stack: Long, message: ByteArray): Int
    external fun sipral_stack_describe(stack: Long, note: ByteArray): Int
    external fun sipral_stack_name(stack: Long, name: ByteArray, len: LongArray): Int
    external fun sipral_stack_codec_order(stack: Long, outCodecs: IntArray, count: LongArray): Int
    external fun sipral_call_playback(stack: Long, samples: ShortArray, written: LongArray): Int
    external fun sipral_call_capture(stack: Long, samples: ShortArray, packet: Long): Int
    external fun sipral_call_media_receive(stack: Long, data: ByteArray, arrival: LongArray): Int
    external fun sipral_stack_destroy(stack: Long): Int
}

/** Everything the library does, with the C conventions read off it. */
object Sipral {
    /**
     * The handle that names nothing.
     */
    const val HANDLE_NONE: Long = 0

    /**
     * The bit a hardware customer is told to check for.
     */
    const val FEATURE_OPUS: Long = 64

    /**
     * The longest message that crosses.
     */
    const val MESSAGE_BYTES: Long = 65535

    /**
     * Nothing built against another major works against this one.
     */
    const val ABI_VERSION_MAJOR: Long = 0

    /**
     * Raised by anything the header gains.
     */
    const val ABI_VERSION_MINOR: Long = 8

    /**
     * The calling thread's last error, or an empty string when it has
     * none. Read the way C reads it: ask for the length, then for the
     * bytes.
     */
    fun lastErrorMessage(): String {
        val needed = LongArray(1)
        SipralNative.sipral_last_error_message(ByteArray(0), needed)
        val room = needed[0].toInt()
        if (room <= 1) {
            return ""
        }
        val buffer = ByteArray(room)
        if (SipralNative.sipral_last_error_message(buffer, needed) != SipralStatus.OK.value) {
            return ""
        }
        val end = buffer.indexOf(0)
        return String(buffer, 0, if (end < 0) buffer.size else end, Charsets.UTF_8)
    }

    /** Turn a status into an exception, and nothing into nothing. */
    private fun check(status: Int) {
        if (status != SipralStatus.OK.value) {
            throw SipralException(SipralStatus.of(status), lastErrorMessage())
        }
    }

    /**
     * Whether this library can serve a binding generated against `major`.`minor`.
     */
    fun abiCheck(major: Long, minor: Long) {
        check(SipralNative.sipral_abi_check(major, minor))
    }

    /**
     * The name of one SipralStatus, for a log line.
     */
    fun statusName(code: Long): String? =
        SipralNative.sipral_status_name(code)

    /**
     * Make one.
     */
    fun stackCreate(config: SipralStackConfig): Long {
        val configBindAddress = config.bindAddress?.toByteArray(Charsets.UTF_8)
        val stackSlot = LongArray(1)
        val configEventCallback = SipralEventListeners.register(config.eventListener)
        var status = -1
        try {
            status = SipralNative.sipral_stack_create(configEventCallback, configBindAddress, config.echo, stackSlot)
        } finally {
            SipralEventListeners.made(configEventCallback, status, stackSlot[0])
        }
        check(status)
        return stackSlot[0]
    }

    /**
     * Read SipralCounters off it.
     */
    fun stackCounters(stack: Long): SipralCounters {
        val countersSlots = LongArray(SipralCounters.SLOTS)
        check(SipralNative.sipral_stack_counters(stack, countersSlots))
        return SipralCounters.of(countersSlots)
    }

    /**
     * Hand it bytes to send.
     */
    fun stackSend(stack: Long, message: ByteArray) {
        check(SipralNative.sipral_stack_send(stack, message))
    }

    /**
     * Hand it text, which crosses as UTF-8 and not as a String.
     */
    fun stackDescribe(stack: Long, note: String) {
        val noteBytes = note.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_stack_describe(stack, noteBytes))
    }

    /**
     * Fill a buffer the caller brings.
     */
    fun stackName(stack: Long, name: ByteArray): Long {
        val lenSlot = LongArray(1)
        check(SipralNative.sipral_stack_name(stack, name, lenSlot))
        return lenSlot[0]
    }

    /**
     * Fill a buffer of numbers the caller brings.
     */
    fun stackCodecOrder(stack: Long, outCodecs: IntArray): Long {
        val countSlot = LongArray(1)
        check(SipralNative.sipral_stack_codec_order(stack, outCodecs, countSlot))
        return countSlot[0]
    }

    /**
     * Fill a buffer of samples the caller brings.
     */
    fun callPlayback(stack: Long, samples: ShortArray): Long {
        val writtenSlot = LongArray(1)
        check(SipralNative.sipral_call_playback(stack, samples, writtenSlot))
        return writtenSlot[0]
    }

    /**
     * Hand it samples, and get one datagram back in the struct.
     */
    fun callCapture(stack: Long, samples: ShortArray, packet: Long) {
        check(SipralNative.sipral_call_capture(stack, samples, packet))
    }

    /**
     * Hand it a datagram that arrived, in a buffer it may rewrite in
     * place, and hear what became of it.
     */
    fun callMediaReceive(stack: Long, data: ByteArray): Long {
        val arrivalSlot = LongArray(1)
        check(SipralNative.sipral_call_media_receive(stack, data, arrivalSlot))
        return arrivalSlot[0]
    }

    /**
     * Take it apart.
     */
    fun stackDestroy(stack: Long) {
        val status = SipralNative.sipral_stack_destroy(stack)
        SipralEventListeners.gone(stack)
        check(status)
    }

}
