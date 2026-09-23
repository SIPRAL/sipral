// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// Hand-written, beside bindings/kotlin/sipral/src/main/jni/idiomatic_media.c:
// what SipralAbi.kt cannot print for sipral_media_packet_t, the struct a
// caller "part-fills with buffers" that a caller here has no way to build
// (bindings/kotlin/README.md). The four entry points this exposes are
// declared in the same native library the generated shim loads --
// "sipral_jni" -- built from both C files together, so nothing here asks
// for a second System.loadLibrary the way the generated one already does
// not.

package org.sipral.idiomatic

/**
 * The four ABI calls SipralAbi.kt cannot print a usable signature for,
 * because each takes a `sipral_media_packet_t *` and the generator has no
 * way to build one from Kotlin (docs/08-ffi.md, "The conventions are
 * load-bearing now"; bindings/kotlin/README.md names the gap). Package-
 * private: [SipralMedia] is the only caller, and it is the one place that
 * owns buffers the right size to hand these.
 */
internal object SipralMediaNative {
    init {
        System.loadLibrary("sipral_jni")
    }

    /**
     * `sipral_media_capture`. `outData` and `outDestination` are filled in
     * place; `outLen` comes back as `[len, destination_len]`.
     */
    external fun mediaCapture(
        media: Long,
        nowMs: Long,
        samples: ShortArray,
        outData: ByteArray,
        outDestination: ByteArray?,
        outLen: LongArray,
    ): Int

    /** `sipral_media_poll_rtcp`, filled the same way. */
    external fun mediaPollRtcp(
        media: Long,
        nowMs: Long,
        outData: ByteArray,
        outDestination: ByteArray?,
        outLen: LongArray,
    ): Int

    /** `sipral_media_poll_transmit`, filled the same way. */
    external fun mediaPollTransmit(
        media: Long,
        nowMs: Long,
        outData: ByteArray,
        outDestination: ByteArray?,
        outLen: LongArray,
    ): Int

    /**
     * `sipral_stack_poll_farewell`. `outCall` comes back as the one call
     * handle the goodbye belonged to, or `SIPRAL_HANDLE_NONE`.
     */
    external fun stackPollFarewell(
        stack: Long,
        outData: ByteArray,
        outDestination: ByteArray?,
        outLen: LongArray,
        outCall: LongArray,
    ): Int
}
