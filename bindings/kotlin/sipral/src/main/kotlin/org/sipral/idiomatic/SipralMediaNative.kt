// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
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
 * The ABI calls SipralAbi.kt cannot print a usable signature for, because
 * each takes a `sipral_media_packet_t *` (or, for the last, a
 * `sipral_path_candidate_t *`) and the generator has no way to build one
 * from Kotlin (docs/08-ffi.md, "The conventions are
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

    /**
     * `sipral_media_mix`: one frame of `mic` mixed into each of two joined
     * calls, with what the far ends sent written into `local`. Each call's
     * packet is filled the way [mediaCapture] fills one: `outDataA`,
     * `outDestinationA` and `outLenA` for `mediaA`, the `B` three for
     * `mediaB`. The generated binding hands the two packets over as bare
     * addresses and has no way to build either, so this is the only way to
     * reach the call from Kotlin.
     */
    external fun mediaMix(
        mediaA: Long,
        mediaB: Long,
        nowMs: Long,
        mic: ShortArray,
        local: ShortArray,
        outDataA: ByteArray,
        outDestinationA: ByteArray?,
        outLenA: LongArray,
        outDataB: ByteArray,
        outDestinationB: ByteArray?,
        outLenB: LongArray,
    ): Int

    /** `sipral_media_poll_rtcp`, filled the same way. */
    external fun mediaPollRtcp(
        media: Long,
        nowMs: Long,
        outData: ByteArray,
        outDestination: ByteArray?,
        outLen: LongArray,
    ): Int

    /**
     * `sipral_local_conference_poll_transmit`, filled the same way; `outCall`
     * comes back as the member call the packet belongs to, or
     * `SIPRAL_HANDLE_NONE` when nothing was waiting.
     */
    external fun localConferencePollTransmit(
        conference: Long,
        outData: ByteArray,
        outDestination: ByteArray?,
        outLen: LongArray,
        outCall: LongArray,
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

    /** `sipral_media_poll_text`: the next datagram due on the call's
     * real-time text socket, filled the same way as [mediaPollRtcp]. */
    external fun mediaPollText(
        media: Long,
        nowMs: Long,
        outData: ByteArray,
        outDestination: ByteArray?,
        outLen: LongArray,
    ): Int

    /** `sipral_media_poll_recording`: the next copy for the recording
     * server, filled the same way; `outFarEnd` comes back as 0 for a copy
     * of this end's audio and 1 for the far end's. */
    external fun mediaPollRecording(
        media: Long,
        outData: ByteArray,
        outDestination: ByteArray?,
        outLen: LongArray,
        outFarEnd: LongArray,
    ): Int

    /**
     * `sipral_media_path_candidate_at`, whose `sipral_path_candidate_t` a
     * caller part-fills with two address buffers the same way. `outLocal`
     * and `outRemote` are filled in place; `outNumbers` comes back as
     * `[priority, kind, outcome, code, local_kind, remote_kind, local_len,
     * remote_len]`.
     */
    external fun mediaPathCandidateAt(
        media: Long,
        index: Long,
        outLocal: ByteArray,
        outRemote: ByteArray,
        outNumbers: LongArray,
    ): Int
}
