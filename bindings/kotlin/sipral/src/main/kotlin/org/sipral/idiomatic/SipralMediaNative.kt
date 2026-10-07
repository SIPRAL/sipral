// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Hand-written, beside idiomatic_media.c: entry points for the structs a
// caller part-fills with buffers, which SipralAbi.kt cannot build
// (bindings/kotlin/README.md). They live in the same "sipral_jni" library
// as the generated shim, so no second System.loadLibrary is needed.

package org.sipral.idiomatic

/**
 * ABI calls taking a `sipral_media_packet_t *` (or
 * `sipral_path_candidate_t *`), which the generator cannot build from
 * Kotlin (docs/08-ffi.md). Internal: [SipralMedia] is the only caller and
 * owns correctly sized buffers.
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
     * calls, with what the far ends sent written into `local`. Each packet is
     * filled like [mediaCapture]'s: `outDataA`, `outDestinationA`, `outLenA`
     * for `mediaA`, the `B` three for `mediaB`.
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
     * `sipral_media_path_candidate_at`: `outLocal` and `outRemote` are filled
     * in place; `outNumbers` comes back as `[priority, kind, outcome, code,
     * local_kind, remote_kind, local_len, remote_len]`.
     */
    external fun mediaPathCandidateAt(
        media: Long,
        index: Long,
        outLocal: ByteArray,
        outRemote: ByteArray,
        outNumbers: LongArray,
    ): Int
}
