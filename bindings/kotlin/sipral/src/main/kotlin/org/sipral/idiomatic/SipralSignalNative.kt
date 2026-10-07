// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Hand-written, beside idiomatic_media.c (see SipralMediaNative.kt):
// sipral_transmit_t is the other struct SipralAbi.kt cannot build;
// `stackPollTransmit(stack: Long, transmit: Long)` takes a bare address.

package org.sipral.idiomatic

/** Signalling-side calls the generated binding cannot express; internal
 * to [SipralClient], the only caller. */
internal object SipralSignalNative {
    init {
        System.loadLibrary("sipral_jni")
    }

    /**
     * `sipral_stack_poll_transmit` without a source address: the caller's
     * socket sends from wherever the platform routes, right for one transport
     * without a wildcard bind. `outLen` comes back as `[len,
     * destination_len, protocol]`.
     */
    external fun stackPollTransmit(
        stack: Long,
        outData: ByteArray,
        outDestination: ByteArray,
        outLen: LongArray,
    ): Int

    /**
     * `sipral_stack_poll_stun`, with the source: the media socket the
     * request must leave from. `outLen` comes back as
     * `[len, destination_len, source_len]`.
     */
    external fun stackPollStun(
        stack: Long,
        outData: ByteArray,
        outDestination: ByteArray,
        outSource: ByteArray,
        outLen: LongArray,
    ): Int

    /**
     * `sipral_stack_transport_bind` for the main transport at [local], with no
     * remote. Only a null pointer says "none"; the generated
     * `stackTransportBind` passes an empty array as a real pointer, which the
     * stack refuses as an address.
     */
    external fun stackTransportRebind(stack: Long, local: ByteArray, nowMs: Long): Int
}
