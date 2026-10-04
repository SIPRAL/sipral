// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Hand-written, beside bindings/kotlin/sipral/src/main/jni/idiomatic_media.c
// -- see SipralMediaNative.kt's own note. sipral_transmit_t is the other
// struct SipralAbi.kt cannot build from Kotlin: sipral_stack_poll_transmit
// is printed as `stackPollTransmit(stack: Long, transmit: Long)`, a native
// address with nothing generated to construct one.

package org.sipral.idiomatic

/**
 * What SipralAbi.kt cannot print a usable signature for on the signalling
 * side, package-private to [SipralClient], the only caller.
 */
internal object SipralSignalNative {
    init {
        System.loadLibrary("sipral_jni")
    }

    /**
     * `sipral_stack_poll_transmit`, with no source address: the caller's own
     * socket answers from wherever the platform routes it, which is exactly
     * right for a stack with one transport and no wildcard bind. `outLen`
     * comes back as `[len, destination_len, protocol]`.
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
     * `sipral_stack_transport_bind` for the main transport, at [local], with
     * no remote: a datagram transport has none, and only a null pointer says
     * so -- the generated `stackTransportBind` hands an empty array over as a
     * real one, which the stack refuses as an address.
     */
    external fun stackTransportRebind(stack: Long, local: ByteArray, nowMs: Long): Int
}
