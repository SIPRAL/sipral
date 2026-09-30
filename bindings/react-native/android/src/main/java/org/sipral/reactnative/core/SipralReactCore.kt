// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// Everything the React Native module does, with nothing of React Native in
// it: one SipralClient from org.sipral.idiomatic, its accounts and calls
// kept by the handle JavaScript names them with, and every event flattened
// into the map the codegen spec's NativeEvent describes. SipralModule is
// the few lines that hand this to the bridge; scripts/check.sh compiles
// this file with the Kotlin layer and runs it on a JVM, over two real
// stacks, without any of React Native.

package org.sipral.reactnative.core

import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.sipral.Sipral
import org.sipral.SipralAudioActivation
import org.sipral.SipralAudioDirection
import org.sipral.SipralCallEndReason
import org.sipral.SipralCallState
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralRegistrationState
import org.sipral.SipralTransport
import org.sipral.idiomatic.SipralAccount
import org.sipral.idiomatic.SipralAudioMode
import org.sipral.idiomatic.SipralCall
import org.sipral.idiomatic.SipralClient
import org.sipral.idiomatic.digitOf
import org.sipral.idiomatic.transferOf

/** A refusal JavaScript receives as `SipralError.code`: a status's name, or one of this layer's. */
class SipralRefusal(val code: String, message: String) : Exception(message)

/** What `open` takes, the fields of the spec's NativeOpenOptions. */
data class SipralOpenOptions(
    val bindHost: String,
    val bindPort: Int = 0,
    val userAgent: String? = null,
    val codecs: String? = null,
    val signalling: String = "udp",
    val signallingServer: String? = null,
    val stunServer: String? = null,
    val manualAudio: Boolean = false,
)

/** What `addAccount` takes, the fields of NativeAccountOptions. */
data class SipralAccountOptions(
    val aor: String,
    val registrarAddress: String,
    val registrar: String? = null,
    val contact: String? = null,
    val displayName: String? = null,
    val authUser: String? = null,
    val authPassword: String? = null,
    val expiresSeconds: Long = 0,
)

/**
 * One client and what hangs off it. [emit] is called with each event,
 * flattened, on the thread that collects the client's events.
 *
 * [audio] decides who runs the calls' audio: [SipralReactCore.deviceAudio]
 * on a phone, `SipralAudioMode.Application` in a test that has no devices.
 */
class SipralReactCore(
    private val emit: (Map<String, Any>) -> Unit,
    private val audio: (manual: Boolean) -> SipralAudioMode = ::deviceAudio,
) {
    private var client: SipralClient? = null
    private var scope: CoroutineScope? = null
    private var mediaHost = "127.0.0.1"
    private val accounts = ConcurrentHashMap<String, SipralAccount>()
    private val calls = ConcurrentHashMap<String, SipralCall>()
    private val arrived = ConcurrentHashMap<String, SipralEvent>()
    private val transfers = ConcurrentHashMap<String, SipralEvent>()

    /** Open the client; the address it signals from comes back. */
    @Synchronized
    fun open(options: SipralOpenOptions): String = guarded {
        if (client != null) {
            throw SipralRefusal("wrongState", "a client is already open; close it first")
        }
        val signalling = when (options.signalling) {
            "udp" -> SipralTransport.UDP
            "tcp" -> SipralTransport.TCP
            "tls" -> SipralTransport.TLS
            else -> throw SipralRefusal("invalidArgument", "signalling is udp, tcp or tls, not ${options.signalling}")
        }
        val opened = SipralClient.open(
            bindHost = options.bindHost,
            bindPort = options.bindPort,
            userAgent = options.userAgent,
            codecs = options.codecs,
            stunServer = options.stunServer,
            audio = audio(options.manualAudio),
            signalling = signalling,
            signallingServer = options.signallingServer,
        )
        val collecting = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        collecting.launch(start = CoroutineStart.UNDISPATCHED) {
            opened.events.collect { event -> deliver(event) }
        }
        client = opened
        scope = collecting
        mediaHost = options.bindHost
        opened.bindAddress
    }

    @Synchronized
    fun close() {
        val closing = client ?: return
        client = null
        scope?.cancel()
        scope = null
        calls.values.forEach { it.close() }
        calls.clear()
        accounts.clear()
        arrived.clear()
        transfers.clear()
        closing.close()
    }

    fun addAccount(options: SipralAccountOptions): String = guarded {
        val account = open().addAccount(
            aor = options.aor,
            registrarAddress = options.registrarAddress,
            registrar = options.registrar,
            contact = options.contact,
            displayName = options.displayName,
            authUser = options.authUser,
            authPassword = options.authPassword,
            expiresSeconds = options.expiresSeconds,
        )
        val id = account.handle.toString()
        accounts[id] = account
        id
    }

    fun register(account: String) = guarded { accountOf(account).register() }

    fun unregister(account: String) = guarded { accountOf(account).unregister() }

    fun removeAccount(account: String) = guarded {
        accountOf(account).remove()
        accounts.remove(account)
        Unit
    }

    fun placeCall(account: String, target: String, destination: String?, codecs: String?): String = guarded {
        val call = open().placeCall(
            accountOf(account),
            target,
            mediaHost = mediaHost,
            destination = destination,
            codecs = codecs,
        )
        keep(call)
    }

    fun answer(call: String) = guarded {
        val event = arrived.remove(call)
            ?: throw SipralRefusal("wrongState", "call $call is not waiting to be answered")
        try {
            keep(open().answerCall(event, mediaHost = mediaHost))
        } catch (refused: Exception) {
            arrived[call] = event
            throw refused
        }
        Unit
    }

    fun reject(call: String, code: Int) = guarded {
        val event = arrived.remove(call)
            ?: throw SipralRefusal("wrongState", "call $call is not waiting to be answered")
        try {
            open().rejectCall(event, code.toLong())
        } catch (refused: Exception) {
            arrived[call] = event
            throw refused
        }
    }

    /** A call answered or placed is hung up; one still ringing here is turned away, 486. */
    fun hangup(call: String) = guarded {
        val kept = calls[call]
        if (kept != null) {
            kept.hangup()
        } else {
            val event = arrived.remove(call) ?: throw SipralRefusal("invalidHandle", "no call $call")
            open().rejectCall(event)
        }
    }

    fun hold(call: String) = guarded { callOf(call).hold() }

    fun resume(call: String) = guarded { callOf(call).resume() }

    fun transfer(call: String, target: String) = guarded { callOf(call).transfer(target) }

    /** Take the transfer the far end of [call] asked for; the call placed to its target comes back. */
    fun acceptTransfer(call: String): String = guarded {
        val event = transfers.remove(call)
            ?: throw SipralRefusal("wrongState", "the far end of call $call asked for no transfer")
        try {
            keep(open().acceptReferral(event, mediaHost = mediaHost))
        } catch (refused: Exception) {
            transfers[call] = event
            throw refused
        }
    }

    fun rejectTransfer(call: String, code: Int) = guarded {
        val event = transfers.remove(call)
            ?: throw SipralRefusal("wrongState", "the far end of call $call asked for no transfer")
        open().rejectReferral(event, code.toLong())
    }

    fun sendDtmf(call: String, digits: String) = guarded { callOf(call).sendDtmf(digits) }

    fun activateAudio() = guarded { devices().activate() }

    fun deactivateAudio() = guarded { devices().deactivate() }

    fun setMuted(muted: Boolean) = guarded { devices().setMuted(SipralAudioDirection.INPUT, muted) }

    private fun deliver(event: SipralEvent) {
        val id = event.call.toString()
        when (event.kind) {
            SipralEventKind.INCOMING_CALL.value.toLong() -> arrived[id] = event
            SipralEventKind.TRANSFER_REQUESTED.value.toLong() -> transfers[id] = event
            else -> {}
        }
        emit(flatten(event))
        if (event.kind == SipralEventKind.CALL_ENDED.value.toLong()) {
            arrived.remove(id)
            transfers.remove(id)
            calls.remove(id)?.close()
        }
    }

    private fun keep(call: SipralCall): String {
        val id = call.handle.toString()
        calls[id] = call
        return id
    }

    private fun open(): SipralClient = client ?: throw SipralRefusal("closed", "the client is not open")

    private fun accountOf(id: String): SipralAccount =
        accounts[id] ?: throw SipralRefusal("invalidHandle", "no account $id")

    private fun callOf(id: String): SipralCall =
        calls[id] ?: throw SipralRefusal("invalidHandle", "no call $id answered or placed")

    private fun devices() = open().audio
        ?: throw SipralRefusal("notSupported", "the library runs no audio devices on this client")

    companion object {
        /**
         * Device mode wherever the library has an engine for the phone --
         * Android from API level 28 -- and a refusal where it has none,
         * since nothing in JavaScript could carry a call's audio there.
         */
        fun deviceAudio(manual: Boolean): SipralAudioMode {
            if (SipralAudioMode.platformDefault !is SipralAudioMode.Device) {
                throw SipralRefusal("notSupported", "the library runs a phone's audio from Android 9 (API level 28)")
            }
            return SipralAudioMode.Device(if (manual) SipralAudioActivation.MANUAL else SipralAudioActivation.AUTOMATIC)
        }

        /** `SIPRAL_EVENT_KIND_CALL_ENDED` as "callEnded": a constant's name in lower camel case. */
        fun camel(name: String): String = name.lowercase().split('_').mapIndexed { at, word ->
            if (at == 0) word else word.replaceFirstChar { it.uppercase() }
        }.joinToString("")

        /**
         * [block], with what it threw turned into the refusal JavaScript
         * reads: a status by its name, anything else as the platform's.
         */
        fun <T> guarded(block: () -> T): T = try {
            block()
        } catch (refused: SipralRefusal) {
            throw refused
        } catch (failed: SipralException) {
            throw SipralRefusal(failed.status?.let { camel(it.name) } ?: "platform", failed.message ?: "")
        } catch (failed: IllegalArgumentException) {
            throw SipralRefusal("invalidArgument", failed.message ?: "")
        } catch (failed: Exception) {
            throw SipralRefusal("platform", failed.message ?: failed.toString())
        }

        private val callKinds = listOf(
            SipralEventKind.INCOMING_CALL, SipralEventKind.CALL_PROGRESS, SipralEventKind.CALL_FORKED,
            SipralEventKind.CALL_CONFIRMED, SipralEventKind.SESSION_CHANGED, SipralEventKind.SESSION_OFFERED,
            SipralEventKind.SESSION_CHANGE_FAILED, SipralEventKind.CALL_REPLACED, SipralEventKind.CALL_ENDED,
            SipralEventKind.DTMF_SENT, SipralEventKind.CALL_ADDRESS_WANTED,
        ).map { it.value.toLong() }.toSet()

        private val digitKinds = setOf(
            SipralEventKind.DIGIT_RECEIVED.value.toLong(),
            SipralEventKind.IN_BAND_DIGIT.value.toLong(),
        )

        private fun text(bytes: ByteArray?): String? = bytes?.toString(Charsets.UTF_8)

        /** One event as the spec's NativeEvent: the members its kind does not use are left out. */
        fun flatten(event: SipralEvent): Map<String, Any> {
            val kind = SipralEventKind.entries.firstOrNull { it.value.toLong() == event.kind }
            val flat = LinkedHashMap<String, Any>()
            flat["kind"] = kind?.let { camel(it.name) } ?: "unknown"
            flat["kindName"] = Sipral.eventKindName(event.kind) ?: "unknown"
            flat["account"] = if (event.account == 0L) "" else event.account.toString()
            flat["call"] = if (event.call == 0L) "" else event.call.toString()
            when {
                event.kind == SipralEventKind.REGISTRATION_CHANGED.value.toLong() -> {
                    val registration = event.payload.registration
                    SipralRegistrationState.entries.firstOrNull { it.value.toLong() == registration.state }
                        ?.let { flat["registrationState"] = camel(it.name) }
                    flat["statusCode"] = registration.statusCode.toInt()
                    flat["retryInMs"] = registration.retryInMs.toDouble()
                }
                event.kind in callKinds -> {
                    val call = event.payload.call
                    SipralCallState.entries.firstOrNull { it.value.toLong() == call.state }
                        ?.let { flat["callState"] = camel(it.name) }
                    SipralCallEndReason.entries.firstOrNull { it.value.toLong() == call.endReason }
                        ?.let { flat["endReason"] = camel(it.name) }
                    flat["statusCode"] = call.statusCode.toInt()
                    flat["retryInMs"] = call.retryInMs.toDouble()
                    flat["heldHere"] = call.heldHere != 0L
                    flat["heldThere"] = call.heldThere != 0L
                    text(call.fromUri)?.let { flat["fromUri"] = it }
                    text(call.fromDisplay)?.let { flat["fromDisplay"] = it }
                    text(call.toUri)?.let { flat["toUri"] = it }
                }
                event.kind in digitKinds -> digitOf(event)?.let { flat["digit"] = it.toString() }
                else -> transferOf(event)?.let { transfer ->
                    flat["statusCode"] = transfer.statusCode.toInt()
                    flat["attended"] = transfer.attended != 0L
                    transfer.target?.let { flat["target"] = it }
                }
            }
            return flat
        }
    }
}
