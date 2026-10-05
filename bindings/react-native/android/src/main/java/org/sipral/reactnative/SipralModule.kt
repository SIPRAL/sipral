// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The TurboModule: NativeSipralSpec is what codegen writes from
// src/NativeSipral.ts, and every method here reads its arguments, runs the
// matching SipralReactCore call off the JavaScript thread, and settles the
// promise. What the core throws reaches JavaScript as a rejection whose code
// is the refusal's.

package org.sipral.reactnative

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableMap
import org.sipral.idiomatic.SipralAndroidAudio
import org.sipral.reactnative.core.SipralAccountOptions
import org.sipral.reactnative.core.SipralOpenOptions
import org.sipral.reactnative.core.SipralReactCore
import org.sipral.reactnative.core.SipralWorker

class SipralModule(context: ReactApplicationContext) : NativeSipralSpec(context) {
    private val core = SipralReactCore(emit = ::forward)

    private val worker = SipralWorker()

    override fun open(options: ReadableMap, promise: Promise) = settle(promise) {
        SipralAndroidAudio.attach(reactApplicationContext)
        core.open(
            SipralOpenOptions(
                bindHost = options.text("bindHost"),
                bindPort = options.number("bindPort")?.toInt() ?: 0,
                userAgent = options.text("userAgent"),
                codecs = options.text("codecs"),
                signalling = options.text("signalling") ?: "udp",
                signallingServer = options.text("signallingServer"),
                stunServer = options.text("stunServer"),
                manualAudio = options.flag("manualAudio") ?: false,
                srtp = options.text("srtp"),
                srtpSuites = options.text("srtpSuites"),
                pathMtu = options.number("pathMtu")?.toLong() ?: 0,
                datagramWithoutStreamBytes = options.number("datagramWithoutStreamBytes")?.toLong() ?: 0,
                pseudonymSalt = options.text("pseudonymSalt"),
                diagnosticTrace = options.flag("diagnosticTrace"),
                tlsPin = options.text("tlsPin"),
                systemEchoCancellation = options.flag("systemEchoCancellation"),
                heldAudio = options.text("heldAudio"),
                maxDialogs = options.number("maxDialogs")?.toLong() ?: 0,
                maxServerTransactions = options.number("maxServerTransactions")?.toLong() ?: 0,
            ),
        )
    }

    override fun close(promise: Promise) = settle(promise) { core.close() }

    override fun addAccount(options: ReadableMap, promise: Promise) = settle(promise) {
        core.addAccount(
            SipralAccountOptions(
                aor = options.getString("aor") ?: "",
                registrarAddress = options.text("registrarAddress"),
                serverUri = options.text("serverUri"),
                serverNaptr = options.flag("serverNaptr") ?: false,
                keepaliveMs = options.number("keepaliveMs")?.toLong() ?: 0,
                registrar = options.text("registrar"),
                contact = options.text("contact"),
                displayName = options.text("displayName"),
                authUser = options.text("authUser"),
                authPassword = options.text("authPassword"),
                expiresSeconds = options.number("expiresSeconds")?.toLong() ?: 0,
                streamProtocol = options.text("streamProtocol"),
                tlsPin = options.text("tlsPin"),
                realms = options.text("realms"),
            ),
        )
    }

    override fun register(account: String, promise: Promise) = settle(promise) { core.register(account) }

    override fun unregister(account: String, promise: Promise) = settle(promise) { core.unregister(account) }

    override fun removeAccount(account: String, promise: Promise) = settle(promise) { core.removeAccount(account) }

    override fun placeCall(account: String, target: String, options: ReadableMap, promise: Promise) = settle(promise) {
        core.placeCall(account, target, options.text("destination"), options.text("codecs"))
    }

    override fun answer(call: String, promise: Promise) = settle(promise) { core.answer(call) }

    override fun reject(call: String, code: Double, promise: Promise) = settle(promise) { core.reject(call, code.toInt()) }

    override fun hangup(call: String, promise: Promise) = settle(promise) { core.hangup(call) }

    override fun hold(call: String, promise: Promise) = settle(promise) { core.hold(call) }

    override fun resume(call: String, promise: Promise) = settle(promise) { core.resume(call) }

    override fun transfer(call: String, target: String, promise: Promise) = settle(promise) { core.transfer(call, target) }

    override fun acceptTransfer(call: String, promise: Promise) = settle(promise) { core.acceptTransfer(call) }

    override fun rejectTransfer(call: String, code: Double, promise: Promise) =
        settle(promise) { core.rejectTransfer(call, code.toInt()) }

    override fun sendDtmf(call: String, digits: String, promise: Promise) = settle(promise) { core.sendDtmf(call, digits) }

    override fun activateAudio(promise: Promise) = settle(promise) { core.activateAudio() }

    override fun deactivateAudio(promise: Promise) = settle(promise) { core.deactivateAudio() }

    override fun setMuted(muted: Boolean, promise: Promise) = settle(promise) { core.setMuted(muted) }

    override fun setSystemEchoCancellation(on: Boolean, promise: Promise) =
        settle(promise) { core.setSystemEchoCancellation(on) }

    override fun setDiagnosticTrace(on: Boolean, promise: Promise) = settle(promise) { core.setDiagnosticTrace(on) }

    override fun setCallGain(call: String, direction: String, gain: Double, promise: Promise) =
        settle(promise) { core.setCallGain(call, direction, gain) }

    override fun setCallMuted(call: String, direction: String, muted: Boolean, promise: Promise) =
        settle(promise) { core.setCallMuted(call, direction, muted) }

    override fun callAudio(call: String, direction: String, promise: Promise) =
        settle(promise) { written(core.callAudio(call, direction)) }

    override fun setAppRate(call: String, hz: Double, promise: Promise) =
        settle(promise) { written(core.setAppRate(call, hz.toInt())) }

    override fun settings(promise: Promise) = settle(promise) { written(core.settings()) }

    override fun invalidate() {
        worker.shutdown { core.close() }
        super.invalidate()
    }

    private fun forward(event: Map<String, Any>) {
        emitOnEvent(written(event))
    }

    /** A flat map the core made, as the bridge's own. */
    private fun written(record: Map<String, Any>): WritableMap {
        val map = Arguments.createMap()
        for ((key, value) in record) {
            when (value) {
                is String -> map.putString(key, value)
                is Boolean -> map.putBoolean(key, value)
                is Int -> map.putInt(key, value)
                is Double -> map.putDouble(key, value)
            }
        }
        return map
    }

    private fun settle(promise: Promise, action: () -> Any) =
        worker.settle(
            resolve = { result -> promise.resolve(result) },
            reject = { code, message, cause -> promise.reject(code, message, cause) },
            action = action,
        )

    private fun ReadableMap.text(key: String): String? =
        if (hasKey(key) && !isNull(key)) getString(key) else null

    private fun ReadableMap.number(key: String): Double? =
        if (hasKey(key) && !isNull(key)) getDouble(key) else null

    private fun ReadableMap.flag(key: String): Boolean? =
        if (hasKey(key) && !isNull(key)) getBoolean(key) else null

    companion object {
        const val NAME = NativeSipralSpec.NAME
    }
}
