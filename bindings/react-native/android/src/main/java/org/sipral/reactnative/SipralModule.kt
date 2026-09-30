// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
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
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import org.sipral.idiomatic.SipralAndroidAudio
import org.sipral.reactnative.core.SipralAccountOptions
import org.sipral.reactnative.core.SipralOpenOptions
import org.sipral.reactnative.core.SipralReactCore
import org.sipral.reactnative.core.SipralRefusal

class SipralModule(context: ReactApplicationContext) : NativeSipralSpec(context) {
    private val core = SipralReactCore(emit = ::forward)

    // One thread, so that the calls JavaScript makes reach the stack in the
    // order it made them; and not the JavaScript one, since placing a call
    // can wait for a STUN server.
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "sipral-react-native").apply { isDaemon = true }
    }

    override fun open(options: ReadableMap, promise: Promise) = settle(promise) {
        SipralAndroidAudio.attach(reactApplicationContext)
        core.open(
            SipralOpenOptions(
                bindHost = options.getString("bindHost") ?: "",
                bindPort = options.number("bindPort")?.toInt() ?: 0,
                userAgent = options.text("userAgent"),
                codecs = options.text("codecs"),
                signalling = options.text("signalling") ?: "udp",
                signallingServer = options.text("signallingServer"),
                stunServer = options.text("stunServer"),
                manualAudio = options.hasKey("manualAudio") && !options.isNull("manualAudio") &&
                    options.getBoolean("manualAudio"),
            ),
        )
    }

    override fun close(promise: Promise) = settle(promise) { core.close() }

    override fun addAccount(options: ReadableMap, promise: Promise) = settle(promise) {
        core.addAccount(
            SipralAccountOptions(
                aor = options.getString("aor") ?: "",
                registrarAddress = options.getString("registrarAddress") ?: "",
                registrar = options.text("registrar"),
                contact = options.text("contact"),
                displayName = options.text("displayName"),
                authUser = options.text("authUser"),
                authPassword = options.text("authPassword"),
                expiresSeconds = options.number("expiresSeconds")?.toLong() ?: 0,
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

    override fun invalidate() {
        worker.execute { core.close() }
        worker.shutdown()
        super.invalidate()
    }

    private fun forward(event: Map<String, Any>) {
        val map = Arguments.createMap()
        for ((key, value) in event) {
            when (value) {
                is String -> map.putString(key, value)
                is Boolean -> map.putBoolean(key, value)
                is Int -> map.putInt(key, value)
                is Double -> map.putDouble(key, value)
            }
        }
        emitOnEvent(map)
    }

    private fun settle(promise: Promise, action: () -> Any) {
        worker.execute {
            try {
                when (val result = action()) {
                    is String -> promise.resolve(result)
                    else -> promise.resolve(null)
                }
            } catch (refused: SipralRefusal) {
                promise.reject(refused.code, refused.message, refused)
            } catch (failed: Exception) {
                promise.reject("platform", failed.message ?: failed.toString(), failed)
            }
        }
    }

    private fun ReadableMap.text(key: String): String? =
        if (hasKey(key) && !isNull(key)) getString(key) else null

    private fun ReadableMap.number(key: String): Double? =
        if (hasKey(key) && !isNull(key)) getDouble(key) else null

    companion object {
        const val NAME = NativeSipralSpec.NAME
    }
}
