// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// org.sipral.idiomatic as a Java caller reaches it. Most of that layer is
// already plain methods Java calls as they are -- hangup, hold, resume,
// close, the state and statistics getters. What Java cannot reach is the
// rest: factories whose every optional argument is a Kotlin default, suspend
// functions, and events as a Flow. Each has a counterpart here: overloads
// for the arguments a server sets, a blocking call and a CompletableFuture
// for every wait, and a listener for a flow.

package org.sipral.jvm

import java.util.concurrent.Callable
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeoutException
import java.util.function.Consumer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.future.future
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralHeldAudio
import org.sipral.SipralTransport
import org.sipral.idiomatic.SipralAccount
import org.sipral.idiomatic.SipralAudioMode
import org.sipral.idiomatic.SipralCall
import org.sipral.idiomatic.SipralClient
import org.sipral.idiomatic.SipralDeclinedChallenge
import org.sipral.idiomatic.awaitNext

/** What [SipralJava.awaitNext] hands back: what the action returned, and
 * the event it caused. */
class SipralAwaited<T>(
    /** What the action returned. */
    val result: T,
    /** The first matching event after the subscription went live. */
    val event: SipralEvent,
)

/**
 * The idiomatic layer's entry points for Java.
 *
 * ```java
 * try (SipralClient client = SipralJava.open("192.0.2.10")) {
 *     SipralAccount account = SipralJava.addAccount(client, "sip:agent@example.com", "203.0.113.5:5060");
 *     SipralCall call = SipralJava.placeCall(client, account, "sip:bob@example.com", "192.0.2.10");
 *     SipralJava.waitConfirmed(call, 30_000);
 *     call.hangup();
 * }
 * ```
 */
object SipralJava {
    /** Where futures and listeners run: never on a stack's poll thread. */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /**
     * [SipralClient.open] on [bindHost]:[bindPort] (0 for any port), with
     * the application running each call's audio: a server has no sound card,
     * and [org.sipral.idiomatic.SipralMedia] carries the PCM. [userAgent]
     * names the stack in `User-Agent` and `Server`.
     */
    @JvmStatic
    @JvmOverloads
    fun open(bindHost: String = "127.0.0.1", bindPort: Int = 0, userAgent: String? = null): SipralClient =
        SipralClient.open(bindHost = bindHost, bindPort = bindPort, userAgent = userAgent, audio = SipralAudioMode.Application)

    /** [SipralClient.open] with the audio mode named, for a JVM that does
     * have devices the library runs. */
    @JvmStatic
    fun open(bindHost: String, bindPort: Int, userAgent: String?, audio: SipralAudioMode): SipralClient =
        SipralClient.open(bindHost = bindHost, bindPort = bindPort, userAgent = userAgent, audio = audio)

    /** [SipralClient.open] in application mode, a party this end holds
     * sent [heldAudio]: silence by default, or what the application sends
     * -- hold music, an announcement, a voice agent's own speech. */
    @JvmStatic
    fun open(bindHost: String, bindPort: Int, userAgent: String?, heldAudio: SipralHeldAudio): SipralClient =
        SipralClient.open(
            bindHost = bindHost, bindPort = bindPort, userAgent = userAgent, audio = SipralAudioMode.Application,
            heldAudio = heldAudio,
        )

    /**
     * [SipralClient.addAccount]: [registrarAddress] is where requests go,
     * `host:port`; with [registrar] the account can register there, as
     * [authUser] with [authPassword] when challenged. [streamProtocol]
     * (`SipralTransport.TCP` or `TLS`) puts the account on a connection of
     * its own to that server, beside accounts on the client's UDP socket to
     * others; a TLS one is held to [tlsPin] when given. [realms] are the
     * realms the password answers, for a server whose calls are challenged
     * under a realm its REGISTERs never meet; a challenge under any other is
     * not answered, and `CHALLENGE_DECLINED` ([declinedChallengeOf]) says
     * so.
     */
    @JvmStatic
    @JvmOverloads
    fun addAccount(
        client: SipralClient,
        aor: String,
        registrarAddress: String,
        registrar: String? = null,
        authUser: String? = null,
        authPassword: String? = null,
        streamProtocol: SipralTransport? = null,
        tlsPin: String? = null,
        realms: List<String> = emptyList(),
    ): SipralAccount = client.addAccount(
        aor = aor,
        registrarAddress = registrarAddress,
        registrar = registrar,
        authUser = authUser,
        authPassword = authPassword,
        streamProtocol = streamProtocol,
        tlsPin = tlsPin,
        realms = realms,
    )

    /** The challenge a `CHALLENGE_DECLINED` [event] reports, or null for
     * any other event ([org.sipral.idiomatic.declinedChallengeOf]). */
    @JvmStatic
    fun declinedChallengeOf(event: SipralEvent): SipralDeclinedChallenge? =
        org.sipral.idiomatic.declinedChallengeOf(event)

    /** [SipralClient.placeCall] to [target], its media socket bound on
     * [mediaHost]. */
    @JvmStatic
    @JvmOverloads
    fun placeCall(client: SipralClient, account: SipralAccount, target: String, mediaHost: String = "127.0.0.1"): SipralCall =
        client.placeCall(account, target, mediaHost = mediaHost)

    /** [SipralClient.answerCall] for the `INCOMING_CALL` [event], its media
     * socket bound on [mediaHost]. */
    @JvmStatic
    @JvmOverloads
    fun answerCall(client: SipralClient, event: SipralEvent, mediaHost: String = "127.0.0.1"): SipralCall =
        client.answerCall(event, mediaHost = mediaHost)

    /** [SipralCall.sendDtmf] the default way: RFC 4733, 100 ms a digit. */
    @JvmStatic
    fun sendDtmf(call: SipralCall, digits: String) = call.sendDtmf(digits)

    /** The digit a `DIGIT_RECEIVED` [event] carries, or null for any other
     * event ([org.sipral.idiomatic.digitOf]). */
    @JvmStatic
    fun digitOf(event: SipralEvent): Char? = org.sipral.idiomatic.digitOf(event)

    /** [SipralAccount.registerAndWait], blocking. */
    @JvmStatic
    @JvmOverloads
    @Throws(TimeoutException::class)
    fun registerAndWait(account: SipralAccount, timeoutMs: Long = 10_000) =
        blocking("registration") { account.registerAndWait(timeoutMs) }

    /** [SipralCall.waitConfirmed], blocking. */
    @JvmStatic
    @JvmOverloads
    @Throws(TimeoutException::class)
    fun waitConfirmed(call: SipralCall, timeoutMs: Long = 30_000) =
        blocking("the call's confirmation") { call.waitConfirmed(timeoutMs) }

    /** [SipralCall.waitEnded], blocking. */
    @JvmStatic
    @JvmOverloads
    @Throws(TimeoutException::class)
    fun waitEnded(call: SipralCall, timeoutMs: Long = 30_000) =
        blocking("the call's end") { call.waitEnded(timeoutMs) }

    /** [SipralAccount.registerAndWait], completing once registered. */
    @JvmStatic
    fun registered(account: SipralAccount, timeoutMs: Long): CompletableFuture<Void?> =
        later("registration") { account.registerAndWait(timeoutMs) }

    /** [SipralCall.waitConfirmed], completing once the call is confirmed. */
    @JvmStatic
    fun confirmed(call: SipralCall, timeoutMs: Long): CompletableFuture<Void?> =
        later("the call's confirmation") { call.waitConfirmed(timeoutMs) }

    /** [SipralCall.waitEnded], completing once the call has ended. */
    @JvmStatic
    fun ended(call: SipralCall, timeoutMs: Long): CompletableFuture<Void?> =
        later("the call's end") { call.waitEnded(timeoutMs) }

    /**
     * Subscribe to [events], run [action], and block until the first event
     * of one of [kinds] arrives: the subscription is live before [action]
     * runs, so the event [action] itself causes is never missed
     * ([org.sipral.idiomatic.awaitNext]).
     */
    @JvmStatic
    @Throws(TimeoutException::class)
    fun <T> awaitNext(
        events: SharedFlow<SipralEvent>,
        kinds: Set<SipralEventKind>,
        timeoutMs: Long,
        action: Callable<T>,
    ): SipralAwaited<T> = blocking("an event of ${kinds.joinToString()}") {
        val (result, event) = events.awaitNext(*kinds.toTypedArray(), timeoutMs = timeoutMs) { action.call() }
        SipralAwaited(result, event)
    }

    /**
     * Hand every event of [events] to [listener], in order, on a thread of
     * the library's own rather than the stack's poll thread, until the
     * returned handle is closed. The subscription is live once this
     * returns. An exception [listener] throws goes to the thread's
     * uncaught-exception handler and the next event is still delivered.
     */
    @JvmStatic
    fun subscribe(events: Flow<SipralEvent>, listener: Consumer<SipralEvent>): AutoCloseable {
        val job = scope.launch(start = CoroutineStart.UNDISPATCHED) {
            events.collect { event ->
                try {
                    listener.accept(event)
                } catch (thrown: Exception) {
                    val thread = Thread.currentThread()
                    thread.uncaughtExceptionHandler?.uncaughtException(thread, thrown)
                }
            }
        }
        return AutoCloseable { job.cancel() }
    }

    private fun <T> blocking(what: String, body: suspend CoroutineScope.() -> T): T = try {
        runBlocking(block = body)
    } catch (late: TimeoutCancellationException) {
        throw TimeoutException("sipral: timed out waiting for $what").apply { initCause(late) }
    }

    private fun later(what: String, body: suspend CoroutineScope.() -> Unit): CompletableFuture<Void?> {
        val done = CompletableFuture<Void?>()
        scope.future(block = body).whenComplete { _, failure ->
            when (failure) {
                null -> done.complete(null)
                is TimeoutCancellationException ->
                    done.completeExceptionally(TimeoutException("sipral: timed out waiting for $what").apply { initCause(failure) })
                else -> done.completeExceptionally(failure)
            }
        }
        return done
    }
}
