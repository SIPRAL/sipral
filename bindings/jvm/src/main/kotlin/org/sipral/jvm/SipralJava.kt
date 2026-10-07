// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// org.sipral.idiomatic for Java callers. Plain methods (hangup, hold,
// close, getters) need nothing; what Java cannot reach is Kotlin default
// arguments, suspend functions and Flows. Here they become overloads,
// blocking calls plus CompletableFutures, and listeners.

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
import org.sipral.idiomatic.SipralNetworkTest
import org.sipral.idiomatic.SipralTokenRequired
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

    /** [SipralClient.open] in application mode, a held party being sent
     * [heldAudio]: silence by default, or the application's frames (hold
     * music, an announcement). */
    @JvmStatic
    fun open(bindHost: String, bindPort: Int, userAgent: String?, heldAudio: SipralHeldAudio): SipralClient =
        SipralClient.open(
            bindHost = bindHost, bindPort = bindPort, userAgent = userAgent, audio = SipralAudioMode.Application,
            heldAudio = heldAudio,
        )

    /** [SipralClient.open] in application mode with at most [maxDialogs]
     * calls (0 for 128; past it an incoming call gets 503 with
     * `Retry-After: 2`) and [maxServerTransactions] requests in progress (0
     * for 256). A server past a hundred calls raises both. */
    @JvmStatic
    fun open(bindHost: String, bindPort: Int, userAgent: String?, maxDialogs: Long, maxServerTransactions: Long): SipralClient =
        SipralClient.open(
            bindHost = bindHost, bindPort = bindPort, userAgent = userAgent, audio = SipralAudioMode.Application,
            maxDialogs = maxDialogs, maxServerTransactions = maxServerTransactions,
        )

    /**
     * [SipralClient.addAccount]: [registrarAddress] is where requests go,
     * `host:port`; with [registrar] the account can register there, as
     * [authUser] with [authPassword]. [streamProtocol] (`SipralTransport.TCP`
     * or `TLS`) puts the account on its own connection, held to [tlsPin] if
     * given. [realms] are the realms the password answers, for a server that
     * challenges calls under a realm REGISTER never sees; other challenges go
     * unanswered and raise `CHALLENGE_DECLINED` ([declinedChallengeOf]).
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

    /** A `TOKEN_REQUIRED` [event]'s request for an OAuth 2.0 token (RFC 8898)
     * with authorization server and scope, or null for another event. The
     * token goes in with [setAccessToken]. */
    @JvmStatic
    fun tokenRequiredOf(event: SipralEvent): SipralTokenRequired? =
        org.sipral.idiomatic.tokenRequiredOf(event)

    /** A `NETWORK_TEST` [event]'s findings, or null for another event. */
    @JvmStatic
    fun networkTestOf(event: SipralEvent): SipralNetworkTest? =
        org.sipral.idiomatic.networkTestOf(event)

    /** [SipralClient.networkTest]: test [account]'s server and measure
     * [echoCall], then hang it up. Returns the test's number. */
    @JvmStatic
    @JvmOverloads
    fun networkTest(
        client: SipralClient,
        account: SipralAccount? = null,
        echoCall: SipralCall? = null,
        echoMs: Long = 0,
        timeoutMs: Long = 0,
    ): Long = client.networkTest(account, echoCall, echoMs, timeoutMs)

    /** [SipralAccount.setAccessToken]: the access token [account]'s server
     * asked for, or null to take it away. */
    @JvmStatic
    fun setAccessToken(account: SipralAccount, token: String?) = account.setAccessToken(token)

    /** [SipralClient.placeCall] to [target], media bound on [mediaHost];
     * [codecs] (`"PCMA,PCMU"`) replaces the client's order. */
    @JvmStatic
    @JvmOverloads
    fun placeCall(
        client: SipralClient,
        account: SipralAccount,
        target: String,
        mediaHost: String = "127.0.0.1",
        codecs: String? = null,
    ): SipralCall = client.placeCall(account, target, mediaHost = mediaHost, codecs = codecs)

    /** [SipralClient.answerCall] for an `INCOMING_CALL` [event], media bound
     * on [mediaHost]. An answer keeps the offer's order, so [codecs] chooses
     * which codecs, not which comes first. */
    @JvmStatic
    @JvmOverloads
    fun answerCall(client: SipralClient, event: SipralEvent, mediaHost: String = "127.0.0.1", codecs: String? = null): SipralCall =
        client.answerCall(event, mediaHost = mediaHost, codecs = codecs)

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
     * Subscribe to [events], run [action], and block until the first event of
     * one of [kinds]. The subscription is live before [action] runs, so its
     * own event is never missed ([org.sipral.idiomatic.awaitNext]).
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
     * Hand every event of [events] to [listener], in order, on a library
     * thread (never the poll thread), until the returned handle is closed.
     * Live once this returns. A throwing [listener] goes to the uncaught
     * exception handler and delivery continues.
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
