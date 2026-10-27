// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// An account's `+sip.instance` (RFC 5626 §4.1) and its own REGISTER header
// fields through SipralClient.addAccount, as a push proxy that requires the
// instance sees them: on the first REGISTER, on the one answering a 401
// challenge, on a refresh and on the de-registration. The registrar is a
// loopback UDP socket that challenges every REGISTER without credentials,
// grants two seconds so the refresh comes within one, and keeps every
// datagram. Run by IdiomaticCheck.kt's main, under -Xcheck:jni.

package org.sipral.idiomatic

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.util.Collections
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.delay
import org.sipral.SipralException
import org.sipral.SipralHeader
import org.sipral.SipralRegistrationState
import org.sipral.SipralStatus

private const val INSTANCE = "urn:uuid:4b1d6c3e-2f7a-4c55-9d0e-8a1f3b6c7d20"

private fun fieldOf(name: String, message: String): String? =
    message.split("\r\n")
        .firstOrNull { it.lowercase().startsWith(name.lowercase() + ":") }
        ?.substringAfter(':')?.trim()

/** A registrar on a loopback UDP port: a REGISTER without `Authorization`
 * is challenged 401, one with it is granted [grantSeconds] (or its removal
 * confirmed); every REGISTER kept as text once, a retransmission answered
 * as the request it repeats. */
private class ChallengingRegistrar(private val grantSeconds: Int) : AutoCloseable {
    private val udp = DatagramSocket(0, InetAddress.getByName("127.0.0.1")).apply { soTimeout = 50 }
    @Volatile private var stopped = false
    val address = "127.0.0.1:${udp.localPort}"
    private val kept: MutableList<String> = Collections.synchronizedList(ArrayList())
    val registers: List<String>
        get() = synchronized(kept) { kept.toList() }

    init {
        Thread(::serve, "challenging-registrar").apply { isDaemon = true; start() }
    }

    private fun serve() {
        val buffer = ByteArray(65536)
        val seen = HashSet<String?>()
        var nonce = 0
        while (!stopped) {
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                udp.receive(packet)
            } catch (_: SocketTimeoutException) {
                continue
            } catch (_: Exception) {
                return
            }
            val message = String(packet.data, 0, packet.length, Charsets.UTF_8)
            if (!message.startsWith("REGISTER ")) continue
            // a stack slowed down retransmits before the answer lands
            if (seen.add(fieldOf("CSeq", message))) {
                kept += message
            }
            val lines = mutableListOf<String>()
            if (fieldOf("Authorization", message) == null) {
                lines += "SIP/2.0 401 Unauthorized"
                lines += echoed(message)
                nonce++
                lines += "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"n$nonce\", algorithm=MD5, qop=\"auth\""
            } else {
                lines += "SIP/2.0 200 OK"
                lines += echoed(message)
                if (fieldOf("Expires", message) != "0") {
                    lines += "Contact: ${fieldOf("Contact", message)};expires=$grantSeconds"
                }
            }
            lines += "Content-Length: 0"
            val out = (lines.joinToString("\r\n") + "\r\n\r\n").toByteArray(Charsets.UTF_8)
            udp.send(DatagramPacket(out, out.size, packet.socketAddress))
        }
    }

    private fun echoed(request: String): List<String> =
        listOf("Via", "From", "To", "Call-ID", "CSeq").map { name ->
            val value = fieldOf(name, request) ?: ""
            if (name == "To") "To: $value;tag=registrar" else "$name: $value"
        }

    override fun close() {
        stopped = true
        udp.close()
    }
}

private suspend fun until(seconds: Int, what: () -> Boolean): Boolean {
    repeat(seconds * 50) {
        if (what()) return true
        delay(20)
    }
    return what()
}

private suspend fun everyRegisterCarriesTheInstanceAndTheAccountsHeaders(): String {
    ChallengingRegistrar(grantSeconds = 2).use { registrar ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
            val account = client.addAccount(
                aor = "sip:alice@example.com",
                registrarAddress = registrar.address,
                registrar = "sip:example.com",
                authUser = "alice",
                authPassword = "open sesame",
                instanceId = INSTANCE,
                headers = listOf(SipralHeader("X-Device-Class", "phone"), SipralHeader("Supported", "path")),
            )
            account.register()
            assertTrue(
                until(10) { account.registrationState == SipralRegistrationState.REGISTERED },
                "never registered: ${account.registrationState}",
            )
            val first = registrar.registers.first()
            val answering = registrar.registers[1]
            assertEquals(null, fieldOf("Authorization", first), first)
            assertTrue(fieldOf("Authorization", answering)?.startsWith("Digest ") == true, answering)
            assertEquals(fieldOf("Call-ID", first), fieldOf("Call-ID", answering))

            // granted two seconds, the binding is refreshed within one
            val granted = registrar.registers.size
            assertTrue(
                until(10) {
                    registrar.registers.drop(granted).any { fieldOf("Expires", it) != "0" } &&
                        account.registrationState == SipralRegistrationState.REGISTERED
                },
                "no refresh: ${registrar.registers.size} REGISTERs",
            )
            val refresh = registrar.registers.drop(granted).first()
            assertEquals(fieldOf("Call-ID", first), fieldOf("Call-ID", refresh))

            val before = registrar.registers.size
            account.unregister()
            assertTrue(
                until(10) {
                    registrar.registers.drop(before).any {
                        fieldOf("Expires", it) == "0" && fieldOf("Authorization", it) != null
                    }
                },
                "no de-registration the registrar accepted",
            )
            val removal = registrar.registers.drop(before).first { fieldOf("Expires", it) == "0" }

            for ((what, register) in listOf(
                "the first" to first, "the one answering the challenge" to answering,
                "the refresh" to refresh, "the de-registration" to removal,
            ) + registrar.registers.map { "a REGISTER" to it }) {
                val contact = fieldOf("Contact", register) ?: ""
                assertTrue(contact.contains("+sip.instance=\"<$INSTANCE>\""), "$what: Contact $contact")
                assertEquals("phone", fieldOf("X-Device-Class", register), "$what:\n$register")
                val supported = fieldOf("Supported", register) ?: ""
                assertTrue(
                    supported.split(',').map { it.trim() }.containsAll(listOf("path", "gruu")),
                    "$what: Supported $supported",
                )
                assertEquals(1, register.split("\r\n").count { it.lowercase().startsWith("supported:") }, what)
            }
            return "every REGISTER (${registrar.registers.size}: the first, the challenged, the refresh, " +
                "the de-registration) carried +sip.instance and the account's own fields"
        }
    }
}

private fun theAccountsHeadersAreCheckedOnAdd(): String {
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
        val noRegistrar = assertFailsWith<SipralException> {
            client.addAccount(
                aor = "sip:alice@example.com", registrarAddress = "127.0.0.1:5060",
                headers = listOf(SipralHeader("X-Device-Class", "phone")),
            )
        }
        assertEquals(SipralStatus.INVALID_ARGUMENT, noRegistrar.status, "an account that never registers")
        val expires = assertFailsWith<SipralException> {
            client.addAccount(
                aor = "sip:alice@example.com", registrarAddress = "127.0.0.1:5060", registrar = "sip:example.com",
                headers = listOf(SipralHeader("Expires", "60")),
            )
        }
        assertEquals(SipralStatus.INVALID_ARGUMENT, expires.status, "Expires is the stack's")
    }
    return "headers refused on an account with no registrar, and Expires left to the stack"
}

internal suspend fun instanceChecks(): String =
    listOf(
        everyRegisterCarriesTheInstanceAndTheAccountsHeaders(),
        theAccountsHeadersAreCheckedOnAdd(),
    ).joinToString("; ")
