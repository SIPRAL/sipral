// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The address a socket bound on every interface advertises toward a peer
// (`sipral_advertised_address`), and the resolver answering
// SIPRAL_EVENT_KIND_LOOKUP_WANTED for accounts added with a server URI.

package org.sipral.idiomatic

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.Hashtable
import org.sipral.Sipral
import org.sipral.SipralDnsAnswer
import org.sipral.SipralDnsRecordType
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralLocateEvent

/**
 * A resolver's answer to one lookup (`sipral_account_looked_up`): a
 * [SipralDnsAnswer] and, with `RECORDS`, each record as TTL in seconds
 * then its zone-file data (`300 192.0.2.40`,
 * `300 10 60 5060 sip1.example.com`).
 */
data class SipralLookup(val answer: SipralDnsAnswer, val records: List<String> = emptyList()) {
    companion object {
        /** The name has no record of that kind, or does not exist. */
        val NOTHING = SipralLookup(SipralDnsAnswer.NOTHING)

        /** The resolver could not answer. */
        val FAILED = SipralLookup(SipralDnsAnswer.FAILED)
    }
}

/**
 * Answers `SIPRAL_EVENT_KIND_LOOKUP_WANTED` for accounts added with a
 * `serverUri`, given the name and record type. Runs on its own thread per
 * lookup and may block.
 */
typealias SipralResolver = (name: String, record: SipralDnsRecordType) -> SipralLookup

/**
 * The resolver a [SipralClient] uses when given none.
 *
 * Addresses come from [InetAddress] (hosts file included) with TTL
 * [ADDRESS_TTL], since the platform does not report one. SRV and NAPTR go
 * to JNDI's `dns:` provider where it exists, same TTL. Android has no JNDI,
 * so there SRV and NAPTR answer `NOTHING`, which RFC 3263 treats as none
 * published and falls back to addresses. An Android app whose server uses
 * SRV should pass a resolver built on `android.net.DnsResolver` (API 29).
 */
object SipralDns {
    /** The TTL, in seconds, for records whose own TTL the platform hides:
     * how soon a moved server is looked up again. */
    const val ADDRESS_TTL = 60L

    /** The platform's resolver, as described above. */
    val platform: SipralResolver = { name, record ->
        when (record) {
            SipralDnsRecordType.A -> addresses(name, v6 = false)
            SipralDnsRecordType.AAAA -> addresses(name, v6 = true)
            SipralDnsRecordType.SRV, SipralDnsRecordType.NAPTR -> directory(name, record)
            else -> SipralLookup.NOTHING
        }
    }

    /** The addresses of one family [InetAddress] finds for [name]. */
    fun addresses(name: String, v6: Boolean): SipralLookup {
        val found = try {
            InetAddress.getAllByName(name).toList()
        } catch (_: UnknownHostException) {
            return SipralLookup.NOTHING
        } catch (_: SecurityException) {
            return SipralLookup.FAILED
        }
        val records = found
            .filter { if (v6) it is Inet6Address else it is Inet4Address }
            .map { it.hostAddress.substringBefore('%') }
            .distinct()
            .map { "$ADDRESS_TTL $it" }
        return if (records.isEmpty()) SipralLookup.NOTHING else SipralLookup(SipralDnsAnswer.RECORDS, records)
    }

    /** SRV or NAPTR through JNDI's DNS provider, where the platform has one. */
    fun directory(name: String, record: SipralDnsRecordType): SipralLookup {
        val type = if (record == SipralDnsRecordType.SRV) "SRV" else "NAPTR"
        return try {
            val environment = Hashtable<String, String>().apply {
                put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory")
                put("java.naming.provider.url", "dns:")
                put("com.sun.jndi.dns.timeout.initial", "2000")
                put("com.sun.jndi.dns.timeout.retries", "2")
            }
            val context = javax.naming.directory.InitialDirContext(environment)
            try {
                val attribute = context.getAttributes(name, arrayOf(type)).get(type)
                    ?: return SipralLookup.NOTHING
                val records = (0 until attribute.size()).mapNotNull { zoneText(record, attribute.get(it).toString()) }
                if (records.isEmpty()) SipralLookup.NOTHING else SipralLookup(SipralDnsAnswer.RECORDS, records)
            } finally {
                context.close()
            }
        } catch (_: javax.naming.NameNotFoundException) {
            SipralLookup.NOTHING
        } catch (_: javax.naming.NamingException) {
            SipralLookup.FAILED
        } catch (_: LinkageError) {
            // Android: no JNDI at all
            SipralLookup.NOTHING
        }
    }

    /**
     * One record as JNDI prints it, rewritten for `sipral_account_looked_up`:
     * [ADDRESS_TTL], then priority, weight, port, target for SRV; order,
     * preference, flags, service, replacement for NAPTR (the regexp dropped,
     * as RFC 3263 uses none). Null for unparseable text.
     */
    fun zoneText(record: SipralDnsRecordType, printed: String): String? {
        val words = Regex("\"[^\"]*\"|\\S+").findAll(printed).map { it.value.trim('"') }.toList()
        fun host(text: String) = if (text == ".") "." else text.trimEnd('.')
        return when {
            record == SipralDnsRecordType.SRV && words.size == 4 ->
                "$ADDRESS_TTL ${words[0]} ${words[1]} ${words[2]} ${host(words[3])}"
            record == SipralDnsRecordType.NAPTR && words.size == 6 ->
                "$ADDRESS_TTL ${words[0]} ${words[1]} ${words[2].ifEmpty { "\"\"" }} ${words[3]} ${host(words[5])}"
            else -> null
        }
    }
}

/**
 * The `LOOKUP_WANTED`, `LOCATED` or `LOCATE_FAILED` payload (the query,
 * the addresses found, or why not and when it retries), or null for any
 * other kind.
 */
fun locateOf(event: SipralEvent): SipralLocateEvent? = when (event.kind) {
    SipralEventKind.LOOKUP_WANTED.value.toLong(),
    SipralEventKind.LOCATED.value.toLong(),
    SipralEventKind.LOCATE_FAILED.value.toLong(),
    -> event.payload.locate
    else -> null
}

/**
 * `sipral_advertised_address`: the `host:port` to advertise for a socket
 * bound at [bound] talking to [peer]. A wildcard bind gives the route
 * toward [peer]; a loopback bind toward a remote peer throws
 * `UNREACHABLE_ADDRESS`, and no route `TRANSPORT_DOWN`. Both arguments
 * are addresses, not names.
 */
fun advertisedAddress(bound: String, peer: String): String {
    val buffer = ByteArray(128)
    val needed = Sipral.advertisedAddress(bound, peer, buffer).toInt()
    return String(buffer, 0, maxOf(0, needed - 1), Charsets.UTF_8)
}

/**
 * This machine's address on the route toward [peer] (`host:port`).
 * `127.0.0.1` when there is no peer, it is a name, or nothing routes to
 * it; that works for a local peer, and the library refuses to advertise it
 * to any other.
 */
fun routeHost(peer: String?): String {
    if (peer == null || !isAddress(peer)) {
        return "127.0.0.1"
    }
    return try {
        advertisedAddress(if (peer.startsWith("[")) "[::]:0" else "0.0.0.0:0", peer).substringBeforeLast(':')
    } catch (_: SipralException) {
        "127.0.0.1"
    }
}

/** Whether [text] is `host:port` with an IP address, not a name, for its
 * host. */
internal fun isAddress(text: String): Boolean {
    val host = text.substringBeforeLast(':', "").trim('[', ']')
    val port = text.substringAfterLast(':', "")
    if (host.isEmpty() || port.toIntOrNull() == null) {
        return false
    }
    val v4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    return v4.matches(host) || (host.contains(':') && host.all { it.isLetterOrDigit() || it == ':' || it == '.' })
}
