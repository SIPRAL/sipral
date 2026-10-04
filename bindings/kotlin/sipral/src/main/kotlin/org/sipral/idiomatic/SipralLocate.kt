// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Where a client is reached, and where a server named by a name is: the
// address a socket bound on every interface advertises toward a peer
// (`sipral_advertised_address`), and the resolver that answers
// SIPRAL_EVENT_KIND_LOOKUP_WANTED for an account added with a server URI.

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
 * What a resolver said to one lookup: a [SipralDnsAnswer], and with
 * `RECORDS` the records of the kind asked for, each its time-to-live in
 * seconds and then its data as a zone file writes it -- `300 192.0.2.40`,
 * `300 10 60 5060 sip1.example.com` (`sipral_account_looked_up`).
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
 * Answers `SIPRAL_EVENT_KIND_LOOKUP_WANTED` for the accounts a client added
 * with a `serverUri`: the name and the kind of record asked for, and what
 * the DNS said. Called on a thread of its own, one per lookup, and may block.
 */
typealias SipralResolver = (name: String, record: SipralDnsRecordType) -> SipralLookup

/**
 * The resolver a [SipralClient] uses when it is given none.
 *
 * Addresses are asked of [InetAddress], which reads the hosts file as well,
 * with a time-to-live of [ADDRESS_TTL], the platform's lookup not saying
 * what the zone's was. SRV and NAPTR are asked of the JDK's DNS provider
 * (JNDI's `dns:`, the system's resolvers) where the platform has it, with
 * that same time-to-live, the provider not reporting one either; Android has
 * no JNDI, and there every SRV or NAPTR query is answered `NOTHING`, which
 * RFC 3263's procedure takes as a domain that publishes none, going on to
 * the host's own addresses. An Android application whose server publishes
 * SRV records passes a resolver built on `android.net.DnsResolver` (API 29)
 * instead.
 */
object SipralDns {
    /** The time-to-live given a record whose own the platform did not say,
     * in seconds: how soon a moved server is looked up again. */
    const val ADDRESS_TTL = 60L

    /** The platform's resolver, as the object documentation describes. */
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
     * One record as the JDK's DNS provider prints it, written as
     * `sipral_account_looked_up` takes it: [ADDRESS_TTL], then priority,
     * weight, port and target for SRV; order, preference, flags, service and
     * replacement for NAPTR, the regular expression left out since RFC 3263
     * follows none. Null for text that is not one.
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
 * The `SIPRAL_EVENT_KIND_LOOKUP_WANTED`, `LOCATED` or `LOCATE_FAILED`
 * payload -- the DNS query an account's server is located with, every
 * address it was located at, or why not and when it is asked again -- or
 * null for an event of any other kind.
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
 * bound at [bound] whose traffic goes to [peer]. A wildcard bind
 * (`0.0.0.0:5060`) gives the address of the route toward [peer]; a loopback
 * bind toward a peer that is not throws `UNREACHABLE_ADDRESS`, and no route
 * at all `TRANSPORT_DOWN`. Both are addresses, not names.
 */
fun advertisedAddress(bound: String, peer: String): String {
    val buffer = ByteArray(128)
    val needed = Sipral.advertisedAddress(bound, peer, buffer).toInt()
    return String(buffer, 0, maxOf(0, needed - 1), Charsets.UTF_8)
}

/**
 * The address of this machine's route toward [peer] (`host:port`), the one
 * a socket bound on every interface is reached at from there; `127.0.0.1`
 * when there is no peer, it is a name rather than an address, or no route
 * reaches it -- the address that works for a peer on this machine and that
 * the library refuses to advertise to any other.
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
