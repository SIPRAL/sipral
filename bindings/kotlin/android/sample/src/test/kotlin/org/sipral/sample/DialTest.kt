// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// What the account screen and the dial pad hand the library: a bare number
// or name dialled at the account's domain, a URI as typed, and the
// registrar named by a host name looked up to an address.

package org.sipral.sample

import java.net.InetAddress
import java.net.UnknownHostException
import org.testng.Assert.assertEquals
import org.testng.Assert.assertNull
import org.testng.Assert.assertThrows
import org.testng.annotations.Test

class DialTest {
    @Test
    fun aBareNumberOrNameIsAUserAtTheAccountsDomain() {
        assertEquals(dialTarget("*43", "sip:alice@pbx.example.com"), "sip:*43@pbx.example.com")
        assertEquals(dialTarget(" 100 ", "sips:alice@pbx.example.com;transport=tls"), "sip:100@pbx.example.com")
        assertEquals(dialTarget("bob", "<sip:alice@192.0.2.10:5080>"), "sip:bob@192.0.2.10:5080")
    }

    @Test
    fun aUriIsDialledAsTypedAndUserAtHostGetsTheSipScheme() {
        assertEquals(dialTarget("sip:bob@example.org", "sip:alice@pbx.example.com"), "sip:bob@example.org")
        assertEquals(dialTarget("SIPS:bob@example.org", "sip:alice@pbx.example.com"), "SIPS:bob@example.org")
        assertEquals(dialTarget("tel:+15550100", "sip:alice@pbx.example.com"), "tel:+15550100")
        assertEquals(dialTarget("bob@example.org", "sip:alice@pbx.example.com"), "sip:bob@example.org")
    }

    @Test
    fun theRegistrarFieldIsAHostAndAPort() {
        assertEquals(hostPortOf("pbx.example.com:45421"), "pbx.example.com" to 45421)
        assertEquals(hostPortOf(" 192.0.2.10:5060 "), "192.0.2.10" to 5060)
        assertEquals(hostPortOf("[2001:db8::1]:5061"), "2001:db8::1" to 5061)
        assertNull(hostPortOf("pbx.example.com"))
        assertNull(hostPortOf(":5060"))
        assertNull(hostPortOf("pbx.example.com:0"))
        assertNull(hostPortOf("pbx.example.com:sip"))
        assertNull(hostPortOf("2001:db8::1:5060"))
    }

    @Test
    fun aRegistrarNamedByAHostIsLookedUpToAnAddressIPv4First() {
        val v4 = InetAddress.getByAddress("pbx.example.com", byteArrayOf(192.toByte(), 0, 2, 10))
        val v6 = InetAddress.getByAddress("pbx.example.com", ByteArray(16).also { it[0] = 0x20; it[1] = 0x01; it[15] = 1 })
        val asked = mutableListOf<String>()
        val lookup = { host: String -> asked += host; arrayOf(v6, v4) }
        assertEquals(registrarAddressOf("pbx.example.com:45421", lookup), "192.0.2.10:45421")
        assertEquals(asked, listOf("pbx.example.com"))
        assertEquals(registrarAddressOf("pbx.example.com:5060") { arrayOf(v6) }, "[2001:0:0:0:0:0:0:1]:5060")
        assertThrows(IllegalArgumentException::class.java) { registrarAddressOf("pbx.example.com", lookup) }
        assertThrows(UnknownHostException::class.java) { registrarAddressOf("nowhere.invalid:5060") { emptyArray() } }
    }

    @Test
    fun anAddressIsGivenAsItIs() {
        assertEquals(registrarAddressOf("192.0.2.10:5060"), "192.0.2.10:5060")
    }
}
