// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The diagnostics bundle on the JVM: no password the account holds, and no
// credential header from anywhere, reaches a byte of the zip; every line is
// stamped and the memory is bounded; a gap in inbound audio is measured from
// the last packet before it to the first after it.

package org.sipral.sample

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.time.ZoneOffset
import java.util.zip.ZipInputStream
import org.testng.Assert.assertEquals
import org.testng.Assert.assertFalse
import org.testng.Assert.assertNull
import org.testng.Assert.assertTrue
import org.testng.annotations.Test

class EvidenceTest {
    private fun unzip(bytes: ByteArray): Map<String, String> {
        val files = linkedMapOf<String, String>()
        ZipInputStream(ByteArrayInputStream(bytes)).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                files[entry.name] = zip.readBytes().toString(Charsets.UTF_8)
            }
        }
        return files
    }

    @Test
    fun noPasswordAndNoCredentialHeaderIsWritten() {
        val bundle = EvidenceBundle(listOf("s3cret-pass", "turn-pw-9", "ab"))
        bundle.add("events.txt", "registered with s3cret-pass\nturn turn-pw-9 and ab stays\n")
        bundle.add(
            "stack-log.txt",
            "TRACE sip REGISTER sip:pbx SIP/2.0\r\nAuthorization: Digest username=\"152\", response=\"0123abcd\"\r\n" +
                "Via: SIP/2.0/UDP 10.0.2.16\r\n2026-10-21T22:00:00.000+03:00 proxy-authorization:Digest nonce=\"x\"\r\n" +
                "WWW-Authenticate: Digest realm=\"asterisk\", nonce=\"abc\"\r\n",
        )
        val out = ByteArrayOutputStream()
        bundle.write(out)
        val raw = out.toByteArray()
        val text = String(raw, Charsets.ISO_8859_1)
        // zip entries are deflated, so the raw bytes prove nothing; the
        // unpacked text does
        val files = unzip(raw)
        assertEquals(files.keys, setOf("events.txt", "stack-log.txt"))
        val all = files.values.joinToString("\n")
        assertFalse(all.contains("s3cret-pass"), all)
        assertFalse(all.contains("turn-pw-9"), all)
        assertFalse(all.contains("0123abcd"), all)
        assertFalse(all.contains("nonce=\"x\""), all)
        assertTrue(all.contains("[password removed]"))
        assertTrue(all.contains("Authorization: [removed]"))
        assertTrue(all.contains("proxy-authorization: [removed]"))
        assertTrue(all.contains("realm=\"asterisk\""), "a challenge carries no secret and is kept")
        assertTrue(all.contains("ab stays"), "a password shorter than ${EvidenceBundle.MIN_SECRET} is not searched for")
        assertFalse(text.contains("s3cret-pass"))
    }

    @Test
    fun aPasswordInsideAnotherIsRemovedWhole() {
        val bundle = EvidenceBundle(listOf("pass", "password1"))
        assertEquals(bundle.scrub("x password1 y pass z"), "x [password removed] y [password removed] z")
    }

    @Test
    fun linesAreStampedAndTheOldestGoFirst() {
        var now = 1_760_000_000_000L
        val log = EventLog(3) { now }
        for (n in 1..5) {
            log.add("line $n")
            now += 1_000
        }
        val lines = log.text().trimEnd().split('\n')
        assertEquals(lines.first(), "(2 older lines were not kept)")
        assertEquals(lines.size, 4)
        assertTrue(lines[1].endsWith(" line 3"), lines[1])
        assertTrue(
            Regex("^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d\\.\\d{3}(?:[+-]\\d\\d:\\d\\d|Z) ").containsMatchIn(lines[1]),
            lines[1],
        )
        assertEquals(log.size, 3)
    }

    @Test
    fun aStampCarriesItsOffset() {
        assertEquals(stamp(0, ZoneOffset.ofHours(3)), "1970-01-01T03:00:00.000+03:00")
        assertEquals(stamp(1_500, ZoneOffset.UTC), "1970-01-01T00:00:01.500Z")
    }

    @Test
    fun aGapIsMeasuredFromTheLastPacketToTheFirstAfterIt() {
        val watch = MediaWatch(quietMs = 300)
        assertNull(watch.sample(0, 10))
        assertNull(watch.sample(250, 22))
        assertNull(watch.sample(500, 22), "250 ms without a packet is not yet a gap")
        assertEquals(watch.sample(750, 22), MediaWatch.Change.Stopped(250))
        assertNull(watch.sample(1_000, 22), "said once")
        assertEquals(watch.sample(2_250, 23), MediaWatch.Change.Back(2_000))
        assertNull(watch.sample(2_500, 40))
    }
}
