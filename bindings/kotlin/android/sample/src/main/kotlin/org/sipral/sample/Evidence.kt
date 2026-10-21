// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// What the Diagnostics screen hands over, with no Android in it, so that the
// JVM tests can hold it to what it promises: every line timestamped, a
// bounded memory, and no password in anything it writes.

package org.sipral.sample

import java.io.OutputStream
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** The wall-clock form every line and file name here is written in: local
 * time with its offset and milliseconds, so lines from the phone, the PBX
 * and a capture can be put side by side. */
fun stamp(wallMs: Long, zone: ZoneId = ZoneId.systemDefault()): String =
    DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSXXX").format(Instant.ofEpochMilli(wallMs).atZone(zone))

/**
 * Lines, each stamped with the wall clock when it was added, the newest
 * [capacity] kept. Safe from any thread: the stack's log arrives on its poll
 * thread, the sample's own events on the main one.
 */
class EventLog(private val capacity: Int, private val clock: () -> Long = System::currentTimeMillis) {
    private val lines = ArrayDeque<String>()
    private var dropped = 0L

    fun add(line: String): String {
        val stamped = "${stamp(clock())} $line"
        synchronized(lines) {
            lines.addLast(stamped)
            while (lines.size > capacity) {
                lines.removeFirst()
                dropped++
            }
        }
        return stamped
    }

    /** Everything kept, oldest first, with a first line saying how many
     * older ones went when there were more than [capacity]. */
    fun text(): String = synchronized(lines) {
        buildString {
            if (dropped > 0) {
                append("($dropped older lines were not kept)\n")
            }
            for (line in lines) {
                append(line).append('\n')
            }
        }
    }

    val size: Int get() = synchronized(lines) { lines.size }
}

/**
 * When inbound audio stopped and how long until it came back, from the
 * received-packet count read at intervals: the number a network change, a
 * Doze window or a radio handover costs a call. A count that does not move
 * for longer than [quietMs] is a gap; the first reading that moves again
 * ends it, and its length is from the last reading that had moved.
 */
class MediaWatch(private val quietMs: Long = 300) {
    private var lastCount = -1L
    private var lastMovedAt = 0L
    private var inGap = false

    sealed interface Change {
        data class Stopped(val sinceMs: Long) : Change
        data class Back(val gapMs: Long) : Change
    }

    fun sample(atMs: Long, received: Long): Change? {
        if (lastCount < 0 || received != lastCount) {
            val first = lastCount < 0
            lastCount = received
            val gap = atMs - lastMovedAt
            lastMovedAt = atMs
            if (inGap && !first) {
                inGap = false
                return Change.Back(gap)
            }
            return null
        }
        if (!inGap && atMs - lastMovedAt > quietMs) {
            inGap = true
            return Change.Stopped(lastMovedAt)
        }
        return null
    }
}

/**
 * One bundle: named text files in a zip, every one of them with every
 * [secrets] value replaced, and every credential header a SIP message could
 * carry cut back to its name, before a byte is written. The stack never
 * logs credentials (`docs/17-observability.md`); this is the second line,
 * for text that came from anywhere else, logcat included.
 */
class EvidenceBundle(private val secrets: List<String>) {
    private val files = linkedMapOf<String, String>()

    fun add(name: String, text: String) {
        files[name] = text
    }

    val names: Set<String> get() = files.keys

    fun write(out: OutputStream) {
        ZipOutputStream(out).use { zip ->
            for ((name, text) in files) {
                zip.putNextEntry(ZipEntry(name))
                zip.write(scrub(text).toByteArray(Charsets.UTF_8))
                zip.closeEntry()
            }
        }
    }

    fun scrub(text: String): String {
        val out = CREDENTIAL_HEADER.replace(text) { "${it.groupValues[1]}: [removed]" }
        // One pass over the text with every password as an alternative,
        // longest first: a password inside a longer one does not leave the
        // rest of the longer one behind, and a replacement is never searched
        // again for a password it happens to contain.
        val wanted = secrets.filter { it.length >= MIN_SECRET }.distinct().sortedByDescending { it.length }
        if (wanted.isEmpty()) {
            return out
        }
        return Regex(wanted.joinToString("|") { Regex.escape(it) }).replace(out, "[password removed]")
    }

    companion object {
        /** Passwords shorter than this are not searched for: one or two
         * characters would turn every log into noise. The account screen
         * says so. */
        const val MIN_SECRET = 4

        /** An `Authorization` or `Proxy-Authorization` header wherever it
         * sits on a line, value and all; a challenge carries no secret and
         * is kept. */
        private val CREDENTIAL_HEADER = Regex("(?i)\\b((?:Proxy-)?Authorization)[ \\t]*:[^\\r\\n]*")
    }
}
