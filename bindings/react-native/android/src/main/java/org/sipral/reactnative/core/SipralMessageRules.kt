// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The message rules JavaScript sets (`setMessageRules`), applied by the
// client's message hook to each message as it passes: JavaScript is too far
// away to answer the hook itself. A field is matched by its name in any case
// and in either form RFC 3261 §7.3.3 gives it, as the core's own Rewrite
// does; the body, and so Content-Length, is never touched.

package org.sipral.reactnative.core

/** One rule, as `MessageRule` in `src/types.ts` has it: [outgoing] null
 * for both directions, [method] null for every method. */
data class SipralMessageRule(
    val outgoing: Boolean? = null,
    val method: String? = null,
    val set: List<Pair<String, String>> = emptyList(),
    val add: List<Pair<String, String>> = emptyList(),
    val remove: List<String> = emptyList(),
) {
    companion object {
        /** The rules in [text], as `setMessageRules` crosses them: one
         * directive a line, `rule <outgoing|incoming|*> <method|*>` opening
         * each rule, then `set name:value`, `add name:value` and
         * `remove name` lines. */
        fun parse(text: String): List<SipralMessageRule> {
            val rules = mutableListOf<SipralMessageRule>()
            for (line in text.split('\n').filter { it.isNotEmpty() }) {
                val directive = line.substringBefore(' ')
                val rest = line.substringAfter(' ', "")
                if (directive == "rule") {
                    val parts = rest.split(' ')
                    if (parts.size != 2) throw refused("a rule line names a direction and a method")
                    val outgoing = when (parts[0]) {
                        "*" -> null
                        "outgoing" -> true
                        "incoming" -> false
                        else -> throw refused("a rule's direction is outgoing or incoming, not ${parts[0]}")
                    }
                    rules += SipralMessageRule(outgoing, parts[1].takeIf { it != "*" })
                    continue
                }
                val last = rules.lastOrNull() ?: throw refused("a $directive line comes after a rule line")
                rules[rules.size - 1] = when (directive) {
                    "set", "add" -> {
                        if (':' !in rest) throw refused("a $directive line is name:value")
                        val field = rest.substringBefore(':') to rest.substringAfter(':')
                        check(field.first)
                        if ('\r' in field.second) throw refused("a field's value is one line")
                        if (directive == "set") last.copy(set = last.set + field) else last.copy(add = last.add + field)
                    }
                    "remove" -> {
                        check(rest)
                        last.copy(remove = last.remove + rest)
                    }
                    else -> throw refused("$directive is no rule directive")
                }
            }
            return rules
        }

        private fun check(name: String) {
            if (name.isEmpty() || name.any { it in ": \t\r\n" }) {
                throw refused("a field name is a token, without a colon, a space or a line break")
            }
            if (canonical(name) == "content-length") throw refused("Content-Length is the library's")
        }

        private fun refused(why: String) = SipralRefusal("invalidArgument", why)

        /** [message] with every rule that fits it applied, or null when none
         * changed it (or it cannot be taken apart, which the stack then
         * reads as it came). */
        fun apply(rules: List<SipralMessageRule>, outgoing: Boolean, message: ByteArray): ByteArray? {
            val fitting = rules.filter { it.outgoing == null || it.outgoing == outgoing }
            if (fitting.isEmpty()) return null
            val parsed = Parsed.of(message) ?: return null
            var changed = false
            for (rule in fitting) {
                if (rule.method != null && rule.method != parsed.method) continue
                for (field in rule.remove) {
                    changed = parsed.remove(field) || changed
                }
                for ((name, value) in rule.set) {
                    parsed.set(name, value)
                    changed = true
                }
                for ((name, value) in rule.add) {
                    parsed.lines += "$name: $value"
                    changed = true
                }
            }
            return if (changed) parsed.bytes() else null
        }

        /** The full name of a field, lower case, whichever form it was written in. */
        internal fun canonical(name: String): String {
            val lower = name.trim().lowercase()
            return COMPACT[lower] ?: lower
        }

        private val COMPACT = mapOf(
            "a" to "accept-contact", "u" to "allow-events", "i" to "call-id", "m" to "contact",
            "e" to "content-encoding", "l" to "content-length", "c" to "content-type", "o" to "event",
            "f" to "from", "y" to "identity", "r" to "refer-to", "b" to "referred-by", "j" to "reject-contact",
            "d" to "request-disposition", "x" to "session-expires", "s" to "subject", "k" to "supported",
            "t" to "to", "v" to "via",
        )
    }

    /** A message taken apart: its start line, each field as written (a
     * folded one with its continuation lines), and its body untouched. */
    private class Parsed(val start: String, val lines: MutableList<String>, val body: ByteArray) {
        /** A request's method, or a response's by its CSeq. */
        val method: String?
            get() = if (start.startsWith("SIP/")) {
                lines.firstOrNull { nameOf(it) == "cseq" }?.substringAfter(':')?.trim()?.split(' ')?.lastOrNull()
            } else {
                start.substringBefore(' ').takeIf { it.isNotEmpty() }
            }

        fun remove(field: String): Boolean {
            val wanted = canonical(field)
            return lines.removeAll { nameOf(it) == wanted }
        }

        fun set(field: String, value: String) {
            val wanted = canonical(field)
            val first = lines.indexOfFirst { nameOf(it) == wanted }
            if (first < 0) {
                lines += "$field: $value"
                return
            }
            lines[first] = "$field: $value"
            for (index in lines.indices.reversed()) {
                if (index > first && nameOf(lines[index]) == wanted) lines.removeAt(index)
            }
        }

        fun bytes(): ByteArray =
            (listOf(start) + lines).joinToString("\r\n").toByteArray(Charsets.UTF_8) +
                "\r\n\r\n".toByteArray(Charsets.UTF_8) + body

        companion object {
            fun of(message: ByteArray): Parsed? {
                var end = -1
                for (index in 0..message.size - 4) {
                    if (message[index] == 13.toByte() && message[index + 1] == 10.toByte() &&
                        message[index + 2] == 13.toByte() && message[index + 3] == 10.toByte()
                    ) {
                        end = index
                        break
                    }
                }
                if (end < 0) return null
                val decoder = Charsets.UTF_8.newDecoder()
                val head = try {
                    decoder.decode(java.nio.ByteBuffer.wrap(message, 0, end)).toString()
                } catch (_: java.nio.charset.CharacterCodingException) {
                    return null
                }
                val all = head.split("\r\n")
                val lines = mutableListOf<String>()
                for (line in all.drop(1)) {
                    if ((line.startsWith(" ") || line.startsWith("\t")) && lines.isNotEmpty()) {
                        lines[lines.size - 1] = lines.last() + "\r\n" + line
                    } else {
                        lines += line
                    }
                }
                return Parsed(all.first(), lines, message.copyOfRange(end + 4, message.size))
            }

            private fun nameOf(line: String): String? =
                line.indexOf(':').takeIf { it >= 0 }?.let { canonical(line.substring(0, it)) }
        }
    }
}
