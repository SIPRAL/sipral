// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The caller read from an INVITE, and whether two caller URIs match by
// docs/15-mobile.md's rule.
//
// The library already matched the INVITE to an announcement, but which one
// does not cross the generated JNI shim (docs/08-ffi.md, "Kotlin"). With
// one outstanding there is nothing to choose; with several, TelecomBridge
// applies the same rule with the library's tie-break (oldest first), so the
// two agree whenever their URI readings do.

package org.sipral.telecom

import java.net.InetAddress

/** The `From` URI and display name, or nulls when absent. */
internal data class CallerId(val uri: String?, val displayName: String?)

internal fun callerOf(message: ByteArray?): CallerId {
    if (message == null) {
        return CallerId(null, null)
    }
    val text = String(message, Charsets.UTF_8)
    val head = text.substringBefore("\r\n\r\n")
    // unfold continuation lines (RFC 3261 §7.3.1) before reading headers
    val lines = mutableListOf<String>()
    for (line in head.split("\r\n")) {
        if (line.isNotEmpty() && (line[0] == ' ' || line[0] == '\t') && lines.isNotEmpty()) {
            lines[lines.size - 1] = lines.last() + " " + line.trim()
        } else {
            lines.add(line)
        }
    }
    for (line in lines.drop(1)) {
        val colon = line.indexOf(':')
        if (colon <= 0) {
            continue
        }
        val name = line.substring(0, colon).trim()
        if (!name.equals("From", ignoreCase = true) && !name.equals("f", ignoreCase = true)) {
            continue
        }
        return parseNameAddr(line.substring(colon + 1).trim())
    }
    return CallerId(null, null)
}

private fun parseNameAddr(value: String): CallerId {
    val open = value.indexOf('<')
    if (open >= 0) {
        val close = value.indexOf('>', open)
        val uri = if (close > open) value.substring(open + 1, close) else value.substring(open + 1)
        val name = value.substring(0, open).trim().removeSurrounding("\"").trim()
        return CallerId(uri.trim(), name.ifEmpty { null })
    }
    // addr-spec: after the first ';' come header parameters (`;tag=`), not
    // the URI (RFC 3261 §20.10)
    return CallerId(value.substringBefore(';').trim(), null)
}

/**
 * The rule: for `sip:`/`sips:` URIs, the same user part (unescaped,
 * case-sensitive) and the same host (case-insensitive, an IP literal
 * compared as an address); nothing else about the URI. Any other scheme
 * falls back to comparing the URI whole, ignoring case.
 */
internal fun sameCaller(announced: String, invited: String): Boolean {
    val a = SipParts.of(announced)
    val b = SipParts.of(invited)
    if (a == null || b == null) {
        return announced.trim().equals(invited.trim(), ignoreCase = true)
    }
    return a.user == b.user && sameHost(a.host, b.host)
}

private class SipParts(val user: String?, val host: String) {
    companion object {
        fun of(uri: String): SipParts? {
            val trimmed = uri.trim()
            val colon = trimmed.indexOf(':')
            if (colon < 0) {
                return null
            }
            val scheme = trimmed.substring(0, colon).lowercase()
            if (scheme != "sip" && scheme != "sips") {
                return null
            }
            val rest = trimmed.substring(colon + 1)
            val at = rest.lastIndexOf('@')
            val userinfo = if (at >= 0) rest.substring(0, at) else null
            val hostport = (if (at >= 0) rest.substring(at + 1) else rest).substringBefore(';').substringBefore('?')
            val host = if (hostport.startsWith("[")) {
                hostport.substringBefore(']') + "]"
            } else {
                hostport.substringBefore(':')
            }
            val user = userinfo?.substringBefore(':')?.let(::unescape)
            return SipParts(user, host)
        }
    }
}

private val IPV4 = Regex("""\d{1,3}(\.\d{1,3}){3}""")

private fun sameHost(a: String, b: String): Boolean {
    val aLiteral = a.startsWith("[") || IPV4.matches(a)
    val bLiteral = b.startsWith("[") || IPV4.matches(b)
    if (aLiteral != bLiteral) {
        return false
    }
    if (!aLiteral) {
        return a.equals(b, ignoreCase = true)
    }
    return try {
        // literals only: parsed, never resolved
        InetAddress.getByName(a.removeSurrounding("[", "]")) == InetAddress.getByName(b.removeSurrounding("[", "]"))
    } catch (_: Exception) {
        a.equals(b, ignoreCase = true)
    }
}

private fun unescape(text: String): String {
    if ('%' !in text) {
        return text
    }
    val out = java.io.ByteArrayOutputStream()
    var i = 0
    while (i < text.length) {
        val c = text[i]
        if (c == '%' && i + 2 < text.length) {
            val hex = text.substring(i + 1, i + 3).toIntOrNull(16)
            if (hex != null) {
                out.write(hex)
                i += 3
                continue
            }
        }
        out.write(c.toString().toByteArray(Charsets.UTF_8))
        i += 1
    }
    return String(out.toByteArray(), Charsets.UTF_8)
}
