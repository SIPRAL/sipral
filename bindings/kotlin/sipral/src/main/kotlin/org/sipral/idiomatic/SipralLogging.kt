// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// How the stack's log levels meet java.util.logging's, for
// SipralClient.logTo.

package org.sipral.idiomatic

import java.util.logging.Level
import java.util.logging.Logger
import org.sipral.SipralLogLevel

/** The `java.util.logging` level a line at [level] is logged at by
 * [SipralClient.logTo]. */
fun julLevelOf(level: SipralLogLevel): Level = when (level) {
    SipralLogLevel.ERROR -> Level.SEVERE
    SipralLogLevel.WARN -> Level.WARNING
    SipralLogLevel.INFO -> Level.INFO
    SipralLogLevel.DEBUG -> Level.FINE
    SipralLogLevel.TRACE -> Level.FINEST
    SipralLogLevel.OFF -> Level.OFF
}

/** The quietest stack level that still carries every line a logger at
 * [level] keeps. */
fun logLevelFor(level: Level): SipralLogLevel = when {
    level.intValue() == Level.OFF.intValue() -> SipralLogLevel.OFF
    level.intValue() <= Level.FINEST.intValue() -> SipralLogLevel.TRACE
    level.intValue() <= Level.FINE.intValue() -> SipralLogLevel.DEBUG
    level.intValue() <= Level.INFO.intValue() -> SipralLogLevel.INFO
    level.intValue() <= Level.WARNING.intValue() -> SipralLogLevel.WARN
    else -> SipralLogLevel.ERROR
}

/** [logger]'s own level, or the nearest ancestor's that has one: what
 * `java.util.logging` itself filters by. */
internal fun effectiveLevel(logger: Logger): Level {
    var at: Logger? = logger
    while (at != null) {
        at.level?.let { return it }
        at = at.parent
    }
    return Level.INFO
}
