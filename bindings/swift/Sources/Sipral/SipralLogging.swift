// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// How the stack's log levels meet the unified logging system's, for
// SipralStack.logTo(subsystem:level:).

#if canImport(os)
import Foundation
import os

extension SipralLogLevel {
    /// The `OSLogType` a line at this level is logged as by
    /// `SipralStack.logTo(subsystem:level:)`: the unified logging system has
    /// no level between `.default` and `.error` for a warning, and none below
    /// `.debug` for a trace line.
    public var osLogType: OSLogType {
        switch self {
        case .error: return .error
        case .warn: return .default
        case .info: return .info
        case .debug, .trace, .off: return .debug
        }
    }
}

/// One `os.Logger` per target under a subsystem, made the first time a line
/// for that target arrives, from whichever thread delivers it.
final class OSLoggers: @unchecked Sendable {
    private let subsystem: String
    private let lock = NSLock()
    private var byCategory: [String: Logger] = [:]

    init(subsystem: String) {
        self.subsystem = subsystem
    }

    func logger(for category: String) -> Logger {
        lock.lock()
        defer { lock.unlock() }
        if let known = byCategory[category] {
            return known
        }
        let made = Logger(subsystem: subsystem, category: category)
        byCategory[category] = made
        return made
    }
}
#endif
