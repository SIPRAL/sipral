// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

/// Helpers for handing several C strings across the boundary at once.
///
/// `SipralAbi.swift`'s printed wrappers each build one struct's pointer
/// members inside the call that reads them (`docs/08-ffi.md`, "Swift"), but
/// `sipral_account_config_t` and `sipral_call_config_t` carry more string
/// members than a caller can fill from one `withCString`. `CStrings.with`
/// nests as many as it is given, so every pointer stays valid for exactly
/// the length of the call that reads them and not a moment longer.

enum CStrings {
    /// Turns ``strings`` into pointer/length pairs, one call at a time, and
    /// only then runs ``body`` -- so every pointer ``body`` sees is still
    /// backed by a live `withCString` frame further up the stack.
    static func with<R>(
        _ strings: [String?],
        _ body: ([(pointer: UnsafePointer<CChar>?, count: Int)]) throws -> R
    ) rethrows -> R {
        func step(_ index: Int, _ acc: [(pointer: UnsafePointer<CChar>?, count: Int)]) throws -> R {
            guard index < strings.count else {
                return try body(acc)
            }
            guard let s = strings[index] else {
                return try step(index + 1, acc + [(nil, 0)])
            }
            return try s.withCString { ptr in
                try step(index + 1, acc + [(ptr, s.utf8.count)])
            }
        }
        return try step(0, [])
    }
}
