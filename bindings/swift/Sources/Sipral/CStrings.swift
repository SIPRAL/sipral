// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

/// Helpers for handing several C strings across the boundary at once.
///
/// Config structs carry more strings than one `withCString` can fill;
/// `CStrings.with` nests as many as needed, so each pointer lives exactly as
/// long as the call.

enum CStrings {
    /// Runs ``body`` with pointer/length pairs for ``strings``, each backed
    /// by a live `withCString` frame.
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
