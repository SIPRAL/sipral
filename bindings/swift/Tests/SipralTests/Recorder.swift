// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import Dispatch
import Foundation

/// Everything one `AsyncStream` yields, read by a single task for as long as
/// the stream lasts and kept, so that a test can wait for what it needs with
/// a deadline.
///
/// A deadline cannot be put on the `for await` loop itself: cancelling the
/// task that iterates an `AsyncStream` finishes the stream, and every later
/// read of `call.events` or `media.frames` would then come back empty. Here
/// nothing is ever cancelled -- the reader ends when the stream does -- and
/// a wait that runs out only stops looking.
final class Recorder<Element: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var seen: [Element] = []

    init(_ stream: AsyncStream<Element>) {
        Task { [self] in
            for await element in stream {
                append(element)
            }
        }
    }

    private func append(_ element: Element) {
        lock.lock()
        defer { lock.unlock() }
        seen.append(element)
    }

    var elements: [Element] {
        lock.lock()
        defer { lock.unlock() }
        return seen
    }

    /// The first element `predicate` accepts, past the first `skipped` ones,
    /// or `nil` once `seconds` have passed with none.
    func first(within seconds: Double, after skipped: Int = 0, where predicate: (Element) -> Bool) async -> Element? {
        let deadline = DispatchTime.now() + seconds
        while true {
            if let found = elements.dropFirst(skipped).first(where: predicate) { return found }
            if DispatchTime.now() >= deadline { return nil }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
    }

    /// How many elements `predicate` accepts once at least `count` of them
    /// have arrived, or however many there were when `seconds` ran out.
    func count(atLeast count: Int, within seconds: Double, where predicate: (Element) -> Bool) async -> Int {
        let deadline = DispatchTime.now() + seconds
        while true {
            let matching = elements.filter(predicate).count
            if matching >= count || DispatchTime.now() >= deadline { return matching }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
    }
}
