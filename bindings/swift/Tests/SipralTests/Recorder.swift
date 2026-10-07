// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Dispatch
import Foundation
import XCTest

/// Whether `condition` came true within `seconds`, checked every 10 ms.
func eventually(within seconds: Double, _ condition: () async -> Bool) async -> Bool {
    let deadline = DispatchTime.now() + seconds
    while true {
        if await condition() { return true }
        if DispatchTime.now() >= deadline { return false }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
}

/// Records everything an `AsyncStream` yields, so a test can wait with a
/// deadline. Cancelling a `for await` task would finish the stream itself,
/// so the reader is never cancelled; a timed-out wait just stops looking.
final class Recorder<Element: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var seen: [Element] = []
    private var ended = false

    init(_ stream: AsyncStream<Element>) {
        Task { [self] in
            for await element in stream {
                append(element)
            }
            finish()
        }
    }

    private func append(_ element: Element) {
        lock.lock()
        defer { lock.unlock() }
        seen.append(element)
    }

    private func finish() {
        lock.lock()
        defer { lock.unlock() }
        ended = true
    }

    var elements: [Element] {
        lock.lock()
        defer { lock.unlock() }
        return seen
    }

    /// Whether the stream has finished and everything it yielded is in
    /// `elements`.
    var isFinished: Bool {
        lock.lock()
        defer { lock.unlock() }
        return ended
    }

    /// Whether the stream finished within `seconds`.
    func finished(within seconds: Double) async -> Bool {
        let deadline = DispatchTime.now() + seconds
        while !isFinished {
            if DispatchTime.now() >= deadline { return false }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        return true
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

/// The first element of `stream` that `predicate` accepts, or `nil` once
/// `seconds` have passed with none: a `for await` that cannot hang a test
/// when what it waits for never comes.
func firstOne<Element: Sendable>(
    of stream: AsyncStream<Element>, within seconds: Double = 5,
    where predicate: @escaping (Element) -> Bool = { _ in true }
) async -> Element? {
    await Recorder(stream).first(within: seconds, where: predicate)
}

/// Like `firstOne(of:within:where:)`, but the reader is gone afterwards
/// either way, for tests that count readers.
func firstOrGiveUp<Element: Sendable>(
    _ stream: AsyncStream<Element>, within seconds: Double,
    where predicate: @escaping @Sendable (Element) -> Bool = { _ in true }
) async -> Element? {
    await withTaskGroup(of: Element?.self) { group in
        group.addTask {
            for await element in stream where predicate(element) {
                return element
            }
            return nil
        }
        group.addTask {
            try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            return nil
        }
        let found = await group.next() ?? nil
        group.cancelAll()
        return found
    }
}
