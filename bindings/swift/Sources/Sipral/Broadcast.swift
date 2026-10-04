// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Dispatch

/// Hands every element it is sent to every reader live at that moment.
///
/// One `AsyncStream` has one reader's worth of elements: two loops over the
/// same stream split them, each element going to whichever loop asked first,
/// so a `CallKitBridge` watching a call and an application watching the same
/// call would each see only part of it. This keeps one continuation per
/// reader instead, and `stream()` mints a fresh one on every call -- the
/// Swift counterpart of the Kotlin layer's `SharedFlow` with `replay = 0`
/// (`bindings/kotlin/README.md`).
///
/// - A reader sees what is sent from the moment `stream()` returns, and
///   nothing sent before it. The one exception is `finish(after:)`'s
///   element: a reader that arrives once this is finished gets that element
///   and is finished at once, so a loop waiting for the end always finds it.
/// - Every reader buffers on its own, under `policy`: a reader that falls
///   behind drops from its own buffer and never holds the others back.
/// - A reader that stops -- its loop left, its task cancelled, its stream
///   dropped -- is forgotten through `onTermination`, and nothing is sent to
///   it again.
/// - `send` and `finish(after:)` are called by whichever thread produces the
///   elements (a stack's poll thread, a media thread), one at a time, which
///   is what keeps every reader's order the order they were sent in.
///   `finish()` may come from any thread; whatever is sent after it is
///   dropped.
///
/// No continuation is ever touched while `queue` is held: `finish()` runs a
/// reader's `onTermination` on the calling thread, and that handler takes
/// `queue` itself.
final class Broadcast<Element: Sendable>: @unchecked Sendable {
    private let policy: AsyncStream<Element>.Continuation.BufferingPolicy
    private let queue: DispatchQueue
    private var readers: [UInt64: AsyncStream<Element>.Continuation] = [:]
    private var lastReader: UInt64 = 0
    private var finished = false
    private var finalElement: Element?

    init(label: String, policy: AsyncStream<Element>.Continuation.BufferingPolicy) {
        self.policy = policy
        self.queue = DispatchQueue(label: label)
    }

    /// A new reader, fed from now on.
    func stream() -> AsyncStream<Element> {
        stream(bufferingPolicy: policy)
    }

    /// A new reader with a buffering policy of its own.
    func stream(bufferingPolicy: AsyncStream<Element>.Continuation.BufferingPolicy) -> AsyncStream<Element> {
        AsyncStream(bufferingPolicy: bufferingPolicy) { continuation in
            let id = queue.sync { () -> UInt64 in
                lastReader &+= 1
                return lastReader
            }
            continuation.onTermination = { [weak self] _ in
                self?.forget(id)
            }
            let (registered, last) = queue.sync { () -> (Bool, Element?) in
                if finished { return (false, finalElement) }
                readers[id] = continuation
                return (true, nil)
            }
            guard !registered else { return }
            if let last {
                continuation.yield(last)
            }
            continuation.finish()
        }
    }

    func send(_ element: Element) {
        let targets = queue.sync { Array(readers.values) }
        for continuation in targets {
            continuation.yield(element)
        }
    }

    /// Finishes every reader, now and to come. `last`, when given, is sent to
    /// every live reader first and handed to every later one before it is
    /// finished. Only the first call does anything.
    func finish(after last: Element? = nil) {
        let targets = queue.sync { () -> [AsyncStream<Element>.Continuation]? in
            guard !finished else { return nil }
            finished = true
            finalElement = last
            defer { readers.removeAll() }
            return Array(readers.values)
        }
        for continuation in targets ?? [] {
            if let last {
                continuation.yield(last)
            }
            continuation.finish()
        }
    }

    /// How many readers are still being fed.
    var readerCount: Int {
        queue.sync { readers.count }
    }

    private func forget(_ id: UInt64) {
        _ = queue.sync { readers.removeValue(forKey: id) }
    }
}
