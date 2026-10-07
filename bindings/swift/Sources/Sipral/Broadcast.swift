// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Dispatch

/// Hands every element it is sent to every reader live at that moment.
///
/// Two loops over one `AsyncStream` split its elements, so each reader gets
/// its own continuation here.
///
/// - A reader sees only what is sent after `stream()` returns, except that a
///   reader arriving after `finish(after:)` still gets that last element, so
///   a loop waiting for the end always ends.
/// - Each reader buffers under `policy` and never holds others back.
/// - A stopped reader is forgotten through `onTermination`.
/// - `send` and `finish(after:)` come from the one producing thread, which
///   keeps order; `finish()` may come from any thread.
///
/// No continuation is touched while `queue` is held: `onTermination` runs on
/// the finishing thread and takes `queue` itself.
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

    /// Finishes every reader, present and future, after sending `last` if
    /// given. Only the first call has effect.
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
