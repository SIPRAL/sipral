// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import XCTest
@testable import Sipral

/// Everything `stream` yields, once it has finished; a failure, and what it
/// had yielded so far, when it has not within `seconds`.
func drain<Element: Sendable>(_ stream: AsyncStream<Element>, within seconds: Double = 10) async -> [Element] {
    let recorder = Recorder(stream)
    let finished = await recorder.finished(within: seconds)
    XCTAssertTrue(finished, "the stream did not finish within \(seconds) seconds")
    return recorder.elements
}

/// `Broadcast` on its own, with no stack: what every reader of
/// `SipralStack.events()`, `Call.events()`, `Call.dtmf()` and
/// `Media.frames()` is promised, pinned down with elements the test sends
/// itself.
final class BroadcastTests: XCTestCase {
    func testEveryReaderGetsEveryElementInOrder() async {
        let broadcast = Broadcast<Int>(label: "test", policy: .unbounded)
        let first = broadcast.stream()
        let second = broadcast.stream()
        let third = broadcast.stream()
        for value in 0..<100 {
            broadcast.send(value)
        }
        broadcast.finish()

        let expected = Array(0..<100)
        let seenFirst = await drain(first)
        let seenSecond = await drain(second)
        let seenThird = await drain(third)
        XCTAssertEqual(seenFirst, expected)
        XCTAssertEqual(seenSecond, expected)
        XCTAssertEqual(seenThird, expected)
    }

    func testConcurrentReadersEachGetEveryElement() async {
        let broadcast = Broadcast<Int>(label: "test", policy: .unbounded)
        let readers = (0..<8).map { _ in broadcast.stream() }
        let producer = Thread {
            for value in 0..<1000 {
                broadcast.send(value)
            }
            broadcast.finish()
        }

        let results = await withTaskGroup(of: [Int].self) { group -> [[Int]] in
            for reader in readers {
                group.addTask { await drain(reader) }
            }
            producer.start()
            var all: [[Int]] = []
            for await seen in group {
                all.append(seen)
            }
            return all
        }
        XCTAssertEqual(results.count, 8)
        for seen in results {
            XCTAssertEqual(seen, Array(0..<1000))
        }
    }

    func testALateReaderSeesNothingSentBeforeIt() async {
        let broadcast = Broadcast<Int>(label: "test", policy: .unbounded)
        broadcast.send(1)
        let late = broadcast.stream()
        broadcast.send(2)
        broadcast.finish()

        let seen = await drain(late)
        XCTAssertEqual(seen, [2])
    }

    func testFinishAfterHandsItsElementToLiveAndLaterReaders() async {
        let broadcast = Broadcast<String>(label: "test", policy: .unbounded)
        let live = broadcast.stream()
        broadcast.send("ringing")
        broadcast.finish(after: "ended")
        broadcast.send("after the end")
        broadcast.finish(after: "a second end")

        let seenLive = await drain(live)
        let seenLater = await drain(broadcast.stream())
        XCTAssertEqual(seenLive, ["ringing", "ended"])
        XCTAssertEqual(seenLater, ["ended"])
    }

    func testAPlainFinishHandsNothingToLaterReaders() async {
        let broadcast = Broadcast<Int>(label: "test", policy: .unbounded)
        broadcast.send(1)
        broadcast.finish()

        let seen = await drain(broadcast.stream())
        XCTAssertEqual(seen, [])
    }

    /// A reader that never reads keeps only its newest elements, and the
    /// reader beside it, which kept up, lost nothing to it.
    func testASlowReaderDropsItsOwnOldestAndNobodyElses() async {
        let broadcast = Broadcast<Int>(label: "test", policy: .bufferingNewest(3))
        let slow = broadcast.stream()
        let unbounded = broadcast.stream(bufferingPolicy: .unbounded)
        for value in 0..<10 {
            broadcast.send(value)
        }
        broadcast.finish()

        let seenSlow = await drain(slow)
        let seenUnbounded = await drain(unbounded)
        XCTAssertEqual(seenSlow, [7, 8, 9])
        XCTAssertEqual(seenUnbounded, Array(0..<10))
    }

    func testAReaderThatStopsIsForgotten() async {
        let broadcast = Broadcast<Int>(label: "test", policy: .unbounded)
        let staying = broadcast.stream()
        let quitter = Task { [events = broadcast.stream()] () -> Int? in
            for await value in events {
                return value
            }
            return nil
        }
        XCTAssertEqual(broadcast.readerCount, 2)

        broadcast.send(1)
        let quitterSaw = await quitter.value
        XCTAssertEqual(quitterSaw, 1)
        let forgotten = await eventually(within: 5) { broadcast.readerCount == 1 }
        XCTAssertTrue(forgotten, "a reader whose loop has ended must be forgotten")

        var dropped: AsyncStream<Int>? = broadcast.stream()
        XCTAssertEqual(broadcast.readerCount, 2)
        dropped = nil
        XCTAssertNil(dropped)
        XCTAssertEqual(broadcast.readerCount, 1, "a stream dropped unread must be forgotten")

        let cancelled = Task { [events = broadcast.stream()] in
            for await _ in events {}
        }
        XCTAssertEqual(broadcast.readerCount, 2)
        cancelled.cancel()
        let cancelledGone = await eventually(within: 5) { broadcast.readerCount == 1 }
        XCTAssertTrue(cancelledGone, "a reader whose task was cancelled must be forgotten")

        broadcast.send(2)
        broadcast.finish()
        XCTAssertEqual(broadcast.readerCount, 0)
        let seen = await drain(staying)
        XCTAssertEqual(seen, [1, 2])
    }
}
