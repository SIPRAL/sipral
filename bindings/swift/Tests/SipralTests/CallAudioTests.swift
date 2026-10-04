// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Foundation
import XCTest
@testable import Sipral

/// A device that records what was asked of it, and can be made to refuse to
/// open or to stop on its own the way an engine does when its configuration
/// changes under it.
final class FakeCallAudioDevice: CallAudioDevice, @unchecked Sendable {
    private let lock = NSLock()
    private var _opened = 0
    private var _closed = 0
    private var _refuse = 0
    private(set) var live: FakeCallAudioStreams?

    var opened: Int { lock.withLock { _opened } }
    var closed: Int { lock.withLock { _closed } }

    /// How many opens to refuse before the next one succeeds.
    func refuse(_ count: Int) {
        lock.withLock { _refuse = count }
    }

    private var _dieAtOnce = false

    /// Every device opened from now on stops on its own a millisecond later.
    func dieAtOnce(_ value: Bool) {
        lock.withLock { _dieAtOnce = value }
    }

    func noteClosed() {
        lock.withLock { _closed += 1 }
    }

    func open(
        sampleRate: Int,
        frameSamples: Int,
        capture: @escaping @Sendable ([Int16]) -> Void,
        failed: @escaping @Sendable (String) -> Void
    ) throws -> CallAudioStreams {
        let serial = try lock.withLock { () -> Int in
            if _refuse > 0 {
                _refuse -= 1
                throw FakeRefusal.notYet
            }
            _opened += 1
            return _opened
        }
        let streams = FakeCallAudioStreams(device: self, serial: serial, frameSamples: frameSamples, capture: capture, failed: failed)
        let dies = lock.withLock { () -> Bool in
            live = streams
            return _dieAtOnce
        }
        if dies {
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(1)) { streams.stopOnItsOwn() }
        }
        return streams
    }
}

enum FakeRefusal: Error, CustomStringConvertible {
    case notYet
    var description: String { "the audio server is not back yet" }
}

final class FakeCallAudioStreams: CallAudioStreams, @unchecked Sendable {
    let serial: Int
    private let device: FakeCallAudioDevice
    private let failedCallback: @Sendable (String) -> Void
    private let lock = NSLock()
    private var _played: [[Int16]] = []
    private var _open = true
    private var timer: DispatchSourceTimer?

    init(
        device: FakeCallAudioDevice, serial: Int, frameSamples: Int,
        capture: @escaping @Sendable ([Int16]) -> Void, failed: @escaping @Sendable (String) -> Void
    ) {
        self.device = device
        self.serial = serial
        failedCallback = failed
        // a microphone producing a frame of this stream's serial every 5 ms
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "fake-mic-\(serial)"))
        timer.schedule(deadline: .now(), repeating: .milliseconds(5))
        timer.setEventHandler { capture([Int16](repeating: Int16(serial), count: frameSamples)) }
        timer.resume()
        self.timer = timer
    }

    var open: Bool { lock.withLock { _open } }
    var played: [[Int16]] { lock.withLock { _played } }

    /// What an engine does when a route change reconfigures it.
    func stopOnItsOwn() {
        failedCallback("the audio engine's configuration changed and it stopped")
    }

    func play(_ frame: [Int16]) {
        lock.withLock {
            if _open { _played.append(frame) }
        }
    }

    func close() {
        let was = lock.withLock { () -> Bool in
            defer { _open = false }
            return _open
        }
        precondition(was, "closed twice")
        timer?.cancel()
        device.noteClosed()
    }
}

/// Collects everything `CallAudio` sends to the far end.
final class SentFrames: @unchecked Sendable {
    private let lock = NSLock()
    private var frames: [[Int16]] = []

    func add(_ frame: [Int16]) { lock.withLock { frames.append(frame) } }
    func clear() { lock.withLock { frames.removeAll() } }
    var all: [[Int16]] { lock.withLock { frames } }
}

final class CallAudioTests: XCTestCase {
    private let frameSamples = 160

    private struct Rig {
        let device = FakeCallAudioDevice()
        let sent = SentFrames()
        let decoded: AsyncStream<[Int16]>
        let feed: AsyncStream<[Int16]>.Continuation
        let audio: CallAudio

        init(frameSamples: Int, retryDelays: [Double] = [0, 0.005, 0.01]) {
            let (stream, continuation) = AsyncStream<[Int16]>.makeStream()
            decoded = stream
            feed = continuation
            let sent = self.sent
            audio = CallAudio(
                sampleRate: 8000, frameSamples: frameSamples, frames: stream,
                send: { sent.add($0) }, device: device, retryDelays: retryDelays
            )
        }
    }

    private func wait(_ what: String, _ rig: Rig, _ condition: () -> Bool) {
        let deadline = Date().addingTimeInterval(5)
        while !condition() {
            if Date() > deadline {
                XCTFail("timed out waiting for \(what); saw \(rig.audio.history)")
                return
            }
            usleep(2000)
        }
    }

    /// Frames from the microphone of streams number `serial` reach the far end.
    private func sends(from serial: Int, _ rig: Rig) {
        rig.sent.clear()
        wait("a frame from streams \(serial)", rig) { rig.sent.all.contains { $0.first == Int16(serial) } }
    }

    private func plays(_ value: Int16, _ rig: Rig) {
        rig.feed.yield([Int16](repeating: value, count: frameSamples))
        wait("frame \(value) at the speaker", rig) { rig.device.live?.played.contains { $0.first == value } ?? false }
    }

    func testHeldAndTakenBackReopensTheDeviceAndDropsWhatArrivedMeanwhile() {
        let rig = Rig(frameSamples: frameSamples)
        rig.audio.start()
        wait("the device to open", rig) { rig.audio.state == .running }
        sends(from: 1, rig)
        plays(11, rig)
        rig.audio.pause(.held)
        XCTAssertEqual(rig.audio.state, .paused)
        wait("the device to be let go", rig) { rig.device.closed == 1 }
        rig.feed.yield([Int16](repeating: 99, count: frameSamples))
        usleep(50_000)
        rig.audio.resume(.held)
        wait("a new device", rig) { rig.device.opened == 2 && rig.audio.state == .running }
        sends(from: 2, rig)
        plays(12, rig)
        XCTAssertFalse(rig.device.live!.played.contains { $0.first == 99 }, "a frame from the hold played late")
        XCTAssertEqual(rig.audio.history, [.started, .paused([.held]), .resumed])
        rig.audio.close()
        XCTAssertEqual(rig.audio.state, .stopped)
        XCTAssertEqual(rig.audio.history.last, .stopped)
        wait("the device to be let go", rig) { rig.device.closed == 2 }
    }

    func testCallKitsSessionAndAHoldTogetherKeepTheDeviceShutUntilBothAreLifted() {
        let rig = Rig(frameSamples: frameSamples)
        rig.audio.pause(.sessionInactive)
        rig.audio.start()
        usleep(50_000)
        XCTAssertEqual(rig.device.opened, 0, "opened before CallKit activated the session")
        XCTAssertEqual(rig.audio.state, .paused)
        rig.audio.resume(.sessionInactive)
        wait("the device to open", rig) { rig.audio.state == .running }
        rig.audio.pause(.held)
        rig.audio.pause(.sessionInactive)
        rig.audio.resume(.held)
        usleep(50_000)
        XCTAssertEqual(rig.device.opened, 1)
        rig.audio.resume(.sessionInactive)
        wait("the device to open again", rig) { rig.device.opened == 2 }
        XCTAssertEqual(rig.audio.history, [
            .paused([.sessionInactive]), .started, .paused([.held]), .paused([.held, .sessionInactive]),
            .paused([.sessionInactive]), .resumed,
        ])
        rig.audio.close()
    }

    func testAnInterruptionTakesTheDeviceBackOnlyWhenTheSystemSaysTheCallMayResume() {
        let rig = Rig(frameSamples: frameSamples)
        rig.audio.start()
        wait("the device to open", rig) { rig.audio.state == .running }
        rig.audio.interruptionBegan()
        wait("the device to be let go", rig) { rig.device.closed == 1 }
        rig.audio.interruptionEnded(shouldResume: false)
        usleep(50_000)
        XCTAssertEqual(rig.device.opened, 1, "taken back without the system's leave")
        XCTAssertEqual(rig.audio.pauses, [.interrupted])
        rig.audio.resume(.interrupted)
        wait("the application's resume", rig) { rig.device.opened == 2 }

        rig.audio.interruptionBegan()
        rig.audio.interruptionEnded(shouldResume: true)
        wait("the system's resume", rig) { rig.device.opened == 3 && rig.audio.state == .running }
        XCTAssertEqual(rig.audio.history, [
            .started, .paused([.interrupted]), .interruptionEnded(shouldResume: false), .resumed,
            .paused([.interrupted]), .interruptionEnded(shouldResume: true), .resumed,
        ])
        rig.audio.close()
    }

    func testAMediaServicesResetBuildsTheDeviceAgainFromNothing() {
        let rig = Rig(frameSamples: frameSamples)
        rig.audio.start()
        wait("the device to open", rig) { rig.audio.state == .running }
        let first = rig.device.live
        rig.audio.mediaServicesLost()
        wait("the dead device to be let go", rig) { rig.device.closed == 1 }
        XCTAssertEqual(rig.audio.state, .recovering)
        usleep(50_000)
        XCTAssertEqual(rig.device.opened, 1, "opened while the media services were gone")
        rig.audio.mediaServicesReset()
        wait("a device built again", rig) { rig.device.opened == 2 && rig.audio.state == .running }
        XCTAssertFalse(rig.device.live === first)
        sends(from: 2, rig)
        plays(21, rig)
        XCTAssertEqual(rig.audio.history, [.started, .mediaServicesLost, .mediaServicesReset, .deviceRestored(attempts: 1)])
        rig.audio.close()
    }

    func testAResetWithoutALossFirstStillReplacesTheDevice() {
        let rig = Rig(frameSamples: frameSamples)
        rig.audio.start()
        wait("the device to open", rig) { rig.audio.state == .running }
        rig.audio.mediaServicesReset()
        wait("a device built again", rig) { rig.device.opened == 2 && rig.audio.state == .running }
        XCTAssertEqual(rig.device.closed, 1)
        rig.audio.close()
    }

    func testADeviceThatStopsOnItsOwnIsBuiltAgainAndOneThatWillNotOpenIsRetried() {
        let rig = Rig(frameSamples: frameSamples)
        rig.audio.start()
        wait("the device to open", rig) { rig.audio.state == .running }
        rig.device.refuse(2)
        let first = rig.device.live!
        first.stopOnItsOwn()
        wait("a device built again", rig) { rig.device.opened == 2 && rig.audio.state == .running }
        sends(from: 2, rig)
        XCTAssertEqual(rig.audio.history, [
            .started, .deviceFailed("the audio engine's configuration changed and it stopped"), .deviceRestored(attempts: 3),
        ])
        // a failure from streams already replaced is old news
        first.stopOnItsOwn()
        usleep(50_000)
        XCTAssertEqual(rig.device.opened, 2)
        XCTAssertEqual(rig.audio.state, .running)
        XCTAssertEqual(rig.audio.history.count, 3)
        rig.audio.close()
    }

    /// An engine that stops as soon as it starts, as one did on the iOS
    /// Simulator every time voice processing reconfigured it: each quick
    /// death waits a step longer before the next open, instead of rebuilding
    /// the device in a tight loop.
    func testADeviceThatDiesAsSoonAsItOpensIsRetriedSlowerAndSlower() {
        let rig = Rig(frameSamples: frameSamples, retryDelays: [0, 0.05, 0.1])
        rig.device.dieAtOnce(true)
        rig.audio.start()
        usleep(400_000)
        let opened = rig.device.opened
        XCTAssertGreaterThan(opened, 1, "a device that died was not opened again")
        XCTAssertLessThanOrEqual(opened, 12, "\(opened) opens in 400 ms: the device is being rebuilt in a loop")
        rig.device.dieAtOnce(false)
        wait("a device that stays up", rig) { rig.audio.state == .running && rig.device.live?.open == true }
        rig.audio.close()
    }

    func testMutedSendsSilenceAndARouteIsReportedOncePerChange() {
        let rig = Rig(frameSamples: frameSamples)
        rig.audio.start()
        wait("the device to open", rig) { rig.audio.state == .running }
        rig.audio.setMuted(true)
        sends(from: 0, rig)
        rig.audio.setMuted(false)
        sends(from: 1, rig)
        let car = CallAudioRoute(output: "Car", outputType: "CarAudio", reason: .newDeviceAvailable)
        rig.audio.routeChanged(car)
        rig.audio.routeChanged(car)
        let speaker = CallAudioRoute(output: "Speaker", outputType: "Speaker", reason: .oldDeviceUnavailable)
        rig.audio.routeChanged(speaker)
        XCTAssertEqual(rig.audio.history, [
            .started, .muteChanged(true), .muteChanged(false), .routeChanged(car), .routeChanged(speaker),
        ])
        rig.audio.close()
    }

    func testEveryTransitionReachesAReader() async {
        let rig = Rig(frameSamples: frameSamples)
        let reader = rig.audio.transitions()
        rig.audio.start()
        rig.audio.pause(.held)
        rig.audio.close()
        let seen = await drain(reader)
        XCTAssertEqual(seen.last, .stopped)
        XCTAssertTrue(seen.contains(.paused([.held])))
    }
}
