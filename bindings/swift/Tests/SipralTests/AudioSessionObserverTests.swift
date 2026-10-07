// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

// iOS only. The simulator cannot raise these notifications, so they are
// posted here exactly as the system would.
#if canImport(AVFoundation) && os(iOS)
@preconcurrency import AVFoundation
import XCTest
@testable import Sipral

final class AudioSessionObserverTests: XCTestCase {
    private func running() async throws -> (CallAudio, FakeCallAudioDevice, AudioSessionObserver) {
        let device = FakeCallAudioDevice()
        let audio = CallAudio(
            sampleRate: 8000, frameSamples: 160, frames: AsyncStream { _ in }, send: { _ in }, device: device,
            retryDelays: [0]
        )
        let observer = AudioSessionObserver(audio: audio)
        audio.start()
        let open = await eventually(within: 5) { audio.state == .running }
        XCTAssertTrue(open)
        return (audio, device, observer)
    }

    private func post(_ name: Notification.Name, _ userInfo: [AnyHashable: Any]? = nil) {
        NotificationCenter.default.post(name: name, object: AVAudioSession.sharedInstance(), userInfo: userInfo)
    }

    func testAnInterruptionLetsTheDeviceGoAndItsEndTakesItBackWhenTheSystemSaysSo() async throws {
        let (audio, device, observer) = try await running()
        defer { observer.cancel(); audio.close() }

        post(AVAudioSession.interruptionNotification, [
            AVAudioSessionInterruptionTypeKey: AVAudioSession.InterruptionType.began.rawValue,
        ])
        XCTAssertEqual(audio.pauses, [.interrupted])
        post(AVAudioSession.interruptionNotification, [
            AVAudioSessionInterruptionTypeKey: AVAudioSession.InterruptionType.ended.rawValue,
            AVAudioSessionInterruptionOptionKey: AVAudioSession.InterruptionOptions.shouldResume.rawValue,
        ])
        let back = await eventually(within: 5) { device.opened == 2 && audio.state == .running }
        XCTAssertTrue(back, "the device was not taken back: \(audio.history)")

        post(AVAudioSession.interruptionNotification, [
            AVAudioSessionInterruptionTypeKey: AVAudioSession.InterruptionType.began.rawValue,
        ])
        post(AVAudioSession.interruptionNotification, [
            AVAudioSessionInterruptionTypeKey: AVAudioSession.InterruptionType.ended.rawValue,
        ])
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(audio.pauses, [.interrupted], "taken back without shouldResume")
        XCTAssertEqual(device.opened, 2)
        XCTAssertEqual(audio.history, [
            .started, .paused([.interrupted]), .interruptionEnded(shouldResume: true), .resumed,
            .paused([.interrupted]), .interruptionEnded(shouldResume: false),
        ])
    }

    func testARouteChangeIsReportedWithWhyItMoved() async throws {
        let (audio, _, observer) = try await running()
        defer { observer.cancel(); audio.close() }

        post(AVAudioSession.routeChangeNotification, [
            AVAudioSessionRouteChangeReasonKey: AVAudioSession.RouteChangeReason.oldDeviceUnavailable.rawValue,
        ])
        post(AVAudioSession.routeChangeNotification, [
            AVAudioSessionRouteChangeReasonKey: AVAudioSession.RouteChangeReason.newDeviceAvailable.rawValue,
        ])
        let output = AVAudioSession.sharedInstance().currentRoute.outputs.first
        let name = output?.portName ?? "none"
        let type = output?.portType.rawValue ?? "none"
        XCTAssertEqual(audio.history, [
            .started,
            .routeChanged(CallAudioRoute(output: name, outputType: type, reason: .oldDeviceUnavailable)),
            .routeChanged(CallAudioRoute(output: name, outputType: type, reason: .newDeviceAvailable)),
        ])
    }

    func testTheMediaServicesGoingAndComingBackBuildANewDevice() async throws {
        let (audio, device, observer) = try await running()
        defer { observer.cancel(); audio.close() }
        let first = device.live

        post(AVAudioSession.mediaServicesWereLostNotification)
        let letGo = await eventually(within: 5) { device.closed == 1 }
        XCTAssertTrue(letGo)
        XCTAssertEqual(audio.state, .recovering)
        post(AVAudioSession.mediaServicesWereResetNotification)
        let rebuilt = await eventually(within: 5) { device.opened == 2 && audio.state == .running }
        XCTAssertTrue(rebuilt)
        XCTAssertFalse(device.live === first, "the device from before the reset was reused")
        XCTAssertEqual(audio.history, [.started, .mediaServicesLost, .mediaServicesReset, .deviceRestored(attempts: 1)])
    }

    func testACancelledObserverChangesNothing() async throws {
        let (audio, device, observer) = try await running()
        defer { audio.close() }
        observer.cancel()
        post(AVAudioSession.interruptionNotification, [
            AVAudioSessionInterruptionTypeKey: AVAudioSession.InterruptionType.began.rawValue,
        ])
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(audio.pauses, [])
        XCTAssertEqual(device.closed, 0)
    }

    /// The real device on the simulator, rebuilt after a posted media
    /// services reset. Opt-in (`SIPRAL_AUDIO_DEVICE=1`): it records from the
    /// Mac's microphone.
    func testTheVoiceProcessingDeviceIsBuiltAgainAfterAReset() async throws {
        guard ProcessInfo.processInfo.environment["SIPRAL_AUDIO_DEVICE"] == "1" else {
            throw XCTSkip("set SIPRAL_AUDIO_DEVICE=1 to open the real microphone and speaker")
        }
        let sent = SentFrames()
        let audio = CallAudio(
            sampleRate: 16000, frameSamples: 320, frames: AsyncStream { _ in }, send: { sent.add($0) },
            device: VoiceProcessingAudioDevice(managesSession: true)
        )
        let observer = AudioSessionObserver(audio: audio)
        defer { observer.cancel(); audio.close() }
        audio.start()
        let open = await eventually(within: 10) { audio.state == .running && !sent.all.isEmpty }
        XCTAssertTrue(open, "no frame from the microphone: \(audio.history)")

        post(AVAudioSession.mediaServicesWereResetNotification)
        sent.clear()
        let rebuilt = await eventually(within: 10) { audio.state == .running && !sent.all.isEmpty }
        XCTAssertTrue(rebuilt, "no frame from the rebuilt engine: \(audio.history)")
        XCTAssertEqual(audio.history.suffix(2), [.mediaServicesReset, .deviceRestored(attempts: 1)])
    }
}
#endif
