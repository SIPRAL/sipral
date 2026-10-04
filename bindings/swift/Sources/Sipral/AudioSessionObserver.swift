// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

// iOS only: `AVAudioSession` exists nowhere else a call runs. A Mac has no
// session to be interrupted, and its device changes reach an `AVAudioEngine`
// as the configuration-change notification `VoiceProcessingAudioDevice`
// already reports.
#if canImport(AVFoundation) && os(iOS)
@preconcurrency import AVFoundation

/// Carries what `AVAudioSession` says about the device onto a `CallAudio`,
/// for as long as it is kept:
///
/// - `interruptionNotification`: `.began` lets the device go
///   (`CallAudioPause.interrupted`); `.ended` reports whether the system
///   says the call may resume (`.shouldResume`), and takes the device back
///   when it does.
/// - `routeChangeNotification`: reported with the output the session is on
///   now and why it moved -- a headset or a car arriving
///   (`newDeviceAvailable`), the device the call was on gone
///   (`oldDeviceUnavailable`).
/// - `mediaServicesWereLostNotification` and
///   `mediaServicesWereResetNotification`: the device let go, then built
///   again from nothing.
///
/// The notifications are posted by the system on a thread of its choosing;
/// nothing here assumes the main one.
public final class AudioSessionObserver: @unchecked Sendable {
    private let center: NotificationCenter
    private let session: AVAudioSession
    private var tokens: [NSObjectProtocol] = []

    public init(
        audio: CallAudio,
        session: AVAudioSession = .sharedInstance(),
        center: NotificationCenter = .default
    ) {
        self.center = center
        self.session = session
        tokens = [
            center.addObserver(forName: AVAudioSession.interruptionNotification, object: session, queue: nil) { note in
                Self.interruption(note, audio)
            },
            center.addObserver(forName: AVAudioSession.routeChangeNotification, object: session, queue: nil) { [session] note in
                audio.routeChanged(Self.route(note, session))
            },
            center.addObserver(forName: AVAudioSession.mediaServicesWereLostNotification, object: session, queue: nil) { _ in
                audio.mediaServicesLost()
            },
            center.addObserver(forName: AVAudioSession.mediaServicesWereResetNotification, object: session, queue: nil) { _ in
                audio.mediaServicesReset()
            },
        ]
    }

    /// Stop observing. Also done when this is released.
    public func cancel() {
        for token in tokens {
            center.removeObserver(token)
        }
        tokens = []
    }

    deinit {
        cancel()
    }

    private static func interruption(_ note: Notification, _ audio: CallAudio) {
        guard let raw = note.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt,
              let type = AVAudioSession.InterruptionType(rawValue: raw) else { return }
        switch type {
        case .began:
            audio.interruptionBegan()
        case .ended:
            let options = (note.userInfo?[AVAudioSessionInterruptionOptionKey] as? UInt)
                .map(AVAudioSession.InterruptionOptions.init(rawValue:)) ?? []
            audio.interruptionEnded(shouldResume: options.contains(.shouldResume))
        @unknown default:
            break
        }
    }

    private static func route(_ note: Notification, _ session: AVAudioSession) -> CallAudioRoute {
        let reason: CallAudioRoute.Reason
        switch (note.userInfo?[AVAudioSessionRouteChangeReasonKey] as? UInt)
            .flatMap(AVAudioSession.RouteChangeReason.init(rawValue:)) {
        case .newDeviceAvailable?: reason = .newDeviceAvailable
        case .oldDeviceUnavailable?: reason = .oldDeviceUnavailable
        default: reason = .other
        }
        let output = session.currentRoute.outputs.first
        return CallAudioRoute(
            output: output?.portName ?? "none",
            outputType: output?.portType.rawValue ?? "none",
            reason: reason
        )
    }
}
#endif
