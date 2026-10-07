// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

// iOS only: on a Mac, device changes arrive as the engine's configuration
// change, which `VoiceProcessingAudioDevice` handles.
#if canImport(AVFoundation) && os(iOS)
@preconcurrency import AVFoundation

/// Forwards `AVAudioSession` notifications to a `CallAudio` while kept:
/// interruptions (resuming only when `.shouldResume`), route changes, and
/// media services lost and reset. Notifications may arrive on any thread.
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
