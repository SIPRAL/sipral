// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Dispatch
import Foundation

/// Why a call's audio device is let go while the call goes on.
public enum CallAudioPause: Hashable, Sendable {
    /// On hold, by CallKit (`CXSetHeldCallAction`) or the application.
    case held

    /// The system interrupted the audio session without CallKit holding the
    /// call (`AVAudioSession.interruptionNotification`, `.began`).
    case interrupted

    /// CallKit has not activated the session, or deactivated it: Apple
    /// requires call audio to wait for `didActivate`.
    case sessionInactive
}

/// Where a call's audio stands.
public enum CallAudioState: Sendable, Equatable {
    /// Not started yet.
    case idle
    case running
    /// Let go on purpose, for the reasons in `CallAudio.pauses`.
    case paused
    /// The device failed, or the media services went, and it is being
    /// opened again.
    case recovering
    /// The call is over, and so is its audio.
    case stopped
}

/// Where the platform sent a call's audio, and why it moved.
public struct CallAudioRoute: Equatable, Sendable {
    public enum Reason: Equatable, Sendable {
        /// A headset, a Bluetooth device or a car became available.
        case newDeviceAvailable
        /// The device the call was on went: unplugged, switched off, out of
        /// range, the car turned off.
        case oldDeviceUnavailable
        /// Anything else the session reports: a category change, an
        /// override to the speaker, a configuration change.
        case other
    }

    /// The output's own name, as the system shows it ("Speaker", "AirPods").
    public let output: String
    /// The output's port type, `AVAudioSession.Port`'s raw value
    /// ("Speaker", "Receiver", "BluetoothHFP", "CarAudio", "Headphones").
    public let outputType: String
    public let reason: Reason

    public init(output: String, outputType: String, reason: Reason) {
        self.output = output
        self.outputType = outputType
        self.reason = reason
    }
}

/// One thing that happened to a call's audio, in the order it happened.
public enum CallAudioTransition: Equatable, Sendable {
    /// The device was opened for the first time and is carrying the call.
    case started
    /// The device was released; the set is every current reason, reported
    /// each time it changes without emptying.
    case paused(Set<CallAudioPause>)
    /// The last reason was lifted and a device is open again.
    case resumed
    /// The interruption ended. With `shouldResume` false the device stays
    /// released, as Apple asks, until `resume(.interrupted)`.
    case interruptionEnded(shouldResume: Bool)
    /// The platform moved the audio. Reported only; a device stopped by the
    /// move reports that itself.
    case routeChanged(CallAudioRoute)
    /// The call was muted or unmuted (`CXSetMutedCallAction`). While muted
    /// the far end is sent silence.
    case muteChanged(Bool)
    /// Media services were lost: every audio object in the process is dead.
    case mediaServicesLost
    /// Media services were reset; the device is being rebuilt.
    case mediaServicesReset
    /// The device failed or would not open, and why. Reported once per
    /// failure; it is opened again until it opens.
    case deviceFailed(String)
    /// A device opened again after `deviceFailed`, at the `attempts`th try.
    case deviceRestored(attempts: Int)
    /// The call is over and the device closed for good.
    case stopped
}

/// A call's microphone and speaker. `open` builds both from nothing each
/// time, as recovery from a media services reset requires.
public protocol CallAudioDevice: AnyObject, Sendable {
    /// `capture` gets 16-bit mono samples at `sampleRate`, in any length, on
    /// any thread. `failed` is called once if the device stops by itself.
    func open(
        sampleRate: Int,
        frameSamples: Int,
        capture: @escaping @Sendable ([Int16]) -> Void,
        failed: @escaping @Sendable (String) -> Void
    ) throws -> CallAudioStreams
}

/// What `CallAudioDevice.open` returned.
public protocol CallAudioStreams: AnyObject, Sendable {
    /// Queue one frame for the speaker. May be called once after `close()`
    /// has begun elsewhere, and must then do nothing.
    func play(_ frame: [Int16])
    /// Stop for good. Called on its own queue.
    func close()
}

/// One call's audio between a `CallAudioDevice` and the call's `Media`,
/// kept alive through what iOS does to it in the middle of a call.
///
/// `pause` closes the device so the session's new owner has it; lifting the
/// last reason opens a new one. A failing device is retried after
/// `retryDelays`, the last repeating while the call lasts. Meanwhile
/// `Media`'s own frame clock sends silence, so the stream has no gap, and
/// frames arriving while released are dropped so playback resumes live.
///
/// Fed by `AudioSessionObserver` (iOS), `CallKitBridge` (hold, mute,
/// session activation) and `follow(_:)` (the call's end). Every change is a
/// `transitions()` item; `history` keeps the last 64.
public final class CallAudio: @unchecked Sendable {
    private let device: CallAudioDevice
    private let sampleRate: Int
    private let frameSamples: Int
    private let send: @Sendable ([Int16]) -> Void
    private let retryDelays: [Double]
    private let frames: AsyncStream<[Int16]>

    /// Guards everything below it.
    private let queue = DispatchQueue(label: "org.sipral.call-audio.state")
    /// Opens and closes off the caller's thread: both can block on the
    /// audio server.
    private let deviceQueue = DispatchQueue(label: "org.sipral.call-audio.device")

    private var current: CallAudioStreams?
    private var generation = 0
    private var pauseSet: Set<CallAudioPause> = []
    private var started = false
    private var stopped = false
    private var everOpened = false
    private var failing = false
    private var attempts = 0
    private var openedAt: DispatchTime?
    private var shortLivedInARow = 0
    private var openScheduled = false
    private var muted = false
    private var lastRoute: CallAudioRoute?
    private var _state = CallAudioState.idle
    private var _history: [CallAudioTransition] = []
    private var playback: Task<Void, Never>?
    private var following: Task<Void, Never>?

    private let broadcast = Broadcast<CallAudioTransition>(
        label: "org.sipral.call-audio.transitions", policy: .bufferingNewest(64)
    )

    /// Opened again at once, then after 100 ms, 250 ms, 500 ms, one second,
    /// and every two seconds after that.
    public static let defaultRetryDelays: [Double] = [0, 0.1, 0.25, 0.5, 1, 2]

    /// Over one call's `Media`.
    public convenience init(media: Media, device: CallAudioDevice, retryDelays: [Double] = CallAudio.defaultRetryDelays) {
        self.init(
            sampleRate: media.sampleRate,
            frameSamples: media.frameSamples,
            frames: media.frames(),
            send: { [weak media] samples in media?.sendAudio(samples) },
            device: device,
            retryDelays: retryDelays
        )
    }

    /// Over any source of decoded frames and any sink for captured ones.
    public init(
        sampleRate: Int,
        frameSamples: Int,
        frames: AsyncStream<[Int16]>,
        send: @escaping @Sendable ([Int16]) -> Void,
        device: CallAudioDevice,
        retryDelays: [Double] = CallAudio.defaultRetryDelays
    ) {
        precondition(!retryDelays.isEmpty, "at least one retry delay is needed")
        self.sampleRate = sampleRate
        self.frameSamples = frameSamples
        self.frames = frames
        self.send = send
        self.device = device
        self.retryDelays = retryDelays
    }

    // MARK: - reading it

    public var state: CallAudioState { queue.sync { _state } }

    /// Every reason the device is let go for; empty while it runs.
    public var pauses: Set<CallAudioPause> { queue.sync { pauseSet } }

    /// The last 64 transitions, oldest first.
    public var history: [CallAudioTransition] { queue.sync { _history } }

    /// A new reader of every transition from now on; see `Broadcast`.
    public func transitions() -> AsyncStream<CallAudioTransition> {
        broadcast.stream()
    }

    // MARK: - driving it

    /// Open the device unless paused, and start moving frames. Once only.
    public func start() {
        let first = queue.sync { () -> Bool in
            guard !started, !stopped else { return false }
            started = true
            if pauseSet.isEmpty {
                scheduleOpen(after: 0)
            } else {
                _state = .paused
            }
            return true
        }
        guard first else { return }
        let frames = self.frames
        playback = Task { [weak self] in
            for await frame in frames {
                guard let self else { return }
                self.play(frame)
            }
        }
    }

    /// Release the device until every reason is `resume`d.
    public func pause(_ reason: CallAudioPause) {
        queue.sync {
            guard !stopped, pauseSet.insert(reason).inserted else { return }
            record(.paused(pauseSet))
            closeCurrent()
            if started {
                _state = .paused
            }
        }
    }

    /// Lift `reason`. A device opens again once no reason is left.
    public func resume(_ reason: CallAudioPause) {
        queue.sync {
            guard !stopped, pauseSet.remove(reason) != nil else { return }
            if pauseSet.isEmpty {
                if started {
                    scheduleOpen(after: 0)
                }
            } else {
                record(.paused(pauseSet))
            }
        }
    }

    /// The system's interruption began: the session is someone else's.
    public func interruptionBegan() {
        pause(.interrupted)
    }

    /// Resumes if the system allows; otherwise waits for
    /// `resume(.interrupted)`.
    public func interruptionEnded(shouldResume: Bool) {
        let wasInterrupted = queue.sync { () -> Bool in
            guard !stopped else { return false }
            record(.interruptionEnded(shouldResume: shouldResume))
            return pauseSet.contains(.interrupted)
        }
        if shouldResume && wasInterrupted {
            resume(.interrupted)
        }
    }

    /// The platform moved the call's audio. Reported once per change.
    public func routeChanged(_ route: CallAudioRoute) {
        queue.sync {
            guard !stopped, route != lastRoute else { return }
            lastRoute = route
            record(.routeChanged(route))
        }
    }

    /// While muted the microphone is still read, and silence is sent.
    public func setMuted(_ muted: Bool) {
        queue.sync {
            guard !stopped, self.muted != muted else { return }
            self.muted = muted
            record(.muteChanged(muted))
        }
    }

    /// Nothing is opened until the services come back.
    public func mediaServicesLost() {
        queue.sync {
            guard !stopped else { return }
            record(.mediaServicesLost)
            closeCurrent()
            failing = true
            attempts = 0
            generation += 1
            openScheduled = false
            if started {
                _state = .recovering
            }
        }
    }

    /// Rebuild now, or at the next resume if paused.
    public func mediaServicesReset() {
        queue.sync {
            guard !stopped else { return }
            record(.mediaServicesReset)
            closeCurrent()
            if !failing {
                failing = true
                attempts = 0
            }
            generation += 1
            openScheduled = false
            if started && pauseSet.isEmpty {
                _state = .recovering
                scheduleOpen(after: 0)
            }
        }
    }

    /// Stop for good when `call` ends.
    public func follow(_ call: Call) {
        let events = call.events()
        let task = Task { [weak self] in
            for await event in events where event.kind == .callEnded {
                self?.close()
                return
            }
            self?.close()
        }
        queue.sync { following = task }
    }

    /// Stop for good: the device closed, no frame moved any more.
    public func close() {
        let tasks = queue.sync { () -> [Task<Void, Never>?] in
            guard !stopped else { return [] }
            stopped = true
            closeCurrent()
            generation += 1
            _state = .stopped
            record(.stopped)
            return [playback, following]
        }
        for task in tasks {
            task?.cancel()
        }
        broadcast.finish()
    }

    // MARK: - the device

    /// Called on `queue`.
    private func record(_ transition: CallAudioTransition) {
        _history.append(transition)
        if _history.count > 64 {
            _history.removeFirst(_history.count - 64)
        }
        broadcast.send(transition)
    }

    /// Called on `queue`: the streams in use are let go, on `deviceQueue`.
    private func closeCurrent() {
        guard let streams = current else { return }
        current = nil
        generation += 1
        deviceQueue.async { streams.close() }
    }

    /// Called on `queue`.
    private func scheduleOpen(after delay: Double) {
        guard !openScheduled else { return }
        openScheduled = true
        let wanted = generation
        deviceQueue.asyncAfter(deadline: .now() + delay) { [weak self] in
            self?.open(wanted)
        }
    }

    /// Called on `deviceQueue`.
    private func open(_ wanted: Int) {
        let stillWanted = queue.sync { () -> Bool in
            openScheduled = false
            return wanted == generation && !stopped && pauseSet.isEmpty && current == nil
        }
        guard stillWanted else { return }
        let generationAtOpen = wanted
        let result = Result { () throws -> CallAudioStreams in
            try device.open(
                sampleRate: sampleRate,
                frameSamples: frameSamples,
                capture: { [weak self] samples in self?.captured(samples) },
                failed: { [weak self] why in self?.failed(generationAtOpen + 1, why) }
            )
        }
        queue.sync {
            attempts += 1
            switch result {
            case .failure(let refused):
                noteFailure(String(describing: refused))
            case .success(let streams):
                guard wanted == generation, !stopped, pauseSet.isEmpty else {
                    deviceQueue.async { streams.close() }
                    return
                }
                current = streams
                generation += 1
                _state = .running
                if failing {
                    record(.deviceRestored(attempts: attempts))
                } else if !everOpened {
                    record(.started)
                } else {
                    record(.resumed)
                }
                failing = false
                everOpened = true
                openedAt = DispatchTime.now()
            }
        }
    }

    /// Called on `queue`. A failure within `CallAudio.shortLived` of opening
    /// counts as not recovered, so the delay keeps growing instead of
    /// retrying in a tight loop.
    private func noteFailure(_ why: String) {
        if !failing {
            failing = true
            attempts = 0
            if let openedAt, DispatchTime.now().uptimeNanoseconds &- openedAt.uptimeNanoseconds < Self.shortLived {
                shortLivedInARow += 1
            } else {
                shortLivedInARow = 0
            }
            record(.deviceFailed(why))
        }
        _state = .recovering
        let delay = retryDelays[min(attempts + shortLivedInARow, retryDelays.count - 1)]
        scheduleOpen(after: delay)
    }

    /// Two seconds, in nanoseconds.
    static let shortLived: UInt64 = 2_000_000_000

    /// The streams opened at generation `opened` stopped on their own.
    private func failed(_ opened: Int, _ why: String) {
        queue.sync {
            guard opened == generation, current != nil, !stopped else { return }
            closeCurrent()
            noteFailure(why)
        }
    }

    private func captured(_ samples: [Int16]) {
        let (live, silent) = queue.sync { (current != nil, muted) }
        guard live else { return }
        send(silent ? [Int16](repeating: 0, count: samples.count) : samples)
    }

    private func play(_ frame: [Int16]) {
        let streams = queue.sync { current }
        streams?.play(frame)
    }
}
