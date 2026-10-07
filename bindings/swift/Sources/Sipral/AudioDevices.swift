// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import CSipral

/// Who runs a stack's audio: `sipral_stack_config_t::audio`.
///
/// `.device`: the library opens the platform devices (the voice-processing
/// unit on Apple platforms, with system echo cancellation) and pumps every
/// call; the application only picks devices via `SipralStack.audio`.
/// `.application`: `Media.frames()` and `Media.sendAudio` carry the audio,
/// for voice agents, recorders and tests.
public enum AudioMode: Sendable, Equatable {
    /// The library opens the devices, and `activation` says when.
    case device(activation: SipralAudioActivation = .automatic)
    /// The application pumps every call's frames itself.
    case application

    /// `.device` with automatic activation where the build has an engine
    /// (macOS, iOS, Windows), `.application` elsewhere (Linux).
    public static var platformDefault: AudioMode {
        guard let features = try? Sipral.capabilities().features,
              features & Sipral.featureAudioDevice != 0 else { return .application }
        return .device()
    }

    var raw: (mode: UInt32, activation: UInt32) {
        switch self {
        case .device(let activation):
            return (SipralAudio.device.rawValue, activation.rawValue)
        case .application:
            return (SipralAudio.application.rawValue, 0)
        }
    }

    /// Whether this is `.device`, whatever its activation.
    public var isDevice: Bool {
        if case .device = self { return true }
        return false
    }
}

/// One audio device, as `sipral_audio_device_at` lists it.
public struct SipralAudioDevice: Sendable, Equatable, Identifiable {
    /// Stable across refreshes and unplugging, never reused, never zero:
    /// safe to save as a user's choice.
    public let id: UInt32
    /// What the platform calls it.
    public let name: String
    /// How many channels it captures; zero for a device that is no
    /// microphone.
    public let inputChannels: Int
    /// How many channels it plays; zero for a device that is no speaker.
    public let outputChannels: Int
    /// Whether the system records from it by default.
    public let isDefaultInput: Bool
    /// Whether the system plays to it by default.
    public let isDefaultOutput: Bool
    /// Whether the last refresh found it. A missing device keeps its row and
    /// id, so saved selections still name it.
    public let isPresent: Bool

    public init(
        id: UInt32, name: String, inputChannels: Int, outputChannels: Int,
        isDefaultInput: Bool, isDefaultOutput: Bool, isPresent: Bool
    ) {
        self.id = id
        self.name = name
        self.inputChannels = inputChannels
        self.outputChannels = outputChannels
        self.isDefaultInput = isDefaultInput
        self.isDefaultOutput = isDefaultOutput
        self.isPresent = isPresent
    }

    /// Whether it can serve `role`: a microphone needs input channels, a
    /// speaker or a ringer output ones.
    public func canServe(_ role: SipralAudioRole) -> Bool {
        role == .microphone ? inputChannels > 0 : outputChannels > 0
    }
}

/// The former name of `SipralAudioDevice`, which clashed with other audio
/// packages. Kept for one minor release.
@available(*, deprecated, renamed: "SipralAudioDevice")
public typealias AudioDevice = SipralAudioDevice

/// The chosen and the current device for a role; they differ while the
/// chosen one is unplugged and the system route stands in. `nil` is the
/// system route.
public struct AudioSelection: Sendable, Equatable {
    public let selected: UInt32?
    public let running: UInt32?
}

/// What the engine is doing (`sipral_audio_info_t`).
public struct AudioStatus: Sendable, Equatable {
    /// Whether the devices are open and the pump is running.
    public let isActive: Bool
    /// Whether the platform's echo-cancelling voice processing is in use.
    public let systemEchoCancellation: Bool
    /// The loudspeaker-to-microphone delay the devices report.
    public let renderDelayMs: UInt64
    /// The rate the microphone runs at, or zero while it is closed.
    public let microphoneRateHz: UInt32
    /// The rate the loudspeaker runs at, or zero while it is closed.
    public let speakerRateHz: UInt32
    /// The device each role runs on, `nil` while it is closed; a `nil`
    /// ringer on an active engine rings through the loudspeaker.
    public let microphone: UInt32?
    public let speaker: UInt32?
    public let ringer: UInt32?
}

/// A change to the engine's devices (`sipral_audio_event_t`), on
/// `SipralEventKind.audioDevicesChanged`.
public struct AudioEventData: Sendable, Equatable {
    public let changeRaw: UInt32
    public let change: SipralAudioChange?
    public let originRaw: UInt32
    /// `.system` for OS changes (devices, defaults), `.engine` for the
    /// library's own actions. Never re-apply a choice on hearing `.engine`.
    public let origin: SipralAudioOrigin?
    /// The role a change is about, for a selection, a loss or a reopening.
    public let role: SipralAudioRole?
    /// The direction whose default moved, for `.defaultChanged`.
    public let direction: SipralAudioDirection?
    /// The device concerned, or `nil`.
    public let device: UInt32?
}

/// What `CallKitBridge` activates and deactivates; a test can substitute it.
public protocol CallAudioSessionEngine: AnyObject, Sendable {
    func activate() throws
    func deactivate() throws
    func setMuted(_ muted: Bool, for direction: SipralAudioDirection) throws
}

/// The library's audio engine for one stack in `AudioMode.device`
/// (`SipralStack.audio`).
///
/// Callable from any thread; no member takes the stack's lock, so a level
/// meter never waits for signalling. A platform that stops answering throws
/// `.deviceTimedOut` after the probe interval rather than hanging.
public final class AudioDevices: CallAudioSessionEngine, @unchecked Sendable {
    public unowned let stack: SipralStack

    init(stack: SipralStack) {
        self.stack = stack
    }

    // MARK: - the list

    /// Re-query the platform and return the list. Ids are kept; gone devices
    /// stay with `isPresent` false. The engine refreshes itself on platform
    /// changes (`audioDevicesChanged`), so this is for a settings screen,
    /// not polling.
    @discardableResult
    public func refresh() throws -> [SipralAudioDevice] {
        _ = try Sipral.audioRefresh(stack: stack.handle)
        return try devices()
    }

    /// The list as it stands, present and absent devices alike.
    public func devices() throws -> [SipralAudioDevice] {
        let count = try Sipral.audioDeviceCount(stack: stack.handle)
        return try (0..<count).map(device(at:))
    }

    /// Called directly: the C call reports the needed name length even when
    /// it does not fit, which the generated wrapper would throw away.
    private func device(at index: Int) throws -> SipralAudioDevice {
        var buffer = [CChar](repeating: 0, count: 256)
        var device = sipral_audio_device_t.sized()
        var needed = 0
        var status = buffer.withUnsafeMutableBufferPointer {
            sipral_audio_device_at(stack.handle, index, &device, $0.baseAddress, $0.count, &needed)
        }
        if status == SipralStatus.bufferTooSmall.rawValue {
            buffer = [CChar](repeating: 0, count: needed)
            status = buffer.withUnsafeMutableBufferPointer {
                sipral_audio_device_at(stack.handle, index, &device, $0.baseAddress, $0.count, &needed)
            }
        }
        try Sipral.check(status)
        let read = (device: device, needed: needed)
        // the trailing NUL is counted in `needed` and is not part of the name
        let length = max(0, min(read.needed, buffer.count) - 1)
        let name = String(
            decoding: buffer.prefix(length).map { UInt8(bitPattern: $0) },
            as: UTF8.self
        )
        return SipralAudioDevice(
            id: read.device.id,
            name: name,
            inputChannels: Int(read.device.input_channels),
            outputChannels: Int(read.device.output_channels),
            isDefaultInput: read.device.default_input != 0,
            isDefaultOutput: read.device.default_output != 0,
            isPresent: read.device.present != 0
        )
    }

    // MARK: - roles

    /// Put `role` on `device`, or back on the system's route with `nil`.
    ///
    /// Roles are chosen separately. Errors: `.noSuchDevice` for an unknown
    /// id, `.deviceUnusable` for no suitable channels or unplugged,
    /// `.notSupported` where the platform owns the route (microphone and
    /// ringer on iOS). On macOS this does not move the system default. While
    /// active, the role moves at once, keeping gain and mute.
    public func select(_ device: UInt32?, for role: SipralAudioRole) throws {
        try Sipral.audioSelect(stack: stack.handle, role: role.rawValue, device: device ?? 0)
    }

    /// `select(_:for:)` by the device itself.
    public func select(_ device: SipralAudioDevice?, for role: SipralAudioRole) throws {
        try select(device?.id, for: role)
    }

    /// What `role` was asked to run on and what it runs on now.
    public func selection(for role: SipralAudioRole) throws -> AudioSelection {
        let read = try Sipral.audioSelection(stack: stack.handle, role: role.rawValue)
        return AudioSelection(
            selected: read.selected == 0 ? nil : read.selected,
            running: read.running == 0 ? nil : read.running
        )
    }

    // MARK: - gain, mute, level

    /// A direction's gain as a factor (1 unchanged, 0.5 half). Kept across
    /// device changes.
    public func setGain(_ gain: Double, for direction: SipralAudioDirection) throws {
        let steps = (max(gain, 0) * Double(Self.unity)).rounded()
        try Sipral.audioSetGain(
            stack: stack.handle, direction: direction.rawValue, gain: UInt32(min(steps, Double(UInt32.max)))
        )
    }

    /// The gain `setGain(_:for:)` set, as a factor.
    public func gain(for direction: SipralAudioDirection) throws -> Double {
        Double(try Sipral.audioGain(stack: stack.handle, direction: direction.rawValue)) / Double(Self.unity)
    }

    /// Mute a direction. Kept across device changes.
    public func setMuted(_ muted: Bool, for direction: SipralAudioDirection) throws {
        try Sipral.audioSetMuted(stack: stack.handle, direction: direction.rawValue, muted: muted ? 1 : 0)
    }

    public func isMuted(_ direction: SipralAudioDirection) throws -> Bool {
        try Sipral.audioMuted(stack: stack.handle, direction: direction.rawValue) != 0
    }

    /// Recent peak, 0 to 1, after gain and mute; zero while inactive. Cheap.
    public func level(for direction: SipralAudioDirection) throws -> Double {
        Double(try Sipral.audioLevel(stack: stack.handle, direction: direction.rawValue)) / Double(Int16.max)
    }

    // MARK: - the platform's echo cancellation

    /// Toggle the platform's echo cancellation on a running stack. Open
    /// devices are reopened at once, keeping devices, gain and mute; calls
    /// survive the short gap. `status().systemEchoCancellation` reports what
    /// the platform did.
    public func setSystemEchoCancellation(_ on: Bool) throws {
        try Sipral.audioSetSystemEchoCancellation(
            stack: stack.handle, on: on ? SipralToggle.on.rawValue : SipralToggle.off.rawValue
        )
    }

    // MARK: - one call's own gain, mute and level

    /// One call's gain on top of the direction's. Kept through hold and
    /// local conferences; `.wrongState` before media starts or after the end.
    public func setGain(_ gain: Double, for direction: SipralAudioDirection, of call: Call) throws {
        let steps = (max(gain, 0) * Double(Self.unity)).rounded()
        try Sipral.audioCallSetGain(
            stack: stack.handle, call: call.handle, direction: direction.rawValue,
            gain: UInt32(min(steps, Double(UInt32.max)))
        )
    }

    /// The gain `setGain(_:for:of:)` set for one call, as a factor.
    public func gain(for direction: SipralAudioDirection, of call: Call) throws -> Double {
        Double(try Sipral.audioCallGain(stack: stack.handle, call: call.handle, direction: direction.rawValue))
            / Double(Self.unity)
    }

    /// Mute one call in one direction. Same rules as `setGain(_:for:of:)`.
    public func setMuted(_ muted: Bool, for direction: SipralAudioDirection, of call: Call) throws {
        try Sipral.audioCallSetMuted(
            stack: stack.handle, call: call.handle, direction: direction.rawValue, muted: muted ? 1 : 0
        )
    }

    public func isMuted(_ direction: SipralAudioDirection, of call: Call) throws -> Bool {
        try Sipral.audioCallMuted(stack: stack.handle, call: call.handle, direction: direction.rawValue) != 0
    }

    /// One call's meter, 0 to 1, after its gain and mute.
    public func level(for direction: SipralAudioDirection, of call: Call) throws -> Double {
        Double(try Sipral.audioCallLevel(stack: stack.handle, call: call.handle, direction: direction.rawValue))
            / Double(Int16.max)
    }

    // MARK: - activation and the ring

    /// Open the devices under `.manual` activation, from CallKit's
    /// `provider(_:didActivate:)`. Earlier calls are picked up.
    public func activate() throws {
        try Sipral.audioActivate(stack: stack.handle)
    }

    /// Close the devices (`provider(_:didDeactivate:)`); calls stay attached.
    public func deactivate() throws {
        try Sipral.audioDeactivate(stack: stack.handle)
    }

    /// Play 16-bit mono `tone` on the ringer until `stopRinging()`. Under
    /// automatic activation it opens the devices itself.
    public func ring(_ tone: [Int16], sampleRate: UInt32, looped: Bool = true) throws {
        try Sipral.audioRing(stack: stack.handle, samples: tone, sampleRateHz: sampleRate, looped: looped ? 1 : 0)
    }

    public func stopRinging() throws {
        try Sipral.audioStopRinging(stack: stack.handle)
    }

    /// What the engine is doing now.
    public func status() throws -> AudioStatus {
        let info = try Sipral.audioInfo(stack: stack.handle)
        return AudioStatus(
            isActive: info.active != 0,
            systemEchoCancellation: info.system_echo_cancellation != 0,
            renderDelayMs: info.render_delay_ms,
            microphoneRateHz: info.microphone_rate_hz,
            speakerRateHz: info.speaker_rate_hz,
            microphone: info.microphone == 0 ? nil : info.microphone,
            speaker: info.speaker == 0 ? nil : info.speaker,
            ringer: info.ringer == 0 ? nil : info.ringer
        )
    }

    /// The gain `sipral_audio_set_gain` calls unity.
    static let unity: UInt32 = 256
}
