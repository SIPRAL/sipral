// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import CSipral

/// Who runs a stack's audio: `sipral_stack_config_t::audio`.
///
/// `.device` has the library open the platform's own devices -- the
/// voice-processing unit on macOS and iOS, with the system's echo
/// cancellation behind the microphone -- and pump every call from the
/// moment its media starts to the moment it ends, with nothing for the
/// application to do but choose devices through `SipralStack.audio`.
/// `.application` is the stack as it was before: `Media.frames()` carries the
/// far end's audio and `Media.sendAudio` takes the microphone's, for an
/// application that runs its own audio -- a voice agent, a recorder, a test.
public enum AudioMode: Sendable, Equatable {
    /// The library opens the devices, and `activation` says when.
    case device(activation: SipralAudioActivation = .automatic)
    /// The application pumps every call's frames itself.
    case application

    /// What a stack is created with unless it says otherwise: `.device` with
    /// automatic activation wherever this build of the library has an engine
    /// for the platform -- macOS, iOS, Windows -- and `.application` where it
    /// has none, Linux among them, so that the same code builds and runs
    /// everywhere and hears nothing only where nothing could be heard.
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
    /// The engine's name for it: stable across refreshes and unplugging,
    /// never reused, never zero -- what `AudioDevices.select` takes, and what
    /// an application saves as a person's choice.
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
    /// Whether the last refresh still found it. A device that went keeps its
    /// row and its id, so a selection saved against it still names it.
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

/// The name `SipralAudioDevice` had until the package prefixed it: a bare
/// `AudioDevice` is a name other audio packages an application imports
/// beside this one use too. Kept for one minor release.
@available(*, deprecated, renamed: "SipralAudioDevice")
public typealias AudioDevice = SipralAudioDevice

/// What a role was asked to run on, and what it runs on now: the two differ
/// while a chosen device is unplugged, when the role runs on the system's
/// route and the choice is kept for the device's return. `nil` is the
/// system's route.
public struct AudioSelection: Sendable, Equatable {
    public let selected: UInt32?
    public let running: UInt32?
}

/// What the engine is doing (`sipral_audio_info_t`).
public struct AudioStatus: Sendable, Equatable {
    /// Whether the devices are open and the pump is running.
    public let isActive: Bool
    /// Whether the platform's own processing sits behind the microphone: the
    /// voice-processing unit on Apple's platforms, which cancels the
    /// loudspeaker's echo.
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
    /// `.system` for the operating system -- a device arriving or leaving,
    /// the default moving -- and `.engine` for the library doing what it was
    /// asked, or what a lost device made it do. An application notes the
    /// first and never re-applies its own choice on hearing the second.
    public let origin: SipralAudioOrigin?
    /// The role a change is about, for a selection, a loss or a reopening.
    public let role: SipralAudioRole?
    /// The direction whose default moved, for `.defaultChanged`.
    public let direction: SipralAudioDirection?
    /// The device concerned, or `nil`.
    public let device: UInt32?
}

/// What `CallKitBridge` drives when the library runs the devices: the one
/// audio session CallKit hands the calls, taken and given back as a whole.
/// `AudioDevices` is the real one; a test records what it was told.
public protocol CallAudioSessionEngine: AnyObject, Sendable {
    func activate() throws
    func deactivate() throws
    func setMuted(_ muted: Bool, for direction: SipralAudioDirection) throws
}

/// The library's own audio engine for one stack in `AudioMode.device`: the
/// devices listed, chosen per role, their gain, mute and level, the ring, and
/// when they are open. `SipralStack.audio`.
///
/// Every member calls the C ABI directly and may be called from any thread;
/// none takes the stack's own lock, so a level meter read on a window's timer
/// never waits for signalling. A platform that stops answering is
/// `SipralError` with `.deviceTimedOut` after the stack's probe interval,
/// never a hang.
public final class AudioDevices: CallAudioSessionEngine, @unchecked Sendable {
    public unowned let stack: SipralStack

    init(stack: SipralStack) {
        self.stack = stack
    }

    // MARK: - the list

    /// Ask the platform again, and return the list. A device seen before
    /// keeps its id; one that has gone stays, `isPresent` false; a new one
    /// gets the next id. The engine refreshes by itself when the platform
    /// announces a change, and says so with
    /// `SipralEventKind.audioDevicesChanged`, so this is for a settings
    /// screen opening rather than for polling.
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

    /// One row, its name read into a buffer that grows to what the library
    /// says it needs: `sipral_audio_device_at` writes the length needed, NUL
    /// counted, even when the name does not fit, which the generated
    /// wrapper, throwing on anything but success, would not hand back.
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
    /// The microphone, the speaker and the ringer are chosen separately.
    /// Refused before anything is opened: `.noSuchDevice` for an id the list
    /// never held, `.deviceUnusable` for a device with no channels for the
    /// role or one that is not plugged in, and `.notSupported` where the
    /// platform cannot put the role on a device of its own -- on iOS, whose
    /// route is the audio session's, the microphone and the ringer. On macOS
    /// the microphone is chosen apart from the speaker without moving the
    /// system's default input, and a ringer on another device plays through
    /// an output of its own. While the engine is active the role moves at
    /// once, with its direction's gain and mute carried over.
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

    /// The gain of a direction as a factor: 1 leaves the audio as it is, 0.5
    /// halves it, 2 doubles it. The input direction is the microphone's gain.
    /// Kept by the engine and applied to whatever device the direction runs
    /// on, so a headset unplugged mid-call comes back as loud as it was.
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

    /// Mute or unmute a direction: the input direction sends silence, the
    /// output one plays none. Kept across a change of device, like the gain.
    public func setMuted(_ muted: Bool, for direction: SipralAudioDirection) throws {
        try Sipral.audioSetMuted(stack: stack.handle, direction: direction.rawValue, muted: muted ? 1 : 0)
    }

    public func isMuted(_ direction: SipralAudioDirection) throws -> Bool {
        try Sipral.audioMuted(stack: stack.handle, direction: direction.rawValue) != 0
    }

    /// The meter: the recent peak of a direction, 0 for silence to 1 for
    /// full scale, after the gain and the mute. Cheap enough for a window's
    /// timer; zero while the engine is not active.
    public func level(for direction: SipralAudioDirection) throws -> Double {
        Double(try Sipral.audioLevel(stack: stack.handle, direction: direction.rawValue)) / Double(Int16.max)
    }

    // MARK: - activation and the ring

    /// Open the devices, under `SipralAudioActivation.manual`: what
    /// CallKit's `provider(_:didActivate:)` is for. Calls whose media started
    /// before this are carried from here on.
    public func activate() throws {
        try Sipral.audioActivate(stack: stack.handle)
    }

    /// Close the devices; calls stay attached and are heard again at the
    /// next `activate()`. What `provider(_:didDeactivate:)` is for.
    public func deactivate() throws {
        try Sipral.audioDeactivate(stack: stack.handle)
    }

    /// Play `tone` -- 16-bit mono PCM at `sampleRate` -- on the ringer's
    /// device until `stopRinging()`, over and over when `looped`. Under
    /// automatic activation the ring opens the devices itself.
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
