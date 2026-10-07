// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(AVFoundation)
// AVFoundation's overlay predates Swift's concurrency annotations; the tap
// and the converter's input block are called synchronously or on the
// engine's own thread, and never share anything this file does not guard.
@preconcurrency import AVFoundation

/// `CallAudioDevice` over `AVAudioEngine`, with the system's own voice
/// processing -- echo cancellation, noise suppression, automatic gain -- on
/// its input node.
///
/// Every `open` builds a new engine, since a media services reset kills the
/// old one. After a configuration change the engine is restarted in place;
/// only one that will not restart is reported as failed.
public final class VoiceProcessingAudioDevice: CallAudioDevice, @unchecked Sendable {
    #if os(iOS)
    private let managesSession: Bool

    /// `managesSession`: `open` configures (`.playAndRecord`, `.voiceChat`)
    /// and activates the session, `close` deactivates it. Use `false` with
    /// CallKit, which activates the session itself.
    public init(managesSession: Bool) {
        self.managesSession = managesSession
    }
    #else
    public init() {}
    #endif

    public func open(
        sampleRate: Int,
        frameSamples: Int,
        capture: @escaping @Sendable ([Int16]) -> Void,
        failed: @escaping @Sendable (String) -> Void
    ) throws -> CallAudioStreams {
        #if os(iOS)
        if managesSession {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.playAndRecord, mode: .voiceChat, options: [.allowBluetoothHFP])
            try session.setActive(true)
        }
        let deactivate = managesSession
        return try EngineStreams(
            sampleRate: sampleRate, frameSamples: frameSamples, capture: capture, failed: failed,
            onClose: {
                if deactivate {
                    try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
                }
            }
        )
        #else
        return try EngineStreams(
            sampleRate: sampleRate, frameSamples: frameSamples, capture: capture, failed: failed, onClose: {}
        )
        #endif
    }
}

/// Why an engine could not be built.
public enum VoiceProcessingAudioDeviceError: Error, Sendable {
    /// The input node reported no format: no microphone, or no permission.
    case noInput
    /// A format or a converter the call's rate needs could not be made.
    case format
}

private final class EngineStreams: CallAudioStreams, @unchecked Sendable {
    private let engine = AVAudioEngine()
    private let player = AVAudioPlayerNode()
    private let callFormat: AVAudioFormat
    private let playerFormat: AVAudioFormat
    private let micConverter: AVAudioConverter
    private let onClose: @Sendable () -> Void
    private let lock = NSLock()
    private var open = true
    private var observer: NSObjectProtocol?

    init(
        sampleRate: Int,
        frameSamples: Int,
        capture: @escaping @Sendable ([Int16]) -> Void,
        failed: @escaping @Sendable (String) -> Void,
        onClose: @escaping @Sendable () -> Void
    ) throws {
        self.onClose = onClose
        guard let callFormat = AVAudioFormat(
            commonFormat: .pcmFormatInt16, sampleRate: Double(sampleRate), channels: 1, interleaved: true
        ), let playerFormat = AVAudioFormat(standardFormatWithSampleRate: Double(sampleRate), channels: 1) else {
            throw VoiceProcessingAudioDeviceError.format
        }
        self.callFormat = callFormat
        self.playerFormat = playerFormat

        let input = engine.inputNode
        try input.setVoiceProcessingEnabled(true)
        let inputFormat = input.outputFormat(forBus: 0)
        guard inputFormat.sampleRate > 0, inputFormat.channelCount > 0 else {
            throw VoiceProcessingAudioDeviceError.noInput
        }
        guard let converter = AVAudioConverter(from: inputFormat, to: callFormat) else {
            throw VoiceProcessingAudioDeviceError.format
        }
        micConverter = converter

        let tapFrames = AVAudioFrameCount(max(frameSamples, 1)) * AVAudioFrameCount(inputFormat.sampleRate) /
            AVAudioFrameCount(max(sampleRate, 1))
        input.installTap(onBus: 0, bufferSize: max(tapFrames, 256), format: inputFormat) { [weak self] buffer, _ in
            guard let self, let samples = self.convert(buffer) else { return }
            capture(samples)
        }
        engine.attach(player)
        engine.connect(player, to: engine.mainMixerNode, format: playerFormat)

        observer = NotificationCenter.default.addObserver(
            forName: .AVAudioEngineConfigurationChange, object: engine, queue: nil
        ) { [weak self] _ in
            self?.configurationChanged(failed)
        }
        engine.prepare()
        do {
            try engine.start()
        } catch {
            close()
            throw error
        }
        player.play()
    }

    private func convert(_ buffer: AVAudioPCMBuffer) -> [Int16]? {
        let ratio = callFormat.sampleRate / buffer.format.sampleRate
        let capacity = AVAudioFrameCount(Double(buffer.frameLength) * ratio) + 16
        guard let out = AVAudioPCMBuffer(pcmFormat: callFormat, frameCapacity: capacity) else { return nil }
        var fed = false
        var error: NSError?
        micConverter.convert(to: out, error: &error) { _, status in
            if fed {
                status.pointee = .noDataNow
                return nil
            }
            fed = true
            status.pointee = .haveData
            return buffer
        }
        guard error == nil, let channel = out.int16ChannelData, out.frameLength > 0 else { return nil }
        return Array(UnsafeBufferPointer(start: channel[0], count: Int(out.frameLength)))
    }

    func play(_ frame: [Int16]) {
        lock.lock()
        defer { lock.unlock() }
        guard open, !frame.isEmpty,
              let buffer = AVAudioPCMBuffer(pcmFormat: playerFormat, frameCapacity: AVAudioFrameCount(frame.count)),
              let channel = buffer.floatChannelData else { return }
        buffer.frameLength = AVAudioFrameCount(frame.count)
        for (index, sample) in frame.enumerated() {
            channel[0][index] = Float(sample) / 32768
        }
        player.scheduleBuffer(buffer)
    }

    /// A configuration change stopped the engine; restart it in place.
    private func configurationChanged(_ failed: @Sendable (String) -> Void) {
        lock.lock()
        defer { lock.unlock() }
        guard open, !engine.isRunning else { return }
        do {
            try engine.start()
            player.play()
        } catch {
            failed("the audio engine stopped when its configuration changed, and would not start again: \(error)")
        }
    }

    func close() {
        lock.lock()
        defer { lock.unlock() }
        guard open else { return }
        open = false
        if let observer {
            NotificationCenter.default.removeObserver(observer)
        }
        engine.inputNode.removeTap(onBus: 0)
        player.stop()
        engine.stop()
        onClose()
    }
}
#endif
