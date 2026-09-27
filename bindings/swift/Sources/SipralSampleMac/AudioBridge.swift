// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

#if canImport(AVFoundation)
// AVFoundation's own overlay has not been audited for Swift 6 concurrency:
// `AVAudioConverterInputBlock` is an Objective-C block type, and the
// compiler treats an imported block parameter as `@Sendable` by default
// whether or not the framework says so. `micConverter`/`playbackConverter`
// call the block synchronously, within `convert(to:error:withInputFrom:)`'s
// own call, on whichever thread called it -- never later and never on
// another thread -- so the buffer it captures is never actually shared
// across a concurrency domain; `@preconcurrency` tells the compiler to take
// AVFoundation's own (missing) Sendable annotations as given rather than
// impose stricter ones of its own on a framework that predates them.
@preconcurrency import AVFoundation
import Sipral

/// Bridges one call's audio (`Media.frames()` / `Media.sendAudio`) to the
/// device's microphone and speaker through `AVAudioEngine`.
///
/// Deliberately simple -- this is the sample's own audio path, not
/// `sipral-io-coreaudio`'s, and exists to show the wiring a real
/// application needs: convert the engine's own format to and from the
/// call's negotiated 16-bit mono PCM at whatever rate it negotiated, one
/// frame at a time.
@MainActor
final class AudioBridge {
    private let engine = AVAudioEngine()
    private let player = AVAudioPlayerNode()
    private var micConverter: AVAudioConverter?
    private var playbackConverter: AVAudioConverter?
    private weak var media: Media?
    private var frameTask: Task<Void, Never>?

    func start(for media: Media) throws {
        self.media = media
        let callFormat = AVAudioFormat(
            commonFormat: .pcmFormatInt16, sampleRate: Double(media.sampleRate),
            channels: 1, interleaved: true
        )!

        let input = engine.inputNode
        let inputFormat = input.outputFormat(forBus: 0)
        micConverter = AVAudioConverter(from: inputFormat, to: callFormat)
        input.installTap(onBus: 0, bufferSize: 1024, format: inputFormat) { [weak self] buffer, _ in
            Task { @MainActor in self?.handleMic(buffer) }
        }

        engine.attach(player)
        let outputFormat = engine.mainMixerNode.outputFormat(forBus: 0)
        engine.connect(player, to: engine.mainMixerNode, format: outputFormat)
        playbackConverter = AVAudioConverter(from: callFormat, to: outputFormat)

        try engine.start()
        player.play()

        let frames = media.frames()
        frameTask = Task { [weak self] in
            for await frame in frames {
                self?.play(frame)
            }
        }
    }

    private func handleMic(_ buffer: AVAudioPCMBuffer) {
        guard let converter = micConverter, let media else { return }
        let ratio = converter.outputFormat.sampleRate / buffer.format.sampleRate
        let capacity = AVAudioFrameCount(Double(buffer.frameLength) * ratio) + 16
        guard let outBuffer = AVAudioPCMBuffer(pcmFormat: converter.outputFormat, frameCapacity: capacity) else {
            return
        }
        var error: NSError?
        converter.convert(to: outBuffer, error: &error) { _, status in
            status.pointee = .haveData
            return buffer
        }
        guard error == nil, let channel = outBuffer.int16ChannelData else { return }
        media.sendAudio(Array(UnsafeBufferPointer(start: channel[0], count: Int(outBuffer.frameLength))))
    }

    private func play(_ frame: [Int16]) {
        guard let converter = playbackConverter else { return }
        let inFormat = converter.inputFormat
        guard let inBuffer = AVAudioPCMBuffer(pcmFormat: inFormat, frameCapacity: AVAudioFrameCount(frame.count)),
              let channel = inBuffer.int16ChannelData else { return }
        inBuffer.frameLength = AVAudioFrameCount(frame.count)
        frame.withUnsafeBufferPointer { pointer in
            guard let base = pointer.baseAddress else { return }
            channel[0].update(from: base, count: frame.count)
        }

        let ratio = converter.outputFormat.sampleRate / inFormat.sampleRate
        let capacity = AVAudioFrameCount(Double(frame.count) * ratio) + 16
        guard let outBuffer = AVAudioPCMBuffer(pcmFormat: converter.outputFormat, frameCapacity: capacity) else {
            return
        }
        var error: NSError?
        converter.convert(to: outBuffer, error: &error) { _, status in
            status.pointee = .haveData
            return inBuffer
        }
        guard error == nil else { return }
        player.scheduleBuffer(outBuffer)
    }

    func stop() {
        frameTask?.cancel()
        engine.inputNode.removeTap(onBus: 0)
        engine.stop()
        player.stop()
    }
}
#endif
