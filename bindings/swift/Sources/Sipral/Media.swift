// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import CSipral
import Dispatch

/// How one stream of a call is protected: a `sipral_stream_encryption_t`
/// read out (`Media.encryption()`). `awaitingKeys` is a stream that will be
/// encrypted once its DTLS-SRTP handshake ends.
public struct StreamProtection: Sendable, Equatable {
    public let media: SipralMediaKind
    public let encrypted: Bool
    public let keyExchange: SipralKeyExchange
    public let suite: SipralSrtpSuite?
    public let authenticated: Bool
    public let awaitingKeys: Bool
}

/// What a call's audio stream agreed about RTCP feedback
/// (`Media.rtcpFeedback()`): RTP/AVPF (RFC 4585), Generic NACKs, and
/// reduced-size RTCP (RFC 5506).
public struct RtcpFeedback: Sendable, Equatable {
    public let feedback: Bool
    public let genericNack: Bool
    public let reducedSize: Bool
}

/// One path a call's ICE agent tried, and what became of it: a
/// `sipral_path_candidate_t` with its two addresses read out.
public struct PathCandidate: Sendable, Equatable {
    /// A candidate pair, or a relay.
    public let kind: SipralPathKind
    /// What became of it.
    public let outcome: SipralPathOutcome
    /// The STUN error code of a refusal, or the TURN server's; zero otherwise.
    public let code: UInt32
    /// What `local` is.
    public let localKind: SipralCandidateKind
    /// What `remote` is, `.unknown` for a relay's server.
    public let remoteKind: SipralCandidateKind
    /// The pair's priority (RFC 8445 §6.1.2.3); zero for a relay.
    public let priority: UInt64
    /// For a pair, the candidate its checks left from; for a relay, the
    /// relayed address. `host:port`.
    public let local: String
    /// For a pair, the far end's candidate; for a relay, the TURN server.
    public let remote: String
}

/// One call's audio, paced at its own frame rate.
///
/// Media has its own handle and never takes the stack's lock, so it runs on
/// its own thread, paced by `sipral_media_info_t.frameMs` rather than by the
/// caller's `sendAudio` rate. `Call` creates it on `mediaStarted` as
/// `call.media`.
///
/// In `AudioMode.device` the engine handles the audio, so
/// `frames(bufferingNewest:)` yields nothing and `sendAudio` is ignored
/// (see `pumpsFrames`). Statistics, ICE paths and the socket work in both
/// modes.
public final class Media: @unchecked Sendable {
    public let handle: SipralHandle
    /// The rate `frames()` hands out and `sendAudio` takes: the codec's,
    /// or the one `setAppRate(_:)` chose.
    public var sampleRate: Int { frameQueue.sync { _sampleRate } }
    /// Samples in one frame at `sampleRate`.
    public var frameSamples: Int { frameQueue.sync { _frameSamples } }
    private var _sampleRate: Int
    private var _frameSamples: Int
    /// Held per frame and while `setAppRate(_:)` changes the frame length.
    private let frameQueue = DispatchQueue(label: "org.sipral.media.frame")
    private let frameSeconds: Double

    /// `true` in `AudioMode.application`, where `frames()` and `sendAudio`
    /// carry the audio.
    public let pumpsFrames: Bool

    private let stack: SipralStack
    /// Guarded by `ioQueue`, with every send and receive: `Call.moveMedia`
    /// replaces it and the engine thread sends on it.
    private var socket: UDPSocket
    private var socketClosed = false
    private let ioQueue = DispatchQueue(label: "org.sipral.media.io")

    private let stateQueue = DispatchQueue(label: "org.sipral.media.state")
    private var _remoteAddress: String?
    /// A `LocalConference` carries the frames, so this thread leaves them.
    private var _carriedByConference = false
    var carriedByConference: Bool { stateQueue.sync { _carriedByConference } }

    /// Called by `LocalConference` as the call joins it and leaves it.
    func setCarriedByConference(_ carried: Bool) {
        stateQueue.sync { _carriedByConference = carried }
    }
    public var remoteAddress: String? { stateQueue.sync { _remoteAddress } }

    /// How many frames one reader of `frames(bufferingNewest:)` holds unread
    /// unless it asks for another number: one second's worth at 20 ms.
    public static let frameBuffer = 50

    private let frameBroadcast = Broadcast<[Int16]>(
        label: "org.sipral.media.frames", policy: .bufferingNewest(Media.frameBuffer)
    )

    /// A new reader of the far end's audio: decoded 16-bit mono PCM, one
    /// frame per item.
    ///
    /// Each stream gets every frame decoded after it is taken. A slow reader
    /// keeps only the newest `limit` frames and never holds up the media
    /// thread or other readers. Streams finish when the media ends; one taken
    /// after that is already finished.
    public func frames(bufferingNewest limit: Int = Media.frameBuffer) -> AsyncStream<[Int16]> {
        frameBroadcast.stream(bufferingPolicy: .bufferingNewest(max(limit, 1)))
    }

    private let outgoing = DispatchQueue(label: "org.sipral.media.outgoing")
    private var pending: [Int16] = []
    private var toSend: [[Int16]] = []

    private let closedSemaphore = DispatchSemaphore(value: 0)
    private var closed = false
    private let closeQueue = DispatchQueue(label: "org.sipral.media.close")

    /// Real-time text socket, served by this thread and closed with it.
    private let textSocket: UDPSocket?
    /// Recording copies' sockets while recording; `ioQueue`.
    private var recordingSockets: (thisEnd: UDPSocket, farEnd: UDPSocket)?

    init(stack: SipralStack, callHandle: SipralHandle, socket: UDPSocket, pumpsFrames: Bool, textSocket: UDPSocket? = nil) throws {
        self.stack = stack
        self.socket = socket
        self.pumpsFrames = pumpsFrames
        self.textSocket = textSocket
        self.handle = try retryingBusy { try Sipral.callMedia(stack: stack.handle, call: callHandle) }

        let info = try Sipral.mediaInfo(media: handle)
        self._sampleRate = Int(info.sample_rate)
        self._frameSamples = info.frame_samples
        self.frameSeconds = Double(max(info.frame_ms, 1)) / 1000.0

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in self?.run() }
    }

    public func info() throws -> sipral_media_info_t {
        try Sipral.mediaInfo(media: handle)
    }

    /// `sipral_media_statistics`. After the call ends, returns the
    /// end-of-call record instead of `.wrongState`.
    public func statistics() throws -> sipral_stream_stats_t {
        do {
            return try Sipral.mediaStatistics(media: handle, nowMs: stack.nowMs())
        } catch let error as SipralError where error.status == .wrongState {
            guard let record = finalQueue.sync(execute: { finalRecord }) else { throw error }
            return record
        }
    }

    private let finalQueue = DispatchQueue(label: "org.sipral.media.final")
    private var finalRecord: sipral_stream_stats_t?

    /// Stores the end-of-call record for `statistics()`.
    func ended(with record: sipral_stream_stats_t) {
        finalQueue.sync { finalRecord = record }
    }

    /// The negotiated RTCP feedback (RFC 4585, RFC 5506), read fresh. Asked
    /// for with `placeCall(feedback: true)`; an offer asking for it is
    /// answered in kind.
    public func rtcpFeedback() throws -> RtcpFeedback {
        let now = try Sipral.mediaInfo(media: handle)
        return RtcpFeedback(
            feedback: now.feedback != 0, genericNack: now.generic_nack != 0, reducedSize: now.reduced_size != 0
        )
    }

    /// Whether the call agreed a real-time text stream (RFC 4103), which
    /// `sendText(_:)` writes to.
    public var hasText: Bool {
        get throws { try Sipral.mediaInfo(media: handle).has_text != 0 }
    }

    /// `sipral_media_send_text`: queue typed UTF-8 text (RFC 4103, T.140).
    /// It leaves in the next 300 ms interval, repeated twice where `red` was
    /// agreed; BACKSPACE (U+0008) erases the far end's last character.
    /// `.notNegotiated` without a text stream, `.exhausted` when the queue is
    /// full.
    public func sendText(_ text: String) throws {
        try retryingBusy { try Sipral.mediaSendText(media: handle, text: text) }
    }

    /// Sockets for the recording copies (`Call.record(toServer:...)`).
    func copyRecording(thisEnd: UDPSocket, farEnd: UDPSocket) {
        let old = ioQueue.sync { () -> (thisEnd: UDPSocket, farEnd: UDPSocket)? in
            defer { recordingSockets = (thisEnd, farEnd) }
            return recordingSockets
        }
        old?.thisEnd.close()
        old?.farEnd.close()
    }

    /// No more copies: the recording session ended. Its sockets close.
    func stopCopyingRecording() {
        let old = ioQueue.sync { () -> (thisEnd: UDPSocket, farEnd: UDPSocket)? in
            defer { recordingSockets = nil }
            return recordingSockets
        }
        old?.thisEnd.close()
        old?.farEnd.close()
    }

    /// The current per-stream encryption report. Only DTLS-SRTP with a
    /// matching fingerprint authenticates the far end; SDES never does.
    public func encryption() throws -> [StreamProtection] {
        let count = try Sipral.mediaEncryptionCount(media: handle)
        return try (0..<count).map { index in
            let stream = try Sipral.mediaEncryptionAt(media: handle, index: index)
            return StreamProtection(
                media: SipralMediaKind(rawValue: stream.media) ?? .unknown,
                encrypted: stream.encrypted != 0,
                keyExchange: SipralKeyExchange(rawValue: stream.key_exchange) ?? .none,
                suite: SipralSrtpSuite(rawValue: stream.suite),
                authenticated: stream.authenticated != 0,
                awaitingKeys: stream.awaiting_keys != 0
            )
        }
    }

    /// `sipral_media_record_start_with`: record both directions to `path`
    /// as WAV or Ogg Opus, mono or stereo (this end left). Zeros mean: the
    /// call's rate, libopus's bitrate, a crash-safe checkpoint every 5 s.
    /// The file is finished by `stopRecording()`, the call ending, or the
    /// stack closing.
    public func record(
        to path: String, format: SipralRecordingFormat = .wav, layout: SipralRecordingLayout = .mixed,
        sampleRate: UInt32 = 0, bitrate: UInt32 = 0, checkpointMs: UInt32 = 0
    ) throws {
        var options = sipral_recording_options_t()
        options.size = MemoryLayout<sipral_recording_options_t>.size
        options.format = format.rawValue
        options.layout = layout.rawValue
        options.sample_rate = sampleRate
        options.bitrate = bitrate
        options.checkpoint_ms = checkpointMs
        try retryingBusy { try Sipral.mediaRecordStartWith(media: handle, path: path, options: options) }
    }

    /// `sipral_media_record_stop`: stop, and finish the file.
    public func stopRecording() throws {
        try retryingBusy { try Sipral.mediaRecordStop(media: handle) }
    }

    /// `sipral_media_record_state`: whether a recording is running, and how
    /// many milliseconds of audio it has taken.
    public var recording: (running: Bool, recordedMs: UInt64) {
        get throws {
            let state = try retryingBusy { try Sipral.mediaRecordState(media: handle) }
            return (state.recording != 0, state.recordedMs)
        }
    }

    /// Every ICE pair, then relay, tried and its outcome. Empty without ICE.
    public func pathCandidates() throws -> [PathCandidate] {
        let count = try Sipral.mediaPathCandidateCount(media: handle)
        return try (0..<count).map { index in
            var local = [CChar](repeating: 0, count: Sipral.addressBytes)
            var remote = [CChar](repeating: 0, count: Sipral.addressBytes)
            var candidate = sipral_path_candidate_t.sized()
            try local.withUnsafeMutableBufferPointer { localBuf in
                try remote.withUnsafeMutableBufferPointer { remoteBuf in
                    candidate.local = localBuf.baseAddress
                    candidate.local_capacity = localBuf.count
                    candidate.remote = remoteBuf.baseAddress
                    candidate.remote_capacity = remoteBuf.count
                    try Sipral.mediaPathCandidateAt(media: handle, index: index, outCandidate: &candidate)
                }
            }
            let text = { (buffer: [CChar], length: Int) in
                String(decoding: buffer.prefix(length).map { UInt8(bitPattern: $0) }, as: UTF8.self)
            }
            return PathCandidate(
                kind: SipralPathKind(rawValue: candidate.kind) ?? .unknown,
                outcome: SipralPathOutcome(rawValue: candidate.outcome) ?? .unknown,
                code: candidate.code,
                localKind: SipralCandidateKind(rawValue: candidate.local_kind) ?? .unknown,
                remoteKind: SipralCandidateKind(rawValue: candidate.remote_kind) ?? .unknown,
                priority: candidate.priority,
                local: text(local, candidate.local_len),
                remote: text(remote, candidate.remote_len)
            )
        }
    }

    /// Queue 16-bit mono PCM to go out, one frame at a time.
    ///
    /// Any length is accepted and re-chunked into frames. Thread-safe, but
    /// not from the media thread. Dropped in `AudioMode.device`.
    public func sendAudio(_ samples: [Int16]) {
        guard pumpsFrames else { return }
        outgoing.sync { toSend.append(samples) }
    }

    /// Set the rate of `frames()` and `sendAudio` independently of the codec
    /// (`sipral_media_set_app_rate`): 8000, 16000, 24000, 48000, or 0 for
    /// the codec's own (the initial value).
    ///
    /// Frame duration is kept, so `sampleRate` and `frameSamples` change.
    /// Unsent queued audio is dropped. Other rates throw `.invalidArgument`;
    /// `AudioMode.device` throws `.wrongState`.
    public func setAppRate(_ hz: UInt32) throws {
        try frameQueue.sync {
            try retryingBusy { try Sipral.mediaSetAppRate(media: handle, hz: hz) }
            let info = try Sipral.mediaInfo(media: handle)
            _sampleRate = Int(info.sample_rate)
            _frameSamples = info.frame_samples
            outgoing.sync {
                pending.removeAll()
                toSend.removeAll()
            }
        }
    }

    private func nextChunk(_ frameSamples: Int) -> [Int16] {
        outgoing.sync {
            while pending.count < frameSamples {
                guard !toSend.isEmpty else {
                    return [Int16](repeating: 0, count: frameSamples)
                }
                pending.append(contentsOf: toSend.removeFirst())
            }
            let chunk = Array(pending.prefix(frameSamples))
            pending.removeFirst(frameSamples)
            return chunk
        }
    }

    /// This call's media socket, as `host:port`: where it is offered now.
    public var localAddress: String {
        ioQueue.sync { socket.localAddress }
    }

    /// Swap in `fresh` and close the old socket (for `Call.moveMedia`).
    func replaceSocket(with fresh: UDPSocket) {
        ioQueue.sync {
            let old = socket
            socket = fresh
            old.close()
        }
    }

    /// Send unless closed: engine packets in device mode, and farewells.
    func sendDatagram(_ payload: [UInt8], to destination: String) {
        ioQueue.sync {
            guard !socketClosed else { return }
            socket.send(payload, to: destination)
        }
    }

    private func receiveOne() -> (data: [UInt8], from: String)? {
        ioQueue.sync { socketClosed ? nil : socket.receive(capacity: 2048) }
    }

    private func drainReceive() {
        while let (receivedData, from) = receiveOne() {
            stateQueue.sync { _remoteAddress = from }
            var mutableData = receivedData
            _ = try? Sipral.mediaReceive(media: handle, data: &mutableData, from: from, nowMs: stack.nowMs())
        }
    }

    /// Pumps the text socket both ways.
    private func pumpText() {
        guard let textSocket else { return }
        while let (data, from) = ioQueue.sync(execute: { socketClosed ? nil : textSocket.receive(capacity: 2048) }) {
            _ = try? Sipral.mediaReceiveText(media: handle, data: data, from: from, nowMs: stack.nowMs())
        }
        drainQueued({ payload, destination, _ in textSocket.send(payload, to: destination) }) { packet in
            try Sipral.mediaPollText(media: self.handle, nowMs: self.stack.nowMs(), packet: &packet)
        }
    }

    /// Send recording copies from each party's socket; the server's RTCP on
    /// them is read and discarded.
    private func pumpRecording() {
        guard ioQueue.sync(execute: { recordingSockets != nil }) else { return }
        for farEnd in [false, true] {
            // the pair held now, never a closed socket
            while ioQueue.sync(execute: { () -> (data: [UInt8], from: String)? in
                guard let open = recordingSockets else { return nil }
                return (farEnd ? open.farEnd : open.thisEnd).receive(capacity: 2048)
            }) != nil {}
        }
        while true {
            var packet = sipral_media_packet_t.sized()
            var data = [UInt8](repeating: 0, count: 1500)
            var destination = [CChar](repeating: 0, count: 128)
            let copied: (payload: [UInt8], destination: String, farEnd: Bool)? = data.withUnsafeMutableBufferPointer { dataBuf in
                destination.withUnsafeMutableBufferPointer { destBuf in
                    packet.data = dataBuf.baseAddress
                    packet.capacity = 1500
                    packet.destination = destBuf.baseAddress
                    packet.destination_capacity = 128
                    guard let farEnd = try? Sipral.mediaPollRecording(media: handle, packet: &packet),
                          packet.len > 0 else { return nil }
                    let payload = Array(UnsafeBufferPointer(start: dataBuf.baseAddress, count: packet.len))
                    let text = destBuf.withMemoryRebound(to: UInt8.self) {
                        String(decoding: UnsafeBufferPointer(start: $0.baseAddress, count: packet.destination_len), as: UTF8.self)
                    }
                    return (payload, text, farEnd != 0)
                }
            }
            guard let copied else { return }
            ioQueue.sync {
                guard let open = recordingSockets else { return }
                (copied.farEnd ? open.farEnd : open.thisEnd).send(copied.payload, to: copied.destination)
            }
        }
    }

    private func drainPacket(_ poll: (inout sipral_media_packet_t) throws -> Void) {
        drainQueued({ payload, destination, protocolRaw in self.send(payload, to: destination, over: protocolRaw) }, poll)
    }

    /// Drain `poll` into `out`.
    private func drainQueued(
        _ out: ([UInt8], String, UInt32) -> Void, _ poll: (inout sipral_media_packet_t) throws -> Void
    ) {
        while true {
            var packet = sipral_media_packet_t.sized()
            var data = [UInt8](repeating: 0, count: 1500)
            var destination = [CChar](repeating: 0, count: 128)
            let sent: Bool = data.withUnsafeMutableBufferPointer { dataBuf in
                destination.withUnsafeMutableBufferPointer { destBuf -> Bool in
                    packet.data = dataBuf.baseAddress
                    packet.capacity = 1500
                    packet.destination = destBuf.baseAddress
                    packet.destination_capacity = 128
                    guard (try? poll(&packet)) != nil, packet.len > 0 else { return false }
                    let payload = Array(UnsafeBufferPointer(start: dataBuf.baseAddress, count: packet.len))
                    let destinationText = destBuf.withMemoryRebound(to: UInt8.self) {
                        String(decoding: UnsafeBufferPointer(start: $0.baseAddress, count: packet.destination_len), as: UTF8.self)
                    }
                    out(payload, destinationText, packet.protocol)
                    return true
                }
            }
            if !sent { return }
        }
    }

    private func captureOnce(_ samples: [Int16]) {
        var packet = sipral_media_packet_t.sized()
        var data = [UInt8](repeating: 0, count: 1500)
        var destination = [CChar](repeating: 0, count: 128)
        data.withUnsafeMutableBufferPointer { dataBuf in
            destination.withUnsafeMutableBufferPointer { destBuf in
                packet.data = dataBuf.baseAddress
                packet.capacity = 1500
                packet.destination = destBuf.baseAddress
                packet.destination_capacity = 128
                guard (try? Sipral.mediaCapture(media: handle, nowMs: stack.nowMs(), samples: samples, packet: &packet)) != nil,
                      packet.len > 0 else { return }
                let payload = Array(UnsafeBufferPointer(start: dataBuf.baseAddress, count: packet.len))
                let destinationText = destBuf.withMemoryRebound(to: UInt8.self) {
                    String(decoding: UnsafeBufferPointer(start: $0.baseAddress, count: packet.destination_len), as: UTF8.self)
                }
                send(payload, to: destinationText, over: packet.protocol)
            }
        }
    }

    /// A datagram from the call's socket, or, when marked TCP/TLS, bytes on
    /// its TURN connection.
    private func send(_ payload: [UInt8], to destination: String, over protocolRaw: UInt32) {
        if protocolRaw == SipralTransport.tcp.rawValue || protocolRaw == SipralTransport.tls.rawValue {
            stack.writeTurn(localAddress, payload)
        } else {
            sendDatagram(payload, to: destination)
        }
    }

    private func run() {
        var active = true
        var next = DispatchTime.now()
        while !isClosed {
            drainReceive()

            if active && (!pumpsFrames || carriedByConference) {
                // The engine or a conference handles audio; only RTCP, ICE
                // and DTLS are left here.
                do {
                    _ = try Sipral.mediaInfo(media: handle)
                } catch let error as SipralError where error.status != .busy {
                    active = false
                    frameBroadcast.finish()
                } catch {
                    // re-entry, as below
                }
                drainPacket { packet in
                    try Sipral.mediaPollRtcp(media: self.handle, nowMs: self.stack.nowMs(), packet: &packet)
                }
                drainPacket { packet in
                    try Sipral.mediaPollTransmit(media: self.handle, nowMs: self.stack.nowMs(), packet: &packet)
                }
                pumpText()
                pumpRecording()
            } else if active {
                frameQueue.sync {
                    var samples = [Int16](repeating: 0, count: _frameSamples)
                    do {
                        let (written, _) = try Sipral.mediaPlayback(media: handle, samples: &samples)
                        if written > 0 {
                            frameBroadcast.send(Array(samples.prefix(written)))
                        }
                    } catch let error as SipralError where error.status != .busy {
                        // The media is gone: finish readers but keep the
                        // loop alive so `close()` finds it responsive.
                        active = false
                        frameBroadcast.finish()
                    } catch {
                        // BUSY would be re-entry: unexpected, not fatal.
                    }

                    captureOnce(nextChunk(_frameSamples))
                }
                drainPacket { packet in
                    try Sipral.mediaPollRtcp(media: self.handle, nowMs: self.stack.nowMs(), packet: &packet)
                }
                drainPacket { packet in
                    try Sipral.mediaPollTransmit(media: self.handle, nowMs: self.stack.nowMs(), packet: &packet)
                }
                pumpText()
                pumpRecording()
            }

            // An absolute schedule, not a sleep per frame: oversleeping would
            // add up to fewer frames per second than the far end expects.
            next = next + .nanoseconds(Int(frameSeconds * 1_000_000_000))
            let now = DispatchTime.now()
            if next > now {
                usleep(useconds_t((next.uptimeNanoseconds - now.uptimeNanoseconds) / 1000))
            } else {
                next = now
            }
        }
        closedSemaphore.signal()
    }

    private var isClosed: Bool { closeQueue.sync { closed } }

    /// Stops the thread, releases the media, closes the socket. Normally
    /// called by `Call.close()`.
    func close() {
        let wasClosed = closeQueue.sync { () -> Bool in
            defer { closed = true }
            return closed
        }
        guard !wasClosed else { return }
        _ = closedSemaphore.wait(timeout: .now() + 5)
        try? Sipral.mediaRelease(media: handle)
        let copies = ioQueue.sync { () -> (thisEnd: UDPSocket, farEnd: UDPSocket)? in
            socketClosed = true
            socket.close()
            textSocket?.close()
            defer { recordingSockets = nil }
            return recordingSockets
        }
        copies?.thisEnd.close()
        copies?.farEnd.close()
        frameBroadcast.finish()
    }

    /// Readers still fed; for tests.
    var debugFrameReaders: Int { frameBroadcast.readerCount }
}
