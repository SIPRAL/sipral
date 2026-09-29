// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

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
/// A call's media has a handle of its own and never takes the stack's lock
/// (`docs/08-ffi.md`, "A call's media has a handle of its own"), so it runs
/// on a thread of its own too -- the one place in this layer where audio
/// crosses as `[Int16]`, paced by `sipral_media_info_t.frameMs` rather than
/// by whatever rate the caller happens to call `sendAudio` at
/// (`bindings/python/sipral/media.py`'s `Media` is the same shape).
///
/// Not built directly: `Call` mints one from its own
/// `SipralEventKind.mediaStarted` and hands it over as `call.media`.
///
/// On a stack in `AudioMode.device` the library's engine takes the far
/// end's audio and gives the microphone's, so this thread carries only the
/// packets: `frames(bufferingNewest:)` hands out nothing and `sendAudio` is
/// not read (`pumpsFrames` says which). Statistics, the ICE paths and the
/// socket are the same in both modes.
public final class Media: @unchecked Sendable {
    public let handle: SipralHandle
    public let sampleRate: Int
    public let frameSamples: Int
    private let frameSeconds: Double

    /// Whether this media carries the call's frames through `frames()` and
    /// `sendAudio` -- `AudioMode.application` -- or the library's engine does.
    public let pumpsFrames: Bool

    private let stack: SipralStack
    /// The call's socket, guarded by `ioQueue` -- as is every send and
    /// receive on it -- since `Call.moveMedia` puts another in its place
    /// and the engine's thread sends on it in device mode.
    private var socket: UDPSocket
    private var socketClosed = false
    private let ioQueue = DispatchQueue(label: "org.sipral.media.io")

    private let stateQueue = DispatchQueue(label: "org.sipral.media.state")
    private var _remoteAddress: String?
    /// Whether a `LocalConference` carries this call's frames, which this
    /// media's own thread then leaves alone, as it does in device mode.
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
    /// Every call returns a stream of its own, and every stream gets every
    /// frame decoded from the moment it is taken -- a recorder and a speech
    /// recogniser can both listen to the same call. A reader that falls
    /// behind keeps only the newest `limit` frames and drops the older ones,
    /// so a slow reader costs a bounded amount of memory and never holds up
    /// the media thread or any other reader: audio that old is of no use to
    /// a live call anyway. Every stream finishes when this media ends --
    /// `close()`, or the stack reporting the media gone -- and one taken
    /// after that is finished from the start.
    public func frames(bufferingNewest limit: Int = Media.frameBuffer) -> AsyncStream<[Int16]> {
        frameBroadcast.stream(bufferingPolicy: .bufferingNewest(max(limit, 1)))
    }

    private let outgoing = DispatchQueue(label: "org.sipral.media.outgoing")
    private var pending: [Int16] = []
    private var toSend: [[Int16]] = []

    private let closedSemaphore = DispatchSemaphore(value: 0)
    private var closed = false
    private let closeQueue = DispatchQueue(label: "org.sipral.media.close")

    /// The call's real-time text socket, when it has one: read and written
    /// on this thread beside the audio, and closed with it.
    private let textSocket: UDPSocket?
    /// The two sockets the copies for a recording server leave from, while
    /// a recording session runs, guarded by `ioQueue`.
    private var recordingSockets: (thisEnd: UDPSocket, farEnd: UDPSocket)?

    init(stack: SipralStack, callHandle: SipralHandle, socket: UDPSocket, pumpsFrames: Bool, textSocket: UDPSocket? = nil) throws {
        self.stack = stack
        self.socket = socket
        self.pumpsFrames = pumpsFrames
        self.textSocket = textSocket
        self.handle = try retryingBusy { try Sipral.callMedia(stack: stack.handle, call: callHandle) }

        let info = try Sipral.mediaInfo(media: handle)
        self.sampleRate = Int(info.sample_rate)
        self.frameSamples = info.frame_samples
        self.frameSeconds = Double(max(info.frame_ms, 1)) / 1000.0

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in self?.run() }
    }

    public func info() throws -> sipral_media_info_t {
        try Sipral.mediaInfo(media: handle)
    }

    public func statistics() throws -> sipral_stream_stats_t {
        try Sipral.mediaStatistics(media: handle, nowMs: stack.nowMs())
    }

    /// What the call agreed about RTCP feedback (RFC 4585, RFC 5506), read
    /// fresh from `sipral_media_info_t`: whether the stream runs RTP/AVPF,
    /// with Generic NACKs, and with reduced-size RTCP. A call asks for it
    /// with `SipralStack.placeCall(feedback: true)`; an offer that asks is
    /// answered in kind. `statistics()` counts what it did.
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

    /// `sipral_media_send_text`: queue what the user typed for the far end
    /// (RFC 4103, T.140), UTF-8. It leaves in the next 300 ms interval, each
    /// block sent twice more as redundancy where both ends agreed `red`; a
    /// new line goes as one, and BACKSPACE (U+0008) erases the far end's
    /// last character. `.notNegotiated` on a call that agreed no text
    /// stream, `.exhausted` when more is waiting unsent than a stream holds.
    public func sendText(_ text: String) throws {
        try retryingBusy { try Sipral.mediaSendText(media: handle, text: text) }
    }

    /// The recorded call's copies leave from these two sockets from now on
    /// (`Call.record(toServer:destination:host:)`).
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

    /// The call's encryption report, now (`sipral_media_encryption_count`
    /// and `sipral_media_encryption_at`): per stream, whether it is
    /// encrypted, how its keys were exchanged, the suite, and whether the
    /// exchange authenticated the far end -- SDES never does, a DTLS-SRTP
    /// handshake whose certificate matched the signalled fingerprint does.
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

    /// `sipral_media_record_start_with`: record both directions to `path` --
    /// WAV, or Ogg Opus where the build has Opus; one channel, or this end
    /// on the left and the far end on the right; at `sampleRate` (zero for
    /// the call's); Ogg Opus at `bitrate` (zero for libopus's choice); made
    /// to survive a crash every `checkpointMs` (zero for five seconds). The
    /// file is finished by `stopRecording()`, by the call ending, or by the
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

    /// Every path this call's ICE agent tried -- the candidate pairs its
    /// checklist held, then the relays it held -- and what became of each
    /// (`sipral_media_path_candidate_count`/`_at`; D5's transport and NAT
    /// half, `docs/05-media.md`). Empty for a call not using ICE.
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
    /// A chunk shorter or longer than one frame is accepted and split (or
    /// padded with what the next call adds) across as many capture calls as
    /// it takes. Thread-safe: called from whatever thread the application
    /// runs its own audio loop or voice-agent callback on, never from the
    /// media thread itself. In `AudioMode.device` the microphone is the
    /// engine's and this is dropped: nothing would ever read it.
    public func sendAudio(_ samples: [Int16]) {
        guard pumpsFrames else { return }
        outgoing.sync { toSend.append(samples) }
    }

    private func nextChunk() -> [Int16] {
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

    /// Put `fresh` in the place of the call's socket, and close the old one:
    /// `Call.moveMedia` once the call has been offered at the new one.
    func replaceSocket(with fresh: UDPSocket) {
        ioQueue.sync {
            let old = socket
            socket = fresh
            old.close()
        }
    }

    /// One datagram out of the call's socket, unless it is closed: what the
    /// library's engine hands `SipralStack` to send in device mode, and a
    /// farewell after the call.
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

    /// What arrived on the text socket, to `sipral_media_receive_text`, and
    /// what is due on it, out of it.
    private func pumpText() {
        guard let textSocket else { return }
        while let (data, from) = ioQueue.sync(execute: { socketClosed ? nil : textSocket.receive(capacity: 2048) }) {
            _ = try? Sipral.mediaReceiveText(media: handle, data: data, from: from, nowMs: stack.nowMs())
        }
        drainQueued({ payload, destination, _ in textSocket.send(payload, to: destination) }) { packet in
            try Sipral.mediaPollText(media: self.handle, nowMs: self.stack.nowMs(), packet: &packet)
        }
    }

    /// Every copy waiting for the recording server, out of the socket its
    /// party's stream is offered from. What the server sends back on them
    /// (its RTCP) is read and let go.
    private func pumpRecording() {
        guard ioQueue.sync(execute: { recordingSockets != nil }) else { return }
        for farEnd in [false, true] {
            // read through the pair held now, never a socket already closed
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

    /// Every packet `poll` hands out, each to `out` with its destination and
    /// what it goes over, until it hands out none.
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

    /// One packet out where it says: a datagram from this call's socket, or
    /// -- marked TCP or TLS -- bytes on the socket's connection to the TURN
    /// server, which the stack holds.
    private func send(_ payload: [UInt8], to destination: String, over protocolRaw: UInt32) {
        if protocolRaw == SipralTransport.tcp.rawValue || protocolRaw == SipralTransport.tls.rawValue {
            stack.writeTurn(localAddress, payload)
        } else {
            sendDatagram(payload, to: destination)
        }
    }

    private func run() {
        var active = true
        while !isClosed {
            let started = DispatchTime.now()
            drainReceive()

            if active && (!pumpsFrames || carriedByConference) {
                // the engine, or a local conference, plays and captures;
                // what is left here is the packets it does not carry: RTCP,
                // and ICE's and DTLS's
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
                var samples = [Int16](repeating: 0, count: frameSamples)
                do {
                    let (written, _) = try Sipral.mediaPlayback(media: handle, samples: &samples)
                    if written > 0 {
                        frameBroadcast.send(Array(samples.prefix(written)))
                    }
                } catch let error as SipralError where error.status != .busy {
                    // The media (or its call, or its stack) is gone
                    // (`docs/08-ffi.md`, "A media handle outlives its call,
                    // and says so"): stop driving it, and tell every reader
                    // no frame is coming, but let the loop keep running so
                    // `close()` still finds it responsive.
                    active = false
                    frameBroadcast.finish()
                } catch {
                    // BUSY here means re-entry from inside a frame this
                    // thread is already running -- not expected on this
                    // path, but not fatal either.
                }

                captureOnce(nextChunk())
                drainPacket { packet in
                    try Sipral.mediaPollRtcp(media: self.handle, nowMs: self.stack.nowMs(), packet: &packet)
                }
                drainPacket { packet in
                    try Sipral.mediaPollTransmit(media: self.handle, nowMs: self.stack.nowMs(), packet: &packet)
                }
                pumpText()
                pumpRecording()
            }

            let elapsedNs = DispatchTime.now().uptimeNanoseconds &- started.uptimeNanoseconds
            let remaining = frameSeconds - Double(elapsedNs) / 1_000_000_000
            if remaining > 0 {
                usleep(useconds_t(remaining * 1_000_000))
            }
        }
        closedSemaphore.signal()
    }

    private var isClosed: Bool { closeQueue.sync { closed } }

    /// Stops the frame-rate thread, `sipral_media_release`, closes the
    /// socket. Called by `Call.close()`, not usually by an application
    /// directly.
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

    /// How many readers of `frames(bufferingNewest:)` are still being fed --
    /// `internal`, for the tests.
    var debugFrameReaders: Int { frameBroadcast.readerCount }
}
