// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import CSipral
import Dispatch

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
public final class Media: @unchecked Sendable {
    public let handle: SipralHandle
    public let sampleRate: Int
    public let frameSamples: Int
    private let frameSeconds: Double

    private let stack: SipralStack
    private let socket: UDPSocket

    private let stateQueue = DispatchQueue(label: "org.sipral.media.state")
    private var _remoteAddress: String?
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

    init(stack: SipralStack, callHandle: SipralHandle, socket: UDPSocket) throws {
        self.stack = stack
        self.socket = socket
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
    /// media thread itself.
    public func sendAudio(_ samples: [Int16]) {
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

    private func drainReceive() {
        while let (receivedData, from) = socket.receive(capacity: 2048) {
            stateQueue.sync { _remoteAddress = from }
            var mutableData = receivedData
            _ = try? Sipral.mediaReceive(media: handle, data: &mutableData, from: from, nowMs: stack.nowMs())
        }
    }

    private func drainPacket(_ poll: (inout sipral_media_packet_t) throws -> Void) {
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
                    send(payload, to: destinationText, over: packet.protocol)
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
            stack.writeTurn(socket.localAddress, payload)
        } else {
            socket.send(payload, to: destination)
        }
    }

    private func run() {
        var active = true
        while !isClosed {
            let started = DispatchTime.now()
            drainReceive()

            if active {
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
        socket.close()
        frameBroadcast.finish()
    }

    /// How many readers of `frames(bufferingNewest:)` are still being fed --
    /// `internal`, for the tests.
    var debugFrameReaders: Int { frameBroadcast.readerCount }
}
