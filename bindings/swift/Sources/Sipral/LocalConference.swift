// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import CSipral
import Dispatch

/// One member of a `LocalConference`, as `sipral_local_conference_member_at`
/// reads it: its handle -- a call's, or the conference's own for this end --
/// whether it is talking, its two mutes and its two gains in the audio
/// engine's steps (256 is unity).
public struct ConferenceMember: Sendable, Equatable {
    public let member: SipralHandle
    public let talking: Bool
    public let mutedInput: Bool
    public let mutedOutput: Bool
    public let gainInput: UInt32
    public let gainOutput: UInt32
}

/// A local conference: any number of this stack's calls, each on its own
/// codec and rate, mixed here so that every member hears everybody but
/// itself -- this end too, unless it was made without (`docs/08-ffi.md`,
/// "A local conference").
///
/// A call added stops carrying its own frames -- its `Media` goes on reading
/// the socket and sending RTCP -- and the conference carries them instead:
/// on a stack in `AudioMode.device` the library's audio engine does, and
/// every packet leaves from the member's own socket through the stack's
/// transmit path; in `AudioMode.application` a thread of this class's own
/// ticks every twenty milliseconds -- `sendAudio` is this end's microphone,
/// `frames()` what it hears. What changes arrives on the stack's events as
/// `SipralEventKind.localConferenceChanged`, with `localConferenceData`.
public final class LocalConference: @unchecked Sendable {
    /// The conference's handle, which is also this end's name as a member.
    public let handle: SipralHandle
    /// Whether this end takes part.
    public let local: Bool
    /// The rate of this end's frames, in hertz.
    public let sampleRate: Int
    /// Samples in one of this end's frames: twenty milliseconds.
    public let frameSamples: Int

    private let stack: SipralStack
    private let stateQueue = DispatchQueue(label: "org.sipral.conference.state")
    private var members: [SipralHandle: Call] = [:]
    private var pending: [Int16] = []
    private var toSend: [[Int16]] = []
    private var closed = false
    private let finished = DispatchSemaphore(value: 0)
    private var ticking = false
    private let frameBroadcast = Broadcast<[Int16]>(
        label: "org.sipral.conference.frames", policy: .bufferingNewest(Media.frameBuffer)
    )

    /// `sipral_local_conference_create`. `maxMembers` counts this end;
    /// `sampleRate` is the rate of its frames -- 8000, 16000, 32000 or
    /// 48000 -- in application mode. A rate the conference cannot mix throws
    /// `SipralError` with `.conferenceRefused`.
    public init(stack: SipralStack, maxMembers: UInt32 = 16, local: Bool = true, sampleRate: UInt32 = 16000) throws {
        self.stack = stack
        var config = sipral_local_conference_config_t.sized()
        config.max_members = maxMembers
        config.local = local ? 0 : SipralToggle.off.rawValue
        config.sample_rate = sampleRate
        let made = config
        handle = try retryingBusy { try Sipral.localConferenceCreate(stack: stack.handle, config: made) }
        let info = try Sipral.localConferenceInfo(conference: handle)
        self.local = info.local != 0
        self.sampleRate = Int(info.sample_rate)
        self.frameSamples = Int(info.frame_samples)
        if !stack.audioMode.isDevice {
            ticking = true
            DispatchQueue.global(qos: .userInitiated).async { [self] in run() }
        }
    }

    /// `sipral_local_conference_add`: `call` takes part from the next tick,
    /// at its own codec's rate. A full conference, a call already in one, or
    /// a codec it cannot mix throws with `.conferenceRefused`.
    public func add(_ call: Call) throws {
        // the call's own thread stops carrying frames before the conference
        // starts, so that no frame is taken twice; a call refused keeps
        // whatever it had -- a call already in this conference keeps being
        // carried by it
        let was = call.media?.carriedByConference ?? false
        call.media?.setCarriedByConference(true)
        do {
            try retryingBusy { try Sipral.localConferenceAdd(conference: handle, call: call.handle) }
        } catch {
            call.media?.setCarriedByConference(was)
            throw error
        }
        stateQueue.sync { members[call.handle] = call }
    }

    /// `sipral_local_conference_remove`: `call` carries its own frames again
    /// from the next tick.
    public func remove(_ call: Call) throws {
        try retryingBusy { try Sipral.localConferenceRemove(conference: handle, call: call.handle) }
        _ = stateQueue.sync { members.removeValue(forKey: call.handle) }
        call.media?.setCarriedByConference(false)
    }

    /// Mute or unmute one way of a member -- `nil` for this end: `.input` is
    /// what it says, `.output` what it hears.
    public func setMuted(_ member: Call?, _ direction: SipralAudioDirection, _ muted: Bool = true) throws {
        let named = member?.handle ?? handle
        try retryingBusy {
            try Sipral.localConferenceSetMuted(
                conference: handle, member: named, direction: direction.rawValue, muted: muted ? 1 : 0
            )
        }
    }

    /// The level of one way of a member, in the audio engine's steps: 256 is
    /// unity, 1024 four times.
    public func setGain(_ member: Call?, _ direction: SipralAudioDirection, _ gain: UInt32) throws {
        let named = member?.handle ?? handle
        try retryingBusy {
            try Sipral.localConferenceSetGain(conference: handle, member: named, direction: direction.rawValue, gain: gain)
        }
    }

    /// `sipral_local_conference_info`.
    public func info() throws -> sipral_local_conference_info_t {
        try retryingBusy { try Sipral.localConferenceInfo(conference: handle) }
    }

    /// Every member, this end first.
    public func memberList() throws -> [ConferenceMember] {
        let count = Int(try info().members)
        return try (0..<count).map { index in
            let member = try retryingBusy { try Sipral.localConferenceMemberAt(conference: handle, index: index) }
            return ConferenceMember(
                member: member.member, talking: member.talking != 0, mutedInput: member.muted_input != 0,
                mutedOutput: member.muted_output != 0, gainInput: member.gain_input, gainOutput: member.gain_output
            )
        }
    }

    /// Who was talking in the last tick, loudest first, by handle.
    public func talkers() throws -> [SipralHandle] {
        let count = Int(try info().talkers)
        var found: [SipralHandle] = []
        for index in 0..<count {
            guard let talker = try? Sipral.localConferenceTalkerAt(conference: handle, index: index) else { break }
            found.append(talker)
        }
        return found
    }

    /// `sipral_local_conference_record_start`: the whole mix, one channel, to
    /// `path`, at the conference's rate unless `sampleRate` names another.
    public func record(to path: String, format: SipralRecordingFormat = .wav, sampleRate: UInt32 = 0) throws {
        var options = sipral_recording_options_t.sized()
        options.format = format.rawValue
        options.sample_rate = sampleRate
        let chosen = options
        try retryingBusy { try Sipral.localConferenceRecordStart(conference: handle, path: path, options: chosen) }
    }

    /// `sipral_local_conference_record_stop`: stop, and finish the file.
    public func stopRecording() throws {
        try retryingBusy { try Sipral.localConferenceRecordStop(conference: handle) }
    }

    /// What this end says, 16-bit mono PCM at `sampleRate`, in any length:
    /// the conference's thread takes a frame of it every tick.
    public func sendAudio(_ samples: [Int16]) {
        stateQueue.sync { toSend.append(samples) }
    }

    /// A new reader of what this end hears, one frame each, in application
    /// mode; `Media.frames(bufferingNewest:)` says how a reader that falls
    /// behind is kept.
    public func frames(bufferingNewest limit: Int = Media.frameBuffer) -> AsyncStream<[Int16]> {
        frameBroadcast.stream(bufferingPolicy: .bufferingNewest(max(limit, 1)))
    }

    private var isClosed: Bool { stateQueue.sync { closed } }

    private func nextChunk() -> [Int16] {
        stateQueue.sync {
            while pending.count < frameSamples, !toSend.isEmpty {
                pending.append(contentsOf: toSend.removeFirst())
            }
            let taken = min(frameSamples, pending.count)
            var chunk = Array(pending.prefix(taken))
            pending.removeFirst(taken)
            chunk.append(contentsOf: repeatElement(0, count: frameSamples - taken))
            return chunk
        }
    }

    private func run() {
        var speaker = [Int16](repeating: 0, count: frameSamples)
        var next = DispatchTime.now()
        while !isClosed {
            guard let written = try? Sipral.localConferenceTick(
                conference: handle, nowMs: stack.nowMs(), mic: nextChunk(), speaker: &speaker
            ) else { break }
            if local {
                frameBroadcast.send(Array(speaker.prefix(written)))
            }
            sendWaiting()
            next = next + .milliseconds(20)
            if next > DispatchTime.now() {
                _ = finished.wait(timeout: next)
            } else {
                next = DispatchTime.now()
            }
        }
        frameBroadcast.finish()
        stateQueue.sync { ticking = false }
    }

    /// Every packet the tick left, out from its member's own socket.
    private func sendWaiting() {
        while true {
            var packet = sipral_media_packet_t.sized()
            var data = [UInt8](repeating: 0, count: 1500)
            var destination = [CChar](repeating: 0, count: 128)
            let sent: (SipralHandle, [UInt8], String)? = data.withUnsafeMutableBufferPointer { dataBuf in
                destination.withUnsafeMutableBufferPointer { destBuf in
                    packet.data = dataBuf.baseAddress
                    packet.capacity = 1500
                    packet.destination = destBuf.baseAddress
                    packet.destination_capacity = 128
                    guard let call = try? Sipral.localConferencePollTransmit(conference: handle, packet: &packet),
                          packet.len > 0 else { return nil }
                    let payload = Array(UnsafeBufferPointer(start: dataBuf.baseAddress, count: packet.len))
                    let text = destBuf.withMemoryRebound(to: UInt8.self) {
                        String(decoding: UnsafeBufferPointer(start: $0.baseAddress, count: packet.destination_len), as: UTF8.self)
                    }
                    return (call, payload, text)
                }
            }
            guard let (call, payload, text) = sent else { return }
            let member = stateQueue.sync { members[call] }
            member?.sendOnMediaSocket(payload, to: text)
        }
    }

    /// `sipral_local_conference_destroy`: every call still in it carries its
    /// own frames again, a recording running is finished, and the handle is
    /// spent.
    public func close() {
        let (wasClosed, wasTicking) = stateQueue.sync { () -> (Bool, Bool) in
            let before = closed
            closed = true
            return (before, ticking)
        }
        if wasClosed { return }
        finished.signal()
        if wasTicking {
            let deadline = DispatchTime.now() + .seconds(5)
            while stateQueue.sync(execute: { ticking }), DispatchTime.now() < deadline {
                usleep(1_000)
            }
        }
        let left = stateQueue.sync { () -> [Call] in
            let calls = Array(members.values)
            members.removeAll()
            return calls
        }
        for call in left {
            call.media?.setCarriedByConference(false)
        }
        _ = try? retryingBusy { try Sipral.localConferenceDestroy(conference: handle) }
    }

    deinit {
        close()
    }
}
