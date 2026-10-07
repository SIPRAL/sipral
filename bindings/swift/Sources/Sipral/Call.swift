// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import CSipral
import Dispatch

/// A `sipral_handle_t` naming one call, and the actions it takes.
///
/// Made by `SipralStack.placeCall` or `answerCall`, and registered with its
/// stack before the caller sees it, so no event for it is lost.
public final class Call: @unchecked Sendable {
    public unowned let stack: SipralStack
    public let handle: SipralHandle

    /// Unread events or digits one reader holds before dropping its oldest.
    public static let eventBuffer = 4096

    private let eventBroadcast = Broadcast<SipralEvent>(
        label: "org.sipral.call.events", policy: .bufferingNewest(Call.eventBuffer)
    )
    private let dtmfBroadcast = Broadcast<Character>(
        label: "org.sipral.call.dtmf", policy: .bufferingNewest(Call.eventBuffer)
    )
    private let textBroadcast = Broadcast<TextEventData>(
        label: "org.sipral.call.text", policy: .bufferingNewest(Call.eventBuffer)
    )

    /// A new reader of every event this call's handle names, decoded whole.
    ///
    /// Each stream gets every event raised after it is taken, in order, so
    /// take the stream before acting (`let events = call.events()`, then
    /// `try call.hold()`). A late reader can still read `media` (set before
    /// `mediaStarted` is delivered) and `ended` (set before `callEnded`).
    ///
    /// Streams finish after `callEnded`, or on `close()`. A reader that
    /// starts after the end gets `callEnded` alone, so `for await` always
    /// ends. `mediaStatistics` comes after `callEnded` and only reaches
    /// `SipralStack.events()`; its record is kept in `finalStatistics`.
    ///
    /// Each reader buffers up to `Call.eventBuffer` events and drops its own
    /// oldest past that, never slowing the others.
    public func events() -> AsyncStream<SipralEvent> {
        eventBroadcast.stream()
    }

    /// A new reader of just the digits, whether sent as RTP events or heard
    /// in-band (`digitReceived`, `inBandDigit`). Same rules as `events()`;
    /// nothing is replayed after the end.
    public func dtmf() -> AsyncStream<Character> {
        dtmfBroadcast.stream()
    }

    /// A new reader of the far end's real-time text (RFC 4103), for a call
    /// with `text: true` whose far end agreed. Same rules as `dtmf()`.
    public func text() -> AsyncStream<TextEventData> {
        textBroadcast.stream()
    }

    /// Readers still fed; `internal` for tests.
    var debugEventReaders: Int { eventBroadcast.readerCount }

    private let stateQueue = DispatchQueue(label: "org.sipral.call.state")
    private var _media: Media?
    private var _ended = false
    private var _closed = false

    public var media: Media? {
        stateQueue.sync { _media }
    }

    private func setMedia(_ media: Media) {
        stateQueue.sync { _media = media }
    }

    public var ended: Bool {
        stateQueue.sync { _ended }
    }

    private var _finalStatistics: sipral_stream_stats_t?

    /// The final `mediaStatistics` record, which arrives just after
    /// `callEnded`; `nil` before that or if media never started.
    /// `Media.statistics()` also returns it after the end, rather than
    /// `.wrongState`.
    public var finalStatistics: sipral_stream_stats_t? {
        stateQueue.sync { _finalStatistics }
    }

    /// Owned by the call until `media` exists, then by `Media`.
    private let mediaSocket: UDPSocket
    private var _mediaAddress: String
    /// The media socket's `host:port`, also the key of its TURN connection.
    var mediaAddress: String { stateQueue.sync { _mediaAddress } }

    /// The `.incomingCall` this call was taken from, for `identity()` and
    /// `answering()`; `nil` for a call this end placed.
    private let incoming: CallEventData?

    /// The real-time text socket; owned like `mediaSocket`.
    private let textSocket: UDPSocket?

    /// The call's real-time text socket, as `host:port`, when it has one.
    public let textAddress: String?

    /// The running recording session, if any.
    private var _recordingSession: RecordingSession?
    public var recordingSession: RecordingSession? { stateQueue.sync { _recordingSession } }

    /// The descriptor `close()` releases when media never started; `internal`
    /// for the concurrency tests.
    var debugMediaSocketDescriptor: Int32 { mediaSocket.fd }

    init(
        stack: SipralStack, handle: SipralHandle, mediaSocket: UDPSocket, incoming: CallEventData? = nil,
        textSocket: UDPSocket? = nil
    ) {
        self.stack = stack
        self.handle = handle
        self.mediaSocket = mediaSocket
        self._mediaAddress = mediaSocket.localAddress
        self.incoming = incoming
        self.textSocket = textSocket
        self.textAddress = textSocket?.localAddress
    }

    /// For farewells after the call ended and for engine-encoded packets;
    /// goes through `media` once it owns the socket.
    func sendOnMediaSocket(_ payload: [UInt8], to address: String) {
        if let media {
            media.sendDatagram(payload, to: address)
        } else {
            mediaSocket.send(payload, to: address)
        }
    }

    /// Called by `SipralStack` on its own poll thread.
    ///
    /// Side effects (minting `media`, marking `ended`) happen before readers
    /// see `event`, so a woken reader finds them already set.
    func deliver(_ event: SipralEvent) {
        if event.kindRaw == SipralEventKind.mediaStarted.rawValue, media == nil {
            // Behind a NAT the poll thread has been reading this socket for
            // the stack until now; from the media handle on, `Media` does.
            stack.mediaSocketTaken(mediaAddress)
            if let minted = try? Media(
                stack: stack, callHandle: handle, socket: mediaSocket, pumpsFrames: !stack.audioMode.isDevice,
                textSocket: textSocket
            ) {
                setMedia(minted)
            }
        }
        if event.kindRaw == SipralEventKind.mediaStatistics.rawValue, let record = event.mediaData?.statistics {
            stateQueue.sync { _finalStatistics = record }
            media?.ended(with: record)
        }
        if event.kindRaw == SipralEventKind.callEnded.rawValue {
            stateQueue.sync { _ended = true }
            eventBroadcast.finish(after: event)
            dtmfBroadcast.finish()
            textBroadcast.finish()
            return
        }
        if let typed = event.textData {
            textBroadcast.send(typed)
        }
        eventBroadcast.send(event)
        let isDigit = event.kindRaw == SipralEventKind.digitReceived.rawValue
            || event.kindRaw == SipralEventKind.inBandDigit.rawValue
        if isDigit, let digit = event.mediaData?.digit {
            dtmfBroadcast.send(digit)
        }
    }

    // MARK: - state

    /// `sipral_call_state`, read fresh rather than cached from events.
    public var state: SipralCallState? {
        get throws {
            let raw = try retryingBusy { try Sipral.callState(stack: stack.handle, call: handle) }
            return SipralCallState(rawValue: raw)
        }
    }

    // MARK: - actions

    /// `sipral_call_answer_media`: accept on the media socket already open.
    ///
    /// With `text: true` the offered real-time text is taken too. `codecs`
    /// replaces the stack's order (`L16/16000` for linear audio); `focus`
    /// marks this end as a conference focus (RFC 4579). An offer asking for
    /// RTCP feedback is answered on RTP/AVPF regardless (RFC 4585 §4.1);
    /// `feedback` adds Generic NACKs and reduced-size RTCP.
    public func answer(codecs: String? = nil, focus: Bool = false, feedback: Bool = false) throws {
        guard textSocket != nil || codecs != nil || focus || feedback else {
            try retryingBusy {
                try Sipral.callAnswerMedia(
                    stack: stack.handle, call: handle, mediaAddress: mediaAddress, nowMs: stack.nowMs()
                )
            }
            return
        }
        try CStrings.with([mediaAddress, textAddress, codecs]) { parts in
            var config = sipral_call_config_t.sized()
            config.media_address = parts[0].pointer
            config.media_address_len = parts[0].count
            config.text_address = parts[1].pointer
            config.text_address_len = parts[1].count
            config.codecs = parts[2].pointer
            config.codecs_len = parts[2].count
            config.focus = focus ? 1 : 0
            config.feedback = feedback ? SipralToggle.on.rawValue : 0
            try retryingBusy {
                try Sipral.callAnswerWith(
                    stack: stack.handle, call: handle, config: config, configHeaders: [], nowMs: stack.nowMs()
                )
            }
        }
    }

    /// `sipral_call_reject`: 486 Busy Here, 603 Decline, or whatever
    /// response code fits.
    public func reject(code: UInt32 = 486) throws {
        try retryingBusy {
            try Sipral.callReject(stack: stack.handle, call: handle, code: code, nowMs: stack.nowMs())
        }
    }

    public func hangup() throws {
        try retryingBusy {
            try Sipral.callHangup(stack: stack.handle, call: handle, nowMs: stack.nowMs())
        }
    }

    /// `sipral_call_hangup_for`: `hangup()` with a `Reason` (RFC 3326) on
    /// the BYE or CANCEL. An unanswered incoming call gets only the Q.850
    /// value (RFC 6432), since a SIP one would repeat the refusal's status.
    public func hangup(reason: HangupReason) throws {
        try retryingBusy {
            try Sipral.callHangupFor(
                stack: stack.handle, call: handle, sipCause: reason.sipCause ?? 0,
                q850Cause: reason.q850Cause ?? 0, text: reason.text ?? "", nowMs: stack.nowMs()
            )
        }
    }

    /// `sipral_call_redirect`: answer a ringing incoming call with a 3xx
    /// (RFC 3261 §21.3) listing targets in order; 302 is call forwarding.
    /// `reason` (`no-answer`, `user-busy`, `unconditional`, ... any token)
    /// adds a `Diversion` (RFC 5806) naming the called address.
    public func redirect(to targets: [String], status: UInt32 = 302, reason: String? = nil) throws {
        try stack.redirect(call: handle, to: targets, status: status, reason: reason)
    }

    /// Who is calling beyond the `From`: asserted identity (trusted peers
    /// only), `Privacy`, diversion. Empty for an outgoing call.
    public func identity() throws -> CallerIdentity {
        try IdentityReader.identity(stack: stack, call: handle, data: incoming)
    }

    /// How a call that came in asked to be answered (RFC 5373) and rung
    /// (`Alert-Info`).
    public func answering() throws -> Answering {
        try IdentityReader.answering(stack: stack, call: handle, data: incoming)
    }

    /// Move the call's media to the current network, as
    /// `SipralEventKind.callAddressWanted` asks after a network change.
    ///
    /// Binds a socket at `host` (default: the new network's address), maps
    /// it via STUN if configured, and sends a re-INVITE changing only `c=`
    /// and the port (RFC 3264 §8.3.1) with the new `Contact`. The new socket
    /// is used whatever the answer: `.sessionChanged` or
    /// `.sessionChangeFailed`. Under ICE this throws `.wrongState`; use
    /// `restartIce()`.
    public func moveMedia(host: String? = nil, port: UInt16 = 0) throws {
        try stack.moving {
            guard let media else {
                throw SipralError(status: .wrongState, message: "the call has no media to move yet")
            }
            let fresh = try stack.openMediaSocket(host: host ?? stack.currentHost, port: port)
            do {
                let publicAddress = try stack.mapMovedSocket(fresh)
                try retryingBusy {
                    try Sipral.callMediaReaddress(
                        stack: stack.handle, call: handle, mediaAddress: fresh.localAddress,
                        publicAddress: publicAddress ?? "", nowMs: stack.nowMs()
                    )
                }
            } catch {
                stack.giveBackMediaSocket(fresh)
                throw error
            }
            let old = media.localAddress
            stack.mediaSocketTaken(fresh.localAddress)
            stack.forgetMapping(old)
            media.replaceSocket(with: fresh)
            stateQueue.sync { _mediaAddress = fresh.localAddress }
        }
    }

    public func hold() throws {
        try retryingBusy {
            try Sipral.callHold(stack: stack.handle, call: handle, nowMs: stack.nowMs())
        }
    }

    public func resume() throws {
        try retryingBusy {
            try Sipral.callResume(stack: stack.handle, call: handle, nowMs: stack.nowMs())
        }
    }

    /// `sipral_call_transfer`: blind transfer to `target` (RFC 3515). This
    /// end stays until the new call is up; `.transferProgress` then
    /// `.transferDone` report it.
    public func transfer(to target: String) throws {
        try retryingBusy {
            try Sipral.callTransfer(stack: stack.handle, call: handle, target: target, nowMs: stack.nowMs())
        }
    }

    /// `sipral_call_restart_ice`: re-offer with new ICE credentials (RFC 8445
    /// §9) and recheck pairs while the current path carries audio; for lost
    /// consent or a network change. The new path arrives as `.mediaPathChosen`.
    public func restartIce() throws {
        try retryingBusy {
            try Sipral.callRestartIce(stack: stack.handle, call: handle, nowMs: stack.nowMs())
        }
    }

    /// `sipral_call_send_dtmf`. `.rtp` sends named events, or the tones in
    /// the audio on a call that negotiated none; `.inBand` sends the tones
    /// on any call.
    public func sendDtmf(_ digits: String, via: SipralDtmf = .rtp, durationMs: UInt32 = 100) throws {
        try retryingBusy {
            try Sipral.callSendDtmf(
                stack: stack.handle, call: handle, digits: digits, via: via.rawValue,
                durationMs: durationMs, nowMs: stack.nowMs()
            )
        }
    }

    /// `sipral_call_dtmf_detection`: when this call listens for digits in the
    /// far end's audio. One heard there is a `SipralEventKind.inBandDigit`,
    /// and reaches `dtmf()` like any other.
    public func setDtmfDetection(_ mode: SipralDtmfDetection) throws {
        try retryingBusy {
            try Sipral.callDtmfDetection(stack: stack.handle, call: handle, mode: mode.rawValue)
        }
    }

    /// `sipral_call_detect_progress`: detect network tones, who answered,
    /// and a machine's beep. Call right after `placeCall`, before the
    /// answer; each finding is a `progressDetected` event.
    public func detectProgress(_ options: ProgressOptions = ProgressOptions()) throws {
        var config = sipral_progress_config_t()
        config.size = MemoryLayout<sipral_progress_config_t>.size
        config.listen = SipralToggle.on.rawValue
        config.region = options.region.rawValue
        config.answering_machine = (options.answeringMachine ? SipralToggle.on : SipralToggle.off).rawValue
        config.beep = (options.beep ? SipralToggle.on : SipralToggle.off).rawValue
        config.beep_window_ms = options.beepWindowMs
        config.max_initial_silence_ms = options.maxInitialSilenceMs
        config.max_greeting_ms = options.maxGreetingMs
        config.silence_after_greeting_ms = options.silenceAfterGreetingMs
        config.max_words = options.maxWords
        config.min_word_ms = options.minWordMs
        config.min_word_gap_ms = options.minWordGapMs
        config.max_decision_ms = options.maxDecisionMs
        config.min_speech_above_floor_db = options.minSpeechAboveFloorDb
        config.beep_min_ms = options.beepMinMs
        config.beep_max_ms = options.beepMaxMs
        config.tone_cycles = options.toneCycles
        try retryingBusy { try Sipral.callDetectProgress(stack: stack.handle, call: handle, config: config) }
    }

    /// `sipral_call_detect_progress` with listening off.
    public func stopProgress() throws {
        var config = sipral_progress_config_t()
        config.size = MemoryLayout<sipral_progress_config_t>.size
        config.listen = SipralToggle.off.rawValue
        try retryingBusy { try Sipral.callDetectProgress(stack: stack.handle, call: handle, config: config) }
    }

    /// `sipral_call_consent_tone`: beep while recording; zeros mean 1400 Hz,
    /// -18 dBm0, 200 ms every 15 s. `local` plays it here too.
    public func setConsentTone(
        frequencyHz: UInt32 = 0, attenuationDb: UInt32 = 0, lengthMs: UInt32 = 0,
        intervalMs: UInt32 = 0, local: Bool = true
    ) throws {
        var tone = sipral_consent_tone_t()
        tone.size = MemoryLayout<sipral_consent_tone_t>.size
        tone.enabled = SipralToggle.on.rawValue
        tone.frequency_hz = frequencyHz
        tone.attenuation_db = attenuationDb
        tone.length_ms = lengthMs
        tone.interval_ms = intervalMs
        tone.local = (local ? SipralToggle.on : SipralToggle.off).rawValue
        try retryingBusy { try Sipral.callConsentTone(stack: stack.handle, call: handle, tone: tone) }
    }

    /// `sipral_call_consent_tone` with the tone off.
    public func clearConsentTone() throws {
        var tone = sipral_consent_tone_t()
        tone.size = MemoryLayout<sipral_consent_tone_t>.size
        tone.enabled = SipralToggle.off.rawValue
        try retryingBusy { try Sipral.callConsentTone(stack: stack.handle, call: handle, tone: tone) }
    }

    // MARK: - conferences

    /// `sipral_call_set_focus`: add or drop `isfocus` (RFC 4579 §4.2) on the
    /// `Contact` of the next answer, re-INVITE or UPDATE.
    public func setFocus(_ focus: Bool) throws {
        try retryingBusy { try Sipral.callSetFocus(stack: stack.handle, call: handle, focus: focus ? 1 : 0) }
    }

    /// `sipral_call_conference_uri`: the conference URI if the far end is a
    /// focus, else `nil`.
    public func conferenceUri() throws -> String? {
        do {
            return try ProtocolText.read { buffer in
                try retryingBusy { try Sipral.callConferenceUri(stack: stack.handle, call: handle, buffer: &buffer) }
            }
        } catch let error as SipralError where error.status == .notAFocus {
            return nil
        }
    }

    /// `sipral_call_subscribe_conference`: subscribe to the focus's
    /// conference package (RFC 4579 §3.4). The subscription outlives the
    /// call; each update is `conferenceChanged`, read with
    /// `SipralSubscription.conference()`. `.notAFocus` if the far end is not.
    public func subscribeConference() throws -> SipralSubscription {
        let made = try retryingBusy {
            try Sipral.callSubscribeConference(stack: stack.handle, call: handle, nowMs: stack.nowMs())
        }
        return SipralSubscription(stack: stack, handle: made, package: "conference")
    }

    // MARK: - a recording server

    /// `sipral_call_record_to`: record to a SIPREC server (RFC 7866, metadata
    /// RFC 7865). The session goes to `destination` over a TCP connection
    /// opened for it, or, with none, where the account sends, which then
    /// must be TCP or TLS: the INVITE is too large for UDP. Two sockets at
    /// `host` carry the audio copies. `.wrongState` before `mediaStarted` or
    /// when already recording.
    public func record(toServer server: String, destination: String? = nil, host: String = "127.0.0.1") throws -> RecordingSession {
        guard let media else {
            throw SipralError(status: .wrongState, message: "the call's media has not started")
        }
        let thisEnd = try UDPSocket(host: host, port: 0)
        let farEnd: UDPSocket
        do {
            farEnd = try UDPSocket(host: host, port: 0)
        } catch {
            thisEnd.close()
            throw error
        }
        let recording: SipralHandle
        var link: UInt32?
        do {
            link = try destination.map { try stack.openRecordingLink(to: $0) }
            recording = try CStrings.with([server, destination, thisEnd.localAddress, farEnd.localAddress]) { parts in
                var config = sipral_record_config_t.sized()
                config.server = parts[0].pointer
                config.server_len = parts[0].count
                config.destination = parts[1].pointer
                config.destination_len = parts[1].count
                config.transport = link ?? 0
                config.this_end = parts[2].pointer
                config.this_end_len = parts[2].count
                config.far_end = parts[3].pointer
                config.far_end_len = parts[3].count
                return try retryingBusy {
                    try Sipral.callRecordTo(stack: stack.handle, call: handle, config: config, nowMs: stack.nowMs())
                }
            }
        } catch {
            if let link {
                stack.closeRecordingLink(link)
            }
            thisEnd.close()
            farEnd.close()
            throw error
        }
        media.copyRecording(thisEnd: thisEnd, farEnd: farEnd)
        let session = RecordingSession(
            handle: recording, thisEnd: thisEnd.localAddress, farEnd: farEnd.localAddress, call: self
        )
        stateQueue.sync { _recordingSession = session }
        stack.recordingStarted(session.handle, of: self, link: link)
        return session
    }

    /// `sipral_call_stop_recording_to`: hang up the recording session.
    public func stopRecordingToServer() throws {
        try retryingBusy { try Sipral.callStopRecordingTo(stack: stack.handle, call: handle, nowMs: stack.nowMs()) }
        recordingEnded()
    }

    /// The recording session is over, whoever ended it: the copies stop and
    /// their sockets close.
    func recordingEnded() {
        stateQueue.sync { _recordingSession = nil }
        media?.stopCopyingRecording()
    }

    /// Hang up if still up, release media, forget the call. Idempotent and
    /// safe under concurrent callers: without the guard, two closes of a call
    /// with no media would close the descriptor twice, and by the second
    /// another thread may have reused that number.
    public func close() {
        let wasClosed = stateQueue.sync { () -> Bool in
            defer { _closed = true }
            return _closed
        }
        guard !wasClosed else { return }

        if !ended {
            try? hangup()
        }
        if let media {
            media.close()
        } else {
            stack.giveBackMediaSocket(mediaSocket)
            textSocket?.close()
        }
        stack.forgetCall(handle)
        eventBroadcast.finish()
        dtmfBroadcast.finish()
        textBroadcast.finish()
    }
}

/// Options for `Call.detectProgress`; each zero limit means the library's
/// default (`sipral_progress_config_t`).
public struct ProgressOptions: Sendable {
    public var region: SipralToneRegion = .europe
    public var answeringMachine = true
    public var beep = true
    public var beepWindowMs: UInt32 = 0
    public var maxInitialSilenceMs: UInt32 = 0
    public var maxGreetingMs: UInt32 = 0
    public var silenceAfterGreetingMs: UInt32 = 0
    public var maxWords: UInt32 = 0
    public var minWordMs: UInt32 = 0
    public var minWordGapMs: UInt32 = 0
    public var maxDecisionMs: UInt32 = 0
    public var minSpeechAboveFloorDb: UInt32 = 0
    public var beepMinMs: UInt32 = 0
    public var beepMaxMs: UInt32 = 0
    public var toneCycles: UInt32 = 0

    public init() {}
}
