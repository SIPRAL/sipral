// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import CSipral
import Dispatch

/// A `sipral_handle_t` naming one call, and the actions it takes.
///
/// Built by `SipralStack.placeCall` for one this stack placed, and by
/// `SipralStack.answerCall` for one that came in; either way it is
/// registered with its stack before the caller ever sees it, so `deliver`
/// always has somewhere to put an event that names this call
/// (`bindings/python/sipral/call.py`'s `Call` is the same shape).
public final class Call: @unchecked Sendable {
    public unowned let stack: SipralStack
    public let handle: SipralHandle

    /// How many events, or digits, one reader of `events()` or `dtmf()` holds
    /// unread before it starts dropping its oldest -- the same bound, and the
    /// same choice of what to drop, as the Kotlin layer's `SipralCall.events`.
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
    /// Every call returns a stream of its own, and every stream gets every
    /// event, in the order the stack raised them: a `CallKitBridge` bound to
    /// this call and the application's own loop over it both see all of
    /// them. A reader sees what arrives from the moment this returns, and
    /// nothing before -- so take the stream first and act second:
    /// `let events = call.events()`, then `try call.hold()`, then wait on
    /// `events`. What a late reader missed that still matters can be read
    /// directly: `media` is set before `SipralEventKind.mediaStarted` is
    /// delivered, `ended` before `SipralEventKind.callEnded`.
    ///
    /// Every stream finishes when the call ends, right after its
    /// `SipralEventKind.callEnded`, or when `close()` runs first. A reader
    /// that starts after the end gets that `callEnded` event alone and
    /// finishes at once, so `for await` over a fresh stream always ends.
    /// `SipralEventKind.mediaStatistics`, which comes after `callEnded`,
    /// reaches the stack's `SipralStack.events()` only; the record it
    /// carries is kept in `finalStatistics`.
    ///
    /// Each reader buffers on its own, up to `Call.eventBuffer` events; one
    /// that falls further behind drops its own oldest, and never slows the
    /// others. A reader that stops -- its loop left, its task cancelled --
    /// is fed nothing more.
    public func events() -> AsyncStream<SipralEvent> {
        eventBroadcast.stream()
    }

    /// A new reader of just the digits: `SipralEventKind.digitReceived`'s
    /// and `SipralEventKind.inBandDigit`'s own `mediaData.digit`, so a voice
    /// agent that only cares about DTMF does not have to filter `events()`
    /// itself, nor care which way a key was sent. The same rules as
    /// `events()`: every reader gets every digit from the moment it asks,
    /// and every stream finishes when the call ends, with no digit replayed
    /// to a reader that starts after that.
    public func dtmf() -> AsyncStream<Character> {
        dtmfBroadcast.stream()
    }

    /// A new reader of the real-time text the far end types (RFC 4103):
    /// each `SipralEventKind.textReceived`'s `textData`, in order, for a call
    /// placed or taken with `text: true` whose far end agreed a text stream.
    /// The same rules as `dtmf()`: every reader gets everything from the
    /// moment it asks, and every stream finishes when the call ends.
    public func text() -> AsyncStream<TextEventData> {
        textBroadcast.stream()
    }

    /// How many readers of `events()` are still being fed -- `internal` for
    /// the same reason as `debugMediaSocketDescriptor`.
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

    /// What the call's media cost in the end: the record
    /// `SipralEventKind.mediaStatistics` carries, kept here from the moment
    /// it arrives -- right after `SipralEventKind.callEnded`, on the poll
    /// thread -- and `nil` before that or for a call whose media never
    /// started. `Media.statistics()` answers with it too once the stream is
    /// gone, so a reader that asks after the end gets the last second of
    /// measurements rather than `.wrongState`.
    public var finalStatistics: sipral_stream_stats_t? {
        stateQueue.sync { _finalStatistics }
    }

    /// The socket the call was placed or answered on: until `media` exists it
    /// is the call's, and from then on `Media` owns it -- and whichever
    /// socket `moveMedia` puts in its place.
    private let mediaSocket: UDPSocket
    private var _mediaAddress: String
    /// The call's media socket, as `host:port`: the name
    /// `sipral_stack_nat_map` gave it, and so of its connection to a TURN
    /// server reached over TCP or TLS; after `moveMedia`, the new one.
    var mediaAddress: String { stateQueue.sync { _mediaAddress } }

    /// The `.incomingCall` this call was taken from, for `identity()` and
    /// `answering()`; `nil` for a call this end placed.
    private let incoming: CallEventData?

    /// The socket this call's real-time text travels on, when it was placed
    /// or taken with `text: true`: the call's until `media` exists, and the
    /// media's from then on.
    private let textSocket: UDPSocket?

    /// The call's real-time text socket, as `host:port`, when it has one.
    public let textAddress: String?

    /// The recording session copying this call to a recording server, while
    /// one does.
    private var _recordingSession: RecordingSession?
    public var recordingSession: RecordingSession? { stateQueue.sync { _recordingSession } }

    /// The raw descriptor `close()` releases on the no-media path -- `internal`
    /// rather than `private` only so `SipralTests` can watch it directly, the
    /// way a white-box concurrency test has to; nothing outside this module
    /// reads it, so the public surface this package exposes is unchanged.
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

    /// Writes to this call's media socket -- used by `SipralStack` for what
    /// `sipral_stack_poll_farewell` hands back once signalling has already
    /// ended, and for the packets the library's engine encodes in device
    /// mode. Through `media` once it exists, which owns the socket then.
    func sendOnMediaSocket(_ payload: [UInt8], to address: String) {
        if let media {
            media.sendDatagram(payload, to: address)
        } else {
            mediaSocket.send(payload, to: address)
        }
    }

    /// Called by `SipralStack` on its own poll thread.
    ///
    /// Every side effect below -- minting `media`, marking `ended` -- happens
    /// before `event` is ever handed to a reader: a task already awaiting
    /// `events()` that wakes and reads `call.media` must see it already set
    /// (`bindings/python/sipral/call.py`'s `deliver` orders its own steps
    /// for the same reason).
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

    /// `sipral_call_state`, read fresh -- not cached from the last event,
    /// which a status query between events would otherwise miss.
    public var state: SipralCallState? {
        get throws {
            let raw = try retryingBusy { try Sipral.callState(stack: stack.handle, call: handle) }
            return SipralCallState(rawValue: raw)
        }
    }

    // MARK: - actions

    /// `sipral_call_answer_media`: accept, with this stack running the audio
    /// through the media socket this call already opened.
    ///
    /// A call taken with `text: true` takes the real-time text the offer
    /// carries, on its own socket. `codecs` answers in that order of this
    /// build's codecs instead of the stack's -- `L16/16000` for linear
    /// audio -- and `focus` says this end is the focus of a conference
    /// (`isfocus`, RFC 4579) on the answer. An offer that asked for RTCP
    /// feedback is answered on RTP/AVPF whatever this says (RFC 4585 §4.1
    /// leaves an answerer no other way to take the stream); `feedback` adds
    /// what this end does with it, Generic NACKs and reduced-size RTCP. Any
    /// of these answers through `sipral_call_answer_with`.
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

    /// `sipral_call_hangup_for`: end the call as `hangup()` does, and say
    /// why with a `Reason` (RFC 3326) on the BYE, or on the CANCEL a call
    /// still ringing turns into. A call that came in and was never answered
    /// is refused with only the Q.850 value (RFC 6432): a SIP one would
    /// repeat the refusal's own status.
    public func hangup(reason: HangupReason) throws {
        try retryingBusy {
            try Sipral.callHangupFor(
                stack: stack.handle, call: handle, sipCause: reason.sipCause ?? 0,
                q850Cause: reason.q850Cause ?? 0, text: reason.text ?? "", nowMs: stack.nowMs()
            )
        }
    }

    /// `sipral_call_redirect`: answer a call that came in, and is still
    /// ringing, with a 3xx (RFC 3261 §21.3) naming where to try instead, in
    /// order of preference -- 302 is call forwarding. `reason` -- `no-answer`,
    /// `user-busy`, `unconditional`, `deflection`, `do-not-disturb` or any
    /// other token -- adds a `Diversion` (RFC 5806) naming the address that
    /// was called.
    public func redirect(to targets: [String], status: UInt32 = 302, reason: String? = nil) throws {
        try stack.redirect(call: handle, to: targets, status: status, reason: reason)
    }

    /// Who is calling, beyond the `From`: for a call that came in, what the
    /// network asserted behind the account's trust gate, the caller's
    /// `Privacy` and where the call was diverted from. Empty for a call this
    /// end placed.
    public func identity() throws -> CallerIdentity {
        try IdentityReader.identity(stack: stack, call: handle, data: incoming)
    }

    /// How a call that came in asked to be answered (RFC 5373) and rung
    /// (`Alert-Info`).
    public func answering() throws -> Answering {
        try IdentityReader.answering(stack: stack, call: handle, data: incoming)
    }

    /// Offer this call at a socket on the network the device is on now:
    /// what `SipralEventKind.callAddressWanted` asks for once
    /// `SipralStack.networkChanged(to:)` has said the old one is gone.
    ///
    /// A socket is bound at `host` -- the new network's address,
    /// `SipralStack.networkChanged(to:)`'s own by default -- asked where it
    /// appears from when the stack has a STUN server, and the call offered
    /// there with `sipral_call_media_readdress`: a re-INVITE with only `c=`
    /// and the port moved (RFC 3264 §8.3.1), carrying the account's new
    /// `Contact`. The new socket carries the call from then on, whatever the
    /// far end answers; the answer arrives as `.sessionChanged`, a refusal as
    /// `.sessionChangeFailed`. A call under ICE is refused with
    /// `.wrongState`: `restartIce()` moves it.
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

    /// `sipral_call_transfer`: ask the far end to call `target` instead, a
    /// blind transfer (RFC 3515). This end stays in the call until the far
    /// end reports the new call up; `.transferProgress` and then
    /// `.transferDone` arrive on `events()`, their `transferData` saying how
    /// it went.
    public func transfer(to target: String) throws {
        try retryingBusy {
            try Sipral.callTransfer(stack: stack.handle, call: handle, target: target, nowMs: stack.nowMs())
        }
    }

    /// `sipral_call_restart_ice`: offer the call again with new ICE
    /// credentials (RFC 8445 §9) and check every pair again once the far end
    /// answers, while the path it has carries the audio -- the remedy for a
    /// path whose consent was lost, and for a network change. The new path
    /// arrives as another `.mediaPathChosen`.
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

    /// `sipral_call_detect_progress`: listen for the network's tones, decide
    /// who answered and listen for the machine's beep, as `options` say.
    /// Call it straight after `SipralStack.placeCall`, before the far end
    /// answers; each thing heard is a `SipralEventKind.progressDetected`
    /// with `progressData` set.
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

    /// `sipral_call_consent_tone`: beep while this call is recorded, every
    /// value left at zero the library's default (1400 Hz, 18 dB below
    /// 0 dBm0, 200 ms every fifteen seconds); `local` has this end hear it
    /// too.
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

    /// `sipral_call_set_focus`: say (`true`) or stop saying that this end is
    /// the focus of a conference the call belongs to (RFC 4579 §4.2):
    /// `isfocus` on the `Contact` of every message the call sends from here
    /// on -- the answer, for a call not answered yet, and the next re-INVITE
    /// or UPDATE for one that is up.
    public func setFocus(_ focus: Bool) throws {
        try retryingBusy { try Sipral.callSetFocus(stack: stack.handle, call: handle, focus: focus ? 1 : 0) }
    }

    /// `sipral_call_conference_uri`: the conference this call belongs to,
    /// when its far end said it is a focus (`isfocus` on its `Contact`), and
    /// `nil` when it said nothing of the kind.
    public func conferenceUri() throws -> String? {
        do {
            return try ProtocolText.read { buffer in
                try retryingBusy { try Sipral.callConferenceUri(stack: stack.handle, call: handle, buffer: &buffer) }
            }
        } catch let error as SipralError where error.status == .notAFocus {
            return nil
        }
    }

    /// `sipral_call_subscribe_conference`: subscribe to the conference
    /// package of this call's focus (RFC 4579 §3.4), from the call's own
    /// account. The subscription outlives the call; each notification is a
    /// `SipralEventKind.conferenceChanged`, and `SipralSubscription.conference()`
    /// reads the picture. `.notAFocus` for a call whose far end is not one.
    public func subscribeConference() throws -> SipralSubscription {
        let made = try retryingBusy {
            try Sipral.callSubscribeConference(stack: stack.handle, call: handle, nowMs: stack.nowMs())
        }
        return SipralSubscription(stack: stack, handle: made, package: "conference")
    }

    // MARK: - a recording server

    /// `sipral_call_record_to`: record this call to the recording server
    /// `server` (SIPREC, RFC 7866). The recording session -- an INVITE with
    /// `Require: siprec`, the metadata (RFC 7865) and one send-only stream
    /// per party -- goes from the call's account: to `destination`
    /// (`host:port`) over a TCP connection this stack opens for it, or, with
    /// no `destination`, where the account sends -- which RFC 3261 does not
    /// let an INVITE this large reach over UDP, so the stack must then
    /// signal over TCP or TLS. Two sockets are bound at `host` for the
    /// copies of the audio. `.wrongState` before
    /// `SipralEventKind.mediaStarted`, and for a call already recorded.
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

    /// `sipral_call_stop_recording_to`: stop recording this call to its
    /// recording server; the recording session is hung up.
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

    /// Hang up if this call is still up, release its media, forget it.
    /// Idempotent, and safe to call regardless of how the call ended --
    /// including two callers racing to close the same call, such as a
    /// `CALL_ENDED` event handler and a user action landing at once, which
    /// is exactly the shape `stateQueue` guards `Media.close()` and
    /// `SipralStack.close()` against elsewhere in this layer. Without the
    /// guard, a second, concurrent call here that finds `media` still `nil`
    /// -- a call closed before its media ever started -- would close
    /// `mediaSocket`'s file descriptor a second time, which POSIX does not
    /// make safe: a fresh, unrelated socket opened by another thread in
    /// between can already hold that same descriptor number by then.
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

/// How `Call.detectProgress` listens: the network's tones, whether to decide
/// who answered and whether to listen for the machine's beep, and every
/// limit of `sipral_progress_config_t`, each zero for the library's default.
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
