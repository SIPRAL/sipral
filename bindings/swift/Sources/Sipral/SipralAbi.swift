// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// Printed from the declarations in crates/sipral-ffi by tools/abi-gen.
// Do not edit: `cargo run -p sipral-abi-gen` writes it again, and
// `scripts/check.sh` fails when what is committed is not what came out.

import CSipral

/// An opaque reference to something this library owns.
///
/// It is a number, not a pointer: nothing is to be read from it, and
/// nothing but this library can make one. Zero is never a live handle,
/// which is what a caller can zero a variable to.
///
/// An account or a call handle names something only on the stack that
/// minted it. Used with any other stack — one alive beside it, or one
/// created after it was destroyed — it is `SIPRAL_STATUS_INVALID_HANDLE`.
public typealias SipralHandle = sipral_handle_t

/// The result of a call across the C ABI.
///
/// The numbers are part of the ABI. A value keeps its meaning for the life of
/// the ABI's major version, and a new one is only ever added at the end.
public enum SipralStatus: Int32, Sendable {
    /// The call did what it was asked to.
    case ok = 0
    /// A pointer was null where one is required, a length disagreed with what
    /// it describes, or a value was outside what the call accepts.
    case invalidArgument = 1
    /// The handle never came from this library, or it came from a stack
    /// other than the one it was used with.
    case invalidHandle = 2
    /// The handle came from this library and what it named is gone: a use
    /// after free, or a second free.
    case staleHandle = 3
    /// A versioned struct declared a size this build cannot work with, or a
    /// binding asked for an ABI this library does not provide.
    case unsupportedVersion = 4
    /// The buffer supplied is too small. The length needed has been written to
    /// the out parameter, and nothing was written to the buffer.
    case bufferTooSmall = 5
    /// The object is already in use by another call, including one further
    /// down the same call stack. Nothing was done, and nothing blocked.
    case busy = 6
    /// The library has no room for another object of this kind.
    case exhausted = 7
    /// A panic was caught at the boundary. The call did not finish, and the
    /// last error carries whatever the panic said.
    case panic = 8
    /// What was asked for cannot be done where the object is: answering a call
    /// this end placed, holding one that is not up, sending DTMF before there
    /// is a dialog to send it in. Not an argument that was wrong; a moment
    /// that was.
    case wrongState = 9
    /// The request could not be assembled or handed to a transport. Nothing
    /// went out, and nothing about the call changed.
    case notSent = 10
    /// The value is one this ABI has a word for and this build has no code
    /// behind. Nothing was applied, and asking again will not change that.
    ///
    /// The third of the three answers a configuration call may give, and the
    /// one that has to be told apart from the other two by a machine.
    /// SipralStatus.invalidArgument says the value is wrong and a
    /// corrected one would be taken; this says the value is right and there is
    /// nothing here to take it. SipralStatus.unsupportedVersion is about
    /// the shape of what crossed the boundary, not about what was set in it.
    ///
    /// It exists so that "accepted and ignored" is not a thing this library
    /// can do. An application that gets it turns the control off, because the
    /// control is genuinely dead in this build; one that gets a silence
    /// instead ships a control that does nothing and finds out from a
    /// customer.
    case notSupported = 11
}

/// What a stack speaks. Names for `sipral_stack_config_t::transport`.
///
/// Zero is not one of them: a stack is told what it is speaking, because
/// guessing wrong in the direction of the plainest transport is how a caller
/// that meant TLS ends up on the wire in the clear.
public enum SipralTransport: UInt32, Sendable {
    /// UDP.
    case udp = 1
    /// TCP.
    case tcp = 2
    /// TLS over TCP.
    case tls = 3
    /// WebSocket.
    case ws = 4
    /// WebSocket over TLS.
    case wss = 5
}

/// Why a transport could not deliver. Names for
/// sipral_stack_transport_failed's `error`.
///
/// Coarse on purpose, and it is the layer below that is coarse: a client
/// transaction informs its user and terminates on every one of these (§17), and
/// the detail belongs in the caller's log, where the real message still is.
public enum SipralTransportError: UInt32, Sendable {
    /// Anything the caller could not classify. Zero, because a caller that
    /// knows only that the write failed is telling the truth by saying nothing.
    case other = 0
    /// Nothing is listening at the far end.
    case connectionRefused = 1
    /// An established connection was reset.
    case connectionReset = 2
    /// No route, or an ICMP unreachable.
    case unreachable = 3
    /// The connection attempt or the write timed out.
    case timedOut = 4
    /// The connection was closed and cannot be written to again.
    case closed = 5
}

/// The three answers a setting can give in a struct that starts out zeroed.
///
/// A boolean cannot carry them. Zero is what a caller who filled nothing in
/// leaves behind, so a plain `0`/`1` setting has no way to say "off" that is
/// not also "I said nothing", and the difference is the whole of B2: the
/// library must not turn a control off because the caller never touched it.
public enum SipralToggle: UInt32, Sendable {
    /// Nothing was said; whatever this build defaults to.
    case `default` = 0
    /// On.
    case on = 1
    /// Off.
    case off = 2
}

/// What a call or a stack says about SRTP. Names for
/// `sipral_stack_config_t::srtp` (the stack's default) and
/// `sipral_call_config_t::srtp` (a per-call override).
///
/// Zero is not one of them, and it is not the same absence on the two
/// structs: on the stack it means this build's own built-in default
/// (`SrtpPolicy::default()`, which is SipralSrtp.notOffered); on a
/// call it means the stack's own setting, whatever that came to. The three
/// values mean exactly what `sipral::SrtpPolicy`'s three variants mean —
/// see there for what each writes and what each answers.
public enum SipralSrtp: UInt32, Sendable {
    /// SrtpPolicy::NotOffered: do not offer it, but answer an offer
    /// that arrives on the secure profile with keys anyway.
    case notOffered = 1
    /// SrtpPolicy::Offered: offer it, and answer a plain offer
    /// plainly.
    case offered = 2
    /// SrtpPolicy::Required: offer it, and let no stream on this call
    /// carry audio unencrypted.
    case required = 3
}

/// One codec this ABI has a number for. Names for every member that says
/// which.
///
/// A value here is permanent, and that is all it is: a number that has left
/// this header is spent for good, so a binding compiled against one keeps
/// working whatever a later build contains. Whether *this* build can produce
/// the codec is a different question, and `SIPRAL_FEATURE_*` together with
/// `sipral_codec_at` are what answer it. A settings screen that offers this
/// list unfiltered is a settings screen with controls that do nothing, which
/// is the mistake `sipral_capabilities` exists to prevent.
public enum SipralCodec: UInt32, Sendable {
    /// No codec: the call has none, or the event is not about one.
    case unknown = 0
    /// G.711 mu-law, payload type 0.
    case pcmu = 1
    /// G.711 A-law, payload type 8.
    case pcma = 2
    /// G.722, wideband at the price of a narrowband stream.
    case g722 = 3
    /// Opus. Declared in every build, whether or not this one linked
    /// libopus, for the reason the enumeration above gives. Whether the
    /// codec is here is `SIPRAL_FEATURE_OPUS` and the list
    /// `sipral_codec_at` enumerates, never the presence of this name.
    case opus = 4
}

/// Which way audio may flow, as seen from here. Names for every `direction`.
public enum SipralDirection: UInt32, Sendable {
    /// Not negotiated.
    case unknown = 0
    /// Both ways.
    case sendRecv = 1
    /// This end sends and does not receive, which is what holding the far end
    /// looks like from here.
    case sendOnly = 2
    /// This end receives and does not send.
    case recvOnly = 3
    /// Neither way, and the stream stays in the session.
    case inactive = 4
}

/// Where control traffic goes. Names for sipral_media_info_t.rtcp.
public enum SipralRtcp: UInt32, Sendable {
    /// Not negotiated.
    case unknown = 0
    /// One port carries both (RFC 5761), which happens only where both ends
    /// asked for it.
    case muxed = 1
    /// A port of its own at each end.
    case separatePort = 2
    /// None at all: the peer said it is not using RTCP.
    case off = 3
}

/// Why media failed. Names for `sipral_media_event_t::fault`.
///
/// The sentence beside it says which case of the kind it was; this is the part
/// a machine acts on, and the two are never the same thing.
public enum SipralMediaFault: UInt32, Sendable {
    /// Nothing failed.
    case none = 0
    /// The negotiation settled on something this build cannot encode or
    /// decode, which means the peer answered with a format that was not in the
    /// offer.
    case unsupportedCodec = 1
    /// The two descriptions agree on nothing that can carry audio.
    case noCommonCodec = 2
    /// One end refused the stream with a port of zero. The call is up and
    /// carries no audio, which is a thing a peer is allowed to want.
    case streamRefused = 3
    /// There is no session description to work from.
    case noDescription = 4
    /// A description could not be read.
    case badDescription = 5
    /// The recording stopped writing: the disk filled, the file went away.
    case recording = 6
    /// The codec refused a frame.
    case codec = 7
    /// Something else the layer below reported and this ABI has no word for.
    case other = 8
}

/// What a datagram handed to sipral_media_receive turned out to be.
public enum SipralArrival: UInt32, Sendable {
    /// Something this ABI has no word for.
    case unknown = 0
    /// Audio, held for playout.
    case queued = 1
    /// Audio that was not used: malformed, late, duplicated, from the wrong
    /// address, or on a payload type nobody negotiated. The counters in
    /// sipral_stream_stats_t say which, over the call.
    case dropped = 2
    /// A reception or sender report, folded into the statistics.
    case control = 3
    /// The far end says it is leaving the session (RFC 3550 §6.6). Audio will
    /// stop; the call has not ended until signalling says so.
    case goodbye = 4
    /// Control traffic that was not believed: from the wrong address, or not a
    /// well-formed compound packet.
    case controlRefused = 5
}

/// Where the frame sipral_media_playback just produced came from.
public enum SipralPlayback: UInt32, Sendable {
    /// Something this ABI has no word for.
    case unknown = 0
    /// A packet the far end sent.
    case packet = 1
    /// One it sent and this end did not get, filled in by the concealment.
    case concealed = 2
    /// Comfort noise, from an RFC 3389 payload the far end sent instead of
    /// audio.
    case comfortNoise = 3
    /// Nothing was due: the buffer is still filling, or the far end has
    /// stopped.
    case silence = 4
}

/// Which way a digit goes to the far end. Names for
/// sipral_call_send_dtmf's `via`.
///
/// The choice is per send, not per call, because it is a fact about the peer
/// rather than about this end, and the way to find out which one a peer takes
/// is to try. A carrier that ignores one of these ignores it silently.
public enum SipralDtmf: UInt32, Sendable {
    /// In the media, as an RFC 4733 named telephone event. What to reach for:
    /// it is the only one carried end to end by every gateway on the path, and
    /// the only one whose timing survives transcoding.
    case rtp = 0
    /// An INFO per digit carrying `application/dtmf-relay`, which states the
    /// signal and how long it was held.
    case infoRelay = 1
    /// An INFO per digit carrying `application/dtmf`, whose whole body is the
    /// character. Some switches take only this one.
    case infoPlain = 2
}

/// What an event is about.
///
/// The numbers are part of the ABI and are only ever added to. A binding
/// that meets a kind it does not know must ignore that event rather than
/// refuse it, which is what makes adding one safe.
///
/// Numbers already spent on features this build does not have:
/// - 15: a subscription's state changed (A1)
/// - 16: the set of audio devices changed (A2)
/// - 18: a request was promoted to a stream transport (B1)
/// - 20: a call was announced and never arrived (C2)
public enum SipralEventKind: UInt32, Sendable {
    /// The stack is running on this thread.
    ///
    /// The first event on every stack, delivered by the first poll and never
    /// again. A binding that has a callback to hand out, a queue to open or a
    /// thread to name has somewhere definite to do it, before anything that
    /// matters can arrive.
    case started = 1
    /// A registration moved: it went out, it took, it is being refreshed, it
    /// was given up, or it failed. `payload.registration` says which, and
    /// `account` says whose.
    case registrationChanged = 2
    /// Somebody is calling. Answer, ring, or reject it.
    case incomingCall = 3
    /// A call this end placed is getting somewhere short of an answer.
    case callProgress = 4
    /// A proxy forked the INVITE and a second phone is ringing.
    /// `payload.call.other` is the branch that has just appeared.
    case callForked = 5
    /// The call is up.
    case callConfirmed = 6
    /// The session inside a live call changed: a hold, a resume, or an offer
    /// either end made and had accepted.
    case sessionChanged = 7
    /// The far end offered a change this stack has no policy for. The
    /// transaction is held open: answer it or refuse it, or the call ends.
    case sessionOffered = 8
    /// A change this end offered was refused. The session stands as it was.
    case sessionChangeFailed = 9
    /// The far end asked this one to call somebody else.
    case transferRequested = 10
    /// A transfer this end asked for is under way.
    case transferProgress = 11
    /// And how it ended.
    case transferDone = 12
    /// A call arrived carrying a `Replaces` and took over one already up.
    /// `payload.call.other` is the one being replaced.
    case callReplaced = 13
    /// The call is over, and its handle is stale from here on.
    case callEnded = 14
    /// What one call's media cost, delivered once, after
    /// `SIPRAL_EVENT_KIND_CALL_ENDED`.
    ///
    /// A6's second consumer. `payload.media.statistics` points at the
    /// completed record; it is the library's and lives as long as the callback
    /// does. The stream is gone by the time this arrives, which is why the
    /// numbers travel in the event rather than behind a lookup that would now
    /// fail.
    case mediaStatistics = 17
    /// Nothing has arrived on the media path for longer than the configured
    /// threshold, while signalling is perfectly happy.
    ///
    /// B5. `payload.media.silent_for_ms` says how long. The call is untouched:
    /// whether to hang up over silence is a decision with a person on the other
    /// end of it.
    case mediaStalled = 19
    /// Audio is running: the negotiation settled and an RTP session is open.
    ///
    /// A4's reporting half and the first half of D5: `payload.media.codec` is
    /// what the two ends agreed on. This is the moment to mint the call's
    /// media handle with `sipral_call_media`, and `sipral_media_info` on it
    /// says the rest.
    case mediaStarted = 21
    /// The session changed under a live call: a hold, a resume, a peer that
    /// moved its media address, or a re-negotiation onto another codec.
    case mediaChanged = 22
    /// Packets are arriving again. `payload.media.silent_for_ms` says how long
    /// the gap turned out to be.
    case mediaResumed = 23
    /// Media could not be started or could not be kept. The call itself is
    /// untouched; `payload.media.fault` and `payload.media.reason` say why.
    case mediaFailed = 24
    /// A recording stopped on its own, part-way through: the disk filled, the
    /// file went away, the volume was unmounted.
    ///
    /// Never an abort. `payload.media.recorded_ms` says how much audio reached
    /// the file before it stopped, and the call carries on without it.
    case recordingStopped = 25
    /// The far end pressed a key (RFC 4733).
    ///
    /// One per keypress, not one per packet: a digit goes out as a run of
    /// updates and then its closing packet three times, and the layer below
    /// collapses them on the timestamp that identifies the event.
    /// `payload.media.digit` is the character, `event_code` the number behind
    /// it for the events no keypad has a key for, and `held_ms` how long it
    /// lasted.
    case digitReceived = 26
}

/// Where a registration is. Names for `sipral_registration_event_t::state`.
public enum SipralRegistrationState: UInt32, Sendable {
    /// The account is gone, or has never been asked about.
    case unknown = 0
    /// Configured and not registered. Nothing has been sent.
    case idle = 1
    /// A REGISTER is in flight and there is no binding yet.
    case registering = 2
    /// The registrar holds a binding.
    case registered = 3
    /// A refresh is in flight. The binding stands until it is answered.
    case refreshing = 4
    /// Something recoverable went wrong and the next attempt is scheduled.
    case retrying = 5
    /// The binding was given up on purpose.
    case unregistered = 6
    /// The registrar refused in a way that trying again cannot fix.
    case failed = 7
    /// A binding a registrar really granted, over a transport that has since
    /// been suspended or lost, which nothing has proved since.
    ///
    /// Not registered, because it is no longer evidence; not failed, because
    /// nothing refused it. A monotonic clock does not advance while a machine
    /// sleeps, so a stack that slept eight hours comes back believing eight
    /// milliseconds passed and every binding still valid — this is the state
    /// that says otherwise, and an application that shows a line as ready on
    /// the strength of it will show it ready when it is not.
    case unverified = 8
    /// A binding read back from a snapshot rather than granted in this
    /// process. It has not been proved either.
    case restored = 9
    /// The account was configured with no registrar and never registers:
    /// a trunk that knows this end by its address. It starts here and
    /// stays here, and `sipral_account_register` refuses it. Not idle,
    /// which is one `sipral_account_register` away from a binding.
    case notRegistering = 10
}

/// Why a registration is not live. Names for
/// `sipral_registration_event_t::failure`.
public enum SipralRegistrationFailure: UInt32, Sendable {
    /// Nothing failed.
    case none = 0
    /// The registrar refused, and will refuse the same request again.
    case rejected = 1
    /// The password was wrong, or there was none to answer with.
    case badCredentials = 2
    /// The registrar is not answering, or says it cannot serve this now.
    case unreachable = 3
    /// The registrar moved. Following it needs an address, which is the
    /// caller's to resolve.
    case redirected = 4
}

/// Where a call is. Names for `sipral_call_event_t::state`, and what
/// `sipral_call_state` writes.
public enum SipralCallState: UInt32, Sendable {
    /// The call is gone, or has never been asked about.
    case unknown = 0
    /// The INVITE has gone and nothing has come back.
    case calling = 1
    /// Somebody is calling and this end has not answered.
    case incoming = 2
    /// The far end is ringing, or this end said it is.
    case ringing = 3
    /// There is audio before anybody answered.
    case earlyMedia = 4
    /// Up.
    case confirmed = 5
    /// Up, in order to be transferred: the second leg of an attended transfer.
    case consulting = 6
    /// A CANCEL or a BYE has gone and is not answered yet.
    case terminating = 7
    /// Over.
    case terminated = 8
}

/// Why a call is over. Names for `sipral_call_event_t::end_reason`.
public enum SipralCallEndReason: UInt32, Sendable {
    /// The call is not over.
    case none = 0
    /// This end hung up.
    case localHangup = 1
    /// The far end hung up.
    case remoteHangup = 2
    /// The far end refused it: busy, declined, not found.
    case refused = 3
    /// Given up before it was answered, from either end.
    case cancelled = 4
    /// Nothing came back, or the transport died.
    case unreachable = 5
    /// Another branch of the same fork was kept and this one was not.
    case forkLost = 6
    /// The branch was still ringing when the answer window closed.
    case abandoned = 7
    /// The session timer ran out and no refresh arrived.
    case expired = 8
}

/// What a call across the boundary answered, when it did not answer
/// `ok`. The message is the calling thread's last error, read before
/// anything else on this thread could replace it.
public struct SipralError: Error, CustomStringConvertible, Sendable {
    /// The code C would have switched on.
    public let status: SipralStatus
    /// The sentence that goes with it.
    public let message: String

    public var description: String {
        message.isEmpty ? "\(status)" : "\(status): \(message)"
    }
}

public extension sipral_abi_version_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_capabilities_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_counters_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_stack_config_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_poll_result_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_stack_settings_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_account_config_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_call_config_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_codec_info_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_media_info_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_stream_stats_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_media_packet_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_transmit_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_event_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

/// One header field an application hands over: a name and a value, UTF-8,
/// neither NUL-terminated.
///
/// Always an element of an array whose length travels beside it, which is
/// why it carries no `size`: an array is strided by the length of its
/// element, so a member appended here would move every element after the
/// first. A header field is a name and a value, and this never grows.
///
/// Built here and handed to C in a list. `withUnsafeArray` copies every
/// piece of text in every element into one buffer, points an array of
/// sipral_header_t into it and hands that array on for as long as one closure
/// runs, with the list's own count. An empty piece of text crosses as a
/// null pointer with a length of zero.
public struct SipralHeader: Sendable {
    /// The field name, `X-Conversation-Id`. A compact form is the field it
    /// abbreviates.
    public var name: String
    /// The value, as it goes on the line after the colon. Null or empty
    /// for a field with an empty value.
    public var value: String

    public init(name: String, value: String) {
        self.name = name
        self.value = value
    }

    /// A list of them as the array of sipral_header_t C reads, for as long as
    /// `body` runs and no longer: every pointer in it points into a buffer
    /// that is gone when `body` returns.
    static func withUnsafeArray<Answer>(_ list: [SipralHeader], _ body: (UnsafeBufferPointer<sipral_header_t>) throws -> Answer) rethrows -> Answer {
        var run: [CChar] = []
        var lengths: [Int] = []
        for element in list {
            let nameBytes = element.name.utf8.map { CChar(bitPattern: $0) }
            run.append(contentsOf: nameBytes)
            lengths.append(nameBytes.count)
            let valueBytes = element.value.utf8.map { CChar(bitPattern: $0) }
            run.append(contentsOf: valueBytes)
            lengths.append(valueBytes.count)
        }
        return try run.withUnsafeBufferPointer { bytes -> Answer in
            var array: [sipral_header_t] = []
            var at = 0
            var part = 0
            for _ in list {
                var record = sipral_header_t()
                record.name = lengths[part] == 0 ? nil : bytes.baseAddress.map { $0 + at }
                record.name_len = lengths[part]
                at += lengths[part]
                part += 1
                record.value = lengths[part] == 0 ? nil : bytes.baseAddress.map { $0 + at }
                record.value_len = lengths[part]
                at += lengths[part]
                part += 1
                array.append(record)
            }
            return try array.withUnsafeBufferPointer(body)
        }
    }
}

/// Everything the library does, with the C conventions read off it.
///
/// Swift gives a namespace `enum` like this one no load hook: there is
/// no module initializer and nothing else the runtime guarantees to run
/// before first use, the way a static constructor does for the .NET
/// binding. Nothing here calls `abiCheck` for you. The application
/// calls it itself, once, as the first thing it does with this module —
/// before creating a stack or calling anything else here:
///
/// ```swift
/// try Sipral.abiCheck(major: Sipral.abiVersionMajor, minor: Sipral.abiVersionMinor)
/// ```
///
/// Skipping it is not safe. The `size` every struct here carries
/// settles how long a struct is, not what is in it: a header and a
/// library that disagree about the order or the meaning of members can
/// still agree about the length, and then every size rule passes while
/// the library reads a pointer out of whatever was put in its place.
/// No entry point can catch that, because whether a pointer is
/// readable is the caller's promise, not something the library can
/// check. This call is the one that finds the disagreement before
/// anything is read.
public enum Sipral {
    /// The value no live handle ever takes.
    public static let handleNone: SipralHandle = 0

    /// The ABI's major version. Nothing published against one major works
    /// against another.
    public static let abiVersionMajor: UInt32 = 0

    /// The ABI's minor version, raised by anything the header gains —
    /// everything the generator prints, and not only a function or a struct
    /// member. `sipral_abi_check` compares the major and this one; the patch it
    /// does not ask about. The
    /// rule for all three numbers is the Versioning section of
    /// `docs/08-ffi.md`, which is where the ABI contract is written down.
    public static let abiVersionMinor: UInt32 = 9

    /// The ABI's patch version, raised by a fix that changes no declaration.
    public static let abiVersionPatch: UInt32 = 0

    /// Bits of sipral_capabilities_t.transports. A caller checks
    /// `capabilities.transports & SIPRAL_TRANSPORT_BIT_TLS != 0` rather than a
    /// growing list of booleans, so a transport this ABI has not learned a bit
    /// for yet reads as absent rather than refusing to compile against an
    /// older header.
    ///
    /// Named after SipralTransport's own numbers (`1 << (value - 1)`), so
    /// a transport added there in the future gets a bit here without the two
    /// numbering schemes ever being asked to agree by hand.
    public static let transportBitUdp: UInt32 = 1

    /// See SIPRAL_TRANSPORT_BIT_UDP.
    public static let transportBitTcp: UInt32 = 2

    /// See SIPRAL_TRANSPORT_BIT_UDP.
    public static let transportBitTls: UInt32 = 4

    /// See SIPRAL_TRANSPORT_BIT_UDP.
    public static let transportBitWs: UInt32 = 8

    /// See SIPRAL_TRANSPORT_BIT_UDP.
    public static let transportBitWss: UInt32 = 16

    /// Bits of sipral_capabilities_t.features.
    public static let featureDtmf: UInt32 = 1

    /// See SIPRAL_FEATURE_DTMF.
    public static let featureRtcpMux: UInt32 = 2

    /// See SIPRAL_FEATURE_DTMF.
    public static let featureRecording: UInt32 = 4

    /// See SIPRAL_FEATURE_DTMF.
    public static let featureMediaStallWatchdog: UInt32 = 8

    /// See SIPRAL_FEATURE_DTMF.
    public static let featureSrtp: UInt32 = 16

    /// See SIPRAL_FEATURE_DTMF, and the module documentation for why this
    /// build never sets it.
    public static let featureSubscriptions: UInt32 = 32

    /// See SIPRAL_FEATURE_DTMF. Opus is behind a compile-time feature,
    /// because libopus is the one part of the audio path that is licensed
    /// rather than written, so a build meant for hardware can leave it out.
    /// The bit is how an application finds out without having to enumerate
    /// the codecs, and it is set from the catalogue this build offers rather
    /// than from any crate's feature flag; `SIPRAL_CODEC_OPUS` keeps its
    /// number either way, since a value that has left this header is spent
    /// for good.
    public static let featureOpus: UInt32 = 64

    /// The buffer a caller has to bring for one outgoing packet.
    ///
    /// Not a path MTU — RTP does not discover one — but the bound the session
    /// itself builds against, so a payload larger than this is a payload no
    /// codec in this build produces. It is checked before anything is encoded,
    /// because a frame that was encoded and then had nowhere to go is a frame
    /// lost from a stream whose timestamps have already moved past it.
    public static let mediaPacketBytes: Int = 1500

    /// Room enough for any address this ABI writes, the NUL included:
    /// `[2001:db8:0000:0000:0000:0000:0000:0001]:65535` and a byte to spare.
    public static let addressBytes: Int = 64

    /// The transport a stack is created with, and the only one this build
    /// binds.
    ///
    /// Named rather than assumed, so that the day a stack has two of them is a
    /// day more numbers become valid and not a day this ABI grows a second way
    /// to hand bytes over.
    public static let transportMain: UInt32 = 0

    /// The largest message that crosses in either direction.
    ///
    /// The bound the layer below parses to, which is what stops a hostile peer
    /// from making the parser do unbounded work. A caller's read buffer wants
    /// to be this big on a stream, where one read can hold the end of one
    /// message and the start of another, and 1500 bytes or so on a datagram
    /// socket, where anything larger was fragmented on the way.
    public static let messageBytes: Int = 65535

    /// The calling thread's last error, or an empty string when it
    /// has none. Read the way C reads it: ask for the length, then
    /// for the bytes.
    public static func lastErrorMessage() -> String {
        var needed = 0
        _ = sipral_last_error_message(nil, 0, &needed)
        guard needed > 1 else { return "" }
        var buffer = [CChar](repeating: 0, count: needed)
        let status = buffer.withUnsafeMutableBufferPointer {
            sipral_last_error_message($0.baseAddress, $0.count, nil)
        }
        guard status == SIPRAL_STATUS_OK else { return "" }
        return String(cString: buffer)
    }

    /// Turn a status into a thrown error, and nothing into nothing.
    static func check(_ status: sipral_status_t) throws {
        guard status != SIPRAL_STATUS_OK else { return }
        throw SipralError(
            status: SipralStatus(rawValue: status) ?? .panic,
            message: lastErrorMessage()
        )
    }

    /// The short name of a status code, as a static NUL-terminated string, or
    /// null for a number that is not a status code.
    ///
    /// The string belongs to the library and lives as long as it is loaded.
    /// It is meant for a log line; the last error is the sentence for a human.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns, and is safe to call from any thread.
    public static func statusName(status: Int32) -> String? {
        guard let text = sipral_status_name(status) else { return nil }
        return String(cString: text)
    }

    /// Report the ABI version this library provides.
    ///
    /// Safety
    ///
    /// `out_version` must point at a `sipral_abi_version_t` whose `size`
    /// member says how long it is.
    public static func abiVersion() throws -> sipral_abi_version_t {
        var version = sipral_abi_version_t.sized()
        let status = sipral_abi_version(&version)
        try check(status)
        return version
    }

    /// Whether this library can serve a binding generated against
    /// `major`.`minor`. Called once, at load, before anything else: by the
    /// binding itself where its language gives it somewhere to call from, and
    /// by the application where it does not. The Versioning section of
    /// `docs/08-ffi.md` says which binding is which.
    ///
    /// `SIPRAL_STATUS_UNSUPPORTED_VERSION` when it cannot, with a last error
    /// naming both versions, which is what the binding should put in the
    /// exception it throws. The patch number is not asked for: it never
    /// changes a declaration, so it cannot make two builds disagree.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns, and is safe to call from any thread.
    public static func abiCheck(major: UInt32, minor: UInt32) throws {
        let status = sipral_abi_check(major, minor)
        try check(status)
    }

    /// How many bytes this build compiled one of the ABI's structs to.
    ///
    /// `name` is what the header calls the type — `sipral_stack_config_t` —
    /// as bytes and a length, the way every string crosses here. A name this
    /// build has no struct for is `SIPRAL_STATUS_INVALID_ARGUMENT`, which is
    /// the answer a caller holding somebody else's header gets.
    ///
    /// Nothing in the library needs asking: the `size` member a struct
    /// carries settles a disagreement in the ordinary course of a call. This
    /// is for finding out there is one before making it. A package built
    /// against one header and loaded over a native library from another
    /// shows up here as a `sizeof` that differs, in one call at load, rather
    /// than in whichever member happened to move.
    ///
    /// Safety
    ///
    /// `name` must be readable for `name_len` bytes, and `out_size` must
    /// point at one `size_t`.
    public static func abiStructSize(name: String) throws -> Int {
        var size = Int()
        let status =
            Array(name.utf8).withUnsafeBufferPointer { raw0 in
                raw0.withMemoryRebound(to: CChar.self) { p0 in
                    sipral_abi_struct_size(p0.baseAddress, p0.count, &size)
                }
            }
        try check(status)
        return size
    }

    /// How many of the ABI's structs carry a `size` member.
    ///
    /// The companion to `sipral_abi_struct_size`, and the part of the check a
    /// caller cannot write for itself. A caller that compares lengths holds
    /// a list of the structs it knows about, and the list is what goes
    /// stale: a struct this ABI gained is one nobody thought to ask about,
    /// and a length check that covers all but the newest still passes. Ask
    /// for this number, compare it with the length of that list, and the day
    /// the ABI grows another the caller is told.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    public static func abiVersionedCount() throws -> Int {
        var count = Int()
        let status = sipral_abi_versioned_count(&count)
        try check(status)
        return count
    }

    /// What this build of the library can do, in one call.
    ///
    /// Names no stack, and answers the same way before any stack is created
    /// as after: a build's capabilities do not change while it runs. Safe to
    /// call from any thread, at any time, including from inside the event
    /// callback.
    ///
    /// Safety
    ///
    /// `out_capabilities` must point at a `sipral_capabilities_t` whose
    /// `size` member says how long it is.
    public static func capabilities() throws -> sipral_capabilities_t {
        var capabilities = sipral_capabilities_t.sized()
        let status = sipral_capabilities(&capabilities)
        try check(status)
        return capabilities
    }

    /// Create a stack, and write its handle to `out_stack`.
    ///
    /// The handle is written only if this returns `SIPRAL_STATUS_OK`. A stack
    /// that is created must be destroyed with sipral_stack_destroy.
    ///
    /// A process holds 256 stacks at once. The next is
    /// `SIPRAL_STATUS_EXHAUSTED` until one of them is destroyed and no poll is
    /// still running on it.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_stack_config_t` whose `size` member
    /// says how long it is, with every pointer in it readable for the length
    /// beside it, and `out_stack` at one `sipral_handle_t`.
    public static func stackCreate(config: sipral_stack_config_t) throws -> SipralHandle {
        var config = config
        var stack = SipralHandle()
        let status = sipral_stack_create(&config, &stack)
        try check(status)
        return stack
    }

    /// Read back what a stack is running with.
    ///
    /// Every value here was either given at creation or defaulted there, and
    /// none of it changes afterwards. It is the other half of a configuration
    /// call that answered `SIPRAL_STATUS_OK`: the call says the value was
    /// taken, this says what it came to.
    ///
    /// Safety
    ///
    /// `out_settings` must point at a `sipral_stack_settings_t` whose `size`
    /// member says how long it is.
    public static func stackSettings(stack: SipralHandle) throws -> sipral_stack_settings_t {
        var settings = sipral_stack_settings_t.sized()
        let status = sipral_stack_settings(stack, &settings)
        try check(status)
        return settings
    }

    /// Destroy a stack.
    ///
    /// The handle is dead the moment this returns, and a second destroy is
    /// `SIPRAL_STATUS_STALE_HANDLE` rather than a corrupted heap. Called from
    /// inside the callback it is still safe: what the poll is holding stays
    /// alive until that poll returns. Called from inside a frame of one of its
    /// calls — a processor — it is `SIPRAL_STATUS_BUSY` and nothing is freed,
    /// because freeing the stack ends that call's media and the frame is
    /// holding it. No account is de-registered and no call is hung up; a stack
    /// that has to leave politely does that first.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    public static func stackDestroy(stack: SipralHandle) throws {
        let status = sipral_stack_destroy(stack)
        try check(status)
    }

    /// Let the stack do its work, and deliver what it has to say.
    ///
    /// `now_ms` is the caller's monotonic clock in milliseconds. It must not
    /// fall more than fifty milliseconds behind the last one this stack saw —
    /// signalling may be called from any thread, and two of them reading the
    /// same clock a moment apart is not a caller mistake — and a jump further
    /// back than that is `SIPRAL_STATUS_INVALID_ARGUMENT` with nothing
    /// delivered.
    ///
    /// The event callback is called from inside this function, on this
    /// thread, and with nothing held: the stack's work is done and its lock
    /// let go before the first event is handed over, so the callback may call
    /// back into the library, this stack included. A poll that finds another
    /// poll of the same stack already delivering — which is what a poll from
    /// inside the callback always finds — does the stack's work and leaves its
    /// events to that one, so they arrive in the order they were raised and
    /// never on two threads at once.
    ///
    /// `result` may be null for a caller that does not want the counts.
    ///
    /// A poll is also where the stack writes: a retransmission falls due, a
    /// registration is refreshed, a transaction gives up and says so. What it
    /// wrote is taken with `sipral_stack_poll_transmit`, which is drained after
    /// every poll and left alone by the next one — see crate::transport for
    /// the loop in full.
    ///
    /// Safety
    ///
    /// `result` must be null or point at a `sipral_poll_result_t` whose `size`
    /// member says how long it is.
    public static func stackPoll(stack: SipralHandle, nowMs: UInt64) throws -> sipral_poll_result_t {
        var result = sipral_poll_result_t.sized()
        let status = sipral_stack_poll(stack, nowMs, &result)
        try check(status)
        return result
    }

    /// D3's health counters for one stack, since it was created.
    ///
    /// Cheap enough to sample on a timer and ship as telemetry: reading this
    /// is one struct copy on top of the call itself, the same as
    /// `sipral_media_statistics` and for the same reason — nothing here walks
    /// the call table or a session to answer.
    ///
    /// Safety
    ///
    /// `out_counters` must point at a `sipral_counters_t` whose `size` member
    /// says how long it is.
    public static func stackCounters(stack: SipralHandle) throws -> sipral_counters_t {
        var counters = sipral_counters_t.sized()
        let status = sipral_stack_counters(stack, &counters)
        try check(status)
        return counters
    }

    /// Configure an account, and write its handle to `out_account`.
    ///
    /// Nothing is sent. The account exists until sipral_account_remove or
    /// until the stack is destroyed.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_account_config_t` whose `size` member
    /// says how long it is, with every pointer in it readable for the length
    /// beside it, and `out_account` at one `sipral_handle_t`.
    public static func accountAdd(stack: SipralHandle, config: sipral_account_config_t, configHeaders: [SipralHeader]) throws -> SipralHandle {
        var config = config
        var account = SipralHandle()
        let status =
            SipralHeader.withUnsafeArray(configHeaders) { p1Headers -> sipral_status_t in
                config.headers = p1Headers.baseAddress
                config.headers_len = p1Headers.count
                return sipral_account_add(stack, &config, &account)
            }
        try check(status)
        return account
    }

    /// Forget an account, and everything scheduled for it.
    ///
    /// Nothing is sent: an account being removed may be one whose registrar is
    /// unreachable, and waiting on that is not this call's job. Give the
    /// binding up politely with sipral_account_unregister first when it
    /// matters.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func accountRemove(stack: SipralHandle, account: SipralHandle) throws {
        let status = sipral_account_remove(stack, account)
        try check(status)
    }

    /// Register, and keep the binding alive until told otherwise.
    ///
    /// Refreshes, credential retries and the back-off after an outage all
    /// happen without another call. What stops them is
    /// sipral_account_unregister, or a refusal that trying again cannot
    /// fix. Every step of it arrives as a `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED`.
    ///
    /// An account configured with no registrar never registers, and this
    /// answers `SIPRAL_STATUS_INVALID_ARGUMENT` for it with nothing sent.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func accountRegister(stack: SipralHandle, account: SipralHandle, nowMs: UInt64) throws {
        let status = sipral_account_register(stack, account, nowMs)
        try check(status)
    }

    /// Give the binding up: a REGISTER with `Expires: 0` (§10.2.2).
    ///
    /// Only this device's binding. A `Contact: *` would remove every binding
    /// the address of record has, including the one belonging to the desk
    /// phone somebody else is holding.
    ///
    /// An account configured with no registrar has no binding to give up, and
    /// is refused the way `sipral_account_register` refuses it.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func accountUnregister(stack: SipralHandle, account: SipralHandle, nowMs: UInt64) throws {
        let status = sipral_account_unregister(stack, account, nowMs)
        try check(status)
    }

    /// Where an account's registration is, as a `SipralRegistrationState`.
    ///
    /// An account configured with no registrar answers
    /// `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING`, always.
    ///
    /// Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    public static func accountRegistrationState(stack: SipralHandle, account: SipralHandle) throws -> UInt32 {
        var state = UInt32()
        let status = sipral_account_registration_state(stack, account, &state)
        try check(status)
        return state
    }

    /// Place a call, and write its handle to `out_call`.
    ///
    /// The handle exists from here on, before any dialog does, because there
    /// has to be something to hang up with while the INVITE is still in
    /// flight. A proxy that forks the INVITE gives the branches handles of
    /// their own, reported as `SIPRAL_EVENT_KIND_CALL_FORKED`.
    ///
    /// With `media_address` set, the offer is this stack's to write and the
    /// call gets audio of its own: `SIPRAL_EVENT_KIND_MEDIA_STARTED` says when,
    /// and `crate::media` carries the packets from then on. `config.srtp`
    /// overrides `sipral_stack_config_t::srtp` for such a call; it is read for
    /// no other kind.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_call_config_t` whose `size` member
    /// says how long it is, with every pointer in it readable for the length
    /// beside it, and `out_call` at one `sipral_handle_t`.
    public static func callPlace(stack: SipralHandle, account: SipralHandle, config: sipral_call_config_t, configHeaders: [SipralHeader], nowMs: UInt64) throws -> SipralHandle {
        var config = config
        var call = SipralHandle()
        let status =
            SipralHeader.withUnsafeArray(configHeaders) { p2Headers -> sipral_status_t in
                config.headers = p2Headers.baseAddress
                config.headers_len = p2Headers.count
                return sipral_call_place(stack, account, &config, &call, nowMs)
            }
        try check(status)
        return call
    }

    /// Say a call that came in is ringing.
    ///
    /// A description makes it a 183 Session Progress rather than a 180
    /// Ringing, because 180 with a body is a contradiction the far end has to
    /// guess at. Pass none for the ordinary case.
    ///
    /// Safety
    ///
    /// `sdp` must be null or readable for `sdp_len` bytes.
    public static func callRing(stack: SipralHandle, call: SipralHandle, sdp: [UInt8], nowMs: UInt64) throws {
        let status =
            sdp.withUnsafeBufferPointer { p2 in
                sipral_call_ring(stack, call, p2.baseAddress, p2.count, nowMs)
            }
        try check(status)
    }

    /// Answer a call that came in.
    ///
    /// `sdp` is the answer to the offer the INVITE carried, and is required:
    /// answering with nothing puts the offer on this end and the answer in the
    /// far end's ACK, which this ABI has no way to hand back.
    ///
    /// Safety
    ///
    /// `sdp` must be readable for `sdp_len` bytes.
    public static func callAnswer(stack: SipralHandle, call: SipralHandle, sdp: [UInt8], nowMs: UInt64) throws {
        let status =
            sdp.withUnsafeBufferPointer { p2 in
                sipral_call_answer(stack, call, p2.baseAddress, p2.count, nowMs)
            }
        try check(status)
    }

    /// Answer a call that came in, and let this stack run its audio.
    ///
    /// The answer to the offer the INVITE carried is written from this stack's
    /// codec order, against `media_address` — where this end will receive
    /// media, which only the application can say because it owns the socket.
    /// `SIPRAL_EVENT_KIND_MEDIA_STARTED` follows once the stream is open.
    ///
    /// The other half of `sipral_call_place` with `media_address` set, and the
    /// alternative to `sipral_call_answer`, which answers with a description
    /// the application wrote and leaves the audio to it.
    ///
    /// Safety
    ///
    /// `media_address` must be readable for `media_address_len` bytes.
    public static func callAnswerMedia(stack: SipralHandle, call: SipralHandle, mediaAddress: String, nowMs: UInt64) throws {
        let status =
            Array(mediaAddress.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    sipral_call_answer_media(stack, call, p2.baseAddress, p2.count, nowMs)
                }
            }
        try check(status)
    }

    /// Refuse a call that came in, with a response code of your choosing.
    ///
    /// 486 Busy Here for a line that is in use, 603 Decline for a person who
    /// does not want to talk. The difference is what a proxy does next.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callReject(stack: SipralHandle, call: SipralHandle, code: UInt32, nowMs: UInt64) throws {
        let status = sipral_call_reject(stack, call, code, nowMs)
        try check(status)
    }

    /// Hang up, whatever the call is doing.
    ///
    /// A CANCEL before it is answered, a BYE after, a refusal for one that
    /// came in and has not been answered. A call that is already ending is
    /// left alone rather than refused.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callHangup(stack: SipralHandle, call: SipralHandle, nowMs: UInt64) throws {
        let status = sipral_call_hangup(stack, call, nowMs)
        try check(status)
    }

    /// Set the header fields that go on what this call sends at the
    /// application's request, from now until they are set again.
    ///
    /// They go on the 180 or 183 from `sipral_call_ring`, the 200 from
    /// `sipral_call_answer` and `sipral_call_answer_media`, the refusal from
    /// `sipral_call_reject`, the refusal or the BYE that `sipral_call_hangup`
    /// turns into, and the re-INVITE or UPDATE that `sipral_call_hold` and
    /// `sipral_call_resume` send. Kept rather than spent on the first of those,
    /// so that a field set before ringing is on the 200 as well. Never on a
    /// CANCEL, which a proxy answers and replaces with its own, and never on
    /// what the stack sends by itself: a session refresh, or the BYE for a 2xx
    /// that was never acknowledged or for a fork that lost.
    ///
    /// Replaces what was set before, whole, and a `headers_len` of zero takes
    /// every field off. Each field is checked first, as it is on
    /// `sipral_call_config_t::headers`, and a refusal names the element, keeps
    /// none of the new fields and leaves the old ones in place. Nothing is
    /// sent.
    ///
    /// Safety
    ///
    /// `headers` must be null with `headers_len` zero, or readable for
    /// `headers_len` elements, each with a name and a value readable for the
    /// lengths beside them.
    public static func callSetHeaders(stack: SipralHandle, call: SipralHandle, headers: [SipralHeader]) throws {
        let status =
            SipralHeader.withUnsafeArray(headers) { p2 in
                sipral_call_set_headers(stack, call, p2.baseAddress, p2.count)
            }
        try check(status)
    }

    /// Put a call on hold (RFC 3264 §8.4).
    ///
    /// The description is the stack's to write: the one already negotiated
    /// with every stream's direction changed. Asking for a hold that is
    /// already in place sends nothing and succeeds.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callHold(stack: SipralHandle, call: SipralHandle, nowMs: UInt64) throws {
        let status = sipral_call_hold(stack, call, nowMs)
        try check(status)
    }

    /// Take it off hold again.
    ///
    /// Every stream goes back to the direction it had before, which is not
    /// always both ways: one that was offered receive-only is resumed
    /// receive-only.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callResume(stack: SipralHandle, call: SipralHandle, nowMs: UInt64) throws {
        let status = sipral_call_resume(stack, call, nowMs)
        try check(status)
    }

    /// Accept a change the far end offered, reported as
    /// `SIPRAL_EVENT_KIND_SESSION_OFFERED`.
    ///
    /// `sdp` is the answer to the offer it carried, and is left out only for a
    /// request that carried none. A re-INVITE nobody answers is retransmitted
    /// and then ends the call, so this or sipral_call_reject_session has
    /// to follow that event.
    ///
    /// Only for a call the application describes. One this stack describes
    /// answers its own re-offers, from the same codec order, before the poll
    /// that saw the request returns — so the event never arrives and this is
    /// `SIPRAL_STATUS_WRONG_STATE`.
    ///
    /// Safety
    ///
    /// `sdp` must be null or readable for `sdp_len` bytes.
    public static func callAcceptSession(stack: SipralHandle, call: SipralHandle, sdp: [UInt8], nowMs: UInt64) throws {
        let status =
            sdp.withUnsafeBufferPointer { p2 in
                sipral_call_accept_session(stack, call, p2.baseAddress, p2.count, nowMs)
            }
        try check(status)
    }

    /// Refuse one instead. The session stands exactly as it was (§14.1).
    ///
    /// 488 Not Acceptable Here is the code that says the description was the
    /// problem rather than the request.
    ///
    /// As with sipral_call_accept_session, only for a call the application
    /// describes.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callRejectSession(stack: SipralHandle, call: SipralHandle, code: UInt32, nowMs: UInt64) throws {
        let status = sipral_call_reject_session(stack, call, code, nowMs)
        try check(status)
    }

    /// Send DTMF on a call that is up, in whichever of the three forms the far
    /// end takes.
    ///
    /// `digits` are `0` to `9`, `*`, `#` and `A` to `D`, the sixteen events of
    /// RFC 4733 §3.2, in the order they were pressed. `duration_ms` is how long
    /// each one lasts, or zero for the default.
    ///
    /// `via` is a SipralDtmf, and it is chosen per send rather than per
    /// call: which form a peer accepts is a fact about the peer, and an
    /// application that has just learned the answer for this one must not have
    /// to tear the call down to act on it. `SIPRAL_DTMF_RTP` puts the digits in
    /// the media, where they replace the audio for as long as they last and
    /// queue behind each other; the two INFO forms put one request per digit in
    /// the dialog.
    ///
    /// `SIPRAL_STATUS_NOT_SUPPORTED` from `SIPRAL_DTMF_RTP` on a call whose
    /// negotiation settled on no telephone event payload type: the key is a
    /// real key and this call has nowhere in the media to put it. The INFO
    /// forms need a dialog rather than a negotiation, and answer
    /// `SIPRAL_STATUS_WRONG_STATE` before there is one.
    ///
    /// Safety
    ///
    /// `digits` must be readable for `digits_len` bytes.
    public static func callSendDtmf(stack: SipralHandle, call: SipralHandle, digits: String, via: UInt32, durationMs: UInt32, nowMs: UInt64) throws {
        let status =
            Array(digits.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    sipral_call_send_dtmf(stack, call, p2.baseAddress, p2.count, via, durationMs, nowMs)
                }
            }
        try check(status)
    }

    /// Ask the far end to call somebody else, and hang up when it has
    /// (RFC 3515).
    ///
    /// A blind transfer: nobody consults the destination first. This end stays
    /// in the call until the transfer has succeeded, because hanging up first
    /// turns a transfer that failed into a call that vanished. Progress
    /// arrives as `SIPRAL_EVENT_KIND_TRANSFER_PROGRESS` and then
    /// `SIPRAL_EVENT_KIND_TRANSFER_DONE`.
    ///
    /// Safety
    ///
    /// `target` must be readable for `target_len` bytes.
    public static func callTransfer(stack: SipralHandle, call: SipralHandle, target: String, nowMs: UInt64) throws {
        let status =
            Array(target.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    sipral_call_transfer(stack, call, p2.baseAddress, p2.count, nowMs)
                }
            }
        try check(status)
    }

    /// Call the transfer target, so that there is somebody to hand the call
    /// to, and write the new call's handle to `out_consultation`.
    ///
    /// The consultation leg of an attended transfer. It is answered like any
    /// other call, and sipral_call_transfer_to is what follows. Putting
    /// `call` on hold first is the application's: it is a session change, and
    /// this stack does not make those uninvited.
    ///
    /// `media_address` is `SIPRAL_STATUS_NOT_SUPPORTED` here. The media engine
    /// places and answers calls; it does not consult, and a consultation leg
    /// registered with it by hand would be one it has described nothing for.
    /// A consultation with audio is placed with `sdp` and run by the
    /// application, as every call was before this stack carried media.
    ///
    /// Safety
    ///
    /// As sipral_call_place.
    public static func callConsult(stack: SipralHandle, call: SipralHandle, config: sipral_call_config_t, configHeaders: [SipralHeader], nowMs: UInt64) throws -> SipralHandle {
        var config = config
        var consultation = SipralHandle()
        let status =
            SipralHeader.withUnsafeArray(configHeaders) { p2Headers -> sipral_status_t in
                config.headers = p2Headers.baseAddress
                config.headers_len = p2Headers.count
                return sipral_call_consult(stack, call, &config, &consultation, nowMs)
            }
        try check(status)
        return consultation
    }

    /// Hand `call` to the far end of `other` (RFC 3891).
    ///
    /// The attended half of a transfer: `other` is normally the consultation
    /// call, and the party at its far end replaces the call it already has
    /// rather than answering a second one. Any call that is up may be named.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callTransferTo(stack: SipralHandle, call: SipralHandle, other: SipralHandle, nowMs: UInt64) throws {
        let status = sipral_call_transfer_to(stack, call, other, nowMs)
        try check(status)
    }

    /// Take a transfer that was asked for, place the call it names, and write
    /// that call's handle to `out_placed`.
    ///
    /// Safety
    ///
    /// `out_placed` must point at one `sipral_handle_t`.
    public static func callAcceptTransfer(stack: SipralHandle, call: SipralHandle, nowMs: UInt64) throws -> SipralHandle {
        var placed = SipralHandle()
        let status = sipral_call_accept_transfer(stack, call, &placed, nowMs)
        try check(status)
        return placed
    }

    /// Refuse one instead.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callRejectTransfer(stack: SipralHandle, call: SipralHandle, code: UInt32, nowMs: UInt64) throws {
        let status = sipral_call_reject_transfer(stack, call, code, nowMs)
        try check(status)
    }

    /// Where a call is, as a `SipralCallState`.
    ///
    /// A call that is over answers `SIPRAL_CALL_STATE_TERMINATED` until the
    /// poll that delivers `SIPRAL_EVENT_KIND_CALL_ENDED` retires its handle, and
    /// `SIPRAL_STATUS_STALE_HANDLE` after that.
    ///
    /// Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    public static func callState(stack: SipralHandle, call: SipralHandle) throws -> UInt32 {
        var state = UInt32()
        let status = sipral_call_state(stack, call, &state)
        try check(status)
        return state
    }

    /// Which way a call is held: `out_here` is set when this end asked the far
    /// end to stop sending, `out_there` when the far end asked this one.
    /// Either may be null.
    ///
    /// Safety
    ///
    /// `out_here` and `out_there` must each be null or point at one
    /// `uint32_t`.
    public static func callHoldState(stack: SipralHandle, call: SipralHandle) throws -> (here: UInt32, there: UInt32) {
        var here = UInt32()
        var there = UInt32()
        let status = sipral_call_hold_state(stack, call, &here, &there)
        try check(status)
        return (here: here, there: there)
    }

    /// The name of a codec, as a static NUL-terminated string, or null for a
    /// number this build has no codec for.
    ///
    /// It is spelled as IANA registered it, which is also how it goes on an
    /// `a=rtpmap` line. The string belongs to the library and lives as long as
    /// it is loaded.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns, and is safe to call from any thread.
    public static func codecName(codec: UInt32) -> String? {
        guard let text = sipral_codec_name(codec) else { return nil }
        return String(cString: text)
    }

    /// How many codecs this build contains.
    ///
    /// A compile-time fact, and the reason A4 starts here rather than at a
    /// configuration: no setting can add a codec that was not linked.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    public static func codecCount() throws -> Int {
        var count = Int()
        let status = sipral_codec_count(&count)
        try check(status)
        return count
    }

    /// One of them, by index, from zero to what `sipral_codec_count` said.
    ///
    /// The order is this build's own preference, quality first, which is what
    /// is offered when nobody has said otherwise.
    ///
    /// Safety
    ///
    /// `out_info` must point at a `sipral_codec_info_t` whose `size` member
    /// says how long it is.
    public static func codecAt(index: Int) throws -> sipral_codec_info_t {
        var info = sipral_codec_info_t.sized()
        let status = sipral_codec_at(index, &info)
        try check(status)
        return info
    }

    /// The codecs this stack offers, in the order it offers them.
    ///
    /// The other half of the configuration: `codecs` in
    /// `sipral_stack_config_t` says what to offer, and this says what that came
    /// to. `out_count` always receives the number there are, so a caller that
    /// passes a capacity of zero and a null buffer learns how much room to
    /// bring and gets `SIPRAL_STATUS_BUFFER_TOO_SMALL`.
    ///
    /// Safety
    ///
    /// `out_codecs` must be writable for `capacity` `uint32_t` or null with a
    /// capacity of zero, and `out_count` must point at one `size_t` or be null.
    public static func stackCodecOrder(stack: SipralHandle, outCodecs: inout [UInt32]) throws -> Int {
        var count = Int()
        let status =
            outCodecs.withUnsafeMutableBufferPointer { p1 in
                sipral_stack_codec_order(stack, p1.baseAddress, p1.count, &count)
            }
        try check(status)
        return count
    }

    /// A handle on one call's media, written to `out_media`.
    ///
    /// Mint it once the call's negotiation has settled —
    /// `SIPRAL_EVENT_KIND_MEDIA_STARTED` is the moment, and minting from inside
    /// that event's callback is allowed — and hand it to every `sipral_media_`
    /// entry point in place of the stack and the call. None of those takes the
    /// stack's lock, which is the point: the thread that carries a call's audio
    /// is never refused a frame because signalling, the event callback or
    /// another call is busy.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a call with no media: one placed with a
    /// description of the caller's own, or one whose negotiation has not
    /// settled. The handle is written only if this returns `SIPRAL_STATUS_OK`.
    ///
    /// The handle outlives the call. Once the call ends, or its stack is
    /// destroyed, every media entry point answers `SIPRAL_STATUS_WRONG_STATE`
    /// on it; a hold, a resume or a change of codec keeps it working. Each
    /// handle minted is released once with `sipral_media_release`, and asking
    /// twice for the same call gives two.
    ///
    /// Safety
    ///
    /// `out_media` must point at one `sipral_handle_t`.
    public static func callMedia(stack: SipralHandle, call: SipralHandle) throws -> SipralHandle {
        var media = SipralHandle()
        let status = sipral_call_media(stack, call, &media)
        try check(status)
        return media
    }

    /// Let a media handle go.
    ///
    /// Its one matching free, whether or not its call is still up and whether
    /// or not its stack still exists. The session is not touched: it belongs to
    /// the call and ends when the call does, so releasing a handle mid-call
    /// stops nothing but the handle. A handle released twice is
    /// `SIPRAL_STATUS_STALE_HANDLE` the second time.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    public static func mediaRelease(media: SipralHandle) throws {
        let status = sipral_media_release(media)
        try check(status)
    }

    /// What one call's media settled on.
    ///
    /// Safety
    ///
    /// `out_info` must point at a `sipral_media_info_t` whose `size` member
    /// says how long it is.
    public static func mediaInfo(media: SipralHandle) throws -> sipral_media_info_t {
        var info = sipral_media_info_t.sized()
        let status = sipral_media_info(media, &info)
        try check(status)
        return info
    }

    /// What one call's media has cost, and what it is costing now.
    ///
    /// A6's live half. `now_ms` is the caller's monotonic clock, as everywhere
    /// else, because "how long since a packet arrived" is a question about the
    /// present and nothing here reads a clock to answer it. Like every media
    /// entry point, this does not move the stack's own clock: it is read at the
    /// frame rate of a user interface, often from the thread that draws one,
    /// and a reading a millisecond behind the last poll is not a caller bug.
    ///
    /// The end-of-call record arrives instead as
    /// `SIPRAL_EVENT_KIND_MEDIA_STATISTICS`, because by then the stream is
    /// gone and this answers `SIPRAL_STATUS_WRONG_STATE`.
    ///
    /// Safety
    ///
    /// `out_stats` must point at a `sipral_stream_stats_t` whose `size` member
    /// says how long it is.
    public static func mediaStatistics(media: SipralHandle, nowMs: UInt64) throws -> sipral_stream_stats_t {
        var stats = sipral_stream_stats_t.sized()
        let status = sipral_media_statistics(media, nowMs, &stats)
        try check(status)
        return stats
    }

    /// Take a datagram off the media socket.
    ///
    /// One entry point for both sockets: RTP and RTCP are told apart by
    /// RFC 5761 §4's rule on the payload type field, so a caller that put both
    /// on one socket does not have to sort them, and one that did not can hand
    /// over whichever arrived.
    ///
    /// `data` is written through. A secured stream is opened in place, and a
    /// caller that needs the ciphertext afterwards keeps its own copy.
    ///
    /// `out_arrival` may be null for a caller that does not want to know what
    /// the datagram turned out to be.
    ///
    /// `now_ms` is when it arrived, on the stack's clock. Reading it here moves
    /// nothing: the network thread and the poll thread read that clock apart,
    /// and a datagram a millisecond behind the last poll is not refused.
    ///
    /// Safety
    ///
    /// `data` must be readable and writable for `len` bytes, `from` readable
    /// for `from_len`, and `out_arrival` must point at one `uint32_t` or be
    /// null.
    public static func mediaReceive(media: SipralHandle, data: inout [UInt8], from: String, nowMs: UInt64) throws -> UInt32 {
        var arrival = UInt32()
        let status =
            data.withUnsafeMutableBufferPointer { p1 in
                Array(from.utf8).withUnsafeBufferPointer { raw2 in
                    raw2.withMemoryRebound(to: CChar.self) { p2 in
                        sipral_media_receive(media, p1.baseAddress, p1.count, p2.baseAddress, p2.count, nowMs, &arrival)
                    }
                }
            }
        try check(status)
        return arrival
    }

    /// Take the frame that is due for the earpiece, and say where it came from.
    ///
    /// Exactly `sipral_media_info_t::frame_samples` samples are written, and a
    /// smaller buffer is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with the number
    /// needed in `out_written`. Every source fills the frame, concealment and
    /// silence included: a device handed nothing for one frame plays whatever
    /// was in its buffer last, and that is a far worse sound than the one being
    /// concealed.
    ///
    /// Safety
    ///
    /// `samples` must be writable for `capacity` `int16_t`, `out_written` must
    /// point at one `size_t` or be null, and `out_source` at one `uint32_t` or
    /// be null.
    public static func mediaPlayback(media: SipralHandle, samples: inout [Int16]) throws -> (written: Int, source: UInt32) {
        var written = Int()
        var source = UInt32()
        let status =
            samples.withUnsafeMutableBufferPointer { p1 in
                sipral_media_playback(media, p1.baseAddress, p1.count, &written, &source)
            }
        try check(status)
        return (written: written, source: source)
    }

    /// Put one frame from the microphone on the wire.
    ///
    /// `sample_count` is `sipral_media_info_t::frame_samples` and nothing else:
    /// a codec cuts one frame at one length, and half a frame encoded as a
    /// whole one is what a peer hears as a stutter.
    ///
    /// A `len` of zero in the packet means the frame was deliberately not sent:
    /// this end is holding the far end, or silence suppression swallowed it.
    /// The RTP timestamp moves by a frame either way, because RFC 3550 §5.1
    /// makes it a measure of time rather than of packets.
    ///
    /// Safety
    ///
    /// `samples` must be readable for `sample_count` `int16_t`, and `packet`
    /// must point at a `sipral_media_packet_t` whose `size` member says how
    /// long it is and whose buffers are writable for the capacities beside
    /// them.
    public static func mediaCapture(media: SipralHandle, samples: [Int16], packet: inout sipral_media_packet_t) throws {
        let status =
            samples.withUnsafeBufferPointer { p1 in
                sipral_media_capture(media, p1.baseAddress, p1.count, &packet)
            }
        try check(status)
    }

    /// The control traffic this call has due.
    ///
    /// A `len` of zero in the packet means nothing is due yet. RFC 3550 §6.3
    /// decides when, and at most one report is due at a time, so one call per
    /// frame is enough.
    ///
    /// It asks one call rather than the whole stack, so the thread that sends
    /// a call's audio sends its reports too, on the same socket and without
    /// reaching the stack: call it after every frame that goes out, and
    /// whenever `sipral_stack_poll` reports a deadline while a call is not
    /// capturing. On a call that negotiated no RTCP it answers zero for ever.
    ///
    /// `now_ms` is read as the stack reads it and moves nothing, as with every
    /// media entry point.
    ///
    /// Safety
    ///
    /// `packet` must point at a `sipral_media_packet_t` as
    /// sipral_media_capture describes.
    public static func mediaPollRtcp(media: SipralHandle, nowMs: UInt64, packet: inout sipral_media_packet_t) throws {
        let status = sipral_media_poll_rtcp(media, nowMs, &packet)
        try check(status)
    }

    /// Whether a digit is going out or waiting to, and how many have not
    /// started yet.
    ///
    /// Either out parameter may be null. A user interface that greys out the
    /// keypad while a number is being sent wants the first; one that shows how
    /// much of a pasted number is left wants the second.
    ///
    /// Safety
    ///
    /// `out_dialling` must point at one `uint32_t` or be null, and
    /// `out_waiting` at one `size_t` or be null.
    public static func mediaDialling(media: SipralHandle) throws -> (dialling: UInt32, waiting: Int) {
        var dialling = UInt32()
        var waiting = Int()
        let status = sipral_media_dialling(media, &dialling, &waiting)
        try check(status)
        return (dialling: dialling, waiting: waiting)
    }

    /// Drop everything queued and stop the digit going out.
    ///
    /// The digit in flight gets no closing packet, which is right for a call
    /// whose media is being taken away: there is nowhere left to send one.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    public static func mediaStopDialling(media: SipralHandle) throws {
        let status = sipral_media_stop_dialling(media)
        try check(status)
    }

    /// Start recording this call to `path`.
    ///
    /// Both directions, mixed, as WAVE. It can be started and stopped as often
    /// as the person on the phone presses the button, and each recording is a
    /// file of its own: a path written to twice would have two headers in it.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a call whose media has ended and for one
    /// already being recorded — two writers on one stream would interleave
    /// frames into both files. `SIPRAL_STATUS_INVALID_ARGUMENT` when the file
    /// system refuses the path, with what it said in the last error.
    ///
    /// The file is made with this call's media held, so this call's audio
    /// waits for the file system to answer and no other call's does.
    ///
    /// Safety
    ///
    /// `path` must be readable for `path_len` bytes.
    public static func mediaRecordStart(media: SipralHandle, path: String) throws {
        let status =
            Array(path.utf8).withUnsafeBufferPointer { raw1 in
                raw1.withMemoryRebound(to: CChar.self) { p1 in
                    sipral_media_record_start(media, p1.baseAddress, p1.count)
                }
            }
        try check(status)
    }

    /// Stop it, and close the file.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when nothing is being recorded. A failure
    /// here leaves a file with all of the audio in it and zeroes in the two
    /// header fields, which is recoverable and is said rather than hidden.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func mediaRecordStop(media: SipralHandle) throws {
        let status = sipral_media_record_stop(media)
        try check(status)
    }

    /// Whether a recording is running on this call, and how much audio it has
    /// taken. Either out parameter may be null.
    ///
    /// The length is of the audio written, not of the file: the header in front
    /// of it is not a recording of anything.
    ///
    /// Safety
    ///
    /// `out_recording` must point at one `uint32_t` or be null, and
    /// `out_recorded_ms` at one `uint64_t` or be null.
    public static func mediaRecordState(media: SipralHandle) throws -> (recording: UInt32, recordedMs: UInt64) {
        var recording = UInt32()
        var recordedMs = UInt64()
        let status = sipral_media_record_state(media, &recording, &recordedMs)
        try check(status)
        return (recording: recording, recordedMs: recordedMs)
    }

    /// Take the next message the stack wants written.
    ///
    /// One at a time, like every other poll here: a caller loops until the
    /// message comes back with a `len` of zero. Call it after every
    /// `sipral_stack_poll` and after every call that hands bytes in, since both
    /// are moments the stack writes at.
    ///
    /// A message longer than `capacity` is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with
    /// the length it needs in `len`, and it is *kept*: the next call with room
    /// for it hands over that same message, before anything queued behind it. So
    /// a caller that brought no buffer at all — a null `data` with a capacity of
    /// zero — learns what to bring without losing the message it asked about.
    ///
    /// Safety
    ///
    /// `transmit` must point at a `sipral_transmit_t` whose `size` member says
    /// how long it is and whose buffers are writable for the capacities beside
    /// them.
    public static func stackPollTransmit(stack: SipralHandle, transmit: inout sipral_transmit_t) throws {
        let status = sipral_stack_poll_transmit(stack, &transmit)
        try check(status)
    }

    /// Hand over one datagram, whole, and say where it came from.
    ///
    /// `from` is the far end, as `host:port`. `to` is the address the datagram
    /// arrived on, which RFC 3581 §4 makes the address the response has to go
    /// out from; null with a length of zero means the address this stack was
    /// created with, which is the answer for a socket bound to one address.
    ///
    /// A WebSocket frame comes in here too: RFC 7118 §4.2 puts one SIP message
    /// in each, so it arrives whole the way a datagram does.
    ///
    /// Bytes that are not a message are `SIPRAL_STATUS_INVALID_ARGUMENT` with
    /// the parse error in the last error. That is an ordinary morning on a
    /// public SIP port and costs exactly this one packet: log it and carry on.
    ///
    /// Safety
    ///
    /// `data` must be readable for `len` bytes, `from` for `from_len`, and `to`
    /// for `to_len`.
    public static func stackReceiveDatagram(stack: SipralHandle, transport: UInt32, data: [UInt8], from: String, to: String, nowMs: UInt64) throws {
        let status =
            data.withUnsafeBufferPointer { p2 in
                Array(from.utf8).withUnsafeBufferPointer { raw3 in
                    raw3.withMemoryRebound(to: CChar.self) { p3 in
                        Array(to.utf8).withUnsafeBufferPointer { raw4 in
                            raw4.withMemoryRebound(to: CChar.self) { p4 in
                                sipral_stack_receive_datagram(stack, transport, p2.baseAddress, p2.count, p3.baseAddress, p3.count, p4.baseAddress, p4.count, nowMs)
                            }
                        }
                    }
                }
            }
        try check(status)
    }

    /// Hand over bytes off a connection, in whatever sizes the reads came in.
    ///
    /// Not a message: a fragment of a framing the layer below reassembles on
    /// `Content-Length` (§18.3), and one call may hold several messages, half of
    /// one, or none at all. No addresses travel with it, because a connection
    /// has one far end and it was named when the transport was bound.
    ///
    /// Framing that cannot be read is fatal to the connection, and unlike a
    /// datagram it cannot be resynchronised: the transport is already retired by
    /// the time this answers `SIPRAL_STATUS_INVALID_ARGUMENT`, and the socket
    /// should be closed. A read of zero bytes is the far end closing, which is
    /// sipral_stack_stream_closed and not this.
    ///
    /// Safety
    ///
    /// `data` must be readable for `len` bytes.
    public static func stackReceiveStream(stack: SipralHandle, transport: UInt32, data: [UInt8], nowMs: UInt64) throws {
        let status =
            data.withUnsafeBufferPointer { p2 in
                sipral_stack_receive_stream(stack, transport, p2.baseAddress, p2.count, nowMs)
            }
        try check(status)
    }

    /// Say that a transport is open and may be written to.
    ///
    /// The one way back from sipral_stack_transport_failed, and the way a
    /// stream stack names its far end: a connection that has just been made
    /// knows its peer, and a stack created before the connect did not. It is
    /// also how a socket re-opened on another address after the network moved
    /// tells this stack what to put in its `Via` from now on — every message
    /// after this one carries `local`, and the ones already in flight carry what
    /// they were written with.
    ///
    /// `local` is the address the far end reaches this one at, as `host:port`.
    /// `remote` is the far end of a connection, and is refused on a datagram
    /// transport, which has many.
    ///
    /// The protocol is not an argument: a stack retransmits or does not
    /// according to what it was created speaking, and a transport that changed
    /// that underneath the timers would be a stack configured out of RFC 3261
    /// §17 halfway through a call.
    ///
    /// Safety
    ///
    /// `local` must be readable for `local_len` bytes and `remote` for
    /// `remote_len`.
    public static func stackTransportBind(stack: SipralHandle, transport: UInt32, local: String, remote: String, nowMs: UInt64) throws {
        let status =
            Array(local.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    Array(remote.utf8).withUnsafeBufferPointer { raw3 in
                        raw3.withMemoryRebound(to: CChar.self) { p3 in
                            sipral_stack_transport_bind(stack, transport, p2.baseAddress, p2.count, p3.baseAddress, p3.count, nowMs)
                        }
                    }
                }
            }
        try check(status)
    }

    /// Say that a transport failed, and that whatever was written to it did not
    /// arrive.
    ///
    /// The transport is retired: every transaction waiting on it fails now, and
    /// the calls and registrations behind them are reported on the next
    /// `sipral_stack_poll` — nothing is delivered from inside this call, here as
    /// everywhere else. Nothing can be sent until
    /// sipral_stack_transport_bind brings one back.
    ///
    /// So this is not the call for one `sendto` that was refused. An ICMP
    /// unreachable is one destination saying no, and a stack that retired its
    /// socket over it would drop the calls that were fine. This is for the
    /// socket that is over.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    public static func stackTransportFailed(stack: SipralHandle, transport: UInt32, error: UInt32, nowMs: UInt64) throws {
        let status = sipral_stack_transport_failed(stack, transport, error, nowMs)
        try check(status)
    }

    /// Say that a connection closed: the far end went away, or a read returned
    /// zero.
    ///
    /// The same retirement as sipral_stack_transport_failed, and a separate
    /// call because it is a separate thing to have happened. An orderly close is
    /// not an error the caller has to invent a kind for, and a stack that made it
    /// one would have the two indistinguishable in a log for ever after.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    public static func stackStreamClosed(stack: SipralHandle, transport: UInt32, nowMs: UInt64) throws {
        let status = sipral_stack_stream_closed(stack, transport, nowMs)
        try check(status)
    }

    /// The short name of an event kind, as a static NUL-terminated
    /// string, or null for a number this build has no kind for.
    ///
    /// The string belongs to the library and lives as long as it is
    /// loaded. A number that is reserved for a feature this build does
    /// not have answers null, the same as one that was never spent: a
    /// name for something that cannot arrive would be a name for
    /// nothing.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns, and is safe to call from any
    /// thread.
    public static func eventKindName(kind: UInt32) -> String? {
        guard let text = sipral_event_kind_name(kind) else { return nil }
        return String(cString: text)
    }

    /// How many lines a header field is on, in a whole SIP message.
    ///
    /// The message is any SIP message in bytes: the one an event carries in
    /// `sipral_event_t::message`, or one the application came by some other
    /// way. The name is matched the way the parser matches it, without regard to
    /// case, and a compact form and its long form are one field (RFC 3261
    /// §7.3.3): `i` counts the `Call-ID` lines, and `Call-ID` counts a line
    /// written `i:`. A field that is not there is a count of zero, not a
    /// failure.
    ///
    /// Safety
    ///
    /// `message` must be readable for `message_len` bytes and `name` for
    /// `name_len`, and `out_count` must point at one `size_t`.
    public static func messageHeaderCount(message: [UInt8], name: String) throws -> Int {
        var count = Int()
        let status =
            message.withUnsafeBufferPointer { p0 in
                Array(name.utf8).withUnsafeBufferPointer { raw1 in
                    raw1.withMemoryRebound(to: CChar.self) { p1 in
                        sipral_message_header_count(p0.baseAddress, p0.count, p1.baseAddress, p1.count, &count)
                    }
                }
            }
        try check(status)
        return count
    }

    /// Where one line of a header field is, in a whole SIP message.
    ///
    /// `index` counts from zero in the order the lines arrived, and has to be
    /// below what `sipral_message_header_count` says for the same name: past it
    /// is `SIPRAL_STATUS_INVALID_ARGUMENT`. `out_offset` and `out_len` then say
    /// where the value sits inside `message`, trimmed at both ends and otherwise
    /// as it arrived, a line fold included. An offset rather than a pointer,
    /// because the bytes are the caller's, and a binding that copied them across
    /// the boundary holds its own copy.
    ///
    /// One line of a field whose value is a comma-separated list may hold
    /// several values; `sipral_message_header_element` reaches those.
    ///
    /// Safety
    ///
    /// As `sipral_message_header_count`, with `out_offset` and `out_len` each
    /// pointing at one `size_t`.
    public static func messageHeader(message: [UInt8], name: String, index: Int) throws -> (offset: Int, len: Int) {
        var offset = Int()
        var len = Int()
        let status =
            message.withUnsafeBufferPointer { p0 in
                Array(name.utf8).withUnsafeBufferPointer { raw1 in
                    raw1.withMemoryRebound(to: CChar.self) { p1 in
                        sipral_message_header(p0.baseAddress, p0.count, p1.baseAddress, p1.count, index, &offset, &len)
                    }
                }
            }
        try check(status)
        return (offset: offset, len: len)
    }

    /// How many values a field whose value is a comma-separated list holds,
    /// across every line it is on.
    ///
    /// RFC 3261 §7.3.1 makes two values on one line, with a comma between them,
    /// and the same two values on two lines one and the same message, and a
    /// proxy is free to turn either into the other. So this counts values
    /// rather than lines, split at every comma that is not inside quotes or
    /// angle brackets. Otherwise as `sipral_message_header_count`.
    ///
    /// Only for a field defined as a list: `P-Asserted-Identity`, `Diversion`,
    /// `Contact`, `Supported`. Any other is split at a comma its value holds as
    /// text, like the one in a `Date` or the ones between the parameters of a
    /// challenge, and `sipral_message_header_count` is the call for it.
    ///
    /// Safety
    ///
    /// As `sipral_message_header_count`.
    public static func messageHeaderElementCount(message: [UInt8], name: String) throws -> Int {
        var count = Int()
        let status =
            message.withUnsafeBufferPointer { p0 in
                Array(name.utf8).withUnsafeBufferPointer { raw1 in
                    raw1.withMemoryRebound(to: CChar.self) { p1 in
                        sipral_message_header_element_count(p0.baseAddress, p0.count, p1.baseAddress, p1.count, &count)
                    }
                }
            }
        try check(status)
        return count
    }

    /// Where one value of a list field is, across every line the field is on.
    ///
    /// `index` counts values in the order they arrived, and has to be below what
    /// `sipral_message_header_element_count` says for the same name. Otherwise
    /// as `sipral_message_header`.
    ///
    /// Safety
    ///
    /// As `sipral_message_header`.
    public static func messageHeaderElement(message: [UInt8], name: String, index: Int) throws -> (offset: Int, len: Int) {
        var offset = Int()
        var len = Int()
        let status =
            message.withUnsafeBufferPointer { p0 in
                Array(name.utf8).withUnsafeBufferPointer { raw1 in
                    raw1.withMemoryRebound(to: CChar.self) { p1 in
                        sipral_message_header_element(p0.baseAddress, p0.count, p1.baseAddress, p1.count, index, &offset, &len)
                    }
                }
            }
        try check(status)
        return (offset: offset, len: len)
    }

}
