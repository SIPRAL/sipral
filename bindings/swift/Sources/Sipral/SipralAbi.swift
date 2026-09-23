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
    /// SrtpPolicy::DtlsOffered: offer DTLS-SRTP (RFC 5764) on
    /// `UDP/TLS/RTP/SAVP`, and answer a plain offer plainly.
    ///
    /// What `Offered` is for SDES, with the difference that matters: the
    /// key never travels in the body, so this is the one policy here that
    /// is sound over a SIP transport somebody else can read. The cost is
    /// a round trip of silence at the start of every call while the
    /// handshake runs, and an application that names it **must** drain
    /// sipral_media_poll_transmit — a handshake whose records never
    /// leave is a call that is up, silent, and reports no error.
    ///
    /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
    /// `SIPRAL_FEATURE_DTLS_SRTP`.
    case dtls = 4
    /// SrtpPolicy::DtlsRequired: offer DTLS-SRTP, and let no stream on
    /// this call carry audio any other way — an answer carrying
    /// `a=crypto` included, since that key travelled in a body this
    /// policy exists to avoid trusting.
    case dtlsRequired = 5
}

/// What a call or a stack says about ICE. Names for
/// `sipral_stack_config_t::ice` (the stack's default) and
/// `sipral_call_config_t::ice` (a per-call override).
///
/// Zero is not one of them, and it is not the same absence on the two
/// structs: on the stack it means this build's own built-in default
/// (`IcePolicy::default()`, which is SipralIce.off); on a call it
/// means the stack's own setting, whatever that came to.
///
/// A call that offers ICE also asks for RFC 5761 multiplexing, whatever
/// `offer_rtcp_mux` says, because an ICE stream with a second component
/// needs a second address and this ABI names one.
public enum SipralIce: UInt32, Sendable {
    /// IcePolicy::Off: do not offer it, and do not answer a peer that
    /// does. The default, and `docs/06-nat.md` says why at length.
    case off = 1
    /// IcePolicy::Offered: offer it, and use it against a peer that
    /// offers it back.
    ///
    /// A peer that does not — an Asterisk with `ice_support=no`, which is
    /// its default — is answered without it and the call runs on the
    /// signalled address and symmetric RTP, exactly as it would have. An
    /// application that names this **must** drain
    /// sipral_media_poll_transmit: a check that never leaves is a
    /// call that never chooses a path.
    ///
    /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
    /// `SIPRAL_FEATURE_ICE`.
    case offered = 2
    /// IcePolicy::Required: offer it, and let no stream on this call
    /// carry audio on a path ICE did not check.
    ///
    /// Each of the three ways a peer can fail to do ICE ends the call's
    /// media with `SIPRAL_EVENT_KIND_MEDIA_FAILED` instead of falling
    /// back. That is the whole difference between this and `Offered`.
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

/// What became of one codec this call's catalogue could have used. Names
/// for sipral_codec_candidate_t.outcome.
///
/// D5's codec half: a negotiation that ends in G.711 when the site
/// configured Opus is a support call, and the answer to it is a list
/// saying which of the two things happened — the far end never named
/// Opus, or it named it and something ahead of it in this end's order
/// won.
public enum SipralCodecOutcome: UInt32, Sendable {
    /// Not an outcome: either the candidate is from a build this ABI has
    /// no number for, or the struct was never filled in.
    case unknown = 0
    /// This is what the call agreed on. Exactly one candidate carries it,
    /// and it names the same codec as `sipral_media_info_t::codec`.
    case chosen = 1
    /// The far end's description did not name it, so it was never in the
    /// running. The commonest answer, and the one that says the question
    /// is about the far end's configuration rather than this one's.
    case notNamed = 2
    /// The far end named it and this end had something better: the codec
    /// in `outranked_by` came first in this call's order.
    case outranked = 3
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
    /// ICE could not carry this call: the far end described none this
    /// stack could use and the policy was `SIPRAL_ICE_REQUIRED`, the far
    /// end took `a=rtcp-mux` out of an answer to an ICE offer, or consent
    /// to send on the pair that was chosen was withdrawn part-way through
    /// (RFC 7675 §5).
    ///
    /// A code of its own because it is the one an application can act on
    /// differently: the call is up and the signalling is sound, and what
    /// changed is only that no path could be checked. A deployment with a
    /// non-ICE profile to fall back to falls back here.
    case ice = 9
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
    /// A record of the DTLS-SRTP handshake that keys this call, which has
    /// been taken. Whatever it owes the far end in reply is waiting in
    /// sipral_media_poll_transmit, and this is the signal to drain it.
    case handshake = 6
    /// Something arrived on a call that agreed to be encrypted and has no
    /// keys yet, so there was nothing to verify it with. The ordinary way
    /// this happens is a peer that starts sending the moment its own half
    /// of the handshake finishes, which is before ours does.
    case notKeyed = 7
}

/// The SRTP transform a call is running. Names for
/// `sipral_media_event_t::suite`.
public enum SipralSrtpSuite: UInt32, Sendable {
    /// No transform: the event is not about one, or the call is not
    /// encrypted.
    case unknown = 0
    /// `AES_CM_128_HMAC_SHA1_80`, the one every implementation has.
    case aesCm80 = 1
    /// `AES_CM_128_HMAC_SHA1_32`, the same cipher with a shorter tag.
    case aesCm32 = 2
    /// `F8_128_HMAC_SHA1_80`, which is what 3GPP asks for. Reachable by
    /// SDES only; RFC 5764 §4.1.2 defines no DTLS-SRTP profile for it.
    case aesF8 = 3
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
    ///
    /// It is one rather than zero on purpose. Zero is what a caller who
    /// filled nothing in leaves behind, and the way a digit travels is the
    /// one setting here that a peer can ignore in silence: a call that
    /// meant INFO and sent nothing at all looks, from this end, exactly
    /// like a call that sent it. So zero names no form and is refused.
    case rtp = 1
    /// An INFO per digit carrying `application/dtmf-relay`, which states the
    /// signal and how long it was held.
    case infoRelay = 2
    /// An INFO per digit carrying `application/dtmf`, whose whole body is the
    /// character. Some switches take only this one.
    case infoPlain = 3
}

/// What an event is about.
///
/// The numbers are part of the ABI and are only ever added to. A binding
/// that meets a kind it does not know must ignore that event rather than
/// refuse it, which is what makes adding one safe.
///
/// Numbers already spent on features this build does not have:
/// - 16: the set of audio devices changed (A2)
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
    /// A subscription moved: it was asked for, granted, put on probation,
    /// scheduled for another attempt, or ended.
    ///
    /// A1. `payload.subscription` says which one and where it is now, and
    /// `reason` why it is not live when it is not. Not sent on every
    /// refresh — a lamp does not move because a refresh was scheduled —
    /// and not sent for a notification arriving, which is
    /// SipralEventKind.notified instead.
    case subscriptionChanged = 15
    /// What one call's media cost, delivered once, after
    /// `SIPRAL_EVENT_KIND_CALL_ENDED`.
    ///
    /// A6's second consumer. `payload.media.statistics` points at the
    /// completed record; it is the library's and lives as long as the callback
    /// does. The stream is gone by the time this arrives, which is why the
    /// numbers travel in the event rather than behind a lookup that would now
    /// fail.
    case mediaStatistics = 17
    /// A request grew too large for a datagram (RFC 3261 §18.1.1) and this
    /// stack has no stream transport open to the destination it names.
    /// `payload.transport_wanted` says where it was going, over what
    /// protocol, and how it measured against the datagram it did not fit.
    ///
    /// B1. Answered with
    /// sipral_stack_transport_bind:
    /// once the application binds a transport to that destination, the
    /// stack sends the request again by itself and this ABI raises
    /// nothing further about it — there is no "it went" event, the same
    /// way there is none for an ordinary request that fit the first time.
    case transportWanted = 18
    /// Nothing has arrived on the media path for longer than the configured
    /// threshold, while signalling is perfectly happy.
    ///
    /// B5. `payload.media.silent_for_ms` says how long. The call is untouched:
    /// whether to hang up over silence is a decision with a person on the other
    /// end of it.
    case mediaStalled = 19
    /// A call a push announced never arrived.
    ///
    /// C2, and not an error. A wake-up chain has a notification service,
    /// a proxy, a bucket timer and a radio in it, and when a call does not
    /// come through it this is the only place that says which end gave up:
    /// the push was delivered, this device woke, refreshed its binding,
    /// and no INVITE followed. `payload.announce` says which announcement
    /// and how long it was waited for; the screen the application raised
    /// can come down.
    case announcedCallMissing = 20
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
    /// The far end pressed a key: an RFC 4733 named telephone event, or an
    /// INFO carrying `application/dtmf-relay` or `application/dtmf`.
    ///
    /// One per keypress, not one per packet: an RFC 4733 digit goes out as
    /// a run of updates and then its closing packet three times, and the
    /// layer below collapses them on the timestamp that identifies the
    /// event; an INFO is one request. `payload.media.digit` is the
    /// character, `event_code` the number behind it for the events no
    /// keypad has a key for, `held_ms` how long it lasted, and `source`
    /// a `SIPRAL_DIGIT_SOURCE` naming which of the two reported it.
    /// `held_ms` zero means either of two different facts: an
    /// `application/dtmf` INFO never carries a duration at all, and a
    /// peer using the other form may have said `Duration=0` and held the
    /// key for no time at all — this C ABI does not tell the two apart.
    case digitReceived = 26
    /// An INFO this end sent for `sipral_call_send_dtmf` reached a final
    /// answer. `payload.call.digit` is the character and
    /// `payload.call.status_code` what the far end answered — a 415 from
    /// a switch that does not take this `Content-Type` included, so the
    /// application learns which of the two INFO forms to try without
    /// guessing from silence. A digit that waited behind another and whose
    /// own INFO could then not be sent at all is reported the same way,
    /// with 503: nothing reached the far end for that one, and no digit
    /// after it is sent.
    case dtmfSent = 27
    /// The lifecycle machine settled: a registrar answered again and
    /// proved a path this stack had stopped believing in, or every rung
    /// of a recovery ladder was climbed and none of them worked.
    /// `payload.recovery` says which, and carries what the ladder that
    /// got there actually knows. `crates/sipral-ffi/src/lifecycle.rs`
    /// and `docs/16-lifecycle.md` are the ladder this reports on.
    case recovery = 28
    /// A dialog's next hop is a name, and this library does not look
    /// names up.
    ///
    /// RFC 3263 §4's TARGET, before any NAPTR, SRV or A lookup: the
    /// route set and the remote target say where this dialog's requests
    /// should go, and what they say is not where they are going. Nothing
    /// here owns a resolver — nothing here owns a socket either — so the
    /// answer is the application's, through
    /// sipral_stack_resolved,
    /// with `payload.resolve.dialog` as the handle it takes.
    ///
    /// **Ignoring it is legitimate and is the common case.** The dialog
    /// keeps the flow its first message travelled on, which §8.1.2 allows
    /// as an alternate address and which is the only thing that survives
    /// a NAT. Nothing times out, nothing retries, and no second event
    /// says the first went unanswered.
    case resolveNeeded = 29
    /// A notification arrived on a subscription, and has been answered.
    ///
    /// A1's other half. The NOTIFY is in `message`, whole and unparsed,
    /// which is where every package this ABI has no reader for is read
    /// from. `payload.subscription.has_dialog_info` says the body was
    /// `application/dialog-info+xml` and could be read, and the picture it
    /// updated is behind
    /// sipral_subscription_dialog_count.
    /// A body that could not be read arrives here all the same, with that
    /// member zero and the request whole: a lamp showing what was last
    /// known beats one showing what a malformed document happened to
    /// contain.
    case notified = 30
    /// The INVITE for a call a push had already announced has arrived
    /// (RFC 8599).
    ///
    /// C2's other half. Queued immediately before the
    /// SipralEventKind.incomingCall naming the same call, and never
    /// without one, so that an application reading its events in order
    /// knows which screen the call belongs to before it is told there is a
    /// call at all. That is the whole point: on a phone the ringing screen
    /// exists first, and a stack that reports the INVITE without saying
    /// which announcement it answers has made the application guess.
    ///
    /// `call` is the call, and `payload.announce.announcement` what
    /// announced it. That announcement is spent: it is not waited for any
    /// more, and `sipral_announcement_forget` on it answers
    /// `SIPRAL_STATUS_WRONG_STATE` rather than taking a screen down twice.
    case callAnnounced = 31
    /// The handshake that keys a call finished, and audio can move
    /// (RFC 5764).
    ///
    /// Only DTLS-SRTP produces it, and it is the moment the call becomes
    /// what it agreed to be: between `SIPRAL_EVENT_KIND_MEDIA_STARTED`
    /// and this one the stream exists, has an address and a codec, and
    /// carries nothing in either direction. An application that draws a
    /// padlock draws it here.
    ///
    /// `call` is the call and `payload.media.suite` is the transform the
    /// handshake chose — the signalling does not, which is why there is
    /// an event for it at all. A call keyed by SDES never produces one,
    /// because such a call is keyed before its session is opened.
    ///
    /// A handshake that does not finish produces
    /// `SIPRAL_EVENT_KIND_MEDIA_FAILED` instead, and the call is left up:
    /// whether to hang it up is a decision with a person on the other end
    /// of it.
    case mediaSecured = 32
    /// `sipral_media_event_t`: ICE chose the path this call's media takes
    /// (RFC 8445 §8.1.1), and audio can move.
    ///
    /// The moment the connectivity checks stop, and the answer to "why is
    /// this call sending to an address the signalling never named" —
    /// which, behind a NAT, is the ordinary outcome rather than a fault.
    /// It arrives again if a nomination of higher priority replaces the
    /// pair part-way through the call.
    ///
    /// The two addresses of the pair are deliberately not carried here,
    /// for the reason `SIPRAL_EVENT_KIND_MEDIA_SECURED` gives about its
    /// own: every packet `sipral_media_capture` and
    /// `sipral_media_poll_transmit` hand back already names the
    /// destination to send it to, so an application that puts this
    /// stack's media on a socket at all has the address the moment it
    /// matters. `sipral_media_statistics` does not repeat it either.
    ///
    /// A call not using ICE never emits it, and that is most calls: the
    /// policy is `SIPRAL_ICE_OFF` unless something asked otherwise.
    case mediaPathChosen = 33
    /// A MESSAGE arrived (RFC 3428 §7) and has already been answered:
    /// 200, because this stack delivers rather than relays.
    /// `payload.message` carries the body, and `account`/`call` on
    /// `sipral_event_t` say where it was addressed and whether it rode
    /// inside a call's dialog.
    case messageReceived = 34
    /// A MESSAGE `sipral_account_message` sent reached its final answer,
    /// or never will. `payload.message.status_code` is 200, a 202 from a
    /// relay, a refusal, or the 408/503 this stack reports for one that
    /// timed out or lost its transport.
    case messageSent = 35
    /// A `message-summary` `NOTIFY` reported the state of a mailbox
    /// (RFC 3842 §3.9). `payload.message` carries the counts of the
    /// `voice-message` class, the one a phone's message-waiting light is
    /// about.
    case messagesWaiting = 36
    /// The account this call belongs to asked for an RFC 6035 voice
    /// quality report and the attempt to publish it has now been made,
    /// once, after `SIPRAL_EVENT_KIND_CALL_ENDED`.
    ///
    /// `payload.media.quality_report_sent` says whether the PUBLISH
    /// left this end — not whether a collector accepted it, which this
    /// stack never waits to learn. Raised only when the account named
    /// a collector to publish to at all
    /// (`sipral_account_settings_t::quality_report_uri`); a call whose
    /// account named none raises nothing here, since nothing was ever
    /// attempted.
    case qualityReportSent = 37
    /// The call this one was joined to has ended, taking the local
    /// conference of two down with it.
    ///
    /// `sipral_call_join` paired the two calls and neither one ever
    /// called `sipral_call_leave` — the partner's own call simply ended
    /// first, the same way any call does, and this is the half of that
    /// this call has to be told: the pairing does not outlive either
    /// side of it. `call` is the survivor; its own session is untouched
    /// and carries on exactly as an unjoined call always has, on
    /// whatever `sipral_media_playback`/`sipral_media_capture` it is
    /// next given directly rather than through `sipral_media_mix`.
    case mediaUnjoined = 38
    /// A STUN server said where one of this end's sockets appears from,
    /// said it has moved, or never answered (RFC 8489). Only on a stack
    /// created with `SIPRAL_NAT_STUN`.
    ///
    /// `payload.nat` says which socket and what it came to. For a
    /// signalling socket the work is already done by the time this
    /// arrives: every account whose `Contact` named the socket names the
    /// public address now, and each one holding a binding has sent the
    /// REGISTER that says so. For a media socket
    /// `sipral_stack_nat_map` named, this is the moment a call can be
    /// placed, rung or answered on it — before it, that is
    /// `SIPRAL_STATUS_WRONG_STATE`. A socket the server never answered
    /// for is described by its own address, as it would have been with
    /// no STUN at all. `account` and `call` are `SIPRAL_HANDLE_NONE`:
    /// a socket is neither.
    case natMapping = 39
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

/// Which of the two ways this stack accepts a digit reported the one
/// SipralEventKind.digitReceived carries. Names for
/// `sipral_media_event_t::source`.
public enum SipralDigitSource: UInt32, Sendable {
    /// RFC 4733: a named telephone event in the RTP stream.
    case rtp = 0
    /// RFC 3261's INFO method (RFC 6086), carrying `application/dtmf-relay`
    /// or `application/dtmf`.
    case info = 1
}

/// What a SipralEventKind.recovery reports happened, for
/// `payload.recovery.state`. Names for the two ways `sipral_ua`'s
/// lifecycle machine settles: a registrar answered again, or a recovery
/// ladder ran out of rungs.
public enum SipralRecoveryOutcome: UInt32, Sendable {
    /// Never written by this build.
    case unknown = 0
    /// A registrar answered again: what was distrusted is proved.
    case running = 1
    /// Every rung was climbed and none of them worked.
    case gaveUp = 2
}

/// The last rung a recovery ladder tried before it gave up, for
/// SipralEventKind.recovery's `payload.recovery.rung`. Meaningful
/// only when `payload.recovery.state` is
/// SipralRecoveryOutcome.gaveUp. Names for `sipral_ua::Rung`, minus
/// Rung::GiveUp itself: `sipral_ua` reports the rung before it that
/// asked for something and went unanswered, not the give-up rung that
/// follows it.
public enum SipralRecoveryRung: UInt32, Sendable {
    /// The ladder did not give up.
    case none = 0
    /// Nothing was believed any more, and nothing was sent.
    case distrust = 1
    /// A REGISTER, and a re-SUBSCRIBE for what was demoted alongside it,
    /// went out or could not.
    case reregister = 2
    /// The application was asked for a transport.
    case wantTransport = 3
    /// The application was asked for an address.
    case wantAddress = 4
}

/// Why a recovery ladder gave up, for SipralEventKind.recovery's
/// `payload.recovery.reason`. Names for `sipral_ua::RecoveryFailure`.
public enum SipralRecoveryFailure: UInt32, Sendable {
    /// The ladder did not give up.
    case none = 0
    /// Every REGISTER that could be sent was sent and none of them was
    /// answered.
    case unreachable = 1
    /// A transport was asked for and the application did not bind one.
    case noTransport = 2
    /// An address was asked for and the application did not supply one.
    case unresolved = 3
}

/// What kind of link the application is on. Names for `from_link` and
/// `to_link` on sipral_stack_network_changed.
///
/// Coarse on purpose: nothing here changes what is sent, and the one
/// value that changes what is *done* is SipralLink.down. The rest is
/// carried so that a change of kind over an unchanged address — a tunnel
/// coming up, a phone moving from Wi-Fi to a mobile network that kept the
/// address — is visible as a change at all.
public enum SipralLink: UInt32, Sendable {
    /// There is no usable interface.
    case down = 0
    /// Cable.
    case wired = 1
    /// Wireless local network.
    case wifi = 2
    /// A mobile network.
    case cellular = 3
    /// A tunnel over one of the others.
    case tunnel = 4
}

/// What a change of network is worth doing about. Names for
/// sipral_stack_network_changed's `out_recovery`.
///
/// Returned from the call itself, so an application does not have to read
/// an event to find out whether anything happened: a laptop that flips
/// between two access points all day gets SipralRecovery.nothing
/// every time and never sends a REGISTER over it.
public enum SipralRecovery: UInt32, Sendable {
    /// Never written by this build.
    case unknown = 0
    /// Nothing this stack uses is different. Nothing is done and nothing
    /// is sent.
    case nothing = 1
    /// The address still stands, so the transports do. What is upstream
    /// of it may not.
    case reregister = 2
    /// A wake: the transport already there is used first, and a new one
    /// is asked for only once it turns out to be dead. Never returned by
    /// this entry point; it is what sipral_stack_resumed starts.
    case reprove = 3
    /// The address is gone. Everything bound to it is unusable and the
    /// application has to open a transport again.
    case rebuild = 4
    /// Packets can leave and names cannot be turned into addresses.
    case resolve = 5
    /// There is no interface. Nothing is tried until there is one.
    case detach = 6
}

/// What a stack does about a NAT in front of it. Names for
/// `sipral_stack_config_t::nat`.
///
/// Zero is not one of them: it means this build's own built-in default,
/// which is SipralNat.off. `docs/06-nat.md` says why that is the
/// default and what `rport` and symmetric RTP already carry without it.
public enum SipralNat: UInt32, Sendable {
    /// Ask nobody. Every address this stack writes is the one the
    /// application gave it.
    case off = 1
    /// Ask the STUN server `sipral_stack_config_t::stun_server` names
    /// where each socket appears from, and write that instead: the
    /// signalling socket's in the `Contact`, a media socket's in `c=` and
    /// `m=`.
    ///
    /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
    /// `SIPRAL_FEATURE_STUN`.
    case stun = 2
}

/// What a socket's mapping came to. Names for
/// `sipral_nat_event_t::mapping`.
public enum SipralNatMapping: UInt32, Sendable {
    /// The first answer: the socket appears at `public`.
    case learned = 1
    /// A later answer about a signalling socket named another address:
    /// the NAT let the mapping go and made a new one, or the network
    /// under the socket changed. `previous` is what it was.
    case moved = 2
    /// The server did not answer, in five and a half seconds, or refused.
    /// The socket is described by its own address, exactly as it would
    /// have been with `SIPRAL_NAT_OFF`; a signalling socket asks again at
    /// its next refresh.
    case unanswered = 3
}

/// Where a subscription is. Names for
/// `sipral_subscription_event_t::state` and for
/// sipral_subscription_state's `out_state`.
public enum SipralSubscriptionState: UInt32, Sendable {
    /// The handle names nothing: never minted here, or ended and let go.
    case unknown = 0
    /// A SUBSCRIBE is on its way and nothing has answered it yet.
    case requesting = 1
    /// The notifier has it and has not decided. RFC 6665 §4.1.3's
    /// `pending` is "insufficient policy information to grant or deny the
    /// subscription yet", and nothing is known about the watched thing
    /// until this becomes SipralSubscriptionState.active.
    case pending = 2
    /// Granted, and notifications are arriving.
    case active = 3
    /// Not live, and a fresh attempt is scheduled. The handle stays
    /// valid: §4.1.2.2's new attempt is "an unrelated initial SUBSCRIBE
    /// request with a freshly generated Call-ID and a new, unique From
    /// tag", and this ABI keeps one name over both of them.
    case retrying = 4
    /// Over, with nothing more coming. The handle names nothing from
    /// here on.
    case ended = 5
}

/// Why a subscription is not live. Names for
/// `sipral_subscription_event_t::reason`.
///
/// Zero unless the state is SipralSubscriptionState.retrying or
/// SipralSubscriptionState.ended. The first nine are what a
/// `Subscription-State: terminated` said in its `reason` parameter (RFC
/// 6665 §4.1.3), and the rest are what happened here instead.
public enum SipralSubscriptionEnd: UInt32, Sendable {
    /// Never written by this build.
    case unknown = 0
    /// `deactivated`: the notifier wants this subscription started again
    /// at once.
    case deactivated = 1
    /// `probation`: started again, but not immediately.
    case probation = 2
    /// `rejected`: the notifier will not serve it, and asking again is
    /// pointless.
    case rejected = 3
    /// `timeout`: it ran out rather than being refreshed.
    case timeout = 4
    /// `giveup`: the notifier could not decide and stopped trying.
    case gaveUp = 5
    /// `noresource`: what was being watched does not exist any more.
    case noResource = 6
    /// `invariant`: the watched thing cannot change, so there is nothing
    /// to notify about.
    case invariant = 7
    /// `terminated` with no reason parameter at all.
    case unstated = 8
    /// This end gave it up: sipral_subscription_end. It wins over
    /// whatever the notifier's closing notification said its own reason
    /// was, because the application asked for this one to stop and that
    /// is the answer to why it is not live.
    case unsubscribed = 9
    /// The notifier answered 489: it does not know this event package.
    case badEvent = 10
    /// The notifier refused the SUBSCRIBE with a status trying again
    /// cannot fix.
    case refused = 11
    /// The SUBSCRIBE was redirected, and following a redirect for one is
    /// not something this stack does by itself.
    case redirected = 12
    /// Nothing answered: the notifier could not be reached at all.
    case unreachable = 13
    /// The SUBSCRIBE was answered and the first NOTIFY never arrived
    /// (§4.1.2.4's timer N, 64·T1).
    case noNotify = 14
    /// What the notifier granted ran out with no refresh answered.
    case expired = 15
}

/// What one watched dialog is doing, and what a lamp is lit from. Names
/// for `sipral_watched_dialog_t::phase` and for
/// sipral_subscription_lamp's `out_phase`.
///
/// RFC 4235 §3.7.1's states, with the order they rank in for a lamp:
/// anything ringing beats anything settled, which is §3.7.2's virtual
/// state machine over every dialog of one resource.
public enum SipralDialogPhase: UInt32, Sendable {
    /// Nothing is going on: no dialog, or every one of them terminated.
    /// This is what an idle lamp shows.
    case idle = 0
    /// A request went out and nothing has answered.
    case trying = 1
    /// Something answered without ringing yet.
    case proceeding = 2
    /// Ringing.
    case early = 3
    /// A call is up.
    case confirmed = 4
    /// This dialog is over. Never sipral_subscription_lamp's answer,
    /// which is SipralDialogPhase.idle when every dialog has ended.
    case terminated = 5
    /// The notifier named a state this build has no number for.
    case unknown = 6
}

/// Which end started a watched dialog. Names for
/// `sipral_watched_dialog_t::direction`.
public enum SipralDialogDirection: UInt32, Sendable {
    /// The notifier did not say.
    case unknown = 0
    /// The watched end placed the call.
    case locally = 1
    /// The watched end was called.
    case remotely = 2
}

/// How a watched dialog ended. Names for
/// `sipral_watched_dialog_t::ended`, and zero while it has not.
public enum SipralDialogEnded: UInt32, Sendable {
    /// It has not ended, or the notifier did not say how.
    case unknown = 0
    /// The caller gave up before it was answered.
    case cancelled = 1
    /// The called end refused it.
    case rejected = 2
    /// A `Replaces` took it over.
    case replaced = 3
    /// The watched end hung up.
    case localBye = 4
    /// The far end hung up.
    case remoteBye = 5
    /// Something went wrong with it.
    case error = 6
    /// Nothing answered in time.
    case timeout = 7
}

/// Which piece of text sipral_subscription_dialog_text is being asked
/// for.
///
/// Every one of them is what the notifier wrote, unparsed: a display name
/// is whatever it put there, and an identity is a URI in the form it sent
/// it in.
public enum SipralDialogText: UInt32, Sendable {
    /// Never asked for.
    case unknown = 0
    /// The notifier's own name for this dialog, which is what it will
    /// keep using for it.
    case id = 1
    /// The dialog's `Call-ID`, when the notifier sent one.
    case callId = 2
    /// Who the watched end is, as a URI.
    case localIdentity = 3
    /// And the display name beside it.
    case localDisplay = 4
    /// Who the other end is, as a URI. This is the one a lamp shows
    /// beside a ringing extension.
    case remoteIdentity = 5
    /// And the display name beside it.
    case remoteDisplay = 6
    /// Where requests for the watched end would be sent.
    case localTarget = 7
    /// And for the other end.
    case remoteTarget = 8
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

public extension sipral_codec_candidate_t {
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

public extension sipral_suspending_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_screen_request_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_subscribe_config_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_watched_dialog_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_push_echo_t {
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
/// binding or an `init` block does for the Kotlin one. What Swift does
/// guarantee is narrower, and it is enough: a static stored property's
/// initializer runs at most once, and finishes before the first read of
/// it returns, on whichever thread reaches it first — the same promise
/// `dispatch_once` made in Objective-C. `abiMismatch` below is one such
/// property, and every call in this `enum` reads it, through
/// `ensureAbi`, before it does anything else. So the check runs the
/// first time this module is asked to do anything at all, on whichever
/// thread makes that first call — not at import, which Swift gives no
/// hook for, but before that first call reaches C, which is the promise
/// this makes instead.
///
/// Skipping it is not something a caller can do: there is no call here
/// that reaches C without going through `ensureAbi` first. The `size`
/// every struct here carries settles how long a struct is, not what is
/// in it: a header and a library that disagree about the order or the
/// meaning of members can still agree about the length, and then every
/// size rule passes while the library reads a pointer out of whatever
/// was put in its place. No entry point can catch that on its own,
/// because whether a pointer is readable is the caller's promise, not
/// something the library can check. This is what finds the
/// disagreement before anything is read, and a mismatch is what it
/// throws — a SipralError, from whichever call the application happens
/// to make first, not a warning that is easy to miss.
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
    public static let abiVersionMinor: UInt32 = 22

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

    /// See SIPRAL_FEATURE_DTMF. RFC 6665 subscriptions and the
    /// dialog-state package a busy lamp field is built on, reached with
    /// sipral_account_subscribe.
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

    /// DTLS-SRTP (RFC 5764): the keys for a call's media come from a
    /// handshake on the media path rather than from the body of a message.
    ///
    /// Behind a compile-time feature for the reason Opus is: a build that
    /// will only ever place SDES calls over a protected SIP transport has no
    /// use for an elliptic curve, and a desk phone counts its flash. Both
    /// `SIPRAL_SRTP_DTLS` and `SIPRAL_SRTP_DTLS_REQUIRED` keep their numbers
    /// in a build without it — a value that has left this header is spent —
    /// and naming one there answers `SIPRAL_STATUS_NOT_SUPPORTED` rather than
    /// quietly placing an unencrypted call.
    ///
    /// An application that sets one of those policies must also drain
    /// `sipral_media_poll_transmit`; see there.
    public static let featureDtlsSrtp: UInt32 = 128

    /// See SIPRAL_FEATURE_DTMF. ICE in the full role (RFC 8445), with
    /// consent freshness (RFC 7675) and the SDP attributes of RFC 8839: a
    /// call's media path is chosen by checking it rather than taken from what
    /// the signalling said.
    ///
    /// Behind a compile-time feature for the reason DTLS-SRTP is, and off by
    /// policy even where it is compiled in — `docs/06-nat.md` tabulates what
    /// it costs on the wire and why it buys nothing against a PBX that learns
    /// the caller's address from the media it receives. Both `SIPRAL_ICE_OFFERED`
    /// and `SIPRAL_ICE_REQUIRED` keep their numbers in a build without it, and
    /// naming one there answers `SIPRAL_STATUS_NOT_SUPPORTED`.
    ///
    /// An application that sets one of those policies must also drain
    /// `sipral_media_poll_transmit`; see there.
    public static let featureIce: UInt32 = 256

    /// See SIPRAL_FEATURE_DTMF. STUN (RFC 8489): a stack created with
    /// `SIPRAL_NAT_STUN` asks a server where its sockets appear from and
    /// writes the answer in the `Contact` and in `c=` and `m=`.
    ///
    /// Behind a compile-time feature of its own, which brings nothing ICE
    /// does not already bring. `SIPRAL_NAT_STUN` keeps its number in a build
    /// without it, and naming it there answers `SIPRAL_STATUS_NOT_SUPPORTED`.
    public static let featureStun: UInt32 = 512

    /// The buffer a caller has to bring for one outgoing packet.
    ///
    /// Not a path MTU — RTP does not discover one — but the bound the session
    /// itself builds against, so a payload larger than this is a payload no
    /// codec in this build produces. It is checked before anything is encoded,
    /// because a frame that was encoded and then had nowhere to go is a frame
    /// lost from a stream whose timestamps have already moved past it.
    public static let mediaPacketBytes: Int = 1500

    /// The bound a datagram of control gets instead, on the way in.
    ///
    /// RTCP is compound: one report packet carries a sender or receiver report
    /// for every source being heard, then the source description, then whatever
    /// extended reports the session agreed on. A call between two ends stays
    /// far inside the media bound, but nothing in RFC 3550 says it has to, and
    /// what arrives is the peer's arithmetic rather than ours. So the media
    /// bound stops being the reason a report is refused: an arriving datagram
    /// that RFC 5761 §4 says is control gets this one, and everything else
    /// still gets SIPRAL_MEDIA_PACKET_BYTES. It bounds the read, so it is
    /// still a bound: a caller that says a megabyte is still refused.
    ///
    /// Sending is unchanged — what this stack builds is its own arithmetic, and
    /// it fits in the media bound.
    public static let mediaRtcpBytes: Int = 8192

    /// Room enough for any address this ABI writes, the NUL included:
    /// `[2001:db8:0000:0000:0000:0000:0000:0001]:65535` and a byte to spare.
    public static let addressBytes: Int = 64

    /// The transport a stack is created with.
    ///
    /// Never retired: sipral_stack_transport_failed and
    /// sipral_stack_stream_closed can still stop it carrying traffic, and
    /// sipral_stack_transport_bind is still what brings it back, exactly
    /// as when this was the only number a stack had. Zero on
    /// `sipral_account_config_t::transport` and `sipral_call_config_t::transport`
    /// means this one, so a caller that never binds a second transport fills
    /// neither in and gets exactly what it always got.
    public static let transportMain: UInt32 = 0

    /// The largest message that crosses in either direction.
    ///
    /// The bound the layer below parses to, which is what stops a hostile peer
    /// from making the parser do unbounded work. A caller's read buffer wants
    /// to be this big on a stream, where one read can hold the end of one
    /// message and the start of another, and 1500 bytes or so on a datagram
    /// socket, where anything larger was fragmented on the way.
    public static let messageBytes: Int = 65535

    /// The answer that lets an INVITE through, and the reason it is a status
    /// code rather than a flag.
    ///
    /// A policy answers with what it wants said: 200 to let the call arrive,
    /// or the status to refuse it with. Making acceptance 200 rather than
    /// zero is the whole safety property of this mechanism — zero is what a
    /// binding hands back when the application's listener threw, and what a
    /// caller who filled nothing in leaves behind, and neither of those may
    /// mean "let the stranger in".
    public static let screenAccept: UInt32 = 200

    /// The calling thread's last error, or an empty string when it
    /// has none. Read the way C reads it: ask for the length, then
    /// for the bytes.
    ///
    /// Not behind `ensureAbi`. This is what a mismatch's own message
    /// is read with, while `abiMismatch` is still being computed, and
    /// going through the check to reach it would be this property
    /// reading itself before it has a value.
    static func rawLastErrorMessage() -> String {
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

    /// The calling thread's last error, or an empty string when it
    /// has none.
    public static func lastErrorMessage() throws -> String {
        try ensureAbi()
        return rawLastErrorMessage()
    }

    /// Whether the library this binding loaded can serve the ABI this
    /// file was printed against, checked once. A static stored
    /// property's initializer in Swift runs at most once and
    /// finishes before the first read of it returns, on whichever
    /// thread reaches it first, which is what makes this safe to
    /// read from every one of them without a lock of its own.
    static let abiMismatch: SipralError? = {
        let status = sipral_abi_check(abiVersionMajor, abiVersionMinor)
        guard status != SIPRAL_STATUS_OK else { return nil }
        return SipralError(
            status: SipralStatus(rawValue: status) ?? .panic,
            message: rawLastErrorMessage()
        )
    }()

    /// Throws what `abiMismatch` found, if it found one. Every call
    /// below reaches this before it reaches C, so a binding loaded
    /// over the wrong library fails here, in whichever call the
    /// application happens to make first, rather than in whichever
    /// one first happens to disagree about a struct's layout.
    static func ensureAbi() throws {
        if let mismatch = abiMismatch {
            throw mismatch
        }
    }

    /// Turn a status into a thrown error, and nothing into nothing.
    static func check(_ status: sipral_status_t) throws {
        guard status != SIPRAL_STATUS_OK else { return }
        throw SipralError(
            status: SipralStatus(rawValue: status) ?? .panic,
            message: rawLastErrorMessage()
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
    public static func statusName(status: Int32) throws -> String? {
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
        var counters = sipral_counters_t.sized()
        let status = sipral_stack_counters(stack, &counters)
        try check(status)
        return counters
    }

    /// Install, replace, or remove the screening policy for one stack.
    ///
    /// Every INVITE that survives sipral_stack_invite_limit reaches this
    /// callback before anything else does: before ringing, before
    /// `SIPRAL_EVENT_KIND_INCOMING_CALL`, before a call handle exists for
    /// anybody to answer or reject. What the callback refuses is answered
    /// with the SIP status it named — when that status refuses, and with 500
    /// when it does not — and forgotten — no event, no handle,
    /// nothing for the application to clean up — and what it takes, by
    /// answering `SIPRAL_SCREEN_ACCEPT`, arrives exactly as it would with no
    /// policy installed at all.
    ///
    /// `callback` given as `NULL` removes the policy: every INVITE reaches
    /// the application again, the way it did before this was ever called.
    /// Calling this a second time with a callback replaces the first outright,
    /// on this stack alone — a different stack's policy, if it has one, is
    /// untouched.
    ///
    /// The rule that the callback must not call back into this stack, and
    /// must not unwind, is on sipral_screen_callback_t and is the reason
    /// this module's own documentation exists; read it there before wiring
    /// one up.
    ///
    /// Safety
    ///
    /// `callback`, when not null, is called on whichever thread is inside an
    /// entry point that is feeding this stack bytes, for as long as the
    /// policy stays installed. `user_data` is handed back to it untouched on
    /// every call and read by nothing here.
    ///
    /// **Whatever `user_data` points at has to outlive the last call, and the
    /// last call is not `sipral_stack_destroy` returning.** A destroy takes
    /// this thread's share of the stack away; a receive already running on
    /// another thread holds one of its own until it is done, and the policy
    /// it is in the middle of asking is still asked. So the moment to free
    /// what the pointer names is once no thread is inside this stack any
    /// more, which is the application's own knowledge and not something this
    /// ABI can answer. Replacing the policy, or removing it with `NULL`, has
    /// the same shape: it takes the stack's lock, so it cannot run while a
    /// policy is being asked, and once it returns the callback that was
    /// there is not asked again.
    public static func stackScreen(stack: SipralHandle, callback: sipral_screen_callback_t, userData: UnsafeMutableRawPointer) throws {
        try ensureAbi()
        let status = sipral_stack_screen(stack, callback, userData)
        try check(status)
    }

    /// How fast one source address may offer this stack an INVITE (A8).
    ///
    /// `burst` calls from one address are let through at once; one more is
    /// earned every `every_ms` after that. What either number means is
    /// exactly what Rate already means by it — `sipral_stack_create`'s
    /// default is ten at once and one every two thousand milliseconds,
    /// loose on purpose, because in most deployments every legitimate call
    /// arrives from the one address a phone registered with.
    ///
    /// A `burst` of zero, or an `every_ms` of zero, is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` and changes nothing: the first admits
    /// no call ever, the first or the one after a week of quiet, and the
    /// second earns a token in no time, which is a limit that never limits —
    /// Rate::unlimited is how the Rust API says that on purpose, and
    /// there is deliberately no way to ask for it from C, since a deployment
    /// that wants no floor at all can simply never call this.
    ///
    /// The floor is asked before sipral_stack_screen's own policy is: a
    /// source that has exhausted it never reaches the callback at all, and is
    /// counted in `sipral_counters_t::screened_refused_by_rate` or
    /// `screened_refused_by_crowding`, never in `screened_refused_by_policy`.
    ///
    /// **It counts by source address, so it counts nothing it cannot name.**
    /// An INVITE that arrived on a byte stream the application bound without
    /// saying where the far end is has no address on it, and this floor lets
    /// every one of those through to the policy — which is where a caller who
    /// cannot identify a stream's far end has to decide, the same way
    /// sipral_screen_request_t.source being null is what it has to decide
    /// on. Naming the far end in `sipral_stack_transport_bind`'s `remote` is
    /// what puts a stream under this floor at all.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func stackInviteLimit(stack: SipralHandle, everyMs: UInt64, burst: UInt32) throws {
        try ensureAbi()
        let status = sipral_stack_invite_limit(stack, everyMs, burst)
        try check(status)
    }

    /// Watch something at the far end (A1).
    ///
    /// One SUBSCRIBE goes out on `account`'s transport, to `account`'s
    /// address, and the handle written back names the subscription from now
    /// until it ends. Nothing has happened yet when this returns: the request
    /// is in the transmit queue, and
    /// `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` reports each step of what
    /// becomes of it.
    ///
    /// A subscription refreshes itself for as long as it is live, at a
    /// fraction of what the notifier granted, and starts a fresh one by itself
    /// after something recoverable — both under this same handle. What ends
    /// it for good is sipral_subscription_end, or an event saying it
    /// ended with no retry, and the handle names nothing after that.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_subscribe_config_t` whose `size`
    /// member says how long it is, with every pointer in it readable for the
    /// length beside it. `out_subscription` must point at one
    /// `sipral_handle_t`.
    public static func accountSubscribe(stack: SipralHandle, account: SipralHandle, config: sipral_subscribe_config_t, nowMs: UInt64) throws -> SipralHandle {
        try ensureAbi()
        var config = config
        var subscription = SipralHandle()
        let status = sipral_account_subscribe(stack, account, &config, &subscription, nowMs)
        try check(status)
        return subscription
    }

    /// Give a subscription up.
    ///
    /// A SUBSCRIBE with `Expires: 0` (§4.1.2.3), and the subscription is not
    /// over when this returns: §4.4.1 makes it live "until the NOTIFY
    /// transaction with a `Subscription-State` of `terminated` completes", so
    /// the closing notification is still answered and
    /// `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` with
    /// `SIPRAL_SUBSCRIPTION_END_UNSUBSCRIBED` says when it has. One that has
    /// no dialog yet has nothing to send this in and ends at once.
    ///
    /// The handle stays usable until that event arrives, and names nothing
    /// after it.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func subscriptionEnd(stack: SipralHandle, subscription: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_subscription_end(stack, subscription, nowMs)
        try check(status)
    }

    /// Where a subscription is, without waiting for its next event.
    ///
    /// SipralSubscriptionState.unknown for a handle that names nothing,
    /// which is what a subscription that has ended leaves behind — and a
    /// status of `SIPRAL_STATUS_OK` all the same, because "it is over" is an
    /// answer to this question rather than a failure of it.
    ///
    /// Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    public static func subscriptionState(stack: SipralHandle, subscription: SipralHandle) throws -> UInt32 {
        try ensureAbi()
        var state = UInt32()
        let status = sipral_subscription_state(stack, subscription, &state)
        try check(status)
        return state
    }

    /// What a lamp for this subscription should show (A1).
    ///
    /// RFC 4235 §3.7.2's virtual state machine over every dialog the notifier
    /// has told this subscription about: anything ringing beats anything
    /// settled, and SipralDialogPhase.idle is what is left once they
    /// have all ended. One call and one number, which is what a busy lamp
    /// field is; sipral_subscription_dialog_count and the two after it
    /// are for an application that wants to show who is on the call as well.
    ///
    /// `SIPRAL_STATUS_NOT_SUPPORTED` for a subscription that has no dialog
    /// state at all — one to another package, or one that is not live, whose
    /// last notification stopped being evidence the moment it stopped being
    /// refreshed.
    ///
    /// Safety
    ///
    /// `out_phase` must point at one `uint32_t`.
    public static func subscriptionLamp(stack: SipralHandle, subscription: SipralHandle) throws -> UInt32 {
        try ensureAbi()
        var phase = UInt32()
        let status = sipral_subscription_lamp(stack, subscription, &phase)
        try check(status)
        return phase
    }

    /// How many dialogs this subscription has been told about.
    ///
    /// They are in the order they were first heard of, and the index one has
    /// here is stable only until the next notification arrives: a dialog that
    /// ended is dropped from the table, and the numbering closes up behind
    /// it. Read a dialog out in the same breath as the count, and read them
    /// both again on the next
    /// SIPRAL_EVENT_KIND_NOTIFIED.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    public static func subscriptionDialogCount(stack: SipralHandle, subscription: SipralHandle) throws -> Int {
        try ensureAbi()
        var count = Int()
        let status = sipral_subscription_dialog_count(stack, subscription, &count)
        try check(status)
        return count
    }

    /// One of them, by index.
    ///
    /// Safety
    ///
    /// `out_dialog` must point at a `sipral_watched_dialog_t` whose `size`
    /// member says how long it is.
    public static func subscriptionDialogAt(stack: SipralHandle, subscription: SipralHandle, index: Int) throws -> sipral_watched_dialog_t {
        try ensureAbi()
        var dialog = sipral_watched_dialog_t.sized()
        let status = sipral_subscription_dialog_at(stack, subscription, index, &dialog)
        try check(status)
        return dialog
    }

    /// A piece of text about one of them, copied into the caller's buffer.
    ///
    /// The same shape `sipral_last_error_message` has, and for the same
    /// reason: the text belongs to the library and a pointer to it would be
    /// one a caller could outlive. `out_needed` always receives the number of
    /// bytes the text needs including the trailing NUL, so a caller that
    /// brought nothing can ask with `capacity` zero and then ask again with
    /// room. A buffer too small for the whole of it is
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` with nothing written to it.
    ///
    /// A piece the notifier did not send is one byte: the NUL.
    ///
    /// Safety
    ///
    /// `buffer` must be writable for `capacity` bytes, and `out_needed` must
    /// point at one `size_t`.
    public static func subscriptionDialogText(stack: SipralHandle, subscription: SipralHandle, index: Int, which: UInt32, buffer: inout [CChar]) throws -> Int {
        try ensureAbi()
        var needed = Int()
        let status =
            buffer.withUnsafeMutableBufferPointer { p4 in
                sipral_subscription_dialog_text(stack, subscription, index, which, p4.baseAddress, p4.count, &needed)
            }
        try check(status)
        return needed
    }

    /// Send an instant message outside any dialog (RFC 3428 §3).
    ///
    /// One MESSAGE goes out on `account`'s transport, to `target`. The
    /// handle written back names the send until its outcome arrives as
    /// `SIPRAL_EVENT_KIND_MESSAGE_SENT`, whether or not the request reached a
    /// transport at all.
    ///
    /// `body` is taken whole, including any byte a header field would
    /// refuse — it is a body, not a header — and `content_type` is checked
    /// the way any text argument at this boundary is.
    ///
    /// Safety
    ///
    /// `target` and `content_type` must be readable for their lengths, and
    /// UTF-8. `body` must be readable for `body_len` bytes, or null with a
    /// length of zero. `out_message` must point at one `sipral_handle_t`.
    public static func accountMessage(stack: SipralHandle, account: SipralHandle, target: String, contentType: String, body: [UInt8], nowMs: UInt64) throws -> SipralHandle {
        try ensureAbi()
        var message = SipralHandle()
        let status =
            Array(target.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    Array(contentType.utf8).withUnsafeBufferPointer { raw3 in
                        raw3.withMemoryRebound(to: CChar.self) { p3 in
                            body.withUnsafeBufferPointer { p4 in
                                sipral_account_message(stack, account, p2.baseAddress, p2.count, p3.baseAddress, p3.count, p4.baseAddress, p4.count, &message, nowMs)
                            }
                        }
                    }
                }
            }
        try check(status)
        return message
    }

    /// A call is expected on this account, announced by a push (C2).
    ///
    /// `caller` is whoever the notification said is calling, as a SIP URI.
    /// The binding is refreshed at once on whatever path exists — §4.1.3
    /// makes that a MUST for a woken agent, and a transport the application
    /// has not opened yet is the ordinary shape of a wake-up, so the REGISTER
    /// is owed and goes the moment one is bound.
    ///
    /// Exactly one of the two values written back names something, and which
    /// one is a race the caller cannot control:
    ///
    /// - `out_announcement` when nothing has arrived yet. The INVITE that
    ///   matches will be reported as `SIPRAL_EVENT_KIND_CALL_ANNOUNCED`
    ///   naming this announcement, immediately before the
    ///   `SIPRAL_EVENT_KIND_INCOMING_CALL` for the same call; and
    ///   `SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING` when none does.
    /// - `out_call` when the INVITE beat the push. The screen just raised
    ///   belongs to that call handle, and no announcement was recorded for it
    ///   to answer. A `SIPRAL_EVENT_KIND_CALL_ANNOUNCED` still arrives for it
    ///   when the incoming-call event has not been delivered yet, because the
    ///   two are queued together and in that order; once it has, this return
    ///   value is the only word about the match there will be.
    ///
    /// An account with no registrar has no binding to refresh, and for one of
    /// those only the matching happens.
    ///
    /// Safety
    ///
    /// `caller` must be readable for `caller_len` bytes, and each of
    /// `out_announcement` and `out_call` must point at one `sipral_handle_t`.
    public static func accountAnnounce(stack: SipralHandle, account: SipralHandle, caller: String, nowMs: UInt64) throws -> (announcement: SipralHandle, call: SipralHandle) {
        try ensureAbi()
        var announcement = SipralHandle()
        var call = SipralHandle()
        let status =
            Array(caller.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    sipral_account_announce(stack, account, p2.baseAddress, p2.count, &announcement, &call, nowMs)
                }
            }
        try check(status)
        return (announcement: announcement, call: call)
    }

    /// Refresh the binding now, without announcing anything (C3).
    ///
    /// For the periodic wake-up a proxy sends to keep a suspended device's
    /// binding alive (RFC 8599 §5.5). A push is evidence that the path to the
    /// proxy is working, so a back-off earned by an earlier outage is not
    /// what to wait for now and is dropped.
    ///
    /// Nothing is sent when a REGISTER is already in flight, which is already
    /// the fastest path, or when the registration has failed in a way trying
    /// again cannot fix — repeating a password that was refused is how an
    /// account gets locked out, and a push does not change that. Both of those
    /// are `SIPRAL_STATUS_OK`: the refresh was asked for and the answer is
    /// that nothing needed sending.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for an account that never registers,
    /// which has no binding to refresh: it is the account that is wrong for
    /// this call, not the build that is missing the feature. A send that could
    /// not happen because no transport is bound yet is reported too, and is
    /// not fatal: the refresh is remembered and goes out the moment one is.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func accountRefreshBinding(stack: SipralHandle, account: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_account_refresh_binding(stack, account, nowMs)
        try check(status)
    }

    /// Stop expecting an announced call.
    ///
    /// The user dismissed the screen, or the application decided the wake-up
    /// was stale. `SIPRAL_STATUS_WRONG_STATE` when it had already been
    /// fulfilled or had already expired, which is not a mistake: the event
    /// that said so and this call can cross.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func announcementForget(stack: SipralHandle, announcement: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_announcement_forget(stack, announcement)
        try check(status)
    }

    /// What the registrar said about push, in the 2xx to the REGISTER that
    /// asked for it.
    ///
    /// `SIPRAL_STATUS_NOT_SUPPORTED` when this account did not ask for push,
    /// or when no binding it could have been said about is standing — none
    /// granted yet, one given up, or one that has lapsed.
    ///
    /// Safety
    ///
    /// `out_echo` must point at a `sipral_push_echo_t` whose `size` member
    /// says how long it is.
    public static func accountPushEcho(stack: SipralHandle, account: SipralHandle) throws -> sipral_push_echo_t {
        try ensureAbi()
        var echo = sipral_push_echo_t.sized()
        let status = sipral_account_push_echo(stack, account, &echo)
        try check(status)
        return echo
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
        let status =
            sdp.withUnsafeBufferPointer { p2 in
                sipral_call_ring(stack, call, p2.baseAddress, p2.count, nowMs)
            }
        try check(status)
    }

    /// Say a call that came in is ringing, with this stack running the audio
    /// before anybody answers.
    ///
    /// The answer to the offer the INVITE carried is written from this
    /// stack's codec order, against `config.media_address` — where this end
    /// will receive media, which only the application can say because it owns
    /// the socket — and the session opens on it there and then: the far end
    /// hears whatever the application plays before anybody picks up.
    /// `SIPRAL_EVENT_KIND_MEDIA_STARTED` follows.
    ///
    /// `config.srtp` overrides the stack's own SRTP policy for this call, the
    /// same way it does on `sipral_call_place`; it is the one way an incoming
    /// call can choose its own SRTP policy at all, since
    /// `sipral_call_answer_media` reads no configuration of its own. Once
    /// this has set it, `sipral_call_answer_media` keeps it: it is answering
    /// a call that already has a catalogue, not choosing one.
    ///
    /// `config.codecs` overrides the stack's codec order for this call in the
    /// same way and for the same window: the answer written here is written
    /// from it, and `sipral_call_answer_media` keeps what it settled.
    ///
    /// `sipral_call_answer_media` after this reuses the session and the
    /// description written here rather than negotiating a second one. What
    /// the 200 OK it sends carries then follows RFC 3262 §5 and RFC 6337
    /// §3.1.1 exactly, from whether this call's 183 went out reliably — see
    /// `docs/05-media.md`, "Ringing with media".
    ///
    /// Every other member of `config` — `target`, `sdp`, `destination`,
    /// `transport`, `keep_all_forks`, `headers` — names something a call to
    /// place would need, and this call already exists; setting one of them
    /// is `SIPRAL_STATUS_INVALID_ARGUMENT` naming it.
    ///
    /// An INVITE that carried no offer is `SIPRAL_STATUS_WRONG_STATE`, with
    /// nothing sent: the offer this end would make instead belongs in no
    /// provisional response this stack can follow up (RFC 3261 §13.2.1,
    /// RFC 6337 §3.1.2).
    ///
    /// Calling this twice on one call is `SIPRAL_STATUS_WRONG_STATE`, and so is
    /// calling it after a `sipral_call_ring` that sent a description of the
    /// application's own: every description in the responses to one INVITE
    /// has to be that same one (RFC 3261 §13.2.1, RFC 6337 §3.1.1). After a
    /// `sipral_call_ring` that sent none, it is not.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_call_config_t` whose `size` member
    /// says how long it is, with `media_address` readable for
    /// `media_address_len` bytes.
    public static func callRingMedia(stack: SipralHandle, call: SipralHandle, config: sipral_call_config_t, configHeaders: [SipralHeader], nowMs: UInt64) throws {
        try ensureAbi()
        var config = config
        let status =
            SipralHeader.withUnsafeArray(configHeaders) { p2Headers -> sipral_status_t in
                config.headers = p2Headers.baseAddress
                config.headers_len = p2Headers.count
                return sipral_call_ring_media(stack, call, &config, nowMs)
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
        try ensureAbi()
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
    /// On a call `sipral_call_ring_media` already rang, nothing is written and
    /// no second session opens: the 183's description and session stand,
    /// `SIPRAL_EVENT_KIND_MEDIA_STARTED` has already been reported, and
    /// `media_address` must still be an address and a port but is not used.
    /// The 200 OK repeats that description when the 183 went out unreliably and
    /// carries none when it went out reliably (RFC 6337 §3.1.1).
    ///
    /// Safety
    ///
    /// `media_address` must be readable for `media_address_len` bytes.
    public static func callAnswerMedia(stack: SipralHandle, call: SipralHandle, mediaAddress: String, nowMs: UInt64) throws {
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
        let status = sipral_call_resume(stack, call, nowMs)
        try check(status)
    }

    /// Offer a call again on another list of codecs (RFC 3264 §8.3.2).
    ///
    /// `codecs` names them the way `sipral_call_config_t::codecs` does:
    /// separated by commas, in the order to offer them. Only the codecs
    /// change. Everything else the call has agreed is offered again as it
    /// is — its media address, its SRTP key or DTLS fingerprint, its ICE
    /// credentials — so nothing is re-keyed and nothing restarts, and a call
    /// on hold stays on hold: `sipral_call_resume` takes it off, on the new
    /// list. A dynamic payload type keeps the codec it has named on this
    /// call, and a codec new to it gets a number nothing has had.
    ///
    /// The list becomes the call's own once the far end accepts it, and
    /// `SIPRAL_EVENT_KIND_MEDIA_CHANGED` names the codec its answer settled
    /// on. A refusal arrives as `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED` and
    /// leaves the call on the list it had.
    ///
    /// For a call whose media the stack describes: one placed or answered
    /// with `media_address` set. `SIPRAL_STATUS_NOT_SUPPORTED` for a name
    /// this build has no codec behind; `SIPRAL_STATUS_INVALID_ARGUMENT` for a
    /// list that is empty, names a codec twice or has a stray comma;
    /// `SIPRAL_STATUS_WRONG_STATE` for a call the stack writes no description
    /// for, one with none agreed yet, one whose stream was refused (a change
    /// of codecs does not bring it back), one still early with a far end that
    /// never listed UPDATE, or while another change is on its way;
    /// `SIPRAL_STATUS_EXHAUSTED` when a codec new to the call finds every
    /// dynamic payload type number already taken.
    ///
    /// Safety
    ///
    /// `codecs` must be readable for `codecs_len` bytes.
    public static func callChangeCodecs(stack: SipralHandle, call: SipralHandle, codecs: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(codecs.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    sipral_call_change_codecs(stack, call, p2.baseAddress, p2.count, nowMs)
                }
            }
        try check(status)
    }

    /// Join two active calls into a local conference of three: from here on,
    /// each call's far end hears the other's far end and this end's own
    /// microphone, mixed. sipral_media_mix
    /// drives one frame of it at a time, on the two calls' own media
    /// handles; this only records the pairing.
    ///
    /// Nothing like a SIP conference server: neither far end's own signalling
    /// ever names the other, and this stack sends no `Refer-To`. Both calls
    /// must already have media running — placed or answered with
    /// `media_address` set, and negotiated — and must agree on a sample rate
    /// and a frame length, since nothing here resamples.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for `call_a == call_b`;
    /// `SIPRAL_STATUS_WRONG_STATE` for a call with no running session, a call
    /// already joined to another, or two calls whose sessions would decode
    /// at different rates or cut audio into frames of different lengths.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callJoin(stack: SipralHandle, callA: SipralHandle, callB: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_call_join(stack, callA, callB)
        try check(status)
    }

    /// Take `call` back out of the pair it is in.
    ///
    /// Neither call's session is touched: each one goes back to carrying its
    /// own audio directly, through `sipral_media_playback` and
    /// `sipral_media_capture`, exactly as an unjoined call always has.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a call that is not currently joined to
    /// another.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callLeave(stack: SipralHandle, call: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_call_leave(stack, call)
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
        try ensureAbi()
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
        try ensureAbi()
        let status = sipral_call_reject_session(stack, call, code, nowMs)
        try check(status)
    }

    /// Send DTMF on a call that is up, in whichever of the three forms the far
    /// end takes.
    ///
    /// `digits` are `0` to `9`, `*`, `#` and `A` to `D`, the sixteen events of
    /// RFC 4733 §3.2, in the order they were pressed, checked as a whole
    /// before anything goes out: one character no keypad has, anywhere in the
    /// string, sends nothing, not even the keys ahead of it. `duration_ms` is
    /// how long each one lasts, or zero for the hundred milliseconds every
    /// one of the three forms defaults to.
    ///
    /// `via` is a SipralDtmf, and it is chosen per send rather than per
    /// call: which form a peer accepts is a fact about the peer, and an
    /// application that has just learned the answer for this one must not have
    /// to tear the call down to act on it. `SIPRAL_DTMF_RTP` puts the digits in
    /// the media, where they replace the audio for as long as they last and
    /// queue behind each other. The two INFO forms put one request per digit
    /// in the dialog, but not all at once: over UDP, overlapping non-INVITE
    /// transactions can arrive in any order, so the next digit's INFO waits
    /// for the one before it to reach a final answer. A 2xx sends it; a
    /// refusal, a timeout or a transport failure ends the sequence there
    /// instead, and the digits still waiting are discarded rather than sent
    /// out of order — the digit that ended it is what
    /// `SIPRAL_EVENT_KIND_DTMF_SENT` names, and nothing is reported for the
    /// ones it took down with it. Digits handed over while an INFO of this
    /// call is still unanswered queue behind the ones already waiting, as the
    /// media's do, rather than go out at once. A call holds at most sixty-four
    /// INFO digits at once, the one in flight included; a string that would
    /// take it past that is refused whole with `SIPRAL_STATUS_INVALID_ARGUMENT`,
    /// the same as one with a character no keypad has, and nothing of it is
    /// sent.
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
        let status = sipral_call_transfer_to(stack, call, other, nowMs)
        try check(status)
    }

    /// Take a transfer that was asked for, place the call it names the way
    /// sipral_call_place places one, and write its handle to
    /// `out_placed`.
    ///
    /// `config.target` is not read: the far end already said where this goes
    /// when it asked for the transfer, and a target of the caller's own would
    /// be a second one contradicting it — `SIPRAL_STATUS_INVALID_ARGUMENT`
    /// naming it. Everything else in `config` means what it means on
    /// `sipral_call_place`: `sdp` for a description the application wrote and
    /// runs the audio of, `media_address` for one this stack writes and runs
    /// (`config.srtp` overriding the stack's own policy for it, the same
    /// way), `headers`, `destination`, `transport` and `keep_all_forks` for
    /// the INVITE this places. `Replaces` and `Referred-By` among `headers`
    /// are `SIPRAL_STATUS_INVALID_ARGUMENT`, nothing sent and the transfer still
    /// there to take: that INVITE takes both from the REFER. Giving neither
    /// `sdp` nor `media_address` is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT`, for the same reason it is on
    /// `sipral_call_place`: the answer to an offerless INVITE has nowhere to
    /// go but the ACK, and this ABI hands nothing back from there.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_call_config_t` whose `size` member
    /// says how long it is, with every pointer in it readable for the length
    /// beside it, and `out_placed` at one `sipral_handle_t`.
    public static func callAcceptTransfer(stack: SipralHandle, call: SipralHandle, config: sipral_call_config_t, configHeaders: [SipralHeader], nowMs: UInt64) throws -> SipralHandle {
        try ensureAbi()
        var config = config
        var placed = SipralHandle()
        let status =
            SipralHeader.withUnsafeArray(configHeaders) { p2Headers -> sipral_status_t in
                config.headers = p2Headers.baseAddress
                config.headers_len = p2Headers.count
                return sipral_call_accept_transfer(stack, call, &config, &placed, nowMs)
            }
        try check(status)
        return placed
    }

    /// Refuse one instead.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callRejectTransfer(stack: SipralHandle, call: SipralHandle, code: UInt32, nowMs: UInt64) throws {
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
    public static func codecName(codec: UInt32) throws -> String? {
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
        var info = sipral_media_info_t.sized()
        let status = sipral_media_info(media, &info)
        try check(status)
        return info
    }

    /// How many codecs were in the running on this call.
    ///
    /// This call's own catalogue, which is the stack's order unless
    /// `sipral_call_config_t::codecs` named another. Zero is an answer, not a
    /// failure: a call negotiated from a description with no media line in it
    /// had nothing in the running at all.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    public static func mediaCodecCandidateCount(media: SipralHandle) throws -> Int {
        try ensureAbi()
        var count = Int()
        let status = sipral_media_codec_candidate_count(media, &count)
        try check(status)
        return count
    }

    /// One of them, by index, from zero to what
    /// `sipral_media_codec_candidate_count` said, in this call's own order.
    ///
    /// D5 in one place: what this end offered, what the far end named, and
    /// which of the two ran out first. An index past the end is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` naming how many there are.
    ///
    /// Safety
    ///
    /// `out_candidate` must point at a `sipral_codec_candidate_t` whose `size`
    /// member says how long it is.
    public static func mediaCodecCandidateAt(media: SipralHandle, index: Int) throws -> sipral_codec_candidate_t {
        try ensureAbi()
        var candidate = sipral_codec_candidate_t.sized()
        let status = sipral_media_codec_candidate_at(media, index, &candidate)
        try check(status)
        return candidate
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
    /// this end is holding the far end, silence suppression swallowed it, or
    /// ICE has not chosen a path for this call yet. The RTP timestamp moves by
    /// a frame in the first two cases, because RFC 3550 §5.1 makes it a
    /// measure of time rather than of packets; in the third nothing is
    /// encoded at all, since there is no packet for the timestamp to belong
    /// to and a codec that carries state would have moved it for nothing.
    ///
    /// `now_ms` is read as the stack reads it and moves nothing, as with every
    /// media entry point. It is what tells ICE that traffic went out on the
    /// pair it chose, which is what RFC 8445 §11 lets it stop sending
    /// keepalives for.
    ///
    /// Safety
    ///
    /// `samples` must be readable for `sample_count` `int16_t`, and `packet`
    /// must point at a `sipral_media_packet_t` whose `size` member says how
    /// long it is and whose buffers are writable for the capacities beside
    /// them.
    public static func mediaCapture(media: SipralHandle, nowMs: UInt64, samples: [Int16], packet: inout sipral_media_packet_t) throws {
        try ensureAbi()
        let status =
            samples.withUnsafeBufferPointer { p2 in
                sipral_media_capture(media, nowMs, p2.baseAddress, p2.count, &packet)
            }
        try check(status)
    }

    /// One frame of a local conference of two calls: decode what `media_a`'s
    /// and `media_b`'s far ends each sent, mix what each of the three
    /// parties — the two far ends and this end — is owed, and send the two
    /// frames the far ends are owed.
    ///
    /// `sipral_call_join` must already have paired the two calls these two
    /// handles belong to. Nothing here checks that itself: checking it would
    /// mean taking the stack's lock on every frame, which is exactly what a
    /// media handle exists to avoid, so this mixes whatever two handles it is
    /// given — the same trust every other `sipral_media_` entry point places
    /// in the caller having minted the handle from a call worth acting on.
    ///
    /// `mic` is this end's own frame, `mic_count` long; `local` is filled
    /// with what this end's own loudspeaker is owed, `local_count` long. Both
    /// are `sipral_media_info_t::frame_samples` on a call this pair actually
    /// agreed on — `sipral_call_join` already made that the same on both.
    /// `packet_a` and `packet_b` are filled the way `sipral_media_capture`
    /// fills one, each with what its own call's far end is now owed: `mic`
    /// mixed with the *other* far end's frame rather than `mic` alone, which
    /// is also what each call's own recording keeps if one is running.
    ///
    /// Drive a joined pair from one thread, one frame at a time. The two
    /// sessions are locked together for the length of the call, in a fixed
    /// order that does not depend on which handle is named first, so a
    /// second `sipral_media_mix` on the same pair waits for this one rather
    /// than deadlocking against it — but a thread still calling
    /// `sipral_media_playback`/`sipral_media_capture` on either call alone at
    /// the same time is a second driver this mix does not know about.
    ///
    /// Safety
    ///
    /// `mic` must be readable for `mic_count` `int16_t` and `local` writable
    /// for `local_count` `int16_t`, the two must not overlap, and
    /// `packet_a` and `packet_b` must each point at a
    /// `sipral_media_packet_t` as `sipral_media_capture` describes.
    public static func mediaMix(mediaA: SipralHandle, mediaB: SipralHandle, nowMs: UInt64, mic: [Int16], local: inout [Int16], packetA: inout sipral_media_packet_t, packetB: inout sipral_media_packet_t) throws {
        try ensureAbi()
        let status =
            mic.withUnsafeBufferPointer { p3 in
                local.withUnsafeMutableBufferPointer { p4 in
                    sipral_media_mix(mediaA, mediaB, nowMs, p3.baseAddress, p3.count, p4.baseAddress, p4.count, &packetA, &packetB)
                }
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
        try ensureAbi()
        let status = sipral_media_poll_rtcp(media, nowMs, &packet)
        try check(status)
    }

    /// A datagram this call owes the far end that is neither audio nor a
    /// report: today, a record of the DTLS-SRTP handshake that keys it.
    ///
    /// A `len` of zero means nothing is due. On a call that is not keyed by a
    /// handshake — every call in a build without `SIPRAL_FEATURE_DTLS_SRTP`,
    /// and every SDES or plain call in a build with it — that is the answer
    /// for ever, and calling this costs one comparison.
    ///
    /// **Drain it to empty**, in a loop, after every `sipral_media_receive`
    /// that answered `SIPRAL_ARRIVAL_HANDSHAKE` and at every deadline
    /// `sipral_stack_poll` names. A handshake whose records never leave is a
    /// ClientHello that never goes out: the call rings, answers, carries no
    /// audio in either direction, and reports nothing wrong for the two
    /// minutes it takes to give up. That is the one failure this entry point
    /// exists to prevent, and there is no way to notice it from the outside.
    ///
    /// `now_ms` is read as the stack reads it and moves nothing, as with every
    /// media entry point.
    ///
    /// Safety
    ///
    /// `packet` must point at a `sipral_media_packet_t` as
    /// sipral_media_capture describes.
    public static func mediaPollTransmit(media: SipralHandle, nowMs: UInt64, packet: inout sipral_media_packet_t) throws {
        try ensureAbi()
        let status = sipral_media_poll_transmit(media, nowMs, &packet)
        try check(status)
    }

    /// The RTCP goodbye of a call whose media has ended (task 8.4.21).
    ///
    /// `MediaEngine::release` builds the BYE RFC 3550 §6.3.7 owes the far end
    /// the moment a call's session stops, but by then the call's media
    /// handle is already gone — every `sipral_media_` entry point on it
    /// answers `SIPRAL_STATUS_WRONG_STATE` — so this is a stack-level call
    /// instead, the one place left that still knows the goodbye belonged to
    /// that call.
    ///
    /// `out_call` is written with the handle of the call the goodbye
    /// belonged to — `SIPRAL_HANDLE_NONE` when nothing was waiting. The
    /// call itself is already over; the handle is there only so the
    /// application knows which media socket to send the datagram from, since
    /// it owns that socket and this ABI never did. Passing it to any other
    /// entry point answers whatever a stale handle of its kind already
    /// answers.
    ///
    /// One at a time, like every other poll in this crate: call it after
    /// every `sipral_stack_poll` that delivered `SIPRAL_EVENT_KIND_CALL_ENDED`
    /// for a call this stack was running media on, and keep calling until
    /// `out_packet` comes back with a `len` of zero. A call whose media never
    /// ran leaves nothing here at all.
    ///
    /// Safety
    ///
    /// `out_call` must point at one `sipral_handle_t`, and `out_packet` at a
    /// `sipral_media_packet_t` as sipral_media_capture describes.
    public static func stackPollFarewell(stack: SipralHandle, outPacket: inout sipral_media_packet_t) throws -> SipralHandle {
        try ensureAbi()
        var call = SipralHandle()
        let status = sipral_stack_poll_farewell(stack, &call, &outPacket)
        try check(status)
        return call
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
        let status =
            data.withUnsafeBufferPointer { p2 in
                sipral_stack_receive_stream(stack, transport, p2.baseAddress, p2.count, nowMs)
            }
        try check(status)
    }

    /// Say that a transport is open and may be written to — the main one
    /// again, or a further one this stack has not had before.
    ///
    /// The one way back from sipral_stack_transport_failed, the way a
    /// stream stack names its far end, and the way a further transport enters
    /// the table at all. `transport` is SIPRAL_TRANSPORT_MAIN to (re)bind
    /// the main one, or any other number: one this stack already has rebinds
    /// it, and one it does not opens it — the number is the caller's own
    /// choice, the same as `sipral_account_config_t::transport` and
    /// `sipral_call_config_t::transport` read it. `out_transport_id` may be
    /// null; when it is not, it receives that same number, which is where a
    /// caller answering
    /// SipralEventKind.transportWanted
    /// reads back the id it just gave one of those two configs.
    ///
    /// `protocol` is a crate::stack::SipralTransport.
    /// Rebinding an existing transport takes zero to mean "whatever it
    /// already speaks" and anything else has to agree with that or this is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` — a stack retransmits or does not
    /// according to what a transport was opened speaking, and changing that
    /// underneath the timers would be a transport configured out of RFC 3261
    /// §17 halfway through a call. Opening a new one needs a protocol to
    /// speak, so zero there is the same refusal for the opposite reason:
    /// nothing to fall back on.
    ///
    /// `local` is the address the far end reaches this one at, as `host:port`.
    /// `remote` is the far end of a connection, and is refused on a datagram
    /// transport, which has many.
    ///
    /// This is also how a request
    /// SipralEventKind.transportWanted
    /// named gets to leave: once this returns `SIPRAL_STATUS_OK` for the
    /// protocol and destination the event gave, the stack sends the request
    /// again by itself on the next `sipral_stack_poll` — there is no further
    /// event about that one request.
    ///
    /// Safety
    ///
    /// `local` must be readable for `local_len` bytes, `remote` for
    /// `remote_len`, and `out_transport_id`, when it is not null, must point
    /// at one `uint32_t`.
    public static func stackTransportBind(stack: SipralHandle, transport: UInt32, `protocol`: UInt32, local: String, remote: String, nowMs: UInt64) throws -> UInt32 {
        try ensureAbi()
        var transportId = UInt32()
        let status =
            Array(local.utf8).withUnsafeBufferPointer { raw3 in
                raw3.withMemoryRebound(to: CChar.self) { p3 in
                    Array(remote.utf8).withUnsafeBufferPointer { raw4 in
                        raw4.withMemoryRebound(to: CChar.self) { p4 in
                            sipral_stack_transport_bind(stack, transport, `protocol`, p3.baseAddress, p3.count, p4.baseAddress, p4.count, nowMs, &transportId)
                        }
                    }
                }
            }
        try check(status)
        return transportId
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
        try ensureAbi()
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
        try ensureAbi()
        let status = sipral_stack_stream_closed(stack, transport, nowMs)
        try check(status)
    }

    /// Ask where a media socket appears from, before a call is described
    /// on it.
    ///
    /// `local` is the address the socket is bound to, as `host:port` — the
    /// same text the call's `media_address` will be. The request is waiting
    /// in sipral_stack_poll_stun when this returns, the answer goes in
    /// through sipral_stack_receive_stun, and
    /// `SIPRAL_EVENT_KIND_NAT_MAPPING` says what it came to, within five and
    /// a half seconds whatever the server does. From then on a call placed,
    /// rung or answered with that `media_address` is described by the public
    /// address, and asks for `a=rtcp-mux`, since one mapping describes one
    /// port. Placing one before the answer is `SIPRAL_STATUS_WRONG_STATE`.
    ///
    /// The mapping is spent by the call it describes. A socket used for a
    /// second call is named here again — nothing kept the first answer true
    /// in between.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` on a stack created without
    /// `SIPRAL_NAT_STUN`, and `SIPRAL_STATUS_INVALID_ARGUMENT` for a
    /// signalling socket of the stack's own, which is kept mapped already.
    ///
    /// Safety
    ///
    /// `local` must be readable for `local_len` bytes.
    public static func stackNatMap(stack: SipralHandle, local: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(local.utf8).withUnsafeBufferPointer { raw1 in
                raw1.withMemoryRebound(to: CChar.self) { p1 in
                    sipral_stack_nat_map(stack, p1.baseAddress, p1.count, nowMs)
                }
            }
        try check(status)
    }

    /// Take the next STUN request a media socket has to send.
    ///
    /// The same record and the same rules as `sipral_stack_poll_transmit`,
    /// on a queue of its own: loop until `len` comes back zero, after every
    /// sipral_stack_nat_map, every sipral_stack_receive_stun and
    /// every `sipral_stack_poll`, since the stack retransmits a request
    /// nobody answered. `source` is always written, and it is the socket to
    /// send from — the whole point is the address the server sees it come
    /// from, so sending it from any other socket learns the wrong one.
    /// `transport` is zero and names nothing here, and `protocol` is UDP.
    ///
    /// Safety
    ///
    /// `transmit` must point at a `sipral_transmit_t` whose `size` member says
    /// how long it is and whose buffers are writable for the capacities beside
    /// them.
    public static func stackPollStun(stack: SipralHandle, transmit: inout sipral_transmit_t) throws {
        try ensureAbi()
        let status = sipral_stack_poll_stun(stack, &transmit)
        try check(status)
    }

    /// Hand over a datagram that arrived on a media socket
    /// sipral_stack_nat_map named, before a call has media on it.
    ///
    /// `to` is the socket it arrived on, as `local` was given there; `from`
    /// is where it came from. `SIPRAL_STATUS_OK` when it was the STUN
    /// server's answer, which is then the stack's and nobody else's;
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for anything else — early media from
    /// a far end, a datagram from a stranger, an answer from any address but
    /// the server's — which costs that one datagram and nothing more. Only
    /// the server's own address is believed, and only an answer to a request
    /// this stack sent: that is the whole defence against a forged answer
    /// naming an address of the attacker's choosing as this end's own.
    ///
    /// Safety
    ///
    /// `data` must be readable for `len` bytes, `from` for `from_len`, and
    /// `to` for `to_len`.
    public static func stackReceiveStun(stack: SipralHandle, data: [UInt8], from: String, to: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            data.withUnsafeBufferPointer { p1 in
                Array(from.utf8).withUnsafeBufferPointer { raw2 in
                    raw2.withMemoryRebound(to: CChar.self) { p2 in
                        Array(to.utf8).withUnsafeBufferPointer { raw3 in
                            raw3.withMemoryRebound(to: CChar.self) { p3 in
                                sipral_stack_receive_stun(stack, p1.baseAddress, p1.count, p2.baseAddress, p2.count, p3.baseAddress, p3.count, nowMs)
                            }
                        }
                    }
                }
            }
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
    public static func eventKindName(kind: UInt32) throws -> String? {
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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
        try ensureAbi()
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

    /// The operating system says this process stops shortly.
    ///
    /// Everything reached from here is synchronous, bounded by the number of
    /// accounts and subscriptions, and cannot fail. Nothing is sent — see
    /// `docs/16-lifecycle.md` for why a graceful de-registration is the wrong
    /// thing to attempt in this window rather than the obvious one — and
    /// nothing stays scheduled: a stack that is suspended and never resumed
    /// has no deadline to fire and no work left behind.
    ///
    /// Calls that are up are left exactly as they are. A lid closing and
    /// opening again is seconds, and hanging up a live call because the
    /// machine blinked is worse than finding out a few seconds later that it
    /// is gone.
    ///
    /// `out_report` receives what was found: bindings that stopped being
    /// evidence, subscriptions whose last notification stopped being
    /// evidence, and calls left untouched.
    ///
    /// Safety
    ///
    /// `out_report` must point at a `sipral_suspending_t` whose `size` member
    /// says how long it is.
    public static func stackSuspending(stack: SipralHandle, nowMs: UInt64) throws -> sipral_suspending_t {
        try ensureAbi()
        var report = sipral_suspending_t.sized()
        let status = sipral_stack_suspending(stack, nowMs, &report)
        try check(status)
        return report
    }

    /// The process is awake again.
    ///
    /// Arbitrary time has passed — arbitrary, not measurable, because the
    /// clock this stack is driven by did not run while the machine was
    /// suspended — and every transport may be dead. What was believed is
    /// dropped and proved again: the transport already there is used first,
    /// because most wakes are short and it still works, and
    /// sipral_account_rebind is how the application hands over a new one
    /// once this stack says it needs one.
    ///
    /// Safe to call without a matching sipral_stack_suspending. Some
    /// platforms only notify on the way back.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func stackResumed(stack: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_stack_resumed(stack, nowMs)
        try check(status)
    }

    /// The network is a different one, described before and after in as much
    /// detail as the decision needs.
    ///
    /// `from_link`/`to_link` is a SipralLink. `*_address` is the local
    /// address this stack's transports are bound to, as an IPv4 or IPv6
    /// literal with no port — a change of it invalidates every transport and
    /// every binding at once. `*_interface` is the platform's own identity
    /// for the interface, never parsed and only ever compared to another one
    /// of itself; two networks can hand out the same address, and a phone
    /// that walks from one office to another gets away with it until a call
    /// comes in. `*_resolves` is whether a name can become an address there,
    /// because that is the one failure that leaves everything else looking
    /// healthy. Any of the four address or interface arguments may be null
    /// with a length of zero, for a fact the application has none to give.
    ///
    /// `out_recovery` receives what was decided, as a SipralRecovery, so
    /// this is safe to call as often as the platform delivers the
    /// notification — most of the time nothing this stack uses is different,
    /// and `SIPRAL_RECOVERY_NOTHING` is the whole of what happens. It may be
    /// null.
    ///
    /// Safety
    ///
    /// Every address and interface pointer must be readable for the length
    /// beside it or null with a length of zero, and `out_recovery` must point
    /// at one `uint32_t` or be null.
    public static func stackNetworkChanged(stack: SipralHandle, fromLink: UInt32, fromAddress: String, fromInterface: String, fromResolves: UInt32, toLink: UInt32, toAddress: String, toInterface: String, toResolves: UInt32, nowMs: UInt64) throws -> UInt32 {
        try ensureAbi()
        var recovery = UInt32()
        let status =
            Array(fromAddress.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    Array(fromInterface.utf8).withUnsafeBufferPointer { raw3 in
                        raw3.withMemoryRebound(to: CChar.self) { p3 in
                            Array(toAddress.utf8).withUnsafeBufferPointer { raw6 in
                                raw6.withMemoryRebound(to: CChar.self) { p6 in
                                    Array(toInterface.utf8).withUnsafeBufferPointer { raw7 in
                                        raw7.withMemoryRebound(to: CChar.self) { p7 in
                                            sipral_stack_network_changed(stack, fromLink, p2.baseAddress, p2.count, p3.baseAddress, p3.count, fromResolves, toLink, p6.baseAddress, p6.count, p7.baseAddress, p7.count, toResolves, nowMs, &recovery)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        try check(status)
        return recovery
    }

    /// There is no usable interface.
    ///
    /// Distinct from sipral_stack_name_resolution_lost because the
    /// recovery is the opposite one: with nothing that can leave, nothing is
    /// tried and nothing is scheduled, which is the cheapest this stack ever
    /// is. The way out is sipral_stack_network_changed, the notification
    /// every platform delivers when an interface comes back.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func stackInterfaceLost(stack: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_stack_interface_lost(stack, nowMs)
        try check(status)
    }

    /// Names no longer become addresses.
    ///
    /// The dangerous one: the interface is up and packets leave, so
    /// everything reads healthy, while every address this stack learned from
    /// a name may now stand for somewhere else. A binding whose registrar was
    /// written as a name stops being evidence; one pointed at a literal
    /// address never needed a resolver and is left running.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func stackNameResolutionLost(stack: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_stack_name_resolution_lost(stack, nowMs)
        try check(status)
    }

    /// Point an account at a transport and an address again.
    ///
    /// `remote` is the far end this account's requests go to now, as
    /// `host:port`. `contact` is where this endpoint can be reached, as it
    /// goes in `Contact`; it is not optional, because after a change of
    /// address the old one names somewhere the far end cannot reach, and a
    /// stack that let it stand would register a binding that silently
    /// receives nothing.
    ///
    /// `transport` must be one this stack already has —
    /// SIPRAL_TRANSPORT_MAIN or
    /// a further one sipral_stack_transport_bind
    /// has bound — and any other number is `SIPRAL_STATUS_INVALID_ARGUMENT`:
    /// this call points an account at a transport, it does not open one.
    ///
    /// Safe to call whether or not this stack is waiting for it. When it is,
    /// answering climbs the next rung at once rather than waiting out the
    /// rest of the back-off — the application answering in milliseconds is
    /// the normal case, and there is nothing to be gained by making a wake
    /// take a further half minute. When it is not, this still repoints the
    /// account, and the next REGISTER this stack sends for it — a refresh, or
    /// the next rung of a ladder started afterwards — uses what was given
    /// here.
    ///
    /// Safety
    ///
    /// `remote` must be readable for `remote_len` bytes and `contact` for
    /// `contact_len` bytes.
    public static func accountRebind(stack: SipralHandle, account: SipralHandle, transport: UInt32, remote: String, contact: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(remote.utf8).withUnsafeBufferPointer { raw3 in
                raw3.withMemoryRebound(to: CChar.self) { p3 in
                    Array(contact.utf8).withUnsafeBufferPointer { raw4 in
                        raw4.withMemoryRebound(to: CChar.self) { p4 in
                            sipral_account_rebind(stack, account, transport, p3.baseAddress, p3.count, p4.baseAddress, p4.count, nowMs)
                        }
                    }
                }
            }
        try check(status)
    }

    /// Say the process has just started, so that time to ready is measured
    /// from somewhere.
    ///
    /// The zero of sipral_account_time_to_ready, and a declaration rather
    /// than something this library could observe: a stack is created long
    /// before the launch it belongs to is over, and only the application
    /// knows which moment its users are waiting from. Every account's
    /// measurement is cleared and taken again, so calling this twice restarts
    /// the clock rather than confusing two launches.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func stackColdStart(stack: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_stack_cold_start(stack, nowMs)
        try check(status)
    }

    /// Write an account's registration down, so a later start can carry it on
    /// instead of paying for a whole handshake.
    ///
    /// `out_len` receives how many bytes it takes whether or not there was
    /// room, so a caller passing a null `buffer` and a `capacity` of zero is
    /// asking how much room to bring and gets `SIPRAL_STATUS_BUFFER_TOO_SMALL`
    /// with the answer — that is the question, not a failure. Nothing is
    /// written to a buffer too short.
    ///
    /// **The bytes are opaque, and reading them is not part of this ABI.**
    /// They carry a version, and a build reads only the layouts it was made
    /// for; an application that parses them is an application that stops
    /// working when the layout grows a field. Storing them is the
    /// application's, and so is protecting them: a snapshot is not a secret,
    /// but it names an address of record, which is a record of who uses this
    /// device.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when there is nothing worth keeping — an
    /// account that has never registered, one that never will, one whose
    /// registration failed, or one whose binding has been given up. A cold
    /// start after that is an ordinary cold start, which is what would have
    /// happened anyway.
    ///
    /// The clock is read and not moved: this writes nothing and sends
    /// nothing, so a snapshot taken on the way into suspend cannot be what
    /// stops a later `now_ms` from being accepted.
    ///
    /// Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// `capacity` of zero, and `out_len` must point at one `size_t` or be
    /// null.
    public static func accountFreeze(stack: SipralHandle, account: SipralHandle, buffer: inout [UInt8], nowMs: UInt64) throws -> Int {
        try ensureAbi()
        var len = Int()
        let status =
            buffer.withUnsafeMutableBufferPointer { p2 in
                sipral_account_freeze(stack, account, p2.baseAddress, p2.count, &len, nowMs)
            }
        try check(status)
        return len
    }

    /// Read one back, on an account that has been added and has not
    /// registered.
    ///
    /// `asleep_ms` is how long the snapshot sat unused, and it is the
    /// caller's to supply because nothing here reads a wall clock and a
    /// monotonic instant does not survive the process that minted it. The
    /// application is the only one that knows whether this is a wake from
    /// suspend or a cold launch a week later. What is left of the binding's
    /// life is what was left when it was written down, less that.
    ///
    /// The account comes up in
    /// SIPRAL_REGISTRATION_STATE_RESTORED
    /// rather than registered: a binding nobody has confirmed since the
    /// machine slept is a belief, not evidence, and the refresh this books is
    /// what turns one into the other.
    ///
    /// Refused, with the account left exactly as it was:
    /// `SIPRAL_STATUS_UNSUPPORTED_VERSION` for bytes a newer build wrote,
    /// `SIPRAL_STATUS_NOT_SUPPORTED` for an account that does not register at
    /// all, and `SIPRAL_STATUS_INVALID_ARGUMENT` for bytes that are not a
    /// snapshot, are damaged, or are another account's — an address of record
    /// that is not this account's is the one mix-up that would otherwise send
    /// a REGISTER for somebody else.
    ///
    /// Safety
    ///
    /// `snapshot` must be readable for `snapshot_len` bytes.
    public static func accountThaw(stack: SipralHandle, account: SipralHandle, snapshot: [UInt8], asleepMs: UInt64, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            snapshot.withUnsafeBufferPointer { p2 in
                sipral_account_thaw(stack, account, p2.baseAddress, p2.count, asleepMs, nowMs)
            }
        try check(status)
    }

    /// How long this account took to become reachable, measured from
    /// sipral_stack_cold_start.
    ///
    /// The number a queue needs: how long it rings each agent before giving
    /// up and trying the next one has to be longer than this, or a phone that
    /// was asleep is skipped every time and its owner is told the queue was
    /// quiet.
    ///
    /// `out_has_value` is zero, and `out_ms` zero with it, until there is an
    /// answer — before the account has registered, for an account that never
    /// registers, and always when no cold start was ever declared, because
    /// nothing marks the moment those became reachable. Zero milliseconds
    /// with `out_has_value` set is a real answer and a different one.
    ///
    /// Safety
    ///
    /// `out_has_value` must point at one `uint32_t` and `out_ms` at one
    /// `uint64_t`.
    public static func accountTimeToReady(stack: SipralHandle, account: SipralHandle) throws -> (hasValue: UInt32, ms: UInt64) {
        try ensureAbi()
        var hasValue = UInt32()
        var ms = UInt64()
        let status = sipral_account_time_to_ready(stack, account, &hasValue, &ms)
        try check(status)
        return (hasValue: hasValue, ms: ms)
    }

    /// Say where a dialog's next hop actually is.
    ///
    /// The answer to
    /// SIPRAL_EVENT_KIND_RESOLVE_NEEDED,
    /// with `dialog` the handle that event carried. `addresses` is
    /// comma-separated `host:port`, **in RFC 3263 §4.3 priority order**: the
    /// first one this stack already has an open transport of the wanted
    /// protocol for is taken, and the ones after it are kept for this stack
    /// to try in turn if that one goes on to fail. A list is therefore not a
    /// convenience — it is what makes failover possible at all, and one
    /// address is a list of one that cannot fail over.
    ///
    /// `protocol` is a SipralTransport when
    /// the lookup named one, which a NAPTR or SRV answer does, and zero when
    /// it did not — an A lookup with nothing above it — in which case the flow
    /// keeps speaking whatever it already spoke. It is looked for, never
    /// opened: nothing here owns a socket, so a protocol nothing has bound is
    /// not something this can invent. An address on one is passed over, and
    /// answering again after
    /// sipral_stack_transport_bind
    /// is how it gets another chance.
    ///
    /// `SIPRAL_STATUS_OK` with nothing changed is the honest answer in two
    /// cases, and neither is an error: the dialog has ended, and none of the
    /// addresses is one this stack can reach on the protocol asked for. The
    /// flow stands exactly as it did.
    ///
    /// There is no `now_ms` here on purpose. Every other call that changes
    /// what this stack will send takes the time because something it does is
    /// timed; this one only writes an address down.
    ///
    /// Safety
    ///
    /// `addresses` must be readable for `addresses_len` bytes.
    public static func stackResolved(stack: SipralHandle, dialog: SipralHandle, addresses: String, `protocol`: UInt32) throws {
        try ensureAbi()
        let status =
            Array(addresses.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    sipral_stack_resolved(stack, dialog, p2.baseAddress, p2.count, `protocol`)
                }
            }
        try check(status)
    }

    /// Point an account's registration at another address.
    ///
    /// For a registrar named by a record with more than one target, and for
    /// the one after it when the first stops answering. The binding's
    /// `Call-ID`, its sequence number and its credentials are all kept, so
    /// the next REGISTER reads to the registrar as the same device
    /// continuing, not as a second one arriving — which is the whole of the
    /// saving and the reason this is not "remove the account and add it
    /// again".
    ///
    /// A REGISTER already in flight or already booked for this account is
    /// superseded at once rather than waited out. Retargeting to the address
    /// an account is already using is `SIPRAL_STATUS_OK` and sends nothing.
    ///
    /// `registrar_address` is `host:port`, not a name: resolving one is the
    /// application's, here as everywhere else in this module.
    /// `SIPRAL_STATUS_NOT_SUPPORTED` for an account with no registrar — a
    /// trunk authenticated by address has nothing to retarget, and
    /// `sipral_account_config_t::registrar_address` is where its outbound
    /// proxy is set.
    ///
    /// Safety
    ///
    /// `registrar_address` must be readable for `registrar_address_len`
    /// bytes.
    public static func accountRetarget(stack: SipralHandle, account: SipralHandle, registrarAddress: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(registrarAddress.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    sipral_account_retarget(stack, account, p2.baseAddress, p2.count, nowMs)
                }
            }
        try check(status)
    }

    /// Copy one call's diagnostic record into `buffer`, as the JSON
    /// `docs/14-diagnostics.md` describes.
    ///
    /// Readable at any point in the call's life, and for as long after it as
    /// the endpoint has not evicted the record to make room for a newer one —
    /// `sipral_stack_config_t` has no member for the ceiling yet, so today
    /// that is sipral_core::diag::RecordLimits::DEFAULT. A call whose
    /// record has been evicted, or that has had nothing decided about it yet,
    /// answers `SIPRAL_STATUS_OK` with `{}`: an empty record is still a
    /// record, and refusing to read one that happens to be empty would make
    /// a caller unable to tell "nothing yet" from "something went wrong".
    ///
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
    /// document, with the length needed in `out_len`.
    ///
    /// Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_len` must point at one `size_t` or be null.
    public static func callRecordJson(stack: SipralHandle, call: SipralHandle, buffer: inout [CChar]) throws -> Int {
        try ensureAbi()
        var len = Int()
        let status =
            buffer.withUnsafeMutableBufferPointer { p2 in
                sipral_call_record_json(stack, call, p2.baseAddress, p2.count, &len)
            }
        try check(status)
        return len
    }

    /// Copy the whole diagnostic document into `buffer`: what a bug report
    /// carries, as the JSON `docs/14-diagnostics.md` describes.
    ///
    /// That is the endpoint's own record — everything decided outside any
    /// call — and then one record per call still held, in the same document,
    /// with the number of records evicted to make room. It is deliberately
    /// the whole of it rather than the endpoint's half: a report that arrives
    /// without the calls it is about answers nothing, and
    /// sipral_call_record_json is already the way to ask about one call.
    ///
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
    /// document, with the length needed in `out_len`.
    ///
    /// Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_len` must point at one `size_t` or be null.
    public static func stackDiagnosticsJson(stack: SipralHandle, buffer: inout [CChar]) throws -> Int {
        try ensureAbi()
        var len = Int()
        let status =
            buffer.withUnsafeMutableBufferPointer { p1 in
                sipral_stack_diagnostics_json(stack, p1.baseAddress, p1.count, &len)
            }
        try check(status)
        return len
    }

    /// Start recording the signalling this stack is fed from here on
    /// (`docs/18-replay.md`), with the same seed `sipral_stack_create` built
    /// it with. Read crate::diagnostics before reaching for this: what it
    /// records and what it deliberately never does is written down there
    /// once rather than repeated at each of these three entry points.
    ///
    /// `note` is one line of prose for whoever opens the file later, or null
    /// for none.
    ///
    /// A recording already running is replaced, not refused: see
    /// crate::diagnostics for why that is the right answer here and the
    /// wrong one for `sipral_media_record_start`.
    ///
    /// Safety
    ///
    /// `note` must be readable for `note_len` bytes or be null with a length
    /// of zero.
    public static func stackRecordingStart(stack: SipralHandle, note: String) throws {
        try ensureAbi()
        let status =
            Array(note.utf8).withUnsafeBufferPointer { raw1 in
                raw1.withMemoryRebound(to: CChar.self) { p1 in
                    sipral_stack_recording_start(stack, p1.baseAddress, p1.count)
                }
            }
        try check(status)
    }

    /// Stop the recording sipral_stack_recording_start began, and copy
    /// the text of it into `buffer` (`docs/18-replay.md`).
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when no recording is running, the same
    /// answer `sipral_media_record_stop` gives for the same question about
    /// an audio recording. `SIPRAL_STATUS_WRONG_STATE` again, with the reason
    /// in the last error, when something this session was fed could not go
    /// in the recording — a message with a body that is not text is the one
    /// way that happens — in which case nothing is written to `buffer` and
    /// the recording is not produced at all: a text format that quietly left
    /// out the one message it could not spell would replay into a different
    /// session and say nothing about it.
    ///
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
    /// text, with the length needed in `out_len` — asking again with a bigger
    /// buffer answers the same recording rather than stopping a new one,
    /// so a caller that does not yet know how big a buffer to bring may ask
    /// twice: once to be told, once to be handed the text. Once a call here
    /// copies the whole of it out, the recording is gone from the stack, the
    /// same as `sipral_last_error_message` empties the slot it reads on a
    /// call that succeeds.
    ///
    /// Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_len` must point at one `size_t` or be null.
    public static func stackRecordingStop(stack: SipralHandle, buffer: inout [CChar]) throws -> Int {
        try ensureAbi()
        var len = Int()
        let status =
            buffer.withUnsafeMutableBufferPointer { p1 in
                sipral_stack_recording_stop(stack, p1.baseAddress, p1.count, &len)
            }
        try check(status)
        return len
    }

}
