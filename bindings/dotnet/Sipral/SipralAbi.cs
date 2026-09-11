// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// Printed from the declarations in crates/sipral-ffi by tools/abi-gen.
// Do not edit: `cargo run -p sipral-abi-gen` writes it again, and
// `scripts/check.sh` fails when what is committed is not what came out.

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Sipral;

/// <summary>
/// The result of a call across the C ABI.
///
/// The numbers are part of the ABI. A value keeps its meaning for the life of
/// the ABI's major version, and a new one is only ever added at the end.
/// </summary>
public enum SipralStatus : int
{
    /// <summary>
    /// The call did what it was asked to.
    /// </summary>
    Ok = 0,
    /// <summary>
    /// A pointer was null where one is required, a length disagreed with what
    /// it describes, or a value was outside what the call accepts.
    /// </summary>
    InvalidArgument = 1,
    /// <summary>
    /// The handle never came from this library.
    /// </summary>
    InvalidHandle = 2,
    /// <summary>
    /// The handle came from this library and what it named is gone: a use
    /// after free, or a second free.
    /// </summary>
    StaleHandle = 3,
    /// <summary>
    /// A versioned struct declared a size this build cannot work with, or a
    /// binding asked for an ABI this library does not provide.
    /// </summary>
    UnsupportedVersion = 4,
    /// <summary>
    /// The buffer supplied is too small. The length needed has been written to
    /// the out parameter, and nothing was written to the buffer.
    /// </summary>
    BufferTooSmall = 5,
    /// <summary>
    /// The object is already in use by another call, including one further
    /// down the same call stack. Nothing was done, and nothing blocked.
    /// </summary>
    Busy = 6,
    /// <summary>
    /// The library has no room for another object of this kind.
    /// </summary>
    Exhausted = 7,
    /// <summary>
    /// A panic was caught at the boundary. The call did not finish, and the
    /// last error carries whatever the panic said.
    /// </summary>
    Panic = 8,
    /// <summary>
    /// What was asked for cannot be done where the object is: answering a call
    /// this end placed, holding one that is not up, sending DTMF before there
    /// is a dialog to send it in. Not an argument that was wrong; a moment
    /// that was.
    /// </summary>
    WrongState = 9,
    /// <summary>
    /// The request could not be assembled or handed to a transport. Nothing
    /// went out, and nothing about the call changed.
    /// </summary>
    NotSent = 10,
    /// <summary>
    /// The value is one this ABI has a word for and this build has no code
    /// behind. Nothing was applied, and asking again will not change that.
    ///
    /// The third of the three answers a configuration call may give, and the
    /// one that has to be told apart from the other two by a machine.
    /// SipralStatus.InvalidArgument says the value is wrong and a
    /// corrected one would be taken; this says the value is right and there is
    /// nothing here to take it. SipralStatus.UnsupportedVersion is about
    /// the shape of what crossed the boundary, not about what was set in it.
    ///
    /// It exists so that "accepted and ignored" is not a thing this library
    /// can do. An application that gets it turns the control off, because the
    /// control is genuinely dead in this build; one that gets a silence
    /// instead ships a control that does nothing and finds out from a
    /// customer.
    /// </summary>
    NotSupported = 11,
}

/// <summary>
/// What a stack speaks. Names for `sipral_stack_config_t::transport`.
///
/// Zero is not one of them: a stack is told what it is speaking, because
/// guessing wrong in the direction of the plainest transport is how a caller
/// that meant TLS ends up on the wire in the clear.
/// </summary>
public enum SipralTransport : uint
{
    /// <summary>
    /// UDP.
    /// </summary>
    Udp = 1,
    /// <summary>
    /// TCP.
    /// </summary>
    Tcp = 2,
    /// <summary>
    /// TLS over TCP.
    /// </summary>
    Tls = 3,
    /// <summary>
    /// WebSocket.
    /// </summary>
    Ws = 4,
    /// <summary>
    /// WebSocket over TLS.
    /// </summary>
    Wss = 5,
}

/// <summary>
/// Why a transport could not deliver. Names for
/// sipral_stack_transport_failed's `error`.
///
/// Coarse on purpose, and it is the layer below that is coarse: a client
/// transaction informs its user and terminates on every one of these (§17), and
/// the detail belongs in the caller's log, where the real message still is.
/// </summary>
public enum SipralTransportError : uint
{
    /// <summary>
    /// Anything the caller could not classify. Zero, because a caller that
    /// knows only that the write failed is telling the truth by saying nothing.
    /// </summary>
    Other = 0,
    /// <summary>
    /// Nothing is listening at the far end.
    /// </summary>
    ConnectionRefused = 1,
    /// <summary>
    /// An established connection was reset.
    /// </summary>
    ConnectionReset = 2,
    /// <summary>
    /// No route, or an ICMP unreachable.
    /// </summary>
    Unreachable = 3,
    /// <summary>
    /// The connection attempt or the write timed out.
    /// </summary>
    TimedOut = 4,
    /// <summary>
    /// The connection was closed and cannot be written to again.
    /// </summary>
    Closed = 5,
}

/// <summary>
/// The three answers a setting can give in a struct that starts out zeroed.
///
/// A boolean cannot carry them. Zero is what a caller who filled nothing in
/// leaves behind, so a plain `0`/`1` setting has no way to say "off" that is
/// not also "I said nothing", and the difference is the whole of B2: the
/// library must not turn a control off because the caller never touched it.
/// </summary>
public enum SipralToggle : uint
{
    /// <summary>
    /// Nothing was said; whatever this build defaults to.
    /// </summary>
    Default = 0,
    /// <summary>
    /// On.
    /// </summary>
    On = 1,
    /// <summary>
    /// Off.
    /// </summary>
    Off = 2,
}

/// <summary>
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
/// </summary>
public enum SipralCodec : uint
{
    /// <summary>
    /// No codec: the call has none, or the event is not about one.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// G.711 mu-law, payload type 0.
    /// </summary>
    Pcmu = 1,
    /// <summary>
    /// G.711 A-law, payload type 8.
    /// </summary>
    Pcma = 2,
    /// <summary>
    /// G.722, wideband at the price of a narrowband stream.
    /// </summary>
    G722 = 3,
    /// <summary>
    /// Opus. Declared in every build, whether or not this one linked
    /// libopus, for the reason the enumeration above gives. Whether the
    /// codec is here is `SIPRAL_FEATURE_OPUS` and the list
    /// `sipral_codec_at` enumerates, never the presence of this name.
    /// </summary>
    Opus = 4,
}

/// <summary>
/// Which way audio may flow, as seen from here. Names for every `direction`.
/// </summary>
public enum SipralDirection : uint
{
    /// <summary>
    /// Not negotiated.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// Both ways.
    /// </summary>
    SendRecv = 1,
    /// <summary>
    /// This end sends and does not receive, which is what holding the far end
    /// looks like from here.
    /// </summary>
    SendOnly = 2,
    /// <summary>
    /// This end receives and does not send.
    /// </summary>
    RecvOnly = 3,
    /// <summary>
    /// Neither way, and the stream stays in the session.
    /// </summary>
    Inactive = 4,
}

/// <summary>
/// Where control traffic goes. Names for SipralMediaInfo.Rtcp.
/// </summary>
public enum SipralRtcp : uint
{
    /// <summary>
    /// Not negotiated.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// One port carries both (RFC 5761), which happens only where both ends
    /// asked for it.
    /// </summary>
    Muxed = 1,
    /// <summary>
    /// A port of its own at each end.
    /// </summary>
    SeparatePort = 2,
    /// <summary>
    /// None at all: the peer said it is not using RTCP.
    /// </summary>
    Off = 3,
}

/// <summary>
/// Why media failed. Names for `sipral_media_event_t::fault`.
///
/// The sentence beside it says which case of the kind it was; this is the part
/// a machine acts on, and the two are never the same thing.
/// </summary>
public enum SipralMediaFault : uint
{
    /// <summary>
    /// Nothing failed.
    /// </summary>
    None = 0,
    /// <summary>
    /// The negotiation settled on something this build cannot encode or
    /// decode, which means the peer answered with a format that was not in the
    /// offer.
    /// </summary>
    UnsupportedCodec = 1,
    /// <summary>
    /// The two descriptions agree on nothing that can carry audio.
    /// </summary>
    NoCommonCodec = 2,
    /// <summary>
    /// One end refused the stream with a port of zero. The call is up and
    /// carries no audio, which is a thing a peer is allowed to want.
    /// </summary>
    StreamRefused = 3,
    /// <summary>
    /// There is no session description to work from.
    /// </summary>
    NoDescription = 4,
    /// <summary>
    /// A description could not be read.
    /// </summary>
    BadDescription = 5,
    /// <summary>
    /// The recording stopped writing: the disk filled, the file went away.
    /// </summary>
    Recording = 6,
    /// <summary>
    /// The codec refused a frame.
    /// </summary>
    Codec = 7,
    /// <summary>
    /// Something else the layer below reported and this ABI has no word for.
    /// </summary>
    Other = 8,
}

/// <summary>
/// What a datagram handed to sipral_call_media_receive turned out to be.
/// </summary>
public enum SipralArrival : uint
{
    /// <summary>
    /// Something this ABI has no word for.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// Audio, held for playout.
    /// </summary>
    Queued = 1,
    /// <summary>
    /// Audio that was not used: malformed, late, duplicated, from the wrong
    /// address, or on a payload type nobody negotiated. The counters in
    /// SipralStreamStats say which, over the call.
    /// </summary>
    Dropped = 2,
    /// <summary>
    /// A reception or sender report, folded into the statistics.
    /// </summary>
    Control = 3,
    /// <summary>
    /// The far end says it is leaving the session (RFC 3550 §6.6). Audio will
    /// stop; the call has not ended until signalling says so.
    /// </summary>
    Goodbye = 4,
    /// <summary>
    /// Control traffic that was not believed: from the wrong address, or not a
    /// well-formed compound packet.
    /// </summary>
    ControlRefused = 5,
}

/// <summary>
/// Where the frame sipral_call_playback just produced came from.
/// </summary>
public enum SipralPlayback : uint
{
    /// <summary>
    /// Something this ABI has no word for.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// A packet the far end sent.
    /// </summary>
    Packet = 1,
    /// <summary>
    /// One it sent and this end did not get, filled in by the concealment.
    /// </summary>
    Concealed = 2,
    /// <summary>
    /// Comfort noise, from an RFC 3389 payload the far end sent instead of
    /// audio.
    /// </summary>
    ComfortNoise = 3,
    /// <summary>
    /// Nothing was due: the buffer is still filling, or the far end has
    /// stopped.
    /// </summary>
    Silence = 4,
}

/// <summary>
/// Which way a digit goes to the far end. Names for
/// sipral_call_send_dtmf's `via`.
///
/// The choice is per send, not per call, because it is a fact about the peer
/// rather than about this end, and the way to find out which one a peer takes
/// is to try. A carrier that ignores one of these ignores it silently.
/// </summary>
public enum SipralDtmf : uint
{
    /// <summary>
    /// In the media, as an RFC 4733 named telephone event. What to reach for:
    /// it is the only one carried end to end by every gateway on the path, and
    /// the only one whose timing survives transcoding.
    /// </summary>
    Rtp = 0,
    /// <summary>
    /// An INFO per digit carrying `application/dtmf-relay`, which states the
    /// signal and how long it was held.
    /// </summary>
    InfoRelay = 1,
    /// <summary>
    /// An INFO per digit carrying `application/dtmf`, whose whole body is the
    /// character. Some switches take only this one.
    /// </summary>
    InfoPlain = 2,
}

/// <summary>
/// What an event is about.
///
/// The numbers are part of the ABI and are only ever added to. A binding
/// that meets a kind it does not know must ignore that event rather than
/// refuse it, which is what makes adding one safe.
/// Numbers already spent on features this build does not have:
/// - 15: a subscription's state changed (A1)
/// - 16: the set of audio devices changed (A2)
/// - 18: a request was promoted to a stream transport (B1)
/// - 20: a call was announced and never arrived (C2)
/// </summary>
public enum SipralEventKind : uint
{
    /// <summary>
    /// The stack is running on this thread.
    ///
    /// The first event on every stack, delivered by the first poll and never
    /// again. A binding that has a callback to hand out, a queue to open or a
    /// thread to name has somewhere definite to do it, before anything that
    /// matters can arrive.
    /// </summary>
    Started = 1,
    /// <summary>
    /// A registration moved: it went out, it took, it is being refreshed, it
    /// was given up, or it failed. `payload.registration` says which, and
    /// `account` says whose.
    /// </summary>
    RegistrationChanged = 2,
    /// <summary>
    /// Somebody is calling. Answer, ring, or reject it.
    /// </summary>
    IncomingCall = 3,
    /// <summary>
    /// A call this end placed is getting somewhere short of an answer.
    /// </summary>
    CallProgress = 4,
    /// <summary>
    /// A proxy forked the INVITE and a second phone is ringing.
    /// `payload.call.other` is the branch that has just appeared.
    /// </summary>
    CallForked = 5,
    /// <summary>
    /// The call is up.
    /// </summary>
    CallConfirmed = 6,
    /// <summary>
    /// The session inside a live call changed: a hold, a resume, or an offer
    /// either end made and had accepted.
    /// </summary>
    SessionChanged = 7,
    /// <summary>
    /// The far end offered a change this stack has no policy for. The
    /// transaction is held open: answer it or refuse it, or the call ends.
    /// </summary>
    SessionOffered = 8,
    /// <summary>
    /// A change this end offered was refused. The session stands as it was.
    /// </summary>
    SessionChangeFailed = 9,
    /// <summary>
    /// The far end asked this one to call somebody else.
    /// </summary>
    TransferRequested = 10,
    /// <summary>
    /// A transfer this end asked for is under way.
    /// </summary>
    TransferProgress = 11,
    /// <summary>
    /// And how it ended.
    /// </summary>
    TransferDone = 12,
    /// <summary>
    /// A call arrived carrying a `Replaces` and took over one already up.
    /// `payload.call.other` is the one being replaced.
    /// </summary>
    CallReplaced = 13,
    /// <summary>
    /// The call is over, and its handle is stale from here on.
    /// </summary>
    CallEnded = 14,
    /// <summary>
    /// What one call's media cost, delivered once, after
    /// `SIPRAL_EVENT_KIND_CALL_ENDED`.
    ///
    /// A6's second consumer. `payload.media.statistics` points at the
    /// completed record; it is the library's and lives as long as the callback
    /// does. The stream is gone by the time this arrives, which is why the
    /// numbers travel in the event rather than behind a lookup that would now
    /// fail.
    /// </summary>
    MediaStatistics = 17,
    /// <summary>
    /// Nothing has arrived on the media path for longer than the configured
    /// threshold, while signalling is perfectly happy.
    ///
    /// B5. `payload.media.silent_for_ms` says how long. The call is untouched:
    /// whether to hang up over silence is a decision with a person on the other
    /// end of it.
    /// </summary>
    MediaStalled = 19,
    /// <summary>
    /// Audio is running: the negotiation settled and an RTP session is open.
    ///
    /// A4's reporting half and the first half of D5: `payload.media.codec` is
    /// what the two ends agreed on, and `sipral_call_media_info` says the rest.
    /// </summary>
    MediaStarted = 21,
    /// <summary>
    /// The session changed under a live call: a hold, a resume, a peer that
    /// moved its media address, or a re-negotiation onto another codec.
    /// </summary>
    MediaChanged = 22,
    /// <summary>
    /// Packets are arriving again. `payload.media.silent_for_ms` says how long
    /// the gap turned out to be.
    /// </summary>
    MediaResumed = 23,
    /// <summary>
    /// Media could not be started or could not be kept. The call itself is
    /// untouched; `payload.media.fault` and `payload.media.reason` say why.
    /// </summary>
    MediaFailed = 24,
    /// <summary>
    /// A recording stopped on its own, part-way through: the disk filled, the
    /// file went away, the volume was unmounted.
    ///
    /// Never an abort. `payload.media.recorded_ms` says how much audio reached
    /// the file before it stopped, and the call carries on without it.
    /// </summary>
    RecordingStopped = 25,
    /// <summary>
    /// The far end pressed a key (RFC 4733).
    ///
    /// One per keypress, not one per packet: a digit goes out as a run of
    /// updates and then its closing packet three times, and the layer below
    /// collapses them on the timestamp that identifies the event.
    /// `payload.media.digit` is the character, `event_code` the number behind
    /// it for the events no keypad has a key for, and `held_ms` how long it
    /// lasted.
    /// </summary>
    DigitReceived = 26,
}

/// <summary>
/// Where a registration is. Names for `sipral_registration_event_t::state`.
/// </summary>
public enum SipralRegistrationState : uint
{
    /// <summary>
    /// The account is gone, or has never been asked about.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// Configured and not registered. Nothing has been sent.
    /// </summary>
    Idle = 1,
    /// <summary>
    /// A REGISTER is in flight and there is no binding yet.
    /// </summary>
    Registering = 2,
    /// <summary>
    /// The registrar holds a binding.
    /// </summary>
    Registered = 3,
    /// <summary>
    /// A refresh is in flight. The binding stands until it is answered.
    /// </summary>
    Refreshing = 4,
    /// <summary>
    /// Something recoverable went wrong and the next attempt is scheduled.
    /// </summary>
    Retrying = 5,
    /// <summary>
    /// The binding was given up on purpose.
    /// </summary>
    Unregistered = 6,
    /// <summary>
    /// The registrar refused in a way that trying again cannot fix.
    /// </summary>
    Failed = 7,
    /// <summary>
    /// A binding a registrar really granted, over a transport that has since
    /// been suspended or lost, which nothing has proved since.
    ///
    /// Not registered, because it is no longer evidence; not failed, because
    /// nothing refused it. A monotonic clock does not advance while a machine
    /// sleeps, so a stack that slept eight hours comes back believing eight
    /// milliseconds passed and every binding still valid — this is the state
    /// that says otherwise, and an application that shows a line as ready on
    /// the strength of it will show it ready when it is not.
    /// </summary>
    Unverified = 8,
    /// <summary>
    /// A binding read back from a snapshot rather than granted in this
    /// process. It has not been proved either.
    /// </summary>
    Restored = 9,
}

/// <summary>
/// Why a registration is not live. Names for
/// `sipral_registration_event_t::failure`.
/// </summary>
public enum SipralRegistrationFailure : uint
{
    /// <summary>
    /// Nothing failed.
    /// </summary>
    None = 0,
    /// <summary>
    /// The registrar refused, and will refuse the same request again.
    /// </summary>
    Rejected = 1,
    /// <summary>
    /// The password was wrong, or there was none to answer with.
    /// </summary>
    BadCredentials = 2,
    /// <summary>
    /// The registrar is not answering, or says it cannot serve this now.
    /// </summary>
    Unreachable = 3,
    /// <summary>
    /// The registrar moved. Following it needs an address, which is the
    /// caller's to resolve.
    /// </summary>
    Redirected = 4,
}

/// <summary>
/// Where a call is. Names for `sipral_call_event_t::state`, and what
/// `sipral_call_state` writes.
/// </summary>
public enum SipralCallState : uint
{
    /// <summary>
    /// The call is gone, or has never been asked about.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// The INVITE has gone and nothing has come back.
    /// </summary>
    Calling = 1,
    /// <summary>
    /// Somebody is calling and this end has not answered.
    /// </summary>
    Incoming = 2,
    /// <summary>
    /// The far end is ringing, or this end said it is.
    /// </summary>
    Ringing = 3,
    /// <summary>
    /// There is audio before anybody answered.
    /// </summary>
    EarlyMedia = 4,
    /// <summary>
    /// Up.
    /// </summary>
    Confirmed = 5,
    /// <summary>
    /// Up, in order to be transferred: the second leg of an attended transfer.
    /// </summary>
    Consulting = 6,
    /// <summary>
    /// A CANCEL or a BYE has gone and is not answered yet.
    /// </summary>
    Terminating = 7,
    /// <summary>
    /// Over.
    /// </summary>
    Terminated = 8,
}

/// <summary>
/// Why a call is over. Names for `sipral_call_event_t::end_reason`.
/// </summary>
public enum SipralCallEndReason : uint
{
    /// <summary>
    /// The call is not over.
    /// </summary>
    None = 0,
    /// <summary>
    /// This end hung up.
    /// </summary>
    LocalHangup = 1,
    /// <summary>
    /// The far end hung up.
    /// </summary>
    RemoteHangup = 2,
    /// <summary>
    /// The far end refused it: busy, declined, not found.
    /// </summary>
    Refused = 3,
    /// <summary>
    /// Given up before it was answered, from either end.
    /// </summary>
    Cancelled = 4,
    /// <summary>
    /// Nothing came back, or the transport died.
    /// </summary>
    Unreachable = 5,
    /// <summary>
    /// Another branch of the same fork was kept and this one was not.
    /// </summary>
    ForkLost = 6,
    /// <summary>
    /// The branch was still ringing when the answer window closed.
    /// </summary>
    Abandoned = 7,
    /// <summary>
    /// The session timer ran out and no refresh arrived.
    /// </summary>
    Expired = 8,
}

/// <summary>
/// The one callback a stack has.
///
/// It is called from inside `sipral_stack_poll`, on the thread that called
/// it, with the `user_data` the stack was created with. It must not
/// unwind, and it must not call back into the stack it was given: see
/// crate::stack.
///
/// Hand it over as a function pointer: keep the delegate alive for as
/// long as the stack is, and pass Marshal.GetFunctionPointerForDelegate.
/// </summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void SipralEventCallback(IntPtr @event, IntPtr userData);

/// <summary>
/// The version of the ABI this library provides.
///
/// Set `size` to `sizeof(sipral_abi_version_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralAbiVersion
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Nothing built against another major version will work.
    /// </summary>
    public uint Major;
    /// <summary>
    /// A build with a higher minor has everything a lower one had.
    /// </summary>
    public uint Minor;
    /// <summary>
    /// A fix that changed no declaration.
    /// </summary>
    public uint Patch;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralAbiVersion Sized()
    {
        var value = default(SipralAbiVersion);
        value.Size = (nuint)Marshal.SizeOf<SipralAbiVersion>();
        return value;
    }
}

/// <summary>
/// What this build of the library can do: codecs compiled in, transports
/// this ABI carries signalling over, and which optional features are
/// present.
///
/// Nothing here is configuration — this answers "can this build ever do X",
/// never "is X turned on for this stack". `sipral_stack_settings` answers
/// that once a stack exists, and `sipral_codec_count` /
/// `sipral_stack_codec_order` already enumerate the codecs this reports only
/// the count of, so this does not repeat what they say.
///
/// Set `size` to `sizeof(sipral_capabilities_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralCapabilities
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// How many codecs this build contains. `sipral_codec_count` gives the
    /// same number; `sipral_codec_at` says which, and in what order they are
    /// offered by default.
    /// </summary>
    public nuint CodecCount;
    /// <summary>
    /// Which transports this build carries signalling over, as the bits
    /// named `SIPRAL_TRANSPORT_BIT_*`.
    /// </summary>
    public uint Transports;
    /// <summary>
    /// Which optional features this build has compiled in, as the bits named
    /// `SIPRAL_FEATURE_*`.
    /// </summary>
    public uint Features;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralCapabilities Sized()
    {
        var value = default(SipralCapabilities);
        value.Size = (nuint)Marshal.SizeOf<SipralCapabilities>();
        return value;
    }
}

/// <summary>
/// D3's flat set of health counters for one stack, since it was created.
///
/// Every member here is monotonic except `active_calls`, which is a gauge:
/// it can be read as smaller than an earlier reading, and none of the others
/// ever will be. Set `size` to `sizeof(sipral_counters_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralCounters
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// A REGISTER went out, counted once per attempt including a retry.
    /// </summary>
    public ulong RegistrationsAttempted;
    /// <summary>
    /// The registrar granted a binding.
    /// </summary>
    public ulong RegistrationsSucceeded;
    /// <summary>
    /// The registrar refused, and will refuse the same request again.
    /// </summary>
    public ulong RegistrationsFailedRejected;
    /// <summary>
    /// The password was wrong, or there was none to answer a challenge with.
    /// </summary>
    public ulong RegistrationsFailedBadCredentials;
    /// <summary>
    /// The registrar did not answer, or said it could not serve this now.
    /// </summary>
    public ulong RegistrationsFailedUnreachable;
    /// <summary>
    /// The registrar moved.
    /// </summary>
    public ulong RegistrationsFailedRedirected;
    /// <summary>
    /// This end hung up.
    /// </summary>
    public ulong CallsEndedLocalHangup;
    /// <summary>
    /// The far end hung up.
    /// </summary>
    public ulong CallsEndedRemoteHangup;
    /// <summary>
    /// The far end refused it: busy, declined, not found.
    /// </summary>
    public ulong CallsEndedRefused;
    /// <summary>
    /// Given up before it was answered, from either end.
    /// </summary>
    public ulong CallsEndedCancelled;
    /// <summary>
    /// Nothing came back, or the transport died.
    /// </summary>
    public ulong CallsEndedUnreachable;
    /// <summary>
    /// Another branch of the same fork was kept and this one was not.
    /// </summary>
    public ulong CallsEndedForkLost;
    /// <summary>
    /// The branch was still ringing when the answer window closed.
    /// </summary>
    public ulong CallsEndedAbandoned;
    /// <summary>
    /// The session timer ran out and no refresh arrived.
    /// </summary>
    public ulong CallsEndedExpired;
    /// <summary>
    /// How many times inbound audio stopped for longer than the configured
    /// threshold while signalling stayed healthy (B5).
    /// </summary>
    public ulong MediaGaps;
    /// <summary>
    /// How many times a call's jitter buffer had to shrink or stretch the
    /// stream to keep its delay where it was aiming.
    /// </summary>
    public ulong JitterBufferEvents;
    /// <summary>
    /// How many times a request would not fit a datagram and there was no
    /// stream to the destination to put it on, so the stack asked for one
    /// (RFC 3261 §18.1.1, B1).
    ///
    /// A request promoted onto a connection that already existed does not
    /// raise it; those are in the diagnostic record instead.
    /// </summary>
    public ulong StreamTransportWanted;
    /// <summary>
    /// Calls with media running right now. The one gauge in this struct: it
    /// moves both ways, and it is what every other member here is not.
    /// </summary>
    public ulong ActiveCalls;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralCounters Sized()
    {
        var value = default(SipralCounters);
        value.Size = (nuint)Marshal.SizeOf<SipralCounters>();
        return value;
    }
}

/// <summary>
/// What a stack is created with.
///
/// Set `size` to `sizeof(sipral_stack_config_t)` and zero the rest before
/// filling anything in. Four members have to be filled: the callback, the
/// transport, the address this end is reachable at, and the entropy. Nothing
/// here can be guessed on the caller's behalf.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralStackConfig
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Where events go. Required: a stack with nowhere to report to is a
    /// stack whose failures are invisible.
    /// </summary>
    public IntPtr EventCallback;
    /// <summary>
    /// Handed back to the callback untouched. The library never reads it.
    /// </summary>
    public IntPtr EventUserData;
    /// <summary>
    /// A SipralTransport.
    /// </summary>
    public uint Transport;
    /// <summary>
    /// The address the far end reaches this one at, as `host:port`, UTF-8 and
    /// not NUL-terminated.
    ///
    /// It goes in every `Via`, so it is the address a response has to come
    /// back to rather than whatever a wildcard socket was bound to. Nothing
    /// here opens a socket or resolves a name.
    /// </summary>
    public IntPtr BindAddress;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint BindAddressLen;
    /// <summary>
    /// What to put in `User-Agent` on every request this stack originates —
    /// REGISTER and INVITE — or null for none.
    ///
    /// Not on responses, and not on a request sent inside a dialog: those are
    /// written a layer below this one, which has no opinion about product
    /// names. The field is optional on every method — §20 Table 3 marks it `o`
    /// throughout — so a message that goes out without it is still well formed.
    /// </summary>
    public IntPtr UserAgent;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint UserAgentLen;
    /// <summary>
    /// Thirty-two bytes of entropy, from the platform's own generator.
    ///
    /// Every branch parameter, tag and `Call-ID` is derived from it, and
    /// §19.3 wants a tag unguessable — cryptographically random, not a
    /// counter or a clock. Two stacks must never be given the same bytes.
    /// </summary>
    public IntPtr Entropy;
    /// <summary>
    /// How many bytes of it. Thirty-two.
    /// </summary>
    public nuint EntropyLen;
    /// <summary>
    /// T1 in milliseconds, or zero for the 500 ms of §17.1.1.1.
    ///
    /// In force on every transport: 64·T1 is how long a transaction has to
    /// finish, whether or not anything retransmits.
    /// </summary>
    public ulong TimerT1Ms;
    /// <summary>
    /// T2 in milliseconds, or zero for four seconds.
    ///
    /// The cap on the doubling that starts at T1, and therefore only a figure
    /// on a transport that retransmits. Setting it on anything but UDP is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` rather than a value nothing reads.
    /// </summary>
    public ulong TimerT2Ms;
    /// <summary>
    /// T4 in milliseconds, or zero for five seconds.
    ///
    /// How long a message lingers in the network, which is what timers I and K
    /// wait out. Zero on a transport that delivers for us, so it is refused
    /// there the same way T2 is.
    /// </summary>
    public ulong TimerT4Ms;
    /// <summary>
    /// The codecs to offer, in the order to offer them: their names, separated
    /// by commas, as UTF-8 and not NUL-terminated. Null for everything this
    /// build contains, quality first.
    ///
    /// A4. The order is the whole of the negotiation's outcome — RFC 3264 §6.1
    /// has the peer's preference decide among what both ends list — and it is
    /// configured per site rather than fixed, because a carrier that bills by
    /// the minute wants the narrowband codec first and a company on its own
    /// network wants the wideband one.
    ///
    /// A name this build has no encoder for is `SIPRAL_STATUS_NOT_SUPPORTED`
    /// here, with the names it does have in the last error. It is never taken
    /// and ignored: a setting that is accepted and then quietly dropped is the
    /// failure neither end can see.
    /// </summary>
    public IntPtr Codecs;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint CodecsLen;
    /// <summary>
    /// How long a frame is, in milliseconds, or zero for twenty.
    ///
    /// Twenty is what every peer expects and what every codec here cuts
    /// cleanly. Opus has a fixed set of frame durations and encodes nothing
    /// else, so an interval it has no size for is refused while Opus is one of
    /// the codecs offered.
    /// </summary>
    public uint FrameMs;
    /// <summary>
    /// Whether to offer RFC 4733 named events, as a `SipralToggle`. On by
    /// default: a phone that cannot send a digit cannot navigate a menu.
    /// </summary>
    public uint OfferDtmf;
    /// <summary>
    /// Whether to ask for RFC 5761 multiplexing, as a `SipralToggle`.
    ///
    /// Off by default. §5.1.1 only permits it where both ends asked, and the
    /// equipment this stack is deployed against does not; asking unasked costs
    /// a line in every offer and buys a port on the calls where nobody answers.
    /// </summary>
    public uint OfferRtcpMux;
    /// <summary>
    /// Whether to stop sending during silence, as a `SipralToggle`.
    ///
    /// Off by default. It halves the bandwidth of a call in which one person is
    /// listening, and it costs the far end's own stall watchdog a reason to
    /// fire — this stack sends no comfort noise of its own to say the silence
    /// is deliberate, so a gap looks the same from there as a stream that died.
    /// </summary>
    public uint SilenceSuppression;
    /// <summary>
    /// Whether inbound audio that stops is reported, as a `SipralToggle`. On by
    /// default; this is B5.
    /// </summary>
    public uint MediaStallWatchdog;
    /// <summary>
    /// How long inbound audio may stop before that is reported, in
    /// milliseconds, or zero for this build's own figure.
    ///
    /// Setting it with the watchdog switched off is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` rather than a value nothing reads.
    /// </summary>
    public ulong MediaStallMs;
    /// <summary>
    /// What the wall clock read when the stack was created, as seconds since
    /// 1 January 1970, or zero.
    ///
    /// The one number a stack that reads no clock cannot work out: RFC 3550
    /// §6.4.1 has a sender report carry "the wall clock time when this report
    /// was sent", and a monotonic instant is not one. Zero means the reports
    /// count from the Unix epoch, which costs nothing a caller is likely to
    /// miss — the round trip the far end computes is a difference, not an
    /// absolute — and costs the correlation of this call's media with anything
    /// else's.
    /// </summary>
    public ulong MediaClockUnixSeconds;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralStackConfig Sized()
    {
        var value = default(SipralStackConfig);
        value.Size = (nuint)Marshal.SizeOf<SipralStackConfig>();
        return value;
    }
}

/// <summary>
/// What one call to sipral_stack_poll did.
///
/// Set `size` to `sizeof(sipral_poll_result_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralPollResult
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Events handed to the callback during this poll.
    /// </summary>
    public nuint EventsDelivered;
    /// <summary>
    /// Events the stack raised that this ABI has no word for yet.
    ///
    /// Counted rather than delivered: an event carrying nothing a binding can
    /// act on is noise, and a number that is not zero is the honest measure of
    /// how far this vocabulary is behind the stack's.
    /// </summary>
    public nuint EventsUnclaimed;
    /// <summary>
    /// Bytes the stack produced and this build had nowhere to send.
    ///
    /// Zero since crate::transport gave them somewhere to go: what the stack
    /// writes waits in it until `sipral_stack_poll_transmit` takes it, and a
    /// poll no longer empties the queue on its way past. The member stays
    /// because a released one always does, and because a build that has to drop
    /// a message again would have somewhere to say so.
    /// </summary>
    public nuint TransmitsDiscarded;
    /// <summary>
    /// Whether there is a deadline at all. Zero means nothing is scheduled and
    /// the next poll can wait for input.
    /// </summary>
    public uint HasDeadline;
    /// <summary>
    /// How long from `now_ms` until the stack has something to do, when
    /// `has_deadline` says there is one. Zero means it is already due.
    /// </summary>
    public ulong NextPollInMs;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralPollResult Sized()
    {
        var value = default(SipralPollResult);
        value.Size = (nuint)Marshal.SizeOf<SipralPollResult>();
        return value;
    }
}

/// <summary>
/// What a stack is actually running with.
///
/// A configuration call that answers `SIPRAL_STATUS_OK` has applied what it was
/// given, and this is where the caller reads back what that came to. It matters
/// because a zero in the config means "the default": a caller that left the
/// timers alone has no other way to learn which figures it is retransmitting
/// on, and one that set them has no other way to be sure.
///
/// Set `size` to `sizeof(sipral_stack_settings_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralStackSettings
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// The SipralTransport this stack speaks.
    /// </summary>
    public uint Transport;
    /// <summary>
    /// Whether this stack retransmits anything itself.
    ///
    /// Zero on a transport that delivers for us, which is every one but UDP.
    /// The two timers that only exist to pace a retransmission read as their
    /// defaults there, and mean nothing.
    /// </summary>
    public uint Retransmits;
    /// <summary>
    /// T1 in milliseconds, with the default filled in.
    /// </summary>
    public ulong TimerT1Ms;
    /// <summary>
    /// T2 in milliseconds, with the default filled in.
    /// </summary>
    public ulong TimerT2Ms;
    /// <summary>
    /// T4 in milliseconds, with the default filled in.
    /// </summary>
    public ulong TimerT4Ms;
    /// <summary>
    /// How many codecs this stack offers. `sipral_stack_codec_order` says
    /// which, and in what order.
    /// </summary>
    public nuint CodecCount;
    /// <summary>
    /// How long a frame is, with the default filled in.
    /// </summary>
    public uint FrameMs;
    /// <summary>
    /// Whether named events are offered, as a `SipralToggle`. Never the
    /// default value: this says what the setting came to, not what was passed.
    /// </summary>
    public uint OfferDtmf;
    /// <summary>
    /// Whether RTCP multiplexing is asked for, as a `SipralToggle`.
    /// </summary>
    public uint OfferRtcpMux;
    /// <summary>
    /// Whether sending stops during silence, as a `SipralToggle`.
    /// </summary>
    public uint SilenceSuppression;
    /// <summary>
    /// How long inbound audio may stop before it is reported, with the default
    /// filled in. Zero when the watchdog is off, which is the one case where
    /// there is no figure to give.
    /// </summary>
    public ulong MediaStallMs;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralStackSettings Sized()
    {
        var value = default(SipralStackSettings);
        value.Size = (nuint)Marshal.SizeOf<SipralStackSettings>();
        return value;
    }
}

/// <summary>
/// What an account is configured with.
///
/// Set `size` to `sizeof(sipral_account_config_t)` and zero the rest before
/// filling anything in.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralAccountConfig
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// The address of record, `sip:alice@example.com`. UTF-8, not
    /// NUL-terminated.
    /// </summary>
    public IntPtr Aor;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint AorLen;
    /// <summary>
    /// Where the REGISTER is addressed, `sip:example.com`, no user part.
    /// </summary>
    public IntPtr Registrar;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint RegistrarLen;
    /// <summary>
    /// Where this endpoint can be reached, as it goes in `Contact`.
    /// </summary>
    public IntPtr Contact;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ContactLen;
    /// <summary>
    /// Where the REGISTER actually goes, as `host:port`. An address, not a
    /// name: RFC 3263 resolution is the caller's.
    /// </summary>
    public IntPtr RegistrarAddress;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint RegistrarAddressLen;
    /// <summary>
    /// The display name that goes in `From`, or null for none.
    /// </summary>
    public IntPtr DisplayName;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint DisplayNameLen;
    /// <summary>
    /// The user name to answer a challenge with, or null for an account that
    /// answers none.
    /// </summary>
    public IntPtr AuthUser;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint AuthUserLen;
    /// <summary>
    /// The password that goes with it. Copied out of the caller's memory; what
    /// happens to the caller's copy is the caller's.
    /// </summary>
    public IntPtr AuthPassword;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint AuthPasswordLen;
    /// <summary>
    /// The `+sip.instance` URN of RFC 5626 §4.1, or null for none.
    /// </summary>
    public IntPtr InstanceId;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint InstanceIdLen;
    /// <summary>
    /// How long a binding to ask for, or zero for an hour.
    ///
    /// A `delta-seconds`, so §20.19 bounds it at 2³²−1 and anything above that
    /// is refused rather than sent as a number no registrar will read. What the
    /// registrar grants wins over the request either way, and the granted
    /// figure is what `sipral_registration_event_t::expires_ms` carries — that
    /// is where the effective value is read back, not here.
    /// </summary>
    public ulong ExpiresSeconds;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralAccountConfig Sized()
    {
        var value = default(SipralAccountConfig);
        value.Size = (nuint)Marshal.SizeOf<SipralAccountConfig>();
        return value;
    }
}

/// <summary>
/// What a call is placed with.
///
/// Set `size` to `sizeof(sipral_call_config_t)` and zero the rest before
/// filling anything in.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralCallConfig
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Who to call, as a URI. UTF-8, not NUL-terminated.
    /// </summary>
    public IntPtr Target;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint TargetLen;
    /// <summary>
    /// The session description to offer, for a call this stack manages no
    /// audio for.
    ///
    /// Exactly one of this and `media_address` is set. Two descriptions of one
    /// session is one too many, and neither is a call whose answer would have
    /// to be written into the ACK.
    /// </summary>
    public IntPtr Sdp;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint SdpLen;
    /// <summary>
    /// Where to send the INVITE, as `host:port`, or null to send it where the
    /// account registers — which is the outbound proxy for a registered line,
    /// and the reason a phone behind a NAT works at all.
    /// </summary>
    public IntPtr Destination;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint DestinationLen;
    /// <summary>
    /// Whether to keep every branch a proxy forks the INVITE into. Zero keeps
    /// the first that answers and hangs up the rest, which is what a telephone
    /// does.
    /// </summary>
    public uint KeepAllForks;
    /// <summary>
    /// Where this end will receive media, as `host:port`, for a call this
    /// stack describes and runs the audio of.
    ///
    /// The application owns the socket, so it is the only one that can say. Set
    /// it and the offer is written from this stack's codec order, the answer is
    /// read, and the call gets a media session that `crate::media` and
    /// `crate::record` reach. Leave it null and set `sdp` instead for a call
    /// where the application describes its own session and runs its own RTP.
    /// </summary>
    public IntPtr MediaAddress;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint MediaAddressLen;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralCallConfig Sized()
    {
        var value = default(SipralCallConfig);
        value.Size = (nuint)Marshal.SizeOf<SipralCallConfig>();
        return value;
    }
}

/// <summary>
/// One codec this build contains.
///
/// Set `size` to `sizeof(sipral_codec_info_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralCodecInfo
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// A SipralCodec.
    /// </summary>
    public uint Codec;
    /// <summary>
    /// The RTP timestamp clock, in hertz, which is what goes on the
    /// `a=rtpmap` line.
    /// </summary>
    public uint ClockRate;
    /// <summary>
    /// The rate the codec actually hears at, which is what the samples crossing
    /// this ABI are in. G.722's two differ, and RFC 3551 §4.5.2 says so.
    /// </summary>
    public uint SampleRate;
    /// <summary>
    /// The payload type RFC 3551 table 4 assigns it, when it has one.
    /// </summary>
    public uint StaticPayloadType;
    /// <summary>
    /// Whether it has one. Opus does not: it is newer than the table and
    /// always travels as a dynamic type.
    /// </summary>
    public uint HasStaticPayloadType;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralCodecInfo Sized()
    {
        var value = default(SipralCodecInfo);
        value.Size = (nuint)Marshal.SizeOf<SipralCodecInfo>();
        return value;
    }
}

/// <summary>
/// What one call's media settled on, and what it is doing now.
///
/// A4's reporting half and as much of D5 as this stack knows: the codec that
/// was agreed, the number it travels under, and the shape of the stream around
/// it. What is deliberately not here is why each other candidate lost —
/// RFC 3264 §6.1 leaves that decision with the peer, and a reason invented on
/// this side would be a reason nobody can act on.
///
/// Set `size` to `sizeof(sipral_media_info_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralMediaInfo
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// A SipralCodec: what the two ends agreed on.
    /// </summary>
    public uint Codec;
    /// <summary>
    /// The payload type on the wire. It is the offer's own number and not
    /// necessarily ours: the two ends pick their own numbers for a format
    /// with no static one, so a peer that numbers it 111 has said what we
    /// say with 96.
    /// </summary>
    public uint PayloadType;
    /// <summary>
    /// The RTP timestamp clock, in hertz.
    /// </summary>
    public uint ClockRate;
    /// <summary>
    /// The rate the samples crossing this ABI are at.
    /// </summary>
    public uint SampleRate;
    /// <summary>
    /// How long a frame is, in milliseconds.
    /// </summary>
    public uint FrameMs;
    /// <summary>
    /// Samples in one frame: exactly what sipral_call_playback fills and
    /// what sipral_call_capture wants.
    /// </summary>
    public nuint FrameSamples;
    /// <summary>
    /// A SipralDirection.
    /// </summary>
    public uint Direction;
    /// <summary>
    /// Whether this end is meant to be sending. Zero while it holds the far
    /// end, or while the far end has refused to receive.
    /// </summary>
    public uint Sending;
    /// <summary>
    /// Whether this end is meant to be receiving.
    /// </summary>
    public uint Receiving;
    /// <summary>
    /// Whether RFC 4733 named events were agreed.
    /// </summary>
    public uint HasDtmf;
    /// <summary>
    /// The payload type they travel under, when they were.
    /// </summary>
    public uint DtmfPayloadType;
    /// <summary>
    /// A SipralRtcp.
    /// </summary>
    public uint Rtcp;
    /// <summary>
    /// Whether the stream is keyed.
    /// </summary>
    public uint Secured;
    /// <summary>
    /// Whether a recording is running on this call.
    /// </summary>
    public uint Recording;
    /// <summary>
    /// How much audio it has taken.
    /// </summary>
    public ulong RecordedMs;
    /// <summary>
    /// Whether the watchdog currently considers inbound audio stopped.
    /// </summary>
    public uint Stalled;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralMediaInfo Sized()
    {
        var value = default(SipralMediaInfo);
        value.Size = (nuint)Marshal.SizeOf<SipralMediaInfo>();
        return value;
    }
}

/// <summary>
/// What one call's media has cost, and what it is costing now.
///
/// A6. Cheap enough to read at the frame rate of a user interface — everything
/// in it is already counted and nothing walks a history — and complete enough
/// to keep as the record of a call, which is the same struct delivered with
/// `SIPRAL_EVENT_KIND_MEDIA_STATISTICS` when the call ends.
///
/// The three delays are in microseconds and not milliseconds. Jitter on a
/// healthy call is a fraction of a millisecond, and a figure that reads zero
/// whenever things are going well is a figure nobody looks at twice.
///
/// Set `size` to `sizeof(sipral_stream_stats_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralStreamStats
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// A SipralCodec: what the call settled on, which is the first thing
    /// anybody looking at a bad call wants to know.
    /// </summary>
    public uint Codec;
    /// <summary>
    /// Whether a round-trip time is known. Zero until a report has come back,
    /// which on a short call may be never: the first one is deliberately
    /// delayed (RFC 3550 §6.2) and a peer that sends no RTCP never provides
    /// one.
    /// </summary>
    public uint HasRoundTrip;
    /// <summary>
    /// The round trip, from RTCP.
    /// </summary>
    public ulong RoundTripUs;
    /// <summary>
    /// Packets this end has put on the wire.
    /// </summary>
    public ulong PacketsSent;
    /// <summary>
    /// Payload octets in them, not counting headers.
    /// </summary>
    public ulong OctetsSent;
    /// <summary>
    /// Packets taken in and held for playout.
    /// </summary>
    public ulong PacketsReceived;
    /// <summary>
    /// Sequence numbers that came due with nothing in them.
    /// </summary>
    public ulong PacketsLost;
    /// <summary>
    /// Packets that arrived behind the playout point.
    /// </summary>
    public ulong PacketsLate;
    /// <summary>
    /// Packets thrown out of the window before they could be played.
    /// </summary>
    public ulong PacketsOverflowed;
    /// <summary>
    /// Packets whose sequence number was already held.
    /// </summary>
    public ulong PacketsDuplicated;
    /// <summary>
    /// Packets accepted after a higher sequence number had already arrived.
    /// </summary>
    public ulong PacketsReordered;
    /// <summary>
    /// Frames dropped in a pause to bring the delay down. Deliberate, and
    /// inaudible when the pause is real.
    /// </summary>
    public ulong FramesShrunk;
    /// <summary>
    /// Frames the concealment was asked to invent in a pause to push the delay
    /// up.
    /// </summary>
    public ulong FramesStretched;
    /// <summary>
    /// How far behind the newest packet the playout point is: the delay the
    /// far end's voice is actually suffering.
    /// </summary>
    public ulong DelayUs;
    /// <summary>
    /// What the buffer is aiming at, from the arrival times it has seen.
    /// </summary>
    public ulong TargetDelayUs;
    /// <summary>
    /// Interarrival jitter, the smoothed mean deviation of transit time
    /// (RFC 3550 §6.4.1).
    /// </summary>
    public ulong JitterUs;
    /// <summary>
    /// Frames concealed as a fraction of frames played, over the last ten
    /// seconds or so. The counters above say what the call has cost; this says
    /// whether it is bad right now.
    /// </summary>
    public float LossRate;
    /// <summary>
    /// One number for a bar on a screen: a hundred for a call with nothing
    /// wrong with it, zero for one nobody can hold. Not a mean opinion score,
    /// and deliberately not shaped like one.
    /// </summary>
    public float Score;
    /// <summary>
    /// Whether the numbers say this call is in trouble now.
    /// </summary>
    public uint Suffering;
    /// <summary>
    /// How long since a packet last arrived. A live call sits at one frame.
    /// </summary>
    public ulong SilentForMs;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralStreamStats Sized()
    {
        var value = default(SipralStreamStats);
        value.Size = (nuint)Marshal.SizeOf<SipralStreamStats>();
        return value;
    }
}

/// <summary>
/// One datagram on its way out, written into the caller's own buffers.
///
/// The caller fills in `size`, the two pointers and the two capacities; the
/// library fills in the two lengths and the bytes. A `len` of zero means there
/// was nothing to send, which on a capture is an ordinary answer: this end may
/// be holding the far end, or silence suppression may have swallowed the frame.
///
/// Both buffers are checked before anything is produced. A packet that was
/// built and then had nowhere to go would be a packet missing from a stream
/// whose timestamps had already moved past it.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralMediaPacket
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Where to write the packet. At least SIPRAL_MEDIA_PACKET_BYTES.
    /// </summary>
    public IntPtr Data;
    /// <summary>
    /// How much room `data` has.
    /// </summary>
    public nuint Capacity;
    /// <summary>
    /// How much was written. Zero means there was nothing to send.
    /// </summary>
    public nuint Len;
    /// <summary>
    /// Where to write the destination, as `host:port` with a trailing NUL. Null
    /// with a capacity of zero for a caller that does not want it.
    /// </summary>
    public IntPtr Destination;
    /// <summary>
    /// How much room `destination` has. At least SIPRAL_ADDRESS_BYTES when
    /// it is not null.
    /// </summary>
    public nuint DestinationCapacity;
    /// <summary>
    /// How many bytes of it were written, the NUL not counted.
    /// </summary>
    public nuint DestinationLen;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralMediaPacket Sized()
    {
        var value = default(SipralMediaPacket);
        value.Size = (nuint)Marshal.SizeOf<SipralMediaPacket>();
        return value;
    }
}

/// <summary>
/// One message on its way out, written into the caller's own buffers.
///
/// The caller fills in `size`, the three pointers and the three capacities; the
/// library fills in everything else. A `len` of zero means the stack had nothing
/// to send, which is how the draining loop ends.
///
/// The two address buffers are checked before a message is taken, so the address
/// side is never the reason one is held. The payload buffer is not: a message
/// too long for it is kept and offered again, because a message the stack has
/// already committed to is not one this ABI may drop.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralTransmit
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Which transport to write to. SIPRAL_TRANSPORT_MAIN, for now always.
    /// </summary>
    public uint Transport;
    /// <summary>
    /// What that transport speaks, as a `SipralTransport`.
    ///
    /// Carried because it is the message's and not the socket's: §18.1.1 lets a
    /// request that outgrew a datagram go out on a stream instead, and the
    /// transport it ends up on is the one this says. Zero for a protocol this
    /// ABI has no number for.
    /// </summary>
    public uint Protocol;
    /// <summary>
    /// Where to write the message. Nothing is written unless the whole of it
    /// fits.
    /// </summary>
    public IntPtr Data;
    /// <summary>
    /// How much room `data` has.
    /// </summary>
    public nuint Capacity;
    /// <summary>
    /// How much was written — or, when the call answered
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL`, how much room the message needs.
    /// </summary>
    public nuint Len;
    /// <summary>
    /// Where to write the destination, as `host:port` with a trailing NUL. Null
    /// with a capacity of zero for a caller whose socket is connected and
    /// already knows.
    /// </summary>
    public IntPtr Destination;
    /// <summary>
    /// How much room `destination` has. At least SIPRAL_ADDRESS_BYTES when
    /// it is not null.
    /// </summary>
    public nuint DestinationCapacity;
    /// <summary>
    /// How many bytes of it were written, the NUL not counted.
    /// </summary>
    public nuint DestinationLen;
    /// <summary>
    /// Where to write the address to send *from*, in the same shape.
    ///
    /// RFC 3581 §4: "The response MUST be sent from the same address and port
    /// that the corresponding request was received on", which a caller listening
    /// on a wildcard address cannot work out for itself. Empty — a `source_len`
    /// of zero — means the transport's own address, which is the answer for
    /// every request this stack originates.
    /// </summary>
    public IntPtr Source;
    /// <summary>
    /// How much room `source` has. At least SIPRAL_ADDRESS_BYTES when it is
    /// not null.
    /// </summary>
    public nuint SourceCapacity;
    /// <summary>
    /// How many bytes of it were written, the NUL not counted.
    /// </summary>
    public nuint SourceLen;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralTransmit Sized()
    {
        var value = default(SipralTransmit);
        value.Size = (nuint)Marshal.SizeOf<SipralTransmit>();
        return value;
    }
}

/// <summary>
/// What a SipralEventKind.RegistrationChanged carries.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralRegistrationEvent
{
    /// <summary>
    /// A SipralRegistrationState.
    /// </summary>
    public uint State;
    /// <summary>
    /// A SipralRegistrationFailure, zero when nothing failed.
    /// </summary>
    public uint Failure;
    /// <summary>
    /// The status the registrar answered with, or zero when none arrived.
    /// </summary>
    public uint StatusCode;
    /// <summary>
    /// The binding's granted lifetime, zero unless it is live.
    /// </summary>
    public ulong ExpiresMs;
    /// <summary>
    /// How long until the refresh, zero unless one is scheduled.
    /// </summary>
    public ulong RefreshInMs;
    /// <summary>
    /// How long until the next attempt. Only meaningful while the state is
    /// retrying, which is exactly when the stack is going to try again.
    /// </summary>
    public ulong RetryInMs;
}

/// <summary>
/// What every call event carries.
///
/// Not every member means something in every kind, and the ones that do not
/// are zero. A zero here always reads as absent rather than as a value.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralCallEvent
{
    /// <summary>
    /// A SipralCallState.
    /// </summary>
    public uint State;
    /// <summary>
    /// A SipralCallEndReason, zero while the call is alive.
    /// </summary>
    public uint EndReason;
    /// <summary>
    /// The status a response carried, or zero.
    /// </summary>
    public uint StatusCode;
    /// <summary>
    /// The other call this event is also about: the sibling of a fork, or the
    /// call that was replaced. SIPRAL_HANDLE_NONE otherwise.
    /// </summary>
    public ulong Other;
    /// <summary>
    /// Whether this end has asked the far end to stop sending.
    /// </summary>
    public uint HeldHere;
    /// <summary>
    /// Whether the far end has asked this one to.
    /// </summary>
    public uint HeldThere;
    /// <summary>
    /// What this end is describing, and how long it is.
    /// </summary>
    public IntPtr LocalSdp;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint LocalSdpLen;
    /// <summary>
    /// And what the far end is.
    /// </summary>
    public IntPtr RemoteSdp;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint RemoteSdpLen;
    /// <summary>
    /// When a refused session change goes out again by itself, zero when it is
    /// not going to.
    /// </summary>
    public ulong RetryInMs;
}

/// <summary>
/// What a transfer event carries.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralTransferEvent
{
    /// <summary>
    /// What the far end's own call is doing, or zero.
    /// </summary>
    public uint StatusCode;
    /// <summary>
    /// Whether the request named a dialog to replace, which is what makes a
    /// transfer attended rather than blind.
    /// </summary>
    public uint Attended;
    /// <summary>
    /// Who to call, as UTF-8. Not NUL-terminated.
    /// </summary>
    public IntPtr Target;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint TargetLen;
}

/// <summary>
/// What a media event carries.
///
/// As with a call event, not every member means something in every kind, and
/// the ones that do not are zero or null.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralMediaEvent
{
    /// <summary>
    /// A SipralCodec: what the negotiation
    /// settled on, zero where the event is not about a codec.
    /// </summary>
    public uint Codec;
    /// <summary>
    /// A SipralDirection: which way audio
    /// may flow, as seen from here.
    /// </summary>
    public uint Direction;
    /// <summary>
    /// How long the stream has been silent, for a stall and for its recovery.
    /// </summary>
    public ulong SilentForMs;
    /// <summary>
    /// How much audio reached the file, for a recording that stopped by
    /// itself.
    /// </summary>
    public ulong RecordedMs;
    /// <summary>
    /// A SipralMediaFault, zero when
    /// nothing failed.
    /// </summary>
    public uint Fault;
    /// <summary>
    /// The sentence behind `fault`, as UTF-8. Not NUL-terminated, and null
    /// when nothing failed.
    /// </summary>
    public IntPtr Reason;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ReasonLen;
    /// <summary>
    /// What the stream cost, for the kind that carries it, and null for every
    /// other. It belongs to the library and lives as long as the callback.
    /// </summary>
    public IntPtr Statistics;
    /// <summary>
    /// The key the far end pressed, as its character, and zero for an event
    /// no keypad has a key for.
    /// </summary>
    public uint Digit;
    /// <summary>
    /// The RFC 4733 event code behind `digit`. Codes at and above sixteen are
    /// real events that are not keys.
    /// </summary>
    public uint EventCode;
    /// <summary>
    /// How long the far end held it.
    /// </summary>
    public ulong HeldMs;
}

/// <summary>
/// The arm of an event that its kind names.
///
/// Reading any other arm reads bytes the library did not write for it.
/// </summary>
[StructLayout(LayoutKind.Explicit)]
public struct SipralEventPayload
{
    /// <summary>
    /// For SipralEventKind.RegistrationChanged.
    /// </summary>
    [FieldOffset(0)]
    public SipralRegistrationEvent Registration;
    /// <summary>
    /// For every call kind.
    /// </summary>
    [FieldOffset(0)]
    public SipralCallEvent Call;
    /// <summary>
    /// For SipralEventKind.TransferRequested,
    /// SipralEventKind.TransferProgress and
    /// SipralEventKind.TransferDone.
    /// </summary>
    [FieldOffset(0)]
    public SipralTransferEvent Transfer;
    /// <summary>
    /// For every media kind: started, changed, stalled, resumed, failed, the
    /// end-of-call statistics, and a recording that stopped by itself.
    /// </summary>
    [FieldOffset(0)]
    public SipralMediaEvent Media;
}

/// <summary>
/// Something the library has to tell the application.
///
/// The pointer handed to the callback is the library's, and it is valid for
/// the duration of that call and no longer. `size` says how much of the
/// struct this build filled in, and a binding reads no further than that. The
/// union stays the last member for the same reason: an arm that grows grows
/// the tail, which is the one place a released struct may change.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralEvent
{
    /// <summary>
    /// How many bytes of this struct are meaningful.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// The stack it is about.
    /// </summary>
    public ulong Stack;
    /// <summary>
    /// What it is.
    /// </summary>
    public SipralEventKind Kind;
    /// <summary>
    /// The account it is about, or SIPRAL_HANDLE_NONE.
    /// </summary>
    public ulong Account;
    /// <summary>
    /// The call it is about, or SIPRAL_HANDLE_NONE.
    /// </summary>
    public ulong Call;
    /// <summary>
    /// The SIP message behind it, whole and unparsed, when there is one.
    ///
    /// A reason phrase, a `Retry-After`, the `Contact` of a redirect and the
    /// caller's display name all live here and none of them is worth a member
    /// of its own. Null when the event came from no single message.
    /// </summary>
    public IntPtr Message;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint MessageLen;
    /// <summary>
    /// The arm SipralEvent.Kind names.
    /// </summary>
    public SipralEventPayload Payload;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralEvent Sized()
    {
        var value = default(SipralEvent);
        value.Size = (nuint)Marshal.SizeOf<SipralEvent>();
        return value;
    }
}

/// <summary>What a call across the boundary answered, when it did not
/// answer Ok. The message is the calling thread's last error, read
/// before anything else on this thread could replace it.</summary>
public sealed class SipralException : Exception
{
    internal SipralException(SipralStatus status, string message)
        : base(message.Length == 0 ? status.ToString() : $"{status}: {message}")
    {
        Status = status;
    }

    /// <summary>The code C would have switched on.</summary>
    public SipralStatus Status { get; }
}

/// <summary>
/// The ABI as the runtime calls it. Every pointer is written as an
/// array or as in, ref or out, so nothing here needs an unsafe block
/// and the runtime pins what it passes.
/// </summary>
internal static class NativeMethods
{
    /// <summary>What the native library is called, before the
    /// platform puts its own prefix and suffix on it.</summary>
    internal const string Library = "sipral";

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_last_error_message(sbyte[] buffer, nuint capacity, out nuint len);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern IntPtr sipral_status_name(int status);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_abi_version(ref SipralAbiVersion outVersion);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_abi_check(uint major, uint minor);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_abi_struct_size(sbyte[] name, nuint nameLen, out nuint size);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_abi_versioned_count(out nuint count);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_capabilities(ref SipralCapabilities outCapabilities);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_create(in SipralStackConfig config, out ulong stack);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_settings(ulong stack, ref SipralStackSettings outSettings);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_destroy(ulong stack);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_poll(ulong stack, ulong nowMs, ref SipralPollResult result);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_counters(ulong stack, ref SipralCounters outCounters);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_add(ulong stack, in SipralAccountConfig config, out ulong account);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_remove(ulong stack, ulong account);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_register(ulong stack, ulong account, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_unregister(ulong stack, ulong account, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_registration_state(ulong stack, ulong account, out uint state);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_place(ulong stack, ulong account, in SipralCallConfig config, out ulong call, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_ring(ulong stack, ulong call, byte[] sdp, nuint sdpLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_answer(ulong stack, ulong call, byte[] sdp, nuint sdpLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_answer_media(ulong stack, ulong call, sbyte[] mediaAddress, nuint mediaAddressLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_reject(ulong stack, ulong call, uint code, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_hangup(ulong stack, ulong call, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_hold(ulong stack, ulong call, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_resume(ulong stack, ulong call, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_accept_session(ulong stack, ulong call, byte[] sdp, nuint sdpLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_reject_session(ulong stack, ulong call, uint code, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_send_dtmf(ulong stack, ulong call, sbyte[] digits, nuint digitsLen, uint via, uint durationMs, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_transfer(ulong stack, ulong call, sbyte[] target, nuint targetLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_consult(ulong stack, ulong call, in SipralCallConfig config, out ulong consultation, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_transfer_to(ulong stack, ulong call, ulong other, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_accept_transfer(ulong stack, ulong call, out ulong placed, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_reject_transfer(ulong stack, ulong call, uint code, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_state(ulong stack, ulong call, out uint state);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_hold_state(ulong stack, ulong call, out uint here, out uint there);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern IntPtr sipral_codec_name(uint codec);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_codec_count(out nuint count);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_codec_at(nuint index, ref SipralCodecInfo outInfo);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_codec_order(ulong stack, uint[] outCodecs, nuint capacity, out nuint count);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_media_info(ulong stack, ulong call, ref SipralMediaInfo outInfo);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_statistics(ulong stack, ulong call, ulong nowMs, ref SipralStreamStats outStats);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_media_receive(ulong stack, ulong call, byte[] data, nuint len, sbyte[] from, nuint fromLen, ulong nowMs, out uint arrival);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_playback(ulong stack, ulong call, short[] samples, nuint capacity, out nuint written, out uint source);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_capture(ulong stack, ulong call, short[] samples, nuint sampleCount, ref SipralMediaPacket packet);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_poll_rtcp(ulong stack, ulong nowMs, out ulong call, ref SipralMediaPacket packet);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_dialling(ulong stack, ulong call, out uint dialling, out nuint waiting);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_stop_dialling(ulong stack, ulong call);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_record_start(ulong stack, ulong call, sbyte[] path, nuint pathLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_record_stop(ulong stack, ulong call);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_record_state(ulong stack, ulong call, out uint recording, out ulong recordedMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_poll_transmit(ulong stack, ref SipralTransmit transmit);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_receive_datagram(ulong stack, uint transport, byte[] data, nuint len, sbyte[] from, nuint fromLen, sbyte[] to, nuint toLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_receive_stream(ulong stack, uint transport, byte[] data, nuint len, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_transport_bind(ulong stack, uint transport, sbyte[] local, nuint localLen, sbyte[] remote, nuint remoteLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_transport_failed(ulong stack, uint transport, uint error, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_stream_closed(ulong stack, uint transport, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern IntPtr sipral_event_kind_name(uint kind);

}

/// <summary>Everything the library does, with the C conventions read
/// off it.</summary>
public static class Sipral
{
    /// <summary>
    /// The value no live handle ever takes.
    /// </summary>
    public const ulong HandleNone = 0;

    /// <summary>
    /// The ABI's major version. Nothing published against one major works
    /// against another.
    /// </summary>
    public const uint AbiVersionMajor = 0;

    /// <summary>
    /// The ABI's minor version, raised by anything the header gains —
    /// everything the generator prints, and not only a function or a struct
    /// member. `sipral_abi_check` compares the major and this one; the patch it
    /// does not ask about. The
    /// rule for all three numbers is the Versioning section of
    /// `docs/08-ffi.md`, which is where the ABI contract is written down.
    /// </summary>
    public const uint AbiVersionMinor = 8;

    /// <summary>
    /// The ABI's patch version, raised by a fix that changes no declaration.
    /// </summary>
    public const uint AbiVersionPatch = 0;

    /// <summary>
    /// Bits of SipralCapabilities.Transports. A caller checks
    /// `capabilities.transports &amp; SIPRAL_TRANSPORT_BIT_TLS != 0` rather than a
    /// growing list of booleans, so a transport this ABI has not learned a bit
    /// for yet reads as absent rather than refusing to compile against an
    /// older header.
    ///
    /// Named after SipralTransport's own numbers (`1 &lt;&lt; (value - 1)`), so
    /// a transport added there in the future gets a bit here without the two
    /// numbering schemes ever being asked to agree by hand.
    /// </summary>
    public const uint TransportBitUdp = 1;

    /// <summary>
    /// See SIPRAL_TRANSPORT_BIT_UDP.
    /// </summary>
    public const uint TransportBitTcp = 2;

    /// <summary>
    /// See SIPRAL_TRANSPORT_BIT_UDP.
    /// </summary>
    public const uint TransportBitTls = 4;

    /// <summary>
    /// See SIPRAL_TRANSPORT_BIT_UDP.
    /// </summary>
    public const uint TransportBitWs = 8;

    /// <summary>
    /// See SIPRAL_TRANSPORT_BIT_UDP.
    /// </summary>
    public const uint TransportBitWss = 16;

    /// <summary>
    /// Bits of SipralCapabilities.Features.
    /// </summary>
    public const uint FeatureDtmf = 1;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF.
    /// </summary>
    public const uint FeatureRtcpMux = 2;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF.
    /// </summary>
    public const uint FeatureRecording = 4;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF.
    /// </summary>
    public const uint FeatureMediaStallWatchdog = 8;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF.
    /// </summary>
    public const uint FeatureSrtp = 16;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF, and the module documentation for why this
    /// build never sets it.
    /// </summary>
    public const uint FeatureSubscriptions = 32;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. Opus is behind a compile-time feature,
    /// because libopus is the one part of the audio path that is licensed
    /// rather than written, so a build meant for hardware can leave it out.
    /// The bit is how an application finds out without having to enumerate
    /// the codecs, and it is set from the catalogue this build offers rather
    /// than from any crate's feature flag; `SIPRAL_CODEC_OPUS` keeps its
    /// number either way, since a value that has left this header is spent
    /// for good.
    /// </summary>
    public const uint FeatureOpus = 64;

    /// <summary>
    /// The buffer a caller has to bring for one outgoing packet.
    ///
    /// Not a path MTU — RTP does not discover one — but the bound the session
    /// itself builds against, so a payload larger than this is a payload no
    /// codec in this build produces. It is checked before anything is encoded,
    /// because a frame that was encoded and then had nowhere to go is a frame
    /// lost from a stream whose timestamps have already moved past it.
    /// </summary>
    public static readonly nuint MediaPacketBytes = 1500;

    /// <summary>
    /// Room enough for any address this ABI writes, the NUL included:
    /// `[2001:db8:0000:0000:0000:0000:0000:0001]:65535` and a byte to spare.
    /// </summary>
    public static readonly nuint AddressBytes = 64;

    /// <summary>
    /// The transport a stack is created with, and the only one this build
    /// binds.
    ///
    /// Named rather than assumed, so that the day a stack has two of them is a
    /// day more numbers become valid and not a day this ABI grows a second way
    /// to hand bytes over.
    /// </summary>
    public const uint TransportMain = 0;

    /// <summary>
    /// The largest message that crosses in either direction.
    ///
    /// The bound the layer below parses to, which is what stops a hostile peer
    /// from making the parser do unbounded work. A caller's read buffer wants
    /// to be this big on a stream, where one read can hold the end of one
    /// message and the start of another, and 1500 bytes or so on a datagram
    /// socket, where anything larger was fragmented on the way.
    /// </summary>
    public static readonly nuint MessageBytes = 65535;

    /// <summary>The calling thread's last error, or an empty string
    /// when it has none. Read the way C reads it: ask for the
    /// length, then for the bytes.</summary>
    public static string LastErrorMessage()
    {
        NativeMethods.sipral_last_error_message(Array.Empty<sbyte>(), 0, out var needed);
        if (needed <= 1)
        {
            return string.Empty;
        }

        var buffer = new sbyte[(int)needed];
        var status = NativeMethods.sipral_last_error_message(buffer, needed, out _);
        if (status != SipralStatus.Ok)
        {
            return string.Empty;
        }

        var bytes = new byte[buffer.Length];
        Buffer.BlockCopy(buffer, 0, bytes, 0, buffer.Length);
        var end = Array.IndexOf(bytes, (byte)0);
        return Encoding.UTF8.GetString(bytes, 0, end < 0 ? bytes.Length : end);
    }

    /// <summary>Turn a status into an exception, and nothing into
    /// nothing.</summary>
    internal static void Check(SipralStatus status)
    {
        if (status == SipralStatus.Ok)
        {
            return;
        }

        throw new SipralException(status, LastErrorMessage());
    }

    /// <summary>
    /// The short name of a status code, as a static NUL-terminated string, or
    /// null for a number that is not a status code.
    ///
    /// The string belongs to the library and lives as long as it is loaded.
    /// It is meant for a log line; the last error is the sentence for a human.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns, and is safe to call from any thread.
    /// </summary>
    public static string? StatusName(int status) =>
        Marshal.PtrToStringUTF8(NativeMethods.sipral_status_name(status));

    /// <summary>
    /// Report the ABI version this library provides.
    ///
    /// Safety
    ///
    /// `out_version` must point at a `sipral_abi_version_t` whose `size`
    /// member says how long it is.
    /// </summary>
    public static SipralAbiVersion AbiVersion()
    {
        var version = SipralAbiVersion.Sized();
        Check(NativeMethods.sipral_abi_version(ref version));
        return version;
    }

    /// <summary>
    /// Whether this library can serve a binding generated against
    /// `major`.`minor`. Every binding calls this once, at load.
    ///
    /// `SIPRAL_STATUS_UNSUPPORTED_VERSION` when it cannot, with a last error
    /// naming both versions, which is what the binding should put in the
    /// exception it throws. The patch number is not asked for: it never
    /// changes a declaration, so it cannot make two builds disagree.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns, and is safe to call from any thread.
    /// </summary>
    public static void AbiCheck(uint major, uint minor)
    {
        Check(NativeMethods.sipral_abi_check(major, minor));
    }

    /// <summary>
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
    /// </summary>
    public static nuint AbiStructSize(string name)
    {
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var nameSigned = new sbyte[nameBytes.Length];
        Buffer.BlockCopy(nameBytes, 0, nameSigned, 0, nameBytes.Length);
        Check(NativeMethods.sipral_abi_struct_size(nameSigned, (nuint)nameSigned.Length, out var size));
        return size;
    }

    /// <summary>
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
    /// </summary>
    public static nuint AbiVersionedCount()
    {
        Check(NativeMethods.sipral_abi_versioned_count(out var count));
        return count;
    }

    /// <summary>
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
    /// </summary>
    public static SipralCapabilities Capabilities()
    {
        var capabilities = SipralCapabilities.Sized();
        Check(NativeMethods.sipral_capabilities(ref capabilities));
        return capabilities;
    }

    /// <summary>
    /// Create a stack, and write its handle to `out_stack`.
    ///
    /// The handle is written only if this returns `SIPRAL_STATUS_OK`. A stack
    /// that is created must be destroyed with sipral_stack_destroy.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_stack_config_t` whose `size` member
    /// says how long it is, with every pointer in it readable for the length
    /// beside it, and `out_stack` at one `sipral_handle_t`.
    /// </summary>
    public static ulong StackCreate(in SipralStackConfig config)
    {
        Check(NativeMethods.sipral_stack_create(in config, out var stack));
        return stack;
    }

    /// <summary>
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
    /// </summary>
    public static SipralStackSettings StackSettings(ulong stack)
    {
        var settings = SipralStackSettings.Sized();
        Check(NativeMethods.sipral_stack_settings(stack, ref settings));
        return settings;
    }

    /// <summary>
    /// Destroy a stack.
    ///
    /// The handle is dead the moment this returns, and a second destroy is
    /// `SIPRAL_STATUS_STALE_HANDLE` rather than a corrupted heap. Called from
    /// inside the callback it is still safe: what the poll is holding stays
    /// alive until that poll returns. No account is de-registered and no call
    /// is hung up; a stack that has to leave politely does that first.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    /// </summary>
    public static void StackDestroy(ulong stack)
    {
        Check(NativeMethods.sipral_stack_destroy(stack));
    }

    /// <summary>
    /// Let the stack do its work, and deliver what it has to say.
    ///
    /// `now_ms` is the caller's monotonic clock in milliseconds. It must not
    /// go backwards between calls on the same stack; one that does is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` and nothing is delivered.
    ///
    /// The event callback is called from inside this function, on this
    /// thread. A call back into the same stack from the callback returns
    /// `SIPRAL_STATUS_BUSY` and does nothing, so a binding cannot deadlock
    /// itself by answering an event with a request.
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
    /// </summary>
    public static SipralPollResult StackPoll(ulong stack, ulong nowMs)
    {
        var result = SipralPollResult.Sized();
        Check(NativeMethods.sipral_stack_poll(stack, nowMs, ref result));
        return result;
    }

    /// <summary>
    /// D3's health counters for one stack, since it was created.
    ///
    /// Cheap enough to sample on a timer and ship as telemetry: reading this
    /// is one struct copy on top of the call itself, the same as
    /// `sipral_call_statistics` and for the same reason — nothing here walks
    /// the call table or a session to answer.
    ///
    /// Safety
    ///
    /// `out_counters` must point at a `sipral_counters_t` whose `size` member
    /// says how long it is.
    /// </summary>
    public static SipralCounters StackCounters(ulong stack)
    {
        var counters = SipralCounters.Sized();
        Check(NativeMethods.sipral_stack_counters(stack, ref counters));
        return counters;
    }

    /// <summary>
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
    /// </summary>
    public static ulong AccountAdd(ulong stack, in SipralAccountConfig config)
    {
        Check(NativeMethods.sipral_account_add(stack, in config, out var account));
        return account;
    }

    /// <summary>
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
    /// </summary>
    public static void AccountRemove(ulong stack, ulong account)
    {
        Check(NativeMethods.sipral_account_remove(stack, account));
    }

    /// <summary>
    /// Register, and keep the binding alive until told otherwise.
    ///
    /// Refreshes, credential retries and the back-off after an outage all
    /// happen without another call. What stops them is
    /// sipral_account_unregister, or a refusal that trying again cannot
    /// fix. Every step of it arrives as a `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED`.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void AccountRegister(ulong stack, ulong account, ulong nowMs)
    {
        Check(NativeMethods.sipral_account_register(stack, account, nowMs));
    }

    /// <summary>
    /// Give the binding up: a REGISTER with `Expires: 0` (§10.2.2).
    ///
    /// Only this device's binding. A `Contact: *` would remove every binding
    /// the address of record has, including the one belonging to the desk
    /// phone somebody else is holding.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void AccountUnregister(ulong stack, ulong account, ulong nowMs)
    {
        Check(NativeMethods.sipral_account_unregister(stack, account, nowMs));
    }

    /// <summary>
    /// Where an account's registration is, as a `SipralRegistrationState`.
    ///
    /// Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    /// </summary>
    public static uint AccountRegistrationState(ulong stack, ulong account)
    {
        Check(NativeMethods.sipral_account_registration_state(stack, account, out var state));
        return state;
    }

    /// <summary>
    /// Place a call, and write its handle to `out_call`.
    ///
    /// The handle exists from here on, before any dialog does, because there
    /// has to be something to hang up with while the INVITE is still in
    /// flight. A proxy that forks the INVITE gives the branches handles of
    /// their own, reported as `SIPRAL_EVENT_KIND_CALL_FORKED`.
    ///
    /// With `media_address` set, the offer is this stack's to write and the
    /// call gets audio of its own: `SIPRAL_EVENT_KIND_MEDIA_STARTED` says when,
    /// and `crate::media` carries the packets from then on.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_call_config_t` whose `size` member
    /// says how long it is, with every pointer in it readable for the length
    /// beside it, and `out_call` at one `sipral_handle_t`.
    /// </summary>
    public static ulong CallPlace(ulong stack, ulong account, in SipralCallConfig config, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_place(stack, account, in config, out var call, nowMs));
        return call;
    }

    /// <summary>
    /// Say a call that came in is ringing.
    ///
    /// A description makes it a 183 Session Progress rather than a 180
    /// Ringing, because 180 with a body is a contradiction the far end has to
    /// guess at. Pass none for the ordinary case.
    ///
    /// Safety
    ///
    /// `sdp` must be null or readable for `sdp_len` bytes.
    /// </summary>
    public static void CallRing(ulong stack, ulong call, byte[] sdp, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_ring(stack, call, sdp, (nuint)sdp.Length, nowMs));
    }

    /// <summary>
    /// Answer a call that came in.
    ///
    /// `sdp` is the answer to the offer the INVITE carried, and is required:
    /// answering with nothing puts the offer on this end and the answer in the
    /// far end's ACK, which this ABI has no way to hand back.
    ///
    /// Safety
    ///
    /// `sdp` must be readable for `sdp_len` bytes.
    /// </summary>
    public static void CallAnswer(ulong stack, ulong call, byte[] sdp, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_answer(stack, call, sdp, (nuint)sdp.Length, nowMs));
    }

    /// <summary>
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
    /// </summary>
    public static void CallAnswerMedia(ulong stack, ulong call, string mediaAddress, ulong nowMs)
    {
        var mediaAddressBytes = Encoding.UTF8.GetBytes(mediaAddress);
        var mediaAddressSigned = new sbyte[mediaAddressBytes.Length];
        Buffer.BlockCopy(mediaAddressBytes, 0, mediaAddressSigned, 0, mediaAddressBytes.Length);
        Check(NativeMethods.sipral_call_answer_media(stack, call, mediaAddressSigned, (nuint)mediaAddressSigned.Length, nowMs));
    }

    /// <summary>
    /// Refuse a call that came in, with a response code of your choosing.
    ///
    /// 486 Busy Here for a line that is in use, 603 Decline for a person who
    /// does not want to talk. The difference is what a proxy does next.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallReject(ulong stack, ulong call, uint code, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_reject(stack, call, code, nowMs));
    }

    /// <summary>
    /// Hang up, whatever the call is doing.
    ///
    /// A CANCEL before it is answered, a BYE after, a refusal for one that
    /// came in and has not been answered. A call that is already ending is
    /// left alone rather than refused.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallHangup(ulong stack, ulong call, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_hangup(stack, call, nowMs));
    }

    /// <summary>
    /// Put a call on hold (RFC 3264 §8.4).
    ///
    /// The description is the stack's to write: the one already negotiated
    /// with every stream's direction changed. Asking for a hold that is
    /// already in place sends nothing and succeeds.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallHold(ulong stack, ulong call, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_hold(stack, call, nowMs));
    }

    /// <summary>
    /// Take it off hold again.
    ///
    /// Every stream goes back to the direction it had before, which is not
    /// always both ways: one that was offered receive-only is resumed
    /// receive-only.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallResume(ulong stack, ulong call, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_resume(stack, call, nowMs));
    }

    /// <summary>
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
    /// </summary>
    public static void CallAcceptSession(ulong stack, ulong call, byte[] sdp, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_accept_session(stack, call, sdp, (nuint)sdp.Length, nowMs));
    }

    /// <summary>
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
    /// </summary>
    public static void CallRejectSession(ulong stack, ulong call, uint code, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_reject_session(stack, call, code, nowMs));
    }

    /// <summary>
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
    /// </summary>
    public static void CallSendDtmf(ulong stack, ulong call, string digits, uint via, uint durationMs, ulong nowMs)
    {
        var digitsBytes = Encoding.UTF8.GetBytes(digits);
        var digitsSigned = new sbyte[digitsBytes.Length];
        Buffer.BlockCopy(digitsBytes, 0, digitsSigned, 0, digitsBytes.Length);
        Check(NativeMethods.sipral_call_send_dtmf(stack, call, digitsSigned, (nuint)digitsSigned.Length, via, durationMs, nowMs));
    }

    /// <summary>
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
    /// </summary>
    public static void CallTransfer(ulong stack, ulong call, string target, ulong nowMs)
    {
        var targetBytes = Encoding.UTF8.GetBytes(target);
        var targetSigned = new sbyte[targetBytes.Length];
        Buffer.BlockCopy(targetBytes, 0, targetSigned, 0, targetBytes.Length);
        Check(NativeMethods.sipral_call_transfer(stack, call, targetSigned, (nuint)targetSigned.Length, nowMs));
    }

    /// <summary>
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
    /// </summary>
    public static ulong CallConsult(ulong stack, ulong call, in SipralCallConfig config, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_consult(stack, call, in config, out var consultation, nowMs));
        return consultation;
    }

    /// <summary>
    /// Hand `call` to the far end of `other` (RFC 3891).
    ///
    /// The attended half of a transfer: `other` is normally the consultation
    /// call, and the party at its far end replaces the call it already has
    /// rather than answering a second one. Any call that is up may be named.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallTransferTo(ulong stack, ulong call, ulong other, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_transfer_to(stack, call, other, nowMs));
    }

    /// <summary>
    /// Take a transfer that was asked for, place the call it names, and write
    /// that call's handle to `out_placed`.
    ///
    /// Safety
    ///
    /// `out_placed` must point at one `sipral_handle_t`.
    /// </summary>
    public static ulong CallAcceptTransfer(ulong stack, ulong call, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_accept_transfer(stack, call, out var placed, nowMs));
        return placed;
    }

    /// <summary>
    /// Refuse one instead.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallRejectTransfer(ulong stack, ulong call, uint code, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_reject_transfer(stack, call, code, nowMs));
    }

    /// <summary>
    /// Where a call is, as a `SipralCallState`.
    ///
    /// A call that is over answers `SIPRAL_CALL_STATE_TERMINATED` until the
    /// poll that delivers `SIPRAL_EVENT_KIND_CALL_ENDED` retires its handle, and
    /// `SIPRAL_STATUS_STALE_HANDLE` after that.
    ///
    /// Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    /// </summary>
    public static uint CallState(ulong stack, ulong call)
    {
        Check(NativeMethods.sipral_call_state(stack, call, out var state));
        return state;
    }

    /// <summary>
    /// Which way a call is held: `out_here` is set when this end asked the far
    /// end to stop sending, `out_there` when the far end asked this one.
    /// Either may be null.
    ///
    /// Safety
    ///
    /// `out_here` and `out_there` must each be null or point at one
    /// `uint32_t`.
    /// </summary>
    public static (uint Here, uint There) CallHoldState(ulong stack, ulong call)
    {
        Check(NativeMethods.sipral_call_hold_state(stack, call, out var here, out var there));
        return (here, there);
    }

    /// <summary>
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
    /// </summary>
    public static string? CodecName(uint codec) =>
        Marshal.PtrToStringUTF8(NativeMethods.sipral_codec_name(codec));

    /// <summary>
    /// How many codecs this build contains.
    ///
    /// A compile-time fact, and the reason A4 starts here rather than at a
    /// configuration: no setting can add a codec that was not linked.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    /// </summary>
    public static nuint CodecCount()
    {
        Check(NativeMethods.sipral_codec_count(out var count));
        return count;
    }

    /// <summary>
    /// One of them, by index, from zero to what `sipral_codec_count` said.
    ///
    /// The order is this build's own preference, quality first, which is what
    /// is offered when nobody has said otherwise.
    ///
    /// Safety
    ///
    /// `out_info` must point at a `sipral_codec_info_t` whose `size` member
    /// says how long it is.
    /// </summary>
    public static SipralCodecInfo CodecAt(nuint index)
    {
        var info = SipralCodecInfo.Sized();
        Check(NativeMethods.sipral_codec_at(index, ref info));
        return info;
    }

    /// <summary>
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
    /// </summary>
    public static nuint StackCodecOrder(ulong stack, uint[] outCodecs)
    {
        Check(NativeMethods.sipral_stack_codec_order(stack, outCodecs, (nuint)outCodecs.Length, out var count));
        return count;
    }

    /// <summary>
    /// What one call's media settled on.
    ///
    /// Safety
    ///
    /// `out_info` must point at a `sipral_media_info_t` whose `size` member
    /// says how long it is.
    /// </summary>
    public static SipralMediaInfo CallMediaInfo(ulong stack, ulong call)
    {
        var info = SipralMediaInfo.Sized();
        Check(NativeMethods.sipral_call_media_info(stack, call, ref info));
        return info;
    }

    /// <summary>
    /// What one call's media has cost, and what it is costing now.
    ///
    /// A6's live half. `now_ms` is the caller's monotonic clock, as everywhere
    /// else, because "how long since a packet arrived" is a question about the
    /// present and nothing here reads a clock to answer it. Unlike
    /// `sipral_stack_poll`, this does not move the stack's own clock: it is
    /// read at the frame rate of a user interface, often from the thread that
    /// draws one, and a reading a millisecond behind the last poll is not a
    /// caller bug.
    ///
    /// The end-of-call record arrives instead as
    /// `SIPRAL_EVENT_KIND_MEDIA_STATISTICS`, because by then the stream is
    /// gone and there is nothing left here to ask.
    ///
    /// Safety
    ///
    /// `out_stats` must point at a `sipral_stream_stats_t` whose `size` member
    /// says how long it is.
    /// </summary>
    public static SipralStreamStats CallStatistics(ulong stack, ulong call, ulong nowMs)
    {
        var stats = SipralStreamStats.Sized();
        Check(NativeMethods.sipral_call_statistics(stack, call, nowMs, ref stats));
        return stats;
    }

    /// <summary>
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
    /// Safety
    ///
    /// `data` must be readable and writable for `len` bytes, `from` readable
    /// for `from_len`, and `out_arrival` must point at one `uint32_t` or be
    /// null.
    /// </summary>
    public static uint CallMediaReceive(ulong stack, ulong call, byte[] data, string from, ulong nowMs)
    {
        var fromBytes = Encoding.UTF8.GetBytes(from);
        var fromSigned = new sbyte[fromBytes.Length];
        Buffer.BlockCopy(fromBytes, 0, fromSigned, 0, fromBytes.Length);
        Check(NativeMethods.sipral_call_media_receive(stack, call, data, (nuint)data.Length, fromSigned, (nuint)fromSigned.Length, nowMs, out var arrival));
        return arrival;
    }

    /// <summary>
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
    /// </summary>
    public static (nuint Written, uint Source) CallPlayback(ulong stack, ulong call, short[] samples)
    {
        Check(NativeMethods.sipral_call_playback(stack, call, samples, (nuint)samples.Length, out var written, out var source));
        return (written, source);
    }

    /// <summary>
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
    /// </summary>
    public static void CallCapture(ulong stack, ulong call, short[] samples, ref SipralMediaPacket packet)
    {
        Check(NativeMethods.sipral_call_capture(stack, call, samples, (nuint)samples.Length, ref packet));
    }

    /// <summary>
    /// The control traffic that is due, for whichever call is due one.
    ///
    /// One at a time, like every other poll here: a caller loops until the
    /// packet comes back with a `len` of zero. `out_call` names the call it
    /// belongs to, and therefore the socket it goes out on.
    ///
    /// RFC 3550 §6.3 decides when. Call this whenever `sipral_stack_poll`
    /// reports a deadline and whenever a frame goes out; on a call that
    /// negotiated no RTCP it answers zero for ever.
    ///
    /// Safety
    ///
    /// `out_call` must point at one `sipral_handle_t` or be null, and `packet`
    /// at a `sipral_media_packet_t` as sipral_call_capture describes.
    /// </summary>
    public static ulong StackPollRtcp(ulong stack, ulong nowMs, ref SipralMediaPacket packet)
    {
        Check(NativeMethods.sipral_stack_poll_rtcp(stack, nowMs, out var call, ref packet));
        return call;
    }

    /// <summary>
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
    /// </summary>
    public static (uint Dialling, nuint Waiting) CallDialling(ulong stack, ulong call)
    {
        Check(NativeMethods.sipral_call_dialling(stack, call, out var dialling, out var waiting));
        return (dialling, waiting);
    }

    /// <summary>
    /// Drop everything queued and stop the digit going out.
    ///
    /// The digit in flight gets no closing packet, which is right for a call
    /// whose media is being taken away: there is nowhere left to send one.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    /// </summary>
    public static void CallStopDialling(ulong stack, ulong call)
    {
        Check(NativeMethods.sipral_call_stop_dialling(stack, call));
    }

    /// <summary>
    /// Start recording this call to `path`.
    ///
    /// Both directions, mixed, as WAVE. It can be started and stopped as often
    /// as the person on the phone presses the button, and each recording is a
    /// file of its own: a path written to twice would have two headers in it.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a call with no media and for one already
    /// being recorded — two writers on one stream would interleave frames into
    /// both files. `SIPRAL_STATUS_INVALID_ARGUMENT` when the file system
    /// refuses the path, with what it said in the last error.
    ///
    /// Safety
    ///
    /// `path` must be readable for `path_len` bytes.
    /// </summary>
    public static void CallRecordStart(ulong stack, ulong call, string path)
    {
        var pathBytes = Encoding.UTF8.GetBytes(path);
        var pathSigned = new sbyte[pathBytes.Length];
        Buffer.BlockCopy(pathBytes, 0, pathSigned, 0, pathBytes.Length);
        Check(NativeMethods.sipral_call_record_start(stack, call, pathSigned, (nuint)pathSigned.Length));
    }

    /// <summary>
    /// Stop it, and close the file.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when nothing is being recorded. A failure
    /// here leaves a file with all of the audio in it and zeroes in the two
    /// header fields, which is recoverable and is said rather than hidden.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallRecordStop(ulong stack, ulong call)
    {
        Check(NativeMethods.sipral_call_record_stop(stack, call));
    }

    /// <summary>
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
    /// </summary>
    public static (uint Recording, ulong RecordedMs) CallRecordState(ulong stack, ulong call)
    {
        Check(NativeMethods.sipral_call_record_state(stack, call, out var recording, out var recordedMs));
        return (recording, recordedMs);
    }

    /// <summary>
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
    /// </summary>
    public static void StackPollTransmit(ulong stack, ref SipralTransmit transmit)
    {
        Check(NativeMethods.sipral_stack_poll_transmit(stack, ref transmit));
    }

    /// <summary>
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
    /// </summary>
    public static void StackReceiveDatagram(ulong stack, uint transport, byte[] data, string from, string to, ulong nowMs)
    {
        var fromBytes = Encoding.UTF8.GetBytes(from);
        var fromSigned = new sbyte[fromBytes.Length];
        Buffer.BlockCopy(fromBytes, 0, fromSigned, 0, fromBytes.Length);
        var toBytes = Encoding.UTF8.GetBytes(to);
        var toSigned = new sbyte[toBytes.Length];
        Buffer.BlockCopy(toBytes, 0, toSigned, 0, toBytes.Length);
        Check(NativeMethods.sipral_stack_receive_datagram(stack, transport, data, (nuint)data.Length, fromSigned, (nuint)fromSigned.Length, toSigned, (nuint)toSigned.Length, nowMs));
    }

    /// <summary>
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
    /// </summary>
    public static void StackReceiveStream(ulong stack, uint transport, byte[] data, ulong nowMs)
    {
        Check(NativeMethods.sipral_stack_receive_stream(stack, transport, data, (nuint)data.Length, nowMs));
    }

    /// <summary>
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
    /// </summary>
    public static void StackTransportBind(ulong stack, uint transport, string local, string remote, ulong nowMs)
    {
        var localBytes = Encoding.UTF8.GetBytes(local);
        var localSigned = new sbyte[localBytes.Length];
        Buffer.BlockCopy(localBytes, 0, localSigned, 0, localBytes.Length);
        var remoteBytes = Encoding.UTF8.GetBytes(remote);
        var remoteSigned = new sbyte[remoteBytes.Length];
        Buffer.BlockCopy(remoteBytes, 0, remoteSigned, 0, remoteBytes.Length);
        Check(NativeMethods.sipral_stack_transport_bind(stack, transport, localSigned, (nuint)localSigned.Length, remoteSigned, (nuint)remoteSigned.Length, nowMs));
    }

    /// <summary>
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
    /// </summary>
    public static void StackTransportFailed(ulong stack, uint transport, uint error, ulong nowMs)
    {
        Check(NativeMethods.sipral_stack_transport_failed(stack, transport, error, nowMs));
    }

    /// <summary>
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
    /// </summary>
    public static void StackStreamClosed(ulong stack, uint transport, ulong nowMs)
    {
        Check(NativeMethods.sipral_stack_stream_closed(stack, transport, nowMs));
    }

    /// <summary>
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
    /// </summary>
    public static string? EventKindName(uint kind) =>
        Marshal.PtrToStringUTF8(NativeMethods.sipral_event_kind_name(kind));

}
