// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One event, one callback, one tagged union.
//!
//! Everything the stack has to say arrives as a [`SipralEvent`]: a size, the
//! handles it is about, a kind, and a union whose arm the kind names. One
//! struct rather than one callback per kind, because a binding that registers
//! fourteen function pointers has fourteen chances to leave one null, and
//! because a kind added later then costs a caller nothing — it reads the
//! kind it does not know and ignores it.
//!
//! Nothing inside the union is an enumerated type. A union arm the library did
//! not write holds whatever the arm it did write put there, and reading a Rust
//! enum out of bits that were never one of its values is undefined behaviour,
//! so every enumerated member in there is a plain integer whose names are
//! declared next to it. The head of the struct, which is written every time,
//! keeps its types.
//!
//! Pointers in an event belong to the library and are valid for the duration of
//! the callback and no longer. A binding copies what it wants out before it
//! returns; there is nothing to free.

use std::collections::HashMap;
use std::ffi::{c_char, c_void};
use std::sync::Arc;
use std::time::Duration;

use sipral::SrtpSuite;
use sipral::{AmdReason, AmdVerdict, CallProgress, DigitSource, MediaEvent, ProgressTone};
use sipral_core::endpoint::Event;
use sipral_core::msg::HeaderName;
use sipral_ua::{
    CallEndReason, CallHandle, CallIdentity, CallState, LifecycleState, RecoveryFailure,
    RegistrationFailure, RegistrationState, Rung, UaEvent, UserAgent,
};

use crate::abi::{Number, alias, codes, record};
use crate::audio::SipralAudioEvent;
use crate::conference::SipralConferenceEvent;
use crate::error::entry;
use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
use crate::identity::{SipralAnswerMode, SipralRingSource, SipralVerstat};
use crate::local_conference::SipralLocalConferenceEvent;
use crate::locate::SipralLocateEvent;
use crate::media::{
    SipralCodec, SipralDirection, SipralMediaFault, SipralSrtpSuite, SipralStreamStats,
    SipralToggle, direction_of, fault_of, named_codec,
};
use crate::names::Names;
use crate::nat::{
    SipralNatEvent, SipralNatRelayEvent, SipralStunServerEvent, SipralTurnStreamEvent,
};
use crate::presence::SipralPresenceEvent;
use crate::realtime_text::SipralTextEvent;
use crate::security::{
    SipralAttestation, SipralKeyExchange, SipralVerificationFailure, SipralVerificationOutcome,
    SipralVerificationStage,
};
use crate::stack::SipralTransport;
use crate::subscription::{SipralSubscriptionEnd, SipralSubscriptionState, named_end, named_state};
use crate::transport::SipralTransportFailedEvent;

/// Declare the event number space, once.
///
/// Everything that has to agree about an event's number is written here and
/// generated from here: the enum, the name a log line prints, and the number
/// the two are indexed by. A kind cannot be added to one of those and missed in
/// the other, because there is only one place to add it.
///
/// A number is spent by appearing in this list, live or reserved, and the
/// generated assertion is that the list runs `1, 2, 3, …` with nothing repeated
/// and no hole. A hole is what two features fall into: each takes the number
/// after the last live kind, each builds, and the one that lands second has
/// silently renamed an event that a shipped binding already knows. A reserved
/// line is that hole filled in advance — the number belongs to a named feature
/// before the feature is written, so taking it is reading rather than choosing.
///
/// Live and reserved lines interleave, in one run, in number order. That is
/// what makes "taking a reserved number in place" the literal truth: the line
/// stays where its number is and turns into a kind, and the features on either
/// side of it keep the numbers they were promised. A list that made every live
/// kind come first would force a feature to take five numbers it has nothing to
/// put behind in order to reach the sixth.
///
/// Removing or reordering a line is what `docs/08-ffi.md` forbids outright, and
/// what the assertion turns from a released mistake into a build failure.
macro_rules! event_kinds {
    (
        $(#[doc = $doc:literal])*
        kinds {
            $(
                $(#[doc = $about:literal])*
                $number:literal = $variant:ident, $name:literal;
                $(
                    reserved $held:literal = $feature:literal;
                )*
            )*
        }
    ) => {
        $(#[doc = $doc])*
        ///
        /// Numbers already spent on features this build does not have, so that
        /// two of them cannot arrive holding the same one:
        ///
        $($(#[doc = concat!(" - `", stringify!($held), "` — ", $feature)])*)*
        #[repr(u32)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum SipralEventKind {
            $(
                $(#[doc = $about])*
                $variant = $number,
            )*
        }

        impl SipralEventKind {
            /// Every kind this build has, in the order their numbers were
            /// spent.
            pub const ALL: &'static [Self] = &[$(Self::$variant),*];

            /// What this enumeration is, for the header and the bindings. The
            /// reserved numbers travel with it, so that the header says what
            /// this list says: the number is spent whether or not a kind has
            /// been written behind it.
            pub(crate) const ABI: $crate::abi::Enumeration = $crate::abi::Enumeration {
                name: "SipralEventKind",
                doc: &[$($doc,)*],
                width: "u32",
                codes: &[$($crate::abi::Code {
                    name: stringify!($variant),
                    doc: &[$($about,)*],
                    value: $number,
                },)*],
                reserved: &[$($($crate::abi::Held {
                    value: $held,
                    feature: $feature,
                },)*)*],
            };
        }

        impl $crate::abi::Enumerated for SipralEventKind {
            type Raw = u32;
        }

        entry! {
            /// The short name of an event kind, as a static NUL-terminated
            /// string, or null for a number this build has no kind for.
            ///
            /// The string belongs to the library and lives as long as it is
            /// loaded. A number that is reserved for a feature this build does
            /// not have answers null, the same as one that was never spent: a
            /// name for something that cannot arrive would be a name for
            /// nothing.
            ///
            /// # Safety
            ///
            /// Reads no memory the caller owns, and is safe to call from any
            /// thread.
            fn sipral_event_kind_name(
                kind: Number<SipralEventKind>,
            ) -> *const c_char, on_panic = std::ptr::null(), {
                match kind {
                    $($number => $name.as_ptr(),)*
                    _ => std::ptr::null(),
                }
            }
        }

        // every number in the list, live and reserved, against the one it has
        // to be: this is the build failure that a collision, a hole or a
        // reordering becomes
        const _: () = {
            let mut next = 1_u32;
            $(
                assert!(
                    $number == next,
                    "an event kind's number is not the one after the last: the numbers this ABI \
                     has spent run 1, 2, 3, … and nothing may repeat, move or leave a hole"
                );
                next += 1;
                $(
                    assert!(
                        $held == next,
                        "a reserved event number is not the one after the last: reservations sit \
                         in the same run as the kinds, so that the number a feature takes is \
                         already written down"
                    );
                    next += 1;
                )*
            )*
        };
    };
}

event_kinds! {
    /// What an event is about.
    ///
    /// The numbers are part of the ABI and are only ever added to. A binding
    /// that meets a kind it does not know must ignore that event rather than
    /// refuse it, which is what makes adding one safe.
    kinds {
        /// The stack is running on this thread.
        ///
        /// The first event on every stack, delivered by the first poll and never
        /// again. A binding that has a callback to hand out, a queue to open or a
        /// thread to name has somewhere definite to do it, before anything that
        /// matters can arrive.
        1 = Started, c"started";
        /// A registration moved: it went out, it took, it is being refreshed, it
        /// was given up, or it failed. `payload.registration` says which, and
        /// `account` says whose.
        2 = RegistrationChanged, c"registration changed";
        /// Somebody is calling. Answer, ring, or reject it.
        3 = IncomingCall, c"incoming call";
        /// A call this end placed is getting somewhere short of an answer.
        4 = CallProgress, c"call progress";
        /// A proxy forked the INVITE and a second phone is ringing.
        /// `payload.call.other` is the branch that has just appeared.
        5 = CallForked, c"call forked";
        /// The call is up.
        6 = CallConfirmed, c"call confirmed";
        /// The session inside a live call changed: a hold, a resume, or an offer
        /// either end made and had accepted.
        7 = SessionChanged, c"session changed";
        /// The far end offered a change this stack has no policy for. The
        /// transaction is held open: answer it or refuse it, or the call ends.
        8 = SessionOffered, c"session offered";
        /// A change this end offered was refused. The session stands as it was.
        9 = SessionChangeFailed, c"session change failed";
        /// The far end asked this one to call somebody else.
        10 = TransferRequested, c"transfer requested";
        /// A transfer this end asked for is under way.
        11 = TransferProgress, c"transfer progress";
        /// And how it ended.
        12 = TransferDone, c"transfer done";
        /// A call arrived carrying a `Replaces` and took over one already up.
        /// `payload.call.other` is the one being replaced.
        13 = CallReplaced, c"call replaced";
        /// The call is over, and its handle is stale from here on.
        14 = CallEnded, c"call ended";

        /// A subscription moved: it was asked for, granted, put on probation,
        /// scheduled for another attempt, or ended.
        ///
        /// A1. `payload.subscription` says which one and where it is now, and
        /// `reason` why it is not live when it is not. Not sent on every
        /// refresh — a lamp does not move because a refresh was scheduled —
        /// and not sent for a notification arriving, which is
        /// [`SipralEventKind::Notified`] instead.
        15 = SubscriptionChanged, c"subscription changed";

        // Held for what `docs/13-client-requirements.md` already commits to, so
        // that features written in separate branches cannot arrive holding the same
        // number. Taking one means turning its line into a kind, in place.
        reserved 16 = "held for the set of audio devices changed (A2), which shipped as 43 in the wave that allocated its number; spent all the same";

        /// What one call's media cost, delivered once, after
        /// `SIPRAL_EVENT_KIND_CALL_ENDED`.
        ///
        /// A6's second consumer. `payload.media.statistics` points at the
        /// completed record; it is the library's and lives as long as the callback
        /// does. The stream is gone by the time this arrives, which is why the
        /// numbers travel in the event rather than behind a lookup that would now
        /// fail.
        17 = MediaStatistics, c"media statistics";
        /// A request grew too large for a datagram (RFC 3261 §18.1.1) and this
        /// stack has no stream transport open to the destination it names.
        /// `payload.transport_wanted` says where it was going, over what
        /// protocol, and how it measured against the datagram it did not fit.
        ///
        /// B1. The call that asked for the request — placing a call,
        /// registering — was refused with `SIPRAL_STATUS_NOT_SENT`, and
        /// nothing went on the wire. Answered with
        /// [`sipral_stack_transport_bind`](crate::transport::sipral_stack_transport_bind):
        /// once the application has bound a transport to that destination,
        /// asking again sends the request on it, and this ABI raises nothing
        /// further about it — there is no "it went" event, the same way there
        /// is none for an ordinary request that fit the first time.
        18 = TransportWanted, c"transport wanted";
        /// Nothing has arrived on the media path for longer than the configured
        /// threshold, while signalling is perfectly happy.
        ///
        /// B5. `payload.media.silent_for_ms` says how long. The call is untouched:
        /// whether to hang up over silence is a decision with a person on the other
        /// end of it.
        19 = MediaStalled, c"media stalled";
        /// A call a push announced never arrived.
        ///
        /// C2, and not an error. A wake-up chain has a notification service,
        /// a proxy, a bucket timer and a radio in it, and when a call does not
        /// come through it this is the only place that says which end gave up:
        /// the push was delivered, this device woke, refreshed its binding,
        /// and no INVITE followed. `payload.announce` says which announcement
        /// and how long it was waited for; the screen the application raised
        /// can come down.
        20 = AnnouncedCallMissing, c"announced call missing";
        /// Audio is running: the negotiation settled and an RTP session is open.
        ///
        /// A4's reporting half and the first half of D5: `payload.media.codec` is
        /// what the two ends agreed on. This is the moment to mint the call's
        /// media handle with `sipral_call_media`, and `sipral_media_info` on it
        /// says the rest.
        21 = MediaStarted, c"media started";
        /// The session changed under a live call: a hold, a resume, a peer that
        /// moved its media address, or a re-negotiation onto another codec.
        22 = MediaChanged, c"media changed";
        /// Packets are arriving again. `payload.media.silent_for_ms` says how long
        /// the gap turned out to be.
        23 = MediaResumed, c"media resumed";
        /// Media could not be started or could not be kept. The call itself is
        /// untouched; `payload.media.fault` and `payload.media.reason` say why.
        24 = MediaFailed, c"media failed";
        /// A recording stopped on its own, part-way through: the disk filled, the
        /// file went away, the volume was unmounted.
        ///
        /// Never an abort. `payload.media.recorded_ms` says how much audio reached
        /// the file before it stopped, and the call carries on without it.
        25 = RecordingStopped, c"recording stopped";
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
        26 = DigitReceived, c"digit received";
        /// An INFO this end sent for `sipral_call_send_dtmf` reached a final
        /// answer. `payload.call.digit` is the character and
        /// `payload.call.status_code` what the far end answered — a 415 from
        /// a switch that does not take this `Content-Type` included, so the
        /// application learns which of the two INFO forms to try without
        /// guessing from silence. A digit that waited behind another and whose
        /// own INFO could then not be sent at all is reported the same way,
        /// with 503: nothing reached the far end for that one, and no digit
        /// after it is sent.
        27 = DtmfSent, c"dtmf sent";
        /// The lifecycle machine settled: a registrar answered again and
        /// proved a path this stack had stopped believing in, or every rung
        /// of a recovery ladder was climbed and none of them worked.
        /// `payload.recovery` says which, and carries what the ladder that
        /// got there actually knows. `crates/sipral-ffi/src/lifecycle.rs`
        /// and `docs/16-lifecycle.md` are the ladder this reports on.
        28 = Recovery, c"recovery";

        /// A dialog's next hop is a name, and this library does not look
        /// names up.
        ///
        /// RFC 3263 §4's TARGET, before any NAPTR, SRV or A lookup: the
        /// route set and the remote target say where this dialog's requests
        /// should go, and what they say is not where they are going. Nothing
        /// here owns a resolver — nothing here owns a socket either — so the
        /// answer is the application's, through
        /// [`sipral_stack_resolved`](crate::resolve::sipral_stack_resolved),
        /// with `payload.resolve.dialog` as the handle it takes.
        ///
        /// **Ignoring it is legitimate and is the common case.** The dialog
        /// keeps the flow its first message travelled on, which §8.1.2 allows
        /// as an alternate address and which is the only thing that survives
        /// a NAT. Nothing times out, nothing retries, and no second event
        /// says the first went unanswered.
        29 = ResolveNeeded, c"resolve needed";

        /// A notification arrived on a subscription, and has been answered.
        ///
        /// A1's other half. The NOTIFY is in `message`, whole and unparsed,
        /// which is where every package this ABI has no reader for is read
        /// from. `payload.subscription.has_dialog_info` says the body was
        /// `application/dialog-info+xml` and could be read, and the picture it
        /// updated is behind
        /// [`sipral_subscription_dialog_count`](crate::subscription::sipral_subscription_dialog_count).
        /// A body that could not be read arrives here all the same, with that
        /// member zero and the request whole: a lamp showing what was last
        /// known beats one showing what a malformed document happened to
        /// contain.
        30 = Notified, c"notified";
        /// The INVITE for a call a push had already announced has arrived
        /// (RFC 8599).
        ///
        /// C2's other half. Queued immediately before the
        /// [`SipralEventKind::IncomingCall`] naming the same call, and never
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
        31 = CallAnnounced, c"call announced";
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
        32 = MediaSecured, c"media secured";
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
        33 = MediaPathChosen, c"media path chosen";
        /// A MESSAGE arrived (RFC 3428 §7) and has already been answered:
        /// 200, because this stack delivers rather than relays.
        /// `payload.message` carries the body, and `account`/`call` on
        /// `sipral_event_t` say where it was addressed and whether it rode
        /// inside a call's dialog.
        34 = MessageReceived, c"message received";
        /// A MESSAGE `sipral_account_message` sent reached its final answer,
        /// or never will. `payload.message.status_code` is 200, a 202 from a
        /// relay, a refusal, or the 408/503 this stack reports for one that
        /// timed out or lost its transport.
        35 = MessageSent, c"message sent";
        /// A `message-summary` `NOTIFY` reported the state of a mailbox
        /// (RFC 3842 §3.9). `payload.message` carries the counts of the
        /// `voice-message` class, the one a phone's message-waiting light is
        /// about.
        36 = MessagesWaiting, c"messages waiting";
        /// The account this call belongs to asked for an RFC 6035 voice
        /// quality report and the attempt to publish it has now been made,
        /// once, after `SIPRAL_EVENT_KIND_CALL_ENDED`.
        ///
        /// `payload.media.quality_report_sent` says whether the PUBLISH
        /// left this end — not whether a collector accepted it, which this
        /// stack never waits to learn. Raised only when the account named
        /// a collector to publish to at all
        /// (`sipral_account_config_t::quality_report_uri`); a call whose
        /// account named none raises nothing here, since nothing was ever
        /// attempted.
        37 = QualityReportSent, c"quality report sent";
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
        38 = MediaUnjoined, c"media unjoined";
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
        39 = NatMapping, c"nat mapping";
        /// A TURN server allocated a relay for a media socket
        /// `sipral_stack_nat_map` named, or gave none (RFC 8656). Only on a
        /// stack created with a `turn_server`.
        ///
        /// `payload.relay` says which socket and what it came to. Allocated,
        /// it is the moment a call can be placed, rung or answered on the
        /// socket with the relay as its relayed ICE candidate — before it,
        /// that is `SIPRAL_STATUS_WRONG_STATE`, as it is while the STUN
        /// answer is awaited. Failed, the call goes without one. `account`
        /// and `call` are `SIPRAL_HANDLE_NONE`: a socket is neither.
        40 = NatRelay, c"nat relay";
        /// A REFER outside any dialog asked this end to place a call (RFC
        /// 3515): click-to-dial from a switchboard, a CRM or an operator
        /// console. Only on a stack created with
        /// `sipral_stack_config_t::referrals` on, and only for one the same
        /// screening an INVITE meets let through.
        ///
        /// `call` is the referral's handle: a handle of the call kind that
        /// names this request rather than a call — `sipral_call_state`
        /// answers `SIPRAL_STATUS_WRONG_STATE` about it, and nothing but the
        /// two calls below takes it. `account` is the line it arrived for,
        /// which the call it asks for is placed from; `message` is the REFER.
        /// `payload.referral` says who to call, whether that is an attended
        /// transfer's target, and who the sender says is asking.
        ///
        /// Take it with `sipral_call_accept_transfer`, which answers 202,
        /// places the call exactly as it does for a transfer inside a call and
        /// writes the placed call's handle; refuse it with
        /// `sipral_call_reject_transfer`. Either spends the handle. **Taking
        /// it is the application's decision each time**: a peer that can make
        /// a phone dial can make it dial anything, and `referred_by` is what
        /// the sender wrote, never proof of who it is.
        ///
        /// Raised a second time, with `payload.referral.status_code` set and
        /// nothing else, when the application answered neither before the
        /// REFER's transaction ran out: the stack answered it with that status
        /// and the handle is stale from here on.
        41 = Referral, c"referral";
        /// A media socket's connection to a TURN server reached over TCP or
        /// TLS (`turn_transport`, RFC 8656 §3.1) is to be opened, or closed.
        /// Only on a stack created with one.
        ///
        /// `payload.turn_stream` says which socket, which server, over what,
        /// and which of the two. `SIPRAL_TURN_STREAM_OPEN` follows
        /// `sipral_stack_nat_map`: open the connection from the socket to the
        /// server — TLS with the platform's own stack, the certificate
        /// checked against the server's name — and say so with
        /// `sipral_stack_turn_connected`, then hand everything it carries to
        /// `sipral_stack_turn_receive` for as long as it is open, and its
        /// closing to `sipral_stack_turn_closed`. What is written on it comes
        /// out of `sipral_stack_poll_stun`, `sipral_media_poll_transmit`,
        /// `sipral_media_capture`, `sipral_media_poll_rtcp` and
        /// `sipral_stack_poll_farewell`, each marked with its `protocol`.
        /// `SIPRAL_TURN_STREAM_CLOSE` says nothing more will be: write what
        /// is still queued for it, and close it. `account` and `call` are
        /// `SIPRAL_HANDLE_NONE`: a socket is neither.
        42 = TurnStream, c"turn stream";
        /// The audio engine's devices moved: a device arrived or left, the
        /// system's default changed, a role was put on a device, lost the
        /// one it was on, or was reopened on another. Only on a stack
        /// created with `sipral_stack_config_t::audio` set to
        /// `SIPRAL_AUDIO_DEVICE`.
        ///
        /// `payload.audio` says what changed and who changed it —
        /// `SIPRAL_AUDIO_ORIGIN_SYSTEM` for the operating system,
        /// `SIPRAL_AUDIO_ORIGIN_ENGINE` for this library doing what the
        /// application asked or what a loss made it do — so that an
        /// application can note the first and need not re-apply its own
        /// choice on hearing the second. `account` and `call` are
        /// `SIPRAL_HANDLE_NONE`: a device is neither.
        43 = AudioDevicesChanged, c"audio devices changed";
        reserved 44 = "held for a second audio device event, which the audio engine did not need; spent all the same";

        /// The network changed under this call and the address its media
        /// was described at is gone: the far end is still sending its audio
        /// there.
        ///
        /// One for every call that can still be offered a new description,
        /// raised by `sipral_stack_network_changed` when it answers
        /// `SIPRAL_RECOVERY_REBUILD`. Answer it by binding a media socket on
        /// the new network and handing its address to
        /// `sipral_call_media_readdress`, after `sipral_account_rebind`, so
        /// that the re-INVITE carries the new `Contact` as well as the new
        /// `c=` and port. `call` is the call; the payload is
        /// `payload.call`, as for every other call event.
        45 = CallAddressWanted, c"call address wanted";
        /// The STUN server a stack asks changed, or every one of them failed.
        /// Only on a stack created with `SIPRAL_NAT_STUN`, or given servers by
        /// `sipral_stack_stun_servers`.
        ///
        /// `payload.stun_server` says which:
        /// `SIPRAL_STUN_SERVER_STATE_CHANGED` when the server in use moved --
        /// the one before it failed, one earlier in the list answered again,
        /// or the list was replaced -- and
        /// `SIPRAL_STUN_SERVER_STATE_ALL_FAILED` when every server in
        /// `stun_server` and `stun_fallbacks` has failed and none is left to
        /// turn to. A server fails when it does not answer in five and a half
        /// seconds, or answers without an address, and is then passed over
        /// for thirty seconds, twice as long each time it fails again, up to
        /// ten minutes. Nothing is asked of the application: the sockets move
        /// to the next server by themselves, and
        /// `SIPRAL_EVENT_KIND_NAT_MAPPING` says what each one learns there.
        /// `account` and `call` are `SIPRAL_HANDLE_NONE`: a server is
        /// neither.
        46 = StunServer, c"stun server";
        /// Who is calling, as a signature says (RFC 8224, RFC 8588): the
        /// stack's verification service at work on an INVITE for an account
        /// that verifies its callers. ABI 0.31.
        ///
        /// `payload.verification.stage` says which half.
        /// `SIPRAL_VERIFICATION_STAGE_CERTIFICATE_WANTED`: the certificate at
        /// `certificate_url` is needed; fetch it and hand it to
        /// `sipral_call_stir_certificate`, or hand over nothing if it cannot
        /// be had. The call waits, and the application has not been told of
        /// it yet — `call` names it all the same, for the answer.
        /// `SIPRAL_VERIFICATION_STAGE_VERIFIED`: the verdict, queued just
        /// before the `SIPRAL_EVENT_KIND_INCOMING_CALL` naming the same call,
        /// whose call events carry it too; or, with `refused` set, before the
        /// `SIPRAL_EVENT_KIND_CALL_ENDED` of a call its strict account
        /// refused with `response_code`. `message` is the INVITE.
        47 = CallerVerification, c"caller verification";
        /// A keypad digit heard in the far end's audio, as the two tones
        /// themselves, on a call listening for them:
        /// `sipral_stack_config_t::dtmf_detection` and
        /// `sipral_call_dtmf_detection` say when. One per press, reported as
        /// it ends; on a call that also negotiated named events, a press the
        /// far end sent both ways is reported once, as
        /// `SIPRAL_EVENT_KIND_DIGIT_RECEIVED`, and one heard only in the audio
        /// waits a quarter of a second before it is reported here.
        ///
        /// `payload.media` carries it the way it carries every digit:
        /// `digit` is the key's character, `event_code` its RFC 4733 code,
        /// `held_ms` how long it sounded and `source`
        /// `SIPRAL_DIGIT_SOURCE_IN_BAND`.
        48 = InBandDigit, c"in-band digit";
        /// What was heard on a call told to listen with
        /// `sipral_call_detect_progress`: a call-progress tone of its network
        /// on early media, the special information tone, who answered, or
        /// the beep an answering machine plays before it records.
        /// `payload.progress` says which, and what was measured.
        49 = ProgressDetected, c"progress detected";
        /// A `conference` subscription's picture of the conference changed,
        /// or the conference ended (RFC 4575 §4.6).
        ///
        /// `payload.conference` says which subscription and what happened:
        /// `SIPRAL_CONFERENCE_UPDATE_APPLIED` for a document merged into the
        /// picture, with the version it is at and how many users it holds,
        /// and `SIPRAL_CONFERENCE_UPDATE_ENDED` for a conference the focus
        /// deleted, after which the subscription is being given up. The
        /// picture itself is read with `sipral_subscription_conference` and
        /// `sipral_subscription_conference_user_at`. A document that was late
        /// or repeated raises nothing, and one that followed a lost one is
        /// answered by the stack asking for full state again. `account` and
        /// `call` are `SIPRAL_HANDLE_NONE`; the NOTIFY itself arrived just
        /// before, as `SIPRAL_EVENT_KIND_NOTIFIED`.
        50 = ConferenceChanged, c"conference changed";
        /// The far end typed something on the call's real-time text stream
        /// (RFC 4103), in the order it typed it.
        ///
        /// `call` is the call; `payload.text` holds the text, UTF-8: an
        /// erasure of the last character as BACKSPACE (U+0008), a new line
        /// as LINE SEPARATOR (U+2028), an alert as BELL (U+0007), and a
        /// REPLACEMENT CHARACTER (U+FFFD) for each block of text that was
        /// lost and no redundant copy recovered (RFC 4103 §5.3), counted in
        /// `payload.text.missing`.
        51 = TextReceived, c"text received";
        /// Presence moved: a `presence` subscription was told about the
        /// presentity (RFC 3856), or the state this account publishes (RFC
        /// 3903) was published, refreshed, removed, lapsed or refused.
        ///
        /// `payload.presence.kind` says which. For a subscription,
        /// `payload.presence.subscription` names it and the rest is what the
        /// PIDF document said: open or closed, the first RPID activity, the
        /// first note and the entity; the NOTIFY itself arrived just before,
        /// as `SIPRAL_EVENT_KIND_NOTIFIED`. For a publication, `account`
        /// names the account and
        /// `payload.presence.publication_state` says what became of it, with
        /// the SIP status, the lifetime the compositor granted and when the
        /// stack refreshes it.
        52 = PresenceChanged, c"presence changed";
        /// A transport this stack signals on stopped carrying traffic: the
        /// application said it failed (`sipral_stack_transport_failed`,
        /// `sipral_stack_transport_failed_with`) or closed
        /// (`sipral_stack_stream_closed`), or a stream carried bytes no
        /// message starts with (`sipral_stack_receive_stream`), or a stream
        /// that had answered a keep-alive ping left the next one unanswered
        /// for ten seconds (RFC 5626 §4.4.1, `SIPRAL_TRANSPORT_ERROR_TIMED_OUT`:
        /// the stack has let the connection go, and the socket is the
        /// application's to close).
        ///
        /// Raised by the next poll, before what the loss did to the
        /// registrations and calls on it. `payload.transport_failed` says
        /// which transport, what it spoke, what went wrong and — when TLS
        /// refused the connection — why, as the application's TLS library
        /// said it: untrusted, a name that does not match, expired, or a
        /// handshake refused, with the library's own sentence beside it.
        /// Nothing is sent on the transport until
        /// `sipral_stack_transport_bind` brings it back; a request asked for
        /// meanwhile is `SIPRAL_STATUS_TRANSPORT_DOWN`. `account` and `call`
        /// are `SIPRAL_HANDLE_NONE`: a transport is neither.
        53 = TransportFailed, c"transport failed";
        /// A local conference changed (ABI 0.32): a member joined or left, who
        /// is talking changed, or its recording stopped by itself.
        ///
        /// `payload.local_conference` says which conference and what
        /// happened: `member` is the call that joined or left — or the
        /// conference's own handle for this end — `departure` why it left,
        /// and `members`, `talkers` and `loudest` how the conference stands
        /// now. The talkers themselves are read with
        /// `sipral_local_conference_talker_at`. `account` and `call` are
        /// `SIPRAL_HANDLE_NONE`: a conference is neither.
        54 = LocalConferenceChanged, c"local conference changed";
        /// A DNS lookup is wanted to locate an account's server by RFC 3263
        /// (ABI 0.34): the account named its registrar or its outbound proxy
        /// with `server_uri` rather than an address.
        ///
        /// `payload.locate` names the query: `name`, and `record`, what to
        /// ask it for. Ask the platform's resolver and hand the answer to
        /// `sipral_account_looked_up` — every one, a failure included, since
        /// the procedure waits for each. Several may be outstanding at once,
        /// one per host an SRV answer named. `account` is the account.
        55 = LookupWanted, c"lookup wanted";
        /// An account's server was located, or located again once the last
        /// answer's time-to-live ran out (ABI 0.34): `payload.locate.targets`
        /// is every address the answer named, first the one the account's
        /// requests go to now. `account` is the account.
        56 = Located, c"located";
        /// A lookup of an account's server named no address (ABI 0.34):
        /// `payload.locate.failure` says why, and `retry_in_ms` when the name
        /// is looked up again. A REGISTER that was waiting for it is reported
        /// failed as well, and backs off; an address an earlier answer named
        /// stays in use meanwhile. `account` is the account.
        57 = LocateFailed, c"locate failed";
        /// A request of an account's was challenged by somebody its
        /// password is not for, and the challenge was not answered (ABI
        /// 0.36): RFC 3261 §22.1 gives each protection domain its own
        /// password, and every answer is material for an offline search of
        /// it by whoever chose the nonce.
        ///
        /// `payload.challenge` says why — `refusal` — and who asked:
        /// `server`, where the challenged request went, and `realms`, what
        /// it was challenged for. Raised before the refusal settles the way
        /// any unanswered challenge does — a call ending with the 401 or
        /// 407, a registration failing with `BAD_CREDENTIALS`, a request
        /// inside a call refused — so the application knows why first. A
        /// server that answers under a realm the account was never told of
        /// is what `sipral_account_config_t::realms` is for. `account` is
        /// the account.
        58 = ChallengeDeclined, c"challenge declined";
        /// An account's own server takes an OAuth 2.0 access token (RFC
        /// 8898) and the account has none it would accept: none was
        /// supplied, or the one supplied was refused — expired or revoked,
        /// which `error` says as `SIPRAL_TOKEN_ERROR_INVALID_TOKEN` (ABI 1.2).
        ///
        /// `payload.token` says where a token comes from: `authz_server`, an
        /// `https` URI RFC 8898 §2.1.1 says to check against the
        /// authorization servers the application trusts before going near
        /// it, and `scope`, what the token has to cover. Fetching it is the
        /// application's; hand it over with `sipral_account_set_access_token`.
        /// The refusal settles meanwhile the way an unanswered challenge does
        /// — a registration failing with `BAD_CREDENTIALS`, a call ending
        /// with the 401 or 407 — and `sipral_account_register` registers
        /// again at once with the new token. `account` is the account.
        59 = TokenRequired, c"token required";
    }
}

/// Which arm of [`SipralEventPayload`] each live kind writes, once.
///
/// Not part of the C ABI -- nothing across the boundary reads this, and
/// `sipral_event_kind_name` above is what a C, Swift or C# caller has
/// instead, because they read the one arm `kind` names and no other, the
/// same discipline every application on top of this ABI is written to. The
/// generated Kotlin/JNI shim cannot be: it reads every arm of every event,
/// since nothing in these declarations otherwise says which value of `kind`
/// writes which arm (`tools/abi-gen/src/kotlin.rs`), and the bytes of an
/// arm nothing wrote are not merely meaningless once another arm has
/// written real data into the same union -- a buffer's own pointer,
/// reinterpreted as some other arm's length, is a number with no relation
/// to any allocation, and dereferencing it is what put
/// `sipral-lab-agent-kotlin` on the floor with a `SIGSEGV` inside
/// `NewByteArray`. So the generator reads this, once, to gate every buffer
/// and every whole-record pointer it prints behind the kind that is the one
/// arm this crate ever actually writes it under; `translate` above and the
/// `MediaEvent` match below are what it transcribes, and the assertion
/// after it is what refuses a kind that arrived here having forgotten to.
pub const EVENT_KIND_ARMS: &[(SipralEventKind, &str)] = &[
    (SipralEventKind::Started, "call"),
    (SipralEventKind::RegistrationChanged, "registration"),
    (SipralEventKind::IncomingCall, "call"),
    (SipralEventKind::CallProgress, "call"),
    (SipralEventKind::CallForked, "call"),
    (SipralEventKind::CallConfirmed, "call"),
    (SipralEventKind::SessionChanged, "call"),
    (SipralEventKind::SessionOffered, "call"),
    (SipralEventKind::SessionChangeFailed, "call"),
    (SipralEventKind::TransferRequested, "transfer"),
    (SipralEventKind::TransferProgress, "transfer"),
    (SipralEventKind::TransferDone, "transfer"),
    (SipralEventKind::CallReplaced, "call"),
    (SipralEventKind::CallEnded, "call"),
    (SipralEventKind::SubscriptionChanged, "subscription"),
    (SipralEventKind::MediaStatistics, "media"),
    (SipralEventKind::TransportWanted, "transport_wanted"),
    (SipralEventKind::MediaStalled, "media"),
    (SipralEventKind::AnnouncedCallMissing, "announce"),
    (SipralEventKind::MediaStarted, "media"),
    (SipralEventKind::MediaChanged, "media"),
    (SipralEventKind::MediaResumed, "media"),
    (SipralEventKind::MediaFailed, "media"),
    (SipralEventKind::RecordingStopped, "media"),
    (SipralEventKind::DigitReceived, "media"),
    (SipralEventKind::DtmfSent, "call"),
    (SipralEventKind::Recovery, "recovery"),
    (SipralEventKind::ResolveNeeded, "resolve"),
    (SipralEventKind::Notified, "subscription"),
    (SipralEventKind::CallAnnounced, "announce"),
    (SipralEventKind::MediaSecured, "media"),
    (SipralEventKind::MediaPathChosen, "media"),
    (SipralEventKind::MessageReceived, "message"),
    (SipralEventKind::MessageSent, "message"),
    (SipralEventKind::MessagesWaiting, "message"),
    (SipralEventKind::QualityReportSent, "media"),
    (SipralEventKind::MediaUnjoined, "media"),
    (SipralEventKind::NatMapping, "nat"),
    (SipralEventKind::NatRelay, "relay"),
    (SipralEventKind::Referral, "referral"),
    (SipralEventKind::TurnStream, "turn_stream"),
    (SipralEventKind::AudioDevicesChanged, "audio"),
    (SipralEventKind::CallAddressWanted, "call"),
    (SipralEventKind::StunServer, "stun_server"),
    (SipralEventKind::CallerVerification, "verification"),
    (SipralEventKind::InBandDigit, "media"),
    (SipralEventKind::ProgressDetected, "progress"),
    (SipralEventKind::ConferenceChanged, "conference"),
    (SipralEventKind::TextReceived, "text"),
    (SipralEventKind::PresenceChanged, "presence"),
    (SipralEventKind::TransportFailed, "transport_failed"),
    (SipralEventKind::LocalConferenceChanged, "local_conference"),
    (SipralEventKind::LookupWanted, "locate"),
    (SipralEventKind::Located, "locate"),
    (SipralEventKind::LocateFailed, "locate"),
    (SipralEventKind::ChallengeDeclined, "challenge"),
    (SipralEventKind::TokenRequired, "token"),
];

// every live kind is here exactly once, in `SipralEventKind::ALL`'s own
// order: the build failure a hole, a duplicate or a reordering becomes, the
// same discipline `event_kinds!`'s own assertion holds the numbers to. Slice
// patterns rather than indexing, which this workspace's lints refuse even
// where a `while` beside it already proved every index in bounds.
const fn arms_match(arms: &[(SipralEventKind, &str)], kinds: &[SipralEventKind]) -> bool {
    match (arms, kinds) {
        ([], []) => true,
        ([(arm, _), rest_of_arms @ ..], [kind, rest_of_kinds @ ..]) => {
            *arm as u32 == *kind as u32 && arms_match(rest_of_arms, rest_of_kinds)
        }
        _ => false,
    }
}

const _: () = {
    assert!(
        arms_match(EVENT_KIND_ARMS, SipralEventKind::ALL),
        "EVENT_KIND_ARMS and SipralEventKind::ALL do not agree, in count or in order -- a kind \
         was added, removed or reordered on one side and not the other"
    );
};

codes! {
    /// Where a registration is. Names for `sipral_registration_event_t::state`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralRegistrationState: u32 {
        /// The account is gone, or has never been asked about.
        Unknown = 0,
        /// Configured and not registered. Nothing has been sent.
        Idle = 1,
        /// A REGISTER is in flight and there is no binding yet.
        Registering = 2,
        /// The registrar holds a binding.
        Registered = 3,
        /// A refresh is in flight. The binding stands until it is answered.
        Refreshing = 4,
        /// Something recoverable went wrong and the next attempt is scheduled.
        Retrying = 5,
        /// The binding was given up on purpose.
        Unregistered = 6,
        /// The registrar refused in a way that trying again cannot fix.
        Failed = 7,
        /// A binding a registrar really granted, over a transport that has since
        /// been suspended or lost, which nothing has proved since.
        ///
        /// Not registered, because it is no longer evidence; not failed, because
        /// nothing refused it. A monotonic clock does not advance while a machine
        /// sleeps, so a stack that slept eight hours comes back believing eight
        /// milliseconds passed and every binding still valid — this is the state
        /// that says otherwise, and an application that shows a line as ready on
        /// the strength of it will show it ready when it is not.
        Unverified = 8,
        /// A binding read back from a snapshot rather than granted in this
        /// process. It has not been proved either.
        Restored = 9,
        /// The account was configured with no registrar and never registers:
        /// a trunk that knows this end by its address. It starts here and
        /// stays here, and `sipral_account_register` refuses it. Not idle,
        /// which is one `sipral_account_register` away from a binding.
        NotRegistering = 10,
    }
}

codes! {
    /// Why a registration is not live. Names for
    /// `sipral_registration_event_t::failure`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralRegistrationFailure: u32 {
        /// Nothing failed.
        None = 0,
        /// The registrar refused, and will refuse the same request again.
        Rejected = 1,
        /// The password was wrong, or there was none to answer with.
        BadCredentials = 2,
        /// The registrar is not answering, or says it cannot serve this now.
        Unreachable = 3,
        /// The registrar moved. Following it needs an address, which is the
        /// caller's to resolve.
        Redirected = 4,
        /// The account's `Contact` names an address the registrar cannot
        /// reach this end at — loopback, to a registrar that is not, or the
        /// unspecified address — and nothing was sent (ABI 0.34). Trying
        /// again cannot help until the account is given one it can:
        /// `sipral_account_rebind`, with an address `sipral_advertised_address`
        /// found.
        UnreachableContact = 5,
    }
}

codes! {
    /// Where a call is. Names for `sipral_call_event_t::state`, and what
    /// `sipral_call_state` writes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralCallState: u32 {
        /// The call is gone, or has never been asked about.
        Unknown = 0,
        /// The INVITE has gone and nothing has come back.
        Calling = 1,
        /// Somebody is calling and this end has not answered.
        Incoming = 2,
        /// The far end is ringing, or this end said it is.
        Ringing = 3,
        /// There is audio before anybody answered.
        EarlyMedia = 4,
        /// Up.
        Confirmed = 5,
        /// Up, in order to be transferred: the second leg of an attended transfer.
        Consulting = 6,
        /// A CANCEL or a BYE has gone and is not answered yet.
        Terminating = 7,
        /// Over.
        Terminated = 8,
    }
}

codes! {
    /// Why a call is over. Names for `sipral_call_event_t::end_reason`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralCallEndReason: u32 {
        /// The call is not over.
        None = 0,
        /// This end hung up.
        LocalHangup = 1,
        /// The far end hung up.
        RemoteHangup = 2,
        /// The far end refused it: busy, declined, not found.
        Refused = 3,
        /// Given up before it was answered, from either end.
        Cancelled = 4,
        /// Nothing came back, or the transport died.
        Unreachable = 5,
        /// Another branch of the same fork was kept and this one was not.
        ForkLost = 6,
        /// The branch was still ringing when the answer window closed.
        Abandoned = 7,
        /// The session timer ran out and no refresh arrived.
        Expired = 8,
    }
}

codes! {
    /// Which of the ways this stack accepts a digit reported the one
    /// [`SipralEventKind::DigitReceived`] or [`SipralEventKind::InBandDigit`]
    /// carries. Names for `sipral_media_event_t::source`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDigitSource: u32 {
        /// RFC 4733: a named telephone event in the RTP stream.
        Rtp = 0,
        /// RFC 3261's INFO method (RFC 6086), carrying `application/dtmf-relay`
        /// or `application/dtmf`.
        Info = 1,
        /// The two tones themselves, heard in the far end's audio, for
        /// [`SipralEventKind::InBandDigit`].
        InBand = 2,
    }
}

codes! {
    /// What a [`SipralEventKind::ProgressDetected`] heard. Names for
    /// `sipral_progress_event_t::what`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralProgressKind: u32 {
        /// Never written by this build.
        Unknown = 0,
        /// A call-progress tone of the configured network: `tone` says which
        /// and `at_ms` when its first burst began, from the first frame
        /// listened to.
        Tone = 1,
        /// The special information tone: the call failed, and an
        /// announcement usually follows. `sit_hz_1` to `sit_hz_3` and
        /// `sit_ms_1` to `sit_ms_3` are what was measured, `at_ms` when the
        /// first of the three began.
        SpecialInformation = 2,
        /// Who answered: `verdict`, `reason`, `at_ms` after answer,
        /// `initial_silence_ms`, `greeting_ms` and `words`.
        AnsweredBy = 3,
        /// The beep a machine plays before it records: `frequency_hz`,
        /// `at_ms` when it ended after answer — when the machine starts
        /// recording — and `length_ms`.
        Beep = 4,
    }
}

codes! {
    /// A call-progress tone. Names for `sipral_progress_event_t::tone`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralProgressTone: u32 {
        /// Not a tone, or one this build has no name for.
        Unknown = 0,
        /// The exchange is ready for digits.
        Dial = 1,
        /// The far end is being alerted.
        Ringback = 2,
        /// The far end is busy.
        Busy = 3,
        /// The network is congested: congestion, or reorder.
        Congestion = 4,
        /// A second call is waiting.
        CallWaiting = 5,
        /// The special information tone.
        SpecialInformation = 6,
    }
}

codes! {
    /// Who answered. Names for `sipral_progress_event_t::verdict`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralAmdVerdict: u32 {
        /// Not a verdict.
        Unknown = 0,
        /// A person.
        Human = 1,
        /// An answering machine or a voice mailbox.
        Machine = 2,
        /// The evidence does not say.
        NotSure = 3,
    }
}

codes! {
    /// Which rule decided who answered. Names for
    /// `sipral_progress_event_t::reason`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralAmdReason: u32 {
        /// Not a verdict.
        None = 0,
        /// A short greeting, then silence: somebody said hello and waits.
        ShortGreeting = 1,
        /// More words than a person answers with.
        TooManyWords = 2,
        /// A greeting longer than a person gives.
        LongGreeting = 3,
        /// Nobody spoke.
        InitialSilence = 4,
        /// No rule decided in the time allowed.
        Timeout = 5,
    }
}

codes! {
    /// What a [`SipralEventKind::Recovery`] reports happened, for
    /// `payload.recovery.state`: the two ways a recovery settles — a
    /// registrar answered again, or the ladder ran out of rungs.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralRecoveryOutcome: u32 {
        /// Never written by this build.
        Unknown = 0,
        /// A registrar answered again: what was distrusted is proved.
        Running = 1,
        /// Every rung was climbed and none of them worked.
        GaveUp = 2,
    }
}

codes! {
    /// The last rung a recovery ladder tried before it gave up, for
    /// [`SipralEventKind::Recovery`]'s `payload.recovery.rung`. Meaningful
    /// only when `payload.recovery.state` is
    /// [`SipralRecoveryOutcome::GaveUp`]. The ladder's own last step, giving
    /// up, has no name here: what is reported is the rung before it that
    /// asked for something and went unanswered.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralRecoveryRung: u32 {
        /// The ladder did not give up.
        None = 0,
        /// Nothing was believed any more, and nothing was sent.
        Distrust = 1,
        /// A REGISTER, and a re-SUBSCRIBE for what was demoted alongside it,
        /// went out or could not.
        Reregister = 2,
        /// The application was asked for a transport.
        WantTransport = 3,
        /// The application was asked for an address.
        WantAddress = 4,
    }
}

codes! {
    /// Why a recovery ladder gave up, for [`SipralEventKind::Recovery`]'s
    /// `payload.recovery.reason`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralRecoveryFailure: u32 {
        /// The ladder did not give up.
        None = 0,
        /// Every REGISTER that could be sent was sent and none of them was
        /// answered.
        Unreachable = 1,
        /// A transport was asked for and the application did not bind one.
        NoTransport = 2,
        /// An address was asked for and the application did not supply one.
        Unresolved = 3,
    }
}

record! {
    /// What a [`SipralEventKind::RegistrationChanged`] carries.
    #[derive(Clone, Copy)]
    pub struct SipralRegistrationEvent {
        /// A [`SipralRegistrationState`].
        pub state: Number<SipralRegistrationState>,
        /// A [`SipralRegistrationFailure`], zero when nothing failed.
        pub failure: Number<SipralRegistrationFailure>,
        /// The status the registrar answered with, or zero when none arrived.
        pub status_code: u32,
        /// The binding's granted lifetime, zero unless it is live.
        pub expires_ms: u64,
        /// How long until the refresh, zero unless one is scheduled.
        pub refresh_in_ms: u64,
        /// How long until the next attempt. Only meaningful while the state is
        /// retrying, which is exactly when the stack is going to try again.
        pub retry_in_ms: u64,
    }
}

record! {
    /// What every call event carries.
    ///
    /// Not every member means something in every kind, and the ones that do not
    /// are zero. A zero here always reads as absent rather than as a value.
    #[derive(Clone, Copy)]
    pub struct SipralCallEvent {
        /// A [`SipralCallState`].
        pub state: Number<SipralCallState>,
        /// A [`SipralCallEndReason`], zero while the call is alive.
        pub end_reason: Number<SipralCallEndReason>,
        /// The status a response carried, or zero.
        pub status_code: u32,
        /// The other call this event is also about: the sibling of a fork, or the
        /// call that was replaced. [`SIPRAL_HANDLE_NONE`] otherwise.
        pub other: SipralHandle,
        /// Whether this end has asked the far end to stop sending.
        pub held_here: u32,
        /// Whether the far end has asked this one to.
        pub held_there: u32,
        /// What this end is describing, and how long it is.
        pub local_sdp: *const u8,
        /// How many bytes of it.
        pub local_sdp_len: usize,
        /// And what the far end is.
        pub remote_sdp: *const u8,
        /// How many bytes of it.
        pub remote_sdp_len: usize,
        /// When a refused session change goes out again by itself, zero when it is
        /// not going to.
        pub retry_in_ms: u64,
        /// The `From` URI of the request that created this call: as written in
        /// the header, without the angle brackets and without header
        /// parameters such as `tag`. The same on every event of this call.
        /// Null and zero when this build has none to report.
        pub from_uri: *const u8,
        /// How many bytes of it.
        pub from_uri_len: usize,
        /// That `From`'s display name, quotes and backslash escapes resolved
        /// (RFC 3261 §25.1). Null and zero when the header named none.
        pub from_display: *const u8,
        /// How many bytes of it.
        pub from_display_len: usize,
        /// The `To` URI of the request that created this call, as written in
        /// the header.
        pub to_uri: *const u8,
        /// How many bytes of it.
        pub to_uri_len: usize,
        /// The `Call-ID` of the request that created this call.
        pub call_id: *const u8,
        /// How many bytes of it.
        pub call_id_len: usize,
        /// The digit an INFO this end sent named, for
        /// [`SipralEventKind::DtmfSent`]. Zero for every other kind.
        pub digit: u32,
        /// For [`SipralEventKind::CallEnded`]: the SIP status the far end's
        /// `Reason` (RFC 3326) named — on the BYE or the CANCEL that ended
        /// the call, or on the refusal. 200 on a CANCEL is a forking proxy
        /// saying another phone answered: not a missed call. Zero when no
        /// SIP reason was given. ABI 0.29.
        pub cause_sip: u32,
        /// The same for a Q.850 cause, which a gateway to the telephone
        /// network writes: 16 a normal clearing, 17 a busy line. Zero when
        /// none was given.
        pub cause_q850: u32,
        /// The `text` of the first `Reason` value, unquoted. Null and zero
        /// when there was none.
        pub cause_text: *const u8,
        /// How many bytes of it.
        pub cause_text_len: usize,
        /// Whether the INVITE of a call that came in arrived from a peer its
        /// account trusts (`trusted_peers` on `sipral_account_config_t`).
        /// When it did not, `asserted_uri`, `asserted_display` and
        /// `verstat` say nothing, whatever it carried (RFC 3325 §8). The same
        /// on every event of the call; zero for a call this end placed.
        pub identity_trusted: u32,
        /// Who the network says is calling: the first `P-Asserted-Identity`,
        /// or a calling `Remote-Party-ID` when there is none, as written.
        /// Null and zero when a trusted peer said nothing.
        pub asserted_uri: *const u8,
        /// How many bytes of it.
        pub asserted_uri_len: usize,
        /// That identity's display name. Null and zero when it named none.
        pub asserted_display: *const u8,
        /// How many bytes of it.
        pub asserted_display_len: usize,
        /// A [`SipralVerstat`]: what the
        /// network concluded about the caller's number.
        pub verstat: Number<SipralVerstat>,
        /// The `SIPRAL_PRIVACY_*` bits the caller's `Privacy` asked for.
        pub privacy: u32,
        /// Who the call was last diverted from: the top-most `Diversion`
        /// (RFC 5806), as written. Null and zero when none.
        /// `sipral_call_identity_text` reads the rest.
        pub diverted_from: *const u8,
        /// How many bytes of it.
        pub diverted_from_len: usize,
        /// Why: its `reason`. Null and zero when none.
        pub diversion_reason: *const u8,
        /// How many bytes of it.
        pub diversion_reason_len: usize,
        /// How many `Diversion` values the INVITE carried.
        pub diversion_count: u32,
        /// How many `History-Info` entries it carried.
        pub history_count: u32,
        /// A [`SipralAnswerMode`]: the
        /// INVITE's `Answer-Mode` (RFC 5373).
        pub answer_mode: Number<SipralAnswerMode>,
        /// Whether that field said `;require`: the caller would rather the
        /// call be refused, with a 403, than answered any other way.
        pub answer_mode_required: u32,
        /// The same for `Priv-Answer-Mode`, which RFC 5373 §4.2 holds to a
        /// stricter policy.
        pub priv_answer_mode: u32,
        /// Whether that field said `;require`.
        pub priv_answer_mode_required: u32,
        /// Whether the call asked to be answered without the user —
        /// `Answer-Mode: Auto`, `answer-after` on `Call-Info` or
        /// `Alert-Info`, or `info=alert-autoanswer` — after
        /// `answer_after_ms`. Whether to is the application's policy.
        pub has_answer_after: u32,
        /// After how long, when `has_answer_after` is set.
        pub answer_after_ms: u64,
        /// A [`SipralRingSource`]: whether
        /// the ring says the caller is internal or external.
        pub ring_source: Number<SipralRingSource>,
        /// The first `Alert-Info` URI, without the angle brackets. Null and
        /// zero when none. `sipral_call_identity_text` reads the rest.
        pub alert_info: *const u8,
        /// How many bytes of it.
        pub alert_info_len: usize,
        /// A [`SipralVerificationOutcome`]:
        /// this stack's own verdict on the caller (RFC 8224 §6.2), for an
        /// account that verifies; zero when nothing was verified. Unlike
        /// `verstat`, which is what a network before this end concluded,
        /// this is what this end checked itself. ABI 0.31.
        pub verification: Number<SipralVerificationOutcome>,
        /// A [`SipralAttestation`]: the
        /// level a valid SHAKEN PASSporT claimed.
        pub attestation: Number<SipralAttestation>,
        /// A [`SipralVerificationFailure`]:
        /// why the verdict did not hold. `sipral_call_identity_text` reads
        /// the number it was signed for, its `origid` and its certificate URL.
        pub verification_failure: Number<SipralVerificationFailure>,
    }
}

record! {
    /// What a transfer event carries.
    #[derive(Clone, Copy)]
    pub struct SipralTransferEvent {
        /// What the far end's own call is doing, or zero.
        pub status_code: u32,
        /// Whether the request named a dialog to replace, which is what makes a
        /// transfer attended rather than blind.
        pub attended: u32,
        /// Who to call, as UTF-8. Not NUL-terminated.
        pub target: *const c_char,
        /// How many bytes of it.
        pub target_len: usize,
    }
}

record! {
    /// What a [`SipralEventKind::Referral`] carries: a REFER outside any
    /// dialog, or the word that one lapsed.
    #[derive(Clone, Copy)]
    pub struct SipralReferralEvent {
        /// Zero while the referral waits for the application. Set on the
        /// event that says it lapsed, to what the stack answered it with —
        /// 408, once its transaction ran out unanswered — and then every
        /// other member is zero or null.
        pub status_code: u32,
        /// Whether its `Refer-To` named a dialog to replace (RFC 3891), which
        /// makes it an attended transfer's second half rather than a plain
        /// request to dial.
        pub attended: u32,
        /// Who to call, as UTF-8. Not NUL-terminated.
        pub target: *const c_char,
        /// How many bytes of it.
        pub target_len: usize,
        /// Its `Referred-By` (RFC 3892), as UTF-8 and as the sender wrote it:
        /// who it says is asking. Context for the decision, never proof of
        /// anything. Null when the REFER carried none, or more than the one
        /// §2.1 allows. Not NUL-terminated.
        pub referred_by: *const c_char,
        /// How many bytes of it.
        pub referred_by_len: usize,
    }
}

record! {
    /// What a media event carries.
    ///
    /// As with a call event, not every member means something in every kind, and
    /// the ones that do not are zero or null.
    #[derive(Clone, Copy)]
    pub struct SipralMediaEvent {
        /// A [`SipralCodec`]: what the negotiation
        /// settled on, zero where the event is not about a codec.
        pub codec: Number<SipralCodec>,
        /// A [`SipralDirection`]: which way audio
        /// may flow, as seen from here.
        pub direction: Number<SipralDirection>,
        /// How long the stream has been silent, for a stall and for its recovery.
        pub silent_for_ms: u64,
        /// How much audio reached the file, for a recording that stopped by
        /// itself.
        pub recorded_ms: u64,
        /// A [`SipralMediaFault`], zero when
        /// nothing failed.
        pub fault: Number<SipralMediaFault>,
        /// The sentence behind `fault`, as UTF-8. Not NUL-terminated, and null
        /// when nothing failed.
        pub reason: *const c_char,
        /// How many bytes of it.
        pub reason_len: usize,
        /// What the stream cost, for the kind that carries it, and null for every
        /// other. It belongs to the library and lives as long as the callback.
        pub statistics: *const SipralStreamStats,
        /// The key the far end pressed, as its character, and zero for an event
        /// no keypad has a key for.
        pub digit: u32,
        /// The RFC 4733 event code behind `digit`. Codes at and above sixteen are
        /// real events that are not keys.
        pub event_code: u32,
        /// How long the far end held it. Zero either for an `application/dtmf`
        /// INFO, which carries no duration at all, or for the other form's
        /// own `Duration=0` — a peer that held the key for no time at all.
        /// The Rust facade keeps the two apart; this ABI does not.
        pub held_ms: u64,
        /// A [`SipralSrtpSuite`]: the transform
        /// this call's media is protected with, for
        /// [`SipralEventKind::MediaSecured`] and zero on every other kind.
        pub suite: Number<SipralSrtpSuite>,
        /// A [`SipralDigitSource`]: which of the two ways this stack accepts a
        /// digit reported this one, for [`SipralEventKind::DigitReceived`].
        pub source: Number<SipralDigitSource>,
        /// Whether the RFC 6035 PUBLISH left this end, for
        /// [`SipralEventKind::QualityReportSent`] and zero on every other
        /// kind. Not whether a collector accepted it.
        pub quality_report_sent: u32,
        /// A [`SipralKeyExchange`]: how
        /// the call's keys were exchanged, for
        /// [`SipralEventKind::MediaStarted`], [`SipralEventKind::MediaChanged`]
        /// and [`SipralEventKind::MediaSecured`], which carry the encryption
        /// report of the call's stream: this, `encrypted`, `authenticated`,
        /// and `suite` from then on. ABI 0.31.
        pub key_exchange: Number<SipralKeyExchange>,
        /// Whether the stream is encrypted, now. Zero at the start of a
        /// DTLS-SRTP call, whose keys arrive with
        /// [`SipralEventKind::MediaSecured`].
        pub encrypted: u32,
        /// Whether the key exchange authenticated the far end: a DTLS-SRTP
        /// handshake that checked its certificate against the signalled
        /// fingerprint. Never for SDES.
        pub authenticated: u32,
    }
}

record! {
    /// What a [`SipralEventKind::ProgressDetected`] carries. `what` says
    /// which of the other members mean anything; the rest are zero.
    #[derive(Clone, Copy)]
    pub struct SipralProgressEvent {
        /// A [`SipralProgressKind`].
        pub what: Number<SipralProgressKind>,
        /// A [`SipralProgressTone`], for a tone.
        pub tone: Number<SipralProgressTone>,
        /// A [`SipralAmdVerdict`], for who answered.
        pub verdict: Number<SipralAmdVerdict>,
        /// A [`SipralAmdReason`], for who answered.
        pub reason: Number<SipralAmdReason>,
        /// When, in milliseconds: a tone's first burst from the first frame
        /// listened to; the decision after answer; the beep's end after
        /// answer.
        pub at_ms: u64,
        /// How long after answer the first word began, or the silence if
        /// nobody spoke.
        pub initial_silence_ms: u64,
        /// From the first word's start to the last word's end.
        pub greeting_ms: u64,
        /// How many words were heard.
        pub words: u32,
        /// The beep's frequency, in hertz, as measured.
        pub frequency_hz: u32,
        /// How long the beep sounded.
        pub length_ms: u64,
        /// The special information tone's first frequency, as measured.
        pub sit_hz_1: u32,
        /// Its second.
        pub sit_hz_2: u32,
        /// Its third.
        pub sit_hz_3: u32,
        /// How long the first sounded.
        pub sit_ms_1: u32,
        /// The second.
        pub sit_ms_2: u32,
        /// The third.
        pub sit_ms_3: u32,
    }
}

record! {
    /// What a [`SipralEventKind::Recovery`] carries: the lifecycle machine
    /// settling, either by proving the path again or by giving the ladder up.
    #[derive(Clone, Copy)]
    pub struct SipralRecoveryEvent {
        /// A [`SipralRecoveryOutcome`].
        pub state: Number<SipralRecoveryOutcome>,
        /// A [`SipralRecoveryRung`]: the last rung tried. Zero unless `state`
        /// is [`SipralRecoveryOutcome::GaveUp`].
        pub rung: Number<SipralRecoveryRung>,
        /// A [`SipralRecoveryFailure`]. Zero unless `state` is
        /// [`SipralRecoveryOutcome::GaveUp`].
        pub reason: Number<SipralRecoveryFailure>,
        /// Bindings the ladder never proved. Meaningful only when `state` is
        /// [`SipralRecoveryOutcome::GaveUp`].
        pub unverified: u32,
    }
}

record! {
    /// What a [`SipralEventKind::CallAnnounced`] and a
    /// [`SipralEventKind::AnnouncedCallMissing`] carry.
    #[derive(Clone, Copy)]
    pub struct SipralAnnounceEvent {
        /// Which announcement. Minted by `sipral_account_announce`, and it
        /// names nothing once either of these two events has been raised
        /// about it.
        pub announcement: SipralHandle,
        /// How long the call was waited for, in milliseconds. Meaningful only
        /// on [`SipralEventKind::AnnouncedCallMissing`].
        pub waited_ms: u64,
    }
}

record! {
    /// What a [`SipralEventKind::SubscriptionChanged`] and a
    /// [`SipralEventKind::Notified`] carry.
    ///
    /// The subscription names itself here rather than in `sipral_event_t`,
    /// which has room for an account and a call and not for every kind of
    /// handle this ABI mints. The account is not carried at all: a caller
    /// asked for the subscription on one, and a sibling from a fork belongs
    /// to the same one as the subscription it forked from.
    #[derive(Clone, Copy)]
    pub struct SipralSubscriptionEvent {
        /// Which subscription. Minted by `sipral_account_subscribe`, or by
        /// this ABI when a fork made one nobody asked for.
        pub subscription: SipralHandle,
        /// A [`SipralSubscriptionState`].
        pub state: Number<SipralSubscriptionState>,
        /// A [`SipralSubscriptionEnd`]:
        /// why it is not live. Zero while it is.
        pub reason: Number<SipralSubscriptionEnd>,
        /// The SIP status a response gave for it, when one did. Zero
        /// otherwise.
        pub status_code: u32,
        /// Whether the notification carried dialog state this build could
        /// read. Zero on every kind but [`SipralEventKind::Notified`], and
        /// zero there for a body in any other form or none at all.
        pub has_dialog_info: u32,
        /// What the notifier granted, in milliseconds. Zero until one has.
        pub expires_ms: u64,
        /// How long until this stack refreshes it, in milliseconds.
        pub refresh_in_ms: u64,
        /// How long until the next attempt, in milliseconds, when the state
        /// is `SIPRAL_SUBSCRIPTION_STATE_RETRYING`. Zero otherwise, which
        /// includes every subscription that has ended for good.
        pub retry_in_ms: u64,
        /// The subscription this one forked from
        /// ([RFC 6665 §4.1.4]), or `SIPRAL_HANDLE_NONE`. A sibling is a
        /// subscription of its own from here on, with its own dialog, its own
        /// refresh and its own state; RFC 4235 §3.9 makes this the normal case
        /// for dialog state, one per device the watched address is registered
        /// on.
        ///
        /// [RFC 6665 §4.1.4]: https://www.rfc-editor.org/rfc/rfc6665#section-4.1.4
        pub forked_from: SipralHandle,
    }
}

record! {
    /// What a [`SipralEventKind::TransportWanted`] carries: a request RFC
    /// 3261 §18.1.1 would not let out over a datagram, and nowhere open to
    /// send it instead.
    #[derive(Clone, Copy)]
    pub struct SipralTransportWantedEvent {
        /// What to open, as a
        /// [`SipralTransport`]. Zero for a
        /// protocol this build has no number for, which
        /// `sipral_stack_transport_bind` then cannot be asked to open
        /// either — nothing this build originates ever measures against a
        /// protocol like that, so this is the layer below having grown one
        /// rather than a caller mistake.
        pub protocol: Number<SipralTransport>,
        /// Where to, as `host:port`. Not NUL-terminated.
        pub destination: *const c_char,
        /// How many bytes of it.
        pub destination_len: usize,
        /// How large the request came out, in bytes as they would have gone
        /// on the wire.
        pub request_bytes: usize,
        /// The largest it could have been and still fitted a datagram: the
        /// path MTU less the §18.1.1 headroom where the MTU is known, 1300
        /// where it is not.
        pub limit_bytes: u32,
    }
}

record! {
    /// What a [`SipralEventKind::ResolveNeeded`] carries: the name a dialog's
    /// next hop is written as, and the handle an answer takes.
    #[derive(Clone, Copy)]
    pub struct SipralResolveEvent {
        /// The dialog this is about, and what
        /// [`sipral_stack_resolved`](crate::resolve::sipral_stack_resolved)
        /// is answered with. Minted by the library and valid while the dialog
        /// is; answering for one that has ended is
        /// `SIPRAL_STATUS_STALE_HANDLE` and changes nothing.
        pub dialog: SipralHandle,
        /// The host to resolve, as the URI spells it — a name, or a literal
        /// address, which is still reported because the flow the dialog is on
        /// may legitimately differ from it. An IPv6 literal carries its
        /// brackets (RFC 3261 §19.1.1). Not NUL-terminated.
        pub host: *const c_char,
        /// How many bytes of it.
        pub host_len: usize,
        /// The port the URI gave, or zero for none. Zero is not 5060: RFC
        /// 3263 §4.2 leaves the choice to whoever does the lookup, because
        /// an SRV answer carries a port of its own.
        pub port: u32,
        /// The transport the URI or the scheme named, as a
        /// [`SipralTransport`], or zero for
        /// neither — which leaves §4.1's NAPTR step to the caller, and is
        /// also what a protocol this build has no number for reads as.
        pub protocol: Number<SipralTransport>,
    }
}

record! {
    /// What a [`SipralEventKind::MessageReceived`], a
    /// [`SipralEventKind::MessageSent`] and a
    /// [`SipralEventKind::MessagesWaiting`] carry.
    ///
    /// One struct for all three, the way [`SipralSubscriptionEvent`] answers
    /// for two kinds: a member meaningless on one kind is zero or null there.
    /// The whole request or response, when there is one, rides in
    /// `sipral_event_t::message` instead — `attach` points it at the same
    /// bytes `content_type` and `body` are read out of, so both are valid for
    /// exactly as long as the callback is.
    #[derive(Clone, Copy)]
    pub struct SipralMessageEvent {
        /// [`SipralEventKind::MessageSent`]: which send, minted by
        /// `sipral_account_message`. [`SIPRAL_HANDLE_NONE`] on the other two
        /// kinds, and names nothing once this event has been raised about it.
        pub message: SipralHandle,
        /// [`SipralEventKind::MessagesWaiting`]: which subscription reported
        /// it. [`SIPRAL_HANDLE_NONE`] on the other two kinds, which are not
        /// subscriptions.
        pub subscription: SipralHandle,
        /// [`SipralEventKind::MessageSent`]: the final status. Zero on the
        /// other two kinds.
        pub status_code: u32,
        /// [`SipralEventKind::MessageReceived`]: the `Content-Type` of the
        /// body, as written. Null on the other two kinds, and on a MESSAGE
        /// with no body at all.
        pub content_type: *const c_char,
        /// How many bytes of it.
        pub content_type_len: usize,
        /// [`SipralEventKind::MessageReceived`]: the body. Null the same as
        /// `content_type`.
        pub body: *const u8,
        /// How many bytes of it.
        pub body_len: usize,
        /// [`SipralEventKind::MessagesWaiting`]: RFC 3842 §3.5's status
        /// line, 1 for `yes` and 0 for `no`. Meaningless on the other two
        /// kinds.
        pub waiting: u32,
        /// [`SipralEventKind::MessagesWaiting`]: new messages of the
        /// `voice-message` class (RFC 3458 §6.2), the one a phone's
        /// message-waiting light is about. Zero when the body named no
        /// `voice-message` line, which a boolean-only notification does.
        pub new_messages: u32,
        /// The same, old.
        pub old_messages: u32,
        /// New messages flagged urgent.
        pub urgent_new_messages: u32,
        /// Old messages flagged urgent.
        pub urgent_old_messages: u32,
        /// [`SipralEventKind::MessagesWaiting`]: `Message-Account`, when the
        /// notifier sent one (RFC 3842 §3.5 makes it mandatory only for a
        /// subscription to a group or collection of accounts). Null on the
        /// other two kinds, and on a body that named none.
        pub message_account: *const c_char,
        /// How many bytes of it.
        pub message_account_len: usize,
    }
}

record! {
    /// What a [`SipralEventKind::CallerVerification`] carries: one half of
    /// the verification of who is calling (RFC 8224 §6.2).
    #[derive(Clone, Copy)]
    pub struct SipralVerificationEvent {
        /// A [`SipralVerificationStage`]:
        /// the certificate is wanted, or the verdict is in.
        pub stage: Number<SipralVerificationStage>,
        /// A [`SipralVerificationOutcome`],
        /// for a verdict.
        pub outcome: Number<SipralVerificationOutcome>,
        /// A [`SipralVerificationFailure`]:
        /// why it did not hold.
        pub failure: Number<SipralVerificationFailure>,
        /// A [`SipralAttestation`]: the
        /// level a valid SHAKEN PASSporT claimed.
        pub attestation: Number<SipralAttestation>,
        /// A [`SipralVerstat`]: the `verstat`
        /// this verdict comes to (3GPP TS 24.229).
        pub verstat: Number<SipralVerstat>,
        /// The response RFC 8224 §6.2.2 prescribes for the failure, zero for
        /// a valid one. Sent only when `refused` is set.
        pub response_code: u32,
        /// Whether the call was refused with it, which only a strict account
        /// does.
        pub refused: u32,
        /// The URL of the certificate: the one to fetch, or the one that was
        /// verified. UTF-8, not NUL-terminated; null and zero when there is
        /// none.
        pub certificate_url: *const c_char,
        /// How many bytes of it.
        pub certificate_url_len: usize,
        /// The calling number a valid PASSporT was signed for, canonical.
        pub orig: *const c_char,
        /// How many bytes of it.
        pub orig_len: usize,
        /// The origination identifier a valid SHAKEN PASSporT claimed (RFC
        /// 8588 §5), a UUID.
        pub origid: *const c_char,
        /// How many bytes of it.
        pub origid_len: usize,
        /// Why it did not hold, in more words than `failure`, for a log.
        pub detail: *const c_char,
        /// How many bytes of it.
        pub detail_len: usize,
    }
}

codes! {
    /// Why an account's password did not answer a challenge. Names for
    /// `sipral_challenge_event_t::refusal`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralChallengeRefusal: u32 {
        /// Never written by this build.
        Unknown = 0,
        /// The challenged request went somewhere other than the account's
        /// own server — its registrar, or the outbound proxy of an account
        /// that does not register — so whoever asked is the far end of a
        /// call, or a peer reached directly.
        NotTheAccountsServer = 1,
        /// The account's server asked for a realm that is not the
        /// account's: not one of `sipral_account_config_t::realms`, or, with
        /// none named, neither the one its server first challenged with nor
        /// one its REGISTERs were challenged with. A proxy passing on a far
        /// end's own challenge looks like this, and so does an SBC that
        /// challenges calls under a realm of its own.
        NotTheAccountsRealm = 2,
    }
}

codes! {
    /// What an account's server said was wrong with the access token it
    /// was given (RFC 6750 §3.1, RFC 8898 §4). Names for
    /// `sipral_token_event_t::error`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralTokenError: u32 {
        /// The server named no error: no token was offered yet.
        None = 0,
        /// `invalid_request`: the request was malformed.
        InvalidRequest = 1,
        /// `invalid_token`: the token is expired, revoked, malformed or
        /// otherwise invalid. A new one is needed.
        InvalidToken = 2,
        /// `insufficient_scope`: the token does not cover what was asked;
        /// `scope` says what would.
        InsufficientScope = 3,
        /// `invalid_scope`.
        InvalidScope = 4,
        /// Another code, as written in `error_code`.
        Other = 5,
    }
}

record! {
    /// What a [`SipralEventKind::TokenRequired`] carries: the `Bearer`
    /// challenge of an account's server (RFC 8898 §4), and where it came
    /// from (ABI 1.2). Every text is UTF-8 and not NUL-terminated; one the
    /// server left out is empty.
    #[derive(Clone, Copy)]
    pub struct SipralTokenEvent {
        /// A [`SipralTokenError`].
        pub error: Number<SipralTokenError>,
        /// A `SipralToggle`: `SIPRAL_TOGGLE_ON` when a proxy asked (407,
        /// answered in `Proxy-Authorization`), `SIPRAL_TOGGLE_OFF` when the
        /// registrar or the far end did (401).
        pub proxy: Number<SipralToggle>,
        /// Where the challenged request went, and the challenge came from,
        /// as `host:port`.
        pub server: *const c_char,
        /// How many bytes of it.
        pub server_len: usize,
        /// The protection domain, empty when the challenge named none.
        pub realm: *const c_char,
        /// How many bytes of it.
        pub realm_len: usize,
        /// The scope the token has to carry: space-separated strings the
        /// authorization server defines (RFC 6749 §3.3).
        pub scope: *const c_char,
        /// How many bytes of it.
        pub scope_len: usize,
        /// The authorization server: an `https` URI. A value that was not
        /// one is left out.
        pub authz_server: *const c_char,
        /// How many bytes of it.
        pub authz_server_len: usize,
        /// The `error` code as the server wrote it, for `Other`.
        pub error_code: *const c_char,
        /// How many bytes of it.
        pub error_code_len: usize,
    }
}

record! {
    /// What a [`SipralEventKind::ChallengeDeclined`] carries: who asked for
    /// the account's password, and why it was not given (ABI 0.36).
    #[derive(Clone, Copy)]
    pub struct SipralChallengeEvent {
        /// A [`SipralChallengeRefusal`].
        pub refusal: Number<SipralChallengeRefusal>,
        /// Where the challenged request went, and the refusal came from, as
        /// `host:port`. Not NUL-terminated.
        pub server: *const c_char,
        /// How many bytes of it.
        pub server_len: usize,
        /// The realms it was challenged for, each on a line of its own,
        /// separated by line feeds: a realm may hold a comma, and never a
        /// line break. UTF-8, not NUL-terminated.
        pub realms: *const c_char,
        /// How many bytes of it.
        pub realms_len: usize,
    }
}

record! {
    /// The arm of an event that its kind names.
    ///
    /// The whole union is zeroed before that one arm is written, so every
    /// byte past the arm, and every byte of another arm, reads as zero —
    /// which is what a member appended to an arm later reads as from a
    /// library built before it. Another arm still means nothing for this
    /// kind.
    #[derive(Clone, Copy)]
    pub union SipralEventPayload {
        /// For [`SipralEventKind::RegistrationChanged`].
        pub registration: SipralRegistrationEvent,
        /// For every call kind.
        pub call: SipralCallEvent,
        /// For [`SipralEventKind::TransferRequested`],
        /// [`SipralEventKind::TransferProgress`] and
        /// [`SipralEventKind::TransferDone`].
        pub transfer: SipralTransferEvent,
        /// For every media kind: started, changed, stalled, resumed, failed, the
        /// end-of-call statistics, and a recording that stopped by itself.
        pub media: SipralMediaEvent,
        /// For [`SipralEventKind::Recovery`].
        pub recovery: SipralRecoveryEvent,
        /// For [`SipralEventKind::TransportWanted`].
        pub transport_wanted: SipralTransportWantedEvent,
        /// For [`SipralEventKind::SubscriptionChanged`] and
        /// [`SipralEventKind::Notified`].
        pub subscription: SipralSubscriptionEvent,
        /// For [`SipralEventKind::CallAnnounced`] and
        /// [`SipralEventKind::AnnouncedCallMissing`].
        pub announce: SipralAnnounceEvent,
        /// For [`SipralEventKind::ResolveNeeded`].
        pub resolve: SipralResolveEvent,
        /// For [`SipralEventKind::MessageReceived`],
        /// [`SipralEventKind::MessageSent`] and
        /// [`SipralEventKind::MessagesWaiting`].
        pub message: SipralMessageEvent,
        /// For [`SipralEventKind::NatMapping`].
        pub nat: SipralNatEvent,
        /// For [`SipralEventKind::NatRelay`].
        pub relay: SipralNatRelayEvent,
        /// For [`SipralEventKind::Referral`].
        pub referral: SipralReferralEvent,
        /// For [`SipralEventKind::TurnStream`].
        pub turn_stream: SipralTurnStreamEvent,
        /// For [`SipralEventKind::AudioDevicesChanged`].
        pub audio: SipralAudioEvent,
        /// For [`SipralEventKind::StunServer`].
        pub stun_server: SipralStunServerEvent,
        /// For [`SipralEventKind::CallerVerification`].
        pub verification: SipralVerificationEvent,
        /// For [`SipralEventKind::ProgressDetected`].
        pub progress: SipralProgressEvent,
        /// For [`SipralEventKind::ConferenceChanged`].
        pub conference: SipralConferenceEvent,
        /// For [`SipralEventKind::TextReceived`].
        pub text: SipralTextEvent,
        /// For [`SipralEventKind::PresenceChanged`].
        pub presence: SipralPresenceEvent,
        /// For [`SipralEventKind::TransportFailed`].
        pub transport_failed: SipralTransportFailedEvent,
        /// For [`SipralEventKind::LocalConferenceChanged`].
        pub local_conference: SipralLocalConferenceEvent,
        /// For [`SipralEventKind::LookupWanted`], [`SipralEventKind::Located`]
        /// and [`SipralEventKind::LocateFailed`].
        pub locate: SipralLocateEvent,
        /// For [`SipralEventKind::ChallengeDeclined`].
        pub challenge: SipralChallengeEvent,
        /// For [`SipralEventKind::TokenRequired`].
        pub token: SipralTokenEvent,
    }
}

record! {
    /// Something the library has to tell the application.
    ///
    /// The pointer handed to the callback is the library's, and it is valid for
    /// the duration of that call and no longer. `size` says how much of the
    /// struct this build filled in, and a binding reads no further than that. The
    /// union stays the last member for the same reason: an arm that grows grows
    /// the tail, which is the one place a released struct may change.
    #[derive(Clone, Copy)]
    pub struct SipralEvent {
        /// How many bytes of this struct are meaningful.
        pub size: usize,
        /// The stack it is about.
        pub stack: SipralHandle,
        /// What it is.
        pub kind: SipralEventKind,
        /// The account it is about, or [`SIPRAL_HANDLE_NONE`].
        pub account: SipralHandle,
        /// The call it is about, or [`SIPRAL_HANDLE_NONE`].
        pub call: SipralHandle,
        /// The SIP message behind it, whole and unparsed, when there is one.
        ///
        /// A reason phrase, a `Retry-After`, the `Contact` of a redirect and the
        /// caller's display name all live here and none of them is worth a member
        /// of its own. Null when the event came from no single message.
        pub message: *const u8,
        /// How many bytes of it.
        pub message_len: usize,
        /// The arm [`SipralEvent::kind`] names.
        pub payload: SipralEventPayload,
    }
}

alias! {
    /// The one callback a stack has.
    ///
    /// It is called from inside `sipral_stack_poll`, on the thread that called
    /// it, with the `user_data` the stack was created with, and never on two
    /// threads at once for one stack. It must not unwind. Nothing is held
    /// while it runs, so it may call back into the library, the stack it was
    /// given included (`docs/08-ffi.md`, "The shape").
    pub type SipralEventCallback = fn(event: *const SipralEvent, user_data: *mut c_void);
}

/// A [`SipralEventPayload`] with the one arm named written, and every other
/// byte of the union zero.
///
/// `SipralEventPayload { call: value }`'s own construction only ever writes
/// `value`'s own bytes; nothing sets the rest of the union, up to its own
/// size (the size of its largest arm), and a fresh value's unwritten bytes
/// are whatever the compiler put on the stack there before -- not
/// necessarily zero, and not the same twice. Every binding but Kotlin's
/// reads the one arm `kind` names and nothing past it, so that was never
/// reached; the generated Kotlin/JNI shim reads every arm of every event,
/// because nothing in these declarations says which value of `kind` writes
/// which arm (`tools/abi-gen/src/kotlin.rs`), and a buffer pointer read out
/// of bytes nothing wrote is not a value with no meaning, the way an
/// unwritten integer is -- it is an address nothing owns, and JNI dies on
/// it exactly as it found here (`SIGSEGV` inside `NewByteArray`, from a
/// `Kotlin lab agent`'s length reading a genuinely negative array size).
macro_rules! payload {
    ($arm:ident: $value:expr) => {{
        // Safety: every member of every arm is a plain integer or a
        // pointer with its own length beside it, and the all-zero bit
        // pattern is already the value each of those reads as "nothing" on
        // its own -- a null pointer, a zero length, a zero code -- so it is
        // a valid value of every arm this union has, whichever is read.
        let mut zeroed: SipralEventPayload = unsafe { std::mem::zeroed() };
        zeroed.$arm = $value;
        zeroed
    }};
}

impl SipralEvent {
    /// An event with nothing in it but its kind, for a kind to fill in.
    ///
    /// The payload is written whole, never a member at a time: a union member
    /// is a place the library has to know it owns before it writes through it,
    /// and one assignment of the arm the kind names is the way to be sure.
    // moved in whole, for the reason above: the union is built at the call
    // site and assigned here once, and a reference would only add a copy
    #[allow(clippy::large_types_passed_by_value)]
    fn of(stack: SipralHandle, kind: SipralEventKind, payload: SipralEventPayload) -> Self {
        Self {
            size: size_of::<Self>(),
            stack,
            kind,
            account: SIPRAL_HANDLE_NONE,
            call: SIPRAL_HANDLE_NONE,
            message: std::ptr::null(),
            message_len: 0,
            payload,
        }
    }
}

impl SipralMediaEvent {
    /// Nothing said about anything, for a kind to fill in.
    const fn empty() -> Self {
        Self {
            codec: 0,
            direction: 0,
            silent_for_ms: 0,
            recorded_ms: 0,
            fault: 0,
            reason: std::ptr::null(),
            reason_len: 0,
            statistics: std::ptr::null(),
            digit: 0,
            event_code: 0,
            held_ms: 0,
            suite: 0,
            source: SipralDigitSource::Rtp as u32,
            quality_report_sent: 0,
            key_exchange: 0,
            encrypted: 0,
            authenticated: 0,
        }
    }
}

impl SipralCallEvent {
    /// Nothing said about anything, for a kind to fill in.
    const fn empty() -> Self {
        Self {
            state: SipralCallState::Unknown as u32,
            end_reason: SipralCallEndReason::None as u32,
            status_code: 0,
            other: SIPRAL_HANDLE_NONE,
            held_here: 0,
            held_there: 0,
            local_sdp: std::ptr::null(),
            local_sdp_len: 0,
            remote_sdp: std::ptr::null(),
            remote_sdp_len: 0,
            retry_in_ms: 0,
            from_uri: std::ptr::null(),
            from_uri_len: 0,
            from_display: std::ptr::null(),
            from_display_len: 0,
            to_uri: std::ptr::null(),
            to_uri_len: 0,
            call_id: std::ptr::null(),
            call_id_len: 0,
            digit: 0,
            cause_sip: 0,
            cause_q850: 0,
            cause_text: std::ptr::null(),
            cause_text_len: 0,
            identity_trusted: 0,
            asserted_uri: std::ptr::null(),
            asserted_uri_len: 0,
            asserted_display: std::ptr::null(),
            asserted_display_len: 0,
            verstat: 0,
            privacy: 0,
            diverted_from: std::ptr::null(),
            diverted_from_len: 0,
            diversion_reason: std::ptr::null(),
            diversion_reason_len: 0,
            diversion_count: 0,
            history_count: 0,
            answer_mode: 0,
            answer_mode_required: 0,
            priv_answer_mode: 0,
            priv_answer_mode_required: 0,
            has_answer_after: 0,
            answer_after_ms: 0,
            ring_source: 0,
            alert_info: std::ptr::null(),
            alert_info_len: 0,
            verification: 0,
            attestation: 0,
            verification_failure: 0,
        }
    }
}

/// The first event on every stack.
pub(crate) fn started(stack: SipralHandle) -> SipralEvent {
    SipralEvent::of(
        stack,
        SipralEventKind::Started,
        payload!(call: SipralCallEvent::empty()),
    )
}

/// What a STUN server said about one socket, as C reads it. The pointers in
/// `payload` point into text the caller keeps beside the event.
#[cfg(feature = "stun")]
pub(crate) fn nat_mapping(stack: SipralHandle, payload: SipralNatEvent) -> SipralEvent {
    SipralEvent::of(stack, SipralEventKind::NatMapping, payload!(nat: payload))
}

/// What happened to the STUN servers a stack asks, as C reads it. The
/// pointers in `payload` point into text the caller keeps beside the event.
#[cfg(feature = "stun")]
pub(crate) fn stun_server(stack: SipralHandle, payload: SipralStunServerEvent) -> SipralEvent {
    SipralEvent::of(
        stack,
        SipralEventKind::StunServer,
        payload!(stun_server: payload),
    )
}

/// A transport lost, as C reads it. The pointer in `payload` points into
/// text the caller keeps beside the event.
pub(crate) fn transport_failed(
    stack: SipralHandle,
    payload: SipralTransportFailedEvent,
) -> SipralEvent {
    SipralEvent::of(
        stack,
        SipralEventKind::TransportFailed,
        payload!(transport_failed: payload),
    )
}

/// What a TURN server said about one media socket's relay, as C reads it.
/// The pointers in `payload` point into text the caller keeps beside the
/// event.
#[cfg(all(feature = "stun", feature = "ice"))]
pub(crate) fn nat_relay(stack: SipralHandle, payload: SipralNatRelayEvent) -> SipralEvent {
    SipralEvent::of(stack, SipralEventKind::NatRelay, payload!(relay: payload))
}

/// What a media socket's connection to its TURN server is to do, as C
/// reads it. The pointers in `payload` point into text the caller keeps
/// beside the event.
#[cfg(all(feature = "stun", feature = "ice"))]
pub(crate) fn turn_stream(stack: SipralHandle, payload: SipralTurnStreamEvent) -> SipralEvent {
    SipralEvent::of(
        stack,
        SipralEventKind::TurnStream,
        payload!(turn_stream: payload),
    )
}

/// What a local conference did, as C reads it.
pub(crate) fn local_conference_changed(
    stack: SipralHandle,
    payload: SipralLocalConferenceEvent,
) -> SipralEvent {
    SipralEvent::of(
        stack,
        SipralEventKind::LocalConferenceChanged,
        payload!(local_conference: payload),
    )
}

/// What the audio engine's devices did, as C reads it.
pub(crate) fn audio_changed(stack: SipralHandle, payload: SipralAudioEvent) -> SipralEvent {
    SipralEvent::of(
        stack,
        SipralEventKind::AudioDevicesChanged,
        payload!(audio: payload),
    )
}

/// Everything one translation needs to reach.
pub(crate) struct Vocabulary<'a> {
    pub(crate) stack: SipralHandle,
    pub(crate) agent: &'a UserAgent,
    pub(crate) accounts: &'a mut Names<sipral_ua::AccountId>,
    pub(crate) calls: &'a mut Names<CallHandle>,
    pub(crate) subscriptions: &'a mut Names<sipral_ua::SubscriptionHandle>,
    pub(crate) messages: &'a mut Names<sipral_ua::MessageHandle>,
    pub(crate) announcements: &'a mut Names<sipral_ua::AnnouncementId>,
    pub(crate) dialogs: &'a mut Names<sipral_core::transaction::DialogId>,
    /// Who is on every call this stack still knows, fixed when each was
    /// created.
    pub(crate) identities: &'a HashMap<CallHandle, Arc<CallIdentity>>,
    /// The identity `call_payload` last attached, if any, so that whoever
    /// queues the event this translation produces can keep its bytes alive
    /// for as long as the delivery takes.
    pub(crate) raised_identity: Option<Arc<CallIdentity>>,
}

/// Say a user agent event the way C says it.
///
/// `None` for one this ABI has no word for. Nothing is invented: an event that
/// would arrive carrying only its own existence tells a binding nothing it can
/// act on, and the poll result counts them instead so that the gap is a number
/// rather than a silence.
///
/// The pointers in what comes back borrow from `event`, and `transport`
/// carries one more this ABI has to point at that `event` holds no bytes for:
/// [`SipralEventKind::TransportWanted`]'s destination or
/// [`SipralEventKind::ResolveNeeded`]'s host, formatted by
/// [`text_to_point_at`] before this is called, since neither has bytes of its
/// own in the shape C reads. Both have to outlive the callback this is handed
/// to.
pub(crate) fn translate(
    known: &mut Vocabulary<'_>,
    event: &UaEvent,
    transport: Option<&str>,
) -> Option<SipralEvent> {
    if let Some(out) = about_registration(known, event) {
        return Some(out);
    }
    if let Some(out) = about_a_call(known, event) {
        return Some(out);
    }
    if let Some(out) = about_a_session(known, event) {
        return Some(out);
    }
    if let Some(out) = about_a_call_ending(known, event) {
        return Some(out);
    }
    if let Some(out) = about_a_transfer(known, event) {
        return Some(out);
    }
    if let Some(out) = about_a_transport(known, event, transport) {
        return Some(out);
    }
    if let Some(out) = about_a_subscription(known, event) {
        return Some(out);
    }
    if let Some(out) = about_a_message(known, event) {
        return Some(out);
    }
    if let Some(out) = about_an_announcement(known, event) {
        return Some(out);
    }
    if let Some(out) = about_a_verification(known, event) {
        return Some(out);
    }
    if let Some(out) = about_a_resolve(known, event, transport) {
        return Some(out);
    }
    if let Some(out) = about_conference_or_presence(known, event) {
        return Some(out);
    }
    if let Some(out) = about_a_location(known, event, transport) {
        return Some(out);
    }
    if let Some(out) = about_a_challenge(known, event, transport) {
        return Some(out);
    }
    if let Some(out) = about_a_token(known, event, transport) {
        return Some(out);
    }
    about_lifecycle(known, event)
}

/// A challenge an account's password did not answer. Who asked and the
/// realms are `text`, the text [`text_to_point_at`] built for this event —
/// the address, a line feed, and the realms one to a line — since neither
/// has bytes of its own in the shape C reads.
fn about_a_challenge(
    known: &mut Vocabulary<'_>,
    event: &UaEvent,
    text: Option<&str>,
) -> Option<SipralEvent> {
    let UaEvent::ChallengeDeclined { account, why, .. } = *event else {
        return None;
    };
    let (server, realms) = text
        .and_then(|text| text.split_once('\n'))
        .unwrap_or_default();
    let payload = SipralChallengeEvent {
        refusal: match why {
            sipral_ua::ChallengeRefusal::NotTheAccountsServer => {
                SipralChallengeRefusal::NotTheAccountsServer as u32
            }
            sipral_ua::ChallengeRefusal::NotTheAccountsRealm => {
                SipralChallengeRefusal::NotTheAccountsRealm as u32
            }
            _ => SipralChallengeRefusal::Unknown as u32,
        },
        server: server.as_ptr().cast::<c_char>(),
        server_len: server.len(),
        realms: realms.as_ptr().cast::<c_char>(),
        realms_len: realms.len(),
    };
    let mut out = SipralEvent::of(
        known.stack,
        SipralEventKind::ChallengeDeclined,
        payload!(challenge: payload),
    );
    out.account = known
        .accounts
        .name_of(account)
        .unwrap_or(SIPRAL_HANDLE_NONE);
    Some(out)
}

/// An account's server asking for an OAuth 2.0 access token. The address is
/// `text`, the text [`text_to_point_at`] built for this event, since it has
/// no bytes of its own; the rest borrows from the event.
fn about_a_token(
    known: &mut Vocabulary<'_>,
    event: &UaEvent,
    text: Option<&str>,
) -> Option<SipralEvent> {
    let UaEvent::TokenRequired {
        account,
        ref challenge,
        ..
    } = *event
    else {
        return None;
    };
    let server = text.unwrap_or_default();
    let realm: &str = &challenge.realm;
    let scope = challenge.scope.as_deref().unwrap_or_default();
    let authz_server = challenge.authz_server.as_deref().unwrap_or_default();
    let (error, code) = match challenge.error {
        None => (SipralTokenError::None, ""),
        Some(ref error) => (
            match error {
                sipral_ua::BearerError::InvalidRequest => SipralTokenError::InvalidRequest,
                sipral_ua::BearerError::InvalidToken => SipralTokenError::InvalidToken,
                sipral_ua::BearerError::InsufficientScope => SipralTokenError::InsufficientScope,
                sipral_ua::BearerError::InvalidScope => SipralTokenError::InvalidScope,
                _ => SipralTokenError::Other,
            },
            error.code(),
        ),
    };
    let payload = SipralTokenEvent {
        error: error as u32,
        proxy: if challenge.proxy {
            SipralToggle::On as u32
        } else {
            SipralToggle::Off as u32
        },
        server: server.as_ptr().cast::<c_char>(),
        server_len: server.len(),
        realm: realm.as_ptr().cast::<c_char>(),
        realm_len: realm.len(),
        scope: scope.as_ptr().cast::<c_char>(),
        scope_len: scope.len(),
        authz_server: authz_server.as_ptr().cast::<c_char>(),
        authz_server_len: authz_server.len(),
        error_code: code.as_ptr().cast::<c_char>(),
        error_code_len: code.len(),
    };
    let mut out = SipralEvent::of(
        known.stack,
        SipralEventKind::TokenRequired,
        payload!(token: payload),
    );
    out.account = known
        .accounts
        .name_of(account)
        .unwrap_or(SIPRAL_HANDLE_NONE);
    Some(out)
}

/// An account's server being located by RFC 3263: a lookup wanted, the
/// addresses found, or none found. The query's name borrows from `event`;
/// the addresses are `targets`, the text [`text_to_point_at`] built for this
/// event, since a list of `SocketAddr`s has no bytes of its own.
fn about_a_location(
    known: &mut Vocabulary<'_>,
    event: &UaEvent,
    targets: Option<&str>,
) -> Option<SipralEvent> {
    let empty = SipralLocateEvent {
        record: crate::locate::SipralDnsRecordType::None as u32,
        failure: crate::locate::SipralLocateFailure::None as u32,
        name: std::ptr::null(),
        name_len: 0,
        targets: std::ptr::null(),
        targets_len: 0,
        retry_in_ms: 0,
    };
    let (account, kind, payload) = match *event {
        UaEvent::LookupWanted { account, ref query } => (
            account,
            SipralEventKind::LookupWanted,
            SipralLocateEvent {
                record: crate::locate::named_record(query.record) as u32,
                name: query.name.as_ptr().cast::<c_char>(),
                name_len: query.name.len(),
                ..empty
            },
        ),
        UaEvent::Located { account, .. } => {
            let (targets, targets_len) = targets.map_or((std::ptr::null(), 0), |text| {
                (text.as_ptr().cast::<c_char>(), text.len())
            });
            (
                account,
                SipralEventKind::Located,
                SipralLocateEvent {
                    targets,
                    targets_len,
                    ..empty
                },
            )
        }
        UaEvent::LocateFailed {
            account,
            reason,
            retry_in,
        } => (
            account,
            SipralEventKind::LocateFailed,
            SipralLocateEvent {
                failure: crate::locate::named_failure(reason) as u32,
                retry_in_ms: millis(retry_in),
                ..empty
            },
        ),
        _ => return None,
    };
    let mut out = SipralEvent::of(known.stack, kind, payload!(locate: payload));
    out.account = known
        .accounts
        .name_of(account)
        .unwrap_or(SIPRAL_HANDLE_NONE);
    Some(out)
}

/// Who is calling, as a signature says: the certificate the verification
/// service wants, or its verdict. Every pointer borrows from `event`.
fn about_a_verification(known: &mut Vocabulary<'_>, event: &UaEvent) -> Option<SipralEvent> {
    use crate::security::{SipralVerificationStage, text_of};
    let (call, payload) = match *event {
        UaEvent::CertificateWanted { call, ref url } => {
            let (certificate_url, certificate_url_len) = text_of(Some(url));
            (
                call,
                SipralVerificationEvent {
                    stage: SipralVerificationStage::CertificateWanted as u32,
                    outcome: 0,
                    failure: 0,
                    attestation: 0,
                    verstat: 0,
                    response_code: 0,
                    refused: 0,
                    certificate_url,
                    certificate_url_len,
                    orig: std::ptr::null(),
                    orig_len: 0,
                    origid: std::ptr::null(),
                    origid_len: 0,
                    detail: std::ptr::null(),
                    detail_len: 0,
                },
            )
        }
        UaEvent::CallerVerified {
            call,
            ref verification,
            ..
        } => {
            let (certificate_url, certificate_url_len) =
                text_of(verification.certificate_url.as_deref());
            let (orig, orig_len) = text_of(verification.orig.as_deref());
            let (origid, origid_len) = text_of(verification.origid.as_deref());
            let (detail, detail_len) = text_of(verification.detail.as_deref());
            (
                call,
                SipralVerificationEvent {
                    stage: SipralVerificationStage::Verified as u32,
                    outcome: crate::security::outcome_code(Some(verification)) as u32,
                    failure: crate::security::failure_code(verification.failure) as u32,
                    attestation: crate::security::attestation_code(verification.attestation) as u32,
                    verstat: crate::identity::verstat_code(Some(&verification.verstat())) as u32,
                    response_code: verification
                        .response
                        .as_ref()
                        .map_or(0, |(code, _)| u32::from(*code)),
                    refused: u32::from(verification.refused),
                    certificate_url,
                    certificate_url_len,
                    orig,
                    orig_len,
                    origid,
                    origid_len,
                    detail,
                    detail_len,
                },
            )
        }
        _ => return None,
    };
    let mut out = SipralEvent::of(
        known.stack,
        SipralEventKind::CallerVerification,
        payload!(verification: payload),
    );
    out.call = known.calls.name_of(call).unwrap_or(SIPRAL_HANDLE_NONE);
    if let UaEvent::CallerVerified {
        account,
        ref request,
        ..
    } = *event
    {
        out.account = account
            .and_then(|id| known.accounts.name_of(id).ok())
            .unwrap_or(SIPRAL_HANDLE_NONE);
        attach(&mut out, Some(request));
    }
    Some(out)
}

/// A conference's picture, a presentity's document, or this account's own
/// published presence.
fn about_conference_or_presence(
    known: &mut Vocabulary<'_>,
    event: &UaEvent,
) -> Option<SipralEvent> {
    match *event {
        UaEvent::ConferenceChanged {
            subscription,
            update,
        } => {
            let named = subscription_named(known, subscription);
            let payload = crate::conference::changed(known.agent, named, subscription, update);
            Some(SipralEvent::of(
                known.stack,
                SipralEventKind::ConferenceChanged,
                payload!(conference: payload),
            ))
        }
        UaEvent::PresenceChanged {
            subscription,
            ref presence,
        } => {
            let named = subscription_named(known, subscription);
            let payload = crate::presence::watched(named, presence);
            Some(SipralEvent::of(
                known.stack,
                SipralEventKind::PresenceChanged,
                payload!(presence: payload),
            ))
        }
        UaEvent::Publication {
            account, ref event, ..
        } => {
            let payload = crate::presence::published(event);
            let mut out = SipralEvent::of(
                known.stack,
                SipralEventKind::PresenceChanged,
                payload!(presence: payload),
            );
            out.account = known
                .accounts
                .name_of(account)
                .unwrap_or(SIPRAL_HANDLE_NONE);
            Some(out)
        }
        _ => None,
    }
}

/// A call a push announced: the INVITE that answered it, or the silence that
/// did not.
fn about_an_announcement(known: &mut Vocabulary<'_>, event: &UaEvent) -> Option<SipralEvent> {
    match *event {
        UaEvent::CallAnnounced {
            call,
            ref announcement,
        } => {
            let named = known
                .announcements
                .name_of(announcement.id())
                .unwrap_or(SIPRAL_HANDLE_NONE);
            let payload = SipralAnnounceEvent {
                announcement: named,
                waited_ms: 0,
            };
            let call = known.calls.name_of(call).unwrap_or(SIPRAL_HANDLE_NONE);
            let mut out = SipralEvent::of(
                known.stack,
                SipralEventKind::CallAnnounced,
                payload!(announce: payload),
            );
            out.call = call;
            Some(out)
        }
        UaEvent::AnnouncedCallMissing {
            ref announcement,
            waited,
        } => {
            let named = known
                .announcements
                .name_of(announcement.id())
                .unwrap_or(SIPRAL_HANDLE_NONE);
            let payload = SipralAnnounceEvent {
                announcement: named,
                waited_ms: millis(waited),
            };
            Some(SipralEvent::of(
                known.stack,
                SipralEventKind::AnnouncedCallMissing,
                payload!(announce: payload),
            ))
        }
        _ => None,
    }
}

/// An event with nothing in it but the subscription it is about.
fn subscription_payload(
    subscription: SipralHandle,
    state: SipralSubscriptionState,
) -> SipralSubscriptionEvent {
    SipralSubscriptionEvent {
        subscription,
        state: state as u32,
        reason: 0,
        status_code: 0,
        has_dialog_info: 0,
        expires_ms: 0,
        refresh_in_ms: 0,
        retry_in_ms: 0,
        forked_from: SIPRAL_HANDLE_NONE,
    }
}

/// The handle one subscription of the layer below is known by here, minting
/// one for a subscription nobody asked for: a sibling a fork produced arrives
/// in an event rather than as the result of a call, the way an incoming call
/// does.
fn subscription_named(
    known: &mut Vocabulary<'_>,
    subscription: sipral_ua::SubscriptionHandle,
) -> SipralHandle {
    known
        .subscriptions
        .name_of(subscription)
        .unwrap_or(SIPRAL_HANDLE_NONE)
}

/// Where a subscription is now, asked of the layer below rather than inferred:
/// the event that says a state changed is raised from the same drain that
/// changed it.
fn subscription_state_now(
    known: &Vocabulary<'_>,
    subscription: sipral_ua::SubscriptionHandle,
) -> SipralSubscriptionState {
    known
        .agent
        .subscription_state(subscription)
        .map_or(SipralSubscriptionState::Unknown, named_state)
}

fn about_a_subscription(known: &mut Vocabulary<'_>, event: &UaEvent) -> Option<SipralEvent> {
    match *event {
        UaEvent::Subscribing { subscription, .. } => {
            let named = subscription_named(known, subscription);
            let payload = subscription_payload(named, SipralSubscriptionState::Requesting);
            Some(SipralEvent::of(
                known.stack,
                SipralEventKind::SubscriptionChanged,
                payload!(subscription: payload),
            ))
        }
        UaEvent::Subscribed {
            subscription,
            state,
            expires,
            refresh_in,
        } => {
            let named = subscription_named(known, subscription);
            let mut payload = subscription_payload(named, named_state(state));
            payload.expires_ms = millis(expires);
            payload.refresh_in_ms = millis(refresh_in);
            Some(SipralEvent::of(
                known.stack,
                SipralEventKind::SubscriptionChanged,
                payload!(subscription: payload),
            ))
        }
        UaEvent::SubscriptionForked {
            subscription,
            sibling,
        } => {
            // the sibling is what this event is about: it is new, and the one
            // it forked from carries on unchanged
            let from = subscription_named(known, subscription);
            let named = subscription_named(known, sibling);
            let mut payload = subscription_payload(named, subscription_state_now(known, sibling));
            payload.forked_from = from;
            Some(SipralEvent::of(
                known.stack,
                SipralEventKind::SubscriptionChanged,
                payload!(subscription: payload),
            ))
        }
        UaEvent::Notified {
            subscription,
            ref request,
            ref info,
        } => {
            let named = subscription_named(known, subscription);
            let mut payload =
                subscription_payload(named, subscription_state_now(known, subscription));
            payload.has_dialog_info = u32::from(info.is_some());
            let mut out = SipralEvent::of(
                known.stack,
                SipralEventKind::Notified,
                payload!(subscription: payload),
            );
            attach(&mut out, Some(request));
            Some(out)
        }
        UaEvent::SubscriptionEnded {
            subscription,
            reason,
            status,
            retry_in,
            ref response,
        } => {
            let named = subscription_named(known, subscription);
            // said here rather than asked for: a subscription that has ended
            // for good is one the layer below has already let go of, and a
            // state read now would be no state at all
            let state = if retry_in.is_some() {
                SipralSubscriptionState::Retrying
            } else {
                SipralSubscriptionState::Ended
            };
            let mut payload = subscription_payload(named, state);
            payload.reason = named_end(reason) as u32;
            payload.status_code = status_of(status);
            payload.retry_in_ms = retry_in.map_or(0, millis);
            let mut out = SipralEvent::of(
                known.stack,
                SipralEventKind::SubscriptionChanged,
                payload!(subscription: payload),
            );
            attach(&mut out, response.as_ref());
            Some(out)
        }
        _ => None,
    }
}

/// An event with nothing in it but zeroes, for a kind to fill in.
const fn empty_message_payload() -> SipralMessageEvent {
    SipralMessageEvent {
        message: SIPRAL_HANDLE_NONE,
        subscription: SIPRAL_HANDLE_NONE,
        status_code: 0,
        content_type: std::ptr::null(),
        content_type_len: 0,
        body: std::ptr::null(),
        body_len: 0,
        waiting: 0,
        new_messages: 0,
        old_messages: 0,
        urgent_new_messages: 0,
        urgent_old_messages: 0,
        message_account: std::ptr::null(),
        message_account_len: 0,
    }
}

fn about_a_message(known: &mut Vocabulary<'_>, event: &UaEvent) -> Option<SipralEvent> {
    match *event {
        UaEvent::MessageReceived {
            account,
            call,
            ref request,
        } => {
            let raw = request.as_raw();
            let mut payload = empty_message_payload();
            // both point straight into `request`, which `attach` below also
            // borrows from and which lives as long as the event this
            // translation produced: no copy, and nothing to keep alive that
            // is not already kept
            if let Some(field) = raw.header(HeaderName::ContentType) {
                payload.content_type = field.as_ptr().cast::<c_char>();
                payload.content_type_len = field.len();
            }
            let body = raw.body();
            if !body.is_empty() {
                payload.body = body.as_ptr();
                payload.body_len = body.len();
            }
            let mut out = SipralEvent::of(
                known.stack,
                SipralEventKind::MessageReceived,
                payload!(message: payload),
            );
            out.account = account
                .and_then(|id| known.accounts.name_of(id).ok())
                .unwrap_or(SIPRAL_HANDLE_NONE);
            out.call = call
                .and_then(|handle| known.calls.name_of(handle).ok())
                .unwrap_or(SIPRAL_HANDLE_NONE);
            attach(&mut out, Some(request));
            Some(out)
        }
        UaEvent::MessageSent {
            message,
            status,
            ref response,
        } => {
            let mut payload = empty_message_payload();
            payload.message = known
                .messages
                .name_of(message)
                .unwrap_or(SIPRAL_HANDLE_NONE);
            payload.status_code = u32::from(status.get());
            let mut out = SipralEvent::of(
                known.stack,
                SipralEventKind::MessageSent,
                payload!(message: payload),
            );
            attach(&mut out, response.as_ref());
            Some(out)
        }
        UaEvent::MessagesWaiting {
            subscription,
            waiting,
            ref account,
            new,
            old,
            urgent_new,
            urgent_old,
        } => {
            let mut payload = empty_message_payload();
            payload.subscription = known
                .subscriptions
                .name_of(subscription)
                .unwrap_or(SIPRAL_HANDLE_NONE);
            payload.waiting = u32::from(waiting);
            payload.new_messages = new;
            payload.old_messages = old;
            payload.urgent_new_messages = urgent_new;
            payload.urgent_old_messages = urgent_old;
            if let Some(text) = account.as_deref() {
                payload.message_account = text.as_ptr().cast::<c_char>();
                payload.message_account_len = text.len();
            }
            Some(SipralEvent::of(
                known.stack,
                SipralEventKind::MessagesWaiting,
                payload!(message: payload),
            ))
        }
        _ => None,
    }
}

/// A request RFC 3261 §18.1.1 would not let out over a datagram, with
/// nowhere open to send it instead. `destination` is the text
/// [`text_to_point_at`] built for the event this is about; `None`
/// here from a caller that has none is the same as the event carrying no
/// destination at all, which never actually happens for this kind but is not
/// this function's to assume.
fn about_a_transport(
    known: &Vocabulary<'_>,
    event: &UaEvent,
    destination: Option<&str>,
) -> Option<SipralEvent> {
    match *event {
        UaEvent::Unclaimed(Event::TransportWanted {
            protocol,
            request_bytes,
            limit_bytes,
            ..
        }) => {
            let mut payload = SipralTransportWantedEvent {
                protocol: crate::stack::SipralTransport::named(protocol),
                destination: std::ptr::null(),
                destination_len: 0,
                request_bytes,
                limit_bytes,
            };
            if let Some(text) = destination {
                payload.destination = text.as_ptr().cast::<c_char>();
                payload.destination_len = text.len();
            }
            Some(SipralEvent::of(
                known.stack,
                SipralEventKind::TransportWanted,
                payload!(transport_wanted: payload),
            ))
        }
        _ => None,
    }
}

/// A dialog whose next hop is a name this library will not look up. `host` is
/// the text [`text_to_point_at`] built for this event, for the same reason
/// `about_a_transport` needs one: a [`Host`](sipral_core::endpoint::Host) that
/// is a literal address has no bytes of its own to point at, and one that is a
/// name has bytes that belong to the event rather than to the shape C reads.
/// Formatting both the same way is one rule instead of two.
fn about_a_resolve(
    known: &mut Vocabulary<'_>,
    event: &UaEvent,
    host: Option<&str>,
) -> Option<SipralEvent> {
    match *event {
        UaEvent::Unclaimed(Event::ResolveNeeded {
            dialog,
            port,
            protocol,
            ..
        }) => {
            // named rather than inserted, so that a dialog asking again --
            // which it does on every target refresh -- is the same handle it
            // was the first time and not another row
            let named = known
                .dialogs
                .name_of(dialog)
                .unwrap_or(crate::handle::SIPRAL_HANDLE_NONE);
            let mut payload = SipralResolveEvent {
                dialog: named,
                host: std::ptr::null(),
                host_len: 0,
                port: u32::from(port.unwrap_or(0)),
                protocol: protocol.map_or(0, crate::stack::SipralTransport::named),
            };
            if let Some(text) = host {
                payload.host = text.as_ptr().cast::<c_char>();
                payload.host_len = text.len();
            }
            Some(SipralEvent::of(
                known.stack,
                SipralEventKind::ResolveNeeded,
                payload!(resolve: payload),
            ))
        }
        _ => None,
    }
}

/// The one piece of text an event has no bytes of its own for, formatted once
/// so the shape this ABI raises has something to point at that outlives the
/// callback.
///
/// Two kinds need it and neither can borrow: a
/// [`SipralEventKind::TransportWanted`]'s destination is a `SocketAddr`, which
/// carries no text at all, and a [`SipralEventKind::ResolveNeeded`]'s host is
/// a `Host`, whose name half borrows from the event and whose address half is
/// again a value with no text. One rule for both beats two. `None` for every
/// other kind of event, which is also what a caller who does not care to check
/// the kind first gets.
pub(crate) fn text_to_point_at(event: &UaEvent) -> Option<String> {
    match *event {
        UaEvent::Unclaimed(Event::TransportWanted { destination, .. }) => {
            Some(destination.to_string())
        }
        UaEvent::Unclaimed(Event::ResolveNeeded { ref host, .. }) => Some(host.to_string()),
        UaEvent::Located { ref targets, .. } => Some(
            targets
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ),
        UaEvent::TokenRequired { from, .. } => Some(from.to_string()),
        UaEvent::ChallengeDeclined {
            from, ref realms, ..
        } => {
            let mut text = format!("{from}\n");
            for (index, realm) in realms.iter().enumerate() {
                if index > 0 {
                    text.push('\n');
                }
                text.push_str(realm);
            }
            Some(text)
        }
        _ => None,
    }
}

fn about_registration(known: &mut Vocabulary<'_>, event: &UaEvent) -> Option<SipralEvent> {
    match *event {
        UaEvent::Registering { account }
        | UaEvent::Refreshing { account }
        | UaEvent::Unregistered { account }
        | UaEvent::Unverified { account } => {
            let payload = registration_payload(known, account, None);
            Some(registration_event(known, account, payload))
        }
        UaEvent::Registered {
            account,
            expires,
            refresh_in,
            ref response,
            ..
        } => {
            let mut payload = registration_payload(known, account, None);
            payload.expires_ms = millis(expires);
            payload.refresh_in_ms = millis(refresh_in);
            // the 2xx, whole, as a refusal always was: the Service-Route, the
            // GRUUs and the P-Associated-URI a registrar sent are read out of
            // it rather than out of members of their own
            let mut out = registration_event(known, account, payload);
            attach(&mut out, Some(response));
            Some(out)
        }
        UaEvent::RegistrationFailed {
            account,
            reason,
            status,
            retry_in,
            ref response,
        } => {
            let mut payload = registration_payload(known, account, Some(reason));
            payload.status_code = status_of(status);
            payload.retry_in_ms = retry_in.map_or(0, millis);
            let mut out = registration_event(known, account, payload);
            attach(&mut out, response.as_ref());
            Some(out)
        }
        _ => None,
    }
}

fn about_a_call(known: &mut Vocabulary<'_>, event: &UaEvent) -> Option<SipralEvent> {
    match *event {
        UaEvent::IncomingCall {
            call,
            account,
            ref request,
            ..
        } => {
            let payload = call_payload(known, call);
            let mut out = call_event(known, SipralEventKind::IncomingCall, call, payload);
            out.account = account
                .and_then(|id| known.accounts.name_of(id).ok())
                .unwrap_or(SIPRAL_HANDLE_NONE);
            attach(&mut out, Some(request));
            Some(out)
        }
        UaEvent::CallProgress {
            call,
            status,
            ref response,
            ..
        } => {
            let mut payload = call_payload(known, call);
            payload.status_code = u32::from(status.get());
            let mut out = call_event(known, SipralEventKind::CallProgress, call, payload);
            attach(&mut out, Some(response));
            Some(out)
        }
        UaEvent::CallForked { call, sibling } => {
            let mut payload = call_payload(known, call);
            payload.other = known.calls.name_of(sibling).unwrap_or(SIPRAL_HANDLE_NONE);
            Some(call_event(
                known,
                SipralEventKind::CallForked,
                call,
                payload,
            ))
        }
        UaEvent::CallConfirmed {
            call, ref response, ..
        } => {
            let payload = call_payload(known, call);
            let mut out = call_event(known, SipralEventKind::CallConfirmed, call, payload);
            attach(&mut out, response.as_ref());
            Some(out)
        }
        UaEvent::DtmfSent {
            call,
            digit,
            status,
        } => {
            let mut payload = call_payload(known, call);
            payload.digit = u32::from(digit);
            payload.status_code = u32::from(status.get());
            Some(call_event(known, SipralEventKind::DtmfSent, call, payload))
        }
        UaEvent::CallAddressWanted { call } => {
            let payload = call_payload(known, call);
            Some(call_event(
                known,
                SipralEventKind::CallAddressWanted,
                call,
                payload,
            ))
        }
        _ => None,
    }
}

fn about_a_session(known: &mut Vocabulary<'_>, event: &UaEvent) -> Option<SipralEvent> {
    match *event {
        UaEvent::SessionChanged {
            call,
            hold,
            ref local,
            ref remote,
        } => {
            let mut payload = call_payload(known, call);
            payload.held_here = u32::from(hold.local);
            payload.held_there = u32::from(hold.remote);
            if let Some(sdp) = local.as_deref() {
                payload.local_sdp = sdp.as_ptr();
                payload.local_sdp_len = sdp.len();
            }
            if let Some(sdp) = remote.as_deref() {
                payload.remote_sdp = sdp.as_ptr();
                payload.remote_sdp_len = sdp.len();
            }
            Some(call_event(
                known,
                SipralEventKind::SessionChanged,
                call,
                payload,
            ))
        }
        UaEvent::Reoffer { call, ref request } => {
            let payload = call_payload(known, call);
            let mut out = call_event(known, SipralEventKind::SessionOffered, call, payload);
            attach(&mut out, Some(request));
            Some(out)
        }
        UaEvent::SessionChangeFailed {
            call,
            status,
            retry_in,
            ref response,
        } => {
            let mut payload = call_payload(known, call);
            payload.status_code = status_of(status);
            payload.retry_in_ms = retry_in.map_or(0, millis);
            let mut out = call_event(known, SipralEventKind::SessionChangeFailed, call, payload);
            attach(&mut out, response.as_ref());
            Some(out)
        }
        _ => None,
    }
}

fn about_a_call_ending(known: &mut Vocabulary<'_>, event: &UaEvent) -> Option<SipralEvent> {
    match *event {
        UaEvent::CallReplaced { call, replaced } => {
            let mut payload = call_payload(known, call);
            payload.other = known.calls.name_of(replaced).unwrap_or(SIPRAL_HANDLE_NONE);
            Some(call_event(
                known,
                SipralEventKind::CallReplaced,
                call,
                payload,
            ))
        }
        UaEvent::CallEnded {
            call,
            reason,
            status,
            ref response,
            ref causes,
        } => {
            let mut payload = call_payload(known, call);
            // the layer below has already let the call go, so the state is
            // said here rather than asked for
            payload.state = SipralCallState::Terminated as u32;
            payload.end_reason = end_reason(reason) as u32;
            payload.status_code = status_of(status);
            said_why(&mut payload, causes);
            let mut out = call_event(known, SipralEventKind::CallEnded, call, payload);
            attach(&mut out, response.as_ref());
            Some(out)
        }
        _ => None,
    }
}

/// The `Reason` values a call's end carried, onto its event: the SIP and
/// the Q.850 cause, and the first value's text. The text borrows from
/// `causes`, which the queued delivery keeps alive with the event.
fn said_why(payload: &mut SipralCallEvent, causes: &[sipral_ua::Reason]) {
    for cause in causes {
        let number = cause.cause.map_or(0, u32::from);
        match cause.protocol {
            sipral_ua::ReasonProtocol::Sip => payload.cause_sip = number,
            sipral_ua::ReasonProtocol::Q850 => payload.cause_q850 = number,
            _ => {}
        }
    }
    if let Some(text) = causes.first().and_then(|cause| cause.text.as_deref()) {
        payload.cause_text = text.as_ptr();
        payload.cause_text_len = text.len();
    }
}

fn about_a_transfer(known: &mut Vocabulary<'_>, event: &UaEvent) -> Option<SipralEvent> {
    match *event {
        UaEvent::TransferRequested {
            call,
            ref target,
            attended,
            ref request,
        } => {
            let uri = target.as_bytes();
            let payload = SipralTransferEvent {
                status_code: 0,
                attended: u32::from(attended),
                target: uri.as_ptr().cast::<c_char>(),
                target_len: uri.len(),
            };
            let mut out = transfer_event(known, SipralEventKind::TransferRequested, call, payload);
            attach(&mut out, Some(request));
            Some(out)
        }
        UaEvent::TransferProgress { call, status } => Some(transfer_event(
            known,
            SipralEventKind::TransferProgress,
            call,
            reported(status.get()),
        )),
        UaEvent::TransferDone { call, status } => Some(transfer_event(
            known,
            SipralEventKind::TransferDone,
            call,
            reported(status.get()),
        )),
        UaEvent::ReferralRequested {
            referral,
            account,
            ref target,
            attended,
            ref referred_by,
            ref request,
        } => {
            let uri = target.as_bytes();
            let (by, by_len) = referred_by
                .as_deref()
                .map_or((std::ptr::null(), 0), |field| {
                    (field.as_ptr().cast::<c_char>(), field.len())
                });
            let payload = SipralReferralEvent {
                status_code: 0,
                attended: u32::from(attended),
                target: uri.as_ptr().cast::<c_char>(),
                target_len: uri.len(),
                referred_by: by,
                referred_by_len: by_len,
            };
            let mut out = SipralEvent::of(
                known.stack,
                SipralEventKind::Referral,
                payload!(referral: payload),
            );
            // minted here, the way an incoming call's handle is: the
            // referral's is what the two calls that answer it take
            out.call = known.calls.name_of(referral).unwrap_or(SIPRAL_HANDLE_NONE);
            out.account = known
                .accounts
                .name_of(account)
                .unwrap_or(SIPRAL_HANDLE_NONE);
            attach(&mut out, Some(request));
            Some(out)
        }
        UaEvent::ReferralLapsed { referral, status } => {
            let payload = SipralReferralEvent {
                status_code: u32::from(status.get()),
                attended: 0,
                target: std::ptr::null(),
                target_len: 0,
                referred_by: std::ptr::null(),
                referred_by_len: 0,
            };
            let mut out = SipralEvent::of(
                known.stack,
                SipralEventKind::Referral,
                payload!(referral: payload),
            );
            out.call = known.calls.name_of(referral).unwrap_or(SIPRAL_HANDLE_NONE);
            Some(out)
        }
        // a protocol event this stack has no policy for and this ABI has no
        // word for; the poll result counts it, and the layer below is free to
        // grow a vocabulary faster than this one.
        //
        // This arm cannot be deleted to make the compiler demand a translation
        // for every new one: `UaEvent` is `#[non_exhaustive]`, so a match on it
        // outside its own crate is required to have a wildcard. What that
        // buys is a layer below that can add an event without breaking this
        // one, and what it costs is that the compiler cannot notice a kind
        // this ABI has not caught up with. The number space above is where the
        // guarantee lives instead, because that is where a mistake would be
        // permanent.
        _ => None,
    }
}

/// The two ways `crates/sipral-ffi/src/lifecycle.rs`'s ladder settles: a
/// registrar proved the path again, or every rung was climbed and none of
/// them worked.
fn about_lifecycle(known: &mut Vocabulary<'_>, event: &UaEvent) -> Option<SipralEvent> {
    match *event {
        UaEvent::Lifecycle {
            state: LifecycleState::Running,
            rung: None,
            next_in: None,
        } => Some(recovery_event(
            known,
            SipralRecoveryEvent {
                state: SipralRecoveryOutcome::Running as u32,
                rung: 0,
                reason: 0,
                unverified: 0,
            },
        )),
        UaEvent::RecoveryGaveUp {
            rung,
            reason,
            unverified,
        } => Some(recovery_event(
            known,
            SipralRecoveryEvent {
                state: SipralRecoveryOutcome::GaveUp as u32,
                rung: recovery_rung(rung) as u32,
                reason: recovery_failure(reason) as u32,
                unverified: u32::try_from(unverified).unwrap_or(u32::MAX),
            },
        )),
        // every other `Lifecycle` variant is a rung mid-ladder — `Suspending`,
        // or `Recovering`/`ResolutionLost`/`InterfaceLost` with a rung that is
        // not the last one — and this ABI has no word for a step, only for
        // where a ladder ends. `SIPRAL_EVENT_KIND_RECOVERY` is that word.
        _ => None,
    }
}

fn recovery_event(known: &Vocabulary<'_>, payload: SipralRecoveryEvent) -> SipralEvent {
    SipralEvent::of(
        known.stack,
        SipralEventKind::Recovery,
        payload!(recovery: payload),
    )
}

fn recovery_rung(rung: Rung) -> SipralRecoveryRung {
    match rung {
        Rung::Distrust => SipralRecoveryRung::Distrust,
        Rung::Reregister => SipralRecoveryRung::Reregister,
        Rung::WantTransport => SipralRecoveryRung::WantTransport,
        Rung::WantAddress => SipralRecoveryRung::WantAddress,
        // `Rung` is `#[non_exhaustive]`, and `give_up_recovering` never
        // reports `Rung::GiveUp` as the rung it gave up on in the first
        // place.
        _ => SipralRecoveryRung::None,
    }
}

fn recovery_failure(reason: RecoveryFailure) -> SipralRecoveryFailure {
    match reason {
        RecoveryFailure::Unreachable => SipralRecoveryFailure::Unreachable,
        RecoveryFailure::NoTransport => SipralRecoveryFailure::NoTransport,
        RecoveryFailure::Unresolved => SipralRecoveryFailure::Unresolved,
        _ => SipralRecoveryFailure::None,
    }
}

/// The transform a call is running, on this side of the boundary: every
/// suite the stack implements has a word of its own (ABI 0.29), and `Unknown`
/// is left for an event that is not about one.
pub(crate) const fn suite_of(suite: SrtpSuite) -> crate::media::SipralSrtpSuite {
    use crate::media::SipralSrtpSuite;
    match suite {
        SrtpSuite::AesCm80 => SipralSrtpSuite::AesCm80,
        SrtpSuite::AesCm32 => SipralSrtpSuite::AesCm32,
        SrtpSuite::AesF8 => SipralSrtpSuite::AesF8,
        SrtpSuite::Aes256Cm80 => SipralSrtpSuite::Aes256Cm80,
        SrtpSuite::Aes256Cm32 => SipralSrtpSuite::Aes256Cm32,
        SrtpSuite::AeadAes128Gcm => SipralSrtpSuite::AeadAes128Gcm,
        SrtpSuite::AeadAes256Gcm => SipralSrtpSuite::AeadAes256Gcm,
    }
}

/// Real-time text the far end typed on `call`, `missing` blocks of it lost:
/// `text` borrows from the caller for the one delivery.
fn text_received(
    known: &mut Vocabulary<'_>,
    call: CallHandle,
    missing: u32,
    text: Option<&str>,
) -> SipralEvent {
    let mut payload = SipralTextEvent {
        text: std::ptr::null(),
        text_len: 0,
        missing,
    };
    if let Some(text) = text {
        payload.text = text.as_ptr().cast::<c_char>();
        payload.text_len = text.len();
    }
    let mut out = SipralEvent::of(
        known.stack,
        SipralEventKind::TextReceived,
        payload!(text: payload),
    );
    out.call = known.calls.name_of(call).unwrap_or(SIPRAL_HANDLE_NONE);
    out
}

/// Say a media event the way C says it.
///
/// `None` for one this ABI has no word for, as with a signalling event: the
/// layer below is free to grow a vocabulary faster than this one, and a number
/// is counted rather than invented.
///
/// `reason` and `statistics` are the caller's, because both are built for the
/// duration of one delivery and neither can be borrowed from the event itself:
/// a `MediaError` is a Rust value with no C shape, and the statistics have to
/// be converted before they have one.
///
/// `encryption` is the call's stream as its encryption report has it at the
/// moment of the event, which the kinds that start, change or secure a call's
/// media carry.
pub(crate) fn media(
    known: &mut Vocabulary<'_>,
    call: CallHandle,
    event: &MediaEvent,
    reason: Option<&str>,
    statistics: Option<&SipralStreamStats>,
    encryption: Option<&sipral::StreamEncryption>,
) -> Option<SipralEvent> {
    // text has an arm of its own: `reason` is the text itself, which is what
    // `media_reason` built it to be
    if let MediaEvent::TextReceived { missing, .. } = *event {
        return Some(text_received(known, call, missing, reason));
    }
    let mut payload = SipralMediaEvent::empty();
    if let Some(stream) = encryption.filter(|_| reports_encryption(event)) {
        payload.key_exchange = crate::security::key_exchange_code(stream.key_exchange) as u32;
        payload.encrypted = u32::from(stream.encrypted);
        payload.authenticated = u32::from(stream.authenticated);
        payload.suite = stream
            .suite
            .map_or(0, |suite| crate::security::suite_code(suite) as u32);
    }
    let kind = match *event {
        MediaEvent::Started { codec, direction } => {
            payload.codec = named_codec(codec) as u32;
            payload.direction = direction_of(direction) as u32;
            SipralEventKind::MediaStarted
        }
        MediaEvent::Changed { codec, direction } => {
            payload.codec = named_codec(codec) as u32;
            payload.direction = direction_of(direction) as u32;
            SipralEventKind::MediaChanged
        }
        MediaEvent::Stalled { silent_for } => {
            payload.silent_for_ms = millis(silent_for);
            SipralEventKind::MediaStalled
        }
        MediaEvent::Resumed { silent_for } => {
            payload.silent_for_ms = millis(silent_for);
            SipralEventKind::MediaResumed
        }
        MediaEvent::Ended(record) => {
            payload.codec = named_codec(record.codec) as u32;
            SipralEventKind::MediaStatistics
        }
        MediaEvent::Failed(ref error) => {
            payload.fault = fault_of(error) as u32;
            SipralEventKind::MediaFailed
        }
        #[cfg(feature = "ice")]
        MediaEvent::PathChosen { .. } => SipralEventKind::MediaPathChosen,
        #[cfg(feature = "dtls")]
        MediaEvent::Secured { suite, .. } => {
            // the address the handshake came from is deliberately not carried
            // here: it is the address `sipral_media_poll_transmit` already
            // hands every record back with, so an application that drove the
            // handshake at all has it
            payload.suite = suite_of(suite) as u32;
            SipralEventKind::MediaSecured
        }
        MediaEvent::DigitReceived {
            digit,
            event,
            held,
            source,
        } => {
            payload.digit = digit.map_or(0, u32::from);
            payload.event_code = u32::from(event);
            // no ABI change here: a duration the peer never gave and a
            // `Duration=0` it did give both read as zero on this side of the
            // boundary, and `sipral_media_event_t::held_ms`'s own doc says so
            payload.held_ms = held.map_or(0, millis);
            payload.source = digit_source(source) as u32;
            if source == DigitSource::InBand {
                SipralEventKind::InBandDigit
            } else {
                SipralEventKind::DigitReceived
            }
        }
        MediaEvent::Progress(heard) => {
            let mut out = SipralEvent::of(
                known.stack,
                SipralEventKind::ProgressDetected,
                payload!(progress: progress_of(heard)),
            );
            out.call = known.calls.name_of(call).unwrap_or(SIPRAL_HANDLE_NONE);
            return Some(out);
        }
        MediaEvent::RecordingStopped {
            ref reason,
            written,
            ..
        } => {
            payload.fault = fault_of(reason) as u32;
            payload.recorded_ms = millis(written);
            SipralEventKind::RecordingStopped
        }
        MediaEvent::QualityReportSent { ok } => {
            payload.quality_report_sent = u32::from(ok);
            SipralEventKind::QualityReportSent
        }
        MediaEvent::Unjoined => SipralEventKind::MediaUnjoined,
        _ => return None,
    };
    if let Some(sentence) = reason {
        payload.reason = sentence.as_ptr().cast::<c_char>();
        payload.reason_len = sentence.len();
    }
    if let Some(record) = statistics {
        payload.statistics = std::ptr::from_ref(record);
    }
    let mut out = SipralEvent::of(known.stack, kind, payload!(media: payload));
    out.call = known.calls.name_of(call).unwrap_or(SIPRAL_HANDLE_NONE);
    Some(out)
}

/// Whether a media event is one of the kinds that carry the encryption
/// report: the call's media started, changed, or was secured.
const fn reports_encryption(event: &MediaEvent) -> bool {
    match event {
        MediaEvent::Started { .. } | MediaEvent::Changed { .. } => true,
        #[cfg(feature = "dtls")]
        MediaEvent::Secured { .. } => true,
        _ => false,
    }
}

/// The sentence a media event carries, for the kinds that have one to say.
///
/// Built here rather than in the translation because it has to outlive the
/// borrow the event holds, and a `String` handed to C has to belong to
/// something that is still alive when the callback reads it.
pub(crate) fn media_reason(event: &MediaEvent) -> Option<String> {
    match *event {
        MediaEvent::Failed(ref error) => Some(error.to_string()),
        MediaEvent::RecordingStopped { ref reason, .. } => Some(reason.to_string()),
        // not a sentence, but the same need: bytes C reads after the borrow
        // of the event has gone
        MediaEvent::TextReceived { ref text, .. } => Some(text.clone()),
        _ => None,
    }
}

fn registration_payload(
    known: &Vocabulary<'_>,
    account: sipral_ua::AccountId,
    failure: Option<RegistrationFailure>,
) -> SipralRegistrationEvent {
    SipralRegistrationEvent {
        state: registration_state(known.agent.registration_state(account)) as u32,
        failure: failure.map_or(SipralRegistrationFailure::None, registration_failure) as u32,
        status_code: 0,
        expires_ms: 0,
        refresh_in_ms: 0,
        retry_in_ms: 0,
    }
}

fn registration_event(
    known: &mut Vocabulary<'_>,
    account: sipral_ua::AccountId,
    payload: SipralRegistrationEvent,
) -> SipralEvent {
    let mut out = SipralEvent::of(
        known.stack,
        SipralEventKind::RegistrationChanged,
        payload!(registration: payload),
    );
    out.account = known
        .accounts
        .name_of(account)
        .unwrap_or(SIPRAL_HANDLE_NONE);
    out
}

fn call_payload(known: &mut Vocabulary<'_>, call: CallHandle) -> SipralCallEvent {
    let mut payload = SipralCallEvent {
        state: call_state(known.agent.call_state(call)) as u32,
        ..SipralCallEvent::empty()
    };
    // read from this stack's own record, never from the layer below: by the
    // time a call has ended, `known.agent` has already let it go (the state
    // above just asked for is `None` for exactly that call), and an event
    // reporting the end is the one place this matters
    if let Some(identity) = known.identities.get(&call) {
        let identity = Arc::clone(identity);
        payload.from_uri = identity.from_uri.as_ptr();
        payload.from_uri_len = identity.from_uri.len();
        if !identity.from_display.is_empty() {
            payload.from_display = identity.from_display.as_ptr();
            payload.from_display_len = identity.from_display.len();
        }
        payload.to_uri = identity.to_uri.as_ptr();
        payload.to_uri_len = identity.to_uri.len();
        payload.call_id = identity.call_id.as_ptr();
        payload.call_id_len = identity.call_id.len();
        who_and_how(&mut payload, &identity);
        // kept on the vocabulary rather than dropped here, so that whoever
        // queues this event can keep these bytes alive for as long as the
        // delivery takes: the map this came from may be missing the entry by
        // then, forgotten alongside a call that has ended in the meantime
        known.raised_identity = Some(identity);
    }
    payload
}

/// What the INVITE of a call said about who is calling and how to answer
/// it, onto a call event. Every pointer borrows from `identity`, which the
/// queued delivery keeps alive with the event.
fn who_and_how(payload: &mut SipralCallEvent, identity: &CallIdentity) {
    let caller = &identity.caller;
    payload.identity_trusted = u32::from(caller.trusted);
    if let Some(shown) = caller.shown() {
        payload.asserted_uri = shown.uri.as_ptr();
        payload.asserted_uri_len = shown.uri.len();
        if !shown.display.is_empty() {
            payload.asserted_display = shown.display.as_ptr();
            payload.asserted_display_len = shown.display.len();
        }
    }
    payload.verstat = crate::identity::verstat_code(caller.verstat.as_ref()) as u32;
    payload.privacy = crate::identity::privacy_bits(caller.privacy);
    if let Some(top) = caller.diversions.first() {
        payload.diverted_from = top.party.uri.as_ptr();
        payload.diverted_from_len = top.party.uri.len();
        if let Some(reason) = top.reason.as_deref() {
            payload.diversion_reason = reason.as_ptr();
            payload.diversion_reason_len = reason.len();
        }
    }
    payload.diversion_count = u32::try_from(caller.diversions.len()).unwrap_or(u32::MAX);
    payload.history_count = u32::try_from(caller.history.len()).unwrap_or(u32::MAX);
    let answering = &identity.answering;
    let (mode, required) = crate::identity::answer_mode_code(answering.answer_mode.as_ref());
    payload.answer_mode = mode as u32;
    payload.answer_mode_required = required;
    let (mode, required) = crate::identity::answer_mode_code(answering.priv_answer_mode.as_ref());
    payload.priv_answer_mode = mode as u32;
    payload.priv_answer_mode_required = required;
    if let Some(after) = answering.answer_after {
        payload.has_answer_after = 1;
        payload.answer_after_ms = millis(after);
    }
    payload.ring_source = crate::identity::ring_source_code(answering.source) as u32;
    if let Some(first) = answering.alert_info.first() {
        payload.alert_info = first.as_ptr();
        payload.alert_info_len = first.len();
    }
    let verified = caller.verification.as_ref();
    payload.verification = crate::security::outcome_code(verified) as u32;
    payload.attestation =
        crate::security::attestation_code(verified.and_then(|verdict| verdict.attestation)) as u32;
    payload.verification_failure =
        crate::security::failure_code(verified.and_then(|verdict| verdict.failure)) as u32;
}

// moved into the event whole, the way `SipralEvent::of` takes its union
#[allow(clippy::large_types_passed_by_value)]
fn call_event(
    known: &mut Vocabulary<'_>,
    kind: SipralEventKind,
    call: CallHandle,
    payload: SipralCallEvent,
) -> SipralEvent {
    let mut out = SipralEvent::of(known.stack, kind, payload!(call: payload));
    out.call = known.calls.name_of(call).unwrap_or(SIPRAL_HANDLE_NONE);
    out
}

fn transfer_event(
    known: &mut Vocabulary<'_>,
    kind: SipralEventKind,
    call: CallHandle,
    payload: SipralTransferEvent,
) -> SipralEvent {
    let mut out = SipralEvent::of(known.stack, kind, payload!(transfer: payload));
    out.call = known.calls.name_of(call).unwrap_or(SIPRAL_HANDLE_NONE);
    out
}

/// A transfer event that says only what the far end reported.
fn reported(status: u16) -> SipralTransferEvent {
    SipralTransferEvent {
        status_code: u32::from(status),
        attended: 0,
        target: std::ptr::null(),
        target_len: 0,
    }
}

fn status_of(status: Option<sipral_core::msg::StatusCode>) -> u32 {
    status.map_or(0, |code| u32::from(code.get()))
}

/// Point the event at the message it came from, which the caller of the
/// callback still owns.
fn attach(event: &mut SipralEvent, message: Option<&sipral_core::msg::OwnedMessage>) {
    if let Some(message) = message {
        let raw = message.as_raw().as_bytes();
        event.message = raw.as_ptr();
        event.message_len = raw.len();
    }
}

/// Milliseconds, saturating rather than wrapping: a duration too long to
/// count is one no caller is waiting for anyway.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

pub(crate) fn registration_state(state: Option<RegistrationState>) -> SipralRegistrationState {
    match state {
        Some(RegistrationState::Idle) => SipralRegistrationState::Idle,
        Some(RegistrationState::Registering) => SipralRegistrationState::Registering,
        Some(RegistrationState::Registered) => SipralRegistrationState::Registered,
        Some(RegistrationState::Refreshing) => SipralRegistrationState::Refreshing,
        Some(RegistrationState::Retrying) => SipralRegistrationState::Retrying,
        Some(RegistrationState::Unregistered) => SipralRegistrationState::Unregistered,
        Some(RegistrationState::Failed) => SipralRegistrationState::Failed,
        Some(RegistrationState::Unverified) => SipralRegistrationState::Unverified,
        Some(RegistrationState::Restored) => SipralRegistrationState::Restored,
        Some(RegistrationState::NotRegistering) => SipralRegistrationState::NotRegistering,
        // nothing to ask about, or a state the layer below has grown and this
        // ABI has no number for; saying so beats picking one that is wrong
        None | Some(_) => SipralRegistrationState::Unknown,
    }
}

fn registration_failure(failure: RegistrationFailure) -> SipralRegistrationFailure {
    match failure {
        RegistrationFailure::Rejected => SipralRegistrationFailure::Rejected,
        RegistrationFailure::BadCredentials => SipralRegistrationFailure::BadCredentials,
        RegistrationFailure::Unreachable => SipralRegistrationFailure::Unreachable,
        RegistrationFailure::Redirected => SipralRegistrationFailure::Redirected,
        RegistrationFailure::UnreachableContact => SipralRegistrationFailure::UnreachableContact,
        _ => SipralRegistrationFailure::None,
    }
}

pub(crate) fn call_state(state: Option<CallState>) -> SipralCallState {
    match state {
        Some(CallState::Calling) => SipralCallState::Calling,
        Some(CallState::Incoming) => SipralCallState::Incoming,
        Some(CallState::Ringing) => SipralCallState::Ringing,
        Some(CallState::EarlyMedia) => SipralCallState::EarlyMedia,
        Some(CallState::Confirmed) => SipralCallState::Confirmed,
        Some(CallState::Consulting) => SipralCallState::Consulting,
        Some(CallState::Terminating) => SipralCallState::Terminating,
        Some(CallState::Terminated) => SipralCallState::Terminated,
        None | Some(_) => SipralCallState::Unknown,
    }
}

fn end_reason(reason: CallEndReason) -> SipralCallEndReason {
    match reason {
        CallEndReason::LocalHangup => SipralCallEndReason::LocalHangup,
        CallEndReason::RemoteHangup => SipralCallEndReason::RemoteHangup,
        CallEndReason::Refused => SipralCallEndReason::Refused,
        CallEndReason::Cancelled => SipralCallEndReason::Cancelled,
        CallEndReason::Unreachable => SipralCallEndReason::Unreachable,
        CallEndReason::ForkLost => SipralCallEndReason::ForkLost,
        CallEndReason::Abandoned => SipralCallEndReason::Abandoned,
        CallEndReason::Expired => SipralCallEndReason::Expired,
        _ => SipralCallEndReason::None,
    }
}

fn digit_source(source: DigitSource) -> SipralDigitSource {
    match source {
        DigitSource::Info => SipralDigitSource::Info,
        DigitSource::InBand => SipralDigitSource::InBand,
        _ => SipralDigitSource::Rtp,
    }
}

/// What a progress detector heard, the way C reads it.
fn progress_of(heard: CallProgress) -> SipralProgressEvent {
    let mut out = SipralProgressEvent {
        what: SipralProgressKind::Unknown as u32,
        tone: SipralProgressTone::Unknown as u32,
        verdict: SipralAmdVerdict::Unknown as u32,
        reason: SipralAmdReason::None as u32,
        at_ms: 0,
        initial_silence_ms: 0,
        greeting_ms: 0,
        words: 0,
        frequency_hz: 0,
        length_ms: 0,
        sit_hz_1: 0,
        sit_hz_2: 0,
        sit_hz_3: 0,
        sit_ms_1: 0,
        sit_ms_2: 0,
        sit_ms_3: 0,
    };
    match heard {
        CallProgress::Tone { tone, at } => {
            out.what = SipralProgressKind::Tone as u32;
            out.tone = progress_tone(tone) as u32;
            out.at_ms = millis(at);
        }
        CallProgress::SpecialInformation {
            frequencies,
            durations,
            at,
        } => {
            out.what = SipralProgressKind::SpecialInformation as u32;
            out.tone = SipralProgressTone::SpecialInformation as u32;
            out.at_ms = millis(at);
            let [first, second, third] = frequencies.map(hertz);
            let [one, two, three] =
                durations.map(|span| u32::try_from(span.as_millis()).unwrap_or(u32::MAX));
            (out.sit_hz_1, out.sit_hz_2, out.sit_hz_3) = (first, second, third);
            (out.sit_ms_1, out.sit_ms_2, out.sit_ms_3) = (one, two, three);
        }
        CallProgress::AnsweredBy {
            verdict,
            reason,
            after,
            initial_silence,
            greeting,
            words,
        } => {
            out.what = SipralProgressKind::AnsweredBy as u32;
            out.verdict = match verdict {
                AmdVerdict::Human => SipralAmdVerdict::Human,
                AmdVerdict::Machine => SipralAmdVerdict::Machine,
                AmdVerdict::NotSure => SipralAmdVerdict::NotSure,
            } as u32;
            out.reason = match reason {
                AmdReason::ShortGreeting => SipralAmdReason::ShortGreeting,
                AmdReason::TooManyWords => SipralAmdReason::TooManyWords,
                AmdReason::LongGreeting => SipralAmdReason::LongGreeting,
                AmdReason::InitialSilence => SipralAmdReason::InitialSilence,
                AmdReason::Timeout => SipralAmdReason::Timeout,
            } as u32;
            out.at_ms = millis(after);
            out.initial_silence_ms = millis(initial_silence);
            out.greeting_ms = millis(greeting);
            out.words = words;
        }
        CallProgress::Beep {
            frequency_hz,
            ended,
            length,
        } => {
            out.what = SipralProgressKind::Beep as u32;
            out.frequency_hz = hertz(frequency_hz);
            out.at_ms = millis(ended);
            out.length_ms = millis(length);
        }
        // a report the facade has grown and this ABI has no word for yet
        _ => {}
    }
    out
}

/// The name this ABI gives a call-progress tone.
const fn progress_tone(tone: ProgressTone) -> SipralProgressTone {
    match tone {
        ProgressTone::Dial => SipralProgressTone::Dial,
        ProgressTone::Ringback => SipralProgressTone::Ringback,
        ProgressTone::Busy => SipralProgressTone::Busy,
        ProgressTone::Congestion => SipralProgressTone::Congestion,
        ProgressTone::CallWaiting => SipralProgressTone::CallWaiting,
        ProgressTone::SpecialInformation => SipralProgressTone::SpecialInformation,
    }
}

/// A measured frequency to the nearest hertz.
fn hertz(frequency: f64) -> u32 {
    // clamped into the range first, so the conversion cannot wrap
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let rounded = frequency.round().clamp(0.0, f64::from(u32::MAX)) as u32;
    rounded
}

#[cfg(test)]
mod tests {
    use super::{
        SipralAnnounceEvent, SipralCallEndReason, SipralCallEvent, SipralCallState, SipralEvent,
        SipralEventKind, SipralEventPayload, SipralRegistrationFailure, SipralRegistrationState,
        call_state, end_reason, millis, registration_failure, registration_state,
        sipral_event_kind_name,
    };
    use sipral_ua::{CallEndReason, CallState, RegistrationFailure, RegistrationState};
    use std::ffi::CStr;
    use std::time::Duration;

    fn name(kind: u32) -> Option<String> {
        let pointer = unsafe { sipral_event_kind_name(kind) };
        if pointer.is_null() {
            return None;
        }
        Some(
            unsafe { CStr::from_ptr(pointer) }
                .to_string_lossy()
                .into_owned(),
        )
    }

    fn started(stack: u64) -> SipralEvent {
        SipralEvent::of(
            stack,
            SipralEventKind::Started,
            payload!(call: SipralCallEvent::empty()),
        )
    }

    #[test]
    fn the_size_member_comes_first_and_says_how_big_the_struct_is() {
        let event = started(9);
        assert_eq!(event.size, size_of::<SipralEvent>());
        let first = unsafe { (&raw const event).cast::<usize>().read_unaligned() };
        assert_eq!(first, size_of::<SipralEvent>());
    }

    #[test]
    fn an_empty_event_names_neither_an_account_nor_a_call() {
        let event = started(9);
        assert_eq!(event.stack, 9);
        assert_eq!(event.account, 0);
        assert_eq!(event.call, 0);
        assert!(event.message.is_null());
        assert_eq!(event.message_len, 0);
    }

    #[test]
    fn the_union_is_the_last_member_so_that_an_arm_can_grow() {
        let event = started(1);
        let base = (&raw const event).cast::<u8>() as usize;
        let payload = (&raw const event.payload).cast::<u8>() as usize;
        let offset = payload - base;
        assert_eq!(
            offset + size_of_val(&event.payload),
            size_of::<SipralEvent>()
        );
    }

    #[test]
    fn bytes_past_the_arm_actually_written_are_zero() {
        // `announce` is one of the union's smallest arms -- a handle and a
        // `u64`, sixteen bytes -- and `message`'s own tail, well past that,
        // is where a byte only `payload!`'s own zeroing could have reached:
        // nothing this call wrote goes anywhere near it. Before `payload!`
        // zeroed the whole union first, that tail was whatever the stack
        // held from before this call, and reading a pointer out of it is
        // what put `sipral-lab-agent-kotlin` on the floor with a `SIGSEGV`
        // inside `NewByteArray` -- the generated Kotlin/JNI shim reads
        // every arm of every event, not only the one `kind` names the way
        // every other binding's own application code already does
        // (`tools/abi-gen/src/kotlin.rs`), and `EVENT_KIND_ARMS` above is
        // what keeps it from dereferencing a pointer out of the bytes this
        // proves are zero rather than out of the ones that are not: the
        // ones another, larger arm's own write left behind, reinterpreted,
        // which are not tested here because they are not zero and are not
        // supposed to be -- see `EVENT_KIND_ARMS`'s own documentation.
        let event = SipralEvent::of(
            1,
            SipralEventKind::CallAnnounced,
            payload!(announce: SipralAnnounceEvent {
                announcement: 7,
                waited_ms: 0,
            }),
        );
        let payload = event.payload;
        assert_eq!(unsafe { payload.announce.announcement }, 7);
        assert_eq!(unsafe { payload.message.urgent_old_messages }, 0);
        assert!(unsafe { payload.message.message_account }.is_null());
        assert_eq!(unsafe { payload.message.message_account_len }, 0);
    }

    #[test]
    fn every_state_the_layer_below_has_is_named_here() {
        let all = [
            (RegistrationState::Idle, SipralRegistrationState::Idle),
            (
                RegistrationState::Registering,
                SipralRegistrationState::Registering,
            ),
            (
                RegistrationState::Registered,
                SipralRegistrationState::Registered,
            ),
            (
                RegistrationState::Refreshing,
                SipralRegistrationState::Refreshing,
            ),
            (
                RegistrationState::Retrying,
                SipralRegistrationState::Retrying,
            ),
            (
                RegistrationState::Unregistered,
                SipralRegistrationState::Unregistered,
            ),
            (RegistrationState::Failed, SipralRegistrationState::Failed),
            (
                RegistrationState::Unverified,
                SipralRegistrationState::Unverified,
            ),
            (
                RegistrationState::Restored,
                SipralRegistrationState::Restored,
            ),
            (
                RegistrationState::NotRegistering,
                SipralRegistrationState::NotRegistering,
            ),
        ];
        for (state, expected) in all {
            assert_eq!(registration_state(Some(state)), expected);
        }
        assert_eq!(registration_state(None), SipralRegistrationState::Unknown);
    }

    #[test]
    fn every_call_state_the_layer_below_has_is_named_here() {
        let all = [
            (CallState::Calling, SipralCallState::Calling),
            (CallState::Incoming, SipralCallState::Incoming),
            (CallState::Ringing, SipralCallState::Ringing),
            (CallState::EarlyMedia, SipralCallState::EarlyMedia),
            (CallState::Confirmed, SipralCallState::Confirmed),
            (CallState::Consulting, SipralCallState::Consulting),
            (CallState::Terminating, SipralCallState::Terminating),
            (CallState::Terminated, SipralCallState::Terminated),
        ];
        for (state, expected) in all {
            assert_eq!(call_state(Some(state)), expected);
        }
        assert_eq!(call_state(None), SipralCallState::Unknown);
    }

    #[test]
    fn every_reason_a_call_ends_for_is_named_here() {
        let all = [
            (CallEndReason::LocalHangup, SipralCallEndReason::LocalHangup),
            (
                CallEndReason::RemoteHangup,
                SipralCallEndReason::RemoteHangup,
            ),
            (CallEndReason::Refused, SipralCallEndReason::Refused),
            (CallEndReason::Cancelled, SipralCallEndReason::Cancelled),
            (CallEndReason::Unreachable, SipralCallEndReason::Unreachable),
            (CallEndReason::ForkLost, SipralCallEndReason::ForkLost),
            (CallEndReason::Abandoned, SipralCallEndReason::Abandoned),
            (CallEndReason::Expired, SipralCallEndReason::Expired),
        ];
        for (reason, expected) in all {
            assert_eq!(end_reason(reason), expected);
        }
    }

    #[test]
    fn every_registration_failure_has_its_own_word() {
        for (failure, expected) in [
            (
                RegistrationFailure::Rejected,
                SipralRegistrationFailure::Rejected,
            ),
            (
                RegistrationFailure::BadCredentials,
                SipralRegistrationFailure::BadCredentials,
            ),
            (
                RegistrationFailure::Unreachable,
                SipralRegistrationFailure::Unreachable,
            ),
            (
                RegistrationFailure::Redirected,
                SipralRegistrationFailure::Redirected,
            ),
            (
                RegistrationFailure::UnreachableContact,
                SipralRegistrationFailure::UnreachableContact,
            ),
        ] {
            assert_eq!(registration_failure(failure), expected);
        }
        assert_eq!(SipralRegistrationFailure::UnreachableContact as u32, 5);
    }

    #[test]
    fn nothing_that_means_absent_shares_a_number_with_something_that_does_not() {
        assert_eq!(SipralRegistrationState::Unknown as u32, 0);
        assert_eq!(SipralRegistrationFailure::None as u32, 0);
        assert_eq!(SipralCallState::Unknown as u32, 0);
        assert_eq!(SipralCallEndReason::None as u32, 0);
    }

    /// The numbers are written out rather than walked. A test that derived
    /// them from the declaration would agree with a declaration that had moved
    /// them, which is the one thing `docs/08-ffi.md` says can never happen.
    #[test]
    fn the_event_numbers_are_where_they_were_published() {
        assert_eq!(SipralEventKind::Started as u32, 1);
        assert_eq!(SipralEventKind::RegistrationChanged as u32, 2);
        assert_eq!(SipralEventKind::IncomingCall as u32, 3);
        assert_eq!(SipralEventKind::CallProgress as u32, 4);
        assert_eq!(SipralEventKind::CallForked as u32, 5);
        assert_eq!(SipralEventKind::CallConfirmed as u32, 6);
        assert_eq!(SipralEventKind::SessionChanged as u32, 7);
        assert_eq!(SipralEventKind::SessionOffered as u32, 8);
        assert_eq!(SipralEventKind::SessionChangeFailed as u32, 9);
        assert_eq!(SipralEventKind::TransferRequested as u32, 10);
        assert_eq!(SipralEventKind::TransferProgress as u32, 11);
        assert_eq!(SipralEventKind::TransferDone as u32, 12);
        assert_eq!(SipralEventKind::CallReplaced as u32, 13);
        assert_eq!(SipralEventKind::CallEnded as u32, 14);
        assert_eq!(SipralEventKind::SubscriptionChanged as u32, 15);
        assert_eq!(SipralEventKind::MediaStatistics as u32, 17);
        assert_eq!(SipralEventKind::TransportWanted as u32, 18);
        assert_eq!(SipralEventKind::MediaStalled as u32, 19);
        assert_eq!(SipralEventKind::AnnouncedCallMissing as u32, 20);
        assert_eq!(SipralEventKind::MediaStarted as u32, 21);
        assert_eq!(SipralEventKind::MediaChanged as u32, 22);
        assert_eq!(SipralEventKind::MediaResumed as u32, 23);
        assert_eq!(SipralEventKind::MediaFailed as u32, 24);
        assert_eq!(SipralEventKind::RecordingStopped as u32, 25);
        assert_eq!(SipralEventKind::DigitReceived as u32, 26);
        assert_eq!(SipralEventKind::DtmfSent as u32, 27);
        assert_eq!(SipralEventKind::Recovery as u32, 28);
        assert_eq!(SipralEventKind::ResolveNeeded as u32, 29);
        assert_eq!(SipralEventKind::Notified as u32, 30);
        assert_eq!(SipralEventKind::CallAnnounced as u32, 31);
        assert_eq!(SipralEventKind::MediaSecured as u32, 32);
        assert_eq!(SipralEventKind::MediaPathChosen as u32, 33);
        assert_eq!(SipralEventKind::MessageReceived as u32, 34);
        assert_eq!(SipralEventKind::MessageSent as u32, 35);
        assert_eq!(SipralEventKind::MessagesWaiting as u32, 36);
        assert_eq!(SipralEventKind::QualityReportSent as u32, 37);
        assert_eq!(SipralEventKind::MediaUnjoined as u32, 38);
        assert_eq!(SipralEventKind::NatMapping as u32, 39);
        assert_eq!(SipralEventKind::NatRelay as u32, 40);
        assert_eq!(SipralEventKind::Referral as u32, 41);
        assert_eq!(SipralEventKind::TurnStream as u32, 42);
        assert_eq!(SipralEventKind::AudioDevicesChanged as u32, 43);
        assert_eq!(SipralEventKind::CallAddressWanted as u32, 45);
        assert_eq!(SipralEventKind::StunServer as u32, 46);
        assert_eq!(SipralEventKind::CallerVerification as u32, 47);
        assert_eq!(SipralEventKind::InBandDigit as u32, 48);
        assert_eq!(SipralEventKind::ProgressDetected as u32, 49);
        assert_eq!(SipralEventKind::ConferenceChanged as u32, 50);
        assert_eq!(SipralEventKind::TextReceived as u32, 51);
        assert_eq!(SipralEventKind::PresenceChanged as u32, 52);
        assert_eq!(SipralEventKind::TransportFailed as u32, 53);
        assert_eq!(SipralEventKind::LocalConferenceChanged as u32, 54);
        assert_eq!(SipralEventKind::LookupWanted as u32, 55);
        assert_eq!(SipralEventKind::Located as u32, 56);
        assert_eq!(SipralEventKind::LocateFailed as u32, 57);
        assert_eq!(SipralEventKind::ChallengeDeclined as u32, 58);
        assert_eq!(SipralEventKind::TokenRequired as u32, 59);
        assert_eq!(SipralEventKind::ALL.len(), 57, "and there are no others");
    }

    /// The numbers this DTMF surface and the media one before it took were
    /// spoken for before either was written, and each took them where they
    /// were rather than appending. A feature that had chosen the next free
    /// number instead would have renamed the one still reserved.
    #[test]
    fn the_numbers_that_were_reserved_for_this_are_the_ones_it_took() {
        assert_eq!(
            SipralEventKind::MediaStatistics as u32,
            17,
            "17 was held for stream statistics (A6)"
        );
        assert_eq!(
            SipralEventKind::MediaStalled as u32,
            19,
            "19 was held for media that stopped arriving (B5)"
        );
        assert_eq!(
            SipralEventKind::DtmfSent as u32,
            27,
            "27 was held for a DTMF digit sent by SIP INFO being answered (8.3.11)"
        );
        assert_eq!(
            SipralEventKind::Recovery as u32,
            28,
            "28 was held for the stack recovering from a suspension or a network change (8.4.13)"
        );
        assert_eq!(
            SipralEventKind::TransportWanted as u32,
            18,
            "18 was held for a request promoted to a stream transport (B1)"
        );
        assert_eq!(
            SipralEventKind::ResolveNeeded as u32,
            29,
            "29 was held for the application being asked to resolve a destination (8.4.11)"
        );
    }

    #[test]
    fn every_kind_has_a_name_of_its_own() {
        let mut seen = Vec::new();
        for kind in SipralEventKind::ALL {
            let Some(text) = name(*kind as u32) else {
                panic!("no name for {kind:?}");
            };
            assert!(!seen.contains(&text), "{text} names two kinds");
            seen.push(text);
        }
    }

    /// The reserved numbers are the mechanism, so this is the test of it: a
    /// number that is spoken for but not built answers exactly like one that
    /// was never spent, and a feature that takes it has to say so in the one
    /// declaration before this build will name it.
    #[test]
    fn a_number_held_for_a_feature_this_build_lacks_names_nothing() {
        // two numbers are held: 16 and 44, both for audio devices; 34 to 37, held while
        // MESSAGE and RTCP-XR were written apart, are live now
        assert_eq!(name(16), None, "16 is reserved, not live");
        assert_eq!(
            name(37).as_deref(),
            Some("quality report sent"),
            "37 is live"
        );
        assert_eq!(name(38).as_deref(), Some("media unjoined"), "38 is live");
        assert_eq!(name(39).as_deref(), Some("nat mapping"), "39 is live");
        assert_eq!(name(40).as_deref(), Some("nat relay"), "40 is live");
        assert_eq!(name(41).as_deref(), Some("referral"), "41 is live");
        assert_eq!(name(42).as_deref(), Some("turn stream"), "42 is live");
        assert_eq!(
            name(43).as_deref(),
            Some("audio devices changed"),
            "43 is live"
        );
        assert_eq!(name(44), None, "44 is reserved, not live");
        assert_eq!(
            name(45).as_deref(),
            Some("call address wanted"),
            "45 is live"
        );
        assert_eq!(name(46).as_deref(), Some("stun server"), "46 is live");
        assert_eq!(
            name(47).as_deref(),
            Some("caller verification"),
            "47 is live"
        );
        assert_eq!(name(48).as_deref(), Some("in-band digit"), "48 is live");
        assert_eq!(name(49).as_deref(), Some("progress detected"), "49 is live");
        assert_eq!(
            name(50).as_deref(),
            Some("conference changed"),
            "50 is live"
        );
        assert_eq!(name(51).as_deref(), Some("text received"), "51 is live");
        assert_eq!(name(52).as_deref(), Some("presence changed"), "52 is live");
        assert_eq!(name(53).as_deref(), Some("transport failed"), "53 is live");
        assert_eq!(
            name(54).as_deref(),
            Some("local conference changed"),
            "54 is live"
        );
        assert_eq!(name(55).as_deref(), Some("lookup wanted"), "55 is live");
        assert_eq!(name(56).as_deref(), Some("located"), "56 is live");
        assert_eq!(name(57).as_deref(), Some("locate failed"), "57 is live");
        assert_eq!(
            name(58).as_deref(),
            Some("challenge declined"),
            "58 is live"
        );
        assert_eq!(name(59).as_deref(), Some("token required"), "59 is live");
        assert_eq!(name(60), None, "past the last kind");
        assert_eq!(name(0), None, "no kind is zero");
        assert_eq!(name(u32::MAX), None);
    }

    #[test]
    fn a_duration_too_long_to_count_saturates_rather_than_wrapping() {
        assert_eq!(millis(Duration::from_secs(1)), 1_000);
        assert_eq!(millis(Duration::ZERO), 0);
        assert_eq!(millis(Duration::MAX), u64::MAX);
    }

    /// A call secured under any suite the stack runs says which one: none of
    /// them falls back to `Unknown`, which is kept for an event that is not
    /// about a transform, and no two share a number.
    #[cfg(feature = "dtls")]
    #[test]
    fn every_suite_the_stack_runs_has_a_word_of_its_own() {
        use crate::media::SipralSrtpSuite;
        use sipral::SrtpSuite;

        let named = [
            (SrtpSuite::AesCm80, 1),
            (SrtpSuite::AesCm32, 2),
            (SrtpSuite::AesF8, 3),
            (SrtpSuite::Aes256Cm80, 4),
            (SrtpSuite::Aes256Cm32, 5),
            (SrtpSuite::AeadAes128Gcm, 6),
            (SrtpSuite::AeadAes256Gcm, 7),
        ];
        let mut seen = Vec::new();
        for (suite, number) in named {
            let word = super::suite_of(suite);
            assert_ne!(word, SipralSrtpSuite::Unknown, "{suite:?}");
            assert_eq!(word as u32, number, "{suite:?}");
            assert!(!seen.contains(&number), "{suite:?}");
            seen.push(number);
        }
    }
}
