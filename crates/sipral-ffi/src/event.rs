// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

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

#[cfg(feature = "dtls")]
use sipral::SrtpSuite;
use sipral::{DigitSource, MediaEvent};
use sipral_core::endpoint::Event;
use sipral_core::msg::HeaderName;
use sipral_ua::{
    CallEndReason, CallHandle, CallIdentity, CallState, LifecycleState, RecoveryFailure,
    RegistrationFailure, RegistrationState, Rung, UaEvent, UserAgent,
};

use crate::abi::{alias, codes, record};
use crate::error::entry;
use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
use crate::media::{SipralStreamStats, direction_of, fault_of, named_codec};
use crate::names::Names;
use crate::nat::{SipralNatEvent, SipralNatRelayEvent, SipralTurnStreamEvent};
use crate::subscription::{SipralSubscriptionState, named_end, named_state};

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
            fn sipral_event_kind_name(kind: u32) -> *const c_char, on_panic = std::ptr::null(), {
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
        reserved 16 = "the set of audio devices changed (A2)";

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
        /// B1. Answered with
        /// [`sipral_stack_transport_bind`](crate::transport::sipral_stack_transport_bind):
        /// once the application binds a transport to that destination, the
        /// stack sends the request again by itself and this ABI raises
        /// nothing further about it — there is no "it went" event, the same
        /// way there is none for an ordinary request that fit the first time.
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
        /// (`sipral_account_settings_t::quality_report_uri`); a call whose
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
    /// Which of the two ways this stack accepts a digit reported the one
    /// [`SipralEventKind::DigitReceived`] carries. Names for
    /// `sipral_media_event_t::source`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDigitSource: u32 {
        /// RFC 4733: a named telephone event in the RTP stream.
        Rtp = 0,
        /// RFC 3261's INFO method (RFC 6086), carrying `application/dtmf-relay`
        /// or `application/dtmf`.
        Info = 1,
    }
}

codes! {
    /// What a [`SipralEventKind::Recovery`] reports happened, for
    /// `payload.recovery.state`. Names for the two ways `sipral_ua`'s
    /// lifecycle machine settles: a registrar answered again, or a recovery
    /// ladder ran out of rungs.
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
    /// [`SipralRecoveryOutcome::GaveUp`]. Names for `sipral_ua::Rung`, minus
    /// [`Rung::GiveUp`] itself: `sipral_ua` reports the rung before it that
    /// asked for something and went unanswered, not the give-up rung that
    /// follows it.
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
    /// `payload.recovery.reason`. Names for `sipral_ua::RecoveryFailure`.
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
        pub state: u32,
        /// A [`SipralRegistrationFailure`], zero when nothing failed.
        pub failure: u32,
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
        pub state: u32,
        /// A [`SipralCallEndReason`], zero while the call is alive.
        pub end_reason: u32,
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
        /// A [`SipralCodec`](crate::media::SipralCodec): what the negotiation
        /// settled on, zero where the event is not about a codec.
        pub codec: u32,
        /// A [`SipralDirection`](crate::media::SipralDirection): which way audio
        /// may flow, as seen from here.
        pub direction: u32,
        /// How long the stream has been silent, for a stall and for its recovery.
        pub silent_for_ms: u64,
        /// How much audio reached the file, for a recording that stopped by
        /// itself.
        pub recorded_ms: u64,
        /// A [`SipralMediaFault`](crate::media::SipralMediaFault), zero when
        /// nothing failed.
        pub fault: u32,
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
        /// A [`SipralSrtpSuite`](crate::media::SipralSrtpSuite): the transform
        /// this call's media is protected with, for
        /// [`SipralEventKind::MediaSecured`] and zero on every other kind.
        pub suite: u32,
        /// A [`SipralDigitSource`]: which of the two ways this stack accepts a
        /// digit reported this one, for [`SipralEventKind::DigitReceived`].
        pub source: u32,
        /// Whether the RFC 6035 PUBLISH left this end, for
        /// [`SipralEventKind::QualityReportSent`] and zero on every other
        /// kind. Not whether a collector accepted it.
        pub quality_report_sent: u32,
    }
}

record! {
    /// What a [`SipralEventKind::Recovery`] carries: the lifecycle machine
    /// settling, either by proving the path again or by giving the ladder up.
    #[derive(Clone, Copy)]
    pub struct SipralRecoveryEvent {
        /// A [`SipralRecoveryOutcome`].
        pub state: u32,
        /// A [`SipralRecoveryRung`]: the last rung tried. Zero unless `state`
        /// is [`SipralRecoveryOutcome::GaveUp`].
        pub rung: u32,
        /// A [`SipralRecoveryFailure`]. Zero unless `state` is
        /// [`SipralRecoveryOutcome::GaveUp`].
        pub reason: u32,
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
        pub state: u32,
        /// A [`SipralSubscriptionEnd`](crate::subscription::SipralSubscriptionEnd):
        /// why it is not live. Zero while it is.
        pub reason: u32,
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
        /// [`SipralTransport`](crate::stack::SipralTransport). Zero for a
        /// protocol this build has no number for, which
        /// `sipral_stack_transport_bind` then cannot be asked to open
        /// either — nothing this build originates ever measures against a
        /// protocol like that, so this is the layer below having grown one
        /// rather than a caller mistake.
        pub protocol: u32,
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
        /// is answered with. Minted by the library, valid while the dialog
        /// is, and answering for one that has ended changes nothing rather
        /// than failing.
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
        /// [`SipralTransport`](crate::stack::SipralTransport), or zero for
        /// neither — which leaves §4.1's NAPTR step to the caller, and is
        /// also what a protocol this build has no number for reads as.
        pub protocol: u32,
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
    /// The arm of an event that its kind names.
    ///
    /// Reading any other arm reads bytes the library did not write for it.
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
    /// given included: see [`crate::stack`].
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
    if let Some(out) = about_a_resolve(known, event, transport) {
        return Some(out);
    }
    about_lifecycle(known, event)
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
        _ => None,
    }
}

fn about_registration(known: &mut Vocabulary<'_>, event: &UaEvent) -> Option<SipralEvent> {
    match *event {
        UaEvent::Registering { account }
        | UaEvent::Refreshing { account }
        | UaEvent::Unregistered { account } => {
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
        } => {
            let mut payload = call_payload(known, call);
            // the layer below has already let the call go, so the state is
            // said here rather than asked for
            payload.state = SipralCallState::Terminated as u32;
            payload.end_reason = end_reason(reason) as u32;
            payload.status_code = status_of(status);
            let mut out = call_event(known, SipralEventKind::CallEnded, call, payload);
            attach(&mut out, response.as_ref());
            Some(out)
        }
        _ => None,
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

/// The transform a call is running, on this side of the boundary.
///
/// RFC 6188's and RFC 7714's four newer suites (8.2.4) have no word of their
/// own on this side of the boundary yet — growing one is an ABI change, and
/// this batch does not make one — so a call running under one of those
/// reports `Unknown`, the same fallback a signalling event this ABI has no
/// word for already uses.
#[cfg(feature = "dtls")]
const fn suite_of(suite: SrtpSuite) -> crate::media::SipralSrtpSuite {
    use crate::media::SipralSrtpSuite;
    match suite {
        SrtpSuite::AesCm80 => SipralSrtpSuite::AesCm80,
        SrtpSuite::AesCm32 => SipralSrtpSuite::AesCm32,
        SrtpSuite::AesF8 => SipralSrtpSuite::AesF8,
        SrtpSuite::Aes256Cm80
        | SrtpSuite::Aes256Cm32
        | SrtpSuite::AeadAes128Gcm
        | SrtpSuite::AeadAes256Gcm => SipralSrtpSuite::Unknown,
    }
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
pub(crate) fn media(
    known: &mut Vocabulary<'_>,
    call: CallHandle,
    event: &MediaEvent,
    reason: Option<&str>,
    statistics: Option<&SipralStreamStats>,
) -> Option<SipralEvent> {
    let mut payload = SipralMediaEvent::empty();
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
            SipralEventKind::DigitReceived
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

/// The sentence a media event carries, for the kinds that have one to say.
///
/// Built here rather than in the translation because it has to outlive the
/// borrow the event holds, and a `String` handed to C has to belong to
/// something that is still alive when the callback reads it.
pub(crate) fn media_reason(event: &MediaEvent) -> Option<String> {
    match *event {
        MediaEvent::Failed(ref error) => Some(error.to_string()),
        MediaEvent::RecordingStopped { ref reason, .. } => Some(reason.to_string()),
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
        // kept on the vocabulary rather than dropped here, so that whoever
        // queues this event can keep these bytes alive for as long as the
        // delivery takes: the map this came from may be missing the entry by
        // then, forgotten alongside a call that has ended in the meantime
        known.raised_identity = Some(identity);
    }
    payload
}

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
        _ => SipralDigitSource::Rtp,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SipralAnnounceEvent, SipralCallEndReason, SipralCallEvent, SipralCallState, SipralEvent,
        SipralEventKind, SipralEventPayload, SipralRegistrationFailure, SipralRegistrationState,
        call_state, end_reason, millis, registration_state, sipral_event_kind_name,
    };
    use sipral_ua::{CallEndReason, CallState, RegistrationState};
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
        assert_eq!(SipralEventKind::ALL.len(), 41, "and there are no others");
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
        // one number is held: 16, for audio devices; 34 to 37, held while
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
        assert_eq!(name(43), None, "past the last kind");
        assert_eq!(name(0), None, "no kind is zero");
        assert_eq!(name(u32::MAX), None);
    }

    #[test]
    fn a_duration_too_long_to_count_saturates_rather_than_wrapping() {
        assert_eq!(millis(Duration::from_secs(1)), 1_000);
        assert_eq!(millis(Duration::ZERO), 0);
        assert_eq!(millis(Duration::MAX), u64::MAX);
    }
}
