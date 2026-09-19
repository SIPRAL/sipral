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

use sipral::{DigitSource, MediaEvent};
use sipral_core::endpoint::Event;
use sipral_ua::{
    CallEndReason, CallHandle, CallIdentity, CallState, LifecycleState, RecoveryFailure,
    RegistrationFailure, RegistrationState, Rung, UaEvent, UserAgent,
};

use crate::abi::{alias, codes, record};
use crate::error::entry;
use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
use crate::media::{SipralStreamStats, direction_of, fault_of, named_codec};
use crate::names::Names;
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

        // Held for the event the C ABI does not raise yet, already planned
        // behind an entry point of its own, so that the branch adding it
        // cannot arrive holding the same number.
        reserved 29 = "the application is asked to resolve a destination";

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
    }
}

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
        /// A [`SipralDigitSource`]: which of the two ways this stack accepts a
        /// digit reported this one, for [`SipralEventKind::DigitReceived`].
        pub source: u32,
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
            source: SipralDigitSource::Rtp as u32,
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
        SipralEventPayload {
            call: SipralCallEvent::empty(),
        },
    )
}

/// Everything one translation needs to reach.
pub(crate) struct Vocabulary<'a> {
    pub(crate) stack: SipralHandle,
    pub(crate) agent: &'a UserAgent,
    pub(crate) accounts: &'a mut Names<sipral_ua::AccountId>,
    pub(crate) calls: &'a mut Names<CallHandle>,
    pub(crate) subscriptions: &'a mut Names<sipral_ua::SubscriptionHandle>,
    pub(crate) announcements: &'a mut Names<sipral_ua::AnnouncementId>,
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
/// carries one more this ABI has to point at that `event` holds no bytes
/// for: [`SipralEventKind::TransportWanted`]'s destination, formatted by
/// [`transport_wanted_destination`] before this is called, since a
/// `SocketAddr` has none of its own. Both have to outlive the callback this
/// is handed to.
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
    if let Some(out) = about_an_announcement(known, event) {
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
                SipralEventPayload { announce: payload },
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
                SipralEventPayload { announce: payload },
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
                SipralEventPayload {
                    subscription: payload,
                },
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
                SipralEventPayload {
                    subscription: payload,
                },
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
                SipralEventPayload {
                    subscription: payload,
                },
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
                SipralEventPayload {
                    subscription: payload,
                },
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
                SipralEventPayload {
                    subscription: payload,
                },
            );
            attach(&mut out, response.as_ref());
            Some(out)
        }
        _ => None,
    }
}

/// A request RFC 3261 §18.1.1 would not let out over a datagram, with
/// nowhere open to send it instead. `destination` is the text
/// [`transport_wanted_destination`] built for the event this is about; `None`
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
                SipralEventPayload {
                    transport_wanted: payload,
                },
            ))
        }
        _ => None,
    }
}

/// The destination of a [`SipralEventKind::TransportWanted`], formatted once
/// so the event this ABI raises for it has bytes to point at: a `SocketAddr`
/// carries none of its own. `None` for every other kind of event, which is
/// also what a caller who does not care to check the kind first gets.
pub(crate) fn transport_wanted_destination(event: &UaEvent) -> Option<String> {
    match *event {
        UaEvent::Unclaimed(Event::TransportWanted { destination, .. }) => {
            Some(destination.to_string())
        }
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
        SipralEventPayload { recovery: payload },
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
        _ => return None,
    };
    if let Some(sentence) = reason {
        payload.reason = sentence.as_ptr().cast::<c_char>();
        payload.reason_len = sentence.len();
    }
    if let Some(record) = statistics {
        payload.statistics = std::ptr::from_ref(record);
    }
    let mut out = SipralEvent::of(known.stack, kind, SipralEventPayload { media: payload });
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
        SipralEventPayload {
            registration: payload,
        },
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
    let mut out = SipralEvent::of(known.stack, kind, SipralEventPayload { call: payload });
    out.call = known.calls.name_of(call).unwrap_or(SIPRAL_HANDLE_NONE);
    out
}

fn transfer_event(
    known: &mut Vocabulary<'_>,
    kind: SipralEventKind,
    call: CallHandle,
    payload: SipralTransferEvent,
) -> SipralEvent {
    let mut out = SipralEvent::of(known.stack, kind, SipralEventPayload { transfer: payload });
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
        SipralCallEndReason, SipralCallEvent, SipralCallState, SipralEvent, SipralEventKind,
        SipralEventPayload, SipralRegistrationFailure, SipralRegistrationState, call_state,
        end_reason, millis, registration_state, sipral_event_kind_name,
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
            SipralEventPayload {
                call: SipralCallEvent::empty(),
            },
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
        assert_eq!(SipralEventKind::Notified as u32, 30);
        assert_eq!(SipralEventKind::CallAnnounced as u32, 31);
        assert_eq!(SipralEventKind::ALL.len(), 29, "and there are no others");
    }

    /// The numbers this DTMF surface and the media one before it took were
    /// spoken for before either was written, and each took them where they
    /// were rather than appending. A feature that had chosen the next free
    /// number instead would have renamed one of the two still reserved.
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
        for held in [16, 29_u32] {
            assert_eq!(name(held), None, "{held} is reserved, not live");
        }
        assert_eq!(name(32), None, "past the last kind");
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
