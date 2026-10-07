// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One event, one callback, one tagged union.
//!
//! Everything the stack reports arrives as a [`SipralEvent`]: a size, handles, a
//! kind, and a union whose arm the kind names. A binding registers one function
//! pointer, and a kind added later is simply ignored by a caller that does not
//! know it.
//!
//! Nothing inside the union is an enumerated type: reading a Rust enum out of an
//! arm the library did not write is undefined behaviour, so enumerated members
//! there are plain integers with names declared next to them.
//!
//! Pointers in an event belong to the library and are valid only for the
//! duration of the callback. Copy what you need; there is nothing to free.

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
use crate::network_test::SipralNetworkTestEvent;
use crate::presence::SipralPresenceEvent;
use crate::realtime_text::SipralTextEvent;
use crate::security::{
    SipralAttestation, SipralKeyExchange, SipralVerificationFailure, SipralVerificationOutcome,
    SipralVerificationStage,
};
use crate::stack::SipralTransport;
use crate::subscription::{SipralSubscriptionEnd, SipralSubscriptionState, named_end, named_state};
use crate::transport::SipralTransportFailedEvent;

/// Declare the event number space, once: the enum, the log name and the
/// number are generated from one list, so none can be missed.
///
/// The generated assertion checks the list runs `1, 2, 3, …` with no repeat and
/// no hole, live and reserved lines interleaved in number order. Without it, two
/// features could each take the next free number and silently rename an event a
/// shipped binding knows. A reserved line turns into a kind in place. Removing
/// or reordering a line is forbidden by `docs/08-ffi.md`.
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
        /// Numbers already spent on features this build does not have:
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
            /// Every kind this build has, in number order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),*];

            /// What this enumeration is, for the header and the bindings,
            /// reserved numbers included.
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
            /// string, or null for a number this build has no kind for
            /// (reserved numbers included).
            ///
            /// The string belongs to the library and lives as long as it is
            /// loaded.
            ///
            /// # Safety
            ///
            /// Reads no caller memory; safe from any thread.
            fn sipral_event_kind_name(
                kind: Number<SipralEventKind>,
            ) -> *const c_char, on_panic = std::ptr::null(), {
                match kind {
                    $($number => $name.as_ptr(),)*
                    _ => std::ptr::null(),
                }
            }
        }

        // a collision, a hole or a reordering fails the build here
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
    /// What an event is about. Numbers are only ever added; a binding must
    /// ignore a kind it does not know.
    kinds {
        /// The stack is running on this thread: the first event, delivered
        /// once by the first poll.
        1 = Started, c"started";
        /// A registration moved. `payload.registration` says how, and
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
        /// And how it ended: the far end's final status, a 2xx hanging this
        /// call up. A refused REFER (RFC 3515 §2.4.2) ends here with its status,
        /// a timeout as 408, a transport failure as 503; the call stays up.
        12 = TransferDone, c"transfer done";
        /// A call arrived carrying a `Replaces` and took over one already up.
        /// `payload.call.other` is the one being replaced.
        13 = CallReplaced, c"call replaced";
        /// The call is over; its handle is stale from here on. `message` is
        /// the refusal, or the far end's BYE or CANCEL, or null.
        14 = CallEnded, c"call ended";

        /// A1. A subscription moved: asked for, granted, on probation,
        /// retrying, or ended. `payload.subscription` says which and where it
        /// is, `reason` why it is not live. Not sent per refresh or per NOTIFY.
        15 = SubscriptionChanged, c"subscription changed";

        // held for `docs/13-client-requirements.md` features; taken in place
        reserved 16 = "held for the set of audio devices changed (A2), which shipped as 43 in the wave that allocated its number; spent all the same";

        /// A6. What one call's media cost, once, after
        /// `SIPRAL_EVENT_KIND_CALL_ENDED`. `payload.media.statistics` points
        /// at the record, library-owned and valid for the callback.
        17 = MediaStatistics, c"media statistics";
        /// B1. A request grew too large for a datagram (RFC 3261 §18.1.1) and
        /// no stream transport is open to its destination; it was refused with
        /// `SIPRAL_STATUS_NOT_SENT`. `payload.transport_wanted` says where.
        /// Bind with
        /// [`sipral_stack_transport_bind`](crate::transport::sipral_stack_transport_bind)
        /// and ask again.
        18 = TransportWanted, c"transport wanted";
        /// B5. No media has arrived for longer than the configured threshold.
        /// `payload.media.silent_for_ms` says how long. The call is left up.
        19 = MediaStalled, c"media stalled";
        /// C2. A call a push announced never arrived: the device woke and
        /// refreshed, and no INVITE followed. `payload.announce` says which
        /// announcement and how long it was waited for.
        20 = AnnouncedCallMissing, c"announced call missing";
        /// A4, D5. Audio is running; `payload.media.codec` is the agreed codec.
        /// Mint the media handle now with `sipral_call_media`.
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
        /// A recording stopped on its own (disk full, file gone).
        /// `payload.media.recorded_ms` says how much was written.
        25 = RecordingStopped, c"recording stopped";
        /// The far end pressed a key (RFC 4733 event, or INFO with
        /// `application/dtmf-relay` or `application/dtmf`), one per press.
        /// `payload.media` gives `digit`, `event_code`, `held_ms` and `source`.
        /// `held_ms` zero means no duration or `Duration=0`, not told apart.
        26 = DigitReceived, c"digit received";
        /// An INFO from `sipral_call_send_dtmf` got a final answer:
        /// `payload.call.digit` and `payload.call.status_code` (415: try the
        /// other INFO form). An unsendable queued digit reports 503 and stops
        /// the rest.
        27 = DtmfSent, c"dtmf sent";
        /// The lifecycle ladder settled: a path proved again, or every rung
        /// failed. `payload.recovery` says which (`docs/16-lifecycle.md`).
        28 = Recovery, c"recovery";

        /// A dialog's next hop is a name to resolve (RFC 3263 §4 TARGET).
        /// Answer with
        /// [`sipral_stack_resolved`](crate::resolve::sipral_stack_resolved)
        /// and `payload.resolve.dialog`. **Ignoring it is fine**: the dialog
        /// keeps its first flow (§8.1.2), which survives a NAT.
        29 = ResolveNeeded, c"resolve needed";

        /// A1. A notification arrived and was answered; the NOTIFY is in
        /// `message`. `payload.subscription.has_dialog_info` says the body was
        /// readable dialog-info, read via
        /// [`sipral_subscription_dialog_count`](crate::subscription::sipral_subscription_dialog_count).
        /// An unreadable body arrives with it zero; the old picture is kept.
        30 = Notified, c"notified";
        /// C2. The INVITE for a call a push announced arrived (RFC 8599),
        /// queued just before its [`SipralEventKind::IncomingCall`].
        /// `payload.announce.announcement` is now spent:
        /// `sipral_announcement_forget` answers `SIPRAL_STATUS_WRONG_STATE`.
        31 = CallAnnounced, c"call announced";
        /// The DTLS-SRTP handshake finished and audio can move (RFC 5764).
        /// `payload.media.suite` is the chosen transform. SDES calls never
        /// raise it; a failed handshake raises `SIPRAL_EVENT_KIND_MEDIA_FAILED`
        /// and leaves the call up.
        32 = MediaSecured, c"media secured";
        /// ICE chose this call's media path (RFC 8445 §8.1.1), and audio can
        /// move; again if a higher-priority pair replaces it. Addresses are not
        /// carried: each outgoing packet names its destination. Never raised
        /// without ICE (default `SIPRAL_ICE_OFF`).
        33 = MediaPathChosen, c"media path chosen";
        /// A MESSAGE arrived (RFC 3428 §7) and was answered 200.
        /// `payload.message` carries the body; `call` is set if it was in-dialog.
        34 = MessageReceived, c"message received";
        /// A MESSAGE from `sipral_account_message` got its final answer:
        /// `payload.message.status_code` (408/503 for timeout or transport).
        35 = MessageSent, c"message sent";
        /// A `message-summary` NOTIFY reported a mailbox (RFC 3842 §3.9);
        /// `payload.message` has the `voice-message` counts.
        36 = MessagesWaiting, c"messages waiting";
        /// The RFC 6035 quality report PUBLISH was attempted once, after
        /// `SIPRAL_EVENT_KIND_CALL_ENDED`, if `quality_report_uri` was set.
        /// `payload.media.quality_report_sent` says it left, not that it landed.
        37 = QualityReportSent, c"quality report sent";
        /// The call this one was joined to ended. `call` is the survivor and
        /// carries on unjoined, fed directly rather than by `sipral_media_mix`.
        38 = MediaUnjoined, c"media unjoined";
        /// A STUN server reported, moved or never answered for a socket
        /// (RFC 8489). Only with `SIPRAL_NAT_STUN`. `payload.nat` says which.
        /// Signalling sockets are already re-registered; a media socket from
        /// `sipral_stack_nat_map` is now usable for calls (before, that is
        /// `SIPRAL_STATUS_WRONG_STATE`). `account`, `call`: none.
        39 = NatMapping, c"nat mapping";
        /// A TURN server allocated a relay for a `sipral_stack_nat_map` socket,
        /// or gave none (RFC 8656). Only with a `turn_server`. `payload.relay`
        /// says which; once allocated, calls may use it (before, that is
        /// `SIPRAL_STATUS_WRONG_STATE`). `account`, `call`: none.
        40 = NatRelay, c"nat relay";
        /// An out-of-dialog REFER asks this end to place a call (RFC 3515),
        /// with `sipral_stack_config_t::referrals` on. `call` is the referral's
        /// handle, taken only by `sipral_call_accept_transfer` (202, places the
        /// call) or `sipral_call_reject_transfer`; either spends it. `account`
        /// is the line, `message` the REFER, `payload.referral` the target.
        /// **The application decides each time**: `referred_by` is unverified.
        /// If left unanswered, raised again with only `status_code` set, and
        /// the handle is stale.
        41 = Referral, c"referral";
        /// A media socket's TCP/TLS connection to a TURN server
        /// (`turn_transport`, RFC 8656 §3.1) is to be opened or closed.
        /// `payload.turn_stream` says which. On `SIPRAL_TURN_STREAM_OPEN`, open
        /// it (TLS checked against the server name), then call
        /// `sipral_stack_turn_connected`, `sipral_stack_turn_receive` and
        /// `sipral_stack_turn_closed`. On `SIPRAL_TURN_STREAM_CLOSE`, flush and
        /// close. `account`, `call`: none.
        42 = TurnStream, c"turn stream";
        /// The audio engine's devices moved (with `SIPRAL_AUDIO_DEVICE`).
        /// `payload.audio` says what and whether the system or the engine did
        /// it. `account`, `call`: none.
        43 = AudioDevicesChanged, c"audio devices changed";
        reserved 44 = "held for a second audio device event, which the audio engine did not need; spent all the same";

        /// The network changed and this call's media address is gone. Raised
        /// per call by `sipral_stack_network_changed` on
        /// `SIPRAL_RECOVERY_REBUILD`: after `sipral_account_rebind`, pass a new
        /// socket address to `sipral_call_media_readdress`.
        45 = CallAddressWanted, c"call address wanted";
        /// The STUN server in use changed, or all failed
        /// (`payload.stun_server`). A server fails after 5.5 s and is skipped
        /// for 30 s, doubling up to ten minutes. Sockets move on by themselves.
        /// `account`, `call`: none.
        46 = StunServer, c"stun server";
        /// Caller verification (RFC 8224, RFC 8588); `payload.verification`.
        /// `CERTIFICATE_WANTED`: fetch `certificate_url` and pass it (or
        /// nothing) to `sipral_call_stir_certificate`; the call waits.
        /// `VERIFIED`: the verdict, just before the call's
        /// `SIPRAL_EVENT_KIND_INCOMING_CALL`, or with `refused` set before its
        /// `SIPRAL_EVENT_KIND_CALL_ENDED`. `message` is the INVITE.
        47 = CallerVerification, c"caller verification";
        /// A keypad digit heard as tones (with DTMF detection enabled), once
        /// per press. A press also sent as a named event is reported once as
        /// `SIPRAL_EVENT_KIND_DIGIT_RECEIVED`; tones alone wait 250 ms.
        48 = InBandDigit, c"in-band digit";
        /// What `sipral_call_detect_progress` heard: a progress tone, the
        /// special information tone, who answered, or a machine's beep
        /// (`payload.progress`).
        49 = ProgressDetected, c"progress detected";
        /// A `conference` subscription's picture changed or the conference
        /// ended (RFC 4575 §4.6); `payload.conference`. Read the picture with
        /// `sipral_subscription_conference`. Out-of-order documents raise
        /// nothing; after a loss the stack asks for full state.
        50 = ConferenceChanged, c"conference changed";
        /// Real-time text from the far end (RFC 4103), in order, UTF-8 in
        /// `payload.text`: BACKSPACE erases, U+2028 is a new line, BELL alerts,
        /// U+FFFD marks each unrecovered lost block (§5.3), counted in `missing`.
        51 = TextReceived, c"text received";
        /// Presence moved: a `presence` subscription's PIDF (RFC 3856), or this
        /// account's publication (RFC 3903). `payload.presence.kind` says
        /// which.
        52 = PresenceChanged, c"presence changed";
        /// A signalling transport stopped: reported failed or closed, bad
        /// stream bytes, or a keep-alive unanswered for ten seconds (RFC 5626
        /// §4.4.1). `payload.transport_failed` says why. Until
        /// `sipral_stack_transport_bind` restores it, requests get
        /// `SIPRAL_STATUS_TRANSPORT_DOWN`. `account`, `call`: none.
        53 = TransportFailed, c"transport failed";
        /// A local conference changed: membership, talkers, or recording
        /// (`payload.local_conference`). `account`, `call`: none.
        54 = LocalConferenceChanged, c"local conference changed";
        /// A DNS lookup is wanted to locate an account's server (RFC 3263).
        /// Pass every answer, failures included, to `sipral_account_looked_up`.
        55 = LookupWanted, c"lookup wanted";
        /// An account's server was located: `payload.locate.targets`, the
        /// address in use first.
        56 = Located, c"located";
        /// Locating an account's server failed; `retry_in_ms` says when it
        /// retries. An earlier address stays in use.
        57 = LocateFailed, c"locate failed";
        /// A challenge was not answered because it came from outside the
        /// account's protection domain (RFC 3261 §22.1): an answer would feed
        /// an offline password guess. `payload.challenge` says who and why.
        58 = ChallengeDeclined, c"challenge declined";
        /// The account's server wants an OAuth 2.0 token (RFC 8898) and has
        /// none acceptable. Check `payload.token.authz_server` against trusted
        /// servers (§2.1.1), then pass a token to
        /// `sipral_account_set_access_token`.
        59 = TokenRequired, c"token required";
        /// A `sipral_stack_network_test` finished; `payload.network_test`.
        60 = NetworkTest, c"network test";
    }
}

/// Which arm of [`SipralEventPayload`] each live kind writes.
///
/// For the Kotlin/JNI generator (`tools/abi-gen/src/kotlin.rs`), which reads
/// every arm and must not dereference one nothing wrote (a `SIGSEGV` once).
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
    (SipralEventKind::NetworkTest, "network_test"),
];

// every live kind once, in order; slice patterns since indexing is linted
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
        /// A binding a registrar granted, over a transport since suspended or
        /// lost, which nothing has proved since.
        ///
        /// A monotonic clock does not advance while a machine sleeps, so after
        /// sleep every binding would otherwise look valid. Do not show the line
        /// as ready in this state.
        Unverified = 8,
        /// A binding read back from a snapshot rather than granted in this
        /// process. It has not been proved either.
        Restored = 9,
        /// The account has no registrar and never registers (a trunk that
        /// knows this end by address). `sipral_account_register` refuses it.
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
        /// The account's `Contact` is unreachable for the registrar (loopback
        /// or unspecified); nothing was sent. Fix with `sipral_account_rebind`.
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
    /// Which way a digit arrived. Names for `sipral_media_event_t::source`.
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
        /// A call-progress tone: `tone`, and `at_ms` when its first burst began.
        Tone = 1,
        /// The special information tone (the call failed): `sit_hz_*` and
        /// `sit_ms_*` as measured, `at_ms` when the first began.
        SpecialInformation = 2,
        /// Who answered: `verdict`, `reason`, `at_ms` after answer,
        /// `initial_silence_ms`, `greeting_ms` and `words`.
        AnsweredBy = 3,
        /// A machine's record beep: `frequency_hz`, `length_ms`, and `at_ms`
        /// when it ended, after answer.
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
    /// What a [`SipralEventKind::Recovery`] reports, for
    /// `payload.recovery.state`.
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
    /// The last rung tried before giving up, for `payload.recovery.rung`.
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
        /// How long until the next attempt; meaningful only while retrying.
        pub retry_in_ms: u64,
    }
}

record! {
    /// What every call event carries. Members that do not apply are zero,
    /// and zero always means absent.
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
        /// The creating request's `From` URI, as written, without brackets or
        /// header parameters. Null and zero when unavailable.
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
        /// For [`SipralEventKind::CallEnded`]: the SIP cause in the far end's
        /// `Reason` (RFC 3326). 200 on a CANCEL means answered elsewhere.
        pub cause_sip: u32,
        /// The Q.850 cause from `Reason` (16 normal, 17 busy), or zero.
        pub cause_q850: u32,
        /// The `text` of the first `Reason` value, unquoted. Null and zero
        /// when there was none.
        pub cause_text: *const u8,
        /// How many bytes of it.
        pub cause_text_len: usize,
        /// Whether an incoming INVITE came from a `trusted_peers` peer. If not,
        /// the asserted identity and `verstat` are empty (RFC 3325 §8).
        pub identity_trusted: u32,
        /// The first `P-Asserted-Identity`, else a `Remote-Party-ID`, as
        /// written. Null and zero when none.
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
        /// The top-most `Diversion` (RFC 5806), as written. Null and zero
        /// when none.
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
        /// Whether the call asked to be auto-answered after `answer_after_ms`
        /// (`Answer-Mode: Auto`, `answer-after`, `info=alert-autoanswer`).
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
        /// A [`SipralVerificationOutcome`]: this stack's own verdict (RFC 8224
        /// §6.2), unlike the network's `verstat`. Zero when not verified.
        pub verification: Number<SipralVerificationOutcome>,
        /// A [`SipralAttestation`]: the
        /// level a valid SHAKEN PASSporT claimed.
        pub attestation: Number<SipralAttestation>,
        /// A [`SipralVerificationFailure`]: why the verdict did not hold.
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
        /// Zero while the referral waits. On the lapse event, the status the
        /// stack answered (408), and every other member is zero or null.
        pub status_code: u32,
        /// Whether `Refer-To` named a dialog to replace (RFC 3891): an
        /// attended transfer.
        pub attended: u32,
        /// Who to call, as UTF-8. Not NUL-terminated.
        pub target: *const c_char,
        /// How many bytes of it.
        pub target_len: usize,
        /// Its `Referred-By` (RFC 3892), UTF-8, unverified. Null when absent or
        /// repeated (§2.1). Not NUL-terminated.
        pub referred_by: *const c_char,
        /// How many bytes of it.
        pub referred_by_len: usize,
    }
}

record! {
    /// What a media event carries. Members that do not apply are zero or null.
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
        /// How long the key was held. Zero for no duration or `Duration=0`.
        pub held_ms: u64,
        /// A [`SipralSrtpSuite`], for [`SipralEventKind::MediaSecured`] and the
        /// encryption report.
        pub suite: Number<SipralSrtpSuite>,
        /// A [`SipralDigitSource`]: which of the two ways this stack accepts a
        /// digit reported this one, for [`SipralEventKind::DigitReceived`].
        pub source: Number<SipralDigitSource>,
        /// Whether the RFC 6035 PUBLISH left this end, for
        /// [`SipralEventKind::QualityReportSent`].
        pub quality_report_sent: u32,
        /// A [`SipralKeyExchange`], on the start, change and secure kinds.
        pub key_exchange: Number<SipralKeyExchange>,
        /// Whether the stream is encrypted now; zero until a DTLS-SRTP
        /// handshake ends.
        pub encrypted: u32,
        /// Whether DTLS-SRTP checked the far end's certificate against the
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
        /// When, in milliseconds: the tone's first burst, or after answer.
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
    /// What a [`SipralEventKind::Recovery`] carries.
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
        /// Which announcement, minted by `sipral_account_announce`. Stale once
        /// either of these two events has been raised about it.
        pub announcement: SipralHandle,
        /// How long the call was waited for, in milliseconds. Meaningful only
        /// on [`SipralEventKind::AnnouncedCallMissing`].
        pub waited_ms: u64,
    }
}

record! {
    /// What a [`SipralEventKind::SubscriptionChanged`] and a
    /// [`SipralEventKind::Notified`] carry.
    #[derive(Clone, Copy)]
    pub struct SipralSubscriptionEvent {
        /// Which subscription, minted by `sipral_account_subscribe` or by this
        /// ABI for a fork sibling.
        pub subscription: SipralHandle,
        /// A [`SipralSubscriptionState`].
        pub state: Number<SipralSubscriptionState>,
        /// A [`SipralSubscriptionEnd`]:
        /// why it is not live. Zero while it is.
        pub reason: Number<SipralSubscriptionEnd>,
        /// The SIP status a response gave for it, when one did. Zero
        /// otherwise.
        pub status_code: u32,
        /// Whether the notification carried readable dialog state. Zero on
        /// every kind but [`SipralEventKind::Notified`].
        pub has_dialog_info: u32,
        /// What the notifier granted, in milliseconds. Zero until one has.
        pub expires_ms: u64,
        /// How long until this stack refreshes it, in milliseconds.
        pub refresh_in_ms: u64,
        /// How long until the next attempt, in milliseconds, when the state
        /// is `SIPRAL_SUBSCRIPTION_STATE_RETRYING`. Zero otherwise.
        pub retry_in_ms: u64,
        /// The subscription this one forked from (RFC 6665 §4.1.4), or
        /// `SIPRAL_HANDLE_NONE`. A sibling is a full subscription (RFC 4235
        /// §3.9: one per device).
        pub forked_from: SipralHandle,
    }
}

record! {
    /// What a [`SipralEventKind::TransportWanted`] carries: a request RFC
    /// 3261 §18.1.1 kept off a datagram, with no stream open for it.
    #[derive(Clone, Copy)]
    pub struct SipralTransportWantedEvent {
        /// What to open, as a [`SipralTransport`]; zero for an unknown one.
        pub protocol: Number<SipralTransport>,
        /// Where to, as `host:port`. Not NUL-terminated.
        pub destination: *const c_char,
        /// How many bytes of it.
        pub destination_len: usize,
        /// The request's size in bytes, as it would go on the wire.
        pub request_bytes: usize,
        /// The largest size that fits a datagram: path MTU less the §18.1.1
        /// headroom, or 1300 when the MTU is unknown.
        pub limit_bytes: u32,
    }
}

record! {
    /// What a [`SipralEventKind::ResolveNeeded`] carries: the name a dialog's
    /// next hop is written as, and the handle an answer takes.
    #[derive(Clone, Copy)]
    pub struct SipralResolveEvent {
        /// The handle
        /// [`sipral_stack_resolved`](crate::resolve::sipral_stack_resolved)
        /// takes; stale once the dialog ends.
        pub dialog: SipralHandle,
        /// The host as the URI spells it; IPv6 literals keep brackets (RFC
        /// 3261 §19.1.1). Not NUL-terminated.
        pub host: *const c_char,
        /// How many bytes of it.
        pub host_len: usize,
        /// The URI's port, or zero for none. Zero is not 5060: an SRV answer
        /// carries its own port (RFC 3263 §4.2).
        pub port: u32,
        /// The transport named, as a [`SipralTransport`], or zero, leaving
        /// §4.1's NAPTR step to the caller.
        pub protocol: Number<SipralTransport>,
    }
}

record! {
    /// What the three message kinds carry; inapplicable members are zero.
    /// `content_type` and `body` point into `sipral_event_t::message`.
    #[derive(Clone, Copy)]
    pub struct SipralMessageEvent {
        /// [`SipralEventKind::MessageSent`]: which send; stale after this.
        pub message: SipralHandle,
        /// [`SipralEventKind::MessagesWaiting`]: which subscription reported
        /// it. [`SIPRAL_HANDLE_NONE`] on the other kinds.
        pub subscription: SipralHandle,
        /// [`SipralEventKind::MessageSent`]: the final status. Zero on the
        /// other two kinds.
        pub status_code: u32,
        /// [`SipralEventKind::MessageReceived`]: the body's `Content-Type`, as
        /// written. Null on the other kinds and for an empty MESSAGE.
        pub content_type: *const c_char,
        /// How many bytes of it.
        pub content_type_len: usize,
        /// [`SipralEventKind::MessageReceived`]: the body. Null the same as
        /// `content_type`.
        pub body: *const u8,
        /// How many bytes of it.
        pub body_len: usize,
        /// [`SipralEventKind::MessagesWaiting`]: RFC 3842 §3.5's status
        /// line, 1 for `yes` and 0 for `no`.
        pub waiting: u32,
        /// [`SipralEventKind::MessagesWaiting`]: new `voice-message` messages
        /// (RFC 3458 §6.2). Zero when the body had no such line.
        pub new_messages: u32,
        /// The same, old.
        pub old_messages: u32,
        /// New messages flagged urgent.
        pub urgent_new_messages: u32,
        /// Old messages flagged urgent.
        pub urgent_old_messages: u32,
        /// [`SipralEventKind::MessagesWaiting`]: `Message-Account`, when sent
        /// (RFC 3842 §3.5). Null otherwise.
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
        /// The certificate URL: to fetch, or that was verified. UTF-8, not
        /// NUL-terminated; null and zero when none.
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
        /// The challenge came from beyond the account's own server.
        NotTheAccountsServer = 1,
        /// The account's server asked for a realm not the account's (e.g. a
        /// proxy relaying a far end's challenge).
        NotTheAccountsRealm = 2,
    }
}

codes! {
    /// What the server said was wrong with the token (RFC 6750 §3.1).
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
    /// What a [`SipralEventKind::TokenRequired`] carries (RFC 8898 §4).
    /// Texts are UTF-8, not NUL-terminated, empty when absent.
    #[derive(Clone, Copy)]
    pub struct SipralTokenEvent {
        /// A [`SipralTokenError`].
        pub error: Number<SipralTokenError>,
        /// A `SipralToggle`: on for a proxy's 407, off for a 401.
        pub proxy: Number<SipralToggle>,
        /// Where the challenged request went, as `host:port`.
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
        /// The authorization server: an `https` URI, or empty if it was not one.
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
    /// the account's password, and why it was not given.
    #[derive(Clone, Copy)]
    pub struct SipralChallengeEvent {
        /// A [`SipralChallengeRefusal`].
        pub refusal: Number<SipralChallengeRefusal>,
        /// Where the challenged request went, as `host:port`. Not
        /// NUL-terminated.
        pub server: *const c_char,
        /// How many bytes of it.
        pub server_len: usize,
        /// The challenged realms, separated by line feeds (a realm may hold a
        /// comma, never a line break). UTF-8, not NUL-terminated.
        pub realms: *const c_char,
        /// How many bytes of it.
        pub realms_len: usize,
    }
}

record! {
    /// The arm of an event that its kind names. The rest of the union is
    /// zeroed, so members appended later read as zero.
    #[derive(Clone, Copy)]
    pub union SipralEventPayload {
        /// For [`SipralEventKind::RegistrationChanged`].
        pub registration: SipralRegistrationEvent,
        /// For every call kind.
        pub call: SipralCallEvent,
        /// For the three transfer kinds.
        pub transfer: SipralTransferEvent,
        /// For every media kind.
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
        /// For the three message kinds.
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
        /// For [`SipralEventKind::NetworkTest`].
        pub network_test: SipralNetworkTestEvent,
    }
}

record! {
    /// Something the library has to tell the application.
    ///
    /// Library-owned, valid for the callback only. Read no further than
    /// `size`; the union stays last so growth only extends the tail.
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
        /// The SIP message behind it, whole and unparsed, or null.
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
    /// Called inside `sipral_stack_poll` on its thread, never concurrently
    /// for one stack. Must not unwind. May call back into the library
    /// (`docs/08-ffi.md`, "The shape").
    pub type SipralEventCallback = fn(event: *const SipralEvent, user_data: *mut c_void);
}

/// A [`SipralEventPayload`] with the named arm written and every other byte
/// zero, since the Kotlin/JNI shim reads every arm.
macro_rules! payload {
    ($arm:ident: $value:expr) => {{
        // Safety: every arm member is an integer or a pointer with a length,
        // and all-zero is a valid value for each.
        let mut zeroed: SipralEventPayload = unsafe { std::mem::zeroed() };
        zeroed.$arm = $value;
        zeroed
    }};
}

impl SipralEvent {
    /// An event with nothing in it but its kind, for a kind to fill in.
    // the union is built at the call site and moved in once
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

/// What a STUN server said about one socket, as C reads it. `payload`
/// points into text the caller keeps beside the event.
#[cfg(feature = "stun")]
pub(crate) fn nat_mapping(stack: SipralHandle, payload: SipralNatEvent) -> SipralEvent {
    SipralEvent::of(stack, SipralEventKind::NatMapping, payload!(nat: payload))
}

/// What happened to a stack's STUN servers, as C reads it. `payload`
/// points into text the caller keeps beside the event.
#[cfg(feature = "stun")]
pub(crate) fn stun_server(stack: SipralHandle, payload: SipralStunServerEvent) -> SipralEvent {
    SipralEvent::of(
        stack,
        SipralEventKind::StunServer,
        payload!(stun_server: payload),
    )
}

/// A transport lost, as C reads it. `payload` points into text the caller
/// keeps beside the event.
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

/// A network test finished, as C reads it. `payload` points into text the
/// caller keeps beside the event.
pub(crate) fn network_tested(stack: SipralHandle, payload: SipralNetworkTestEvent) -> SipralEvent {
    SipralEvent::of(
        stack,
        SipralEventKind::NetworkTest,
        payload!(network_test: payload),
    )
}

/// A TURN relay result for one media socket, as C reads it. `payload`
/// points into text the caller keeps beside the event.
#[cfg(all(feature = "stun", feature = "ice"))]
pub(crate) fn nat_relay(stack: SipralHandle, payload: SipralNatRelayEvent) -> SipralEvent {
    SipralEvent::of(stack, SipralEventKind::NatRelay, payload!(relay: payload))
}

/// What a media socket's TURN connection is to do, as C reads it.
/// `payload` points into text the caller keeps beside the event.
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
    /// Who is on every call this stack still knows, fixed at creation.
    pub(crate) identities: &'a HashMap<CallHandle, Arc<CallIdentity>>,
    /// The identity `call_payload` last attached, kept alive by whoever
    /// queues the event for the duration of delivery.
    pub(crate) raised_identity: Option<Arc<CallIdentity>>,
}

/// Say a user agent event the way C says it, or `None` (counted by the
/// poll). The result borrows from `event` and `transport`, the text from
/// [`text_to_point_at`]; both must outlive the callback.
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

/// A challenge an account's password did not answer. `text` is from
/// [`text_to_point_at`]: the address, a line feed, then one realm per line.
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

/// An account's server asking for an OAuth 2.0 access token. `text` is the
/// address from [`text_to_point_at`]; the rest borrows from the event.
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

/// An account's server being located (RFC 3263). `targets` is from
/// [`text_to_point_at`].
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

/// The handle for a subscription of the layer below, minting one for a fork
/// sibling nobody asked for.
fn subscription_named(
    known: &mut Vocabulary<'_>,
    subscription: sipral_ua::SubscriptionHandle,
) -> SipralHandle {
    known
        .subscriptions
        .name_of(subscription)
        .unwrap_or(SIPRAL_HANDLE_NONE)
}

/// A subscription's current state, asked of the layer below: the event is
/// raised from the same drain that changed it.
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
            // the event is about the new sibling; its origin is unchanged
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
            // stated, not asked: an ended subscription is already released
            // below
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
            // both point into `request`, which the event keeps alive
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

/// A request RFC 3261 §18.1.1 kept off a datagram, with no stream open for
/// it. `destination` is the text [`text_to_point_at`] built for the event.
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

/// A dialog whose next hop is a name to resolve. `host` is from
/// [`text_to_point_at`].
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
            // looked up, not inserted: every target refresh asks again and
            // must get the same handle
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

/// Text an event has no bytes of its own for, formatted once so the event
/// can point at it. `None` for kinds that need none.
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
            // the whole 2xx, so Service-Route, GRUUs and P-Associated-URI
            // can be read from it
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
            ref request,
            ref causes,
        } => {
            let mut payload = call_payload(known, call);
            // already released below, so the state is stated, not asked
            payload.state = SipralCallState::Terminated as u32;
            payload.end_reason = end_reason(reason) as u32;
            payload.status_code = status_of(status);
            said_why(&mut payload, causes);
            let mut out = call_event(known, SipralEventKind::CallEnded, call, payload);
            // the refusal, or the far end's BYE/CANCEL; never both, since a
            // refused call had no dialog for a BYE
            attach(&mut out, response.as_ref().or(request.as_ref()));
            Some(out)
        }
        _ => None,
    }
}

/// The call end's `Reason` causes onto its event; text borrows `causes`.
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
            // minted here like an incoming call's handle; the two answering
            // calls take it
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
        // no word for it here; counted by the poll. `UaEvent` is
        // `#[non_exhaustive]`, so the number space is the guarantee.
        _ => None,
    }
}

/// The two ways `crates/sipral-ffi/src/lifecycle.rs`'s ladder settles.
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
        // other `Lifecycle` variants are mid-ladder steps, which this ABI
        // does not report; only where the ladder ends
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
        // `Rung` is `#[non_exhaustive]`; `GiveUp` is never reported as the
        // rung given up on
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

/// The C name of the transform a call is running; `Unknown` is kept for
/// events not about one.
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

/// Real-time text typed on `call`, `missing` blocks lost. `text` borrows
/// from the caller for one delivery.
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

/// Say a media event the way C says it, or `None` (counted). `reason` and
/// `statistics` are the caller's, built for one delivery; `encryption` is
/// the stream's report for the start, change and secure kinds.
pub(crate) fn media(
    known: &mut Vocabulary<'_>,
    call: CallHandle,
    event: &MediaEvent,
    reason: Option<&str>,
    statistics: Option<&SipralStreamStats>,
    encryption: Option<&sipral::StreamEncryption>,
) -> Option<SipralEvent> {
    // text has its own arm; `reason` is the text (see `media_reason`)
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
            // the handshake's address is not carried:
            // `sipral_media_poll_transmit` already returns it with each record
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
            // a missing duration and `Duration=0` both read as zero here
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

/// Whether a media event carries the encryption report.
const fn reports_encryption(event: &MediaEvent) -> bool {
    match event {
        MediaEvent::Started { .. } | MediaEvent::Changed { .. } => true,
        #[cfg(feature = "dtls")]
        MediaEvent::Secured { .. } => true,
        _ => false,
    }
}

/// The text a media event carries, owned so it outlives the event borrow.
pub(crate) fn media_reason(event: &MediaEvent) -> Option<String> {
    match *event {
        MediaEvent::Failed(ref error) => Some(error.to_string()),
        MediaEvent::RecordingStopped { ref reason, .. } => Some(reason.to_string()),
        // not a sentence, but it must outlive the event borrow too
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
    // read from this stack's own record: after a call ends the layer below
    // has already released it
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
        // kept on the vocabulary so the queued delivery can keep these bytes
        // alive; the map entry may be gone by then
        known.raised_identity = Some(identity);
    }
    payload
}

/// The INVITE's caller identity and answer hints, onto a call event. Pointers
/// borrow from `identity`, kept alive with the queued event.
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

// moved in whole, like `SipralEvent::of`'s union
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

/// Point the event at its source message, still owned by the callback's
/// caller.
fn attach(event: &mut SipralEvent, message: Option<&sipral_core::msg::OwnedMessage>) {
    if let Some(message) = message {
        let raw = message.as_raw().as_bytes();
        event.message = raw.as_ptr();
        event.message_len = raw.len();
    }
}

/// Milliseconds, saturating rather than wrapping.
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
        // nothing to ask about, or a state this ABI has no number for
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
        // a report this ABI has no word for yet
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
        // `message`'s tail lies past the small `announce` arm: only
        // `payload!`'s zeroing reaches it
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

    /// Written out rather than walked: a derived test would agree with a
    /// declaration that had moved them (`docs/08-ffi.md`).
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
        assert_eq!(SipralEventKind::NetworkTest as u32, 60);
        assert_eq!(SipralEventKind::ALL.len(), 58, "and there are no others");
    }

    /// Reserved numbers were taken in place, not by appending.
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

    /// A reserved number answers exactly like one never spent.
    #[test]
    fn a_number_held_for_a_feature_this_build_lacks_names_nothing() {
        // 16 and 44 are reserved (audio devices); 34 to 37 are live now
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
        assert_eq!(name(60).as_deref(), Some("network test"), "60 is live");
        assert_eq!(name(61), None, "past the last kind");
        assert_eq!(name(0), None, "no kind is zero");
        assert_eq!(name(u32::MAX), None);
    }

    #[test]
    fn a_duration_too_long_to_count_saturates_rather_than_wrapping() {
        assert_eq!(millis(Duration::from_secs(1)), 1_000);
        assert_eq!(millis(Duration::ZERO), 0);
        assert_eq!(millis(Duration::MAX), u64::MAX);
    }

    /// Every suite has its own number, none falls back to `Unknown`, and no
    /// two share one.
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
