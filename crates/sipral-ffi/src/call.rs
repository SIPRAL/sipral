// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Calls: placed, answered, held, handed on, hung up.
//!
//! Every call here is named by a handle of this stack's, and every one of them
//! takes the time from the caller, for the same reason poll does: nothing in
//! this library reads a clock, so a retransmission schedule that started at an
//! instant the caller did not name would be one the caller cannot reason
//! about.
//!
//! A call is placed with a session description and answered with one. Offering
//! nothing and letting the far end offer in its 2xx is legal (§13.2.1) and is
//! deliberately not reachable from here: the answer would then have to travel
//! in the ACK, written by an application that has no media layer on this side
//! of the boundary to write it with.
//!
//! DTMF goes out three ways and the caller picks one per send, because which
//! of them a peer accepts is a fact about the peer: RFC 4733's telephone event
//! in the media, which is the one to reach for, and an INFO carrying either
//! `application/dtmf-relay` or `application/dtmf` for the switches that take
//! only signalling. A stack built with no media path can still send the last
//! two.

use std::ffi::c_char;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sipral::CallMedia;
use sipral_core::endpoint::OutgoingInDialogRequest;
use sipral_core::msg::{HeaderName, Method, StatusCode, Uri};
use sipral_ua::{ForkPolicy, HeadersFor, OutgoingCall, UaError};

use crate::abi::{codes, record};
use crate::error::{Fail, entry, fail};
use crate::event::{SipralCallState, call_state};
use crate::handle::SipralHandle;
use crate::header::{SipralHeader, supplied};
use crate::media::{address, media_failed};
use crate::stack::{StackState, handle_failed, with_stack, with_stack_at};
use crate::status::SipralStatus;
use crate::text::{bytes, required_text, text};
use crate::versioned::{Versioned, read_versioned};

/// What one DTMF tone lasts when the caller does not say (RFC 4733 §2.5.2.2
/// has no figure; every switch that generates one uses about this).
const DEFAULT_DTMF_MS: u32 = 160;

/// Longer than any key is held, and short enough that a caller who passed
/// milliseconds where it meant seconds finds out.
const MAX_DTMF_MS: u32 = 10_000;

/// The sixteen events a keypad has (RFC 4733 §3.2, Table 3).
const KEYPAD: &[u8] = b"0123456789*#ABCD";

record! {
    /// What a call is placed with.
    ///
    /// Set `size` to `sizeof(sipral_call_config_t)` and zero the rest before
    /// filling anything in.
    #[derive(Clone, Copy)]
    pub struct SipralCallConfig {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// Who to call, as a URI. UTF-8, not NUL-terminated.
        pub target: *const c_char,
        /// How many bytes of it.
        pub target_len: usize,
        /// The session description to offer, for a call this stack manages no
        /// audio for.
        ///
        /// Exactly one of this and `media_address` is set. Two descriptions of one
        /// session is one too many, and neither is a call whose answer would have
        /// to be written into the ACK.
        pub sdp: *const u8,
        /// How many bytes of it.
        pub sdp_len: usize,
        /// Where to send the INVITE, as `host:port`, or null to send it where the
        /// account registers — which is the outbound proxy for a registered line,
        /// and the reason a phone behind a NAT works at all.
        pub destination: *const c_char,
        /// How many bytes of it.
        pub destination_len: usize,
        /// Whether to keep every branch a proxy forks the INVITE into. Zero keeps
        /// the first that answers and hangs up the rest, which is what a telephone
        /// does.
        pub keep_all_forks: u32,
        /// Where this end will receive media, as `host:port`, for a call this
        /// stack describes and runs the audio of.
        ///
        /// The application owns the socket, so it is the only one that can say. Set
        /// it and the offer is written from this stack's codec order, the answer is
        /// read, and the call gets a media session that `crate::media` and
        /// `crate::record` reach. Leave it null and set `sdp` instead for a call
        /// where the application describes its own session and runs its own RTP.
        pub media_address: *const c_char,
        /// How many bytes of it.
        pub media_address_len: usize,
        /// Header fields to put on the INVITE, in the order given, or null for
        /// none.
        ///
        /// Each is checked before anything is built: the name a token, the value
        /// one line of text, and not a field the stack writes on a call itself.
        /// Those are listed in `docs/04-ua.md` with the reason for each, and
        /// `User-Agent` joins them when `sipral_stack_config_t::user_agent` is
        /// set. A refusal is `SIPRAL_STATUS_INVALID_ARGUMENT` naming the element,
        /// and no call.
        pub headers: *const SipralHeader,
        /// How many elements `headers` has.
        pub headers_len: usize,
        /// What this call does about SRTP, overriding
        /// `sipral_stack_config_t::srtp` for it: a `SipralSrtp`, or zero to
        /// take the stack's own setting. Any other value is
        /// `SIPRAL_STATUS_INVALID_ARGUMENT`, and nothing is built.
        ///
        /// Read only for a call this stack describes the media of —
        /// `media_address` set — and otherwise not this ABI's to act on: a
        /// call placed with `sdp` is a session the application wrote, and
        /// SRTP in it is the application's own line to write or not.
        pub srtp: u32,
    }
}

// Safety: the trait's contract. Plain data with no invariant between the
// members, and all-zero is valid: every pointer is null beside a length of
// zero.
unsafe impl Versioned for SipralCallConfig {
    const NAME: &'static str = "sipral_call_config";
    const MIN_SIZE: usize = crate::versioned::min_size::CALL_CONFIG;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// Why the layer below would not do it.
pub(crate) fn ua_failed(error: &UaError) -> Fail {
    let status = match *error {
        // the handle was live here, so the layer below disagreeing means what
        // it named has just gone
        UaError::NoSuchAccount | UaError::NoSuchCall => SipralStatus::StaleHandle,
        UaError::WrongState(_)
        | UaError::NoSession
        | UaError::ChangeInProgress
        | UaError::CannotRenegotiate => SipralStatus::WrongState,
        // an account configured without a registrar is the wrong account to
        // register rather than the wrong moment: a corrected configuration
        // would be taken, and no amount of waiting will change this one
        UaError::Sdp(_) | UaError::NoRegistrar | UaError::Header(_) => {
            SipralStatus::InvalidArgument
        }
        _ => SipralStatus::NotSent,
    };
    fail(status, error.to_string())
}

/// The same, for the endpoint underneath when this ABI drives it directly.
fn send_failed(error: &impl core::fmt::Display) -> Fail {
    fail(SipralStatus::NotSent, error.to_string())
}

fn status_code(code: u32) -> Result<StatusCode, Fail> {
    let refuse = || {
        fail(
            SipralStatus::InvalidArgument,
            format!("{code} is not a SIP status code"),
        )
    };
    let narrowed = u16::try_from(code).map_err(|_| refuse())?;
    StatusCode::new(narrowed).map_err(|_| refuse())
}

fn call_uri(supplied: &str) -> Result<Uri, Fail> {
    Uri::parse_str(supplied).map_err(|error| {
        fail(
            SipralStatus::InvalidArgument,
            format!("target is {supplied:?}, which is not a URI: {error}"),
        )
    })
}

/// The session description a call is placed or answered with.
///
/// # Safety
///
/// `sdp` must be readable for `len` bytes.
unsafe fn description(sdp: *const u8, len: usize) -> Result<Option<Arc<[u8]>>, Fail> {
    Ok(unsafe { bytes(sdp, len, "sdp") }?.map(Arc::from))
}

/// Where this end will receive media, when the call is one this stack
/// describes.
///
/// # Safety
///
/// The two members it reads must be a pointer readable for the length beside
/// it.
unsafe fn managed_media(config: &SipralCallConfig) -> Result<Option<SocketAddr>, Fail> {
    let Some(local) = (unsafe {
        text(
            config.media_address,
            config.media_address_len,
            "media_address",
        )
    })?
    else {
        return Ok(None);
    };
    if config.sdp_len != 0 || !config.sdp.is_null() {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "media_address and sdp are both set, and a call has one description of its session: \
             media_address writes it from this stack's codec order, sdp is one the application \
             wrote",
        ));
    }
    let Ok(address) = local.parse::<SocketAddr>() else {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!("media_address is {local:?}, which is not an address and a port"),
        ));
    };
    Ok(Some(address))
}

/// Turn what crossed the boundary into a call to place.
///
/// `managed` says the description is this stack's to write, so the one in the
/// config is neither wanted nor required.
///
/// # Safety
///
/// Every pointer in `config` must be readable for the length beside it.
unsafe fn outgoing_from(
    state: &StackState,
    config: &SipralCallConfig,
    managed: bool,
) -> Result<OutgoingCall, Fail> {
    let target = unsafe { required_text(config.target, config.target_len, "target") }?;
    let mut outgoing = OutgoingCall::new(call_uri(target)?);
    if !managed {
        let Some(offer) = (unsafe { description(config.sdp, config.sdp_len) })? else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "a call placed from here carries an offer, because the answer to one that does \
                 not has to be written into the ACK. Set sdp for a session the application \
                 describes, or media_address for one this stack describes",
            ));
        };
        outgoing = outgoing.offer(offer);
    }
    if let Some(elsewhere) =
        unsafe { text(config.destination, config.destination_len, "destination") }?
    {
        let Ok(address) = elsewhere.parse::<SocketAddr>() else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("destination is {elsewhere:?}, which is not an address and a port"),
            ));
        };
        outgoing = outgoing.to_address(state.transport, address);
    }
    if config.keep_all_forks != 0 {
        outgoing = outgoing.forks(ForkPolicy::KeepAll);
    }
    if let Some(ref named) = state.user_agent {
        outgoing = outgoing.header(HeaderName::UserAgent, named);
    }
    let asked = unsafe {
        supplied(
            config.headers,
            config.headers_len,
            HeadersFor::Call,
            state.user_agent.is_some(),
        )
    }?;
    for (name, value) in asked {
        outgoing = outgoing.header(name, value);
    }
    Ok(outgoing)
}

entry! {
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
    /// # Safety
    ///
    /// `config` must point at a `sipral_call_config_t` whose `size` member
    /// says how long it is, with every pointer in it readable for the length
    /// beside it, and `out_call` at one `sipral_handle_t`.
    fn sipral_call_place(
        stack: SipralHandle,
        account: SipralHandle,
        config: *const SipralCallConfig,
        out_call: *mut SipralHandle,
        now_ms: u64,
    ) {
        if out_call.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_call is null"));
        }
        let config = unsafe { read_versioned(config) }?;
        let media = unsafe { managed_media(&config) }?;
        // checked here, before the account is even looked up, so a bad value
        // never reaches the point of building anything
        let srtp = crate::media::srtp_policy(config.srtp, "srtp")?;
        let handle = with_stack_at(stack, now_ms, |state, now| {
            let id = state.accounts.get(account).map_err(handle_failed)?;
            let outgoing = unsafe { outgoing_from(state, &config, media.is_some()) }?;
            let placed = match media {
                Some(local) => {
                    let placed = match srtp {
                        // the stack's own catalogue, untouched: this is what
                        // `srtp` being unspecified on the call has to mean
                        None => {
                            state.engine.place(&mut state.agent, id, outgoing, local, now)
                        }
                        Some(policy) => {
                            let catalog = state.engine.catalog().clone().with_srtp(policy);
                            let media = CallMedia::new(catalog, state.media_config());
                            state.engine.place_with(
                                &mut state.agent,
                                id,
                                outgoing,
                                local,
                                media,
                                now,
                            )
                        }
                    }
                    .map_err(|error| media_failed(&error))?;
                    state.manage(placed);
                    placed
                }
                None => state
                    .agent
                    .call(id, &outgoing, now)
                    .map_err(|error| ua_failed(&error))?,
            };
            if let Some(identity) = state.agent.call_identity(placed) {
                state.record_identity(placed, identity);
            }
            state
                .calls
                .name_of(placed)
                .map_err(|status| fail(status, "no room for another call on this stack"))
        })?;
        unsafe { out_call.write(handle) };
        Ok(())
    }
}

entry! {
    /// Say a call that came in is ringing.
    ///
    /// A description makes it a 183 Session Progress rather than a 180
    /// Ringing, because 180 with a body is a contradiction the far end has to
    /// guess at. Pass none for the ordinary case.
    ///
    /// # Safety
    ///
    /// `sdp` must be null or readable for `sdp_len` bytes.
    fn sipral_call_ring(
        stack: SipralHandle,
        call: SipralHandle,
        sdp: *const u8,
        sdp_len: usize,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let early = unsafe { description(sdp, sdp_len) }?;
            state
                .agent
                .ring(id, early, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Answer a call that came in.
    ///
    /// `sdp` is the answer to the offer the INVITE carried, and is required:
    /// answering with nothing puts the offer on this end and the answer in the
    /// far end's ACK, which this ABI has no way to hand back.
    ///
    /// # Safety
    ///
    /// `sdp` must be readable for `sdp_len` bytes.
    fn sipral_call_answer(
        stack: SipralHandle,
        call: SipralHandle,
        sdp: *const u8,
        sdp_len: usize,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let Some(answer) = (unsafe { description(sdp, sdp_len) })? else {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    "answering a call needs a session description",
                ));
            };
            state
                .agent
                .answer(id, Some(answer), now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
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
    /// # Safety
    ///
    /// `media_address` must be readable for `media_address_len` bytes.
    fn sipral_call_answer_media(
        stack: SipralHandle,
        call: SipralHandle,
        media_address: *const c_char,
        media_address_len: usize,
        now_ms: u64,
    ) {
        let local = unsafe { address(media_address, media_address_len, "media_address") }?;
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            state
                .engine
                .answer(&mut state.agent, id, local, now)
                .map_err(|error| media_failed(&error))?;
            state.manage(id);
            Ok(())
        })
    }
}

entry! {
    /// Refuse a call that came in, with a response code of your choosing.
    ///
    /// 486 Busy Here for a line that is in use, 603 Decline for a person who
    /// does not want to talk. The difference is what a proxy does next.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_reject(
        stack: SipralHandle,
        call: SipralHandle,
        code: u32,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let status = status_code(code)?;
            state
                .agent
                .reject(id, status, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Hang up, whatever the call is doing.
    ///
    /// A CANCEL before it is answered, a BYE after, a refusal for one that
    /// came in and has not been answered. A call that is already ending is
    /// left alone rather than refused.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_hangup(stack: SipralHandle, call: SipralHandle, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            state
                .agent
                .hangup(id, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
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
    /// # Safety
    ///
    /// `headers` must be null with `headers_len` zero, or readable for
    /// `headers_len` elements, each with a name and a value readable for the
    /// lengths beside them.
    fn sipral_call_set_headers(
        stack: SipralHandle,
        call: SipralHandle,
        headers: *const SipralHeader,
        headers_len: usize,
    ) {
        with_stack(stack, |state| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            // the stack writes no User-Agent on any of these
            let asked = unsafe { supplied(headers, headers_len, HeadersFor::Call, false) }?;
            state
                .agent
                .respond_with_headers(id, &asked)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Put a call on hold (RFC 3264 §8.4).
    ///
    /// The description is the stack's to write: the one already negotiated
    /// with every stream's direction changed. Asking for a hold that is
    /// already in place sends nothing and succeeds.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_hold(stack: SipralHandle, call: SipralHandle, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            state.agent.hold(id, now).map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Take it off hold again.
    ///
    /// Every stream goes back to the direction it had before, which is not
    /// always both ways: one that was offered receive-only is resumed
    /// receive-only.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_resume(stack: SipralHandle, call: SipralHandle, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            state
                .agent
                .resume(id, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Accept a change the far end offered, reported as
    /// `SIPRAL_EVENT_KIND_SESSION_OFFERED`.
    ///
    /// `sdp` is the answer to the offer it carried, and is left out only for a
    /// request that carried none. A re-INVITE nobody answers is retransmitted
    /// and then ends the call, so this or [`sipral_call_reject_session`] has
    /// to follow that event.
    ///
    /// Only for a call the application describes. One this stack describes
    /// answers its own re-offers, from the same codec order, before the poll
    /// that saw the request returns — so the event never arrives and this is
    /// `SIPRAL_STATUS_WRONG_STATE`.
    ///
    /// # Safety
    ///
    /// `sdp` must be null or readable for `sdp_len` bytes.
    fn sipral_call_accept_session(
        stack: SipralHandle,
        call: SipralHandle,
        sdp: *const u8,
        sdp_len: usize,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            describes_its_own(state, id)?;
            let answer = unsafe { bytes(sdp, sdp_len, "sdp") }?;
            state
                .agent
                .accept_reoffer(id, answer, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Refuse one instead. The session stands exactly as it was (§14.1).
    ///
    /// 488 Not Acceptable Here is the code that says the description was the
    /// problem rather than the request.
    ///
    /// As with [`sipral_call_accept_session`], only for a call the application
    /// describes.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_reject_session(
        stack: SipralHandle,
        call: SipralHandle,
        code: u32,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            describes_its_own(state, id)?;
            let status = status_code(code)?;
            state
                .agent
                .reject_reoffer(id, status, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

codes! {
    /// Which way a digit goes to the far end. Names for
    /// [`sipral_call_send_dtmf`]'s `via`.
    ///
    /// The choice is per send, not per call, because it is a fact about the peer
    /// rather than about this end, and the way to find out which one a peer takes
    /// is to try. A carrier that ignores one of these ignores it silently.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDtmf: u32 {
        /// In the media, as an RFC 4733 named telephone event. What to reach for:
        /// it is the only one carried end to end by every gateway on the path, and
        /// the only one whose timing survives transcoding.
        Rtp = 0,
        /// An INFO per digit carrying `application/dtmf-relay`, which states the
        /// signal and how long it was held.
        InfoRelay = 1,
        /// An INFO per digit carrying `application/dtmf`, whose whole body is the
        /// character. Some switches take only this one.
        InfoPlain = 2,
    }
}

entry! {
    /// Send DTMF on a call that is up, in whichever of the three forms the far
    /// end takes.
    ///
    /// `digits` are `0` to `9`, `*`, `#` and `A` to `D`, the sixteen events of
    /// RFC 4733 §3.2, in the order they were pressed. `duration_ms` is how long
    /// each one lasts, or zero for the default.
    ///
    /// `via` is a [`SipralDtmf`], and it is chosen per send rather than per
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
    /// # Safety
    ///
    /// `digits` must be readable for `digits_len` bytes.
    fn sipral_call_send_dtmf(
        stack: SipralHandle,
        call: SipralHandle,
        digits: *const c_char,
        digits_len: usize,
        via: u32,
        duration_ms: u32,
        now_ms: u64,
    ) {
        let form = dtmf_form(via)?;
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let pressed = unsafe { required_text(digits, digits_len, "digits") }?;
            let keys = keypad(pressed)?;
            let held = tone_length(duration_ms)?;
            if form == SipralDtmf::Rtp {
                let length = Duration::from_millis(u64::from(held));
                return crate::media::dial_in_media(state, id, pressed, length);
            }
            let Some(dialog) = state.agent.call_dialog(id) else {
                return Err(fail(
                    SipralStatus::WrongState,
                    "the call has no dialog to send an INFO in, so it is not up yet",
                ));
            };
            let kind: &[u8] = match form {
                SipralDtmf::InfoPlain => b"application/dtmf",
                _ => b"application/dtmf-relay",
            };
            for key in keys {
                let body = match form {
                    SipralDtmf::InfoPlain => Arc::from(vec![key]),
                    _ => dtmf_body(key, held),
                };
                let request = OutgoingInDialogRequest::new(Method::Info).body(kind, body);
                state
                    .agent
                    .endpoint()
                    .request_in_dialog(dialog, &request, now)
                    .map_err(|error| send_failed(&error))?;
            }
            Ok(())
        })
    }
}

/// The form a number names, or a refusal saying what the three are.
fn dtmf_form(via: u32) -> Result<SipralDtmf, Fail> {
    match via {
        0 => Ok(SipralDtmf::Rtp),
        1 => Ok(SipralDtmf::InfoRelay),
        2 => Ok(SipralDtmf::InfoPlain),
        _ => Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "{via} is not a way to send a digit; they are 0 for the media, 1 for INFO with \
                 application/dtmf-relay and 2 for INFO with application/dtmf"
            ),
        )),
    }
}

/// Refuse a session change on a call whose descriptions are this stack's.
///
/// Not a guess about what the application meant: the engine has already
/// answered the re-offer, so a second answer would be a second one on the wire.
fn describes_its_own(state: &StackState, call: sipral_ua::CallHandle) -> Result<(), Fail> {
    if state.manages(call) {
        return Err(fail(
            SipralStatus::WrongState,
            "this stack writes the descriptions for this call and has already answered the change \
             the far end offered",
        ));
    }
    Ok(())
}

/// The digits, upper-cased, or which one was not a key.
fn keypad(pressed: &str) -> Result<Vec<u8>, Fail> {
    let mut keys = Vec::with_capacity(pressed.len());
    for (index, key) in pressed.bytes().enumerate() {
        let key = key.to_ascii_uppercase();
        if !KEYPAD.contains(&key) {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("digit {index} is not one of the sixteen a keypad has"),
            ));
        }
        keys.push(key);
    }
    if keys.is_empty() {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "there are no digits to send",
        ));
    }
    Ok(keys)
}

fn tone_length(duration_ms: u32) -> Result<u32, Fail> {
    match duration_ms {
        0 => Ok(DEFAULT_DTMF_MS),
        held if held <= MAX_DTMF_MS => Ok(held),
        held => Err(fail(
            SipralStatus::InvalidArgument,
            format!("a tone of {held} ms is longer than any key is held"),
        )),
    }
}

/// One key, in the two lines every switch that takes DTMF over signalling
/// reads: which event it was, and for how long.
fn dtmf_body(key: u8, duration_ms: u32) -> Arc<[u8]> {
    let mut body = Vec::with_capacity(32);
    body.extend_from_slice(b"Signal=");
    body.push(key);
    body.extend_from_slice(b"\r\nDuration=");
    body.extend_from_slice(duration_ms.to_string().as_bytes());
    body.extend_from_slice(b"\r\n");
    Arc::from(body)
}

entry! {
    /// Ask the far end to call somebody else, and hang up when it has
    /// (RFC 3515).
    ///
    /// A blind transfer: nobody consults the destination first. This end stays
    /// in the call until the transfer has succeeded, because hanging up first
    /// turns a transfer that failed into a call that vanished. Progress
    /// arrives as `SIPRAL_EVENT_KIND_TRANSFER_PROGRESS` and then
    /// `SIPRAL_EVENT_KIND_TRANSFER_DONE`.
    ///
    /// # Safety
    ///
    /// `target` must be readable for `target_len` bytes.
    fn sipral_call_transfer(
        stack: SipralHandle,
        call: SipralHandle,
        target: *const c_char,
        target_len: usize,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let target = unsafe { required_text(target, target_len, "target") }?;
            let target = call_uri(target)?;
            state
                .agent
                .transfer(id, &target, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Call the transfer target, so that there is somebody to hand the call
    /// to, and write the new call's handle to `out_consultation`.
    ///
    /// The consultation leg of an attended transfer. It is answered like any
    /// other call, and [`sipral_call_transfer_to`] is what follows. Putting
    /// `call` on hold first is the application's: it is a session change, and
    /// this stack does not make those uninvited.
    ///
    /// `media_address` is `SIPRAL_STATUS_NOT_SUPPORTED` here. The media engine
    /// places and answers calls; it does not consult, and a consultation leg
    /// registered with it by hand would be one it has described nothing for.
    /// A consultation with audio is placed with `sdp` and run by the
    /// application, as every call was before this stack carried media.
    ///
    /// # Safety
    ///
    /// As [`sipral_call_place`].
    fn sipral_call_consult(
        stack: SipralHandle,
        call: SipralHandle,
        config: *const SipralCallConfig,
        out_consultation: *mut SipralHandle,
        now_ms: u64,
    ) {
        if out_consultation.is_null() {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "out_consultation is null",
            ));
        }
        let config = unsafe { read_versioned(config) }?;
        if unsafe { managed_media(&config) }?.is_some() {
            return Err(fail(
                SipralStatus::NotSupported,
                "media_address is set and this build cannot manage the media of a consultation \
                 leg; place it with sdp and run its audio in the application",
            ));
        }
        // no catalogue here to apply it to, but the same refusal as
        // `sipral_call_place` for a value this ABI names nothing for
        crate::media::srtp_policy(config.srtp, "srtp")?;
        let handle = with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let outgoing = unsafe { outgoing_from(state, &config, false) }?;
            let placed = state
                .agent
                .consult(id, &outgoing, now)
                .map_err(|error| ua_failed(&error))?;
            if let Some(identity) = state.agent.call_identity(placed) {
                state.record_identity(placed, identity);
            }
            state
                .calls
                .name_of(placed)
                .map_err(|status| fail(status, "no room for another call on this stack"))
        })?;
        unsafe { out_consultation.write(handle) };
        Ok(())
    }
}

entry! {
    /// Hand `call` to the far end of `other` (RFC 3891).
    ///
    /// The attended half of a transfer: `other` is normally the consultation
    /// call, and the party at its far end replaces the call it already has
    /// rather than answering a second one. Any call that is up may be named.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_transfer_to(
        stack: SipralHandle,
        call: SipralHandle,
        other: SipralHandle,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let other = state.calls.get(other).map_err(handle_failed)?;
            state
                .agent
                .transfer_to(id, other, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Take a transfer that was asked for, place the call it names, and write
    /// that call's handle to `out_placed`.
    ///
    /// # Safety
    ///
    /// `out_placed` must point at one `sipral_handle_t`.
    fn sipral_call_accept_transfer(
        stack: SipralHandle,
        call: SipralHandle,
        out_placed: *mut SipralHandle,
        now_ms: u64,
    ) {
        if out_placed.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_placed is null"));
        }
        let handle = with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            // No offer travels through this entry point yet -- it has no
            // parameter to carry one -- so the INVITE goes out offerless and
            // the answer is expected in the 2xx, exactly as it always has.
            let placed = state
                .agent
                .accept_transfer(id, None, now)
                .map_err(|error| ua_failed(&error))?;
            if let Some(identity) = state.agent.call_identity(placed) {
                state.record_identity(placed, identity);
            }
            state
                .calls
                .name_of(placed)
                .map_err(|status| fail(status, "no room for another call on this stack"))
        })?;
        unsafe { out_placed.write(handle) };
        Ok(())
    }
}

entry! {
    /// Refuse one instead.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_reject_transfer(
        stack: SipralHandle,
        call: SipralHandle,
        code: u32,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let status = status_code(code)?;
            state
                .agent
                .reject_transfer(id, status, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Where a call is, as a `SipralCallState`.
    ///
    /// A call that is over answers `SIPRAL_CALL_STATE_TERMINATED` until the
    /// poll that delivers `SIPRAL_EVENT_KIND_CALL_ENDED` retires its handle, and
    /// `SIPRAL_STATUS_STALE_HANDLE` after that.
    ///
    /// # Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    fn sipral_call_state(stack: SipralHandle, call: SipralHandle, out_state: *mut u32) {
        if out_state.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_state is null"));
        }
        let state = with_stack(stack, |state| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let where_it_is = state.agent.call_state(id).map_or(
                // the handle is still ours and the layer below has let the
                // call go, which is what being over looks like from here
                SipralCallState::Terminated,
                |state| call_state(Some(state)),
            );
            Ok(where_it_is as u32)
        })?;
        unsafe { out_state.write(state) };
        Ok(())
    }
}

entry! {
    /// Which way a call is held: `out_here` is set when this end asked the far
    /// end to stop sending, `out_there` when the far end asked this one.
    /// Either may be null.
    ///
    /// # Safety
    ///
    /// `out_here` and `out_there` must each be null or point at one
    /// `uint32_t`.
    fn sipral_call_hold_state(
        stack: SipralHandle,
        call: SipralHandle,
        out_here: *mut u32,
        out_there: *mut u32,
    ) {
        let held = with_stack(stack, |state| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            state.agent.hold_state(id).ok_or_else(|| {
                fail(
                    SipralStatus::WrongState,
                    "the call has described nothing yet, so it is held neither way",
                )
            })
        })?;
        if !out_here.is_null() {
            unsafe { out_here.write(u32::from(held.local)) };
        }
        if !out_there.is_null() {
            unsafe { out_there.write(u32::from(held.remote)) };
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        SipralCallConfig, SipralDtmf, dtmf_body, dtmf_form, keypad, sipral_call_accept_session,
        sipral_call_accept_transfer, sipral_call_answer, sipral_call_answer_media,
        sipral_call_consult, sipral_call_hangup, sipral_call_hold, sipral_call_hold_state,
        sipral_call_place, sipral_call_reject, sipral_call_reject_session, sipral_call_resume,
        sipral_call_ring, sipral_call_send_dtmf, sipral_call_state, sipral_call_transfer,
        sipral_call_transfer_to, tone_length,
    };
    use crate::account::{
        SipralAccountConfig, sipral_account_add, sipral_account_register, sipral_account_remove,
    };
    use crate::error::last_error_text;
    use crate::event::{SipralCallState, SipralEventKind};
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle, StackTags, split};
    use crate::media::{SipralSrtp, sipral_call_media, sipral_media_release};
    use crate::stack::tests::{Observed, config, create, poll, record, stack, stack_on};
    use crate::stack::{sipral_stack_destroy, with_stack};
    use crate::status::SipralStatus;
    use sipral_core::endpoint::Input;
    use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, parse};
    use std::ffi::c_char;
    use std::net::SocketAddr;
    use std::ptr;

    const AOR: &str = "sip:alice@example.com";
    const REGISTRAR: &str = "sip:example.com";
    const CONTACT: &str = "sip:alice@192.0.2.10:5060";
    const PEER: &str = "203.0.113.5:5060";
    const TARGET: &str = "sip:bob@example.com";

    /// Where a managed call receives its media, which is the application's
    /// socket and therefore the application's to name.
    pub(crate) const MEDIA: &str = "192.0.2.10:40000";

    /// Where the far end receives its own, as the answers below say.
    pub(crate) const PEER_MEDIA: &str = "203.0.113.5:41000";

    /// What a media test offers, so that the answer it writes has one format to
    /// agree with.
    const ONE_CODEC: &str = "PCMU";

    const OFFER: &[u8] = b"v=0\r\n\
o=alice 1 1 IN IP4 192.0.2.10\r\n\
s=-\r\n\
c=IN IP4 192.0.2.10\r\n\
t=0 0\r\n\
m=audio 40000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=sendrecv\r\n";

    const ANSWER: &[u8] = b"v=0\r\n\
o=bob 1 1 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 41000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=sendrecv\r\n";

    /// A re-offer that changes the format list, which is what the user agent
    /// has no policy of its own for: a change that keeps the same media is one
    /// it answers itself, and only a different one reaches the layer above.
    pub(crate) const REOFFERED: &[u8] = b"v=0\r\n\
o=bob 1 2 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 41000 RTP/AVP 0 8\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=sendrecv\r\n";

    /// An answer naming a format nobody offered, which happens and is better
    /// said than played as noise.
    pub(crate) const ALAW_ANSWER: &[u8] = b"v=0\r\n\
o=bob 1 1 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 41000 RTP/AVP 8\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=sendrecv\r\n";

    /// What the far end answers a hold with: it will receive, and not send
    /// (RFC 3264 §6.1).
    const HELD_ANSWER: &[u8] = b"v=0\r\n\
o=bob 1 2 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 41000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=recvonly\r\n";

    fn as_text(value: &str) -> (*const c_char, usize) {
        (value.as_ptr().cast::<c_char>(), value.len())
    }

    fn peer() -> SocketAddr {
        PEER.parse().expect("a written address")
    }

    fn local() -> SocketAddr {
        crate::stack::tests::BIND
            .parse()
            .expect("a written address")
    }

    fn account_config() -> SipralAccountConfig {
        let (aor, aor_len) = as_text(AOR);
        let (registrar, registrar_len) = as_text(REGISTRAR);
        let (contact, contact_len) = as_text(CONTACT);
        let (registrar_address, registrar_address_len) = as_text(PEER);
        SipralAccountConfig {
            size: size_of::<SipralAccountConfig>(),
            aor,
            aor_len,
            registrar,
            registrar_len,
            contact,
            contact_len,
            registrar_address,
            registrar_address_len,
            display_name: ptr::null(),
            display_name_len: 0,
            auth_user: ptr::null(),
            auth_user_len: 0,
            auth_password: ptr::null(),
            auth_password_len: 0,
            instance_id: ptr::null(),
            instance_id_len: 0,
            expires_seconds: 0,
            headers: ptr::null(),
            headers_len: 0,
        }
    }

    pub(crate) fn call_config() -> SipralCallConfig {
        let (target, target_len) = as_text(TARGET);
        SipralCallConfig {
            size: size_of::<SipralCallConfig>(),
            target,
            target_len,
            sdp: OFFER.as_ptr(),
            sdp_len: OFFER.len(),
            destination: ptr::null(),
            destination_len: 0,
            keep_all_forks: 0,
            media_address: ptr::null(),
            media_address_len: 0,
            headers: ptr::null(),
            headers_len: 0,
            srtp: 0,
        }
    }

    /// The same, for a call whose session this stack describes.
    pub(crate) fn managed_config() -> SipralCallConfig {
        let (media_address, media_address_len) = as_text(MEDIA);
        SipralCallConfig {
            sdp: ptr::null(),
            sdp_len: 0,
            media_address,
            media_address_len,
            ..call_config()
        }
    }

    /// Name an account on a stack that already exists.
    pub(crate) fn account_on(handle: SipralHandle) -> SipralHandle {
        let config = account_config();
        let mut account = SIPRAL_HANDLE_NONE;
        let status =
            unsafe { sipral_account_add(handle, ptr::from_ref(&config), &raw mut account) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        account
    }

    /// The same, presenting itself with a display name, which is what a call
    /// it places writes in `From`.
    fn account_named(handle: SipralHandle, display_name: &str) -> SipralHandle {
        let mut config = account_config();
        (config.display_name, config.display_name_len) = as_text(display_name);
        let mut account = SIPRAL_HANDLE_NONE;
        let status =
            unsafe { sipral_account_add(handle, ptr::from_ref(&config), &raw mut account) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        account
    }

    /// A stack with one account, ready to place a call.
    fn line(observed: &mut Observed) -> (SipralHandle, SipralHandle) {
        let handle = stack(observed);
        (handle, account_on(handle))
    }

    /// The same, offering one codec, so that a test writes an answer of one
    /// line rather than conducting a negotiation of its own.
    pub(crate) fn media_line(
        observed: &mut Observed,
        tune: impl FnOnce(&mut crate::stack::SipralStackConfig),
    ) -> (SipralHandle, SipralHandle) {
        let (codecs, codecs_len) = as_text(ONE_CODEC);
        let mut config = config(record, observed);
        config.codecs = codecs;
        config.codecs_len = codecs_len;
        tune(&mut config);
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        (handle, account_on(handle))
    }

    fn place(
        stack: SipralHandle,
        account: SipralHandle,
        config: &SipralCallConfig,
        now_ms: u64,
    ) -> (SipralStatus, SipralHandle) {
        let mut call = SIPRAL_HANDLE_NONE;
        let status = unsafe {
            sipral_call_place(stack, account, ptr::from_ref(config), &raw mut call, now_ms)
        };
        (status, call)
    }

    fn state_of(stack: SipralHandle, call: SipralHandle) -> u32 {
        let mut state = u32::MAX;
        let status = unsafe { sipral_call_state(stack, call, &raw mut state) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        state
    }

    /// What the stack wanted written, drained the way
    /// `sipral_stack_poll_transmit` drains it: whatever is held back for want of
    /// a buffer comes first, then the queue behind it.
    pub(crate) fn sent(stack: SipralHandle) -> Vec<Vec<u8>> {
        with_stack(stack, |state| {
            let mut all = Vec::new();
            while let Some(transmit) = state.held.take().or_else(|| state.agent.poll_transmit()) {
                all.push(transmit.payload.to_vec());
            }
            Ok(all)
        })
        .expect("the stack is live")
    }

    /// The one message the stack wanted written.
    pub(crate) fn one(stack: SipralHandle) -> Vec<u8> {
        let mut all = sent(stack);
        assert_eq!(all.len(), 1, "expected exactly one message out");
        all.pop().unwrap_or_default()
    }

    fn field(bytes: &[u8], name: HeaderName<'_>) -> Vec<u8> {
        let mut scratch = ParseScratch::new();
        let message = parse(bytes, &mut scratch, ParseMode::Lenient).expect("a message");
        message.header(name).unwrap_or_default().to_vec()
    }

    fn start_line(bytes: &[u8]) -> String {
        String::from_utf8_lossy(
            bytes
                .split(|byte| *byte == b'\r')
                .next()
                .unwrap_or_default(),
        )
        .into_owned()
    }

    /// The 200 the far end answers an INVITE with: the same dialog, a tag of
    /// its own, somewhere to send the ACK, and the answer to the offer.
    ///
    /// The tag is added only to the first one. A re-INVITE goes out inside a
    /// dialog whose `To` already carries it, and a second tag would name a
    /// dialog nobody is in.
    pub(crate) fn accepted(request: &[u8], body: &[u8], first: bool) -> Vec<u8> {
        let mut out = b"SIP/2.0 200 OK\r\n".to_vec();
        for (name, value) in [
            ("Via", field(request, HeaderName::Via)),
            ("From", field(request, HeaderName::From)),
            ("To", {
                let mut to = field(request, HeaderName::To);
                if first {
                    to.extend_from_slice(b";tag=farend");
                }
                to
            }),
            ("Call-ID", field(request, HeaderName::CallId)),
            ("CSeq", field(request, HeaderName::CSeq)),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"Contact: <sip:bob@203.0.113.5:5060>\r\n");
        out.extend_from_slice(b"Content-Type: application/sdp\r\n");
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        out.extend_from_slice(body);
        out
    }

    /// A 180 the far end sends back for the INVITE this end placed.
    fn ringing(invite: &[u8]) -> Vec<u8> {
        let mut out = b"SIP/2.0 180 Ringing\r\n".to_vec();
        for (name, value) in [
            ("Via", field(invite, HeaderName::Via)),
            ("From", field(invite, HeaderName::From)),
            ("To", {
                let mut to = field(invite, HeaderName::To);
                to.extend_from_slice(b";tag=farend");
                to
            }),
            ("Call-ID", field(invite, HeaderName::CallId)),
            ("CSeq", field(invite, HeaderName::CSeq)),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"Contact: <sip:bob@203.0.113.5:5060>\r\n");
        out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        out
    }

    pub(crate) fn deliver(stack: SipralHandle, message: &[u8], now_ms: u64) {
        with_stack(stack, |state| {
            let now = state.instant(now_ms)?;
            let transport = state.transport;
            state
                .agent
                .receive(
                    Input::Datagram {
                        transport,
                        remote: peer(),
                        local: local(),
                        data: message,
                    },
                    now,
                )
                .expect("a well formed datagram");
            Ok(())
        })
        .expect("the stack is live");
    }

    /// A call this end placed and the far end answered, described by the
    /// application and carrying no audio this stack knows about.
    pub(crate) fn connected(observed: &mut Observed) -> (SipralHandle, SipralHandle) {
        let (handle, account) = line(observed);
        let (status, call) = place(handle, account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        assert!(start_line(&invite).starts_with("INVITE"));
        deliver(handle, &accepted(&invite, ANSWER, true), 1_100);
        let result = poll(handle, 1_100);
        assert!(result.events_delivered >= 2);
        assert_eq!(
            state_of(handle, call),
            SipralCallState::Confirmed as u32,
            "the call did not come up"
        );
        // the ACK the answer produced, taken the way a caller takes it; what is
        // left waiting here would be the next test's "one message out"
        let _ = sent(handle);
        (handle, call)
    }

    /// The same, with the session described by this stack and audio running on
    /// it: what every media test starts from.
    pub(crate) fn media_call(observed: &mut Observed) -> (SipralHandle, SipralHandle) {
        media_call_tuned(observed, |_| {})
    }

    /// The same, on a stack configured to taste.
    pub(crate) fn media_call_tuned(
        observed: &mut Observed,
        tune: impl FnOnce(&mut crate::stack::SipralStackConfig),
    ) -> (SipralHandle, SipralHandle) {
        let (handle, account) = media_line(observed, tune);
        up(observed, handle, account, ANSWER)
    }

    /// The same, offering the codecs named and answered with the line given,
    /// for the test that needs a call on something other than the mu-law
    /// every other fixture here negotiates.
    pub(crate) fn media_call_offering(
        observed: &mut Observed,
        codecs: &'static str,
        answer: &[u8],
    ) -> (SipralHandle, SipralHandle) {
        let (handle, account) = media_line(observed, |config| {
            let (text, len) = as_text(codecs);
            config.codecs = text;
            config.codecs_len = len;
        });
        up(observed, handle, account, answer)
    }

    /// One call placed on a line that is ready, answered with `answer`, and
    /// up with audio on it.
    fn up(
        observed: &Observed,
        handle: SipralHandle,
        account: SipralHandle,
        answer: &[u8],
    ) -> (SipralHandle, SipralHandle) {
        let (status, call) = place(handle, account, &managed_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        deliver(handle, &accepted(&invite, answer, true), 1_100);
        poll(handle, 1_100);
        assert_eq!(
            state_of(handle, call),
            SipralCallState::Confirmed as u32,
            "the call did not come up"
        );
        assert!(
            observed.kinds().contains(&SipralEventKind::MediaStarted),
            "the call came up without audio: {:?}",
            observed.kinds()
        );
        let _ = sent(handle);
        (handle, call)
    }

    /// A managed call whose far end answered with a format nobody offered, so
    /// that the negotiation fails while the call stands.
    pub(crate) fn media_call_refused(observed: &mut Observed) -> (SipralHandle, SipralHandle) {
        let (handle, account) = media_line(observed, |_| {});
        let (status, call) = place(handle, account, &managed_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        deliver(handle, &accepted(&invite, ALAW_ANSWER, true), 1_100);
        poll(handle, 1_100);
        (handle, call)
    }

    /// The ACK the far end sends for a 200 it was answered with, which is what
    /// finally confirms a call that came in.
    pub(crate) fn acknowledged(response: &[u8]) -> Vec<u8> {
        let mut out = format!("ACK {CONTACT} SIP/2.0\r\n").into_bytes();
        for (name, value) in [
            (
                "Via",
                b"SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-an-ack".to_vec(),
            ),
            ("Max-Forwards", b"70".to_vec()),
            ("From", field(response, HeaderName::From)),
            ("To", field(response, HeaderName::To)),
            ("Call-ID", field(response, HeaderName::CallId)),
            ("CSeq", b"1 ACK".to_vec()),
            ("Content-Length", b"0".to_vec()),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    /// A re-INVITE from the far end, inside the dialog the INVITE opened.
    ///
    /// The dialog seen from over there: what we put in `From` is its `To`, and
    /// the tag it answered with is its own.
    pub(crate) fn reoffer(invite: &[u8], body: &[u8]) -> Vec<u8> {
        let mut from = field(invite, HeaderName::To);
        from.extend_from_slice(b";tag=farend");
        let mut out = format!("INVITE {CONTACT} SIP/2.0\r\n").into_bytes();
        for (name, value) in [
            (
                "Via",
                b"SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-a-reoffer".to_vec(),
            ),
            ("Max-Forwards", b"70".to_vec()),
            ("From", from),
            ("To", field(invite, HeaderName::From)),
            ("Call-ID", field(invite, HeaderName::CallId)),
            ("CSeq", b"2 INVITE".to_vec()),
            ("Contact", b"<sip:bob@203.0.113.5:5060>".to_vec()),
            ("Content-Type", b"application/sdp".to_vec()),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        out.extend_from_slice(body);
        out
    }

    /// Hang up and let the far end answer, so that the call really ends.
    pub(crate) fn hangup(stack: SipralHandle, call: SipralHandle, now_ms: u64) {
        assert_eq!(
            unsafe { sipral_call_hangup(stack, call, now_ms) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let bye = one(stack);
        assert!(start_line(&bye).starts_with("BYE"));
        deliver(stack, &accepted(&bye, b"", false), now_ms + 1);
        poll(stack, now_ms + 1);
    }

    /// An INVITE from somebody else, addressed here.
    fn invitation() -> Vec<u8> {
        let mut out = b"INVITE sip:alice@192.0.2.10:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-a-call-in\r\n\
Max-Forwards: 70\r\n\
From: <sip:bob@example.com>;tag=farend\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: a-call-in@203.0.113.5\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@203.0.113.5:5060>\r\n\
Content-Type: application/sdp\r\n"
            .to_vec();
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", ANSWER.len()).as_bytes());
        out.extend_from_slice(ANSWER);
        out
    }

    /// The same, with a `From` whose quoted display name escapes a quote of
    /// its own, and a `To` whose URI carries a parameter that belongs to the
    /// address rather than to the header.
    fn invitation_with_identity() -> Vec<u8> {
        let mut out = b"INVITE sip:alice@192.0.2.10:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-a-call-in-id\r\n\
Max-Forwards: 70\r\n\
From: \"Bob \\\"the Builder\\\"\" <sip:bob@example.com;transport=tcp>;tag=farend\r\n\
To: <sip:alice@example.com;user=phone>\r\n\
Call-ID: identity-in@203.0.113.5\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@203.0.113.5:5060>\r\n\
Content-Type: application/sdp\r\n"
            .to_vec();
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", ANSWER.len()).as_bytes());
        out.extend_from_slice(ANSWER);
        out
    }

    /// The CANCEL the far end sends for [`invitation`] before it is answered:
    /// the same Request-URI, `Via`, `From`, `To`, `Call-ID` and sequence
    /// number (RFC 3261 §9.1).
    fn cancellation() -> Vec<u8> {
        b"CANCEL sip:alice@192.0.2.10:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-a-call-in\r\n\
Max-Forwards: 70\r\n\
From: <sip:bob@example.com>;tag=farend\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: a-call-in@203.0.113.5\r\n\
CSeq: 1 CANCEL\r\n\
Content-Length: 0\r\n\r\n"
            .to_vec()
    }

    /// A request the far end sends inside the dialog this end's 200 opened:
    /// `From` and `To` exactly as that 200 wrote them, since the far end is the
    /// one that sent the INVITE, and `more` written in before the body.
    fn from_far_end(ours: &[u8], method: &str, branch: &str, cseq: u32, more: &str) -> Vec<u8> {
        let mut out = format!(
            "{method} sip:alice@192.0.2.10:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-{branch}\r\n\
Max-Forwards: 70\r\n"
        )
        .into_bytes();
        for (name, value) in [
            ("From", field(ours, HeaderName::From)),
            ("To", field(ours, HeaderName::To)),
            ("Call-ID", field(ours, HeaderName::CallId)),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(
            format!(
                "CSeq: {cseq} {method}\r\n\
Contact: <sip:bob@203.0.113.5:5060>\r\n\
{more}Content-Length: 0\r\n\r\n"
            )
            .as_bytes(),
        );
        out
    }

    /// The handle the one incoming-call event named.
    fn called(observed: &Observed) -> SipralHandle {
        observed
            .events
            .iter()
            .zip(observed.named.iter())
            .find(|(event, _)| event.1 == SipralEventKind::IncomingCall)
            .map(|(_, named)| named.1)
            .expect("an incoming call was reported")
    }

    #[test]
    fn a_call_that_comes_in_is_named_reported_ringing_and_answered() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        assert_ne!(call, SIPRAL_HANDLE_NONE);
        assert_eq!(state_of(handle, call), SipralCallState::Incoming as u32);
        // the 100 Trying the core sent by itself
        let _ = sent(handle);

        assert_eq!(
            unsafe { sipral_call_ring(handle, call, ptr::null(), 0, 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert!(start_line(&one(handle)).starts_with("SIP/2.0 180"));
        assert_eq!(state_of(handle, call), SipralCallState::Ringing as u32);

        assert_eq!(
            unsafe { sipral_call_answer(handle, call, ANSWER.as_ptr(), ANSWER.len(), 1_200) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let accepted = one(handle);
        assert!(start_line(&accepted).starts_with("SIP/2.0 200"));
        assert_eq!(
            field(&accepted, HeaderName::ContentType),
            b"application/sdp"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_that_comes_in_can_be_refused_with_the_status_it_deserves() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);
        assert_eq!(
            unsafe { sipral_call_reject(handle, call, 603, 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert!(start_line(&one(handle)).starts_with("SIP/2.0 603"));
        poll(handle, 1_100);
        assert!(observed.kinds().contains(&SipralEventKind::CallEnded));
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn an_incoming_calls_event_names_its_from_display_and_to_exactly() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        deliver(handle, &invitation_with_identity(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let seen = observed
            .identities_of(call)
            .into_iter()
            .find(|seen| seen.kind == SipralEventKind::IncomingCall)
            .expect("the incoming call event named who is on it");
        assert_eq!(seen.from_uri, b"sip:bob@example.com;transport=tcp");
        assert_eq!(seen.from_display, b"Bob \"the Builder\"");
        assert_eq!(seen.to_uri, b"sip:alice@example.com;user=phone");
        assert_eq!(seen.call_id, b"identity-in@203.0.113.5");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The map this comes from is forgotten in the same `drain` that
    /// translates the call's own ending, so this is also the test that the
    /// bytes a delivery already queued do not go with it.
    #[test]
    fn an_incoming_calls_identity_survives_into_its_own_ended_event() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);
        assert_eq!(
            unsafe { sipral_call_reject(handle, call, 603, 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let _ = one(handle);
        poll(handle, 1_100);
        let ended = observed
            .identities_of(call)
            .into_iter()
            .find(|seen| seen.kind == SipralEventKind::CallEnded)
            .expect("the call ended");
        assert_eq!(ended.from_uri, b"sip:bob@example.com");
        assert!(ended.from_display.is_empty(), "the invite named no display");
        assert_eq!(ended.to_uri, b"sip:alice@example.com");
        assert_eq!(ended.call_id, b"a-call-in@203.0.113.5");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A caller who gives up at once: the INVITE and its CANCEL both arrive
    /// before the application polls, so the layer below has already let the
    /// call go when the event announcing it is translated.
    #[test]
    fn a_call_cancelled_before_the_poll_still_names_who_was_calling() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        deliver(handle, &invitation(), 1_000);
        deliver(handle, &cancellation(), 1_010);
        poll(handle, 1_010);
        let call = called(&observed);
        let seen = observed.identities_of(call);
        for kind in [SipralEventKind::IncomingCall, SipralEventKind::CallEnded] {
            let one = seen
                .iter()
                .find(|one| one.kind == kind)
                .unwrap_or_else(|| panic!("no {kind:?} among {seen:?}"));
            assert_eq!(one.from_uri, b"sip:bob@example.com", "{kind:?}");
            assert!(one.from_display.is_empty(), "{kind:?}");
            assert_eq!(one.to_uri, b"sip:alice@example.com", "{kind:?}");
            assert_eq!(one.call_id, b"a-call-in@203.0.113.5", "{kind:?}");
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The third way a call is placed through this ABI, beside
    /// `sipral_call_place` and `sipral_call_consult`: the one a REFER asked
    /// for, taken with `sipral_call_accept_transfer`.
    #[test]
    fn a_call_a_transfer_placed_names_its_own_from_and_to_and_call_id() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);
        assert_eq!(
            unsafe { sipral_call_answer(handle, call, ANSWER.as_ptr(), ANSWER.len(), 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let ok = one(handle);
        deliver(handle, &from_far_end(&ok, "ACK", "xfer-ack", 1, ""), 1_150);
        poll(handle, 1_150);
        deliver(
            handle,
            &from_far_end(
                &ok,
                "REFER",
                "xfer-refer",
                2,
                "Refer-To: <sip:carol@example.com>\r\n",
            ),
            1_200,
        );
        poll(handle, 1_200);
        assert!(
            observed
                .kinds()
                .contains(&SipralEventKind::TransferRequested),
            "the REFER was reported"
        );
        let _ = sent(handle);

        let mut placed = SIPRAL_HANDLE_NONE;
        assert_eq!(
            unsafe { sipral_call_accept_transfer(handle, call, &raw mut placed, 1_300) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let invite = sent(handle)
            .into_iter()
            .find(|bytes| start_line(bytes).starts_with("INVITE sip:carol@example.com"))
            .expect("the call the REFER asked for went out");
        deliver(handle, &ringing(&invite), 1_350);
        poll(handle, 1_350);

        let progress = observed
            .identities_of(placed)
            .into_iter()
            .find(|seen| seen.kind == SipralEventKind::CallProgress)
            .expect("the transferred call rang");
        assert_eq!(progress.from_uri, b"sip:alice@example.com");
        assert_eq!(progress.to_uri, b"sip:carol@example.com");
        assert_eq!(progress.call_id, field(&invite, HeaderName::CallId));
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_is_placed_and_the_invite_goes_out() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (status, call) = place(handle, account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(call, SIPRAL_HANDLE_NONE);
        assert_eq!(state_of(handle, call), SipralCallState::Calling as u32);
        let invite = one(handle);
        assert!(start_line(&invite).starts_with("INVITE sip:bob@example.com"));
        assert_eq!(field(&invite, HeaderName::ContentType), b"application/sdp");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_placed_without_an_offer_is_refused() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let mut config = call_config();
        config.sdp = ptr::null();
        config.sdp_len = 0;
        assert_eq!(
            place(handle, account, &config, 0).0,
            SipralStatus::InvalidArgument
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The rule that an offerless INVITE gets its answer in the ACK is
    /// RFC 3261 §13.2.1 (Creating the Initial INVITE); §14.1 is UAC behavior
    /// for a re-INVITE that modifies a session already up, a different rule
    /// this same file cites correctly elsewhere. The needle is assembled at
    /// runtime so this test does not just match its own assertion.
    #[test]
    fn the_module_doc_cites_the_section_that_puts_the_answer_in_the_ack() {
        // the needle spans a line break, and a Windows checkout puts a CR in
        // front of it
        let source = include_str!("call.rs").replace("\r\n", "\n");
        let section = '\u{a7}';
        assert!(
            source.contains(&format!("is legal ({section}13.2.1) and is")),
            "offering nothing and answering in the ACK is §13.2.1, not §14.1"
        );
    }

    #[test]
    fn a_target_that_is_not_a_uri_is_refused() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let mut config = call_config();
        (config.target, config.target_len) = as_text("bob");
        assert_eq!(
            place(handle, account, &config, 0).0,
            SipralStatus::InvalidArgument
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_destination_that_is_a_name_is_refused_because_nothing_here_resolves_one() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let mut config = call_config();
        (config.destination, config.destination_len) = as_text("proxy.example.com:5060");
        assert_eq!(
            place(handle, account, &config, 0).0,
            SipralStatus::InvalidArgument
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn placing_a_call_on_an_account_that_is_gone_is_stale() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        assert_eq!(
            unsafe { crate::account::sipral_account_remove(handle, account) },
            SipralStatus::Ok
        );
        assert_eq!(
            place(handle, account, &call_config(), 0).0,
            SipralStatus::StaleHandle
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_that_was_answered_is_confirmed_and_the_application_is_told() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        assert!(
            observed.kinds().contains(&SipralEventKind::CallConfirmed),
            "{:?}",
            observed.kinds()
        );
        let named = observed
            .events
            .iter()
            .zip(observed.named.iter())
            .find(|(event, _)| event.1 == SipralEventKind::CallConfirmed)
            .map(|(_, named)| named.1);
        assert_eq!(named, Some(call), "the event names the call it is about");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    fn held_state(stack: SipralHandle, call: SipralHandle) -> (u32, u32) {
        let mut here = u32::MAX;
        let mut there = u32::MAX;
        let status = unsafe { sipral_call_hold_state(stack, call, &raw mut here, &raw mut there) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        (here, there)
    }

    #[test]
    fn holding_a_call_that_is_up_writes_the_description_and_sends_it() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        let _ = sent(handle);
        assert_eq!(
            unsafe { sipral_call_hold(handle, call, 2_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let reinvite = one(handle);
        assert!(start_line(&reinvite).starts_with("INVITE"));
        let offered = String::from_utf8_lossy(&reinvite).into_owned();
        assert!(
            offered.contains("a=sendonly"),
            "the held description is not the one that went out: {offered}"
        );
        assert_eq!(
            held_state(handle, call),
            (0, 0),
            "the hold is offered, and it is not in effect until it is taken"
        );

        deliver(handle, &accepted(&reinvite, HELD_ANSWER, false), 2_100);
        poll(handle, 2_100);
        assert_eq!(held_state(handle, call), (1, 0));
        assert!(
            observed.kinds().contains(&SipralEventKind::SessionChanged),
            "{:?}",
            observed.kinds()
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// `HELD_ANSWER` carries `a=recvonly`, which per RFC 4566 means the party
    /// that wrote it — the far end — will receive and not send. The doc
    /// comment above the constant had the two swapped. The needle is
    /// assembled at runtime so this test does not just match its own
    /// assertion.
    #[test]
    fn the_held_answer_doc_matches_what_recvonly_means() {
        // the needle spans a line break, and a Windows checkout puts a CR in
        // front of it
        let source = include_str!("call.rs").replace("\r\n", "\n");
        let section = '\u{a7}';
        assert!(
            source.contains(&format!(
                "it will receive, and not send\n    /// (RFC 3264 {section}6.1)"
            )),
            "a=recvonly means the far end receives and does not send"
        );
    }

    #[test]
    fn resuming_a_call_that_was_never_held_sends_nothing_and_succeeds() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        let _ = sent(handle);
        assert_eq!(
            unsafe { sipral_call_resume(handle, call, 2_000) },
            SipralStatus::Ok
        );
        assert!(sent(handle).is_empty());
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn holding_a_call_that_is_not_up_says_so_rather_than_saying_nothing() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (_, call) = place(handle, account, &call_config(), 0);
        assert_eq!(
            unsafe { sipral_call_hold(handle, call, 0) },
            SipralStatus::WrongState
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn dtmf_goes_out_as_one_info_per_key() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        let _ = sent(handle);
        let (digits, digits_len) = as_text("1#d");
        assert_eq!(
            unsafe {
                sipral_call_send_dtmf(
                    handle,
                    call,
                    digits,
                    digits_len,
                    SipralDtmf::InfoRelay as u32,
                    0,
                    2_000,
                )
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let written = sent(handle);
        assert_eq!(written.len(), 3, "one INFO per key");
        for (message, expected) in written.iter().zip(["Signal=1", "Signal=#", "Signal=D"]) {
            assert!(start_line(message).starts_with("INFO"));
            assert_eq!(
                field(message, HeaderName::ContentType),
                b"application/dtmf-relay"
            );
            let body = String::from_utf8_lossy(message).into_owned();
            assert!(body.contains(expected), "{body}");
            assert!(body.contains("Duration=160"), "{body}");
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn an_options_is_answered_by_the_stack_and_never_reaches_the_caller() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        poll(handle, 1_000);
        // an OPTIONS is what a proxy pings a phone with, and §11.2 makes
        // answering it a MUST. It used to arrive here as one more unclaimed
        // event that nothing replied to, and an Asterisk that got no reply
        // marked the contact unreachable and refused every inbound call to
        // it with 503. There is no decision in the answer, so the stack
        // gives it and the caller never hears about it
        let ping = b"OPTIONS sip:alice@192.0.2.10:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-are-you-there\r\n\
Max-Forwards: 70\r\n\
From: <sip:proxy@example.com>;tag=asking\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: are-you-there@203.0.113.5\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";
        deliver(handle, ping, 1_100);

        // before the poll, which drains the transmit queue on the caller's
        // behalf and would carry the answer away with it
        let answers: Vec<String> = sent(handle)
            .iter()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .filter(|text| text.contains("CSeq: 1 OPTIONS"))
            .collect();
        let [answer] = answers.as_slice() else {
            panic!("expected exactly one answer to the OPTIONS, got {answers:?}");
        };
        assert!(answer.starts_with("SIP/2.0 200 "), "{answer}");
        // §11.2: built as though the request had been an INVITE, so it says
        // what this end can do rather than only that it is alive
        assert!(answer.contains("Allow: "), "{answer}");
        assert!(answer.contains("OPTIONS"), "{answer}");
        assert!(answer.contains("Accept: application/sdp"), "{answer}");
        assert!(answer.contains("Supported: "), "{answer}");

        let before = observed.events.len();
        let result = poll(handle, 1_100);
        assert_eq!(
            result.events_unclaimed, 0,
            "the OPTIONS was answered, so there was nothing left over"
        );
        assert_eq!(
            observed.events.len(),
            before,
            "and nothing the application has to decide reached the callback"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A form this ABI has no number for is refused rather than quietly taken
    /// as the default: an application that meant the media and passed a
    /// mistyped constant would otherwise send in the dialog and never know.
    #[test]
    fn a_way_of_sending_a_digit_that_does_not_exist_is_refused() {
        assert_eq!(dtmf_form(0).ok(), Some(SipralDtmf::Rtp));
        assert_eq!(dtmf_form(1).ok(), Some(SipralDtmf::InfoRelay));
        assert_eq!(dtmf_form(2).ok(), Some(SipralDtmf::InfoPlain));
        for wrong in [3, 4, u32::MAX] {
            assert!(dtmf_form(wrong).is_err(), "{wrong} was taken as a form");
        }
    }

    /// The other INFO body: the whole of it is the key. A switch that reads
    /// this one and not the other is the reason the form is chosen per send.
    #[test]
    fn the_plain_info_body_is_the_key_and_nothing_else() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        let _ = sent(handle);
        let (digits, digits_len) = as_text("5");
        assert_eq!(
            unsafe {
                sipral_call_send_dtmf(
                    handle,
                    call,
                    digits,
                    digits_len,
                    SipralDtmf::InfoPlain as u32,
                    0,
                    2_000,
                )
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let written = sent(handle);
        assert_eq!(written.len(), 1);
        let message = String::from_utf8_lossy(&written[0]).into_owned();
        assert!(message.contains("Content-Type: application/dtmf"));
        assert!(
            !message.contains("application/dtmf-relay"),
            "the plain form sent the relay body"
        );
        assert!(message.ends_with('5'), "the body is not just the key");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn dtmf_on_a_call_that_is_not_up_says_so() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (_, call) = place(handle, account, &call_config(), 0);
        let (digits, digits_len) = as_text("1");
        assert_eq!(
            unsafe {
                sipral_call_send_dtmf(
                    handle,
                    call,
                    digits,
                    digits_len,
                    SipralDtmf::InfoRelay as u32,
                    0,
                    0,
                )
            },
            SipralStatus::WrongState
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn only_the_sixteen_keys_a_keypad_has_are_digits() {
        assert_eq!(
            keypad("0123456789*#ABCD").ok(),
            Some(b"0123456789*#ABCD".to_vec())
        );
        assert_eq!(keypad("abcd").ok(), Some(b"ABCD".to_vec()));
        for refused in ["1 2", "E", "1e", "", "+", "\u{00e9}"] {
            assert!(
                keypad(refused).is_err(),
                "{refused:?} was taken for a keypad"
            );
        }
    }

    /// RFC 4733's section 3 has only 3.1, 3.2 and 3.3; the sixteen DTMF event
    /// codes are Table 3 in 3.2. A doc comment pointing at a section that
    /// does not exist is a defect the generator copies into the public
    /// header verbatim, so it is checked here rather than left to be noticed
    /// by eye.
    ///
    /// The needles are assembled at runtime, not written as one literal, so
    /// this test inspecting its own file does not just match itself.
    #[test]
    fn the_keypad_doc_cites_a_section_rfc_4733_actually_has() {
        // the needle spans a line break, and a Windows checkout puts a CR in
        // front of it
        let source = include_str!("call.rs").replace("\r\n", "\n");
        let section = '\u{a7}';
        assert!(
            source.contains(&format!("(RFC 4733 {section}3.2, Table 3)")),
            "the KEYPAD constant should point at Table 3 in §3.2"
        );
        assert!(
            source.contains(&format!(
                "RFC 4733 {section}3.2, in the order they were pressed"
            )),
            "sipral_call_send_dtmf's doc should point at §3.2 as well"
        );
    }

    #[test]
    fn a_tone_length_nobody_holds_a_key_for_is_refused() {
        assert_eq!(tone_length(0).ok(), Some(super::DEFAULT_DTMF_MS));
        assert_eq!(tone_length(100).ok(), Some(100));
        assert_eq!(
            tone_length(super::MAX_DTMF_MS).ok(),
            Some(super::MAX_DTMF_MS)
        );
        assert!(tone_length(super::MAX_DTMF_MS + 1).is_err());
        assert!(tone_length(u32::MAX).is_err());
    }

    #[test]
    fn one_key_is_two_lines() {
        let body = dtmf_body(b'5', 160);
        assert_eq!(body.as_ref(), b"Signal=5\r\nDuration=160\r\n");
    }

    #[test]
    fn hanging_up_a_call_that_is_up_sends_a_bye_and_ends_it() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        let _ = sent(handle);
        assert_eq!(
            unsafe { sipral_call_hangup(handle, call, 2_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let bye = one(handle);
        assert!(start_line(&bye).starts_with("BYE"));
        // the BYE is out and the dialog is gone with it; what is left is the
        // event that says so, and the handle lives until it is delivered
        assert_eq!(state_of(handle, call), SipralCallState::Terminated as u32);

        poll(handle, 2_000);
        assert!(observed.kinds().contains(&SipralEventKind::CallEnded));
        let mut state = u32::MAX;
        assert_eq!(
            unsafe { sipral_call_state(handle, call, &raw mut state) },
            SipralStatus::StaleHandle
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_placed_calls_events_all_carry_its_own_from_and_to_and_call_id() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = account_named(handle, "Alice");
        let (status, call) = place(handle, account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);

        deliver(handle, &ringing(&invite), 1_050);
        poll(handle, 1_050);
        deliver(handle, &accepted(&invite, ANSWER, true), 1_100);
        poll(handle, 1_100);
        let _ = sent(handle); // the ACK
        hangup(handle, call, 1_200);

        let seen = observed.identities_of(call);
        assert!(
            [
                SipralEventKind::CallProgress,
                SipralEventKind::CallConfirmed,
                SipralEventKind::CallEnded,
            ]
            .iter()
            .all(|kind| seen.iter().any(|one| one.kind == *kind)),
            "expected progress, confirmed and ended among {:?}",
            seen.iter().map(|one| one.kind).collect::<Vec<_>>()
        );
        for one in &seen {
            assert_eq!(one.from_uri, b"sip:alice@example.com", "{:?}", one.kind);
            assert_eq!(one.from_display, b"Alice", "{:?}", one.kind);
            assert_eq!(one.to_uri, TARGET.as_bytes(), "{:?}", one.kind);
        }
        let call_id = &seen[0].call_id;
        assert!(!call_id.is_empty());
        assert!(
            seen.iter().all(|one| one.call_id == *call_id),
            "one call, one Call-ID, on every event of it"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_that_was_hung_up_answers_stale_to_a_second_attempt() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        assert_eq!(
            unsafe { sipral_call_hangup(handle, call, 2_000) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_call_hangup(handle, call, 2_001) },
            SipralStatus::StaleHandle,
            "the call is gone from the moment it ends, not from the poll that says so"
        );
        assert_eq!(
            unsafe { sipral_call_hold(handle, call, 2_002) },
            SipralStatus::StaleHandle
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_this_end_placed_cannot_be_answered_or_rejected_as_if_it_came_in() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (_, call) = place(handle, account, &call_config(), 0);
        assert_eq!(
            unsafe { sipral_call_answer(handle, call, ANSWER.as_ptr(), ANSWER.len(), 0) },
            SipralStatus::WrongState
        );
        assert_eq!(
            unsafe { sipral_call_reject(handle, call, 486, 0) },
            SipralStatus::WrongState
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn answering_with_no_description_is_refused_before_the_state_is_looked_at() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (_, call) = place(handle, account, &call_config(), 0);
        assert_eq!(
            unsafe { sipral_call_answer(handle, call, ptr::null(), 0, 0) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_number_that_is_not_a_status_code_is_refused() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (_, call) = place(handle, account, &call_config(), 0);
        for refused in [0_u32, 99, 700, 1_000, u32::MAX] {
            assert_eq!(
                unsafe { sipral_call_reject(handle, call, refused, 0) },
                SipralStatus::InvalidArgument,
                "{refused} was taken for a status code"
            );
            assert_eq!(
                unsafe { sipral_call_reject_session(handle, call, refused, 0) },
                SipralStatus::InvalidArgument
            );
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_transfer_of_a_call_that_is_not_up_says_so() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (_, call) = place(handle, account, &call_config(), 0);
        let (target, target_len) = as_text("sip:carol@example.com");
        assert_eq!(
            unsafe { sipral_call_transfer(handle, call, target, target_len, 0) },
            SipralStatus::WrongState
        );
        assert_eq!(
            unsafe { sipral_call_transfer_to(handle, call, call, 0) },
            SipralStatus::WrongState
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_blind_transfer_of_a_call_that_is_up_sends_a_refer() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        let _ = sent(handle);
        let (target, target_len) = as_text("sip:carol@example.com");
        assert_eq!(
            unsafe { sipral_call_transfer(handle, call, target, target_len, 2_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let refer = one(handle);
        assert!(start_line(&refer).starts_with("REFER"));
        let body = String::from_utf8_lossy(&refer).into_owned();
        assert!(body.contains("sip:carol@example.com"), "{body}");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_consultation_call_is_a_call_of_its_own() {
        let mut observed = Observed::default();
        let (handle, first) = connected(&mut observed);
        let _ = sent(handle);
        let config = call_config();
        let mut second = SIPRAL_HANDLE_NONE;
        let status = unsafe {
            sipral_call_consult(
                handle,
                first,
                ptr::from_ref(&config),
                &raw mut second,
                2_000,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(second, first);
        assert_eq!(state_of(handle, second), SipralCallState::Calling as u32);
        assert!(start_line(&one(handle)).starts_with("INVITE"));
        // handing the first call to a leg that is still ringing is refused:
        // there is no dialog to name in a Replaces
        assert_eq!(
            unsafe { sipral_call_transfer_to(handle, first, second, 2_100) },
            SipralStatus::WrongState
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn accepting_a_change_nobody_offered_says_so() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        assert_eq!(
            unsafe { sipral_call_accept_session(handle, call, ptr::null(), 0, 2_000) },
            SipralStatus::WrongState
        );
        assert_eq!(
            unsafe { sipral_call_reject_session(handle, call, 488, 2_000) },
            SipralStatus::WrongState
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_handle_from_one_stack_does_not_open_another() {
        // tags of its own, so both stacks start at the first generation the way
        // every stack did before a handle carried one; tags from the process's
        // own set come back carrying whatever other tests minted, and can refuse
        // the handle for a reason that has nothing to do with its stack
        static TAGS: StackTags = StackTags::new();
        let mut first_observed = Observed::default();
        let mut second_observed = Observed::default();
        let first = stack_on(&TAGS, &mut first_observed);
        let second = stack_on(&TAGS, &mut second_observed);
        let first_account = account_on(first);
        let second_account = account_on(second);
        let (status, foreign) = place(first, first_account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let (status, own) = place(second, second_account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let _ = one(second);
        // both stacks number their calls from the same first slot, so the two
        // handles differ in nothing but the stack they carry
        assert_ne!(foreign, own);
        assert_eq!(
            unsafe { sipral_call_hangup(second, foreign, 1_000) },
            SipralStatus::InvalidHandle,
            "the handle hung up the second stack's own call"
        );
        let message = last_error_text();
        assert!(
            message.contains("minted by another stack"),
            "the refusal does not say why: {message}"
        );
        assert!(
            sent(second).is_empty(),
            "the second stack sent something for its own call"
        );
        assert_eq!(state_of(second, own), SipralCallState::Calling as u32);
        assert_eq!(unsafe { sipral_stack_destroy(first) }, SipralStatus::Ok);
        assert_eq!(unsafe { sipral_stack_destroy(second) }, SipralStatus::Ok);
    }

    /// The tag is given back when a stack goes and taken by the next one, so
    /// the handles an application kept from the first stack carry the tag the
    /// second one mints with. They still name nothing there.
    #[test]
    fn a_handle_kept_from_a_destroyed_stack_names_nothing_on_the_stack_that_took_its_tag() {
        static TAGS: StackTags = StackTags::new();
        let mut gone_observed = Observed::default();
        let gone = stack_on(&TAGS, &mut gone_observed);
        let kept_account = account_on(gone);
        let (status, kept_call) = place(gone, kept_account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(unsafe { sipral_stack_destroy(gone) }, SipralStatus::Ok);

        let mut observed = Observed::default();
        let taken = stack_on(&TAGS, &mut observed);
        let tag_of = |handle| split(handle).expect("a handle").tag;
        assert_eq!(
            tag_of(taken),
            tag_of(gone),
            "the second stack has another tag, so this proves nothing"
        );
        let account = account_on(taken);
        let (status, call) = place(taken, account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let _ = one(taken);

        assert_eq!(
            unsafe { sipral_call_hangup(taken, kept_call, 1_000) },
            SipralStatus::InvalidHandle,
            "the kept call handle hung up the new stack's call"
        );
        let message = last_error_text();
        assert!(
            message.contains("minted by another stack"),
            "the refusal does not say why: {message}"
        );
        assert_eq!(
            unsafe { sipral_account_register(taken, kept_account, 1_000) },
            SipralStatus::InvalidHandle,
            "the kept account handle registered the new stack's account"
        );
        let message = last_error_text();
        assert!(
            message.contains("minted by another stack"),
            "the refusal does not say why: {message}"
        );
        assert!(
            sent(taken).is_empty(),
            "the new stack sent something for what the old handles matched"
        );
        assert_eq!(state_of(taken, call), SipralCallState::Calling as u32);
        assert_eq!(unsafe { sipral_stack_destroy(taken) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_that_ended_leaves_a_stale_handle_behind() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (_, call) = place(handle, account, &call_config(), 1_000);
        let invite = one(handle);
        // 486 Busy Here: the call is over and nothing is going to revive it
        let mut refused = b"SIP/2.0 486 Busy Here\r\n".to_vec();
        for name in [
            HeaderName::Via,
            HeaderName::From,
            HeaderName::To,
            HeaderName::CallId,
            HeaderName::CSeq,
        ] {
            refused.extend_from_slice(name.canonical().as_bytes());
            refused.extend_from_slice(b": ");
            refused.extend_from_slice(&field(&invite, name));
            refused.extend_from_slice(b"\r\n");
        }
        refused.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        deliver(handle, &refused, 1_100);
        let result = poll(handle, 1_100);
        assert!(result.events_delivered >= 2);
        assert!(observed.kinds().contains(&SipralEventKind::CallEnded));
        let mut state = u32::MAX;
        assert_eq!(
            unsafe { sipral_call_state(handle, call, &raw mut state) },
            SipralStatus::StaleHandle,
            "the handle outlived the call it named"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_null_out_parameter_is_a_bad_argument() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let config = call_config();
        assert_eq!(
            unsafe {
                sipral_call_place(handle, account, ptr::from_ref(&config), ptr::null_mut(), 0)
            },
            SipralStatus::InvalidArgument
        );
        let (_, call) = place(handle, account, &config, 0);
        assert_eq!(
            unsafe { sipral_call_state(handle, call, ptr::null_mut()) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A call has one description of its session. Two ways of saying what it
    /// is are one too many, and the answer says which two.
    #[test]
    fn a_call_described_twice_is_refused_rather_than_one_of_them_winning() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |_| {});
        let (media_address, media_address_len) = as_text(MEDIA);
        let mut config = call_config();
        config.media_address = media_address;
        config.media_address_len = media_address_len;
        let (status, call) = place(handle, account, &config, 1_000);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(call, SIPRAL_HANDLE_NONE);
        let message = last_error_text();
        assert!(
            message.contains("media_address") && message.contains("sdp"),
            "the message names neither: {message}"
        );

        let mut neither = call_config();
        neither.sdp = ptr::null();
        neither.sdp_len = 0;
        assert_eq!(
            place(handle, account, &neither, 1_000).0,
            SipralStatus::InvalidArgument,
            "and a call described neither way is refused too"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The other half of a managed call: one that came in, answered with a
    /// description this stack writes.
    #[test]
    fn a_call_that_comes_in_can_be_answered_with_media_of_this_stacks_own() {
        let mut observed = Observed::default();
        let (handle, _) = media_line(&mut observed, |_| {});
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);

        let (media_address, media_address_len) = as_text(MEDIA);
        let status = unsafe {
            sipral_call_answer_media(handle, call, media_address, media_address_len, 1_100)
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let answered = one(handle);
        assert!(start_line(&answered).starts_with("SIP/2.0 200"));
        let body = String::from_utf8_lossy(&answered).into_owned();
        assert!(
            body.contains("m=audio 40000 RTP/AVP 0"),
            "the answer is not this stack's own: {body}"
        );
        deliver(handle, &acknowledged(&answered), 1_200);
        poll(handle, 1_200);
        assert!(
            observed.kinds().contains(&SipralEventKind::MediaStarted),
            "the call was answered without audio: {:?}",
            observed.kinds()
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A change the far end offers on a managed call is answered by the stack,
    /// from the same codec order, before the poll that saw it returns. So it is
    /// not handed to the application, and the two entry points that would
    /// answer it a second time say so.
    #[test]
    fn a_stack_that_describes_a_call_answers_its_own_re_offers() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |_| {});
        let (status, call) = place(handle, account, &managed_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        deliver(handle, &accepted(&invite, ANSWER, true), 1_100);
        poll(handle, 1_100);
        let _ = sent(handle);

        deliver(handle, &reoffer(&invite, REOFFERED), 1_200);
        poll(handle, 1_200);
        assert!(
            !observed.kinds().contains(&SipralEventKind::SessionOffered),
            "the application was asked to answer what the stack already had: {:?}",
            observed.kinds()
        );
        assert!(
            !sent(handle).is_empty(),
            "nothing went out in answer to the re-offer"
        );
        assert!(
            observed.kinds().contains(&SipralEventKind::MediaChanged),
            "the application was told nothing about the session that changed: {:?}",
            observed.kinds()
        );
        assert_eq!(
            unsafe {
                sipral_call_accept_session(handle, call, ANSWER.as_ptr(), ANSWER.len(), 1_300)
            },
            SipralStatus::WrongState
        );
        assert_eq!(
            unsafe { sipral_call_reject_session(handle, call, 488, 1_300) },
            SipralStatus::WrongState
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A half-wired feature behind this ABI is worse than an absent one, so the
    /// consultation leg says what it cannot do rather than taking a media
    /// address it would then ignore.
    #[test]
    fn a_consultation_with_media_of_this_stacks_own_is_refused_rather_than_ignored() {
        let mut observed = Observed::default();
        let (handle, call) = media_call(&mut observed);
        let (media_address, media_address_len) = as_text(MEDIA);
        let mut config = call_config();
        config.sdp = ptr::null();
        config.sdp_len = 0;
        config.media_address = media_address;
        config.media_address_len = media_address_len;
        let mut consulted = SIPRAL_HANDLE_NONE;
        let status = unsafe {
            sipral_call_consult(
                handle,
                call,
                ptr::from_ref(&config),
                &raw mut consulted,
                2_000,
            )
        };
        assert_eq!(status, SipralStatus::NotSupported);
        assert_eq!(consulted, SIPRAL_HANDLE_NONE);
        assert!(last_error_text().contains("consultation"));
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn every_call_entry_point_refuses_a_handle_that_names_nothing() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        let (digits, digits_len) = as_text("1");
        let (target, target_len) = as_text(TARGET);
        let refused = [
            unsafe { sipral_call_hangup(handle, SIPRAL_HANDLE_NONE, 0) },
            unsafe { sipral_call_hold(handle, SIPRAL_HANDLE_NONE, 0) },
            unsafe { sipral_call_resume(handle, SIPRAL_HANDLE_NONE, 0) },
            unsafe { sipral_call_reject(handle, SIPRAL_HANDLE_NONE, 486, 0) },
            unsafe {
                sipral_call_answer(handle, SIPRAL_HANDLE_NONE, ANSWER.as_ptr(), ANSWER.len(), 0)
            },
            unsafe {
                sipral_call_send_dtmf(handle, SIPRAL_HANDLE_NONE, digits, digits_len, 0, 0, 0)
            },
            unsafe { sipral_call_transfer(handle, SIPRAL_HANDLE_NONE, target, target_len, 0) },
            unsafe { sipral_call_transfer_to(handle, SIPRAL_HANDLE_NONE, SIPRAL_HANDLE_NONE, 0) },
            unsafe { super::sipral_call_set_headers(handle, SIPRAL_HANDLE_NONE, ptr::null(), 0) },
        ];
        for status in refused {
            assert_eq!(status, SipralStatus::InvalidHandle);
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The size is checked before either handle is even looked up: a stack
    /// that was never created and a call config too short to be any version
    /// of this one both fail, and the size is the one this answers with — for
    /// a call placed on an account and for a consultation leg of a call alike.
    #[test]
    fn a_call_config_shorter_than_its_min_size_is_unsupported_version_even_for_an_invalid_handle() {
        let mut config = call_config();
        config.size = crate::versioned::min_size::CALL_CONFIG - 1;
        let (placed, _) = place(SIPRAL_HANDLE_NONE, SIPRAL_HANDLE_NONE, &config, 0);
        assert_eq!(
            placed,
            SipralStatus::UnsupportedVersion,
            "sipral_call_place"
        );
        let mut consultation = SIPRAL_HANDLE_NONE;
        let consulted = unsafe {
            sipral_call_consult(
                SIPRAL_HANDLE_NONE,
                SIPRAL_HANDLE_NONE,
                ptr::from_ref(&config),
                &raw mut consultation,
                0,
            )
        };
        assert_eq!(
            consulted,
            SipralStatus::UnsupportedVersion,
            "sipral_call_consult"
        );
    }

    /// The collision 8.4.17 exists to close: on the first stack of a
    /// process, its first account, its first call and its first media handle
    /// are all tag zero, slot zero, generation one, and every lookup here
    /// used to tell them apart only by which table happened to be asked. A
    /// handle of any other kind is now `SIPRAL_STATUS_INVALID_HANDLE`
    /// wherever one kind is expected — including
    /// `sipral_call_hangup(stack, stack, now)`, the exact call this test is
    /// named for.
    #[test]
    fn a_handle_of_the_wrong_kind_is_invalid_handle_wherever_it_is_offered() {
        let mut observed = Observed::default();
        let (stack_handle, call) = media_call(&mut observed);
        // a second account of this stack's, so a wrong-kind check can be
        // proven without disturbing the one the call was placed on
        let account = account_on(stack_handle);
        let mut media = SIPRAL_HANDLE_NONE;
        assert_eq!(
            unsafe { sipral_call_media(stack_handle, call, &raw mut media) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );

        // sipral_call_hangup(stack, stack, now): a call was expected
        for wrong in [stack_handle, account, media] {
            assert_eq!(
                unsafe { sipral_call_hangup(stack_handle, wrong, 2_000) },
                SipralStatus::InvalidHandle,
                "{wrong:#018x} is not a call"
            );
        }
        // an account was expected
        for wrong in [stack_handle, call, media] {
            assert_eq!(
                unsafe { sipral_account_remove(stack_handle, wrong) },
                SipralStatus::InvalidHandle,
                "{wrong:#018x} is not an account"
            );
        }
        // media was expected — reached by its own handle, with no stack to
        // resolve first, so this is the table's own kind check alone
        for wrong in [stack_handle, account, call] {
            assert_eq!(
                unsafe { sipral_media_release(wrong) },
                SipralStatus::InvalidHandle,
                "{wrong:#018x} is not a call's media"
            );
        }
        // a stack was expected
        for wrong in [account, call, media] {
            assert_eq!(
                unsafe { sipral_stack_destroy(wrong) },
                SipralStatus::InvalidHandle,
                "{wrong:#018x} is not a stack"
            );
        }

        hangup(stack_handle, call, 2_000);
        assert_eq!(
            unsafe { sipral_stack_destroy(stack_handle) },
            SipralStatus::Ok
        );
    }

    // -- header fields -------------------------------------------------------

    fn header_of(name: &str, value: &str) -> crate::header::SipralHeader {
        let (name, name_len) = as_text(name);
        let (value, value_len) = as_text(value);
        crate::header::SipralHeader {
            name,
            name_len,
            value,
            value_len,
        }
    }

    /// The first line of a field, read the way C reads it: through the
    /// accessor, with the offset and the length it answers.
    fn field_through_c(message: &[u8], name: &str) -> Option<Vec<u8>> {
        let mut count = usize::MAX;
        let status = unsafe {
            crate::header::sipral_message_header_count(
                message.as_ptr(),
                message.len(),
                name.as_ptr().cast::<c_char>(),
                name.len(),
                &raw mut count,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        if count == 0 {
            return None;
        }
        let (mut offset, mut len) = (usize::MAX, usize::MAX);
        let status = unsafe {
            crate::header::sipral_message_header(
                message.as_ptr(),
                message.len(),
                name.as_ptr().cast::<c_char>(),
                name.len(),
                0,
                &raw mut offset,
                &raw mut len,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        Some(message[offset..offset + len].to_vec())
    }

    #[test]
    fn a_field_put_on_the_invite_through_c_is_read_out_of_the_200_the_far_end_answered_with() {
        // the near end places the call, the far end answers it
        let mut near_seen = Observed::default();
        let (near, account) = line(&mut near_seen);
        let labelled = [header_of("X-Conversation-Id", "c-7")];
        let mut config = call_config();
        // to the address of record the far end's account has, so that the call
        // it answers belongs to a line and its 200 carries that line's Contact
        (config.target, config.target_len) = as_text(AOR);
        config.headers = labelled.as_ptr();
        config.headers_len = labelled.len();
        let (status, placed) = place(near, account, &config, 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(near);
        assert_eq!(
            field_through_c(&invite, "X-Conversation-Id").as_deref(),
            Some(&b"c-7"[..])
        );

        // the far end is a stack of its own, and reads the field back out of
        // the INVITE through the accessor to echo it
        let mut far_seen = Observed::default();
        let (far, _) = line(&mut far_seen);
        deliver(far, &invite, 1_000);
        poll(far, 1_000);
        let incoming = called(&far_seen);
        let _ = sent(far);
        let echoed = field_through_c(&invite, "x-conversation-id").expect("the field is there");
        let echoed = String::from_utf8(echoed).expect("text");
        let answering = [header_of("X-Conversation-Id", &echoed)];
        assert_eq!(
            unsafe {
                super::sipral_call_set_headers(far, incoming, answering.as_ptr(), answering.len())
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            unsafe { sipral_call_answer(far, incoming, ANSWER.as_ptr(), ANSWER.len(), 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let accepted = one(far);
        assert!(start_line(&accepted).starts_with("SIP/2.0 200"));
        assert_eq!(
            field_through_c(&accepted, "X-Conversation-Id").as_deref(),
            Some(&b"c-7"[..])
        );

        // and the 200 is one the near end takes
        deliver(near, &accepted, 1_200);
        let result = poll(near, 1_200);
        assert!(
            near_seen.kinds().contains(&SipralEventKind::CallConfirmed),
            "{:?}, {} unclaimed, the call in state {}, after:\n{}",
            near_seen.kinds(),
            result.events_unclaimed,
            state_of(near, placed),
            String::from_utf8_lossy(&accepted)
        );
        assert_eq!(unsafe { sipral_stack_destroy(far) }, SipralStatus::Ok);
        assert_eq!(unsafe { sipral_stack_destroy(near) }, SipralStatus::Ok);
    }

    #[test]
    fn a_field_the_stack_writes_is_refused_on_every_call_path_and_nothing_is_sent() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);

        let owned = [
            header_of("X-Conversation-Id", "c-7"),
            header_of("Contact", "<sip:elsewhere@example.net>"),
        ];
        let mut config = call_config();
        config.headers = owned.as_ptr();
        config.headers_len = owned.len();
        let (status, call) = place(handle, account, &config, 1_000);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(call, SIPRAL_HANDLE_NONE);
        let said = last_error_text();
        assert!(
            said.contains("headers[1]") && said.contains("Contact"),
            "{said}"
        );
        assert!(sent(handle).is_empty(), "nothing was built");

        // the compact form is the field it abbreviates
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let incoming = called(&observed);
        let _ = sent(handle);
        let compact = [header_of("i", "somebody-elses@example.net")];
        assert_eq!(
            unsafe {
                super::sipral_call_set_headers(handle, incoming, compact.as_ptr(), compact.len())
            },
            SipralStatus::InvalidArgument
        );
        let said = last_error_text();
        assert!(said.contains("Call-ID"), "{said}");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_field_that_is_not_one_line_of_text_under_a_token_is_refused() {
        const NOT_UTF8: &[u8] = b"c-\xff";
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (name, name_len) = as_text("X-Conversation-Id");
        for (hostile, why) in [
            (
                header_of(
                    "X-Conversation-Id",
                    "c-7\r\nContact: <sip:elsewhere@example.net>",
                ),
                "control byte",
            ),
            (header_of("X-Two Words", "1"), "not a token"),
            (
                crate::header::SipralHeader {
                    name,
                    name_len,
                    value: NOT_UTF8.as_ptr().cast::<c_char>(),
                    value_len: NOT_UTF8.len(),
                },
                "not UTF-8",
            ),
        ] {
            let smuggled = [hostile];
            let mut config = call_config();
            config.headers = smuggled.as_ptr();
            config.headers_len = smuggled.len();
            assert_eq!(
                place(handle, account, &config, 1_000).0,
                SipralStatus::InvalidArgument
            );
            let said = last_error_text();
            assert!(said.contains("headers[0]") && said.contains(why), "{said}");
            assert!(sent(handle).is_empty(), "nothing was built");
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn the_stacks_own_user_agent_is_not_written_twice() {
        let mut observed = Observed::default();
        let mut stack_config = config(record, &mut observed);
        (stack_config.user_agent, stack_config.user_agent_len) = as_text("Sipral-Test/1");
        let (status, handle) = create(&stack_config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let account = account_on(handle);
        let second = [header_of("User-Agent", "Somebody-Else/2")];
        let mut config = call_config();
        config.headers = second.as_ptr();
        config.headers_len = second.len();
        assert_eq!(
            place(handle, account, &config, 1_000).0,
            SipralStatus::InvalidArgument
        );
        assert!(last_error_text().contains("User-Agent"));
        assert!(sent(handle).is_empty());

        // on a stack that writes none, the application's is the one
        let mut bare_observed = Observed::default();
        let (bare, bare_account) = line(&mut bare_observed);
        assert_eq!(
            place(bare, bare_account, &config, 1_000).0,
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(field(&one(bare), HeaderName::UserAgent), b"Somebody-Else/2");
        assert_eq!(unsafe { sipral_stack_destroy(bare) }, SipralStatus::Ok);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn more_headers_than_any_message_takes_are_refused_before_an_element_is_read() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let too_many = vec![header_of("X-Bulk", "1"); 65];
        let mut config = call_config();
        config.headers = too_many.as_ptr();
        config.headers_len = too_many.len();
        assert_eq!(
            place(handle, account, &config, 1_000).0,
            SipralStatus::InvalidArgument
        );
        assert!(last_error_text().contains("65"), "{}", last_error_text());
        assert!(sent(handle).is_empty(), "nothing was built");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_null_headers_pointer_with_a_nonzero_length_is_refused() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let mut config = call_config();
        config.headers = ptr::null();
        config.headers_len = 1;
        assert_eq!(
            place(handle, account, &config, 1_000).0,
            SipralStatus::InvalidArgument
        );
        assert!(
            last_error_text().contains("headers is null"),
            "{}",
            last_error_text()
        );
        assert!(sent(handle).is_empty(), "nothing was built");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// `SIPRAL_SRTP_REQUIRED` reaches the offer through `catalog_of` and
    /// `with_srtp` exactly as `SIPRAL_SRTP_OFFERED` does — both write the
    /// secure profile with a key; only a plain re-offer or a plain answer is
    /// where the two differ, and this is not that (`docs/05-media.md`, "SRTP
    /// through the facade").
    #[test]
    fn a_stack_set_to_srtp_required_offers_the_secure_profile_with_a_key() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |config| {
            config.srtp = SipralSrtp::Required as u32;
        });
        let (status, _) = place(handle, account, &managed_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let body = String::from_utf8_lossy(&one(handle)).into_owned();
        assert!(
            body.contains("RTP/SAVP"),
            "no secure profile offered: {body}"
        );
        assert!(body.contains("a=crypto:"), "no key offered: {body}");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_stack_set_to_srtp_offered_writes_the_same_offer_as_required() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |config| {
            config.srtp = SipralSrtp::Offered as u32;
        });
        let (status, _) = place(handle, account, &managed_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let body = String::from_utf8_lossy(&one(handle)).into_owned();
        assert!(
            body.contains("RTP/SAVP"),
            "no secure profile offered: {body}"
        );
        assert!(body.contains("a=crypto:"), "no key offered: {body}");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// This build's own built-in default (`SrtpPolicy::default()`,
    /// `docs/08-ffi.md`), and what `sipral_stack_config_t::srtp` left at zero
    /// has always meant, before this member existed to say so explicitly.
    #[test]
    fn a_stack_set_to_srtp_not_offered_offers_the_plain_profile() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |config| {
            config.srtp = SipralSrtp::NotOffered as u32;
        });
        let (status, _) = place(handle, account, &managed_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let body = String::from_utf8_lossy(&one(handle)).into_owned();
        assert!(body.contains("RTP/AVP"), "{body}");
        assert!(
            !body.contains("a=crypto"),
            "offered when it should not: {body}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_calls_own_srtp_overrides_the_stacks() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |config| {
            config.srtp = SipralSrtp::NotOffered as u32;
        });
        let mut call_config = managed_config();
        call_config.srtp = SipralSrtp::Required as u32;
        let (status, _) = place(handle, account, &call_config, 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let body = String::from_utf8_lossy(&one(handle)).into_owned();
        assert!(
            body.contains("RTP/SAVP") && body.contains("a=crypto:"),
            "the call's own REQUIRED did not override the stack's NOT_OFFERED: {body}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_calls_srtp_of_zero_takes_the_stacks_value() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |config| {
            config.srtp = SipralSrtp::Required as u32;
        });
        let mut call_config = managed_config();
        call_config.srtp = 0;
        let (status, _) = place(handle, account, &call_config, 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let body = String::from_utf8_lossy(&one(handle)).into_owned();
        assert!(
            body.contains("RTP/SAVP") && body.contains("a=crypto:"),
            "zero on the call did not fall back to the stack's REQUIRED: {body}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn an_out_of_range_call_srtp_is_invalid_argument_and_places_nothing() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |_| {});
        let mut call_config = managed_config();
        call_config.srtp = 4;
        let (status, call) = place(handle, account, &call_config, 1_000);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(call, SIPRAL_HANDLE_NONE);
        assert!(sent(handle).is_empty(), "nothing was built");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// `sipral_call_consult` takes the same `sipral_call_config_t`, and the
    /// member's own documentation promises the same refusal wherever the
    /// struct is read: a value this ABI names nothing for is not quietly
    /// accepted by one entry point and refused by its sibling.
    #[test]
    fn an_out_of_range_srtp_on_a_consultation_is_invalid_argument_and_places_nothing() {
        let mut observed = Observed::default();
        let (handle, first) = connected(&mut observed);
        let _ = sent(handle);
        let mut config = call_config();
        config.srtp = 4;
        let mut second = SIPRAL_HANDLE_NONE;
        let status = unsafe {
            sipral_call_consult(
                handle,
                first,
                ptr::from_ref(&config),
                &raw mut second,
                2_000,
            )
        };
        assert_eq!(
            status,
            SipralStatus::InvalidArgument,
            "{}",
            last_error_text()
        );
        assert_eq!(second, SIPRAL_HANDLE_NONE);
        assert!(sent(handle).is_empty(), "nothing was built");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// Where `SIPRAL_SRTP_OFFERED` and `SIPRAL_SRTP_REQUIRED` part ways, reached
    /// through the C entry points: the stack's policy is also what a call that
    /// comes in is answered under, and a plain offer is answered plainly under
    /// the first and not answered at all under the second (`docs/05-media.md`,
    /// "SRTP through the facade").
    #[test]
    fn a_plain_offer_is_answered_under_srtp_offered_and_not_under_srtp_required() {
        let mut observed = Observed::default();
        let (handle, _) = media_line(&mut observed, |config| {
            config.srtp = SipralSrtp::Offered as u32;
        });
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);
        let (media_address, media_address_len) = as_text(MEDIA);
        let status = unsafe {
            sipral_call_answer_media(handle, call, media_address, media_address_len, 1_100)
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let answered = String::from_utf8_lossy(&one(handle)).into_owned();
        assert!(
            answered.starts_with("SIP/2.0 200")
                && answered.contains("RTP/AVP")
                && !answered.contains("a=crypto"),
            "a plain offer under OFFERED is answered plainly: {answered}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        let mut observed = Observed::default();
        let (handle, _) = media_line(&mut observed, |config| {
            config.srtp = SipralSrtp::Required as u32;
        });
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);
        let status = unsafe {
            sipral_call_answer_media(handle, call, media_address, media_address_len, 1_100)
        };
        assert_ne!(
            status,
            SipralStatus::Ok,
            "a plain offer under REQUIRED was answered"
        );
        assert!(
            sent(handle).is_empty(),
            "nothing is sent for a refused answer"
        );
        assert_eq!(
            state_of(handle, call),
            SipralCallState::Incoming as u32,
            "the call is still the application's to reject"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A caller compiled against a header from before this member existed
    /// declares a `sipral_call_config_t` no longer than
    /// `crate::versioned::min_size::CALL_CONFIG`, so `srtp` is never among the
    /// bytes it sent — even when, as here, live bytes happen to sit past the
    /// declared length. It must read as the zero that means "unspecified" and
    /// take the stack's own setting, exactly as a header that never grew this
    /// member would.
    #[test]
    fn a_call_config_at_its_old_min_size_takes_the_stacks_srtp() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |config| {
            config.srtp = SipralSrtp::Required as u32;
        });
        let mut call_config = managed_config();
        call_config.srtp = SipralSrtp::NotOffered as u32;
        call_config.size = crate::versioned::min_size::CALL_CONFIG;
        let (status, _) = place(handle, account, &call_config, 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let body = String::from_utf8_lossy(&one(handle)).into_owned();
        assert!(
            body.contains("RTP/SAVP") && body.contains("a=crypto:"),
            "a member appended after the old MIN_SIZE must not be read from a struct \
             declared that short, so this call was supposed to take the stack's REQUIRED: {body}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The same, the other way round: the stack's own `srtp` appended past its
    /// old MIN_SIZE must not be read from a `sipral_stack_config_t` declared
    /// that short either, so a call on it gets this build's built-in default
    /// rather than the value still sitting in memory past the declared size.
    #[test]
    fn a_stack_config_at_its_old_min_size_gets_the_default_srtp() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |config| {
            config.srtp = SipralSrtp::Required as u32;
            config.size = crate::versioned::min_size::STACK_CONFIG;
        });
        let (status, _) = place(handle, account, &managed_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let body = String::from_utf8_lossy(&one(handle)).into_owned();
        assert!(
            body.contains("RTP/AVP") && !body.contains("a=crypto"),
            "a member appended after the old MIN_SIZE must not be read from a stack \
             declared that short, so this call was supposed to get the built-in default: {body}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }
}
