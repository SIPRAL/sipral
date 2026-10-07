// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Calls: placed, answered, held, handed on, hung up.
//!
//! Every entry point takes the time from the caller: this library reads no clock.
//!
//! A call is placed and answered with a session description. Offering nothing
//! is legal (§13.2.1) and is not reachable from here: the answer would then
//! travel in the ACK, and the application has no media layer here to write it.
//!
//! DTMF goes out three ways, chosen per send because which one a peer accepts
//! is a fact about the peer: RFC 4733 events in the media, or an INFO carrying
//! `application/dtmf-relay` or `application/dtmf`.

use std::ffi::c_char;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sipral::{CallMedia, CodecCatalog, IcePolicy, SrtpPolicy};
use sipral_core::endpoint::{SendError, TransportId};
use sipral_core::msg::{HeaderName, StatusCode, Uri};
use sipral_ua::{ForkPolicy, HeadersFor, OutgoingCall, OutgoingExtras, UaError};
// only the tests name the bound by number
#[cfg(test)]
use sipral_ua::dtmf::{DEFAULT_DTMF_MS, MAX_DTMF_MS};

use crate::abi::{Number, codes, record};
use crate::error::{Fail, entry, fail};
use crate::event::{SipralCallState, call_state};
use crate::handle::SipralHandle;
use crate::header::{SipralHeader, supplied};
use crate::media::{SipralIce, SipralSrtp, SipralToggle, address, media_failed};
use crate::stack::{StackState, handle_failed, with_stack, with_stack_at};
use crate::status::SipralStatus;
use crate::text::{bytes, required_text, text};
use crate::versioned::{Versioned, read_versioned};

record! {
    /// What a call is placed with.
    ///
    /// Set `size` to `sizeof(sipral_call_config_t)` and zero the rest before filling it in.
    #[derive(Clone, Copy)]
    pub struct SipralCallConfig {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// Who to call, as a URI. UTF-8, not NUL-terminated.
        pub target: *const c_char,
        /// How many bytes of it.
        pub target_len: usize,
        /// The session description to offer, for a call whose audio the application runs.
        /// Exactly one of this and `media_address` is set.
        pub sdp: *const u8,
        /// How many bytes of it.
        pub sdp_len: usize,
        /// Where to send the INVITE, as `host:port`, or null for where the account registers
        /// (the outbound proxy of a registered line).
        pub destination: *const c_char,
        /// How many bytes of it.
        pub destination_len: usize,
        /// Nonzero keeps every branch a proxy forks the INVITE into. Zero keeps the first that
        /// answers and hangs up the rest.
        pub keep_all_forks: u32,
        /// Where this end receives media, as `host:port`, for a call whose audio this stack runs.
        ///
        /// Set, the offer is written from this stack's codec order and the call gets a media
        /// session the `sipral_media_*` entry points reach. Null: set `sdp` instead.
        pub media_address: *const c_char,
        /// How many bytes of it.
        pub media_address_len: usize,
        /// Header fields to put on the INVITE, in order, or null for none.
        ///
        /// Each is checked first: the name a token, the value one line, and not a field the
        /// stack writes itself (`docs/04-ua.md`; `User-Agent` too when
        /// `sipral_stack_config_t::user_agent` is set). A refusal is
        /// `SIPRAL_STATUS_INVALID_ARGUMENT` naming the element, and no call.
        pub headers: *const SipralHeader,
        /// How many elements `headers` has.
        pub headers_len: usize,
        /// What this call does about SRTP, overriding `sipral_stack_config_t::srtp`: a
        /// `SipralSrtp`, or zero for the stack's setting. Any other value is
        /// `SIPRAL_STATUS_INVALID_ARGUMENT`. Read only with `media_address` set.
        pub srtp: Number<SipralSrtp>,
        /// Which transport the INVITE goes out on, read only with `destination`:
        /// [`SIPRAL_TRANSPORT_MAIN`](crate::transport::SIPRAL_TRANSPORT_MAIN) for zero, or a
        /// number [`sipral_stack_transport_bind`](crate::transport::sipral_stack_transport_bind)
        /// has bound. Nonzero with `destination` null is `SIPRAL_STATUS_INVALID_ARGUMENT`.
        pub transport: u32,
        /// What this call offers and in what order, overriding `sipral_stack_config_t::codecs`:
        /// codec names separated by commas, as `sipral_codec_info_t::name` spells them, UTF-8,
        /// not NUL-terminated. Null for the stack's order.
        ///
        /// The rest of the stack's catalogue (frame length, events, multiplexing, SRTP) is kept.
        /// An unknown name, a repeated name or a stray comma is `SIPRAL_STATUS_INVALID_ARGUMENT`.
        /// Applied only with `media_address` set, but the names are checked either way.
        pub codecs: *const c_char,
        /// How many bytes of it.
        pub codecs_len: usize,
        /// What this call does about ICE, overriding `sipral_stack_config_t::ice`: a `SipralIce`,
        /// or zero for the stack's setting. Any other value is `SIPRAL_STATUS_INVALID_ARGUMENT`.
        /// Read only with `media_address` set.
        pub ice: Number<SipralIce>,
        /// Where this call's real-time text arrives (RFC 4103), as `host:port` of a second
        /// socket the application bound, not NUL-terminated; null for no text. Set, the
        /// description carries an `m=text` stream for T.140 with redundancy, carried by
        /// `sipral_media_send_text`, `sipral_media_poll_text` and `sipral_media_receive_text`.
        ///
        /// Read only with `media_address`. Not offered with SRTP, DTLS-SRTP or ICE: the text
        /// stream has no key or candidates of its own, and clear text beside encrypted audio is
        /// worse.
        pub text_address: *const c_char,
        /// How many bytes of it.
        pub text_address_len: usize,
        /// Whether this call asks for RTCP feedback: a `SipralToggle`. On offers RTP/AVPF
        /// (RFC 4585) with Generic NACKs and reduced-size RTCP (RFC 5506). Off by default,
        /// because a far end that knows only RTP/AVP refuses the profile. Read only with
        /// `media_address`. An offer on a feedback profile is answered on it regardless
        /// (RFC 4585 §4.1); the NACKs and reduced-size RTCP are agreed only when this is on.
        pub feedback: Number<SipralToggle>,
        /// Nonzero to say this end is the focus of a conference (RFC 4579
        /// §3.3): `isfocus` goes on the Contact of every message this call
        /// sends from here on.
        pub focus: u32,
        /// Nonzero to follow a 3xx to its `Contact` targets (RFC 3261 §8.1.3.4), most preferred
        /// first, as new INVITEs of the same call. Not followed: a target already tried, a 380, a
        /// 6xx, a forked call, past eight redirections. Zero (default) ends the call with
        /// `SIPRAL_EVENT_KIND_CALL_ENDED` carrying the 3xx status and readable `Contact` addresses.
        /// Added in ABI 1.2.
        pub follow_redirects: u32,
        /// Zero. Pads the struct to a multiple of its alignment, so a member a later version
        /// appends never lands in padding. The library reads nothing from it.
        pub reserved: u32,
    }
}

// Safety: plain data with no invariant between members; all-zero is valid (null pointers
// beside zero lengths).
unsafe impl Versioned for SipralCallConfig {
    const NAME: &'static str = "sipral_call_config";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralCallConfig, focus);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// Why the layer below would not do it.
pub(crate) fn ua_failed(error: &UaError) -> Fail {
    let status = match *error {
        // the handle was live, so the layer below has just let it go
        UaError::NoSuchAccount | UaError::NoSuchCall | UaError::NoSuchPublication => {
            SipralStatus::StaleHandle
        }
        UaError::NotAFocus => SipralStatus::NotAFocus,
        UaError::UnreachableAddress { .. } => SipralStatus::UnreachableAddress,
        // values that would be taken corrected
        UaError::Publish(sipral_ua::PublishError::Unwritable(_)) | UaError::Recording(_) => {
            SipralStatus::InvalidArgument
        }
        // a moment wrong, not a value: `sipral_stack_stir` or `media_clock_unix_seconds`
        // supplies the time
        UaError::WrongState(_)
        | UaError::NoSession
        | UaError::ChangeInProgress
        | UaError::CannotRenegotiate
        | UaError::NoWallClock
        // the next `SIPRAL_EVENT_KIND_LOCATED` ends it
        | UaError::NotLocated
        | UaError::Publish(sipral_ua::PublishError::NothingPublished) => SipralStatus::WrongState,
        // no registrar is the wrong account rather than the wrong moment: waiting will not
        // change it
        UaError::Sdp(_)
        | UaError::NoRegistrar
        | UaError::Header(_)
        | UaError::InvalidDtmf(_)
        | UaError::InvalidKeepalive(_)
        | UaError::NotARedirection(_)
        | UaError::Signing
        | UaError::MessageTooLarge { .. } => SipralStatus::InvalidArgument,
        // an out-of-dialog MESSAGE to this target is already in flight
        UaError::MessagePending => SipralStatus::Busy,
        UaError::Send(SendError::LimitReached { .. }) => SipralStatus::LimitReached,
        // every number was checked when given, so an unknown transport was retired since
        UaError::Send(SendError::UnknownTransport) => SipralStatus::TransportDown,
        _ => SipralStatus::NotSent,
    };
    fail(status, error.to_string())
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

/// Where this end will receive media, for a call this stack describes.
///
/// # Safety
///
/// `config.media_address` must be readable for `config.media_address_len` bytes.
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
    // an sdp of no bytes is no sdp, whatever the pointer
    if config.sdp_len != 0 {
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

/// The member of `sipral_call_config_t` [`sipral_call_ring_media`] needs: where this end
/// will receive media. Members only a call to place needs are refused by name rather than
/// ignored.
///
/// # Safety
///
/// `config.media_address` must be readable for `config.media_address_len` bytes.
unsafe fn ring_media_address(config: &SipralCallConfig) -> Result<SocketAddr, Fail> {
    fn refused(member: &str) -> Fail {
        fail(
            SipralStatus::InvalidArgument,
            format!(
                "{member} is not read here: the call already exists, and only media_address, \
                 srtp, codecs, ice, text_address, feedback and focus apply to one"
            ),
        )
    }
    // a member of no bytes is absent whatever its pointer
    if config.target_len != 0 {
        return Err(refused("target"));
    }
    if config.sdp_len != 0 {
        return Err(refused("sdp"));
    }
    if config.destination_len != 0 {
        return Err(refused("destination"));
    }
    if config.transport != 0 {
        return Err(refused("transport"));
    }
    if config.keep_all_forks != 0 {
        return Err(refused("keep_all_forks"));
    }
    if config.headers_len != 0 {
        return Err(refused("headers"));
    }
    unsafe {
        address(
            config.media_address,
            config.media_address_len,
            "media_address",
        )
    }
}

/// The codec order `config` names, checked, or `None` for the stack's order.
///
/// Read before the stack is locked, so a bad name is refused before anything is built.
///
/// # Safety
///
/// `config.codecs` must be readable for `config.codecs_len` bytes.
unsafe fn codec_order(config: &SipralCallConfig) -> Result<Option<Vec<&str>>, Fail> {
    let Some(list) = (unsafe { text(config.codecs, config.codecs_len, "codecs") })? else {
        return Ok(None);
    };
    let named = crate::media::names_in(list)?;
    // which names have an encoder is a fact about the build, not the stack
    CodecCatalog::with_order(&named).map_err(|error| media_failed(&error))?;
    Ok(Some(named))
}

/// The catalogue one call runs its media with, or `None` for the stack's own untouched.
///
/// The overrides compose here, so one does not drop the policy another applied. Worked
/// out before the socket's relay is taken ([`outside`]): a relay taken and then dropped
/// with a refusal would be lost to the socket.
///
/// `base` is the account's catalogue for a call being placed, or the incoming call's for
/// one being rung. `floor` is the SRTP policy the account named for itself: a call may
/// tighten it and never loosen it, else `SIPRAL_STATUS_SECURITY_POLICY` before anything
/// is built.
fn call_catalog(
    base: &CodecCatalog,
    floor: Option<SrtpPolicy>,
    (srtp, ice, feedback): (Option<SrtpPolicy>, Option<IcePolicy>, bool),
    codecs: Option<&[&str]>,
) -> Result<Option<CodecCatalog>, Fail> {
    if let (Some(policy), Some(floor)) = (srtp, floor)
        && !policy.at_least(floor)
    {
        return Err(fail(
            SipralStatus::SecurityPolicy,
            format!(
                "this call asked for {policy:?}, and its account requires SRTP ({floor:?}): a \
                 call may ask for more than its account and never for less"
            ),
        ));
    }
    if srtp.is_none() && ice.is_none() && !feedback && codecs.is_none() {
        return Ok(None);
    }
    let mut catalog = base.clone();
    if let Some(names) = codecs {
        catalog = catalog
            .with_codecs(names)
            .map_err(|error| media_failed(&error))?;
    }
    if let Some(policy) = srtp {
        catalog = catalog.with_srtp(policy);
    }
    if let Some(policy) = ice {
        catalog = catalog.with_ice(policy);
    }
    if feedback {
        catalog = catalog.with_feedback(true);
    }
    Ok(Some(catalog))
}

/// The SRTP policy `account` named for itself, which no call of it may
/// loosen ([`call_catalog`]).
fn floor_of(state: &StackState, account: Option<sipral_ua::AccountId>) -> Option<SrtpPolicy> {
    account
        .and_then(|account| state.engine.account_srtp(account))
        .and_then(|srtp| srtp.policy)
}

/// The catalogue and settings one call runs its media with, or `None` for the stack's own
/// untouched: [`call_catalog`]'s answer plus what the stack learned about the socket.
///
/// `public` is the socket's STUN-learned address ([`crate::nat`]); a call described by it
/// is never the untouched catalogue. `relay` is its TURN relay, the relayed ICE candidate.
fn call_media(
    state: &StackState,
    base: &CodecCatalog,
    catalog: Option<CodecCatalog>,
    (public, relay): (Option<SocketAddr>, crate::nat::HeldRelay),
    text: Option<SocketAddr>,
) -> Option<CallMedia> {
    if catalog.is_none() && public.is_none() && relay.is_none() && text.is_none() {
        return None;
    }
    let catalog = catalog.unwrap_or_else(|| base.clone());
    let media = dressed(
        CallMedia::new(catalog, state.media_config()),
        (public, relay),
    );
    Some(match text {
        Some(address) => media.text(address),
        None => media,
    })
}

/// What a call's configuration says about its media beyond the codecs:
/// SRTP, ICE and feedback, checked before the stack is locked.
fn media_choices(
    config: &SipralCallConfig,
) -> Result<(Option<SrtpPolicy>, Option<IcePolicy>, bool), Fail> {
    let srtp = crate::media::srtp_policy(config.srtp, "srtp")?;
    let ice = crate::media::ice_policy(config.ice, "ice")?;
    let feedback = crate::media::toggled(config.feedback, "feedback", false)?;
    Ok((srtp, ice, feedback))
}

/// Where the call's real-time text arrives, when its configuration names a socket.
///
/// # Safety
///
/// `config.text_address` must be readable for `config.text_address_len` bytes.
unsafe fn text_address(
    config: &SipralCallConfig,
    managed: bool,
) -> Result<Option<SocketAddr>, Fail> {
    if config.text_address.is_null() && config.text_address_len == 0 {
        return Ok(None);
    }
    if !managed {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "text_address is set without media_address: the text stream goes in a description \
             this stack writes, and a call described by the application carries whatever text \
             stream its own sdp names",
        ));
    }
    Ok(Some(unsafe {
        address(config.text_address, config.text_address_len, "text_address")
    }?))
}

/// Whether the configuration says this end is a conference focus.
fn focus_of(config: &SipralCallConfig) -> Result<bool, Fail> {
    match config.focus {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(fail(
            SipralStatus::InvalidArgument,
            format!("focus is {other}, and it is 0 or 1"),
        )),
    }
}

/// `media`, described by the public address and given the relay the stack
/// learned for its socket, when it learned either.
fn dressed(
    media: CallMedia,
    (public, relay): (Option<SocketAddr>, crate::nat::HeldRelay),
) -> CallMedia {
    let media = match public {
        Some(public) => media.public_address(public),
        None => media,
    };
    #[cfg(feature = "ice")]
    let media = match relay {
        Some(relay) => media.relay(relay),
        None => media,
    };
    #[cfg(not(feature = "ice"))]
    if let Some(never) = relay {
        match never {}
    }
    media
}

/// Where a call on media socket `local` is described as being, and the relay it takes,
/// asked in that order so a socket still awaiting STUN is refused before its relay is taken.
fn outside(
    state: &mut StackState,
    local: SocketAddr,
) -> Result<(Option<SocketAddr>, crate::nat::HeldRelay), Fail> {
    crate::stack::media_port_allowed(state, local)?;
    let public = crate::nat::Nat::public_for(state, local)?;
    let relay = crate::nat::Nat::relay_for(state, local)?;
    Ok((public, relay))
}

/// Where `config` sends the INVITE, other than the account's address, and what it does with
/// forked branches: read the same way by [`sipral_call_place`] and
/// [`sipral_call_accept_transfer`].
///
/// # Safety
///
/// `config.destination` must be readable for `config.destination_len` bytes.
unsafe fn destination_and_forks(
    state: &StackState,
    config: &SipralCallConfig,
) -> Result<(Option<(TransportId, SocketAddr)>, ForkPolicy), Fail> {
    let destination = if let Some(elsewhere) =
        unsafe { text(config.destination, config.destination_len, "destination") }?
    {
        let Ok(address) = elsewhere.parse::<SocketAddr>() else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("destination is {elsewhere:?}, which is not an address and a port"),
            ));
        };
        let transport = crate::transport::named(state, config.transport)?;
        Some((transport, address))
    } else if config.transport == 0 {
        None
    } else {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "transport is read together with destination; a call with no destination override \
             already goes out on its account's own transport",
        ));
    };
    let forks = if config.keep_all_forks == 0 {
        ForkPolicy::KeepFirst
    } else {
        ForkPolicy::KeepAll
    };
    Ok((destination, forks))
}

/// Turn what crossed the boundary into a call to place. `managed`: the description is
/// this stack's to write.
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
    let (destination, forks) = unsafe { destination_and_forks(state, config) }?;
    if let Some((transport, address)) = destination {
        outgoing = outgoing.to_address(transport, address);
    }
    outgoing = outgoing.forks(forks);
    match config.follow_redirects {
        0 => {}
        1 => outgoing = outgoing.follow_redirects(),
        other => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("follow_redirects is {other}, and it is 0 or 1"),
            ));
        }
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
    /// The handle exists before any dialog, so the INVITE can be hung up while in flight.
    /// Branches a proxy forks get their own handles (`SIPRAL_EVENT_KIND_CALL_FORKED`).
    ///
    /// With `media_address` set the stack writes the offer and runs the audio:
    /// `SIPRAL_EVENT_KIND_MEDIA_STARTED` says when, and `sipral_media_*` carry the packets.
    ///
    /// # Safety
    ///
    /// `config` must point at a `sipral_call_config_t` whose `size` member says how long it is,
    /// with every pointer in it readable for the length beside it, and `out_call` at one
    /// `sipral_handle_t`.
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
        // checked before the account is looked up, so nothing is built
        let choices = media_choices(&config)?;
        let codecs = unsafe { codec_order(&config) }?;
        let text = unsafe { text_address(&config, media.is_some()) }?;
        let focus = focus_of(&config)?;
        let handle = with_stack_at(stack, now_ms, |state, now| {
            let id = state.accounts.get(account).map_err(handle_failed)?;
            let mut outgoing = unsafe { outgoing_from(state, &config, media.is_some()) }?;
            if focus {
                outgoing = outgoing.focus();
            }
            let placed = match media {
                Some(local) => {
                    let base = state.engine.account_catalog(id);
                    let floor = floor_of(state, Some(id));
                    let catalog = call_catalog(&base, floor, choices, codecs.as_deref())?;
                    let outside = outside(state, local)?;
                    let placed = match call_media(state, &base, catalog, outside, text) {
                        // the stack's own catalogue, untouched
                        None => {
                            state.engine.place(&mut state.agent, id, outgoing, local, now)
                        }
                        Some(media) => state.engine.place_with(
                            &mut state.agent,
                            id,
                            outgoing,
                            local,
                            media,
                            now,
                        ),
                    };
                    // the refused call's relay goes back onto its socket
                    crate::nat::Nat::take_back(state, now);
                    let placed = placed.map_err(|error| media_failed(&error))?;
                    crate::nat::Nat::spent(state, local, now);
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
    /// A description makes it a 183 rather than a 180, since a 180 with a body is ambiguous.
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
    /// Say a call that came in is ringing, with this stack running the audio before anybody
    /// answers.
    ///
    /// The answer to the INVITE's offer is written from this stack's codec order against
    /// `config.media_address`, and the session opens at once: the far end hears what the
    /// application plays. `SIPRAL_EVENT_KIND_MEDIA_STARTED` follows. `config.srtp` and
    /// `config.codecs` override the stack's for this call, and `sipral_call_answer_media` keeps
    /// what was settled here; it is the only way an incoming call chooses its own SRTP policy.
    ///
    /// `sipral_call_answer_media` then reuses this session and description. What its 200 OK
    /// carries follows RFC 3262 §5 and RFC 6337 §3.1.1, by whether the 183 went out reliably
    /// (`docs/05-media.md`, "Ringing with media").
    ///
    /// Setting `target`, `sdp`, `destination`, `transport`, `keep_all_forks` or `headers` is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` naming it. `SIPRAL_STATUS_WRONG_STATE`, with nothing
    /// sent: an INVITE with no offer (RFC 3261 §13.2.1, RFC 6337 §3.1.2); a second call of this;
    /// a call after a `sipral_call_ring` that sent the application's own description
    /// (RFC 3261 §13.2.1, RFC 6337 §3.1.1).
    ///
    /// # Safety
    ///
    /// `config` must point at a `sipral_call_config_t` whose `size` member says how long it is,
    /// with `media_address` readable for `media_address_len` bytes.
    fn sipral_call_ring_media(
        stack: SipralHandle,
        call: SipralHandle,
        config: *const SipralCallConfig,
        now_ms: u64,
    ) {
        unsafe { described(stack, call, config, now_ms, Reply::Ring) }
    }
}

/// Which response [`described`] sends.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reply {
    Ring,
    Answer,
}

/// Ring or answer a call that came in, with media this stack describes from
/// what `config` says.
///
/// # Safety
///
/// As [`sipral_call_ring_media`].
unsafe fn described(
    stack: SipralHandle,
    call: SipralHandle,
    config: *const SipralCallConfig,
    now_ms: u64,
    reply: Reply,
) -> Result<(), Fail> {
    let config = unsafe { read_versioned(config) }?;
    let local = unsafe { ring_media_address(&config) }?;
    let choices = media_choices(&config)?;
    let codecs = unsafe { codec_order(&config) }?;
    let text = unsafe { text_address(&config, true) }?;
    let focus = focus_of(&config)?;
    with_stack_at(stack, now_ms, |state, now| {
        let id = state.calls.get(call).map_err(handle_failed)?;
        let base = state
            .engine
            .call_catalog(id)
            .cloned()
            .unwrap_or_else(|| state.engine.catalog().clone());
        let floor = floor_of(state, state.agent.call_account(id));
        let catalog = call_catalog(&base, floor, choices, codecs.as_deref())?;
        if focus {
            state
                .agent
                .set_focus(id, true)
                .map_err(|error| ua_failed(&error))?;
        }
        // a call rung with media keeps its 183's description and mapping
        let (public, relay) = if reply == Reply::Answer && state.agent.has_described(id) {
            (None, None)
        } else {
            outside(state, local)?
        };
        let sent = match (
            call_media(state, &base, catalog, (public, relay), text),
            reply,
        ) {
            // the stack's own catalogue, untouched
            (None, Reply::Ring) => state.engine.ring(&mut state.agent, id, local, now),
            (Some(media), Reply::Ring) => {
                state
                    .engine
                    .ring_with(&mut state.agent, id, local, media, now)
            }
            (None, Reply::Answer) => state.engine.answer(&mut state.agent, id, local, now),
            (Some(media), Reply::Answer) => {
                state
                    .engine
                    .answer_with(&mut state.agent, id, local, media, now)
            }
        };
        // a refused response hands the socket's relay back
        crate::nat::Nat::take_back(state, now);
        sent.map_err(|error| media_failed(&error))?;
        crate::nat::Nat::spent(state, local, now);
        state.manage(id);
        Ok(())
    })
}

entry! {
    /// Answer a call that came in with `sdp`, the answer to the INVITE's offer (required).
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
    /// The answer is written from this stack's codec order against `media_address`.
    /// `SIPRAL_EVENT_KIND_MEDIA_STARTED` follows once the stream is open.
    ///
    /// On a call `sipral_call_ring_media` already rang, the 183's description and session
    /// stand and `media_address` must still parse but is unused. The 200 OK repeats that
    /// description if the 183 went unreliably and carries none if reliably (RFC 6337 §3.1.1).
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
            // a call rung with media keeps its 183's description, so its mapping is not asked
            // again; nor for a call the engine never saw, refused below with nothing taken
            let catalog = state.engine.call_catalog(id).cloned();
            let (public, relay) = if state.agent.has_described(id) || catalog.is_none() {
                (None, None)
            } else {
                outside(state, local)?
            };
            let answered = match catalog {
                Some(catalog) if public.is_some() || relay.is_some() => {
                    let media = dressed(
                        CallMedia::new(catalog, state.media_config()),
                        (public, relay),
                    );
                    state
                        .engine
                        .answer_with(&mut state.agent, id, local, media, now)
                }
                _ => state.engine.answer(&mut state.agent, id, local, now),
            };
            crate::nat::Nat::take_back(state, now);
            answered.map_err(|error| media_failed(&error))?;
            crate::nat::Nat::spent(state, local, now);
            state.manage(id);
            Ok(())
        })
    }
}

entry! {
    /// Answer a call that came in with media this stack describes, from `config`:
    /// `sipral_call_answer_media` with the members `sipral_call_ring_media` reads. Any other
    /// member set is `SIPRAL_STATUS_INVALID_ARGUMENT` naming it. On a call already rung with
    /// media, only `focus` changes anything.
    ///
    /// # Safety
    ///
    /// `config` must point at a `sipral_call_config_t` whose `size` member says how long it is,
    /// with every pointer in it readable for the length beside it.
    fn sipral_call_answer_with(
        stack: SipralHandle,
        call: SipralHandle,
        config: *const SipralCallConfig,
        now_ms: u64,
    ) {
        unsafe { described(stack, call, config, now_ms, Reply::Answer) }
    }
}

entry! {
    /// Refuse a call that came in with a response code of your choosing: 486 for a line in use,
    /// 603 for a person who declines. A proxy acts differently on each.
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
    /// Hang up, whatever the call is doing: CANCEL before an answer, BYE after, a refusal for
    /// an unanswered incoming call. A call already ending is left alone.
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
    /// Set the header fields that go on what this call sends at the application's request,
    /// until set again.
    ///
    /// They go on the responses of `sipral_call_ring`, `sipral_call_answer`,
    /// `sipral_call_answer_media` and `sipral_call_reject`, the refusal or BYE of
    /// `sipral_call_hangup`, and the re-INVITE or UPDATE of `sipral_call_hold` and
    /// `sipral_call_resume`. Kept across them. Never on a CANCEL (a proxy replaces it) or on
    /// what the stack sends by itself.
    ///
    /// Replaces the previous set whole; `headers_len` zero clears it. Each field is checked as
    /// on `sipral_call_config_t::headers`; a refusal names the element and keeps the old set.
    ///
    /// # Safety
    ///
    /// `headers` must be null with `headers_len` zero, or readable for `headers_len` elements,
    /// each with a name and a value readable for the lengths beside them.
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
    /// The stack writes the description: the negotiated one with every direction changed. A
    /// hold already in place or on its way sends nothing and succeeds.
    ///
    /// While another session change runs, it succeeds and waits until that is over
    /// (RFC 3261 §14.1); the outcome arrives as `SIPRAL_EVENT_KIND_SESSION_CHANGED` or
    /// `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`. Only the last state asked for waits, so a
    /// resume asked for while a hold is still on its way goes after it. One still waiting
    /// when the call ends is never sent.
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
    /// Take it off hold. Each stream returns to its previous direction (a receive-only one stays
    /// receive-only), and waits for a running change as `sipral_call_hold` does.
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
    /// Offer a call again on another list of codecs (RFC 3264 §8.3.2).
    ///
    /// `codecs` is as `sipral_call_config_t::codecs`. Only the codecs change: address, keys,
    /// fingerprint and ICE credentials are offered as they are, and a held call stays held. A
    /// dynamic payload type keeps its codec; a new codec gets an unused number.
    ///
    /// The list becomes the call's once accepted; `SIPRAL_EVENT_KIND_MEDIA_CHANGED` names the
    /// codec settled on. A refusal arrives as `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`.
    ///
    /// For a call placed or answered with `media_address`. `SIPRAL_STATUS_NOT_SUPPORTED`: a name
    /// with no codec in this build. `SIPRAL_STATUS_INVALID_ARGUMENT`: an empty list, a repeated
    /// name or a stray comma. `SIPRAL_STATUS_WRONG_STATE`: no stack-written description, none
    /// agreed yet, a refused stream, an early call whose far end never listed UPDATE, or
    /// another change on its way. `SIPRAL_STATUS_EXHAUSTED`: no dynamic payload type left.
    ///
    /// # Safety
    ///
    /// `codecs` must be readable for `codecs_len` bytes.
    fn sipral_call_change_codecs(
        stack: SipralHandle,
        call: SipralHandle,
        codecs: *const c_char,
        codecs_len: usize,
        now_ms: u64,
    ) {
        let list = unsafe { required_text(codecs, codecs_len, "codecs") }?;
        let named = crate::media::names_in(list)?;
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            state
                .engine
                .change_codecs(&mut state.agent, id, &named, now)
                .map_err(|error| match error {
                    // the handle was just found, so what the engine lacks is its media
                    sipral::MediaError::NoSuchCall => fail(
                        SipralStatus::WrongState,
                        "the stack writes no description for this call: it was placed or \
                         answered without media_address, so its offers are the application's",
                    ),
                    other => media_failed(&other),
                })
        })
    }
}

entry! {
    /// Restart ICE on a call (RFC 8445 §9): offer it again with new credentials and check every
    /// pair again once the far end answers.
    ///
    /// The last description is offered again with new `ice-ufrag` and `ice-pwd`
    /// (RFC 8839 §4.4.1.1.1), the candidates still held, and the same role. Nothing reaches the
    /// agent until the far end accepts (§4.4). The old pair carries audio meanwhile, and the new
    /// selection arrives as `SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN`. A refusal arrives as
    /// `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED` and leaves ICE as it was.
    ///
    /// The remedy for lost consent (`SIPRAL_MEDIA_FAULT_ICE`) and a local network change. For a
    /// call placed or answered with `media_address`. `SIPRAL_STATUS_WRONG_STATE`: no
    /// stack-written description, no ICE agent, no description yet, or another change on its
    /// way. `SIPRAL_STATUS_NOT_SUPPORTED` from a build without ICE.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_restart_ice(stack: SipralHandle, call: SipralHandle, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            restart_ice(state, id, now)
        })
    }
}

/// [`sipral_call_restart_ice`] on a call the handle table found.
#[cfg(feature = "ice")]
fn restart_ice(
    state: &mut StackState,
    call: sipral::CallHandle,
    now: std::time::Instant,
) -> Result<(), Fail> {
    state
        .engine
        .restart_ice(&mut state.agent, call, now)
        .map_err(|error| match error {
            // the handle was just found, so what the engine lacks is its media
            sipral::MediaError::NoSuchCall => fail(
                SipralStatus::WrongState,
                "the stack writes no description for this call: it was placed or answered \
                 without media_address, so its offers are the application's",
            ),
            sipral::MediaError::NoIce => fail(
                SipralStatus::WrongState,
                "this call runs no ICE agent to restart: its policy offered none, or the far end \
                 answered without it",
            ),
            other => media_failed(&other),
        })
}

/// Without the agent there is nothing to restart.
#[cfg(not(feature = "ice"))]
fn restart_ice(
    _state: &mut crate::stack::StackState,
    _call: sipral::CallHandle,
    _now: std::time::Instant,
) -> Result<(), Fail> {
    Err(fail(
        SipralStatus::NotSupported,
        "this build has no ICE agent; SIPRAL_FEATURE_ICE says so",
    ))
}

entry! {
    /// Describe a call's media at a socket the application bound on a new network and offer it
    /// to the far end (RFC 3264 §8.3.1), as `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED` asks.
    ///
    /// `media_address` is the new socket, `host:port`; `public_address` is where it appears
    /// from outside, or null with length zero. The re-INVITE moves only `c=` and the `m=` port,
    /// and carries the account's current `Contact`, so `sipral_account_rebind` goes first. The
    /// new socket is the call's whatever the answer: `SIPRAL_EVENT_KIND_SESSION_CHANGED` and
    /// `SIPRAL_EVENT_KIND_MEDIA_CHANGED`, or `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`.
    ///
    /// For a call placed or answered with `media_address`. `SIPRAL_STATUS_WRONG_STATE`: no
    /// stack-written description, a session running ICE (moved by a restart instead), no
    /// description yet, or another change on its way.
    ///
    /// # Safety
    ///
    /// `media_address` must be readable for `media_address_len` bytes, and `public_address` for
    /// `public_address_len` bytes or null with a length of zero.
    fn sipral_call_media_readdress(
        stack: SipralHandle,
        call: SipralHandle,
        media_address: *const c_char,
        media_address_len: usize,
        public_address: *const c_char,
        public_address_len: usize,
        now_ms: u64,
    ) {
        let local = unsafe { address(media_address, media_address_len, "media_address") }?;
        let public = match unsafe { text(public_address, public_address_len, "public_address") }?
        {
            None => None,
            Some(written) => Some(written.parse::<SocketAddr>().map_err(|_| {
                fail(
                    SipralStatus::InvalidArgument,
                    format!("public_address is {written:?}, which is not an address and a port"),
                )
            })?),
        };
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            crate::stack::media_port_allowed(state, local)?;
            state
                .engine
                .readdress(&mut state.agent, id, local, public, now)
                .map_err(|error| match error {
                    // the handle was just found, so what the engine lacks is its media
                    sipral::MediaError::NoSuchCall => fail(
                        SipralStatus::WrongState,
                        "the stack writes no description for this call: it was placed or \
                         answered without media_address, so its offers are the application's",
                    ),
                    #[cfg(feature = "ice")]
                    sipral::MediaError::MovesWithIce => fail(
                        SipralStatus::WrongState,
                        "this call runs ICE, whose candidates name the old socket: \
                         sipral_call_restart_ice moves it, not a new address",
                    ),
                    other => media_failed(&other),
                })
        })
    }
}

entry! {
    /// Join two active calls into a local three-way conference: each far end hears the other
    /// and this end's microphone, mixed. [`sipral_media_mix`](crate::media::sipral_media_mix)
    /// drives it one frame at a time; this only records the pairing.
    ///
    /// No SIP conference: neither far end is told. Both calls need running media and the same
    /// sample rate and frame length, since nothing resamples.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for `call_a == call_b`; `SIPRAL_STATUS_WRONG_STATE` for a
    /// call with no running session, one already joined, or mismatched rate or frame length.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_join(stack: SipralHandle, call_a: SipralHandle, call_b: SipralHandle) {
        with_stack(stack, |state| {
            let a = state.calls.get(call_a).map_err(handle_failed)?;
            let b = state.calls.get(call_b).map_err(handle_failed)?;
            if crate::local_conference::in_a_conference(state, a)
                || crate::local_conference::in_a_conference(state, b)
            {
                return Err(media_failed(&sipral::MediaError::AlreadyJoined));
            }
            state.engine.join(a, b).map_err(|error| media_failed(&error))
        })
    }
}

entry! {
    /// Take `call` back out of its pair. Neither session is touched; each call carries its own
    /// audio again. `SIPRAL_STATUS_WRONG_STATE` for a call not joined.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_leave(stack: SipralHandle, call: SipralHandle) {
        with_stack(stack, |state| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            state.engine.leave(id).map_err(|error| media_failed(&error))?;
            Ok(())
        })
    }
}

entry! {
    /// Accept a change the far end offered (`SIPRAL_EVENT_KIND_SESSION_OFFERED`).
    ///
    /// `sdp`, the answer, is required (RFC 3264 §5): null or empty is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` and the request still waits. An unanswered re-INVITE
    /// ends the call, so this or [`sipral_call_reject_session`] must follow the event. An offer
    /// in a PRACK (RFC 3262 §5) is answered the same way, in the PRACK's 2xx.
    ///
    /// Only for a call the application describes; a stack-described call answers its own
    /// re-offers, so this is `SIPRAL_STATUS_WRONG_STATE` there.
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
            let answer = unsafe { bytes(sdp, sdp_len, "sdp") }?.ok_or_else(|| {
                fail(
                    SipralStatus::InvalidArgument,
                    "sdp is required: the far end's change carried an offer, and an offer is \
                     answered with a session description (RFC 3264 §5)",
                )
            })?;
            state
                .agent
                .accept_reoffer(id, answer, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Refuse one instead; the session stands as it was (§14.1). 488 Not Acceptable Here says
    /// the description was the problem. Only for a call the application describes.
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
    /// Which way a digit goes to the far end: [`sipral_call_send_dtmf`]'s `via`. Chosen per
    /// send, since it is a fact about the peer, and a peer ignores an unsupported one silently.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDtmf: u32 {
        /// In the media, as an RFC 4733 telephone event: the one to reach for, carried end to
        /// end and surviving transcoding. One, not zero: zero is an unfilled field, refused.
        Rtp = 1,
        /// An INFO per digit carrying `application/dtmf-relay`, which states the
        /// signal and how long it was held.
        InfoRelay = 2,
        /// An INFO per digit carrying `application/dtmf`, whose whole body is the
        /// character. Some switches take only this one.
        InfoPlain = 3,
        /// In the media, as the key's two tones written into the audio in place of the microphone,
        /// for a far end that listens only to the audio. `SIPRAL_DTMF_RTP` falls back to this on a
        /// call with no telephone event.
        InBand = 4,
    }
}

entry! {
    /// Send DTMF on a call that is up, in the form the far end takes.
    ///
    /// `digits` are `0`-`9`, `*`, `#` and `A`-`D`, the sixteen events of
    /// RFC 4733 §3.2, in the order they were pressed. The whole string is checked first: one
    /// bad character sends nothing. `duration_ms` is each tone's length, or zero for 100 ms.
    ///
    /// `via` is a [`SipralDtmf`]. `SIPRAL_DTMF_RTP` puts the digits in the media, replacing the
    /// audio while they last, queued. The INFO forms send one request per digit, each after the
    /// previous one's final answer, since UDP may reorder overlapping transactions. A refusal,
    /// timeout or transport failure ends the sequence: `SIPRAL_EVENT_KIND_DTMF_SENT` names that
    /// digit, and the rest are discarded unreported. Digits handed over meanwhile queue behind.
    /// A call holds at most sixty-four INFO digits, the one in flight included; a string past
    /// that is refused whole with `SIPRAL_STATUS_INVALID_ARGUMENT`.
    ///
    /// `SIPRAL_DTMF_RTP` without a negotiated telephone event writes the tones into the audio,
    /// as `SIPRAL_DTMF_IN_BAND` always does. The media forms are `SIPRAL_STATUS_WRONG_STATE`
    /// before there is media, the INFO forms before there is a dialog.
    ///
    /// # Safety
    ///
    /// `digits` must be readable for `digits_len` bytes.
    fn sipral_call_send_dtmf(
        stack: SipralHandle,
        call: SipralHandle,
        digits: *const c_char,
        digits_len: usize,
        via: Number<SipralDtmf>,
        duration_ms: u32,
        now_ms: u64,
    ) {
        let form = dtmf_form(via)?;
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let pressed = unsafe { required_text(digits, digits_len, "digits") }?;
            keypad(pressed)?;
            let held = tone_length(duration_ms)?;
            if matches!(form, SipralDtmf::Rtp | SipralDtmf::InBand) {
                let length = Duration::from_millis(u64::from(held));
                let in_band = form == SipralDtmf::InBand;
                return crate::media::dial_in_media(state, id, pressed, length, in_band);
            }
            let info_form = match form {
                SipralDtmf::InfoPlain => sipral_ua::DtmfInfoForm::Plain,
                _ => sipral_ua::DtmfInfoForm::Relay,
            };
            state
                .agent
                .send_dtmf_info(id, pressed, info_form, held, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

/// The form a number names, or a refusal saying what the three are.
fn dtmf_form(via: u32) -> Result<SipralDtmf, Fail> {
    match via {
        1 => Ok(SipralDtmf::Rtp),
        2 => Ok(SipralDtmf::InfoRelay),
        3 => Ok(SipralDtmf::InfoPlain),
        4 => Ok(SipralDtmf::InBand),
        _ => Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "{via} is not a way to send a digit; they are 1 for the media, 2 for INFO with \
                 application/dtmf-relay, 3 for INFO with application/dtmf and 4 for the tones in \
                 the audio"
            ),
        )),
    }
}

/// Refuse a session change on a call whose descriptions are this stack's: the engine has
/// already answered the re-offer.
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

/// The digits, upper-cased, or which one was not a key. Delegates to
/// [`sipral_ua::dtmf::digit`], the validation incoming INFO shares.
fn keypad(pressed: &str) -> Result<Vec<u8>, Fail> {
    let mut keys = Vec::with_capacity(pressed.len());
    for (index, key) in pressed.chars().enumerate() {
        let refused = || {
            fail(
                SipralStatus::InvalidArgument,
                format!("digit {index} is not one of the sixteen a keypad has"),
            )
        };
        let byte = u8::try_from(key).map_err(|_| refused())?;
        let byte = sipral_ua::dtmf::digit(byte).map_err(|_| refused())?;
        keys.push(byte);
    }
    if keys.is_empty() {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "there are no digits to send",
        ));
    }
    Ok(keys)
}

/// Delegates to [`sipral_ua::dtmf::duration_ms`], the bound every form shares. Run before
/// the form is looked at, so all three refuse a length with the same status and words.
fn tone_length(duration_ms: u32) -> Result<u32, Fail> {
    sipral_ua::dtmf::duration_ms(duration_ms)
        .map_err(|error| fail(SipralStatus::InvalidArgument, error.to_string()))
}

entry! {
    /// Ask the far end to call somebody else, and hang up when it has (RFC 3515).
    ///
    /// A blind transfer. This end stays in the call until the transfer succeeds, so a failed
    /// transfer does not lose the call. Progress arrives as `SIPRAL_EVENT_KIND_TRANSFER_PROGRESS`,
    /// then `SIPRAL_EVENT_KIND_TRANSFER_DONE`.
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
    /// Call the transfer target, and write the new call's handle to `out_consultation`.
    ///
    /// The consultation leg of an attended transfer; [`sipral_call_transfer_to`] follows.
    /// Holding `call` first is the application's choice. `media_address` is
    /// `SIPRAL_STATUS_NOT_SUPPORTED` here: place the consultation with `sdp` and run its audio.
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
        // nothing to apply them to, but the same refusals as `sipral_call_place`
        media_choices(&config)?;
        unsafe { codec_order(&config) }?;
        unsafe { text_address(&config, false) }?;
        let focus = focus_of(&config)?;
        let handle = with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let mut outgoing = unsafe { outgoing_from(state, &config, false) }?;
            if focus {
                outgoing = outgoing.focus();
            }
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
    /// Hand `call` to the far end of `other` (RFC 3891): the attended half of a transfer, where
    /// `other` is normally the consultation call. Any call that is up may be named.
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
    /// Take a transfer that was asked for, place the call it names as [`sipral_call_place`]
    /// does, and write its handle to `out_placed`.
    ///
    /// `config.target` set is `SIPRAL_STATUS_INVALID_ARGUMENT`: the REFER names the target.
    /// Every other member means what it means on `sipral_call_place`. `Replaces` or
    /// `Referred-By` among `headers` is `SIPRAL_STATUS_INVALID_ARGUMENT` with the transfer still
    /// waiting: the INVITE takes both from the REFER. Neither `sdp` nor `media_address` is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT`, as on `sipral_call_place`.
    ///
    /// `call` may be a referral's handle (`SIPRAL_EVENT_KIND_REFERRAL`, a REFER outside any
    /// dialog), placed from the account the event names. Its handle is stale once the REFER is
    /// answered; one refused before anything was sent is still there to take.
    ///
    /// A call that cannot be sent after the 202 ends the subscription with RFC 3515 §2.4.5's
    /// 503, and this answers `SIPRAL_STATUS_NOT_SENT`.
    ///
    /// # Safety
    ///
    /// `config` must point at a `sipral_call_config_t` whose `size` member says how long it is,
    /// with every pointer in it readable for the length beside it, and `out_placed` at one
    /// `sipral_handle_t`.
    fn sipral_call_accept_transfer(
        stack: SipralHandle,
        call: SipralHandle,
        config: *const SipralCallConfig,
        out_placed: *mut SipralHandle,
        now_ms: u64,
    ) {
        if out_placed.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_placed is null"));
        }
        let config = unsafe { read_versioned(config) }?;
        // absent when its length is zero, whatever the pointer
        if config.target_len != 0 {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "target is not read here: sipral_call_accept_transfer places the call the far \
                 end already named when it asked for the transfer, and a target of the caller's \
                 own would be a second one contradicting it",
            ));
        }
        let media = unsafe { managed_media(&config) }?;
        let choices = media_choices(&config)?;
        let codecs = unsafe { codec_order(&config) }?;
        let text = unsafe { text_address(&config, media.is_some()) }?;
        if focus_of(&config)? {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "focus is not read here: a transferred call is placed to the target the far end \
                 named, and a focus says so on a call it places itself",
            ));
        }
        let handle = with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            // a referral answered is spent and its handle retired below; one refused before
            // anything was sent keeps it
            let referral = state.agent.referral_waiting(id);
            let mut accept = || -> Result<SipralHandle, Fail> {
            let (destination, forks) = unsafe { destination_and_forks(state, &config) }?;
            let asked = unsafe {
                supplied(
                    config.headers,
                    config.headers_len,
                    HeadersFor::Call,
                    state.user_agent.is_some(),
                )
            }?;
            // taken after the configuration is read and before the headers borrow the stack's
            // User-Agent, so a refused transfer keeps both the transfer and the relay
            let base = state.agent.call_account(id).map_or_else(
                || state.engine.catalog().clone(),
                |account| state.engine.account_catalog(account),
            );
            let outside = match media {
                Some(local) => {
                    let floor = floor_of(state, state.agent.call_account(id));
                    let catalog = call_catalog(&base, floor, choices, codecs.as_deref())?;
                    Some((catalog, outside(state, local)?))
                }
                None => None,
            };
            let mut headers = Vec::new();
            if let Some(ref named) = state.user_agent {
                headers.push((HeaderName::UserAgent, &**named));
            }
            headers.extend(asked);
            let extra = OutgoingExtras {
                destination,
                forks,
                headers: &headers,
            };
            let placed = if let (Some(local), Some((catalog, outside))) = (media, outside) {
                let placed = match call_media(state, &base, catalog, outside, text) {
                    // the stack's own catalogue, untouched
                    None => state
                        .engine
                        .accept_transfer(&mut state.agent, id, local, extra, now),
                    Some(media) => state.engine.accept_transfer_with(
                        &mut state.agent,
                        id,
                        local,
                        extra,
                        media,
                        now,
                    ),
                };
                // a refused transfer hands the socket's relay back
                crate::nat::Nat::take_back(state, now);
                let placed = placed.map_err(|error| media_failed(&error))?;
                crate::nat::Nat::spent(state, local, now);
                state.manage(placed);
                placed
            } else {
                let Some(offer) = (unsafe { description(config.sdp, config.sdp_len) })? else {
                    return Err(fail(
                        SipralStatus::InvalidArgument,
                        "a call placed from here carries an offer, because the answer to one \
                         that does not has to be written into the ACK. Set sdp for a session the \
                         application describes, or media_address for one this stack describes",
                    ));
                };
                state
                    .agent
                    .accept_transfer(id, Some(offer), extra, now)
                    .map_err(|error| ua_failed(&error))?
            };
            if let Some(identity) = state.agent.call_identity(placed) {
                state.record_identity(placed, identity);
            }
            state
                .calls
                .name_of(placed)
                .map_err(|status| fail(status, "no room for another call on this stack"))
            };
            let placed = accept();
            if referral && !state.agent.referral_waiting(id) {
                state.calls.forget(id);
            }
            placed
        })?;
        unsafe { out_placed.write(handle) };
        Ok(())
    }
}

entry! {
    /// Take a transfer asked for inside `call` with a call the application placed itself,
    /// `placed`, and report that call's progress to the far end as if the REFER had placed it
    /// (ABI 1.2).
    ///
    /// For an application that reaches the target its own way, such as a bridge. The REFER is
    /// answered 202 (RFC 3515 §2.4.2); `placed` then reports each provisional status in a
    /// NOTIFY (§2.4.5), and its final status ends the subscription (§2.4.7). A `placed` already
    /// up is reported with a 200 at once. Ending `call` stays the application's.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when nothing waits on `call` (a referral's handle included),
    /// or `placed` is `call`, is over, or already reports to another REFER. A refusal leaves the
    /// REFER waiting.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_accept_transfer_placed(
        stack: SipralHandle,
        call: SipralHandle,
        placed: SipralHandle,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let placed = state.calls.get(placed).map_err(handle_failed)?;
            if state.agent.referral_waiting(id) {
                return Err(fail(
                    SipralStatus::WrongState,
                    "a referral asks this end to place the call it names: take it with \
                     sipral_call_accept_transfer",
                ));
            }
            state
                .agent
                .accept_transfer_placed(id, placed, now)
                .map_err(|error| ua_failed(&error))
        })
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
            // RFC 3515 §2.4.2 allows "any appropriate 4xx-6xx class response", and a 3xx
            // redirects; under 300 would say the REFER was taken
            if status.get() < 300 {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    format!("{code} does not refuse anything: a refusal is 300 to 699"),
                ));
            }
            let referral = state.agent.referral_waiting(id);
            let refused = state
                .agent
                .reject_transfer(id, status, now)
                .map_err(|error| ua_failed(&error));
            // a referral refused is spent, and so is its handle
            if referral && !state.agent.referral_waiting(id) {
                state.calls.forget(id);
            }
            refused
        })
    }
}

entry! {
    /// Where a call is, as a `SipralCallState`.
    ///
    /// A call that is over answers `SIPRAL_CALL_STATE_TERMINATED` until the poll delivering
    /// `SIPRAL_EVENT_KIND_CALL_ENDED` retires its handle, then `SIPRAL_STATUS_STALE_HANDLE`. A
    /// referral's handle is `SIPRAL_STATUS_WRONG_STATE`: there is no call yet.
    ///
    /// # Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    fn sipral_call_state(stack: SipralHandle, call: SipralHandle, out_state: *mut Number<SipralCallState>) {
        if out_state.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_state is null"));
        }
        let state = with_stack(stack, |state| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            if state.agent.referral_waiting(id) {
                return Err(fail(
                    SipralStatus::WrongState,
                    "the handle names a referral, which is a request to place a call rather than \
                     a call: take it with sipral_call_accept_transfer or refuse it with \
                     sipral_call_reject_transfer",
                ));
            }
            let where_it_is = state.agent.call_state(id).map_or(
                // the layer below let the call go: that is what over looks like here
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
    /// Which way a call is held: `out_here` when this end asked the far end to stop sending,
    /// `out_there` when the far end asked. Either may be null.
    ///
    /// # Safety
    ///
    /// `out_here` and `out_there` must each be null or point at one `uint32_t`.
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
        SipralCallConfig, SipralDtmf, dtmf_form, keypad, sipral_call_accept_session,
        sipral_call_accept_transfer, sipral_call_answer, sipral_call_answer_media,
        sipral_call_change_codecs, sipral_call_consult, sipral_call_hangup, sipral_call_hold,
        sipral_call_hold_state, sipral_call_media_readdress, sipral_call_place, sipral_call_reject,
        sipral_call_reject_session, sipral_call_reject_transfer, sipral_call_resume,
        sipral_call_ring, sipral_call_ring_media, sipral_call_send_dtmf, sipral_call_state,
        sipral_call_transfer, sipral_call_transfer_to, tone_length,
    };
    use crate::account::{
        SipralAccountConfig, sipral_account_add, sipral_account_register, sipral_account_remove,
    };
    use crate::error::last_error_text;
    use crate::event::{SipralCallState, SipralDigitSource, SipralEventKind};
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle, StackTags, split};
    use crate::media::{SipralSrtp, sipral_call_media, sipral_media_release};
    use crate::stack::tests::{Observed, config, create, poll, record, stack, stack_on};
    use crate::stack::{sipral_stack_destroy, with_stack};
    use crate::status::SipralStatus;
    use sipral_core::endpoint::{Input, TransportId};
    use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, parse};
    use std::ffi::c_char;
    use std::net::SocketAddr;
    use std::ptr;

    const AOR: &str = "sip:alice@example.com";
    const REGISTRAR: &str = "sip:example.com";
    const CONTACT: &str = "sip:alice@192.0.2.10:5060";
    const PEER: &str = "203.0.113.5:5060";
    const TARGET: &str = "sip:bob@example.com";

    /// Where a managed call receives its media (the application's socket).
    pub(crate) const MEDIA: &str = "192.0.2.10:40000";

    /// Where the far end receives its own, as the answers below say.
    pub(crate) const PEER_MEDIA: &str = "203.0.113.5:41000";

    /// What a media test offers, so the answer has one format to agree with.
    const ONE_CODEC: &str = "PCMU";

    const OFFER: &[u8] = b"v=0\r\n\
o=alice 1 1 IN IP4 192.0.2.10\r\n\
s=-\r\n\
c=IN IP4 192.0.2.10\r\n\
t=0 0\r\n\
m=audio 40000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=sendrecv\r\n";

    pub(crate) const ANSWER: &[u8] = b"v=0\r\n\
o=bob 1 1 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 41000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=sendrecv\r\n";

    /// A re-offer that changes the format list: a change keeping the same media is answered by
    /// the user agent itself and never reaches the layer above.
    pub(crate) const REOFFERED: &[u8] = b"v=0\r\n\
o=bob 1 2 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 41000 RTP/AVP 0 8\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=sendrecv\r\n";

    /// An answer naming a format nobody offered.
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

    pub(crate) fn as_text(value: &str) -> (*const c_char, usize) {
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
            transport: 0,
            push_provider: ptr::null(),
            push_provider_len: 0,
            push_prid: ptr::null(),
            push_prid_len: 0,
            push_param: ptr::null(),
            push_param_len: 0,
            push_wakes_itself: 0,
            quality_report_uri: ptr::null(),
            quality_report_uri_len: 0,
            session_timer: 0,
            session_interval_seconds: 0,
            privacy: 0,
            trusted_peers: ptr::null(),
            trusted_peers_len: 0,
            srtp: 0,
            srtp_suites: ptr::null(),
            srtp_suites_len: 0,
            stir_verification: 0,
            stir_key: ptr::null(),
            stir_key_len: 0,
            stir_certificate_url: ptr::null(),
            stir_certificate_url_len: 0,
            stir_orig: ptr::null(),
            stir_orig_len: 0,
            stir_origid: ptr::null(),
            stir_origid_len: 0,
            stir_attestation: 0,
            recording_in_clear: 0,
            keepalive_ms: 0,
            server_uri: ptr::null(),
            server_uri_len: 0,
            tls_pin_sha256: ptr::null(),
            tls_pin_sha256_len: 0,
            server_naptr: 0,
            reserved: 0,
            stream_protocol: 0,
            reserved_35: 0,
            realms: std::ptr::null(),
            realms_len: 0,
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
            transport: 0,
            codecs: ptr::null(),
            codecs_len: 0,
            ice: 0,
            text_address: ptr::null(),
            text_address_len: 0,
            feedback: 0,
            focus: 0,
            follow_redirects: 0,
            reserved: 0,
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

    /// What `sipral_call_accept_transfer` reads: `call_config` without `target`.
    pub(crate) fn transfer_config() -> SipralCallConfig {
        SipralCallConfig {
            target: ptr::null(),
            target_len: 0,
            ..call_config()
        }
    }

    /// The same, for a transfer whose session this stack describes.
    pub(crate) fn managed_transfer_config() -> SipralCallConfig {
        SipralCallConfig {
            target: ptr::null(),
            target_len: 0,
            ..managed_config()
        }
    }

    /// What `sipral_call_ring_media` reads: `media_address` and, when asked, `srtp`.
    pub(crate) fn ring_media_config() -> SipralCallConfig {
        let (media_address, media_address_len) = as_text(MEDIA);
        SipralCallConfig {
            size: size_of::<SipralCallConfig>(),
            target: ptr::null(),
            target_len: 0,
            sdp: ptr::null(),
            sdp_len: 0,
            destination: ptr::null(),
            destination_len: 0,
            keep_all_forks: 0,
            media_address,
            media_address_len,
            headers: ptr::null(),
            headers_len: 0,
            srtp: 0,
            transport: 0,
            codecs: ptr::null(),
            codecs_len: 0,
            ice: 0,
            text_address: ptr::null(),
            text_address_len: 0,
            feedback: 0,
            focus: 0,
            follow_redirects: 0,
            reserved: 0,
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

    /// The same, with a display name, which a call it places writes in `From`.
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
    pub(crate) fn line(observed: &mut Observed) -> (SipralHandle, SipralHandle) {
        let handle = stack(observed);
        (handle, account_on(handle))
    }

    /// The same, offering one codec, so a test answers in one line.
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

    pub(crate) fn place(
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

    pub(crate) fn state_of(stack: SipralHandle, call: SipralHandle) -> u32 {
        let mut state = u32::MAX;
        let status = unsafe { sipral_call_state(stack, call, &raw mut state) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        state
    }

    /// What the stack wanted written, drained as `sipral_stack_poll_transmit` drains it:
    /// what is held back for want of a buffer first.
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

    pub(crate) fn field(bytes: &[u8], name: HeaderName<'_>) -> Vec<u8> {
        let mut scratch = ParseScratch::new();
        let message = parse(bytes, &mut scratch, ParseMode::Lenient).expect("a message");
        message.header(name).unwrap_or_default().to_vec()
    }

    /// The body of a message, whatever it holds — empty when there is none.
    pub(crate) fn body(bytes: &[u8]) -> Vec<u8> {
        let mut scratch = ParseScratch::new();
        let message = parse(bytes, &mut scratch, ParseMode::Lenient).expect("a message");
        message.body().to_vec()
    }

    pub(crate) fn start_line(bytes: &[u8]) -> String {
        String::from_utf8_lossy(
            bytes
                .split(|byte| *byte == b'\r')
                .next()
                .unwrap_or_default(),
        )
        .into_owned()
    }

    /// The far end's 200 to an INVITE, with the answer. The tag is added only when `first`:
    /// a re-INVITE's `To` already carries it.
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

    /// The far end's final answer to a non-INVITE request (BYE, REFER, INFO) this end sent
    /// in the dialog `request` opened or travelled in.
    pub(crate) fn answered_with(request: &[u8], status: u32, reason: &str) -> Vec<u8> {
        let mut out = format!("SIP/2.0 {status} {reason}\r\n").into_bytes();
        for (name, value) in [
            ("Via", field(request, HeaderName::Via)),
            ("From", field(request, HeaderName::From)),
            ("To", field(request, HeaderName::To)),
            ("Call-ID", field(request, HeaderName::CallId)),
            ("CSeq", field(request, HeaderName::CSeq)),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        out
    }

    /// An INFO from the far end in a dialog this end placed, with a body of the caller's
    /// content type. `branch` and `cseq` are the caller's, so a second INFO is not read as a
    /// retransmission.
    fn incoming_info(
        invite: &[u8],
        branch: &str,
        cseq: u32,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Vec<u8> {
        let mut out = b"INFO sip:alice@203.0.113.5 SIP/2.0\r\n".to_vec();
        out.extend_from_slice(
            format!("Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-{branch}\r\n").as_bytes(),
        );
        out.extend_from_slice(b"Max-Forwards: 70\r\n");
        for (name, value) in [
            ("From", {
                let mut to = field(invite, HeaderName::To);
                to.extend_from_slice(b";tag=farend");
                to
            }),
            ("To", field(invite, HeaderName::From)),
            ("Call-ID", field(invite, HeaderName::CallId)),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("CSeq: {cseq} INFO\r\n").as_bytes());
        out.extend_from_slice(b"Contact: <sip:bob@203.0.113.5:5060>\r\n");
        if let Some(content_type) = content_type {
            out.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        out.extend_from_slice(body);
        out
    }

    /// A 180 the far end sends back for the INVITE this end placed.
    pub(crate) fn ringing(invite: &[u8]) -> Vec<u8> {
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
            let transport = TransportId(0);
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

    /// A call this end placed and the far end answered, with the application's description.
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
        // take the ACK, or the next test sees it as its one message
        let _ = sent(handle);
        (handle, call)
    }

    /// The same, with audio run by this stack: what every media test starts from.
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

    /// The same, offering the codecs named and answered with the line given.
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

    /// The far end's answer to a second call on the line: same codec, its own port.
    pub(crate) const SECOND_ANSWER: &[u8] = b"v=0\r\n\
o=bob 1 1 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 42000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=sendrecv\r\n";

    /// Where the far end of [`SECOND_ANSWER`] receives its own media.
    pub(crate) const SECOND_PEER_MEDIA: &str = "203.0.113.5:42000";

    /// A second call, placed and answered on `media_call`'s stack and account, for join
    /// tests. Not `up`, whose fixed timestamps are already behind this stack's clock.
    pub(crate) fn second_media_call(
        observed: &Observed,
        handle: SipralHandle,
        account: SipralHandle,
    ) -> SipralHandle {
        let (status, call) = place(handle, account, &managed_config(), 2_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        deliver(handle, &accepted(&invite, SECOND_ANSWER, true), 2_100);
        poll(handle, 2_100);
        assert_eq!(
            state_of(handle, call),
            SipralCallState::Confirmed as u32,
            "the second call did not come up"
        );
        assert!(
            observed.kinds().contains(&SipralEventKind::MediaStarted),
            "the second call came up without audio: {:?}",
            observed.kinds()
        );
        let _ = sent(handle);
        call
    }

    /// Two calls on one stack, both with media running, for join tests.
    pub(crate) fn media_call_pair(
        observed: &mut Observed,
    ) -> (SipralHandle, SipralHandle, SipralHandle) {
        let (handle, account) = media_line(observed, |_| {});
        let (_, call_a) = up(observed, handle, account, ANSWER);
        let call_b = second_media_call(observed, handle, account);
        (handle, call_a, call_b)
    }

    /// One call placed on a ready line, answered with `answer`, up with audio.
    pub(crate) fn up(
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

    /// A managed call answered with a format nobody offered: negotiation fails, call stands.
    pub(crate) fn media_call_refused(observed: &mut Observed) -> (SipralHandle, SipralHandle) {
        let (handle, account) = media_line(observed, |_| {});
        let (status, call) = place(handle, account, &managed_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        deliver(handle, &accepted(&invite, ALAW_ANSWER, true), 1_100);
        poll(handle, 1_100);
        (handle, call)
    }

    /// The far end's ACK for a 200, which confirms a call that came in.
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

    /// A re-INVITE from the far end in the dialog the INVITE opened: our `From` is its `To`,
    /// and its answer tag is its own.
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
    pub(crate) fn invitation() -> Vec<u8> {
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

    /// The same, with a `From` display name escaping a quote, and a `To` URI carrying a
    /// parameter of the address.
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

    /// The same message with an extra header field after the start line.
    pub(crate) fn insert_header(message: &[u8], extra: &str) -> Vec<u8> {
        let head = message
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(message.len(), |at| at + 1);
        let mut out = message[..head].to_vec();
        out.extend_from_slice(extra.as_bytes());
        out.extend_from_slice(&message[head..]);
        out
    }

    /// [`invitation`] with no body at all: the far end leaves the offer to
    /// this end (RFC 3261 §13.2.1).
    fn invitation_without_offer() -> Vec<u8> {
        b"INVITE sip:alice@192.0.2.10:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-a-call-in\r\n\
Max-Forwards: 70\r\n\
From: <sip:bob@example.com>;tag=farend\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: a-call-in@203.0.113.5\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@203.0.113.5:5060>\r\n\
Content-Length: 0\r\n\r\n"
            .to_vec()
    }

    /// [`invitation`], asking for reliable provisional responses (RFC 3262
    /// §3): `Require: 100rel` when `require`, `Supported: 100rel` otherwise.
    fn invitation_with_100rel(require: bool) -> Vec<u8> {
        let list = if require { "Require" } else { "Supported" };
        insert_header(&invitation(), &format!("{list}: 100rel\r\n"))
    }

    /// The far end's CANCEL for [`invitation`] before it is answered (RFC 3261 §9.1).
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

    /// A request from the far end in the dialog this end's 200 opened, `From` and `To` as
    /// that 200 wrote them, and `more` before the body.
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
    pub(crate) fn called(observed: &Observed) -> SipralHandle {
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

    /// The map is forgotten in the same `drain` that translates the call's end, so this also
    /// checks that bytes a delivery already queued are not dropped with it.
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

    /// A caller who gives up at once: INVITE and CANCEL arrive before the poll, so the call
    /// is already gone when its event is translated.
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

    /// Answer an incoming call and have the far end REFER it to carol. Returns the call the
    /// REFER arrived on.
    pub(crate) fn ready_for_a_transfer(
        observed: &mut Observed,
        handle: SipralHandle,
    ) -> SipralHandle {
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(observed);
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
        call
    }

    /// Accept a transfer, and hand back the INVITE it placed to carol.
    pub(crate) fn accept_transfer(
        handle: SipralHandle,
        call: SipralHandle,
        config: &SipralCallConfig,
    ) -> (SipralStatus, SipralHandle, Vec<u8>) {
        let mut placed = SIPRAL_HANDLE_NONE;
        let status = unsafe {
            sipral_call_accept_transfer(handle, call, ptr::from_ref(config), &raw mut placed, 1_300)
        };
        let invite = sent(handle)
            .into_iter()
            .find(|bytes| start_line(bytes).starts_with("INVITE sip:carol@example.com"))
            .unwrap_or_default();
        (status, placed, invite)
    }

    /// The third way to place a call: the one a REFER asked for.
    #[test]
    fn a_call_a_transfer_placed_names_its_own_from_and_to_and_call_id() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        let call = ready_for_a_transfer(&mut observed, handle);

        let (status, placed, invite) = accept_transfer(handle, call, &transfer_config());
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert!(!invite.is_empty(), "the call the REFER asked for went out");
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

    /// 8.4.4: accepted with `media_address`, the transfer's INVITE carries this stack's offer
    /// and audio comes up once carol answers, as with `sipral_call_place`.
    #[test]
    fn a_transfer_accepted_with_media_address_places_an_invite_this_stack_wrote_and_media_starts_when_it_is_up()
     {
        let mut observed = Observed::default();
        let (handle, _) = media_line(&mut observed, |_| {});
        let call = ready_for_a_transfer(&mut observed, handle);

        let (status, placed, invite) = accept_transfer(handle, call, &managed_transfer_config());
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(placed, SIPRAL_HANDLE_NONE);
        let body = String::from_utf8_lossy(&invite).into_owned();
        assert!(
            body.contains("m=audio"),
            "the offer was not this stack's own: {body}"
        );

        deliver(handle, &accepted(&invite, ANSWER, true), 1_350);
        poll(handle, 1_350);
        assert!(
            observed.kinds().contains(&SipralEventKind::MediaStarted),
            "the transferred call came up without audio: {:?}",
            observed.kinds()
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// 8.4.4: accepted with `sdp`, the INVITE carries exactly that description and no audio
    /// is run here.
    #[test]
    fn a_transfer_accepted_with_sdp_carries_exactly_that_description_and_the_stack_runs_no_audio() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        let call = ready_for_a_transfer(&mut observed, handle);

        let (status, _, invite) = accept_transfer(handle, call, &transfer_config());
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(
            body(&invite),
            OFFER,
            "the INVITE did not carry exactly what sdp gave it"
        );

        deliver(handle, &accepted(&invite, ANSWER, true), 1_350);
        poll(handle, 1_350);
        assert!(
            !observed.kinds().contains(&SipralEventKind::MediaStarted),
            "a call placed with sdp is the application's to run audio for: {:?}",
            observed.kinds()
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// 8.4.4: `srtp` on an accepted transfer overrides the stack's policy the
    /// same way it does on `sipral_call_place`.
    #[test]
    fn an_accepted_transfer_under_srtp_required_offers_the_secure_profile_with_a_key() {
        let mut observed = Observed::default();
        let (handle, _) = media_line(&mut observed, |_| {});
        let call = ready_for_a_transfer(&mut observed, handle);

        let mut config = managed_transfer_config();
        config.srtp = SipralSrtp::Required as u32;
        let (status, _, invite) = accept_transfer(handle, call, &config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let body = String::from_utf8_lossy(&invite).into_owned();
        assert!(
            body.contains("RTP/SAVP") && body.contains("a=crypto:"),
            "{body}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// 8.4.4: header fields in `config.headers` reach the INVITE an accepted
    /// transfer places, the same as they do on `sipral_call_place`.
    #[test]
    fn application_headers_on_an_accepted_transfer_reach_the_invite_it_places() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        let call = ready_for_a_transfer(&mut observed, handle);

        let labelled = [header_of("X-Conversation-Id", "xfer-9")];
        let mut config = transfer_config();
        config.headers = labelled.as_ptr();
        config.headers_len = labelled.len();
        let (status, _, invite) = accept_transfer(handle, call, &config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(
            field_through_c(&invite, "X-Conversation-Id").as_deref(),
            Some(&b"xfer-9"[..])
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// 8.4.4: the target of an accepted transfer is the REFER's, never the
    /// caller's — setting `config.target` is refused, and nothing is placed.
    #[test]
    fn a_target_set_on_an_accepted_transfer_is_invalid_argument_and_places_nothing() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        let call = ready_for_a_transfer(&mut observed, handle);

        let mut config = transfer_config();
        (config.target, config.target_len) = as_text("sip:wrong@example.com");
        let (status, placed, invite) = accept_transfer(handle, call, &config);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(placed, SIPRAL_HANDLE_NONE);
        assert!(last_error_text().contains("target"));
        assert!(invite.is_empty(), "an INVITE went out despite the refusal");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// 8.4.4: `Replaces` is the REFER's to give (RFC 3891 §3), so one in `config.headers` is
    /// refused, nothing is sent, and the transfer is still there to take.
    #[test]
    fn a_replaces_in_the_headers_of_an_accepted_transfer_is_invalid_argument_and_places_nothing() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        let call = ready_for_a_transfer(&mut observed, handle);

        let replacing = [header_of("Replaces", "other@192.0.2.1;to-tag=x;from-tag=y")];
        let mut config = transfer_config();
        config.headers = replacing.as_ptr();
        config.headers_len = replacing.len();
        let (status, placed, invite) = accept_transfer(handle, call, &config);
        assert_eq!(
            status,
            SipralStatus::InvalidArgument,
            "{}",
            String::from_utf8_lossy(&invite)
        );
        assert_eq!(placed, SIPRAL_HANDLE_NONE);
        assert!(
            last_error_text().contains("Replaces"),
            "{}",
            last_error_text()
        );
        assert!(invite.is_empty(), "an INVITE went out despite the refusal");

        let (status, _, invite) = accept_transfer(handle, call, &transfer_config());
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert!(!invite.is_empty(), "the refusal used the transfer up");
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

    /// Offerless INVITE answered in the ACK is RFC 3261 §13.2.1, not §14.1. The needle is
    /// assembled at runtime so the test does not match itself.
    #[test]
    fn the_module_doc_cites_the_section_that_puts_the_answer_in_the_ack() {
        // the needle spans a line break; Windows checkouts add a CR
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

    /// The payload of one frame of a loud tone captured on a call this end
    /// holds, on a stack whose `held_audio` is `held_audio`.
    fn held_payload(held_audio: u32) -> Vec<u8> {
        let mut observed = Observed::default();
        let (handle, call) = media_call_tuned(&mut observed, |config| {
            config.held_audio = held_audio;
        });
        let _ = sent(handle);
        assert_eq!(
            unsafe { sipral_call_hold(handle, call, 2_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let reinvite = one(handle);
        deliver(handle, &accepted(&reinvite, HELD_ANSWER, false), 2_100);
        poll(handle, 2_100);
        assert_eq!(held_state(handle, call), (1, 0), "the hold is in force");
        let media = crate::media::tests::media_of(handle, call);
        let mut buffers = crate::media::tests::Buffers::new();
        let mut packet = buffers.packet();
        let samples = [3_000_i16; 160];
        let status = unsafe {
            crate::media::sipral_media_capture(
                media,
                2_120,
                samples.as_ptr(),
                samples.len(),
                &raw mut packet,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let (payload, _) = buffers.taken(&packet);
        crate::media::tests::release(media);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        payload.get(12..).unwrap_or_default().to_vec()
    }

    /// A held party gets silence by default (mu-law 0xFF), since the frames may be a
    /// microphone's, and the application's frames when `held_audio` asks for them.
    #[test]
    fn a_held_party_hears_silence_in_application_mode_unless_the_application_is_named() {
        let silent =
            |payload: &[u8]| !payload.is_empty() && payload.iter().all(|byte| *byte == 0xFF);
        let default = held_payload(crate::stack::SipralHeldAudio::Default as u32);
        assert!(silent(&default), "{default:?}");
        let silence = held_payload(crate::stack::SipralHeldAudio::Silence as u32);
        assert!(silent(&silence), "{silence:?}");
        let application = held_payload(crate::stack::SipralHeldAudio::Application as u32);
        assert!(
            !application.is_empty() && !silent(&application),
            "{application:?}"
        );

        let mut observed = Observed::default();
        let mut settings = config(record, &mut observed);
        settings.held_audio = 3;
        let (status, _) = create(&settings);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(
            last_error_text().contains("held_audio"),
            "{}",
            last_error_text()
        );
    }

    /// `HELD_ANSWER` carries `a=recvonly`: the far end receives and does not send
    /// (RFC 4566). The needle is assembled at runtime so the test does not match itself.
    #[test]
    fn the_held_answer_doc_matches_what_recvonly_means() {
        // the needle spans a line break; Windows checkouts add a CR
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

    /// 8.3.11-bis(b): UDP may reorder overlapping non-INVITE transactions, so each INFO digit
    /// waits for the previous one's final answer.
    #[test]
    fn a_string_of_digits_goes_out_one_info_at_a_time() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        let _ = sent(handle);
        let (digits, digits_len) = as_text("1#D");
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
        for expected in ["Signal=1", "Signal=#", "Signal=D"] {
            let written = one(handle);
            assert!(start_line(&written).starts_with("INFO"));
            assert_eq!(
                field(&written, HeaderName::ContentType),
                b"application/dtmf-relay"
            );
            let text = String::from_utf8_lossy(&written).into_owned();
            assert!(text.contains(expected), "{text}");
            // 8.3.11-bis(d): the 100 ms every form defaults to
            assert!(text.contains("Duration=100"), "{text}");
            deliver(handle, &answered_with(&written, 200, "OK"), 2_100);
        }
        assert!(
            sent(handle).is_empty(),
            "nothing was left to send after the third digit"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A non-2xx mid-string ends the sequence; the waiting digits are discarded, not sent out
    /// of order.
    #[test]
    fn a_refusal_mid_string_means_the_rest_is_never_sent() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        let _ = sent(handle);
        let (digits, digits_len) = as_text("123");
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
        let first = one(handle);
        deliver(handle, &answered_with(&first, 200, "OK"), 2_100);
        let second = one(handle);
        deliver(handle, &answered_with(&second, 486, "Busy Here"), 2_100);
        assert!(
            sent(handle).is_empty(),
            "a 486 on the second digit means the third is never sent"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The whole string is checked before anything goes out: one bad
    /// character anywhere sends nothing, not even the keys ahead of it.
    #[test]
    fn an_invalid_character_anywhere_in_the_string_sends_nothing() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        let _ = sent(handle);
        let (digits, digits_len) = as_text("12E4");
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
            SipralStatus::InvalidArgument
        );
        assert!(
            sent(handle).is_empty(),
            "a bad character anywhere in the string refuses the whole of it"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn an_options_is_answered_by_the_stack_and_never_reaches_the_caller() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        poll(handle, 1_000);
        // §11.2 makes answering OPTIONS a MUST, and a proxy pings with it: Asterisk marks a
        // silent contact unreachable and refuses its inbound calls with 503. The stack answers
        // and the caller never hears of it
        let ping = b"OPTIONS sip:alice@192.0.2.10:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-are-you-there\r\n\
Max-Forwards: 70\r\n\
From: <sip:proxy@example.com>;tag=asking\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: are-you-there@203.0.113.5\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";
        deliver(handle, ping, 1_100);

        // before the poll, which would drain the answer away
        let answers: Vec<String> = sent(handle)
            .iter()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .filter(|text| text.contains("CSeq: 1 OPTIONS"))
            .collect();
        let [answer] = answers.as_slice() else {
            panic!("expected exactly one answer to the OPTIONS, got {answers:?}");
        };
        assert!(answer.starts_with("SIP/2.0 200 "), "{answer}");
        // §11.2: built as for an INVITE, so it says what this end can do
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

    /// A form with no number is refused rather than taken as the default, else a mistyped
    /// constant would silently send in the dialog. Zero, an unfilled field, most of all.
    #[test]
    fn a_way_of_sending_a_digit_that_does_not_exist_is_refused() {
        assert_eq!(dtmf_form(1).ok(), Some(SipralDtmf::Rtp));
        assert_eq!(dtmf_form(2).ok(), Some(SipralDtmf::InfoRelay));
        assert_eq!(dtmf_form(3).ok(), Some(SipralDtmf::InfoPlain));
        assert_eq!(dtmf_form(4).ok(), Some(SipralDtmf::InBand));
        for wrong in [0, 5, 6, u32::MAX] {
            assert!(dtmf_form(wrong).is_err(), "{wrong} was taken as a form");
        }
    }

    /// The other INFO body, whose whole content is the key.
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

    /// With no negotiated telephone event, a digit goes into the audio from the media form as
    /// well as the in-band one: the digits queue, sound, and are done.
    #[test]
    fn a_call_with_no_named_events_takes_a_digit_in_its_audio() {
        let mut observed = Observed::default();
        let (handle, call) = media_call(&mut observed);
        let media = crate::media::tests::media_of(handle, call);
        let (digits, digits_len) = as_text("12#");
        for via in [SipralDtmf::Rtp, SipralDtmf::InBand] {
            assert_eq!(
                unsafe {
                    sipral_call_send_dtmf(handle, call, digits, digits_len, via as u32, 0, 2_000)
                },
                SipralStatus::Ok,
                "{via:?}: {}",
                last_error_text()
            );
        }
        let mut dialling = u32::MAX;
        let mut waiting = usize::MAX;
        let status = unsafe {
            crate::media::sipral_media_dialling(media, &raw mut dialling, &raw mut waiting)
        };
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!(
            (dialling, waiting),
            (1, 6),
            "six digits queued in the audio"
        );
        // six digits of a hundred milliseconds and their pauses, in frames
        for _ in 0..(6 * 160 / 20 + 2) {
            crate::media::tests::capture_one(media, &[0; crate::media::tests::FRAME]);
        }
        let status = unsafe {
            crate::media::sipral_media_dialling(media, &raw mut dialling, &raw mut waiting)
        };
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!((dialling, waiting), (0, 0), "the digits never finished");
        crate::media::tests::release(media);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// 8.3.11(c): a tone length refused by one form is refused by every one, with the same
    /// status and words, and nothing goes out.
    #[test]
    fn a_tone_length_one_form_refuses_is_refused_by_every_form_alike() {
        let mut observed = Observed::default();
        let (handle, call) = media_call(&mut observed);
        let _ = sent(handle);
        let (digits, digits_len) = as_text("5");
        let answers: Vec<(SipralStatus, String)> = [
            SipralDtmf::Rtp,
            SipralDtmf::InfoRelay,
            SipralDtmf::InfoPlain,
            SipralDtmf::InBand,
        ]
        .into_iter()
        .map(|via| {
            let status = unsafe {
                sipral_call_send_dtmf(handle, call, digits, digits_len, via as u32, 20, 2_000)
            };
            (status, last_error_text())
        })
        .collect();
        assert!(sent(handle).is_empty(), "a refused tone length went out");
        for answer in &answers {
            assert_eq!(answer.0, SipralStatus::InvalidArgument, "{answers:?}");
            assert_eq!(Some(answer), answers.first(), "{answers:?}");
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// 8.3.11(a): a refused INFO reaches the application with the digit and the status.
    #[test]
    fn a_refused_info_reaches_the_application_as_dtmf_sent() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        let (digits, digits_len) = as_text("5");
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
        let info = one(handle);
        deliver(
            handle,
            &answered_with(&info, 415, "Unsupported Media Type"),
            2_100,
        );
        poll(handle, 2_100);
        let sent = observed
            .identities_of(call)
            .into_iter()
            .find(|seen| seen.kind == SipralEventKind::DtmfSent)
            .expect("the refusal reached the application");
        assert_eq!(sent.digit, u32::from('5'));
        assert_eq!(sent.status_code, 415);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// 8.3.11(b): an incoming INFO of either content type is reported as
    /// `SIPRAL_EVENT_KIND_DIGIT_RECEIVED` with `SIPRAL_DIGIT_SOURCE_INFO`.
    #[test]
    fn an_incoming_info_of_either_content_type_is_a_digit_received_from_info() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (status, call) = place(handle, account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        deliver(handle, &accepted(&invite, ANSWER, true), 1_100);
        poll(handle, 1_100);
        let _ = sent(handle); // the ACK

        deliver(
            handle,
            &incoming_info(
                &invite,
                "relay",
                51,
                Some("application/dtmf-relay"),
                b"Signal=7\r\nDuration=200\r\n",
            ),
            2_000,
        );
        poll(handle, 2_000);
        let answer = one(handle);
        assert!(start_line(&answer).starts_with("SIP/2.0 200 "));
        let heard = observed
            .of(SipralEventKind::DigitReceived)
            .into_iter()
            .find(|heard| heard.call == call)
            .expect("the relay INFO was reported");
        assert_eq!(heard.digit, u32::from('7'));
        assert_eq!(heard.event_code, 7);
        assert_eq!(heard.held_ms, 200);
        assert_eq!(heard.source, SipralDigitSource::Info as u32);

        deliver(
            handle,
            &incoming_info(&invite, "plain", 52, Some("application/dtmf"), b"9"),
            2_100,
        );
        poll(handle, 2_100);
        let answer = one(handle);
        assert!(start_line(&answer).starts_with("SIP/2.0 200 "));
        let heard = observed
            .of(SipralEventKind::DigitReceived)
            .into_iter()
            .rfind(|heard| heard.call == call)
            .expect("the plain INFO was reported");
        assert_eq!(heard.digit, u32::from('9'));
        assert_eq!(heard.event_code, 9);
        assert_eq!(heard.held_ms, 0);
        assert_eq!(heard.source, SipralDigitSource::Info as u32);

        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// 8.3.11-bis(c): a key held for no time is reported as zero, not the 100 ms default.
    #[test]
    fn a_received_duration_of_zero_is_reported_as_zero() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (status, call) = place(handle, account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        deliver(handle, &accepted(&invite, ANSWER, true), 1_100);
        poll(handle, 1_100);
        let _ = sent(handle); // the ACK

        deliver(
            handle,
            &incoming_info(
                &invite,
                "zero",
                51,
                Some("application/dtmf-relay"),
                b"Signal=6\r\nDuration=0\r\n",
            ),
            2_000,
        );
        poll(handle, 2_000);
        one(handle);
        let heard = observed
            .of(SipralEventKind::DigitReceived)
            .into_iter()
            .find(|heard| heard.call == call)
            .expect("the relay INFO was reported");
        assert_eq!(heard.digit, u32::from('6'));
        assert_eq!(heard.held_ms, 0);

        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// 8.3.11-bis(a): only `application/dtmf-relay` and `application/dtmf` are digits. Any
    /// other INFO (RFC 5168 media control, or no body) is answered by the stack (RFC 6086
    /// §4.2.2), else it is retransmitted and ends the call (RFC 3261 §12.2.1.2).
    #[test]
    fn an_info_that_is_not_dtmf_is_answered_by_the_stack() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (status, _call) = place(handle, account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        deliver(handle, &accepted(&invite, ANSWER, true), 1_100);
        poll(handle, 1_100);
        let _ = sent(handle); // the ACK

        deliver(
            handle,
            &incoming_info(
                &invite,
                "mediactl",
                51,
                Some("application/media_control+xml"),
                b"<media_control><vc_primitive>...</vc_primitive></media_control>",
            ),
            2_000,
        );
        let result = poll(handle, 2_000);
        let answer = sent(handle);
        assert!(
            answer
                .iter()
                .any(|bytes| bytes.starts_with(b"SIP/2.0 415 ")),
            "a body this stack does not read is refused 415: {:?}",
            answer
                .iter()
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                .collect::<Vec<_>>()
        );
        assert_eq!(result.events_unclaimed, 0);

        deliver(
            handle,
            &incoming_info(&invite, "nobody", 52, None, b""),
            2_100,
        );
        let result = poll(handle, 2_100);
        assert!(
            sent(handle)
                .iter()
                .any(|bytes| bytes.starts_with(b"SIP/2.0 200 ")),
            "an INFO with no body is answered 200"
        );
        assert_eq!(result.events_unclaimed, 0);

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

    /// RFC 4733 §3 has only 3.1-3.3; the DTMF events are Table 3 in 3.2. The generator copies
    /// this doc into the public header, so the citation is checked here. The needle is
    /// assembled at runtime so the test does not match itself.
    #[test]
    fn the_send_dtmf_doc_cites_a_section_rfc_4733_actually_has() {
        // the needle spans a line break; Windows checkouts add a CR
        let source = include_str!("call.rs").replace("\r\n", "\n");
        let section = '\u{a7}';
        assert!(
            source.contains(&format!(
                "RFC 4733 {section}3.2, in the order they were pressed"
            )),
            "sipral_call_send_dtmf's doc should point at §3.2"
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
        // the BYE is out and the dialog gone; the handle lives until the event is delivered
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
        // a still-ringing leg has no dialog to name in a Replaces
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
            unsafe {
                sipral_call_accept_session(handle, call, ANSWER.as_ptr(), ANSWER.len(), 2_000)
            },
            SipralStatus::WrongState
        );
        assert_eq!(
            unsafe { sipral_call_reject_session(handle, call, 488, 2_000) },
            SipralStatus::WrongState
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// Every offered change carries an offer, and RFC 3264 §5 has it answered: accepting with
    /// no description is refused, and the request still waits.
    #[test]
    fn a_change_the_far_end_offered_is_accepted_only_with_an_answer() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (status, call) = place(handle, account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        deliver(handle, &accepted(&invite, ANSWER, true), 1_100);
        poll(handle, 1_100);
        let _ = sent(handle);

        deliver(handle, &reoffer(&invite, REOFFERED), 1_200);
        poll(handle, 1_200);
        assert!(
            observed.kinds().contains(&SipralEventKind::SessionOffered),
            "{:?}",
            observed.kinds()
        );
        let _ = sent(handle);

        assert_eq!(
            unsafe { sipral_call_accept_session(handle, call, ptr::null(), 0, 1_300) },
            SipralStatus::InvalidArgument
        );
        assert!(
            sent(handle).is_empty(),
            "an answer went out with no description in it"
        );
        assert_eq!(
            unsafe {
                sipral_call_accept_session(handle, call, ANSWER.as_ptr(), ANSWER.len(), 1_300)
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let out = sent(handle);
        assert!(
            out.iter()
                .any(|bytes| bytes.starts_with(b"SIP/2.0 200 ") && bytes.ends_with(ANSWER)),
            "{:?}",
            out.iter()
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                .collect::<Vec<_>>()
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_handle_from_one_stack_does_not_open_another() {
        // tags of its own, so both stacks start at the first generation; the process's shared
        // set carries other tests' tags and could refuse the handle for unrelated reasons
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
        // both stacks number calls from the same slot, so only the stack differs
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

    /// A stack's tag is reused by the next one, so old handles carry the new stack's tag.
    /// They still name nothing there.
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

    /// A call has one description of its session; setting two is refused, naming both.
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

    /// The other half of a managed call: an incoming call answered with this stack's description.
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

    /// A re-offer on a managed call is answered by the stack before the poll returns, so it
    /// never reaches the application and the entry points that would answer it say so. This
    /// one only adds an unknown format, so nothing moves and `MEDIA_CHANGED` stays silent.
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
        // the re-offer only adds a format this stack does not carry, so PCMU runs at the same
        // address: nothing moved, nothing to report
        assert!(
            !observed.kinds().contains(&SipralEventKind::MediaChanged),
            "a re-offer that changed nothing the running session uses should \
             report nothing: {:?}",
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

    /// The far end's answer to a codec change onto PCMA.
    const ALAW_REANSWER: &[u8] = b"v=0\r\n\
o=bob 1 2 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 41000 RTP/AVP 8\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=sendrecv\r\n";

    fn change_codecs(
        stack: SipralHandle,
        call: SipralHandle,
        list: &str,
        now_ms: u64,
    ) -> SipralStatus {
        let (codecs, codecs_len) = as_text(list);
        unsafe { sipral_call_change_codecs(stack, call, codecs, codecs_len, now_ms) }
    }

    /// The far end's answer to the resume that follows `HELD_ANSWER`.
    const RESUMED_ANSWER: &[u8] = b"v=0\r\n\
o=bob 1 3 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 41000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=sendrecv\r\n";

    #[test]
    fn a_resume_from_c_behind_a_hold_still_on_its_way_goes_once_the_hold_is_answered() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |config| {
            let (codecs, codecs_len) = as_text("PCMU,PCMA");
            config.codecs = codecs;
            config.codecs_len = codecs_len;
        });
        let (status, call) = place(handle, account, &managed_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        deliver(handle, &accepted(&invite, ANSWER, true), 1_100);
        poll(handle, 1_100);
        let _ = sent(handle);

        assert_eq!(
            unsafe { sipral_call_hold(handle, call, 2_000) },
            SipralStatus::Ok
        );
        let hold = one(handle);
        assert_eq!(
            unsafe { sipral_call_resume(handle, call, 2_010) },
            SipralStatus::Ok,
            "the resume is taken, to go after the hold"
        );
        assert_eq!(
            change_codecs(handle, call, "PCMA", 2_020),
            SipralStatus::WrongState,
            "a codec change is refused while a change runs, never taken and lost"
        );
        assert!(sent(handle).is_empty(), "nothing crosses the hold");

        deliver(handle, &accepted(&hold, HELD_ANSWER, false), 2_100);
        poll(handle, 2_100);
        let resume = sent(handle)
            .into_iter()
            .find(|message| start_line(message).starts_with("INVITE"))
            .expect("the resume goes once the hold is answered");
        let offered = String::from_utf8_lossy(&resume).into_owned();
        assert!(offered.contains("a=sendrecv"), "{offered}");
        assert_eq!(held_state(handle, call), (1, 0));

        deliver(handle, &accepted(&resume, RESUMED_ANSWER, false), 2_200);
        poll(handle, 2_200);
        assert_eq!(held_state(handle, call), (0, 0));
        let kinds = observed.kinds();
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| **kind == SipralEventKind::SessionChanged)
                .count(),
            2,
            "{kinds:?}"
        );
        assert!(
            !kinds.contains(&SipralEventKind::SessionChangeFailed),
            "{kinds:?}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// Tell the stack its address moved from `192.0.2.1` to `198.51.100.7`,
    /// and hand back what it decided.
    fn moved_network(stack: SipralHandle, now_ms: u64) -> u32 {
        let (from, from_len) = as_text("192.0.2.1");
        let (to, to_len) = as_text("198.51.100.7");
        let mut recovery = 0_u32;
        let status = unsafe {
            crate::lifecycle::sipral_stack_network_changed(
                stack,
                1,
                from,
                from_len,
                ptr::null(),
                0,
                1,
                3,
                to,
                to_len,
                ptr::null(),
                0,
                1,
                now_ms,
                &raw mut recovery,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        recovery
    }

    fn readdress(
        stack: SipralHandle,
        call: SipralHandle,
        local: &str,
        now_ms: u64,
    ) -> SipralStatus {
        let (address, address_len) = as_text(local);
        unsafe {
            sipral_call_media_readdress(stack, call, address, address_len, ptr::null(), 0, now_ms)
        }
    }

    /// The network changes under a managed call: the stack names the call, and the new
    /// address goes out in a re-INVITE's `c=` and `m=`, nothing else moved.
    #[test]
    fn a_call_whose_network_changed_is_named_and_offered_at_the_new_address() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |_| {});
        let (status, call) = place(handle, account, &managed_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        deliver(handle, &accepted(&invite, ANSWER, true), 1_100);
        poll(handle, 1_100);
        let _ = sent(handle);
        observed.events.clear();
        observed.named.clear();

        assert_eq!(
            moved_network(handle, 2_000),
            crate::lifecycle::SipralRecovery::Rebuild as u32
        );
        poll(handle, 2_000);
        let wanted: Vec<SipralHandle> = observed
            .events
            .iter()
            .zip(&observed.named)
            .filter(|(event, _)| event.1 == SipralEventKind::CallAddressWanted)
            .map(|(_, named)| named.1)
            .collect();
        assert_eq!(wanted, vec![call], "{:?}", observed.kinds());

        assert_eq!(
            readdress(handle, call, "198.51.100.7:42000", 2_010),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let reinvite = sent(handle)
            .into_iter()
            .find(|message| start_line(message).starts_with("INVITE"))
            .expect("the re-offer goes");
        let offered = String::from_utf8_lossy(&body(&reinvite)).into_owned();
        assert!(offered.contains("c=IN IP4 198.51.100.7\r\n"), "{offered}");
        assert!(offered.contains("m=audio 42000 "), "{offered}");
        let first = String::from_utf8_lossy(&body(&invite)).into_owned();
        let origin = |sdp: &str| {
            sdp.lines()
                .find(|line| line.starts_with("o="))
                .map(|line| line.rsplit(' ').next().unwrap_or_default().to_owned())
        };
        assert_eq!(origin(&offered), origin(&first), "o= keeps its address");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// What `sipral_call_media_readdress` refuses: a bad address, an application-described
    /// call, and a call already changing.
    #[test]
    fn moving_a_call_says_why_it_cannot() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |_| {});
        let (status, managed) = place(handle, account, &managed_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        deliver(handle, &accepted(&invite, ANSWER, true), 1_100);
        poll(handle, 1_100);
        let _ = sent(handle);

        assert_eq!(
            readdress(handle, managed, "not an address", 1_200),
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { sipral_call_hold(handle, managed, 1_300) },
            SipralStatus::Ok
        );
        assert_eq!(
            readdress(handle, managed, "198.51.100.7:42000", 1_310),
            SipralStatus::WrongState,
            "a move asked while the hold is on its way is refused, never taken and lost"
        );

        let (status, described) = place(handle, account, &call_config(), 1_400);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let _ = sent(handle);
        assert_eq!(
            readdress(handle, described, "198.51.100.7:42000", 1_410),
            SipralStatus::WrongState,
            "a call whose description the application wrote is the application's to move"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// What a carrier's INVITE says about the caller, besides its `From`.
    const ASSERTING: &str = "P-Asserted-Identity: \"Bob Jones\" <tel:+15551234567;verstat=TN-Validation-Passed>\r\n\
Diversion: <sip:desk@example.com>;reason=no-answer, <sip:front@example.com>;reason=unconditional\r\n\
History-Info: <sip:front@example.com>;index=1\r\n\
Privacy: id\r\n\
Answer-Mode: Auto;require\r\n\
Alert-Info: <urn:alert:source:external>\r\n";

    /// A stack whose one account is tuned by `tune` before it is added.
    fn tuned_line(
        observed: &mut Observed,
        tune: impl FnOnce(&mut SipralAccountConfig),
    ) -> (SipralHandle, SipralHandle) {
        let handle = stack(observed);
        let mut config = account_config();
        tune(&mut config);
        let mut account = SIPRAL_HANDLE_NONE;
        let status =
            unsafe { sipral_account_add(handle, ptr::from_ref(&config), &raw mut account) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        (handle, account)
    }

    fn identity_text(stack: SipralHandle, call: SipralHandle, which: u32, index: usize) -> String {
        let mut buffer = [0 as c_char; 128];
        let mut needed = 0_usize;
        let status = unsafe {
            crate::identity::sipral_call_identity_text(
                stack,
                call,
                index,
                which,
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut needed,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let bytes: Vec<u8> = buffer[..needed - 1]
            .iter()
            .map(|byte| byte.cast_unsigned())
            .collect();
        String::from_utf8(bytes).expect("UTF-8")
    }

    #[test]
    fn an_incoming_call_from_a_trusted_peer_says_who_the_network_says_is_calling() {
        let mut observed = Observed::default();
        let (handle, _) = tuned_line(&mut observed, |config| {
            (config.trusted_peers, config.trusted_peers_len) = as_text("198.51.100.1, 203.0.113.5");
        });
        deliver(handle, &insert_header(&invitation(), ASSERTING), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let seen = observed
            .identities_of(call)
            .into_iter()
            .find(|seen| seen.kind == SipralEventKind::IncomingCall)
            .expect("the incoming call was reported");
        assert_eq!(seen.identity_trusted, 1);
        assert_eq!(
            seen.asserted_uri,
            b"tel:+15551234567;verstat=TN-Validation-Passed"
        );
        assert_eq!(seen.asserted_display, b"Bob Jones");
        assert_eq!(seen.verstat, crate::identity::SipralVerstat::Passed as u32);
        assert_eq!(seen.privacy, crate::identity::SIPRAL_PRIVACY_ID);
        assert_eq!(seen.diverted_from, b"sip:desk@example.com");
        assert_eq!(seen.diversion_reason, b"no-answer");
        assert_eq!((seen.diversion_count, seen.history_count), (2, 1));
        assert_eq!(
            (seen.answer_mode, seen.answer_mode_required),
            (crate::identity::SipralAnswerMode::Auto as u32, 1)
        );
        assert_eq!((seen.has_answer_after, seen.answer_after_ms), (1, 0));
        assert_eq!(
            seen.ring_source,
            crate::identity::SipralRingSource::External as u32
        );
        assert_eq!(seen.alert_info, b"urn:alert:source:external");

        let mut count = 0_usize;
        let diversion = crate::identity::SipralIdentityText::Diversion as u32;
        assert_eq!(
            unsafe {
                crate::identity::sipral_call_identity_count(handle, call, diversion, &raw mut count)
            },
            SipralStatus::Ok
        );
        assert_eq!(count, 2);
        assert_eq!(
            identity_text(handle, call, diversion, 1),
            "sip:front@example.com"
        );
        assert_eq!(
            identity_text(
                handle,
                call,
                crate::identity::SipralIdentityText::DiversionReason as u32,
                1
            ),
            "unconditional"
        );
        let mut needed = 0_usize;
        assert_eq!(
            unsafe {
                crate::identity::sipral_call_identity_text(
                    handle,
                    call,
                    2,
                    diversion,
                    ptr::null_mut(),
                    0,
                    &raw mut needed,
                )
            },
            SipralStatus::InvalidArgument,
            "past the end"
        );
        // with room enough, `out_needed` may be null
        let mut buffer = [0 as c_char; 64];
        assert_eq!(
            unsafe {
                crate::identity::sipral_call_identity_text(
                    handle,
                    call,
                    1,
                    diversion,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    ptr::null_mut(),
                )
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let written = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) };
        assert_eq!(written.to_bytes(), b"sip:front@example.com");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// RFC 3325 §8, across the boundary: an account that trusts nobody is
    /// told nothing the network asserted, and still told what was forwarded.
    #[test]
    fn an_incoming_call_from_a_peer_nobody_trusts_asserts_nothing() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        deliver(handle, &insert_header(&invitation(), ASSERTING), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let seen = observed
            .identities_of(call)
            .into_iter()
            .find(|seen| seen.kind == SipralEventKind::IncomingCall)
            .expect("the incoming call was reported");
        assert_eq!(seen.identity_trusted, 0);
        assert!(seen.asserted_uri.is_empty());
        assert_eq!(seen.verstat, crate::identity::SipralVerstat::None as u32);
        assert_eq!(seen.diverted_from, b"sip:desk@example.com");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_cancelled_because_another_phone_answered_says_so_on_its_end() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);
        deliver(
            handle,
            &insert_header(
                &cancellation(),
                "Reason: SIP ;cause=200 ;text=\"Call completed elsewhere\"\r\n",
            ),
            1_100,
        );
        poll(handle, 1_100);
        let ended = observed
            .identities_of(call)
            .into_iter()
            .find(|seen| seen.kind == SipralEventKind::CallEnded)
            .expect("the call ended");
        assert_eq!((ended.cause_sip, ended.cause_q850), (200, 0));
        assert_eq!(ended.cause_text, b"Call completed elsewhere");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_hangup_for_a_reason_writes_it_on_the_bye() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (status, call) = place(handle, account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        deliver(handle, &accepted(&invite, ANSWER, true), 1_100);
        poll(handle, 1_100);
        let _ = sent(handle);
        let (said, said_len) = as_text("Normal call clearing");
        assert_eq!(
            unsafe {
                crate::identity::sipral_call_hangup_for(handle, call, 0, 16, said, said_len, 1_200)
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let bye = one(handle);
        assert!(start_line(&bye).starts_with("BYE "));
        assert_eq!(
            field(&bye, HeaderName::Extension("Reason")),
            b"Q.850;cause=16;text=\"Normal call clearing\""
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A 302 to the call this end placed, naming Carol.
    fn moved_to_carol(invite: &[u8]) -> Vec<u8> {
        String::from_utf8_lossy(&answered_with(invite, 302, "Moved Temporarily"))
            .replace(
                "Content-Length: 0\r\n",
                "Contact: <sip:carol@example.com>\r\nContent-Length: 0\r\n",
            )
            .into_bytes()
    }

    #[test]
    fn a_302_ends_a_call_from_c_unless_it_was_placed_to_follow_one() {
        for follow in [0, 1] {
            let mut observed = Observed::default();
            let (handle, account) = line(&mut observed);
            let mut config = call_config();
            config.follow_redirects = follow;
            let (status, call) = place(handle, account, &config, 1_000);
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            let invite = one(handle);
            deliver(handle, &moved_to_carol(&invite), 1_100);
            poll(handle, 1_100);
            let invites: Vec<String> = sent(handle)
                .iter()
                .map(|bytes| start_line(bytes))
                .filter(|line| line.starts_with("INVITE "))
                .collect();
            let ended = observed
                .calls
                .iter()
                .find(|seen| seen.kind == SipralEventKind::CallEnded && seen.call == call);
            if follow == 0 {
                assert!(invites.is_empty(), "followed anyway: {invites:?}");
                assert_eq!(ended.map(|seen| seen.status_code), Some(302));
            } else {
                assert_eq!(invites, ["INVITE sip:carol@example.com SIP/2.0"]);
                assert!(ended.is_none(), "the call is still being placed");
            }
            assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        }

        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let mut config = call_config();
        config.follow_redirects = 2;
        let (status, _) = place(handle, account, &config, 1_000);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(sent(handle).is_empty(), "nothing went");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_forwarded_from_c_is_answered_302_with_where_to_go_and_why() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);
        let (targets, targets_len) = as_text("sip:carol@example.com, tel:+15550001111");
        let (reason, reason_len) = as_text("no-answer");
        assert_eq!(
            unsafe {
                crate::identity::sipral_call_redirect(
                    handle,
                    call,
                    486,
                    targets,
                    targets_len,
                    reason,
                    reason_len,
                    1_100,
                )
            },
            SipralStatus::InvalidArgument,
            "a 486 is not a redirection"
        );
        assert_eq!(
            unsafe {
                crate::identity::sipral_call_redirect(
                    handle,
                    call,
                    302,
                    targets,
                    targets_len,
                    reason,
                    reason_len,
                    1_100,
                )
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let answer = one(handle);
        assert!(start_line(&answer).starts_with("SIP/2.0 302 "));
        assert_eq!(
            field(&answer, HeaderName::Contact),
            b"<sip:carol@example.com>, <tel:+15550001111>"
        );
        assert_eq!(
            field(&answer, HeaderName::Extension("Diversion")),
            b"<sip:alice@example.com>;reason=no-answer;counter=1"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The per-account options the C ABI lacked: the session timer and anonymous calls.
    #[test]
    fn an_account_from_c_sets_its_session_timer_and_its_anonymity() {
        let mut observed = Observed::default();
        let (handle, account) = tuned_line(&mut observed, |config| {
            config.session_timer = crate::identity::SipralSessionTimer::Interval as u32;
            config.session_interval_seconds = 120;
            config.privacy = crate::identity::SIPRAL_PRIVACY_ID;
            (config.trusted_peers, config.trusted_peers_len) = as_text("203.0.113.5");
        });
        let (status, _) = place(handle, account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        assert_eq!(field(&invite, HeaderName::SessionExpires), b"120");
        assert!(
            field(&invite, HeaderName::From)
                .starts_with(b"\"Anonymous\" <sip:anonymous@anonymous.invalid>")
        );
        assert_eq!(field(&invite, HeaderName::Extension("Privacy")), b"id");
        assert_eq!(
            field(&invite, HeaderName::Extension("P-Asserted-Identity")),
            b"<sip:alice@example.com>",
            "the trusted peer is still told"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        let mut observed = Observed::default();
        let (handle, account) = tuned_line(&mut observed, |config| {
            config.session_timer = crate::identity::SipralSessionTimer::Off as u32;
        });
        let (status, _) = place(handle, account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        assert_eq!(field(&invite, HeaderName::SessionExpires), b"");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn an_account_option_out_of_range_is_refused_before_anything_exists() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let refused = |tune: &dyn Fn(&mut SipralAccountConfig)| {
            let mut config = account_config();
            tune(&mut config);
            let mut account = SIPRAL_HANDLE_NONE;
            unsafe { sipral_account_add(handle, ptr::from_ref(&config), &raw mut account) }
        };
        assert_eq!(
            refused(&|config| {
                config.session_timer = 2;
                config.session_interval_seconds = 30;
            }),
            SipralStatus::InvalidArgument,
            "under RFC 4028's floor"
        );
        assert_eq!(
            refused(&|config| config.session_timer = 9),
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            refused(&|config| config.privacy = crate::identity::SIPRAL_PRIVACY_NONE),
            SipralStatus::InvalidArgument,
            "none is read, never asked for"
        );
        assert_eq!(
            refused(&|config| {
                (config.trusted_peers, config.trusted_peers_len) = as_text("proxy.example.com");
            }),
            SipralStatus::InvalidArgument,
            "a trusted peer is an address"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_codec_change_asked_for_from_c_moves_the_call_onto_the_codec_named() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |config| {
            let (codecs, codecs_len) = as_text("PCMU,PCMA");
            config.codecs = codecs;
            config.codecs_len = codecs_len;
        });
        let (status, call) = place(handle, account, &managed_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        deliver(handle, &accepted(&invite, ANSWER, true), 1_100);
        poll(handle, 1_100);
        let _ = sent(handle);

        assert_eq!(
            change_codecs(handle, call, "PCMA", 1_200),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let reinvite = one(handle);
        assert!(start_line(&reinvite).starts_with("INVITE"));
        let offered = String::from_utf8_lossy(&body(&reinvite)).into_owned();
        assert!(offered.contains(" RTP/AVP 8"), "{offered}");
        assert!(!offered.contains("PCMU"), "{offered}");
        // another change on its way is the user agent's refusal, as a state
        assert_eq!(
            change_codecs(handle, call, "PCMU", 1_250),
            SipralStatus::WrongState
        );

        deliver(handle, &accepted(&reinvite, ALAW_REANSWER, false), 1_300);
        poll(handle, 1_300);
        assert!(
            observed.kinds().contains(&SipralEventKind::MediaChanged),
            "the codec moved and nothing said so: {:?}",
            observed.kinds()
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_codec_change_that_cannot_be_offered_says_why_and_sends_nothing() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |_| {});
        let (handle, call) = up(&observed, handle, account, ANSWER);
        for (list, expected) in [
            ("", SipralStatus::InvalidArgument),
            ("PCMU,,PCMA", SipralStatus::InvalidArgument),
            ("PCMU,pcmu", SipralStatus::InvalidArgument),
            ("G723", SipralStatus::NotSupported),
        ] {
            assert_eq!(
                change_codecs(handle, call, list, 1_200),
                expected,
                "{list:?}"
            );
            assert!(sent(handle).is_empty(), "{list:?} sent something");
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        // a call whose description is the application's own
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        let _ = sent(handle);
        assert_eq!(
            change_codecs(handle, call, "PCMU", 2_000),
            SipralStatus::WrongState
        );
        assert!(
            last_error_text().contains("media_address"),
            "{}",
            last_error_text()
        );
        assert!(sent(handle).is_empty());
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The consultation leg refuses a media address it would ignore rather than taking it.
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
            // a real list: the names are read before the handle is looked up
            change_codecs(handle, SIPRAL_HANDLE_NONE, "PCMU", 0),
            unsafe { sipral_call_reject(handle, SIPRAL_HANDLE_NONE, 486, 0) },
            unsafe {
                sipral_call_answer(handle, SIPRAL_HANDLE_NONE, ANSWER.as_ptr(), ANSWER.len(), 0)
            },
            unsafe {
                // a real form: it is read before the handle is looked up
                sipral_call_send_dtmf(
                    handle,
                    SIPRAL_HANDLE_NONE,
                    digits,
                    digits_len,
                    SipralDtmf::Rtp as u32,
                    0,
                    0,
                )
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

    /// The size is checked before either handle is looked up: with no stack and a config too
    /// short for any version, the size is what fails, for a placed call and a consultation alike.
    #[test]
    fn a_call_config_shorter_than_its_min_size_is_unsupported_version_even_for_an_invalid_handle() {
        let mut config = call_config();
        config.size = <crate::call::SipralCallConfig as crate::versioned::Versioned>::MIN_SIZE - 1;
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

    /// 8.4.17: the first stack's first account, call and media handle share tag, slot and
    /// generation, so a handle of another kind is `SIPRAL_STATUS_INVALID_HANDLE` wherever one
    /// kind is expected, `sipral_call_hangup(stack, stack, now)` included.
    #[test]
    fn a_handle_of_the_wrong_kind_is_invalid_handle_wherever_it_is_offered() {
        let mut observed = Observed::default();
        let (stack_handle, call) = media_call(&mut observed);
        // a second account, so the wrong-kind check leaves the call's account alone
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
        // media was expected: no stack to resolve, so this is the table's own kind check
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

    /// The first line of a field, read through the C accessor.
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
        // to the far end's address of record, so its 200 carries that line's Contact
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

        // the far end, a stack of its own, echoes the field it reads from the INVITE
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

    /// `SIPRAL_SRTP_REQUIRED` reaches the offer exactly as `SIPRAL_SRTP_OFFERED` does; they
    /// differ only on a plain re-offer or answer (`docs/05-media.md`, "SRTP through the facade").
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

    /// This build's default (`SrtpPolicy::default()`, `docs/08-ffi.md`): what zero means.
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

    /// D6: the order is the call's, not the process's: the stack offers one codec, this call
    /// another.
    #[test]
    fn a_calls_own_codecs_override_the_stacks() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |_| {});
        let mut call_config = managed_config();
        let (codecs, codecs_len) = as_text("G722");
        call_config.codecs = codecs;
        call_config.codecs_len = codecs_len;
        let (status, _) = place(handle, account, &call_config, 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let body = String::from_utf8_lossy(&one(handle)).into_owned();
        assert!(
            body.contains("a=rtpmap:9 G722/8000"),
            "the call's own order did not reach the offer: {body}"
        );
        assert!(
            !body.contains("PCMU"),
            "the stack's order is still in the offer: {body}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// D6: the stack's order is left alone: the next call offers what the stack was
    /// configured with, not G.722.
    #[test]
    fn a_calls_own_codecs_leave_the_stacks_order_alone() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |_| {});
        let mut first = managed_config();
        let (codecs, codecs_len) = as_text("G722");
        first.codecs = codecs;
        first.codecs_len = codecs_len;
        assert_eq!(place(handle, account, &first, 1_000).0, SipralStatus::Ok);
        let _ = sent(handle);

        let (status, _) = place(handle, account, &managed_config(), 2_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let body = String::from_utf8_lossy(&one(handle)).into_owned();
        assert!(
            body.contains("a=rtpmap:0 PCMU/8000") && !body.contains("G722"),
            "the earlier call's order outlived it: {body}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The two overrides compose: a call naming both gets both.
    #[test]
    fn a_call_that_names_codecs_and_srtp_gets_both() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |config| {
            config.srtp = SipralSrtp::NotOffered as u32;
        });
        let mut call_config = managed_config();
        let (codecs, codecs_len) = as_text("G722");
        call_config.codecs = codecs;
        call_config.codecs_len = codecs_len;
        call_config.srtp = SipralSrtp::Required as u32;
        let (status, _) = place(handle, account, &call_config, 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let body = String::from_utf8_lossy(&one(handle)).into_owned();
        assert!(
            body.contains("a=rtpmap:9 G722/8000"),
            "the codec order was lost: {body}"
        );
        assert!(
            body.contains("RTP/SAVP") && body.contains("a=crypto:"),
            "the srtp policy was lost: {body}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// What the call said nothing about is kept from the stack's catalogue, which is why the
    /// derivation starts from it.
    #[test]
    fn a_call_that_names_codecs_keeps_the_stacks_frame_length() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |config| {
            config.frame_ms = 40;
        });
        let mut call_config = managed_config();
        let (codecs, codecs_len) = as_text("G722");
        call_config.codecs = codecs;
        call_config.codecs_len = codecs_len;
        let (status, call) = place(handle, account, &call_config, 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let _ = sent(handle);
        assert_eq!(
            with_stack(handle, |state| Ok(state
                .engine
                .call_catalog(state.calls.get(call).expect("a live call"))
                .expect("a catalogue")
                .frame_length()))
            .expect("the stack is live"),
            40,
            "the call's order came back with the built-in frame length"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The names are checked where the caller still knows which string it
    /// passed, and before anything is built.
    #[test]
    fn a_codec_this_build_has_no_encoder_for_is_invalid_argument_and_places_nothing() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |_| {});
        let mut call_config = managed_config();
        let (codecs, codecs_len) = as_text("SILK");
        call_config.codecs = codecs;
        call_config.codecs_len = codecs_len;
        let (status, call) = place(handle, account, &call_config, 1_000);
        assert_eq!(status, SipralStatus::NotSupported, "{}", last_error_text());
        assert_eq!(call, SIPRAL_HANDLE_NONE);
        assert!(sent(handle).is_empty(), "nothing was built");
        assert!(last_error_text().contains("SILK"), "{}", last_error_text());
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// And a list that is wrong as a list, rather than in one of its names,
    /// is refused the same way `sipral_stack_config_t::codecs` refuses it.
    #[test]
    fn a_stray_comma_in_a_calls_codecs_is_invalid_argument() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |_| {});
        let mut call_config = managed_config();
        let (codecs, codecs_len) = as_text("PCMU,,G722");
        call_config.codecs = codecs;
        call_config.codecs_len = codecs_len;
        let (status, call) = place(handle, account, &call_config, 1_000);
        assert_eq!(
            status,
            SipralStatus::InvalidArgument,
            "{}",
            last_error_text()
        );
        assert_eq!(call, SIPRAL_HANDLE_NONE);
        assert!(sent(handle).is_empty(), "nothing was built");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// `sipral_call_consult` refuses a codec this build has no encoder for too.
    #[test]
    fn an_unknown_codec_on_a_consultation_is_refused_and_places_nothing() {
        let mut observed = Observed::default();
        let (handle, first) = connected(&mut observed);
        let _ = sent(handle);
        let mut config = call_config();
        let (codecs, codecs_len) = as_text("SILK");
        config.codecs = codecs;
        config.codecs_len = codecs_len;
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
        assert_eq!(status, SipralStatus::NotSupported, "{}", last_error_text());
        assert_eq!(second, SIPRAL_HANDLE_NONE);
        assert!(sent(handle).is_empty(), "nothing was built");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn an_out_of_range_call_srtp_is_invalid_argument_and_places_nothing() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |_| {});
        let mut call_config = managed_config();
        call_config.srtp = 8;
        let (status, call) = place(handle, account, &call_config, 1_000);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(call, SIPRAL_HANDLE_NONE);
        assert!(sent(handle).is_empty(), "nothing was built");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// `sipral_call_consult` refuses a value this ABI names nothing for too.
    #[test]
    fn an_out_of_range_srtp_on_a_consultation_is_invalid_argument_and_places_nothing() {
        let mut observed = Observed::default();
        let (handle, first) = connected(&mut observed);
        let _ = sent(handle);
        let mut config = call_config();
        config.srtp = 8;
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

    /// Where `SIPRAL_SRTP_OFFERED` and `SIPRAL_SRTP_REQUIRED` part: an incoming plain offer is
    /// answered plainly under the first and refused under the second (`docs/05-media.md`,
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
        // 8.10: refused by the policy it was answered under
        assert_eq!(
            status,
            SipralStatus::SecurityPolicy,
            "a plain offer under REQUIRED was answered: {}",
            last_error_text()
        );
        let refused = String::from_utf8_lossy(&one(handle)).into_owned();
        assert!(refused.starts_with("SIP/2.0 488 "), "{refused}");
        assert_ne!(
            state_of(handle, call),
            SipralCallState::Incoming as u32,
            "the call was refused, not left ringing"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// An `sdp` of no bytes beside a `media_address` is no `sdp`, whatever its pointer.
    #[test]
    fn a_call_config_with_an_empty_sdp_beside_its_media_address_places_the_call() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |_| {});
        let mut call_config = managed_config();
        let nothing = [0_u8; 1];
        // a binding passes an empty buffer as a real pointer and zero
        call_config.sdp = nothing.as_ptr();
        call_config.sdp_len = 0;
        let (status, _) = place(handle, account, &call_config, 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A `sipral_call_config_t` ending before `srtp` predates the freeze and is refused:
    /// `transport` would be read from its tail padding. The oldest version served is minor 33's.
    #[test]
    fn a_call_config_from_before_the_freeze_is_refused() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |_| {});
        let mut call_config = managed_config();
        call_config.size = std::mem::offset_of!(SipralCallConfig, srtp);
        let (status, _) = place(handle, account, &call_config, 1_000);
        assert_eq!(status, SipralStatus::UnsupportedVersion);
        assert!(sent(handle).is_empty(), "nothing was built");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// No 100rel asked, so the 183 goes unreliably, a preview (RFC 6337 §3.1.1), and the
    /// 200 OK repeats it unchanged.
    #[test]
    fn ringing_with_media_unreliably_is_repeated_in_the_200_ok() {
        let mut observed = Observed::default();
        let (handle, _) = media_line(&mut observed, |_| {});
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        // the 100 Trying the core sent by itself
        let _ = sent(handle);

        let config = ring_media_config();
        let status = unsafe { sipral_call_ring_media(handle, call, ptr::from_ref(&config), 1_100) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let progress = one(handle);
        assert!(start_line(&progress).starts_with("SIP/2.0 183"));
        assert!(
            field(&progress, HeaderName::Require).is_empty(),
            "nothing here asked for 100rel, so this must not go reliably"
        );
        let early = body(&progress);
        assert!(
            !early.is_empty(),
            "the 183 should carry the description this stack wrote"
        );
        poll(handle, 1_100);
        assert_eq!(
            observed.of(SipralEventKind::MediaStarted).len(),
            1,
            "ringing with media should start the session once"
        );

        let (media_address, media_address_len) = as_text(MEDIA);
        let status = unsafe {
            sipral_call_answer_media(handle, call, media_address, media_address_len, 1_200)
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let confirmed = one(handle);
        assert!(start_line(&confirmed).starts_with("SIP/2.0 200"));
        assert_eq!(
            body(&confirmed),
            early,
            "an early answer sent unreliably is only a preview (RFC 6337 §3.1.1); the 200 OK \
             must repeat it unchanged"
        );
        poll(handle, 1_200);
        assert_eq!(
            observed.of(SipralEventKind::MediaStarted).len(),
            1,
            "answering a call already rung with media must not start a second session"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// With 100rel required the 183 goes reliably and is PRACKed, so the 200 OK carries no
    /// description (RFC 6337 §3.1.1, UAS rule #2).
    #[test]
    fn ringing_with_media_reliably_holds_the_200_ok_for_the_prack() {
        let mut observed = Observed::default();
        let (handle, _) = media_line(&mut observed, |_| {});
        deliver(handle, &invitation_with_100rel(true), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);

        let config = ring_media_config();
        let status = unsafe { sipral_call_ring_media(handle, call, ptr::from_ref(&config), 1_100) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let progress = one(handle);
        assert!(start_line(&progress).starts_with("SIP/2.0 183"));
        assert!(
            String::from_utf8_lossy(&field(&progress, HeaderName::Require)).contains("100rel"),
            "the INVITE required 100rel, so this must go reliably"
        );
        let rseq = field(&progress, HeaderName::RSeq);
        assert!(!rseq.is_empty(), "a reliable provisional carries an RSeq");
        poll(handle, 1_100);
        assert_eq!(observed.of(SipralEventKind::MediaStarted).len(), 1);

        let (media_address, media_address_len) = as_text(MEDIA);
        let status = unsafe {
            sipral_call_answer_media(handle, call, media_address, media_address_len, 1_200)
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert!(
            sent(handle).is_empty(),
            "RFC 3262 §5 holds the 200 OK until the 183 is acknowledged"
        );

        let rseq_text = String::from_utf8_lossy(&rseq).into_owned();
        let prack = from_far_end(
            &progress,
            "PRACK",
            "ring-media-prack",
            2,
            &format!("RAck: {rseq_text} 1 INVITE\r\n"),
        );
        deliver(handle, &prack, 1_300);
        let mut messages = sent(handle);
        let at = messages
            .iter()
            .position(|message| field(message, HeaderName::CSeq) == b"1 INVITE")
            .expect("the 200 OK to the INVITE followed the PRACK");
        let final_ok = messages.remove(at);
        assert!(start_line(&final_ok).starts_with("SIP/2.0 200"));
        assert!(
            body(&final_ok).is_empty(),
            "the answer already went out reliably; RFC 6337 §3.1.1 forbids repeating it"
        );
        let prack_ok = messages.pop().expect("the 2xx to the PRACK itself");
        assert!(start_line(&prack_ok).starts_with("SIP/2.0 200"));
        assert_eq!(field(&prack_ok, HeaderName::CSeq), b"2 PRACK");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// Ringing with media twice on one call is refused, as answering twice would be.
    #[test]
    fn ringing_with_media_twice_is_refused() {
        let mut observed = Observed::default();
        let (handle, _) = media_line(&mut observed, |_| {});
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);

        let config = ring_media_config();
        assert_eq!(
            unsafe { sipral_call_ring_media(handle, call, ptr::from_ref(&config), 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let _ = sent(handle);

        let status = unsafe { sipral_call_ring_media(handle, call, ptr::from_ref(&config), 1_150) };
        assert_eq!(status, SipralStatus::WrongState, "{}", last_error_text());
        assert!(
            sent(handle).is_empty(),
            "nothing goes out for a refused second 183"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// Ringing with media after a plain `sipral_call_ring` 180 is no
    /// obstacle — only ringing with media twice is refused.
    #[test]
    fn ringing_with_media_after_a_plain_ring_is_allowed() {
        let mut observed = Observed::default();
        let (handle, _) = media_line(&mut observed, |_| {});
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);

        assert_eq!(
            unsafe { sipral_call_ring(handle, call, ptr::null(), 0, 1_050) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert!(start_line(&one(handle)).starts_with("SIP/2.0 180"));

        let config = ring_media_config();
        let status = unsafe { sipral_call_ring_media(handle, call, ptr::from_ref(&config), 1_100) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert!(start_line(&one(handle)).starts_with("SIP/2.0 183"));
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// An INVITE with no offer cannot be rung with media: the offer belongs in the first
    /// reliable non-failure message (RFC 3261 §13.2.1, RFC 6337 §3.1.2), and its answer would
    /// come in a PRACK (RFC 3262 §5) that nothing here hands on. Refused, nothing sent.
    #[test]
    fn ringing_with_media_an_invite_that_carried_no_offer_is_refused() {
        let mut observed = Observed::default();
        let (handle, _) = media_line(&mut observed, |_| {});
        deliver(handle, &invitation_without_offer(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);

        let config = ring_media_config();
        let status = unsafe { sipral_call_ring_media(handle, call, ptr::from_ref(&config), 1_100) };
        assert_eq!(status, SipralStatus::WrongState, "{}", last_error_text());
        assert!(
            sent(handle).is_empty(),
            "an offer went out in a provisional response to an INVITE that carried none"
        );
        assert_eq!(
            state_of(handle, call),
            SipralCallState::Incoming as u32,
            "the call is still the application's to answer or reject"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// After a 183 the application described, ringing with media is refused: RFC 3261 §13.2.1
    /// allows only "that same exact answer" in other responses, and RFC 6337 §3.1.1 has them
    /// all identical.
    #[test]
    fn ringing_with_media_after_a_183_the_application_described_is_refused() {
        let mut observed = Observed::default();
        let (handle, _) = media_line(&mut observed, |_| {});
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);

        assert_eq!(
            unsafe { sipral_call_ring(handle, call, OFFER.as_ptr(), OFFER.len(), 1_050) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert!(start_line(&one(handle)).starts_with("SIP/2.0 183"));

        let config = ring_media_config();
        let status = unsafe { sipral_call_ring_media(handle, call, ptr::from_ref(&config), 1_100) };
        assert_eq!(status, SipralStatus::WrongState, "{}", last_error_text());
        assert!(
            sent(handle).is_empty(),
            "a second, different description went out in response to the same INVITE"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// `srtp` on the ringing config overrides the stack's: the stack requires SRTP, the call
    /// asks for `OFFERED`, so a plain offer is answered plainly.
    #[test]
    fn ringing_config_srtp_overrides_the_stacks_own() {
        let mut observed = Observed::default();
        let (handle, _) = media_line(&mut observed, |config| {
            config.srtp = SipralSrtp::Required as u32;
        });
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);

        let mut config = ring_media_config();
        config.srtp = SipralSrtp::Offered as u32;
        let status = unsafe { sipral_call_ring_media(handle, call, ptr::from_ref(&config), 1_100) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let progress = String::from_utf8_lossy(&one(handle)).into_owned();
        assert!(
            progress.starts_with("SIP/2.0 183")
                && progress.contains("RTP/AVP")
                && !progress.contains("a=crypto"),
            "the ringing config's OFFERED should have overridden the stack's REQUIRED: {progress}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// `srtp` REQUIRED on the ringing config refuses a plain INVITE exactly as
    /// `sipral_call_answer_media` does, with nothing sent.
    #[test]
    fn ringing_config_srtp_required_refuses_a_plain_invite_offering_no_key() {
        let mut observed = Observed::default();
        let (handle, _) = media_line(&mut observed, |_| {});
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);

        let mut config = ring_media_config();
        config.srtp = SipralSrtp::Required as u32;
        let status = unsafe { sipral_call_ring_media(handle, call, ptr::from_ref(&config), 1_100) };
        assert_eq!(
            status,
            SipralStatus::SecurityPolicy,
            "a plain offer under REQUIRED was rung: {}",
            last_error_text()
        );
        let refused = String::from_utf8_lossy(&one(handle)).into_owned();
        assert!(refused.starts_with("SIP/2.0 488 "), "{refused}");
        assert_ne!(
            state_of(handle, call),
            SipralCallState::Incoming as u32,
            "the call was refused, not left ringing"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// Assert `sipral_call_ring_media` refuses a member it does not read, naming it.
    fn assert_ring_media_refuses(
        handle: SipralHandle,
        call: SipralHandle,
        config: &SipralCallConfig,
        member: &str,
    ) {
        let status = unsafe { sipral_call_ring_media(handle, call, ptr::from_ref(config), 1_100) };
        assert_eq!(
            status,
            SipralStatus::InvalidArgument,
            "{member}: {}",
            last_error_text()
        );
        assert!(sent(handle).is_empty(), "{member}: nothing was built");
    }

    #[test]
    fn ringing_media_config_refuses_everything_but_media_address_and_srtp() {
        let mut observed = Observed::default();
        let (handle, _) = media_line(&mut observed, |_| {});
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);

        let mut with_target = ring_media_config();
        (with_target.target, with_target.target_len) = as_text(TARGET);
        assert_ring_media_refuses(handle, call, &with_target, "target");

        let mut with_sdp = ring_media_config();
        with_sdp.sdp = OFFER.as_ptr();
        with_sdp.sdp_len = OFFER.len();
        assert_ring_media_refuses(handle, call, &with_sdp, "sdp");

        let mut with_destination = ring_media_config();
        (
            with_destination.destination,
            with_destination.destination_len,
        ) = as_text(PEER);
        assert_ring_media_refuses(handle, call, &with_destination, "destination");

        let mut with_forks = ring_media_config();
        with_forks.keep_all_forks = 1;
        assert_ring_media_refuses(handle, call, &with_forks, "keep_all_forks");

        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A member the call does not read is refused when set; one of no bytes is unset whatever
    /// its pointer, since a binding passing buffers has no null to pass.
    #[test]
    fn ringing_media_config_reads_an_empty_member_as_absent_whatever_its_pointer() {
        let mut observed = Observed::default();
        let (handle, _) = media_line(&mut observed, |_| {});
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);

        let mut config = ring_media_config();
        (config.target, config.target_len) = as_text("");
        config.sdp = OFFER.as_ptr();
        config.sdp_len = 0;
        (config.destination, config.destination_len) = as_text("");
        config.headers = std::ptr::NonNull::<crate::header::SipralHeader>::dangling().as_ptr();
        config.headers_len = 0;
        let status = unsafe { sipral_call_ring_media(handle, call, ptr::from_ref(&config), 1_100) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert!(start_line(&one(handle)).starts_with("SIP/2.0 183"));
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A REFER outside any dialog (RFC 3515 §4.1): a switchboard asking this
    /// end's line to ring Carol.
    fn referral(branch: &str) -> Vec<u8> {
        format!(
            "REFER sip:alice@192.0.2.10:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-{branch}\r\n\
Max-Forwards: 70\r\n\
From: <sip:switchboard@example.com>;tag=sb-{branch}\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: {branch}@203.0.113.5\r\n\
CSeq: 7 REFER\r\n\
Contact: <sip:switchboard@203.0.113.5:5060>\r\n\
Refer-To: <sip:carol@example.com>\r\n\
Referred-By: <sip:switchboard@example.com>\r\n\
Content-Length: 0\r\n\r\n"
        )
        .into_bytes()
    }

    /// A stack that takes referrals, with its line, the referral delivered and reported.
    fn referred(observed: &mut Observed, branch: &str) -> (SipralHandle, SipralHandle) {
        let (handle, account) = media_line(observed, |config| {
            config.referrals = crate::media::SipralToggle::On as u32;
        });
        deliver(handle, &referral(branch), 1_000);
        poll(handle, 1_000);
        let asked = observed
            .referrals
            .first()
            .expect("the referral was reported");
        assert_eq!(asked.account, account, "the line it arrived for");
        assert_eq!(asked.status_code, 0, "waiting, not lapsed");
        assert!(
            sent(handle)
                .iter()
                .all(|message| !start_line(message).starts_with("SIP/2.0 ")),
            "nothing is answered on the application's behalf"
        );
        (handle, asked.referral)
    }

    fn call_state_status(stack: SipralHandle, call: SipralHandle) -> SipralStatus {
        let mut state = u32::MAX;
        unsafe { sipral_call_state(stack, call, &raw mut state) }
    }

    #[test]
    fn a_referral_is_refused_403_on_a_stack_that_did_not_take_them() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        deliver(handle, &referral("off"), 1_000);
        poll(handle, 1_000);
        assert_eq!(start_line(&one(handle)), "SIP/2.0 403 Forbidden");
        assert!(observed.referrals.is_empty(), "and nobody is asked");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// `target` on a transfer's config is refused when set; one of no bytes is unset,
    /// whatever its pointer.
    #[test]
    fn a_transfer_config_with_an_empty_target_pointer_is_taken() {
        let mut observed = Observed::default();
        let (handle, referral) = referred(&mut observed, "empty");
        let mut config = managed_transfer_config();
        (config.target, config.target_len) = as_text("");
        let mut placed = SIPRAL_HANDLE_NONE;
        let status = unsafe {
            sipral_call_accept_transfer(
                handle,
                referral,
                ptr::from_ref(&config),
                &raw mut placed,
                1_100,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(placed, SIPRAL_HANDLE_NONE);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_referral_says_what_it_asks_and_is_taken_like_a_transfer() {
        let mut observed = Observed::default();
        let (handle, referral) = referred(&mut observed, "take");
        let asked = observed.referrals[0].clone();
        assert_ne!(referral, SIPRAL_HANDLE_NONE);
        assert_eq!(asked.target, "sip:carol@example.com");
        assert_eq!(asked.attended, 0);
        assert_eq!(
            asked.referred_by.as_deref(),
            Some("<sip:switchboard@example.com>")
        );
        assert!(asked.message_len > 0, "the REFER rides along whole");
        assert_eq!(
            call_state_status(handle, referral),
            SipralStatus::WrongState,
            "a referral is not a call: {}",
            last_error_text()
        );

        let mut placed = SIPRAL_HANDLE_NONE;
        let status = unsafe {
            sipral_call_accept_transfer(
                handle,
                referral,
                ptr::from_ref(&managed_transfer_config()),
                &raw mut placed,
                1_100,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(placed, SIPRAL_HANDLE_NONE);
        assert_ne!(placed, referral, "the call placed is a call of its own");
        let out = sent(handle);
        let lines: Vec<String> = out.iter().map(|message| start_line(message)).collect();
        assert!(
            lines.iter().any(|line| line == "SIP/2.0 202 Accepted"),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("NOTIFY sip:switchboard@203.0.113.5:5060")),
            "{lines:?}"
        );
        let invite = out
            .iter()
            .find(|message| start_line(message).starts_with("INVITE sip:carol@example.com"))
            .expect("the call it asked for");
        assert_eq!(
            field(invite, HeaderName::ReferredBy),
            b"<sip:switchboard@example.com>"
        );
        assert_eq!(state_of(handle, placed), SipralCallState::Calling as u32);

        // the referral's handle is spent with its answer
        assert_eq!(
            call_state_status(handle, referral),
            SipralStatus::StaleHandle
        );
        let again = unsafe {
            sipral_call_accept_transfer(
                handle,
                referral,
                ptr::from_ref(&managed_transfer_config()),
                &raw mut placed,
                1_200,
            )
        };
        assert_eq!(again, SipralStatus::StaleHandle);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_referral_is_refused_with_a_refusal_and_its_handle_goes_with_it() {
        let mut observed = Observed::default();
        let (handle, referral) = referred(&mut observed, "refuse");
        // RFC 3515 §2.4.2's refusals are 4xx-6xx; a 2xx would say it was taken
        assert_eq!(
            unsafe { sipral_call_reject_transfer(handle, referral, 200, 1_100) },
            SipralStatus::InvalidArgument
        );
        assert!(sent(handle).is_empty(), "and nothing went");
        assert_eq!(
            unsafe { sipral_call_reject_transfer(handle, referral, 603, 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(start_line(&one(handle)), "SIP/2.0 603 Decline");
        assert_eq!(
            call_state_status(handle, referral),
            SipralStatus::StaleHandle
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_referral_nobody_answers_is_reported_lapsed_and_its_handle_goes() {
        let mut observed = Observed::default();
        let (handle, referral) = referred(&mut observed, "lapse");
        poll(handle, 1_000 + 32_000);
        let lapsed = observed.referrals.get(1).expect("the lapse was reported");
        assert_eq!(lapsed.referral, referral, "about the same referral");
        assert_eq!(lapsed.status_code, 408);
        assert!(lapsed.target.is_empty() && lapsed.referred_by.is_none());
        assert!(
            sent(handle)
                .iter()
                .any(|message| start_line(message) == "SIP/2.0 408 Request Timeout"),
            "the REFER was answered for the application"
        );
        assert_eq!(
            call_state_status(handle, referral),
            SipralStatus::StaleHandle
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }
}
