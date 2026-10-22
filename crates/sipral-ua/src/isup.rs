// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! SIP-T and SIP-I: the ISUP a carrier gateway carries inside SIP, and what
//! this agent makes of it.
//!
//! A gateway between SIP and the telephone network puts the ISUP message of
//! the call in the SIP message that carries it (RFC 3372, ITU-T Q.1912.5):
//! an IAM beside the INVITE's offer, ACM and CPG on the 18x, ANM or CON on
//! the 200, REL on the BYE or on a refusal. RFC 3204's `application/ISUP`
//! is the body, alone or as a part of `multipart/mixed` beside the SDP.
//!
//! # What this agent does with it
//!
//! - **It understands the body.** An INVITE, re-INVITE, UPDATE, PRACK or
//!   INFO carrying ISUP of a variant [`sipral_core::isup`] reads — ITU-T or
//!   ETSI, or a `version` with no `base` that says otherwise — is taken,
//!   whatever its `handling`; the SDP beside it is the session description.
//!   A part marked `handling=required` that is not understood, ANSI ISUP
//!   among them, is refused with 415 and an `Accept` listing what is (RFC
//!   3261 §8.2.3, RFC 3204 §6, RFC 5621 §8.4); marked optional, it is
//!   ignored.
//! - **The caller, from the IAM, where SIP says less** (RFC 3398 §8.2.1,
//!   ITU-T Q.1912.5 Table 7-4): [`CallerIdentity::isup`] holds what the
//!   IAM says about the call; a calling party number whose presentation is
//!   restricted asks for `Privacy: id` whatever `From` says, so a withheld
//!   number stays withheld; from a trusted peer, with no
//!   `P-Asserted-Identity` and no `Remote-Party-ID`, a calling party number
//!   the network provided or verified, its presentation allowed or
//!   restricted, is the asserted identity — one restricted by the network,
//!   or not available, is not; and with no `Diversion` and no
//!   `History-Info`, the redirecting and original called numbers are the
//!   diversions, most recent first, with the reasons the redirection
//!   information gives.
//! - **The release cause, from the REL**, into the Q.850 cause the call's end
//!   is reported with, when no `Reason` header gave one: RFC 3398 §7.2.3
//!   prefers the header when both are there.
//!
//! A number becomes a URI only when it is international, as `tel:+` and its
//! digits: a national or subscriber number is a global one only with the
//! country it belongs to, which the gateway knows and this end does not, and
//! a `tel:` URI for a local number needs that context (RFC 3966 §5.1.5).
//! Such a number stays in [`IsupCaller`](crate::isup::IsupCaller), digits and nature.
//!
//! # What it sends
//!
//! No ISUP. RFC 3372 §4.1: generating the encapsulated ISUP is "not the
//! responsibility of an IP endpoint like a SIP phone"; the gateway at the
//! other end writes the ISUP for the network from the SIP it receives
//! (§4.2, RFC 3398 §10.1 for a BYE). [`IsupBuilder`](sipral_core::isup::IsupBuilder) is there for an
//! application that is a gateway.
//!
//! [`CallerIdentity::isup`]: crate::CallerIdentity::isup

pub use sipral_core::isup::{
    BackwardCall, CallEvent, CalledStatus, Cause, CodingStandard, EventKind, ForwardCall,
    GenericNumber, Isup, IsupBody, IsupBuilder, IsupError, Location, MessageType, Nature,
    NatureOfConnection, Number, NumberQualifier, NumberingPlan, Parameters, Presentation,
    RedirectReason, RedirectingIndicator, Redirection, Screening, Variant, cause_name, code, parse,
};
use sipral_core::msg::{BodyPart, MediaTypeRef, OwnedMessage, RawMessage};

use crate::identity::{CallerIdentity, Diversion, Party};
use crate::reason::{Reason, ReasonProtocol};

/// What the IAM of an incoming call said about it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct IsupCaller {
    /// The IAM, as the gateway carried it, from its message type code on.
    pub message: Box<[u8]>,
    /// The body's `version` parameter (RFC 3204 §3.1), when it had one.
    pub version: Option<Box<str>>,
    /// The calling party number, with its presentation and screening.
    pub calling: Option<Number>,
    /// Every generic number qualified as an additional calling party number:
    /// what a caller with a special arrangement presents beside the
    /// network's own number.
    pub additional_calling: Box<[Number]>,
    /// The called party number.
    pub called: Option<Number>,
    /// The original called number: who the call was first placed to.
    pub original_called: Option<Number>,
    /// The redirecting number: who the call was last redirected from.
    pub redirecting: Option<Number>,
    /// Why, and how often.
    pub redirection: Option<Redirection>,
    /// The calling party's category: `0x0a` an ordinary subscriber, `0x0f` a
    /// payphone.
    pub category: Option<u8>,
}

impl IsupCaller {
    fn of(message: &Isup<'_>, body: &IsupBody<'_>) -> Self {
        Self {
            message: Box::from(message.bytes()),
            version: body
                .version()
                .and_then(|version| std::str::from_utf8(&version).ok().map(Box::from)),
            calling: message.calling_party(),
            additional_calling: message
                .generic_numbers()
                .filter(|generic| generic.qualifier == NumberQualifier::AdditionalCalling)
                .map(|generic| generic.number)
                .collect(),
            called: message.called_party(),
            original_called: message.original_called(),
            redirecting: message.redirecting(),
            redirection: message.redirection(),
            category: message.calling_category(),
        }
    }
}

/// The ISUP body of a message, when it has one this crate reads: a variant
/// [`Variant::readable`] names, and a message that parses.
#[must_use]
pub fn isup_of(message: &OwnedMessage) -> Option<Isup<'_>> {
    readable(&message.as_raw())
}

fn readable<'a>(message: &RawMessage<'a>) -> Option<Isup<'a>> {
    let body = IsupBody::find(message)?;
    if !body.variant().readable() {
        return None;
    }
    body.parse().ok()
}

/// Whether a body part is one this agent understands in a request that
/// carries a session: SDP, or ISUP of a variant it reads.
pub(crate) fn understood_part(part: &BodyPart<'_>) -> bool {
    part.is("application", "sdp")
        || part
            .content_type()
            .is_some_and(|media| readable_type(&media))
}

/// Whether an `application/ISUP` media type names a variant this crate
/// reads (RFC 3204 §3.1's `version`, then `base`).
pub(crate) fn readable_type(media: &MediaTypeRef<'_>) -> bool {
    media.is("application", "isup") && Variant::of_media(media).readable()
}

/// Read the IAM an incoming INVITE carries into what it says about the
/// caller (see the module's documentation).
pub(crate) fn read_caller(identity: &mut CallerIdentity, request: &RawMessage<'_>, trusted: bool) {
    let Some(body) = IsupBody::find(request) else {
        return;
    };
    if !body.variant().readable() {
        return;
    }
    let Ok(message) = body.parse() else {
        return;
    };
    if message.message_type() != MessageType::InitialAddress {
        return;
    }
    let caller = IsupCaller::of(&message, &body);
    if let Some(calling) = &caller.calling {
        // Q.1912.5 Table 7-4: allowed or restricted, the number is asserted
        // and a restricted one asks for `id`; restricted by the network, or
        // not available, it is not asserted at all
        let presentation = calling.presentation;
        if presentation == Some(Presentation::Restricted) {
            identity.privacy.id = true;
        }
        let presentable = matches!(
            presentation,
            Some(Presentation::Allowed | Presentation::Restricted)
        );
        let vouched = calling.screening.is_some_and(Screening::vouched);
        if trusted
            && vouched
            && presentable
            && identity.asserted.is_empty()
            && identity.remote_party.is_empty()
            && let Some(uri) = global_uri(calling)
        {
            identity.asserted = Box::from([party(uri)]);
        }
    }
    if identity.diversions.is_empty() && identity.history.is_empty() {
        identity.diversions = diversions_of(&caller);
    }
    identity.isup = Some(caller);
}

/// `tel:+` and the digits, for an international number of decimal digits.
fn global_uri(number: &Number) -> Option<String> {
    (number.nature == Nature::International && number.is_dialable())
        .then(|| format!("tel:+{}", number.digits))
}

fn party(uri: String) -> Party {
    Party {
        uri: uri.into_bytes().into_boxed_slice(),
        ..Party::default()
    }
}

/// The diversions the IAM's redirecting and original called numbers stand
/// for, most recent first, as `Diversion` values would say them (RFC 5806
/// §4): the reason, how many diversions each value covers, and whether the
/// number may be shown.
fn diversions_of(caller: &IsupCaller) -> Box<[Diversion]> {
    let redirection = caller.redirection;
    let all_restricted = redirection.is_some_and(|info| info.indicator.all_restricted());
    let privacy = |number: &Number| {
        let withheld = all_restricted || number.presentation.is_some_and(Presentation::withheld);
        Some(Box::from(if withheld { "full" } else { "off" }))
    };
    let total = redirection
        .and_then(|info| info.counter)
        .filter(|count| *count > 0);
    let original = caller.original_called.as_ref().filter(|first| {
        caller
            .redirecting
            .as_ref()
            .is_none_or(|last| last.digits != first.digits)
    });
    let mut out = Vec::with_capacity(2);
    if let Some(last) = &caller.redirecting
        && let Some(uri) = global_uri(last)
    {
        out.push(Diversion {
            party: party(uri),
            reason: Some(Box::from(
                redirection
                    .and_then(|info| info.reason)
                    .unwrap_or(RedirectReason::Unknown)
                    .diversion_reason(),
            )),
            // the first diversion is the original called number's own
            counter: total.map(|count| {
                if original.is_some() {
                    count.saturating_sub(1).max(1)
                } else {
                    count
                }
            }),
            privacy: privacy(last),
            ..Diversion::default()
        });
    }
    if let Some(first) = original
        && let Some(uri) = global_uri(first)
    {
        out.push(Diversion {
            party: party(uri),
            reason: Some(Box::from(
                redirection
                    .map_or(RedirectReason::Unknown, |info| info.original_reason)
                    .diversion_reason(),
            )),
            counter: total.map(|_| 1),
            privacy: privacy(first),
            ..Diversion::default()
        });
    }
    out.into_boxed_slice()
}

/// The Q.850 cause an ISUP REL in this message carries, as the `Reason` it
/// stands for, named as Q.850 names it.
pub(crate) fn release_reason(message: &RawMessage<'_>) -> Option<Reason> {
    let release = readable(message)?;
    if release.message_type() != MessageType::Release {
        return None;
    }
    let cause = release.cause()?;
    Some(Reason::q850(
        u16::from(cause.value),
        cause.name().unwrap_or(""),
    ))
}

/// The end's causes with the REL's added, when no `Reason` gave a Q.850 one
/// (RFC 3398 §7.2.3 prefers the header).
pub(crate) fn with_release_cause(
    causes: Box<[Reason]>,
    message: Option<&OwnedMessage>,
) -> Box<[Reason]> {
    if causes
        .iter()
        .any(|cause| cause.protocol == ReasonProtocol::Q850)
    {
        return causes;
    }
    let Some(release) = message.and_then(|message| release_reason(&message.as_raw())) else {
        return causes;
    };
    let mut out = causes.into_vec();
    out.push(release);
    out.into_boxed_slice()
}
