// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Who is on a call beyond its `From`, how it asked to be answered, why it
//! ended, and where to send it instead — across the boundary.
//!
//! What the network says about a caller (RFC 3325's asserted identity,
//! `Remote-Party-ID`, `verstat`), what the caller asked to keep private
//! (RFC 3323), where the call was diverted from (RFC 5806, RFC 7044), how it
//! asked to be answered (RFC 5373, `Alert-Info`) and why the far end ended it
//! (RFC 3326) are read by the stack and handed to C typed: the facts most
//! applications show ride on every call event (`sipral_call_event_t`), and
//! the lists behind them are read one entry at a time with
//! [`sipral_call_identity_count`] and [`sipral_call_identity_text`].
//!
//! The asserted identity is behind the account's trust gate:
//! `trusted_peers` on `sipral_account_config_t` names the peers whose
//! assertions are believed (RFC 3325 §8), and from anywhere else it is left
//! out. `privacy` on the same struct places the account's calls
//! anonymously (RFC 3323). `docs/04-ua.md` has the reasoning.

use std::ffi::c_char;
use std::sync::Arc;

use sipral_core::msg::{StatusCode, Uri};
use sipral_ua::{
    AnswerMode, AnswerModeField, CallIdentity, Privacy, Reason, Redirect, RingSource, Verstat,
};

use crate::abi::{codes, constants};
use crate::call::ua_failed;
use crate::diagnostics::copy_out;
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::stack::{StackState, handle_failed, with_stack, with_stack_at};
use crate::status::SipralStatus;
use crate::text::text;

constants! {
    /// Bits of `sipral_call_event_t::privacy` and of
    /// `sipral_account_config_t::privacy` (RFC 3323 §4.2): `header`, obscure
    /// the fields that could identify the caller.
    pub const SIPRAL_PRIVACY_HEADER: u32 = 1 << 0;
    /// `session`: hide the session description from the far end.
    pub const SIPRAL_PRIVACY_SESSION: u32 = 1 << 1;
    /// `user`: user-level privacy.
    pub const SIPRAL_PRIVACY_USER: u32 = 1 << 2;
    /// `id` (RFC 3325 §9.3): keep the asserted identity inside the trust
    /// domain. What "withhold my number" asks for.
    pub const SIPRAL_PRIVACY_ID: u32 = 1 << 3;
    /// `critical`: fail the call rather than go without the privacy asked
    /// for.
    pub const SIPRAL_PRIVACY_CRITICAL: u32 = 1 << 4;
    /// `none`: no privacy, stated. Read only; an account asks for none by
    /// leaving every bit clear.
    pub const SIPRAL_PRIVACY_NONE: u32 = 1 << 5;
}

codes! {
    /// The verdict a terminating network reached on the caller's number
    /// (3GPP TS 24.229's `verstat`, the mark STIR/SHAKEN leaves). Names for
    /// `sipral_call_event_t::verstat`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralVerstat: u32 {
        /// Nothing said, or said by a peer the account does not trust.
        None = 0,
        /// `TN-Validation-Passed`.
        Passed = 1,
        /// `TN-Validation-Failed`.
        Failed = 2,
        /// `No-TN-Validation`.
        NotValidated = 3,
        /// Some other value.
        Other = 4,
    }
}

codes! {
    /// `Answer-Mode` and `Priv-Answer-Mode` (RFC 5373 §3). Names for
    /// `sipral_call_event_t::answer_mode` and `priv_answer_mode`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralAnswerMode: u32 {
        /// The INVITE carried no such field.
        None = 0,
        /// `Manual`: wait for the user.
        Manual = 1,
        /// `Auto`: answer without waiting for the user.
        Auto = 2,
        /// Any other value, which RFC 5373 has ignored.
        Other = 3,
    }
}

codes! {
    /// Where the ring says the caller is. Names for
    /// `sipral_call_event_t::ring_source`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralRingSource: u32 {
        /// Nothing said.
        Unknown = 0,
        /// Another extension of the same switch.
        Internal = 1,
        /// The outside world.
        External = 2,
    }
}

codes! {
    /// Which list, and which piece of each entry, [`sipral_call_identity_count`]
    /// and [`sipral_call_identity_text`] are asked about.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralIdentityText: u32 {
        /// Never asked for.
        Unknown = 0,
        /// `P-Asserted-Identity`: the URI of each asserted party.
        Asserted = 1,
        /// And each one's display name.
        AssertedDisplay = 2,
        /// `Remote-Party-ID`: the URI of each party named.
        RemoteParty = 3,
        /// And each one's display name.
        RemotePartyDisplay = 4,
        /// `Diversion`, most recent first: who the call was diverted from.
        Diversion = 5,
        /// And the display name beside it.
        DiversionDisplay = 6,
        /// And why: `no-answer`, `user-busy`, `unconditional` and the rest.
        DiversionReason = 7,
        /// `History-Info`: the URI of each target the request was sent to.
        History = 8,
        /// And each entry's `index`.
        HistoryIndex = 9,
        /// Every `Alert-Info` URI.
        AlertInfo = 10,
        /// Every `info=` value on `Alert-Info`.
        AlertName = 11,
        /// The calling number this stack's verification found a valid
        /// PASSporT signed for (RFC 8224 §6.2), canonical: one entry, or none
        /// when nothing verified. ABI 0.31.
        VerifiedOrig = 12,
        /// Its origination identifier (RFC 8588 §5), a UUID.
        VerifiedOrigid = 13,
        /// The URL of the certificate it was verified against, or that could
        /// not be had.
        VerificationCertificate = 14,
        /// Why it did not verify, in words, for a log.
        VerificationDetail = 15,
    }
}

codes! {
    /// How an account's calls ask for a session timer (RFC 4028). Names for
    /// `sipral_account_config_t::session_timer`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralSessionTimer: u32 {
        /// The stack's default: thirty minutes, RFC 4028 §4's recommendation.
        Default = 0,
        /// Ask for none. A far end that insists on one is still honoured.
        Off = 1,
        /// Ask for `session_interval_seconds`, at least 90 (§5's floor).
        Interval = 2,
    }
}

/// `privacy` as the bits C reads.
pub(crate) const fn privacy_bits(privacy: Privacy) -> u32 {
    let mut bits = 0;
    if privacy.header {
        bits |= SIPRAL_PRIVACY_HEADER;
    }
    if privacy.session {
        bits |= SIPRAL_PRIVACY_SESSION;
    }
    if privacy.user {
        bits |= SIPRAL_PRIVACY_USER;
    }
    if privacy.id {
        bits |= SIPRAL_PRIVACY_ID;
    }
    if privacy.critical {
        bits |= SIPRAL_PRIVACY_CRITICAL;
    }
    if privacy.none {
        bits |= SIPRAL_PRIVACY_NONE;
    }
    bits
}

/// The privacy an account asks for, from the bits C wrote.
pub(crate) fn privacy_of(bits: u32) -> Result<Privacy, Fail> {
    let known = SIPRAL_PRIVACY_HEADER
        | SIPRAL_PRIVACY_SESSION
        | SIPRAL_PRIVACY_USER
        | SIPRAL_PRIVACY_ID
        | SIPRAL_PRIVACY_CRITICAL;
    if bits & !known != 0 {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "privacy is {bits:#x}, and only SIPRAL_PRIVACY_HEADER, _SESSION, _USER, _ID and \
                 _CRITICAL are privacy an account can ask for"
            ),
        ));
    }
    Ok(Privacy {
        header: bits & SIPRAL_PRIVACY_HEADER != 0,
        session: bits & SIPRAL_PRIVACY_SESSION != 0,
        user: bits & SIPRAL_PRIVACY_USER != 0,
        id: bits & SIPRAL_PRIVACY_ID != 0,
        critical: bits & SIPRAL_PRIVACY_CRITICAL != 0,
        none: false,
    })
}

pub(crate) const fn verstat_code(verstat: Option<&Verstat>) -> SipralVerstat {
    match verstat {
        None => SipralVerstat::None,
        Some(Verstat::Passed) => SipralVerstat::Passed,
        Some(Verstat::Failed) => SipralVerstat::Failed,
        Some(Verstat::NotValidated) => SipralVerstat::NotValidated,
        Some(_) => SipralVerstat::Other,
    }
}

pub(crate) const fn answer_mode_code(field: Option<&AnswerModeField>) -> (SipralAnswerMode, u32) {
    match field {
        None => (SipralAnswerMode::None, 0),
        Some(field) => (
            match field.mode {
                AnswerMode::Manual => SipralAnswerMode::Manual,
                AnswerMode::Auto => SipralAnswerMode::Auto,
                _ => SipralAnswerMode::Other,
            },
            field.required as u32,
        ),
    }
}

pub(crate) const fn ring_source_code(source: Option<RingSource>) -> SipralRingSource {
    match source {
        Some(RingSource::Internal) => SipralRingSource::Internal,
        Some(RingSource::External) => SipralRingSource::External,
        _ => SipralRingSource::Unknown,
    }
}

/// What this stack read about a call it still knows.
fn identity_of(state: &StackState, call: SipralHandle) -> Result<Arc<CallIdentity>, Fail> {
    let id = state.calls.get(call).map_err(handle_failed)?;
    state.identities.get(&id).cloned().ok_or_else(|| {
        fail(
            SipralStatus::WrongState,
            "this call has no identity read yet: it is a referral, or its request could not be \
             read",
        )
    })
}

/// A list, as the texts of one piece of each of its entries.
fn pieces(identity: &CallIdentity, which: SipralIdentityText) -> Vec<&[u8]> {
    let caller = &identity.caller;
    let answering = &identity.answering;
    match which {
        SipralIdentityText::Asserted => caller.asserted.iter().map(|one| &*one.uri).collect(),
        SipralIdentityText::AssertedDisplay => {
            caller.asserted.iter().map(|one| &*one.display).collect()
        }
        SipralIdentityText::RemoteParty => caller
            .remote_party
            .iter()
            .map(|one| &*one.party.uri)
            .collect(),
        SipralIdentityText::RemotePartyDisplay => caller
            .remote_party
            .iter()
            .map(|one| &*one.party.display)
            .collect(),
        SipralIdentityText::Diversion => caller
            .diversions
            .iter()
            .map(|one| &*one.party.uri)
            .collect(),
        SipralIdentityText::DiversionDisplay => caller
            .diversions
            .iter()
            .map(|one| &*one.party.display)
            .collect(),
        SipralIdentityText::DiversionReason => caller
            .diversions
            .iter()
            .map(|one| one.reason.as_deref().map_or(&b""[..], str::as_bytes))
            .collect(),
        SipralIdentityText::History => caller.history.iter().map(|one| &*one.party.uri).collect(),
        SipralIdentityText::HistoryIndex => caller
            .history
            .iter()
            .map(|one| one.index.as_bytes())
            .collect(),
        SipralIdentityText::AlertInfo => answering.alert_info.iter().map(|one| &**one).collect(),
        SipralIdentityText::AlertName => answering
            .alert_names
            .iter()
            .map(|one| one.as_bytes())
            .collect(),
        SipralIdentityText::VerifiedOrig => verified(caller, |verdict| verdict.orig.as_deref()),
        SipralIdentityText::VerifiedOrigid => verified(caller, |verdict| verdict.origid.as_deref()),
        SipralIdentityText::VerificationCertificate => {
            verified(caller, |verdict| verdict.certificate_url.as_deref())
        }
        SipralIdentityText::VerificationDetail => {
            verified(caller, |verdict| verdict.detail.as_deref())
        }
        SipralIdentityText::Unknown => Vec::new(),
    }
}

/// One text of this stack's own verdict on the caller, as a list of one or
/// none.
fn verified<'a>(
    caller: &'a sipral_ua::CallerIdentity,
    piece: impl Fn(&'a sipral_ua::CallerVerification) -> Option<&'a str>,
) -> Vec<&'a [u8]> {
    caller
        .verification
        .as_ref()
        .and_then(piece)
        .map(str::as_bytes)
        .into_iter()
        .collect()
}

fn which_of(which: u32) -> Result<SipralIdentityText, Fail> {
    Ok(match which {
        1 => SipralIdentityText::Asserted,
        2 => SipralIdentityText::AssertedDisplay,
        3 => SipralIdentityText::RemoteParty,
        4 => SipralIdentityText::RemotePartyDisplay,
        5 => SipralIdentityText::Diversion,
        6 => SipralIdentityText::DiversionDisplay,
        7 => SipralIdentityText::DiversionReason,
        8 => SipralIdentityText::History,
        9 => SipralIdentityText::HistoryIndex,
        10 => SipralIdentityText::AlertInfo,
        11 => SipralIdentityText::AlertName,
        12 => SipralIdentityText::VerifiedOrig,
        13 => SipralIdentityText::VerifiedOrigid,
        14 => SipralIdentityText::VerificationCertificate,
        15 => SipralIdentityText::VerificationDetail,
        other => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("{other} is not a SIPRAL_IDENTITY_TEXT this library names"),
            ));
        }
    })
}

entry! {
    /// How many entries one of a call's identity lists has:
    /// `SIPRAL_IDENTITY_TEXT_DIVERSION` for the `Diversion` values,
    /// `SIPRAL_IDENTITY_TEXT_HISTORY` for the `History-Info` entries, and so
    /// on — each piece of an entry answers the same count as the entry.
    ///
    /// Read once, as the INVITE arrived, and the same for the rest of the
    /// call. A call this end placed has none of them: zero.
    ///
    /// # Safety
    ///
    /// `out_count` must point at one `size_t`.
    fn sipral_call_identity_count(
        stack: SipralHandle,
        call: SipralHandle,
        which: u32,
        out_count: *mut usize,
    ) {
        if out_count.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_count is null"));
        }
        let which = which_of(which)?;
        with_stack(stack, |state| {
            let identity = identity_of(state, call)?;
            unsafe { out_count.write(pieces(&identity, which).len()) };
            Ok(())
        })
    }
}

entry! {
    /// One piece of one entry of a call's identity lists, copied into the
    /// caller's buffer with a trailing NUL: the shape
    /// `sipral_subscription_dialog_text` has, for the same reason — the text
    /// is the library's, and a pointer to it is one a caller could outlive.
    ///
    /// `out_needed` always receives the bytes needed including the NUL, so a
    /// caller that brought nothing can ask with `capacity` zero and ask again
    /// with room; a buffer too small is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with
    /// nothing written. A piece the entry does not have — a display name
    /// the field did not write — is one byte, the NUL. An index past the
    /// end is `SIPRAL_STATUS_INVALID_ARGUMENT`.
    ///
    /// # Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or null with a capacity
    /// of zero, and `out_needed` must point at one `size_t`.
    fn sipral_call_identity_text(
        stack: SipralHandle,
        call: SipralHandle,
        which: u32,
        index: usize,
        buffer: *mut c_char,
        capacity: usize,
        out_needed: *mut usize,
    ) {
        if out_needed.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_needed is null"));
        }
        let which = which_of(which)?;
        with_stack(stack, |state| {
            let identity = identity_of(state, call)?;
            let listed = pieces(&identity, which);
            let Some(piece) = listed.get(index) else {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    format!("index {index} is past the {} entries there are", listed.len()),
                ));
            };
            let text = String::from_utf8_lossy(piece);
            unsafe { copy_out(&text, buffer, capacity, out_needed) }
        })
    }
}

entry! {
    /// End a call and say why (RFC 3326): what `sipral_call_hangup` does, with
    /// a `Reason` on the BYE or the CANCEL it turns into.
    ///
    /// `sip_cause` is a SIP status and `q850_cause` a Q.850 cause, each zero
    /// for none; both may be given, and neither is a plain hangup. `text`, when
    /// given, goes on the first value written: the SIP one, or the Q.850 one
    /// when there is no SIP one. On the refusal of a call that came in and was
    /// never answered only the Q.850 value goes (RFC 6432): a SIP one would
    /// repeat the status the refusal carries.
    ///
    /// # Safety
    ///
    /// `text` must be readable for `text_len` bytes or null with a length of
    /// zero.
    fn sipral_call_hangup_for(
        stack: SipralHandle,
        call: SipralHandle,
        sip_cause: u32,
        q850_cause: u32,
        text: *const c_char,
        text_len: usize,
        now_ms: u64,
    ) {
        let said = unsafe { crate::text::text(text, text_len, "text") }?.unwrap_or("");
        let cause = |value: u32, name: &str| {
            u16::try_from(value).map_err(|_| {
                fail(
                    SipralStatus::InvalidArgument,
                    format!("{name} is {value}, and a cause is a number up to 65535"),
                )
            })
        };
        let mut reasons = Vec::new();
        if sip_cause != 0 {
            reasons.push(Reason::sip(cause(sip_cause, "sip_cause")?, said));
        }
        if q850_cause != 0 {
            let with = if reasons.is_empty() { said } else { "" };
            reasons.push(Reason::q850(cause(q850_cause, "q850_cause")?, with));
        }
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            state
                .agent
                .hangup_for(id, &reasons, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Answer a call that came in with a 3xx: somewhere else to try
    /// (RFC 3261 §21.3), and why (RFC 5806).
    ///
    /// `status_code` is 300 to 399, 302 for call forwarding. `targets` is where to
    /// try, as URIs separated by commas, in the order of preference; one is
    /// required for every status but 380. `reason`, when given, is the
    /// `Diversion` reason — `no-answer`, `user-busy`, `unconditional`,
    /// `deflection`, `do-not-disturb` or any other token — and puts a
    /// `Diversion` naming the address that was called on the answer, above
    /// the ones the INVITE already carried.
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for another status, a target that is
    /// not a URI, or none where one is needed; `SIPRAL_STATUS_WRONG_STATE` for
    /// a call that is not waiting to be answered.
    ///
    /// # Safety
    ///
    /// `targets` must be readable for `targets_len` bytes and `reason` for
    /// `reason_len` bytes, each or null with a length of zero.
    fn sipral_call_redirect(
        stack: SipralHandle,
        call: SipralHandle,
        status_code: u32,
        targets: *const c_char,
        targets_len: usize,
        reason: *const c_char,
        reason_len: usize,
        now_ms: u64,
    ) {
        let written = u16::try_from(status_code)
            .ok()
            .and_then(|code| StatusCode::new(code).ok())
            .ok_or_else(|| {
                fail(
                    SipralStatus::InvalidArgument,
                    format!("status_code is {status_code}, which is not a status code"),
                )
            })?;
        let mut redirect = Redirect::with_status(written).map_err(|error| ua_failed(&error))?;
        let listed = unsafe { text(targets, targets_len, "targets") }?.unwrap_or("");
        for target in listed.split(',').map(str::trim).filter(|one| !one.is_empty()) {
            let uri = Uri::parse_str(target).map_err(|error| {
                fail(
                    SipralStatus::InvalidArgument,
                    format!("{target:?} in targets is not a URI: {error}"),
                )
            })?;
            redirect = redirect.to(uri);
        }
        if let Some(why) = unsafe { text(reason, reason_len, "reason") }? {
            redirect = redirect.diverted(why);
        }
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            state
                .agent
                .redirect(id, &redirect, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}
