// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The ISUP a carrier gateway carries inside SIP, across the boundary (ABI
//! 1.4).
//!
//! What a call needs from it reaches C without asking: the caller's number,
//! its presentation and the diversions an IAM says are folded into the
//! caller's identity (`sipral_call_event_t::asserted_uri`, `privacy`,
//! `diverted_from`, and the identity lists, `SIPRAL_IDENTITY_TEXT_ISUP_*`
//! among them), and a REL's cause into a call's end (`cause_q850`,
//! `cause_text`). `docs/04-ua.md` has the mapping.
//!
//! The raw message is for an application that wants more. Every event that
//! carries a SIP message carries it whole (`sipral_event_t::message`):
//! [`sipral_message_isup`] finds the ISUP body in it, alone or as one part of
//! a multipart body; [`sipral_isup_read`] reads that body's message type,
//! cause, event, calling number and redirection into a
//! [`SipralIsup`]; [`sipral_isup_number`] writes any of its numbers out as
//! text. None of the three needs a stack.

use std::ffi::c_char;

use sipral_core::isup::{Isup, IsupBody, Number as IsupNumber, NumberQualifier, parse};
use sipral_core::msg::ParseScratch;

use crate::abi::{Number, codes, record};
use crate::diagnostics::copy_out;
use crate::error::{Fail, entry, fail};
use crate::header::{offset_in, parsed};
use crate::status::SipralStatus;
use crate::text::bytes;
use crate::versioned::{Versioned, declared_size, write_versioned};

codes! {
    /// Which number of an ISUP message [`sipral_isup_number`] writes out.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralIsupNumber: u32 {
        /// Never asked for.
        Unknown = 0,
        /// The calling party number (Q.763 §3.10).
        Calling = 1,
        /// The called party number of an IAM (§3.9).
        Called = 2,
        /// The original called number (§3.39): who the call was first placed
        /// to.
        OriginalCalled = 3,
        /// The redirecting number (§3.44): who it was last diverted from.
        Redirecting = 4,
        /// The redirection number (§3.46): where an ACM, a CPG or an ANM says
        /// it is diverted to.
        Redirection = 5,
        /// The connected number (§3.16) of an ANM, a CON or a CPG.
        Connected = 6,
        /// The first generic number qualified as an additional calling party
        /// number (§3.26).
        AdditionalCalling = 7,
    }
}

record! {
    /// What one ISUP message says, as far as an endpoint reads it (ITU-T
    /// Q.763), filled by [`sipral_isup_read`]. ABI 1.4.
    ///
    /// Every value is the Recommendation's own number for it, so its tables
    /// name them; a member whose parameter the message did not carry is zero,
    /// with a `has_` member beside the ones where zero is a value.
    #[derive(Clone, Copy)]
    pub struct SipralIsup {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// The message type code (Table 4): 1 IAM, 6 ACM, 44 CPG, 9 ANM, 7
        /// CON, 12 REL, 16 RLC. Any other is recognised and not read further.
        pub message_type: u32,
        /// Whether the message carried cause indicators.
        pub has_cause: u32,
        /// The cause value: 16 normal call clearing, 17 user busy, when
        /// `cause_coding` is 0 and the value is Q.850's.
        pub cause_value: u32,
        /// Where it arose (Q.850 Table 1): 0 the user, 2 the public network
        /// serving the local user, 3 a transit network, 4 the public network
        /// serving the remote user, 7 international, 10 beyond an
        /// interworking point.
        pub cause_location: u32,
        /// The event a CPG reports (§3.21): 1 alerting, 2 progress, 3 in-band
        /// information available, 4 to 6 forwarded on busy, on no reply,
        /// unconditionally. Zero for any other message.
        pub event: u32,
        /// The called party's status in the backward call indicators (§3.5,
        /// bits DC) of an ACM, a CON, or an ANM or CPG that carries them: 1
        /// subscriber free, 2 connect when free; zero for no indication.
        pub called_status: u32,
        /// Whether the message carried a calling party number.
        pub has_calling: u32,
        /// Its nature of address (§3.10 b): 1 subscriber, 2 unknown, 3
        /// national, 4 international.
        pub calling_nature: u32,
        /// Its presentation (§3.10 e): 0 allowed, 1 restricted, 2 not
        /// available, 3 restricted by the network.
        pub calling_presentation: u32,
        /// Its screening (§3.10 f): 0 user provided and not verified, 1 user
        /// provided, verified and passed, 2 verified and failed, 3 network
        /// provided.
        pub calling_screening: u32,
        /// Whether the message carried redirection information.
        pub has_redirection: u32,
        /// Its redirecting indicator (§3.45, bits CBA): 3 call diverted, 4
        /// diverted with all redirection information restricted.
        pub redirecting_indicator: u32,
        /// How many times the call has been redirected, 1 to 5; zero when the
        /// parameter's second octet was not there.
        pub redirection_counter: u32,
        /// Why it was last redirected (bits PONM): 0 unknown, 1 user busy, 2
        /// no reply, 3 unconditional, 4 deflection during alerting, 5
        /// deflection immediate response, 6 mobile subscriber not reachable.
        pub redirecting_reason: u32,
        /// Why it was first redirected (bits HGFE), the same numbers.
        pub original_redirecting_reason: u32,
        /// The calling party's category of an IAM (§3.11): 10 an ordinary
        /// subscriber, 15 a payphone, 13 a test call; zero for any other
        /// message, which is also the category "unknown".
        pub calling_category: u32,
        /// Whose list `cause_value` is from, the cause's coding standard
        /// (Q.850 §2.2.2): 0 ITU-T, the values Q.850 lists; 1 ISO/IEC; 2
        /// national; 3 specific to the location. Only at 0 is `cause_value`
        /// the Q.850 cause of that number. Zero without cause indicators.
        /// ABI 1.11.
        pub cause_coding: u32,
        /// Zero.
        pub reserved_1_11: u32,
    }
}

// Safety: plain integers, filled only by the library.
unsafe impl Versioned for SipralIsup {
    const NAME: &'static str = "sipral_isup";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralIsup, calling_category);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// The ISUP message a caller handed over, read.
///
/// # Safety
///
/// `body` must be readable for `body_len` bytes.
unsafe fn handed<'a>(body: *const u8, body_len: usize) -> Result<Isup<'a>, Fail> {
    let Some(octets) = (unsafe { bytes(body, body_len, "body") })? else {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "body is required and was not given",
        ));
    };
    parse(octets).map_err(|error| {
        fail(
            SipralStatus::InvalidArgument,
            format!("body is not an ISUP message: {error}"),
        )
    })
}

fn number_of(message: &Isup<'_>, which: u32) -> Result<Option<IsupNumber>, Fail> {
    Ok(match which {
        1 => message.calling_party(),
        2 => message.called_party(),
        3 => message.original_called(),
        4 => message.redirecting(),
        5 => message.redirection_number(),
        6 => message.connected(),
        7 => message
            .generic_numbers()
            .find(|generic| generic.qualifier == NumberQualifier::AdditionalCalling)
            .map(|generic| generic.number),
        other => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("{other} is not a SIPRAL_ISUP_NUMBER this library names"),
            ));
        }
    })
}

entry! {
    /// Where the ISUP body of a whole SIP message is (RFC 3204), as an offset
    /// into `message` and a length. ABI 1.4.
    ///
    /// The body itself when it is `application/ISUP`, else the first such part
    /// of a multipart body. A message that carries none is a length of zero,
    /// not a failure, as an absent header field counts zero. Hand the bytes
    /// found to `sipral_isup_read`.
    ///
    /// # Safety
    ///
    /// `message` must be readable for `message_len` bytes, and `out_offset`
    /// and `out_len` must each point at one `size_t`.
    fn sipral_message_isup(
        message: *const u8,
        message_len: usize,
        out_offset: *mut usize,
        out_len: *mut usize,
    ) {
        if out_offset.is_null() || out_len.is_null() {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "out_offset and out_len are both required",
            ));
        }
        let Some(whole) = (unsafe { bytes(message, message_len, "message") })? else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "message is required and was not given",
            ));
        };
        let mut scratch = ParseScratch::new();
        let raw = parsed(whole, &mut scratch)?;
        let (offset, len) = match IsupBody::find(&raw) {
            Some(body) => (offset_in(whole, body.bytes())?, body.bytes().len()),
            None => (0, 0),
        };
        unsafe {
            out_offset.write(offset);
            out_len.write(len);
        }
        Ok(())
    }
}

entry! {
    /// Read one ISUP message, from its message type code on (ITU-T Q.763),
    /// into `out_isup`. ABI 1.4.
    ///
    /// A message that does not fit what its type lays out is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT`, the last error saying where it ends.
    /// A type other than the seven `sipral_isup_t::message_type` names is
    /// read for its code alone.
    ///
    /// # Safety
    ///
    /// `body` must be readable for `body_len` bytes, and `out_isup` must point
    /// at a `sipral_isup_t` whose `size` member says how long it is.
    fn sipral_isup_read(body: *const u8, body_len: usize, out_isup: *mut SipralIsup) {
        unsafe { declared_size(out_isup.cast_const()) }?;
        let message = unsafe { handed(body, body_len) }?;
        let cause = message.cause();
        let calling = message.calling_party();
        let redirection = message.redirection();
        let out = SipralIsup {
            size: size_of::<SipralIsup>(),
            message_type: u32::from(message.message_type().code()),
            has_cause: u32::from(cause.is_some()),
            cause_value: cause.map_or(0, |cause| u32::from(cause.value)),
            cause_location: cause.map_or(0, |cause| u32::from(cause.location.code())),
            event: message
                .event()
                .map_or(0, |event| u32::from(event.kind.code())),
            called_status: message
                .backward_call()
                .map_or(0, |backward| u32::from(backward.called_status.code())),
            has_calling: u32::from(calling.is_some()),
            calling_nature: calling
                .as_ref()
                .map_or(0, |number| u32::from(number.nature.code())),
            calling_presentation: calling
                .as_ref()
                .and_then(|number| number.presentation)
                .map_or(0, |presentation| u32::from(presentation.code())),
            calling_screening: calling
                .as_ref()
                .and_then(|number| number.screening)
                .map_or(0, |screening| u32::from(screening.code())),
            has_redirection: u32::from(redirection.is_some()),
            redirecting_indicator: redirection.map_or(0, |info| u32::from(info.indicator.code())),
            redirection_counter: redirection
                .and_then(|info| info.counter)
                .map_or(0, u32::from),
            redirecting_reason: redirection
                .and_then(|info| info.reason)
                .map_or(0, |reason| u32::from(reason.code())),
            original_redirecting_reason: redirection
                .map_or(0, |info| u32::from(info.original_reason.code())),
            calling_category: message.calling_category().map_or(0, u32::from),
            cause_coding: cause.map_or(0, |cause| u32::from(cause.coding.code())),
            reserved_1_11: 0,
        };
        unsafe { write_versioned(out_isup, out) }
    }
}

entry! {
    /// One number of an ISUP message as text, copied into the caller's buffer
    /// with a trailing NUL. ABI 1.4.
    ///
    /// `+` and the digits for an international number, the digits alone for
    /// any other; the operator codes 11 and 12 are `B` and `C`, the end of
    /// pulsing signal `F`. A number the message does not carry is just the
    /// NUL. `out_needed` always receives the bytes needed including the NUL;
    /// too small is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with nothing written.
    ///
    /// # Safety
    ///
    /// `body` must be readable for `body_len` bytes, `buffer` writable for
    /// `capacity` bytes or null with a capacity of zero, and `out_needed`
    /// must point at one `size_t` or be null.
    fn sipral_isup_number(
        body: *const u8,
        body_len: usize,
        which: Number<SipralIsupNumber>,
        buffer: *mut c_char,
        capacity: usize,
        out_needed: *mut usize,
    ) {
        let message = unsafe { handed(body, body_len) }?;
        let text = number_of(&message, which)?.map(|number| number.text()).unwrap_or_default();
        unsafe { copy_out(&text, buffer, capacity, out_needed) }
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use sipral_core::isup::{
        BackwardCall, CalledStatus, Cause, ForwardCall, IsupBuilder, Location, Nature,
        NatureOfConnection, Number, Presentation, RedirectReason, Redirection, Screening,
    };

    use super::{SipralIsup, sipral_isup_number, sipral_isup_read, sipral_message_isup};
    use crate::status::SipralStatus;

    fn iam() -> Vec<u8> {
        IsupBuilder::initial_address(
            NatureOfConnection::default(),
            ForwardCall::default(),
            0x0a,
            3,
            &Number::new(Nature::National, "5555550102"),
        )
        .calling_party(
            &Number::new(Nature::International, "15555550100")
                .presented(Presentation::Restricted)
                .screened(Screening::Network),
        )
        .redirecting(&Number::new(Nature::International, "15555550101"))
        .redirection(Redirection::diverted(
            RedirectReason::UserBusy,
            RedirectReason::Unconditional,
            2,
        ))
        .build()
        .expect("an IAM")
    }

    fn read(isup: &[u8]) -> (SipralStatus, SipralIsup) {
        let mut out = SipralIsup {
            size: size_of::<SipralIsup>(),
            ..unsafe { std::mem::zeroed() }
        };
        let status = unsafe { sipral_isup_read(isup.as_ptr(), isup.len(), &raw mut out) };
        (status, out)
    }

    fn number(isup: &[u8], which: u32) -> String {
        let mut buffer = [0_u8; 64];
        let mut needed = 0;
        let status = unsafe {
            sipral_isup_number(
                isup.as_ptr(),
                isup.len(),
                which,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &raw mut needed,
            )
        };
        assert_eq!(status, SipralStatus::Ok);
        String::from_utf8_lossy(&buffer[..needed - 1]).into_owned()
    }

    #[test]
    fn an_iam_reads_into_the_record_and_its_numbers_into_text() {
        let iam = iam();
        let (status, out) = read(&iam);
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!(out.size, size_of::<SipralIsup>());
        assert_eq!(out.message_type, 1);
        assert_eq!((out.has_calling, out.calling_nature), (1, 4));
        assert_eq!((out.calling_presentation, out.calling_screening), (1, 3));
        assert_eq!((out.has_redirection, out.redirecting_indicator), (1, 3));
        assert_eq!((out.redirection_counter, out.redirecting_reason), (2, 1));
        assert_eq!(out.original_redirecting_reason, 3);
        assert_eq!((out.calling_category, out.has_cause), (10, 0));
        assert_eq!(number(&iam, 1), "+15555550100");
        assert_eq!(number(&iam, 2), "5555550102");
        assert_eq!(number(&iam, 4), "+15555550101");
        assert_eq!(number(&iam, 3), "", "not carried, so just the NUL");
    }

    #[test]
    fn a_rel_and_an_acm_say_their_cause_and_status() {
        let rel = IsupBuilder::release(Cause::new(17, Location::PublicRemote))
            .build()
            .expect("a REL");
        let (status, out) = read(&rel);
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!((out.message_type, out.has_cause), (12, 1));
        assert_eq!((out.cause_value, out.cause_location), (17, 4));
        assert_eq!((out.cause_coding, out.reserved_1_11), (0, 0), "ITU-T's");

        let acm = IsupBuilder::address_complete(BackwardCall {
            called_status: CalledStatus::SubscriberFree,
            ..BackwardCall::default()
        })
        .build()
        .expect("an ACM");
        let (_, out) = read(&acm);
        assert_eq!((out.message_type, out.called_status), (6, 1));
        assert_eq!((out.has_cause, out.cause_coding), (0, 0));
    }

    #[test]
    fn a_cause_of_a_national_coding_standard_says_so() {
        let mut rel = IsupBuilder::release(Cause::new(17, Location::PublicRemote))
            .build()
            .expect("a REL");
        // octet 1 of the cause indicators: ext, coding standard 00, spare, location 0100
        let at = rel
            .windows(2)
            .position(|pair| pair == [0x84, 0x91])
            .expect("the cause indicators");
        for (coding, octet) in [(2, 0xc4), (1, 0xa4), (3, 0xe4)] {
            if let Some(first) = rel.get_mut(at) {
                *first = octet;
            }
            let (status, out) = read(&rel);
            assert_eq!(status, SipralStatus::Ok);
            assert_eq!(out.size, size_of::<SipralIsup>());
            assert_eq!((out.has_cause, out.cause_value), (1, 17));
            assert_eq!((out.cause_coding, out.cause_location), (coding, 4));
        }
    }

    #[test]
    fn what_is_not_isup_is_refused_and_a_message_without_any_is_a_length_of_zero() {
        let (status, _) = read(&[0x0c, 0x09, 0x00]);
        assert_eq!(status, SipralStatus::InvalidArgument);
        let mut needed = 0;
        let wrong = unsafe {
            sipral_isup_number(
                [0x10_u8, 0].as_ptr(),
                2,
                99,
                ptr::null_mut(),
                0,
                &raw mut needed,
            )
        };
        assert_eq!(wrong, SipralStatus::InvalidArgument);

        let rel = IsupBuilder::release(Cause::new(16, Location::User))
            .build()
            .expect("a REL");
        let mut bye = format!(
            "BYE sip:alice@192.0.2.1 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.9;branch=z9hG4bKrel\r\n\
             Max-Forwards: 70\r\nFrom: <sip:gw@example.com>;tag=a\r\nTo: <sip:alice@example.com>;tag=b\r\n\
             Call-ID: rel@gw\r\nCSeq: 2 BYE\r\nContent-Type: application/ISUP;version=itu-t92+\r\n\
             Content-Length: {}\r\n\r\n",
            rel.len()
        )
        .into_bytes();
        let start = bye.len();
        bye.extend_from_slice(&rel);
        let (mut offset, mut len) = (usize::MAX, usize::MAX);
        let status =
            unsafe { sipral_message_isup(bye.as_ptr(), bye.len(), &raw mut offset, &raw mut len) };
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!((offset, len), (start, rel.len()));

        let plain =
            b"OPTIONS sip:a@192.0.2.1 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.9;branch=z9hG4bKo\r\n\
Max-Forwards: 70\r\nFrom: <sip:b@example.com>;tag=a\r\nTo: <sip:a@example.com>\r\nCall-ID: o\r\n\
CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
        let status = unsafe {
            sipral_message_isup(plain.as_ptr(), plain.len(), &raw mut offset, &raw mut len)
        };
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!((offset, len), (0, 0));
    }
}
