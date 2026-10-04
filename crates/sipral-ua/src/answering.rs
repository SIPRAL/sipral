// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! How a call asks to be answered: `Answer-Mode` and `Priv-Answer-Mode`
//! (RFC 5373), and `Alert-Info` (RFC 3261 §20.4, RFC 7462) with the
//! auto-answer conventions phones and switches built on it.
//!
//! An intercom, a paging group or a click-to-call from a CRM wants the phone
//! to pick up by itself; a switch wants the ring to say whether the caller is
//! a colleague or the outside world. None of that changes what the stack
//! does — "the UAS MUST NOT" answer automatically without a policy of its
//! own (RFC 5373 §4.2), and the policy is the application's — so it is read,
//! typed, and handed up with the call.
//!
//! Three shapes are in use for "answer this by yourself", and all three are
//! read into [`Answering::answer_after`]:
//!
//! - `Answer-Mode: Auto` (RFC 5373), the standard one, as zero;
//! - `answer-after=N` on `Call-Info` or `Alert-Info`, N seconds;
//! - `info=alert-autoanswer` on `Alert-Info`, with `delay=N` beside it or
//!   none.
//!
//! Where the ring is from is RFC 7462's `<urn:alert:source:internal>` and
//! `<urn:alert:source:external>`, or the `info=` value switches write
//! instead: `alert-internal`, `internal`, `alert-external`, `external`.

use std::time::Duration;

use sipral_core::msg::{HeaderName, Params, RawMessage, trim};

const ANSWER_MODE: HeaderName<'static> = HeaderName::Extension("Answer-Mode");
const PRIV_ANSWER_MODE: HeaderName<'static> = HeaderName::Extension("Priv-Answer-Mode");
const ALERT_INFO: HeaderName<'static> = HeaderName::Extension("Alert-Info");
const CALL_INFO: HeaderName<'static> = HeaderName::Extension("Call-Info");

/// `Answer-Mode`'s value (RFC 5373 §3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AnswerMode {
    /// Wait for the user.
    Manual,
    /// Answer without waiting for the user.
    Auto,
    /// Any other token, as written — §3: "implementations MUST ignore
    /// unknown values", and ignoring it is the application's to do.
    Other(Box<str>),
}

/// One `Answer-Mode` or `Priv-Answer-Mode` field.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AnswerModeField {
    /// What the caller asked for.
    pub mode: AnswerMode,
    /// `;require`: the caller would rather the call be refused — with a 403,
    /// §4.2 says — than answered any other way.
    pub required: bool,
}

impl AnswerModeField {
    fn parse(value: &[u8]) -> Option<Self> {
        let (head, params) = Params::split(value);
        let head = trim(head);
        let text = std::str::from_utf8(head).ok()?;
        if text.is_empty() {
            return None;
        }
        let mode = if text.eq_ignore_ascii_case("Auto") {
            AnswerMode::Auto
        } else if text.eq_ignore_ascii_case("Manual") {
            AnswerMode::Manual
        } else {
            AnswerMode::Other(Box::from(text))
        };
        Some(Self {
            mode,
            required: params.has("require"),
        })
    }

    fn of(message: &RawMessage<'_>, name: HeaderName<'_>) -> Option<Self> {
        message.header(name).and_then(Self::parse)
    }
}

/// Where the ring says the caller is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RingSource {
    /// A colleague: another extension of the same switch.
    Internal,
    /// The outside world.
    External,
}

/// How an incoming call asks to be answered and rung.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Answering {
    /// `Answer-Mode` (RFC 5373 §3).
    pub answer_mode: Option<AnswerModeField>,
    /// `Priv-Answer-Mode` (RFC 5373 §3): the same, asked with the privilege
    /// of overriding the user's own settings — §4.2 has a UAS apply "a
    /// stricter authorization policy" to it.
    pub priv_answer_mode: Option<AnswerModeField>,
    /// After how long the caller asked the call to be answered without the
    /// user, whichever of the three conventions said so (see the module
    /// note). `None` when nothing asked.
    pub answer_after: Option<Duration>,
    /// Where the ring says the caller is, when it said.
    pub source: Option<RingSource>,
    /// Every `Alert-Info` URI, in the order written, without the angle
    /// brackets: a tone to play, or one of RFC 7462's `urn:alert:` names.
    pub alert_info: Box<[Box<[u8]>]>,
    /// Every `info=` value on `Alert-Info`, as written: a ring pattern such
    /// as `Ring2`, or one of the auto-answer and source words above.
    pub alert_names: Box<[Box<str>]>,
}

impl Answering {
    /// Read what an INVITE says about how to answer it and ring for it.
    #[must_use]
    pub fn of_request(request: &RawMessage<'_>) -> Self {
        let answer_mode = AnswerModeField::of(request, ANSWER_MODE);
        let priv_answer_mode = AnswerModeField::of(request, PRIV_ANSWER_MODE);
        let automatic = [&answer_mode, &priv_answer_mode]
            .into_iter()
            .flatten()
            .any(|field| field.mode == AnswerMode::Auto);
        let mut out = Self {
            answer_after: automatic.then_some(Duration::ZERO),
            answer_mode,
            priv_answer_mode,
            ..Self::default()
        };
        let mut uris: Vec<Box<[u8]>> = Vec::new();
        let mut names: Vec<Box<str>> = Vec::new();
        for value in request.field_values(ALERT_INFO) {
            let value = trim(value);
            // `info=alert-autoanswer` with no URI before it is out of §20.4's
            // grammar and common enough to be read anyway: the whole value
            // is then parameters
            let own = if value.first() == Some(&b'<') {
                let (head, params) = Params::split(value);
                if let Some(uri) = head
                    .strip_prefix(b"<")
                    .and_then(|rest| rest.strip_suffix(b">"))
                {
                    out.source = out.source.or_else(|| source_of_urn(uri));
                    uris.push(Box::from(uri));
                }
                owned(params)
            } else {
                owned(Params::split(&value_with_leading_semicolon(value)).1)
            };
            out.read_alert_params(&own, &mut names);
        }
        for value in request.field_values(CALL_INFO) {
            let (_, params) = Params::split(value);
            if let Some(after) = params
                .get("answer-after")
                .and_then(|digits| seconds(&digits))
            {
                out.answer_after = Some(out.answer_after.map_or(after, |known| known.min(after)));
            }
        }
        out.alert_info = uris.into_boxed_slice();
        out.alert_names = names.into_boxed_slice();
        out
    }

    /// What one `Alert-Info` value's parameters say.
    fn read_alert_params(
        &mut self,
        params: &[(Vec<u8>, Option<Vec<u8>>)],
        names: &mut Vec<Box<str>>,
    ) {
        let get = |wanted: &[u8]| {
            params
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
                .map(|(_, value)| value.as_deref().map(unquoted).unwrap_or_default())
        };
        if let Some(after) = get(b"answer-after").and_then(|digits| seconds(&digits)) {
            self.answer_after = Some(self.answer_after.map_or(after, |known| known.min(after)));
        }
        let Some(info) = get(b"info") else {
            return;
        };
        if let Ok(text) = std::str::from_utf8(&info)
            && !text.is_empty()
        {
            names.push(Box::from(text));
        }
        if info.eq_ignore_ascii_case(b"alert-autoanswer") {
            let delay = get(b"delay")
                .and_then(|digits| seconds(&digits))
                .unwrap_or(Duration::ZERO);
            self.answer_after = Some(self.answer_after.map_or(delay, |known| known.min(delay)));
        } else if info.eq_ignore_ascii_case(b"alert-internal")
            || info.eq_ignore_ascii_case(b"internal")
        {
            self.source = self.source.or(Some(RingSource::Internal));
        } else if info.eq_ignore_ascii_case(b"alert-external")
            || info.eq_ignore_ascii_case(b"external")
        {
            self.source = self.source.or(Some(RingSource::External));
        }
    }
}

/// Parameters, copied out of the value they were read from.
fn owned(params: Params<'_>) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    params
        .map(|(name, value)| (name.to_vec(), value.map(<[u8]>::to_vec)))
        .collect()
}

/// `value` with a `;` in front, so that a value whose head is itself a
/// parameter splits into parameters and nothing else.
fn value_with_leading_semicolon(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 1);
    out.push(b';');
    out.extend_from_slice(trim(value));
    out
}

fn unquoted(value: &[u8]) -> Vec<u8> {
    sipral_core::msg::unquote(value).into_owned()
}

/// RFC 7462 §4.2's `source` URNs.
fn source_of_urn(uri: &[u8]) -> Option<RingSource> {
    let lower = uri.to_ascii_lowercase();
    if lower.starts_with(b"urn:alert:source:internal") {
        Some(RingSource::Internal)
    } else if lower.starts_with(b"urn:alert:source:external") {
        Some(RingSource::External)
    } else {
        None
    }
}

/// A whole number of seconds, as written.
fn seconds(digits: &[u8]) -> Option<Duration> {
    let text = std::str::from_utf8(trim(digits)).ok()?;
    text.parse::<u64>().ok().map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{AnswerMode, Answering, RingSource};
    use sipral_core::msg::{ParseMode, ParseScratch, parse};

    fn read(fields: &str) -> Answering {
        let message = format!(
            "INVITE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKanswer\r\n\
From: <sip:bob@example.com>;tag=f\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: answering\r\n\
CSeq: 1 INVITE\r\n\
{fields}\
Content-Length: 0\r\n\r\n"
        );
        let mut scratch = ParseScratch::new();
        let raw = parse(message.as_bytes(), &mut scratch, ParseMode::Lenient).expect("an INVITE");
        Answering::of_request(&raw)
    }

    #[test]
    fn answer_mode_auto_with_require_is_an_answer_now_that_must_be_one() {
        let read = read("Answer-Mode: Auto;require\r\nPriv-Answer-Mode: Manual\r\n");
        let asked = read.answer_mode.expect("an Answer-Mode");
        assert_eq!(asked.mode, AnswerMode::Auto);
        assert!(asked.required);
        let private = read.priv_answer_mode.expect("a Priv-Answer-Mode");
        assert_eq!(private.mode, AnswerMode::Manual);
        assert!(!private.required);
        assert_eq!(read.answer_after, Some(Duration::ZERO));
    }

    #[test]
    fn an_unknown_answer_mode_is_kept_as_written_and_asks_for_nothing() {
        let read = read("Answer-Mode: Whenever\r\n");
        assert_eq!(
            read.answer_mode.map(|field| field.mode),
            Some(AnswerMode::Other("Whenever".into()))
        );
        assert_eq!(read.answer_after, None);
    }

    #[test]
    fn each_auto_answer_convention_reads_as_the_delay_it_asks_for() {
        assert_eq!(
            read("Call-Info: <sip:192.0.2.9>;answer-after=3\r\n").answer_after,
            Some(Duration::from_secs(3))
        );
        assert_eq!(
            read("Alert-Info: <http://www.notused.com>;info=alert-autoanswer;delay=2\r\n")
                .answer_after,
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            read("Alert-Info: info=alert-autoanswer\r\n").answer_after,
            Some(Duration::ZERO)
        );
        assert_eq!(
            read("Alert-Info: <http://tones.example/ring.wav>;answer-after=5\r\n").answer_after,
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            read("Alert-Info: <http://tones.example/ring.wav>\r\n").answer_after,
            None
        );
    }

    #[test]
    fn where_the_ring_is_from_reads_from_the_urn_or_the_info_word() {
        let urn = read("Alert-Info: <urn:alert:source:internal>, <urn:alert:priority:high>\r\n");
        assert_eq!(urn.source, Some(RingSource::Internal));
        assert_eq!(urn.alert_info.len(), 2);
        assert_eq!(&*urn.alert_info[1], b"urn:alert:priority:high");
        let word = read("Alert-Info: <http://www.notused.com>;info=alert-external\r\n");
        assert_eq!(word.source, Some(RingSource::External));
        assert_eq!(&*word.alert_names, &[Box::from("alert-external")]);
        let pattern = read("Alert-Info: <http://www.notused.com>;info=Ring2\r\n");
        assert_eq!(pattern.source, None);
        assert_eq!(&*pattern.alert_names, &[Box::from("Ring2")]);
    }
}
