// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Who is calling, as far as the network will say, and how far to believe it.
//!
//! `From` is what the caller wrote about itself. The network's view is in
//! `P-Asserted-Identity` (RFC 3325 §9.1), `Remote-Party-ID`
//! (draft-ietf-sip-privacy-04), `verstat` (3GPP TS 24.229 §7.2A.20),
//! `Diversion` (RFC 5806), `History-Info` (RFC 7044) and `Privacy`
//! (RFC 3323 §4.2).
//!
//! # The trust gate
//!
//! RFC 3325 §8: a UAS MUST NOT use `P-Asserted-Identity` from an element it
//! does not trust. An account names its trusted peers by source address
//! ([`Account::trust`]); from anywhere else the asserted identity,
//! `Remote-Party-ID` and `verstat` are left out. `Diversion` and
//! `History-Info` have no trust model and are read either way.
//!
//! # Outgoing anonymity
//!
//! [`Account::privacy`] makes `From` anonymous (RFC 3323 §4.1.1.3) and fills
//! `Privacy`. The account's identity goes in `P-Asserted-Identity` only toward
//! a trusted peer, which can still bill the call and strips it (RFC 3325 §7).
//! Toward any other peer, an application-written `P-Asserted-Identity` or
//! `P-Preferred-Identity` is dropped too (§6).
//!
//! [`Account::trust`]: crate::Account::trust
//! [`Account::privacy`]: crate::Account::privacy

use std::borrow::Cow;

use sipral_core::msg::{HeaderName, NameAddrRef, Params, RawMessage, trim};

use crate::reason::Reason;

/// `P-Asserted-Identity` (RFC 3325 §9.1).
pub(crate) const ASSERTED: HeaderName<'static> = HeaderName::Extension("P-Asserted-Identity");
/// `Privacy` (RFC 3323 §4.2).
pub(crate) const PRIVACY: HeaderName<'static> = HeaderName::Extension("Privacy");
const REMOTE_PARTY: HeaderName<'static> = HeaderName::Extension("Remote-Party-ID");
pub(crate) const DIVERSION: HeaderName<'static> = HeaderName::Extension("Diversion");
const HISTORY: HeaderName<'static> = HeaderName::Extension("History-Info");

/// RFC 3323 §4.1.1.3's `From` for a caller who asked to be anonymous.
pub(crate) const ANONYMOUS_FROM: &[u8] = b"\"Anonymous\" <sip:anonymous@anonymous.invalid>";

/// One party a header field names: its URI as written, without the angle
/// brackets, and the display name beside it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Party {
    /// The URI, as written in the field.
    pub uri: Box<[u8]>,
    /// The display name, quotes and backslash escapes resolved. Empty when
    /// the field named none.
    pub display: Box<[u8]>,
}

impl Party {
    fn of(address: &NameAddrRef<'_>) -> Self {
        Self {
            uri: Box::from(address.uri_bytes()),
            display: address
                .display_name()
                .map_or_else(|| Box::from(&b""[..]), |name| Box::from(name.as_ref())),
        }
    }
}

/// What a `Privacy` field asked for (RFC 3323 §4.2, and RFC 3325 §9.3's
/// `id`), one flag per `priv-value`. All false is no privacy asked for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[allow(clippy::struct_excessive_bools)]
pub struct Privacy {
    /// `header`: obscure the header fields that could identify the caller.
    pub header: bool,
    /// `session`: hide the session description from the far end.
    pub session: bool,
    /// `user`: user-level privacy, the caller's own `From` among it.
    pub user: bool,
    /// `id`: keep the asserted identity from anything outside the trust
    /// domain (RFC 3325 §9.3).
    pub id: bool,
    /// `critical`: the call is to fail rather than go without the privacy
    /// asked for.
    pub critical: bool,
    /// `none`: no privacy, stated.
    pub none: bool,
}

impl Privacy {
    /// Privacy of the identity, as a caller withholding their number asks
    /// for it: `id` toward the network, and the `From` anonymous.
    #[must_use]
    pub const fn withheld() -> Self {
        Self {
            header: false,
            session: false,
            user: false,
            id: true,
            critical: false,
            none: false,
        }
    }

    /// Whether anything is asked to be kept private.
    #[must_use]
    pub const fn requested(&self) -> bool {
        self.header || self.session || self.user || self.id || self.critical
    }

    /// Every `Privacy` field of a message, read together. `,` is accepted
    /// like `;` since some senders write it; unknown values are ignored.
    #[must_use]
    pub fn of_message(message: &RawMessage<'_>) -> Self {
        let mut out = Self::default();
        for line in message.header_values(PRIVACY) {
            for value in line.split(|byte| *byte == b';' || *byte == b',') {
                let value = trim(value);
                let set = |name: &[u8]| value.eq_ignore_ascii_case(name);
                out.header |= set(b"header");
                out.session |= set(b"session");
                out.user |= set(b"user");
                out.id |= set(b"id");
                out.critical |= set(b"critical");
                out.none |= set(b"none");
            }
        }
        out
    }

    /// The field value, in §4.2's order: `header;session;user;id;critical`,
    /// or `none`. `None` when nothing is set at all.
    #[must_use]
    pub fn to_value(&self) -> Option<Vec<u8>> {
        let names: [(&[u8], bool); 5] = [
            (b"header", self.header),
            (b"session", self.session),
            (b"user", self.user),
            (b"id", self.id),
            (b"critical", self.critical),
        ];
        let mut out = Vec::new();
        for (name, on) in names {
            if on {
                if !out.is_empty() {
                    out.push(b';');
                }
                out.extend_from_slice(name);
            }
        }
        if out.is_empty() && self.none {
            out.extend_from_slice(b"none");
        }
        (!out.is_empty()).then_some(out)
    }
}

/// The verdict a terminating network reached on the caller's number
/// (3GPP TS 24.229 §7.2A.20's `verstat`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Verstat {
    /// `TN-Validation-Passed`: the number was verified.
    Passed,
    /// `TN-Validation-Failed`: it was checked and did not verify.
    Failed,
    /// `No-TN-Validation`: it was not checked.
    NotValidated,
    /// Any other value, as written.
    Other(Box<str>),
}

impl Verstat {
    fn of(value: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(value).ok()?;
        if text.is_empty() {
            return None;
        }
        Some(if text.eq_ignore_ascii_case("TN-Validation-Passed") {
            Self::Passed
        } else if text.eq_ignore_ascii_case("TN-Validation-Failed") {
            Self::Failed
        } else if text.eq_ignore_ascii_case("No-TN-Validation") {
            Self::NotValidated
        } else {
            Self::Other(Box::from(text))
        })
    }

    /// The `verstat` a URI carries, wherever in it: a `tel:` URI's own
    /// parameters, or the telephone-subscriber in a SIP URI's user part.
    fn in_uri(uri: &[u8]) -> Option<Self> {
        let at = uri
            .windows(8)
            .position(|window| window.eq_ignore_ascii_case(b"verstat="))?;
        let rest = uri.get(at + 8..)?;
        let end = rest
            .iter()
            .position(|byte| matches!(*byte, b';' | b'@' | b'>' | b'?' | b','))
            .unwrap_or(rest.len());
        Self::of(rest.get(..end)?)
    }
}

/// One `Diversion` value (RFC 5806 §4): who the call was diverted from, and
/// why. The top-most is the most recent diversion.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Diversion {
    /// The party the call was diverted from.
    pub party: Party,
    /// `reason`, as written: `user-busy`, `no-answer`, `unconditional`,
    /// `deflection` and the rest. `None` when the value named none.
    pub reason: Option<Box<str>>,
    /// `counter`: how many diversions this value stands for.
    pub counter: Option<u8>,
    /// `privacy`: `full`, `name`, `uri` or `off`, as written.
    pub privacy: Option<Box<str>>,
    /// `screen`: whether the network screened the number, when it said.
    pub screened: Option<bool>,
}

/// One `History-Info` entry (RFC 7044 §9): a target the request was sent to
/// on its way here.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HistoryEntry {
    /// The target, URI as written, escaped headers included.
    pub party: Party,
    /// `index`: where the entry sits in the tree of retargetings, `1.1.2`.
    pub index: Box<str>,
    /// RFC 4458's `cause` URI parameter: the SIP status a diversion to this
    /// target stands for, 302 for an unconditional one.
    pub cause: Option<u16>,
    /// The `Reason` escaped into the URI's headers (§4): what the previous
    /// target answered when the request was sent here instead.
    pub reason: Option<Reason>,
    /// How this target was reached, when the entry said (§9's `rc`, `mp`
    /// and `np` tags) — with the index of the entry it was reached from.
    pub target: Option<(Retarget, Box<str>)>,
}

/// §9's three `hi-target-param`s.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Retarget {
    /// `rc`: the target changed but the user it reaches did not.
    Changed,
    /// `mp`: the target is a different user: the call was diverted.
    Mapped,
    /// `np`: nothing changed on the way.
    Unchanged,
}

/// One `Remote-Party-ID` value (draft-ietf-sip-privacy-04 §9).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RemoteParty {
    /// The party named.
    pub party: Party,
    /// `party`: whether this is the calling party (`true`, also when the
    /// parameter is absent) or the called one.
    pub calling: bool,
    /// `screen=yes`: the network vouched for it.
    pub screened: bool,
    /// `privacy`, as written: `full`, `name`, `uri` or `off`.
    pub privacy: Option<Box<str>>,
}

/// Everything an INVITE said about who is calling, beyond its `From`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CallerIdentity {
    /// Whether the INVITE came from a peer the account trusts
    /// ([`Account::trust`](crate::Account::trust)). When it did not,
    /// `asserted`, `remote_party` and `verstat` are empty, whatever the
    /// request carried (RFC 3325 §8).
    pub trusted: bool,
    /// `P-Asserted-Identity`: one or two parties, a SIP URI and a `tel:` one.
    pub asserted: Box<[Party]>,
    /// `Remote-Party-ID`, every value, calling and called.
    pub remote_party: Box<[RemoteParty]>,
    /// The `verstat` of the asserted identity, or of the `From` when there
    /// was no asserted identity to carry one.
    pub verstat: Option<Verstat>,
    /// What the caller asked to be kept private (RFC 3323).
    pub privacy: Privacy,
    /// `Diversion`, top-most — the most recent diversion — first.
    pub diversions: Box<[Diversion]>,
    /// `History-Info`, in the order written.
    pub history: Box<[HistoryEntry]>,
    /// This end's own verdict on the caller (RFC 8224 §6.2), for an account
    /// whose verification is in force
    /// ([`Account::stir_verification`](crate::Account::stir_verification)).
    /// `None` when nothing was verified. Not behind the trust gate: a
    /// signature is its own proof.
    pub verification: Option<crate::CallerVerification>,
}

impl CallerIdentity {
    /// Read everything an INVITE says about who is calling. `trusted` is
    /// whether it came from a peer the account it arrived for trusts.
    #[must_use]
    pub fn of_request(request: &RawMessage<'_>, trusted: bool) -> Self {
        let asserted: Box<[Party]> = if trusted {
            request
                .field_values(ASSERTED)
                .filter_map(|value| NameAddrRef::parse(value).ok())
                .map(|address| Party::of(&address))
                .collect()
        } else {
            Box::default()
        };
        let remote_party: Box<[RemoteParty]> = if trusted {
            request
                .field_values(REMOTE_PARTY)
                .filter_map(remote_party_of)
                .collect()
        } else {
            Box::default()
        };
        let verstat = trusted
            .then(|| {
                asserted
                    .iter()
                    .find_map(|party| Verstat::in_uri(&party.uri))
                    .or_else(|| {
                        request
                            .from()
                            .ok()
                            .and_then(|from| Verstat::in_uri(from.uri_bytes()))
                    })
            })
            .flatten();
        Self {
            trusted,
            asserted,
            remote_party,
            verstat,
            privacy: Privacy::of_message(request),
            diversions: request
                .field_values(DIVERSION)
                .filter_map(diversion_of)
                .collect(),
            history: request
                .field_values(HISTORY)
                .filter_map(history_of)
                .collect(),
            verification: None,
        }
    }

    /// The identity to show for the caller: the first asserted one, then a
    /// calling `Remote-Party-ID`. `None` when the network said nothing this
    /// end believes.
    #[must_use]
    pub fn shown(&self) -> Option<&Party> {
        self.asserted.first().or_else(|| {
            self.remote_party
                .iter()
                .find(|party| party.calling)
                .map(|party| &party.party)
        })
    }
}

/// A parameter's value as text, when it reads as UTF-8.
fn text_of(value: Option<Cow<'_, [u8]>>) -> Option<Box<str>> {
    value.and_then(|bytes| std::str::from_utf8(&bytes).ok().map(Box::from))
}

fn diversion_of(value: &[u8]) -> Option<Diversion> {
    let address = NameAddrRef::parse(value).ok()?;
    let params = address.params();
    Some(Diversion {
        party: Party::of(&address),
        reason: text_of(params.get("reason")),
        counter: params
            .get("counter")
            .and_then(|digits| std::str::from_utf8(&digits).ok()?.parse().ok()),
        privacy: text_of(params.get("privacy")),
        screened: params.get("screen").and_then(|answer| {
            if answer.eq_ignore_ascii_case(b"yes") {
                Some(true)
            } else if answer.eq_ignore_ascii_case(b"no") {
                Some(false)
            } else {
                None
            }
        }),
    })
}

fn remote_party_of(value: &[u8]) -> Option<RemoteParty> {
    let address = NameAddrRef::parse(value).ok()?;
    let params = address.params();
    Some(RemoteParty {
        party: Party::of(&address),
        calling: params
            .get("party")
            .is_none_or(|party| party.eq_ignore_ascii_case(b"calling")),
        screened: params
            .get("screen")
            .is_some_and(|answer| answer.eq_ignore_ascii_case(b"yes")),
        privacy: text_of(params.get("privacy")),
    })
}

fn history_of(value: &[u8]) -> Option<HistoryEntry> {
    let address = NameAddrRef::parse(value).ok()?;
    let params = address.params();
    let index = text_of(params.get("index"))?;
    let uri = address.uri_bytes();
    let target = [
        ("rc", Retarget::Changed),
        ("mp", Retarget::Mapped),
        ("np", Retarget::Unchanged),
    ]
    .into_iter()
    .find_map(|(name, kind)| text_of(params.get(name)).map(|from| (kind, from)));
    Some(HistoryEntry {
        party: Party::of(&address),
        index,
        cause: uri_parameter(uri, b"cause")
            .and_then(|digits| std::str::from_utf8(&digits).ok()?.parse().ok()),
        reason: escaped_header(uri, b"Reason").and_then(|value| Reason::parse(&value)),
        target,
    })
}

/// A parameter of a URI (`;name=value`), before any `?headers`.
fn uri_parameter(uri: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    let end = uri
        .iter()
        .position(|byte| *byte == b'?')
        .unwrap_or(uri.len());
    let (_, params) = Params::split(uri.get(..end)?);
    let wanted = std::str::from_utf8(name).ok()?;
    params.get(wanted).map(Cow::into_owned)
}

/// A header escaped into a URI's `?name=value&...` part (RFC 3261 §19.1.1),
/// percent-decoded.
fn escaped_header(uri: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    let start = uri.iter().position(|byte| *byte == b'?')? + 1;
    uri.get(start..)?
        .split(|byte| *byte == b'&')
        .find_map(|pair| {
            let equals = pair.iter().position(|byte| *byte == b'=')?;
            let (key, value) = (pair.get(..equals)?, pair.get(equals + 1..)?);
            key.eq_ignore_ascii_case(name)
                .then(|| percent_decoded(value))
        })
}

fn percent_decoded(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    let mut at = 0;
    while let Some(&byte) = value.get(at) {
        if byte == b'%'
            && let (Some(high), Some(low)) = (
                value.get(at + 1).and_then(|digit| hex(*digit)),
                value.get(at + 2).and_then(|digit| hex(*digit)),
            )
        {
            out.push(high << 4 | low);
            at += 3;
            continue;
        }
        out.push(byte);
        at += 1;
    }
    out
}

const fn hex(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{CallerIdentity, Privacy, Retarget, Verstat};
    use crate::reason::ReasonProtocol;
    use sipral_core::msg::{ParseMode, ParseScratch, parse};

    const INVITE: &[u8] = b"INVITE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKident\r\n\
From: \"Unknown\" <sip:+15551230000@carrier.example;user=phone>;tag=f\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: identity\r\n\
CSeq: 1 INVITE\r\n\
P-Asserted-Identity: \"Bob Jones\" <sip:+15551234567;verstat=TN-Validation-Passed@carrier.example;user=phone>\r\n\
P-Asserted-Identity: <tel:+15551234567;verstat=TN-Validation-Passed>\r\n\
Remote-Party-ID: \"Bob\" <sip:5551234567@carrier.example>;party=calling;screen=yes;privacy=off\r\n\
Privacy: id; header\r\n\
Diversion: <sip:desk@example.com>;reason=no-answer;counter=1;screen=no, \"Front, Desk\" <sip:front@example.com>;reason=unconditional\r\n\
History-Info: <sip:front@example.com>;index=1\r\n\
History-Info: <sip:desk@example.com?Reason=SIP%3Bcause%3D302%3Btext%3D%22Moved%22>;index=1.1;rc=1\r\n\
History-Info: <sip:alice@example.com;cause=408>;index=1.1.1;mp=1.1\r\n\
Content-Length: 0\r\n\r\n";

    fn read(trusted: bool) -> CallerIdentity {
        let mut scratch = ParseScratch::new();
        let raw = parse(INVITE, &mut scratch, ParseMode::Lenient).expect("an INVITE");
        CallerIdentity::of_request(&raw, trusted)
    }

    #[test]
    fn a_trusted_peer_is_believed_about_who_is_calling() {
        let identity = read(true);
        assert!(identity.trusted);
        assert_eq!(identity.asserted.len(), 2);
        assert_eq!(&*identity.asserted[0].display, b"Bob Jones");
        assert!(identity.asserted[1].uri.starts_with(b"tel:+15551234567"));
        assert_eq!(identity.verstat, Some(Verstat::Passed));
        assert_eq!(identity.remote_party.len(), 1);
        assert!(identity.remote_party[0].calling);
        assert!(identity.remote_party[0].screened);
        assert_eq!(identity.remote_party[0].privacy.as_deref(), Some("off"));
        assert_eq!(
            identity.shown().map(|party| &*party.display),
            Some(&b"Bob Jones"[..])
        );
    }

    /// RFC 3325 §8: from an element it does not trust, a UAS "MUST NOT use
    /// the P-Asserted-Identity header field in any way".
    #[test]
    fn an_untrusted_peer_is_not_believed_and_what_it_forwarded_is_still_read() {
        let identity = read(false);
        assert!(!identity.trusted);
        assert!(identity.asserted.is_empty());
        assert!(identity.remote_party.is_empty());
        assert_eq!(identity.verstat, None);
        assert!(identity.shown().is_none());
        assert_eq!(identity.diversions.len(), 2);
        assert_eq!(identity.history.len(), 3);
        assert!(identity.privacy.id && identity.privacy.header);
    }

    #[test]
    fn a_diversion_says_who_the_call_came_from_and_why() {
        let identity = read(false);
        let top = &identity.diversions[0];
        assert_eq!(&*top.party.uri, b"sip:desk@example.com");
        assert_eq!(top.reason.as_deref(), Some("no-answer"));
        assert_eq!(top.counter, Some(1));
        assert_eq!(top.screened, Some(false));
        let second = &identity.diversions[1];
        assert_eq!(&*second.party.display, b"Front, Desk");
        assert_eq!(second.reason.as_deref(), Some("unconditional"));
    }

    #[test]
    fn a_history_entry_carries_its_index_its_cause_and_the_reason_escaped_into_it() {
        let identity = read(false);
        let [first, second, third] = &*identity.history else {
            panic!("three entries: {:?}", identity.history);
        };
        assert_eq!(&*first.index, "1");
        assert_eq!(first.target, None);
        assert_eq!(&*second.index, "1.1");
        let reason = second.reason.as_ref().expect("the escaped Reason");
        assert_eq!(reason.protocol, ReasonProtocol::Sip);
        assert_eq!(reason.cause, Some(302));
        assert_eq!(reason.text.as_deref(), Some("Moved"));
        assert_eq!(
            second.target.as_ref().map(|(kind, from)| (*kind, &**from)),
            Some((Retarget::Changed, "1"))
        );
        assert_eq!(third.cause, Some(408));
        assert_eq!(
            third.target.as_ref().map(|(kind, from)| (*kind, &**from)),
            Some((Retarget::Mapped, "1.1"))
        );
    }

    #[test]
    fn privacy_writes_in_the_rfcs_order_and_reads_back() {
        let asked = Privacy {
            id: true,
            header: true,
            ..Privacy::default()
        };
        assert_eq!(asked.to_value().as_deref(), Some(&b"header;id"[..]));
        assert!(asked.requested());
        assert_eq!(
            Privacy {
                none: true,
                ..Privacy::default()
            }
            .to_value()
            .as_deref(),
            Some(&b"none"[..])
        );
        assert_eq!(Privacy::default().to_value(), None);
        assert!(!Privacy::default().requested());
        assert_eq!(Privacy::withheld().to_value().as_deref(), Some(&b"id"[..]));
    }

    #[test]
    fn every_verstat_value_the_specification_names_reads_as_itself() {
        assert_eq!(
            Verstat::in_uri(b"tel:+1555;verstat=TN-Validation-Failed"),
            Some(Verstat::Failed)
        );
        assert_eq!(
            Verstat::in_uri(b"sip:+1555;verstat=No-TN-Validation@x;user=phone"),
            Some(Verstat::NotValidated)
        );
        assert_eq!(
            Verstat::in_uri(b"tel:+1555;verstat=Something-Else"),
            Some(Verstat::Other("Something-Else".into()))
        );
        assert_eq!(Verstat::in_uri(b"tel:+1555"), None);
        assert_eq!(Verstat::in_uri(b"tel:+1555;verstat="), None);
    }
}
