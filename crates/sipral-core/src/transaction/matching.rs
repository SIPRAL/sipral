// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Which transaction a message belongs to (RFC 3261 §17.1.3 and §17.2.3).
//!
//! A response finds its client transaction by the top `Via` branch and the
//! `CSeq` method. The method matters: a CANCEL shares the branch of the
//! request it cancels but is its own transaction.
//!
//! A request finds its server transaction by branch, `Via` sent-by and method,
//! "except for ACK, where the method of the request that created the
//! transaction is INVITE". Sent-by guards against "accidental or malicious
//! duplication of branch parameters from different clients".
//!
//! A pre-RFC 3261 peer sends no magic cookie and its branch is not unique.
//! §17.2.3 then compares Request-URI, `Call-ID`, `CSeq` and top `Via` for the
//! INVITE, the ACK and "all other request methods"; the INVITE and the others
//! also compare the To tag. The ACK does not, and compares the `CSeq` number
//! only, "not the method", so it finds its INVITE. Two simplifications:
//!
//! - The RFC compares the ACK's To tag with the tag in the server's response.
//!   A key built from a request does not have it, so an ACK is looked up
//!   twice (`server_for` in the store): without a To tag, finding an INVITE
//!   that opened a dialog, and with its own, finding a re-INVITE. The first
//!   lookup does not check the ACK's tag against ours; an ACK agreeing on
//!   Request-URI, From tag, `Call-ID`, `CSeq` number and whole top `Via` is
//!   taken as matching.
//! - Request-URI and top `Via` are compared as raw bytes, not by their
//!   equivalence rules (RFC 3261 §19.1.4). Real retransmissions, ACKs and
//!   CANCELs repeat them byte for byte; a peer respelling itself mid-dialog
//!   is not what this fallback is for.

use super::super::msg::HostRef;
use super::super::msg::{HeaderError, HeaderName, MAGIC_COOKIE, Method, RawMessage, ViaRef};

/// The key a client transaction is found by.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ClientKey {
    branch: Box<[u8]>,
    /// Case-sensitive: RFC 3261 method names are fixed byte sequences, so
    /// `invite` is a different method.
    method: Box<[u8]>,
}

impl ClientKey {
    /// The key for the transaction a request creates.
    ///
    /// # Errors
    /// [`HeaderError`] when the top `Via` is missing or unreadable, when it
    /// carries no branch, or when the message is not a request.
    pub(crate) fn for_request(request: &RawMessage<'_>) -> Result<Self, HeaderError> {
        let method = request
            .method()
            .ok_or(HeaderError::Malformed("not a request"))?;
        Ok(Self {
            branch: branch_of(&request.top_via()?)?,
            method: method.as_str().as_bytes().into(),
        })
    }

    /// The key a response is looked up by.
    ///
    /// # Errors
    /// [`HeaderError`] when the top `Via` or the `CSeq` is missing or
    /// unreadable.
    pub(crate) fn for_response(response: &RawMessage<'_>) -> Result<Self, HeaderError> {
        Ok(Self {
            branch: branch_of(&response.top_via()?)?,
            method: response.cseq()?.method.as_str().as_bytes().into(),
        })
    }
}

/// The key a server transaction is found by.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ServerKey {
    /// The peer sent the magic cookie, so its branch is unique to it.
    Rfc3261 {
        branch: Box<[u8]>,
        sent_by: Box<[u8]>,
        method: Box<[u8]>,
    },
    /// The peer predates RFC 3261 and its branch says nothing.
    Legacy {
        request_uri: Box<[u8]>,
        /// `None` for a peer that sent none: RFC 2543 did not require one,
        /// and §12.1.1 has a UAS "prepared to receive a request without a
        /// tag in the From field, in which case the tag is considered to
        /// have a value of null".
        from_tag: Option<Box<[u8]>>,
        call_id: Box<[u8]>,
        cseq: u32,
        method: Box<[u8]>,
        top_via: Box<[u8]>,
        /// §17.2.3: the request's own To tag, for the INVITE and every other
        /// method. An ACK is keyed without it and looked up with it again
        /// (see the module doc).
        to_tag: Option<Box<[u8]>>,
    },
}

impl ServerKey {
    /// The key for a request from the network, creating a transaction or
    /// looking one up. An ACK is keyed as an INVITE, which puts it on the
    /// transaction whose response it acknowledges.
    ///
    /// # Errors
    /// [`HeaderError`] when a field the key is built from is missing or
    /// unreadable.
    pub(crate) fn for_request(request: &RawMessage<'_>) -> Result<Self, HeaderError> {
        let method = request.transaction_lookup_method()?;
        Self::with_method(request, method)
    }

    /// The key of the INVITE server transaction a CANCEL is aimed at.
    ///
    /// §9.2: a CANCEL "is matched to the INVITE" by the same branch and
    /// sent-by. Its own transaction, keyed on CANCEL by
    /// [`ServerKey::for_request`], exists at the same time.
    ///
    /// # Errors
    /// [`HeaderError`] when a field the key is built from is missing.
    pub(crate) fn for_cancelled(request: &RawMessage<'_>) -> Result<Self, HeaderError> {
        Self::with_method(request, Method::Invite)
    }

    /// Whether this transaction's key is the one a CANCEL is aimed at.
    ///
    /// `cancel` comes from [`ServerKey::for_cancelled`]. §9.2 matches
    /// "assuming that the request method is anything but CANCEL or ACK": every
    /// field but the method must agree. An ACK never names its own
    /// transaction, so only CANCEL is ruled out; otherwise a CANCEL would
    /// cancel its own transaction.
    ///
    /// A `Legacy` key's To tag is compared too: §17.2.3's rule for "all other
    /// request methods" names it, and §9.1 has the CANCEL copy `To`, tag
    /// included.
    pub(crate) fn is_cancelled_by(&self, cancel: &Self) -> bool {
        let not_a_cancel = |method: &[u8]| method != Method::Cancel.as_str().as_bytes();
        match (self, cancel) {
            (
                Self::Rfc3261 {
                    branch,
                    sent_by,
                    method,
                },
                Self::Rfc3261 {
                    branch: aimed_branch,
                    sent_by: aimed_sent_by,
                    ..
                },
            ) => branch == aimed_branch && sent_by == aimed_sent_by && not_a_cancel(method),
            (
                Self::Legacy {
                    request_uri,
                    from_tag,
                    call_id,
                    cseq,
                    method,
                    top_via,
                    to_tag,
                },
                Self::Legacy {
                    request_uri: aimed_uri,
                    from_tag: aimed_from_tag,
                    call_id: aimed_call_id,
                    cseq: aimed_cseq,
                    top_via: aimed_top_via,
                    to_tag: aimed_to_tag,
                    ..
                },
            ) => {
                request_uri == aimed_uri
                    && from_tag == aimed_from_tag
                    && call_id == aimed_call_id
                    && cseq == aimed_cseq
                    && top_via == aimed_top_via
                    && to_tag == aimed_to_tag
                    && not_a_cancel(method)
            }
            _ => false,
        }
    }

    /// This key with `ack`'s To tag, for the second lookup of a legacy ACK
    /// (§17.2.3, see the module doc).
    ///
    /// `None` for an RFC 3261 key, a non-ACK request, or an ACK without a To
    /// tag: none has a second place to look.
    pub(crate) fn with_ack_to_tag(&self, ack: &RawMessage<'_>) -> Option<Self> {
        let Self::Legacy {
            request_uri,
            from_tag,
            call_id,
            cseq,
            method,
            top_via,
            to_tag: None,
        } = self
        else {
            return None;
        };
        if ack.method() != Some(Method::Ack) {
            return None;
        }
        let tag = ack.to().ok()?.tag()?;
        Some(Self::Legacy {
            request_uri: request_uri.clone(),
            from_tag: from_tag.clone(),
            call_id: call_id.clone(),
            cseq: *cseq,
            method: method.clone(),
            top_via: top_via.clone(),
            to_tag: Some(tag.into_owned().into()),
        })
    }

    fn with_method(request: &RawMessage<'_>, method: Method<'_>) -> Result<Self, HeaderError> {
        let via = request.top_via()?;
        let method: Box<[u8]> = method.as_str().as_bytes().into();

        // the cookie promises a branch "unique across space and time"
        // (§8.1.1.7), but a cookie alone does not keep it. RFC 4475 §3.2.1
        // offers "the RFC 2543-style transaction identifier" instead of a
        // refusal, which is the rule below
        let identified = via
            .branch()
            .is_some_and(|branch| branch.len() > MAGIC_COOKIE.len());
        if via.has_magic_cookie() && identified {
            return Ok(Self::Rfc3261 {
                branch: branch_of(&via)?,
                sent_by: sent_by_of(&via),
                method,
            });
        }

        let cseq = request.cseq()?;
        let from = request.from()?;
        // an ACK skips the To tag; see the module doc
        let to_tag = if request.method() == Some(Method::Ack) {
            None
        } else {
            request.to()?.tag().map(|tag| tag.into_owned().into())
        };
        Ok(Self::Legacy {
            request_uri: request
                .request_uri_bytes()
                .ok_or(HeaderError::Malformed("not a request"))?
                .into(),
            from_tag: from.tag().map(|tag| tag.into_owned().into()),
            call_id: request.call_id()?.into(),
            // "CSeq number (not the method)", so that an ACK matches the
            // INVITE it acknowledges
            cseq: cseq.seq,
            method,
            top_via: request
                .header(HeaderName::Via)
                .ok_or(HeaderError::Missing)?
                .into(),
            to_tag,
        })
    }
}

fn branch_of(via: &ViaRef<'_>) -> Result<Box<[u8]>, HeaderError> {
    let branch = via
        .branch()
        .ok_or(HeaderError::Malformed("Via has no branch to match on"))?;
    Ok(branch.into_owned().into())
}

/// The sent-by, normalised through the parsed form so `h : 5060` and
/// `h:5060` are equal.
fn sent_by_of(via: &ViaRef<'_>) -> Box<[u8]> {
    let mut out = Vec::with_capacity(32);
    match via.host {
        // a host name is case-insensitive; an address literal has one spelling
        HostRef::Name(name) => out.extend(name.bytes().map(|b| b.to_ascii_lowercase())),
        HostRef::Ipv4(addr) => out.extend_from_slice(addr.to_string().as_bytes()),
        HostRef::Ipv6(addr) => {
            out.push(b'[');
            out.extend_from_slice(addr.to_string().as_bytes());
            out.push(b']');
        }
    }
    if let Some(port) = via.port {
        out.push(b':');
        out.extend_from_slice(port.to_string().as_bytes());
    }
    out.into()
}

#[cfg(test)]
mod tests {
    use super::{ClientKey, ServerKey};
    use crate::msg::{ParseMode, ParseScratch, RawMessage, parse};

    fn with<T>(buf: &[u8], f: impl FnOnce(&RawMessage<'_>) -> T) -> T {
        let mut scratch = ParseScratch::new();
        let message = parse(buf, &mut scratch, ParseMode::Strict).expect("a message");
        f(&message)
    }

    const INVITE: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnashds8\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

    const RINGING: &[u8] = b"SIP/2.0 180 Ringing\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnashds8\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>;tag=a6c85cf\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

    #[test]
    fn a_response_finds_the_transaction_its_request_created() {
        let request = with(INVITE, ClientKey::for_request).expect("a key");
        let response = with(RINGING, ClientKey::for_response).expect("a key");
        assert_eq!(request, response);
    }

    #[test]
    fn a_cancel_shares_the_branch_and_is_a_different_transaction() {
        // "The method is needed since a CANCEL request constitutes a different
        // transaction, but shares the same value of the branch parameter"
        let cancel = b"CANCEL sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnashds8\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 CANCEL\r\n\
Content-Length: 0\r\n\
\r\n";
        let invite = with(INVITE, ClientKey::for_request).expect("a key");
        let cancel = with(cancel, ClientKey::for_request).expect("a key");
        assert_ne!(invite, cancel, "same branch, different transaction");

        let cancel_response = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnashds8\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>;tag=a6c85cf\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 CANCEL\r\n\
Content-Length: 0\r\n\
\r\n";
        assert_eq!(
            with(cancel_response, ClientKey::for_response).expect("a key"),
            cancel,
            "and its response follows the CSeq method to the right one"
        );
    }

    #[test]
    fn an_ack_is_keyed_as_the_invite_it_answers() {
        // 17.2.3 rule 3: "except for ACK, where the method of the request that
        // created the transaction is INVITE"
        let ack = b"ACK sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnashds8\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>;tag=a6c85cf\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 ACK\r\n\
Content-Length: 0\r\n\
\r\n";
        assert_eq!(
            with(ack, ServerKey::for_request).expect("a key"),
            with(INVITE, ServerKey::for_request).expect("a key")
        );
    }

    #[test]
    fn a_cancel_is_its_own_transaction_and_still_finds_the_invite() {
        // 9.2: the CANCEL "is matched to the INVITE" by branch and sent-by,
        // while being a server transaction of its own keyed on CANCEL
        let cancel = b"CANCEL sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnashds8\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 CANCEL\r\n\
Content-Length: 0\r\n\
\r\n";
        let own = with(cancel, ServerKey::for_request).expect("a key");
        let target = with(cancel, ServerKey::for_cancelled).expect("a key");
        assert_ne!(own, target, "a CANCEL is not the INVITE it cancels");
        assert_eq!(
            target,
            with(INVITE, ServerKey::for_request).expect("a key"),
            "the CANCEL has to reach the INVITE's transaction"
        );
    }

    #[test]
    fn the_sent_by_is_part_of_the_key() {
        // "there could be accidental or malicious duplication of branch
        // parameters from different clients"
        let elsewhere = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bKnashds8\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        assert_ne!(
            with(INVITE, ServerKey::for_request).expect("a key"),
            with(elsewhere, ServerKey::for_request).expect("a key")
        );
    }

    #[test]
    fn the_sent_by_is_compared_as_a_value_not_as_bytes() {
        // COLON is SWS ":" SWS, and a host name is case-insensitive
        let spaced = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP Host.Example.COM : 5060;branch=z9hG4bK1\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: c\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let tight = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK1\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: c\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        assert_eq!(
            with(spaced, ServerKey::for_request).expect("a key"),
            with(tight, ServerKey::for_request).expect("a key")
        );
    }

    #[test]
    fn a_peer_without_the_magic_cookie_is_matched_the_old_way() {
        // RFC 4475 3.4.1 inv2543 is one of these
        let old = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=0ae4be1c\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let old_ack = b"ACK sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=0ae4be1c\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>;tag=a6c85cf\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 ACK\r\n\
Content-Length: 0\r\n\
\r\n";
        let key = with(old, ServerKey::for_request).expect("a key");
        assert_eq!(
            with(old_ack, ServerKey::for_request).expect("a key"),
            key,
            "the ACK matches on the CSeq number, not its method"
        );
        assert_ne!(
            with(INVITE, ServerKey::for_request).expect("a key"),
            key,
            "a peer with the cookie is not keyed the old way"
        );
    }

    #[test]
    fn a_legacy_cancel_still_finds_the_transaction_it_cancels() {
        // §9.2 must still work for a legacy peer: the fallback compares the
        // whole Via and the other four fields
        let options = b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=0ae4be1c\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 OPTIONS\r\n\
Content-Length: 0\r\n\
\r\n";
        let cancel = b"CANCEL sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=0ae4be1c\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 CANCEL\r\n\
Content-Length: 0\r\n\
\r\n";
        let transaction = with(options, ServerKey::for_request).expect("a key");
        let aimed = with(cancel, ServerKey::for_cancelled).expect("a key");
        assert!(
            transaction.is_cancelled_by(&aimed),
            "the same five fields, without a trustworthy branch, still match"
        );

        // the same branch a different call happens to share, since a legacy
        // peer's branch says nothing on its own
        let elsewhere = b"CANCEL sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=0ae4be1c\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a-different-call\r\n\
CSeq: 314159 CANCEL\r\n\
Content-Length: 0\r\n\
\r\n";
        assert!(
            !transaction
                .is_cancelled_by(&with(elsewhere, ServerKey::for_cancelled).expect("a key")),
            "a shared legacy branch alone must not be enough to match"
        );

        // the same branch and Call-ID, but a CSeq number that names a
        // different request on that call
        let wrong_cseq = b"CANCEL sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=0ae4be1c\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 2 CANCEL\r\n\
Content-Length: 0\r\n\
\r\n";
        assert!(
            !transaction
                .is_cancelled_by(&with(wrong_cseq, ServerKey::for_cancelled).expect("a key")),
            "a CANCEL for a different CSeq number on the same call must not match"
        );
    }

    #[test]
    fn a_cancel_keyed_the_other_way_than_its_transaction_never_matches() {
        // a CANCEL whose magic cookie disagrees with the transaction it names
        // (a forged shape) falls through to the last arm, which no
        // field-by-field branch inspects
        let cookie = with(INVITE, ServerKey::for_request).expect("a key");
        let no_cookie = b"CANCEL sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=0ae4be1c\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 CANCEL\r\n\
Content-Length: 0\r\n\
\r\n";
        assert!(
            !cookie.is_cancelled_by(&with(no_cookie, ServerKey::for_cancelled).expect("a key")),
            "an RFC 3261 transaction must not be cancelled by a legacy-keyed CANCEL"
        );

        let legacy = with(no_cookie, ServerKey::for_request).expect("a key");
        let with_cookie = b"CANCEL sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnashds8\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 CANCEL\r\n\
Content-Length: 0\r\n\
\r\n";
        assert!(
            !legacy.is_cancelled_by(&with(with_cookie, ServerKey::for_cancelled).expect("a key")),
            "a legacy transaction must not be cancelled by an RFC 3261-keyed CANCEL"
        );
    }

    #[test]
    fn a_legacy_in_dialog_request_is_told_apart_by_its_to_tag() {
        // §17.2.3 "all other request methods" compares the To tag: two INFOs
        // in different dialogs must not collide
        let one = b"INFO sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=0ae4be1c\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>;tag=aaa\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 1 INFO\r\n\
Content-Length: 0\r\n\
\r\n";
        let other = b"INFO sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=0ae4be1c\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>;tag=bbb\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 1 INFO\r\n\
Content-Length: 0\r\n\
\r\n";
        assert_ne!(
            with(one, ServerKey::for_request).expect("a key"),
            with(other, ServerKey::for_request).expect("a key"),
            "two dialogs must not share a transaction because a legacy peer's \
             branch says nothing"
        );
        // and a genuine retransmission, which repeats the To tag along with
        // everything else, still matches
        assert_eq!(
            with(one, ServerKey::for_request).expect("a key"),
            with(one, ServerKey::for_request).expect("a key")
        );
    }

    #[test]
    fn a_legacy_cancel_matches_only_inside_the_dialog_it_names() {
        // §9.2 uses §17.2.3's rule, which compares the To tag; §9.1 has the
        // CANCEL copy To, tag included
        let info = b"INFO sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=0ae4be1c\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>;tag=aaa\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 1 INFO\r\n\
Content-Length: 0\r\n\
\r\n";
        let same_dialog = b"CANCEL sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=0ae4be1c\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>;tag=aaa\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 1 CANCEL\r\n\
Content-Length: 0\r\n\
\r\n";
        let other_dialog = b"CANCEL sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=0ae4be1c\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>;tag=bbb\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 1 CANCEL\r\n\
Content-Length: 0\r\n\
\r\n";
        let transaction = with(info, ServerKey::for_request).expect("a key");
        assert!(
            transaction
                .is_cancelled_by(&with(same_dialog, ServerKey::for_cancelled).expect("a key"))
        );
        assert!(
            !transaction
                .is_cancelled_by(&with(other_dialog, ServerKey::for_cancelled).expect("a key")),
            "a CANCEL naming another dialog must not match this one's transaction"
        );
    }

    #[test]
    fn an_ack_matches_its_invite_however_the_to_tags_disagree() {
        // the INVITE has no To tag, its ACK always has one. §17.2.3 compares
        // against the response's tag; the fallback leaves that out rather
        // than always fail
        let invite = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=0ae4be1c\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let ack = b"ACK sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=0ae4be1c\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>;tag=a6c85cf\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 ACK\r\n\
Content-Length: 0\r\n\
\r\n";
        assert_eq!(
            with(invite, ServerKey::for_request).expect("a key"),
            with(ack, ServerKey::for_request).expect("a key")
        );
    }

    #[test]
    fn a_request_with_no_branch_at_all_cannot_be_keyed_on_one() {
        let bare = b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: c\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\
\r\n";
        assert!(with(bare, ClientKey::for_request).is_err());
        // but the old rule does not need one
        assert!(with(bare, ServerKey::for_request).is_ok());
    }

    #[test]
    fn a_request_with_no_from_tag_is_keyed_the_old_way_rather_than_dropped() {
        // RFC 4475 §3.4.1 (inv2543): no branch and no From tag, both legal in
        // RFC 2543, and §12.1.1 has a UAS "prepared to receive a request
        // without a tag in the From field"
        let old = b"INVITE sip:UserB@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP iftgw.example.com\r\n\
From: <sip:+13035551111@ift.client.example.net;user=phone>\r\n\
To: sip:+16505552222@ss1.example.net;user=phone\r\n\
Call-ID: inv2543.1717@ift.client.example.com\r\n\
CSeq: 56 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let key = with(old, ServerKey::for_request).expect("the old rule keys it");
        // and the ACK for its final response, which carries none either, finds it
        let ack = b"ACK sip:UserB@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP iftgw.example.com\r\n\
From: <sip:+13035551111@ift.client.example.net;user=phone>\r\n\
To: sip:+16505552222@ss1.example.net;user=phone;tag=b1\r\n\
Call-ID: inv2543.1717@ift.client.example.com\r\n\
CSeq: 56 ACK\r\n\
Content-Length: 0\r\n\
\r\n";
        assert_eq!(with(ack, ServerKey::for_request).expect("a key"), key);
        // while a request that did carry a tag is a different transaction
        let tagged = b"INVITE sip:UserB@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP iftgw.example.com\r\n\
From: <sip:+13035551111@ift.client.example.net;user=phone>;tag=x\r\n\
To: sip:+16505552222@ss1.example.net;user=phone\r\n\
Call-ID: inv2543.1717@ift.client.example.com\r\n\
CSeq: 56 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        assert_ne!(with(tagged, ServerKey::for_request).expect("a key"), key);
    }

    #[test]
    fn a_branch_that_is_only_the_magic_cookie_identifies_nothing() {
        // RFC 4475 §3.2.1 (badbranch): a cookie with no identifier. Keyed on
        // the branch, every such request from one sent-by would collide; the
        // RFC's alternative to a 400 is the RFC 2543 rule
        let request = |call_id: &str, seq: u32| {
            format!(
                "OPTIONS sip:user@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK\r\n\
Max-Forwards: 3\r\n\
From: sip:caller@example.org;tag=33242\r\n\
To: sip:user@example.com\r\n\
Call-ID: {call_id}\r\n\
CSeq: {seq} OPTIONS\r\n\
Content-Length: 0\r\n\
\r\n"
            )
            .into_bytes()
        };
        let first = with(&request("badbranch.1", 8), ServerKey::for_request).expect("a key");
        let second = with(&request("badbranch.2", 9), ServerKey::for_request).expect("a key");
        assert!(matches!(first, ServerKey::Legacy { .. }), "{first:?}");
        assert_ne!(first, second, "two requests were made one transaction");
        // a retransmission is still the same one
        assert_eq!(
            with(&request("badbranch.1", 8), ServerKey::for_request).expect("a key"),
            first
        );
    }
}
