// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Which transaction a message belongs to (RFC 3261 §17.1.3 and §17.2.3).
//!
//! A response finds its client transaction by the branch in the top `Via` and
//! the method in `CSeq`. The method is not redundant: a CANCEL borrows the
//! branch of the request it cancels while being a transaction of its own, so
//! branch alone would deliver its responses to the INVITE.
//!
//! A request finds its server transaction by the branch, the `Via`'s sent-by
//! and the method — "except for ACK, where the method of the request that
//! created the transaction is INVITE". The sent-by is in there because
//! "there could be accidental or malicious duplication of branch parameters
//! from different clients".
//!
//! A peer that predates RFC 3261 sends no magic cookie and its branch is not
//! unique, so §17.2.3 falls back to matching on the Request-URI, the From tag,
//! the `Call-ID`, the `CSeq` number — not its method, so that an ACK matches
//! the INVITE — and the top `Via`. That is implemented here, with one omission
//! written down rather than hidden: the RFC also compares an ACK's To tag
//! against the tag in the response the server sent, to tell an ACK for a 2xx
//! from an ACK for something else. Doing that needs the transaction's own
//! response rather than a key, and it only matters when a proxy forked and
//! then crashed. RFC 6026's `Accepted` state covers the 2xx side of it.

use super::super::msg::HostRef;
use super::super::msg::{HeaderError, HeaderName, Method, RawMessage, ViaRef};

/// The key a client transaction is found by.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ClientKey {
    branch: Box<[u8]>,
    /// Case-sensitive: RFC 3261 writes the six method names as fixed byte
    /// sequences, so `invite` is a different method, not the same one shouted
    /// quietly.
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
        from_tag: Box<[u8]>,
        call_id: Box<[u8]>,
        cseq: u32,
        method: Box<[u8]>,
        top_via: Box<[u8]>,
    },
}

impl ServerKey {
    /// The key for a request arriving from the network, whether it is creating
    /// a transaction or looking one up.
    ///
    /// An ACK is keyed as an INVITE, which is what puts it on the transaction
    /// that sent the response it acknowledges.
    ///
    /// # Errors
    /// [`HeaderError`] when a field the key is built from is missing or
    /// unreadable.
    pub(crate) fn for_request(request: &RawMessage<'_>) -> Result<Self, HeaderError> {
        // an ACK belongs to the INVITE server transaction that answered
        let method = request.transaction_lookup_method()?;
        Self::with_method(request, method)
    }

    /// The key of the INVITE server transaction a CANCEL is aimed at.
    ///
    /// §9.2: a CANCEL "is matched to the INVITE" it cancels, and it carries
    /// the same branch and sent-by for exactly that. Its own transaction is a
    /// different one, keyed on CANCEL by [`ServerKey::for_request`], and both
    /// exist at once.
    ///
    /// # Errors
    /// [`HeaderError`] when a field the key is built from is missing.
    pub(crate) fn for_cancelled(request: &RawMessage<'_>) -> Result<Self, HeaderError> {
        Self::with_method(request, Method::Invite)
    }

    fn with_method(request: &RawMessage<'_>, method: Method<'_>) -> Result<Self, HeaderError> {
        let via = request.top_via()?;
        let method: Box<[u8]> = method.as_str().as_bytes().into();

        if via.has_magic_cookie() {
            return Ok(Self::Rfc3261 {
                branch: branch_of(&via)?,
                sent_by: sent_by_of(&via),
                method,
            });
        }

        let cseq = request.cseq()?;
        let from = request.from()?;
        Ok(Self::Legacy {
            request_uri: request
                .request_uri_bytes()
                .ok_or(HeaderError::Malformed("not a request"))?
                .into(),
            from_tag: from
                .tag()
                .ok_or(HeaderError::Malformed("no From tag to match on"))?
                .into_owned()
                .into(),
            call_id: request.call_id()?.into(),
            // "CSeq number (not the method)", so that an ACK matches the
            // INVITE it acknowledges
            cseq: cseq.seq,
            method,
            top_via: request
                .header(HeaderName::Via)
                .ok_or(HeaderError::Missing)?
                .into(),
        })
    }
}

fn branch_of(via: &ViaRef<'_>) -> Result<Box<[u8]>, HeaderError> {
    let branch = via
        .branch()
        .ok_or(HeaderError::Malformed("Via has no branch to match on"))?;
    Ok(branch.into_owned().into())
}

/// The sent-by, normalised through the parsed form so that `h : 5060` and
/// `h:5060` are the one value they are.
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
}
