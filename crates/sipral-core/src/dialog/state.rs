// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The dialog itself (RFC 3261 §12).

use std::sync::Arc;

use super::DialogError;
use super::key::{CallId, DialogKey, Tag};
use super::request::InDialogRequest;
use crate::msg::{Contacts, HeaderError, Method, RawMessage, StatusCode, Uri};

/// Where a dialog is in its life (RFC 3261 §12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialogState {
    /// Opened by a provisional response: one 2xx from confirmed, one non-2xx
    /// final from gone.
    Early,
    /// A 2xx has been exchanged.
    Confirmed,
    /// Over. Nothing moves a dialog out of here.
    Terminated,
}

/// What is to be done with a request that arrived inside a dialog (§12.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Incoming {
    /// In order. The dialog has taken whatever the request changes.
    Accepted,
    /// Out of order, to be rejected with a 500. A rejected request changes
    /// nothing in the dialog.
    OutOfOrder,
}

/// A dialog: the state two user agents keep for as long as a call lasts.
///
/// Only what RFC 3261 §12 names. Media, offer/answer and fork choice live
/// above. Which tag is ours follows from the message, so the dialog does
/// not remember who started it; see [`DialogKey`].
#[derive(Clone, Debug)]
pub struct Dialog {
    key: DialogKey,
    state: DialogState,
    local_uri: Uri,
    remote_uri: Uri,
    remote_target: Uri,
    route_set: Arc<[Uri]>,
    local_seq: Option<u32>,
    remote_seq: Option<u32>,
    secure: bool,
}

/// §8.1.1.5: "The sequence number value MUST be expressible as a 32-bit
/// unsigned integer and MUST be less than 2**31."
const CSEQ_CEILING: u32 = 1 << 31;

impl Dialog {
    /// The dialog a response to our request opens (§12.1.2, UAC behaviour).
    ///
    /// `over_tls` comes from the transport: `secure` needs TLS and a SIPS
    /// Request-URI.
    ///
    /// # Errors
    /// [`DialogError::NotDialogCreating`] for a response that is neither
    /// 101-199 nor 2xx, [`DialogError::NoRemoteTarget`] when there is no
    /// `Contact`, and [`DialogError::Field`] or [`DialogError::Uri`] for a
    /// field that is missing or malformed.
    pub fn from_response(
        request: &RawMessage<'_>,
        response: &RawMessage<'_>,
        over_tls: bool,
    ) -> Result<Self, DialogError> {
        let state = state_for(response.status().ok_or(DialogError::WrongKind)?)?;

        // §12.1.2: Record-Route is "taken in reverse order"
        let mut route_set = record_route(response)?;
        route_set.reverse();

        Ok(Self {
            key: DialogKey::new(
                CallId::new(request.call_id()?),
                Tag::new(&request.from()?.tag().ok_or(DialogError::MissingTag)?),
                // §12.1.2: a missing To tag is a null tag
                response.to()?.tag().map(|t| Tag::new(&t)),
            ),
            state,
            local_uri: uri_of(request.from()?.uri_bytes())?,
            remote_uri: uri_of(request.to()?.uri_bytes())?,
            remote_target: contact_uri(response)?.ok_or(DialogError::NoRemoteTarget)?,
            route_set: route_set.into(),
            local_seq: Some(request.cseq()?.seq),
            remote_seq: None,
            secure: over_tls && request_uri_is_secure(request),
        })
    }

    /// The dialog our response to an incoming request opens (§12.1.1, UAS
    /// behaviour). `local_tag` goes in its `To`; `status` decides early or
    /// confirmed.
    ///
    /// # Errors
    /// As [`Dialog::from_response`].
    pub fn from_request(
        request: &RawMessage<'_>,
        local_tag: &[u8],
        status: StatusCode,
        over_tls: bool,
    ) -> Result<Self, DialogError> {
        let state = state_for(status)?;

        Ok(Self {
            key: DialogKey::new(
                CallId::new(request.call_id()?),
                Tag::new(local_tag),
                // §12.1.1: a missing From tag is a null tag
                request.from()?.tag().map(|t| Tag::new(&t)),
            ),
            state,
            local_uri: uri_of(request.to()?.uri_bytes())?,
            remote_uri: uri_of(request.from()?.uri_bytes())?,
            remote_target: contact_uri(request)?.ok_or(DialogError::NoRemoteTarget)?,
            // §12.1.1: Record-Route is "taken in order"
            route_set: record_route(request)?.into(),
            local_seq: None,
            remote_seq: Some(request.cseq()?.seq),
            secure: over_tls && request_uri_is_secure(request),
        })
    }

    /// The dialog's name.
    #[must_use]
    pub const fn key(&self) -> &DialogKey {
        &self.key
    }

    /// Where the dialog is in its life.
    #[must_use]
    pub const fn state(&self) -> DialogState {
        self.state
    }

    /// The URI that goes in `From` on our requests.
    #[must_use]
    pub const fn local_uri(&self) -> &Uri {
        &self.local_uri
    }

    /// The URI that goes in `To` on our requests.
    #[must_use]
    pub const fn remote_uri(&self) -> &Uri {
        &self.remote_uri
    }

    /// Where the peer is reachable for the rest of this dialog.
    #[must_use]
    pub const fn remote_target(&self) -> &Uri {
        &self.remote_target
    }

    /// The proxies to traverse, nearest first.
    #[must_use]
    pub fn route_set(&self) -> &[Uri] {
        &self.route_set
    }

    /// The number the last request we sent carried, if we have sent one.
    #[must_use]
    pub const fn local_seq(&self) -> Option<u32> {
        self.local_seq
    }

    /// The number the last request the peer sent carried, if it has sent one.
    #[must_use]
    pub const fn remote_seq(&self) -> Option<u32> {
        self.remote_seq
    }

    /// Whether the dialog is bound to TLS all the way (§12.1).
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        self.secure
    }

    /// The next request to send inside this dialog (§12.2.1.1). Consumes a
    /// sequence number.
    ///
    /// # Errors
    /// [`DialogError::NotItsOwnRequest`] for ACK and CANCEL, and
    /// [`DialogError::SequenceExhausted`] at the §8.1.1.5 ceiling.
    pub fn next_request(&mut self, method: Method<'_>) -> Result<InDialogRequest, DialogError> {
        if matches!(method, Method::Ack | Method::Cancel) {
            return Err(DialogError::NotItsOwnRequest);
        }
        let cseq = match self.local_seq {
            Some(previous) => previous
                .checked_add(1)
                .filter(|next| *next < CSEQ_CEILING)
                .ok_or(DialogError::SequenceExhausted)?,
            // §8.1.1.5 allows any start; the core draws no random numbers, and
            // each direction counts separately.
            None => 1,
        };
        self.local_seq = Some(cseq);

        let (request_uri, route) = self.target_and_route();
        Ok(InDialogRequest::new(
            method,
            request_uri,
            &route,
            addr_with_tag(&self.remote_uri, self.key.remote_tag()),
            addr_with_tag(&self.local_uri, Some(self.key.local_tag())),
            self.key.call_id().clone(),
            cseq,
        ))
    }

    /// The ACK for a 2xx to `invite` (§13.2.2.4).
    ///
    /// Unlike the ACK to a non-2xx (§17.1.1.3), this one follows the route
    /// set, may carry an answer, and is resent by hand for every repeated 2xx.
    /// It reuses the INVITE's sequence number and credentials.
    ///
    /// # Errors
    /// [`DialogError::Field`] when the INVITE has no readable `CSeq`.
    pub fn ack_2xx(&self, invite: &RawMessage<'_>) -> Result<InDialogRequest, DialogError> {
        // §13.2.2.4: same CSeq number as the INVITE, method ACK
        let cseq = invite.cseq()?.seq;
        let (request_uri, route) = self.target_and_route();
        let mut ack = InDialogRequest::new(
            Method::Ack,
            request_uri,
            &route,
            addr_with_tag(&self.remote_uri, self.key.remote_tag()),
            addr_with_tag(&self.local_uri, Some(self.key.local_tag())),
            self.key.call_id().clone(),
            cseq,
        );
        ack.copy_credentials(invite);
        Ok(ack)
    }

    /// A response arrived to a request we sent inside this dialog (§12.2.1.2).
    ///
    /// # Errors
    /// [`DialogError::WrongKind`] for a request, and [`DialogError::Field`]
    /// or [`DialogError::Uri`] for a `CSeq` or `Contact` that does not parse.
    pub fn on_response(&mut self, response: &RawMessage<'_>) -> Result<DialogState, DialogError> {
        let status = response.status().ok_or(DialogError::WrongKind)?;
        if self.state == DialogState::Terminated {
            return Ok(self.state);
        }
        let method = response.cseq()?.method;

        if status.is_success() {
            // §12.2.1.2: a 2xx to a target refresh replaces the remote target
            if is_target_refresh(method)
                && let Some(target) = contact_uri(response)?
            {
                self.remote_target = target;
            }
            if self.state == DialogState::Early && method == Method::Invite {
                // §13.2.2.4: the route set is recomputed from the 2xx, since RFC 2543
                // did not mirror Record-Route in provisionals. Sequence numbers stay.
                let mut recomputed = record_route(response)?;
                recomputed.reverse();
                self.route_set = recomputed.into();
                self.state = DialogState::Confirmed;
            }
            // §15.1.1: the session, and with it the dialog, is over
            if method == Method::Bye {
                self.state = DialogState::Terminated;
            }
        } else if status.is_final() {
            // §12.2.1.2: a 481 or 408 ends the dialog
            let gone = matches!(status.get(), 408 | 481);
            // §12.3: a non-2xx final to the request that created an early dialog
            // ends it; a rejected UPDATE or PRACK inside it does not.
            let invite_refused = self.state == DialogState::Early && method == Method::Invite;
            if gone || invite_refused || method == Method::Bye {
                self.state = DialogState::Terminated;
            }
        }
        Ok(self.state)
    }

    /// A request arrived inside this dialog (§12.2.2). The caller has already
    /// matched it to this dialog.
    ///
    /// # Errors
    /// [`DialogError::WrongKind`] for a response, and [`DialogError::Field`]
    /// or [`DialogError::Uri`] for a `CSeq` or `Contact` that does not parse.
    pub fn on_request(&mut self, request: &RawMessage<'_>) -> Result<Incoming, DialogError> {
        let cseq = request.cseq()?;
        let method = cseq.method;

        // An ACK carries the INVITE's number, so a retransmitted one may look
        // old, and it has no response to refuse it with. It is not a target
        // refresh either.
        if method == Method::Ack {
            return Ok(Incoming::Accepted);
        }

        // §12.2.2: lower is out of order. Equal is a retransmission.
        if let Some(remote) = self.remote_seq
            && cseq.seq < remote
        {
            return Ok(Incoming::OutOfOrder);
        }
        // §12.2.2: gaps are normal, a proxy challenge skips numbers
        self.remote_seq = Some(cseq.seq);

        // §12.2.2: a target refresh replaces the remote target
        if is_target_refresh(method)
            && let Some(target) = contact_uri(request)?
        {
            self.remote_target = target;
        }
        // §15.1.2: the UAS answers the BYE, and the dialog is over
        if method == Method::Bye {
            self.state = DialogState::Terminated;
        }
        Ok(Incoming::Accepted)
    }

    /// End the dialog without waiting for anything on the wire, e.g. when no
    /// response arrived at all (§12.2.1.2).
    pub const fn terminate(&mut self) {
        self.state = DialogState::Terminated;
    }

    /// Continue the numbering of a request this end sent before the dialog
    /// existed (RFC 6665 §4.4.1).
    ///
    /// For the subscriber: the NOTIFY opens the dialog, after our SUBSCRIBE
    /// already used a number. Restarting at one would make the refresh run
    /// backwards and get a 500 (§12.2.2). Only ever moves the number forward.
    pub const fn resume_from(&mut self, seq: u32) {
        match self.local_seq {
            Some(previous) if previous >= seq => (),
            _ => self.local_seq = Some(seq),
        }
    }

    /// The 2xx has gone out, so an early dialog is now confirmed (§12.1.1).
    /// An ended dialog stays ended.
    pub const fn confirm(&mut self) {
        if matches!(self.state, DialogState::Early) {
            self.state = DialogState::Confirmed;
        }
    }

    /// The Request-URI and the `Route` values for a request in this dialog
    /// (§12.2.1.1).
    ///
    /// A first hop without `;lr` is a strict router, which overwrites the
    /// Request-URI with the top `Route`. So the request goes to that proxy and
    /// the real target goes last in the route.
    fn target_and_route(&self) -> (Uri, Vec<Uri>) {
        match self.route_set.first() {
            None => (self.remote_target.as_request_uri(), Vec::new()),
            Some(first) if first.is_loose_route() => {
                (self.remote_target.as_request_uri(), self.route_set.to_vec())
            }
            Some(strict) => {
                let mut route: Vec<Uri> = self.route_set.iter().skip(1).cloned().collect();
                route.push(self.remote_target.clone());
                (strict.as_request_uri(), route)
            }
        }
    }
}

/// §12.1: only 101-199 and 2xx with a To tag open a dialog.
fn state_for(status: StatusCode) -> Result<DialogState, DialogError> {
    if status.is_success() {
        Ok(DialogState::Confirmed)
    } else if status.is_provisional() && status.get() >= 101 {
        Ok(DialogState::Early)
    } else {
        Err(DialogError::NotDialogCreating)
    }
}

/// Target refresh requests: re-INVITE (§12.2), UPDATE (RFC 3311 §5.1).
/// "Note that an ACK is NOT a target refresh request."
fn is_target_refresh(method: Method<'_>) -> bool {
    // RFC 6665 §3.1 and §3.2 add SUBSCRIBE and NOTIFY, so a notifier that
    // moves is followed.
    matches!(
        method,
        Method::Invite | Method::Update | Method::Subscribe | Method::Notify
    )
}

fn request_uri_is_secure(request: &RawMessage<'_>) -> bool {
    matches!(request.request_uri(), Some(Ok(uri)) if uri.scheme().is_secure())
}

/// The route set, "preserving all URI parameters", hence built from the
/// raw bytes.
fn record_route(message: &RawMessage<'_>) -> Result<Vec<Uri>, DialogError> {
    message
        .record_route()
        .map(|hop| uri_of(hop?.addr().uri_bytes()))
        .collect()
}

/// The `Contact` a remote target is taken from, if the message carries one.
fn contact_uri(message: &RawMessage<'_>) -> Result<Option<Uri>, DialogError> {
    let contacts = match message.contact() {
        Ok(contacts) => contacts,
        Err(HeaderError::Missing) => return Ok(None),
        Err(e) => return Err(DialogError::Field(e)),
    };
    let Contacts::Addrs(mut addrs) = contacts else {
        // "Contact: *" is not an address
        return Err(DialogError::NoRemoteTarget);
    };
    // §12.1: "the URI from the Contact header field", singular
    match addrs.next() {
        Some(addr) => Ok(Some(uri_of(addr?.uri_bytes())?)),
        None => Ok(None),
    }
}

fn uri_of(bytes: &[u8]) -> Result<Uri, DialogError> {
    Uri::parse(bytes).map_err(DialogError::Uri)
}

/// `<uri>;tag=...`, always in brackets so URI parameters stay in the URI.
fn addr_with_tag(uri: &Uri, tag: Option<&Tag>) -> Box<[u8]> {
    let mut out = Vec::with_capacity(uri.as_bytes().len() + 16);
    out.push(b'<');
    out.extend_from_slice(uri.as_bytes());
    out.push(b'>');
    // §12.2.1.1: a null tag means no tag parameter
    if let Some(tag) = tag {
        out.extend_from_slice(b";tag=");
        out.extend_from_slice(tag.as_bytes());
    }
    out.into_boxed_slice()
}

#[cfg(test)]
mod tests {
    use super::{Dialog, DialogState, Incoming};
    use crate::dialog::DialogError;
    use crate::msg::{Method, ParseMode, ParseScratch, RawMessage, StatusCode, Uri, parse};

    const INVITE: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
Max-Forwards: 70\r\n\
From: Alice <sip:alice@example.com>;tag=alice1\r\n\
To: Bob <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:alice@192.0.2.1>\r\n\
Content-Length: 0\r\n\
\r\n";

    /// The same INVITE at the callee: each proxy prepended itself to
    /// `Record-Route`.
    const INVITE_VIA_PROXIES: &[u8] = b"INVITE sip:bob@192.0.2.4 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.3:5060;branch=z9hG4bK3\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
Record-Route: <sip:p2.example.net;lr>, <sip:p1.example.net;lr>\r\n\
Max-Forwards: 68\r\n\
From: Alice <sip:alice@example.com>;tag=alice1\r\n\
To: Bob <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:alice@192.0.2.1>\r\n\
Content-Length: 0\r\n\
\r\n";

    fn response(status: u16, extra: &str) -> Vec<u8> {
        format!(
            "SIP/2.0 {status} Whatever\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
Record-Route: <sip:p2.example.net;lr>\r\n\
Record-Route: <sip:p1.example.net;lr>\r\n\
From: Alice <sip:alice@example.com>;tag=alice1\r\n\
To: Bob <sip:bob@example.com>;tag=bob1\r\n\
Call-ID: a84b4c76e66710\r\n\
{extra}\
Contact: <sip:bob@192.0.2.4>\r\n\
Content-Length: 0\r\n\
\r\n"
        )
        .into_bytes()
    }

    fn ringing() -> Vec<u8> {
        response(180, "CSeq: 314159 INVITE\r\n")
    }

    fn ok() -> Vec<u8> {
        response(200, "CSeq: 314159 INVITE\r\n")
    }

    fn with<R>(bytes: &[u8], f: impl FnOnce(&RawMessage<'_>) -> R) -> R {
        let mut scratch = ParseScratch::new();
        let message = parse(bytes, &mut scratch, ParseMode::Strict).expect("a message");
        f(&message)
    }

    fn caller_dialog(response: &[u8]) -> Dialog {
        with(INVITE, |request| {
            with(response, |response| {
                Dialog::from_response(request, response, false).expect("a dialog")
            })
        })
    }

    fn callee_dialog() -> Dialog {
        with(INVITE_VIA_PROXIES, |request| {
            Dialog::from_request(request, b"bob1", StatusCode::new(200).expect("200"), false)
                .expect("a dialog")
        })
    }

    fn feed_response(dialog: &mut Dialog, bytes: &[u8]) -> DialogState {
        with(bytes, |response| {
            dialog.on_response(response).expect("a response")
        })
    }

    fn feed_request(dialog: &mut Dialog, bytes: &[u8]) -> Incoming {
        with(bytes, |request| {
            dialog.on_request(request).expect("a request")
        })
    }

    fn in_dialog_request(method: &str, cseq: u32, extra: &str) -> Vec<u8> {
        format!(
            "{method} sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.4:5060;branch=z9hG4bK9\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bob1\r\n\
To: Alice <sip:alice@example.com>;tag=alice1\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: {cseq} {method}\r\n\
{extra}\
Content-Length: 0\r\n\
\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn the_caller_reverses_the_route_set_the_response_carried() {
        let dialog = caller_dialog(&ok());
        let hops: Vec<&str> = dialog.route_set().iter().map(Uri::as_str).collect();
        assert_eq!(hops, ["sip:p1.example.net;lr", "sip:p2.example.net;lr"]);
        assert_eq!(dialog.remote_target().as_str(), "sip:bob@192.0.2.4");
        assert_eq!(dialog.local_uri().as_str(), "sip:alice@example.com");
        assert_eq!(dialog.remote_uri().as_str(), "sip:bob@example.com");
        assert_eq!(dialog.local_seq(), Some(314_159));
        assert_eq!(dialog.remote_seq(), None);
        assert_eq!(dialog.state(), DialogState::Confirmed);
    }

    #[test]
    fn the_callee_keeps_the_route_set_in_the_order_it_arrived() {
        let dialog = callee_dialog();
        let hops: Vec<&str> = dialog.route_set().iter().map(Uri::as_str).collect();
        assert_eq!(hops, ["sip:p2.example.net;lr", "sip:p1.example.net;lr"]);
        assert_eq!(dialog.remote_target().as_str(), "sip:alice@192.0.2.1");
        assert_eq!(dialog.local_uri().as_str(), "sip:bob@example.com");
        assert_eq!(dialog.remote_uri().as_str(), "sip:alice@example.com");
        assert_eq!(dialog.local_seq(), None);
        assert_eq!(dialog.remote_seq(), Some(314_159));
        assert_eq!(dialog.key().local_tag().as_bytes(), b"bob1");
    }

    #[test]
    fn a_provisional_opens_it_early_and_the_2xx_confirms_it() {
        let mut dialog = caller_dialog(&ringing());
        assert_eq!(dialog.state(), DialogState::Early);
        assert_eq!(feed_response(&mut dialog, &ok()), DialogState::Confirmed);
    }

    #[test]
    fn a_100_trying_names_nothing_so_it_opens_nothing() {
        let trying = response(100, "CSeq: 314159 INVITE\r\n");
        let made = with(INVITE, |request| {
            with(&trying, |response| {
                Dialog::from_response(request, response, false)
            })
        });
        assert_eq!(made.unwrap_err(), DialogError::NotDialogCreating);
    }

    #[test]
    fn a_response_with_no_contact_leaves_nowhere_to_send_the_next_request() {
        let no_contact = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
From: Alice <sip:alice@example.com>;tag=alice1\r\n\
To: Bob <sip:bob@example.com>;tag=bob1\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let made = with(INVITE, |request| {
            with(no_contact, |response| {
                Dialog::from_response(request, response, false)
            })
        });
        assert_eq!(made.unwrap_err(), DialogError::NoRemoteTarget);
    }

    #[test]
    fn a_peer_that_sends_no_to_tag_still_gets_a_dialog() {
        let untagged = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
From: Alice <sip:alice@example.com>;tag=alice1\r\n\
To: Bob <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:bob@192.0.2.4>\r\n\
Content-Length: 0\r\n\
\r\n";
        let mut dialog = caller_dialog(untagged);
        assert!(dialog.key().remote_tag().is_none());
        let request = dialog.next_request(Method::Bye).expect("a BYE");
        assert_eq!(
            request.to(),
            b"<sip:bob@example.com>",
            "a null tag is omitted, not written empty"
        );
    }

    #[test]
    fn a_remote_uri_that_would_not_survive_its_brackets_makes_no_dialog() {
        // A '"' in an unbracketed user part opens a quoted string in the lexer
        // and hides ";tag=alice1" inside the URI
        let request = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
Max-Forwards: 70\r\n\
From: sip:a\"b@example.com;tag=alice1\r\n\
To: Bob <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:alice@192.0.2.1>\r\n\
Content-Length: 0\r\n\
\r\n";
        let made = with(request, |request| {
            Dialog::from_request(request, b"bob1", StatusCode::new(200).expect("200"), false)
        });
        match made {
            Err(DialogError::Field(_)) => (),
            Ok(mut dialog) => {
                let bye = dialog.next_request(Method::Bye).expect("a BYE");
                panic!(
                    "a dialog was made, and its BYE says To: {}",
                    String::from_utf8_lossy(bye.to())
                );
            }
            Err(other) => panic!("refused, but not for its From: {other}"),
        }
    }

    #[test]
    fn a_tag_that_would_not_go_back_out_as_one_parameter_makes_no_dialog() {
        // A tag is a token (§25.1). It is written back after `;tag=`, so a ';'
        // or ',' in it would inject a parameter or a second address.
        let quoted_maddr = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
Max-Forwards: 70\r\n\
From: Alice <sip:alice@example.com>;tag=\"alice1;maddr=198.51.100.66\"\r\n\
To: Bob <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:alice@192.0.2.1>\r\n\
Content-Length: 0\r\n\
\r\n";
        let made = with(quoted_maddr, |request| {
            Dialog::from_request(request, b"bob1", StatusCode::new(200).expect("200"), false)
        });
        match made {
            Err(DialogError::Field(_)) => (),
            Ok(mut dialog) => {
                let bye = dialog.next_request(Method::Bye).expect("a BYE");
                panic!(
                    "callee: a dialog was made, and its BYE says To: {}",
                    String::from_utf8_lossy(bye.to())
                );
            }
            Err(other) => panic!("callee: refused, but not for its From: {other}"),
        }

        let two_addresses = String::from_utf8_lossy(&ok()).replace(
            "To: Bob <sip:bob@example.com>;tag=bob1",
            "To: Bob <sip:bob@example.com>;tag=bob1, <sip:mallory@example.net>",
        );
        let made = with(INVITE, |request| {
            with(two_addresses.as_bytes(), |response| {
                Dialog::from_response(request, response, false)
            })
        });
        match made {
            Err(DialogError::Field(_)) => (),
            Ok(mut dialog) => {
                let bye = dialog.next_request(Method::Bye).expect("a BYE");
                panic!(
                    "caller: a dialog was made, and its BYE says To: {}",
                    String::from_utf8_lossy(bye.to())
                );
            }
            Err(other) => panic!("caller: refused, but not for its To: {other}"),
        }
    }

    #[test]
    fn the_secure_flag_wants_both_tls_and_a_sips_request_uri() {
        let over_sips = b"INVITE sips:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/TLS 192.0.2.1:5061;branch=z9hG4bK1\r\n\
From: Alice <sip:alice@example.com>;tag=alice1\r\n\
To: Bob <sips:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sips:alice@192.0.2.1>\r\n\
Content-Length: 0\r\n\
\r\n";
        let dialog = |request: &[u8], over_tls: bool| {
            with(request, |request| {
                with(&ok(), |response| {
                    Dialog::from_response(request, response, over_tls).expect("a dialog")
                })
            })
        };
        assert!(dialog(over_sips, true).is_secure());
        assert!(!dialog(over_sips, false).is_secure(), "SIPS but not TLS");
        assert!(!dialog(INVITE, true).is_secure(), "TLS but not SIPS");
    }

    #[test]
    fn the_sequence_number_climbs_by_one_in_our_direction() {
        let mut dialog = caller_dialog(&ok());
        for expected in [314_160, 314_161, 314_162] {
            let request = dialog.next_request(Method::Options).expect("a request");
            assert_eq!(request.cseq(), expected);
            assert_eq!(dialog.local_seq(), Some(expected));
        }
        assert_eq!(dialog.remote_seq(), None, "the other direction is theirs");
    }

    #[test]
    fn a_dialog_we_did_not_start_counts_from_one() {
        let mut dialog = callee_dialog();
        assert_eq!(dialog.local_seq(), None);
        assert_eq!(dialog.next_request(Method::Bye).expect("a BYE").cseq(), 1);
    }

    #[test]
    fn ack_and_cancel_do_not_get_a_number_of_their_own() {
        let mut dialog = caller_dialog(&ok());
        for method in [Method::Ack, Method::Cancel] {
            assert_eq!(
                dialog.next_request(method).unwrap_err(),
                DialogError::NotItsOwnRequest
            );
        }
        assert_eq!(dialog.local_seq(), Some(314_159), "and consume nothing");
    }

    #[test]
    fn with_no_route_set_the_request_goes_straight_to_the_remote_target() {
        let no_proxies = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
From: Alice <sip:alice@example.com>;tag=alice1\r\n\
To: Bob <sip:bob@example.com>;tag=bob1\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:bob@192.0.2.4>\r\n\
Content-Length: 0\r\n\
\r\n";
        let mut dialog = caller_dialog(no_proxies);
        let request = dialog.next_request(Method::Bye).expect("a BYE");
        assert_eq!(request.request_uri().as_str(), "sip:bob@192.0.2.4");
        assert_eq!(request.route().count(), 0, "and no Route at all");
    }

    #[test]
    fn a_loose_route_set_goes_out_in_order_and_leaves_the_request_uri_alone() {
        let mut dialog = caller_dialog(&ok());
        let request = dialog.next_request(Method::Bye).expect("a BYE");
        assert_eq!(request.request_uri().as_str(), "sip:bob@192.0.2.4");
        let route: Vec<&[u8]> = request.route().collect();
        assert_eq!(
            route,
            [
                b"<sip:p1.example.net;lr>".as_slice(),
                b"<sip:p2.example.net;lr>".as_slice()
            ]
        );
    }

    #[test]
    fn a_strict_router_takes_the_request_uri_and_the_target_goes_last() {
        // §12.2.1.1's worked example: the strict router proxy1 gets the request
        // and the target is pushed to the end of the Route.
        let via_a_strict_router = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
Record-Route: <sip:proxy4.example.net>, <sip:proxy3.example.net;lr>\r\n\
Record-Route: <sip:proxy2.example.net>, <sip:proxy1.example.net>\r\n\
From: Alice <sip:alice@example.com>;tag=alice1\r\n\
To: Bob <sip:bob@example.com>;tag=bob1\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:user@ua.example.org>\r\n\
Content-Length: 0\r\n\
\r\n";
        let mut dialog = caller_dialog(via_a_strict_router);
        let request = dialog.next_request(Method::Bye).expect("a BYE");
        assert_eq!(request.request_uri().as_str(), "sip:proxy1.example.net");
        let route: Vec<&[u8]> = request.route().collect();
        assert_eq!(
            route,
            [
                b"<sip:proxy2.example.net>".as_slice(),
                b"<sip:proxy3.example.net;lr>".as_slice(),
                b"<sip:proxy4.example.net>".as_slice(),
                b"<sip:user@ua.example.org>".as_slice(),
            ]
        );
    }

    #[test]
    fn the_built_request_carries_the_dialog_and_nothing_of_its_own() {
        let mut dialog = caller_dialog(&ok());
        let request = dialog.next_request(Method::Bye).expect("a BYE");
        let message = request
            .builder()
            .via(b"SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK7")
            .max_forwards(70)
            .build()
            .expect("a message");

        assert_eq!(
            message.as_raw().as_bytes(),
            b"BYE sip:bob@192.0.2.4 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK7\r\n\
Route: <sip:p1.example.net;lr>\r\n\
Route: <sip:p2.example.net;lr>\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=alice1\r\n\
To: <sip:bob@example.com>;tag=bob1\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314160 BYE\r\n\
Content-Length: 0\r\n\
\r\n"
        );
    }

    #[test]
    fn a_request_that_goes_backwards_is_refused_and_changes_nothing() {
        let mut dialog = callee_dialog();
        assert_eq!(
            feed_request(&mut dialog, &in_dialog_request("INFO", 314_160, "")),
            Incoming::Accepted
        );
        let earlier = in_dialog_request(
            "INVITE",
            314_159,
            "Contact: <sip:bob@192.0.2.99>\r\nContent-Type: application/sdp\r\n",
        );
        assert_eq!(feed_request(&mut dialog, &earlier), Incoming::OutOfOrder);
        assert_eq!(dialog.remote_seq(), Some(314_160), "not rolled back");
        assert_eq!(
            dialog.remote_target().as_str(),
            "sip:alice@192.0.2.1",
            "a rejected request performs none of its state changes"
        );
    }

    #[test]
    fn a_late_ack_is_not_out_of_order() {
        let mut dialog = callee_dialog();
        feed_request(&mut dialog, &in_dialog_request("INFO", 314_160, ""));
        assert_eq!(
            feed_request(&mut dialog, &in_dialog_request("ACK", 314_159, "")),
            Incoming::Accepted
        );
        assert_eq!(dialog.remote_seq(), Some(314_160), "and moves nothing");
    }

    #[test]
    fn a_gap_in_the_numbers_is_not_an_error() {
        let mut dialog = callee_dialog();
        assert_eq!(
            feed_request(&mut dialog, &in_dialog_request("INFO", 314_200, "")),
            Incoming::Accepted
        );
        assert_eq!(dialog.remote_seq(), Some(314_200));
    }

    #[test]
    fn only_a_target_refresh_moves_the_remote_target() {
        let mut dialog = callee_dialog();
        let contact = "Contact: <sip:bob@192.0.2.44>\r\n";

        // "Note that an ACK is NOT a target refresh request."
        feed_request(&mut dialog, &in_dialog_request("ACK", 314_159, contact));
        assert_eq!(dialog.remote_target().as_str(), "sip:alice@192.0.2.1");

        feed_request(&mut dialog, &in_dialog_request("INVITE", 314_160, contact));
        assert_eq!(dialog.remote_target().as_str(), "sip:bob@192.0.2.44");

        let moved = "Contact: <sip:bob@192.0.2.45>\r\n";
        feed_request(&mut dialog, &in_dialog_request("UPDATE", 314_161, moved));
        assert_eq!(
            dialog.remote_target().as_str(),
            "sip:bob@192.0.2.45",
            "RFC 3311 makes UPDATE a target refresh too"
        );

        feed_request(&mut dialog, &in_dialog_request("INVITE", 314_162, ""));
        assert_eq!(dialog.remote_target().as_str(), "sip:bob@192.0.2.45");
    }

    #[test]
    fn a_2xx_to_our_re_invite_moves_the_target_too() {
        let mut dialog = caller_dialog(&ok());
        let moved = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK7\r\n\
From: Alice <sip:alice@example.com>;tag=alice1\r\n\
To: Bob <sip:bob@example.com>;tag=bob1\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314160 INVITE\r\n\
Contact: <sip:bob@192.0.2.77>\r\n\
Content-Length: 0\r\n\
\r\n";
        assert_eq!(feed_response(&mut dialog, moved), DialogState::Confirmed);
        assert_eq!(dialog.remote_target().as_str(), "sip:bob@192.0.2.77");
        assert_eq!(dialog.route_set().len(), 2);
    }

    #[test]
    fn a_refused_invite_ends_the_early_dialog_it_opened() {
        let mut dialog = caller_dialog(&ringing());
        let busy = response(486, "CSeq: 314159 INVITE\r\n");
        assert_eq!(feed_response(&mut dialog, &busy), DialogState::Terminated);
    }

    #[test]
    fn but_a_refused_update_inside_an_early_dialog_leaves_it_standing() {
        let mut dialog = caller_dialog(&ringing());
        let refused = response(488, "CSeq: 314160 UPDATE\r\n");
        assert_eq!(feed_response(&mut dialog, &refused), DialogState::Early);
    }

    #[test]
    fn a_481_or_a_408_ends_a_confirmed_dialog() {
        for status in [408, 481] {
            let mut dialog = caller_dialog(&ok());
            let gone = response(status, "CSeq: 314160 INFO\r\n");
            assert_eq!(
                feed_response(&mut dialog, &gone),
                DialogState::Terminated,
                "{status}"
            );
        }
        let mut dialog = caller_dialog(&ok());
        let refused = response(501, "CSeq: 314160 INFO\r\n");
        assert_eq!(feed_response(&mut dialog, &refused), DialogState::Confirmed);
    }

    #[test]
    fn a_bye_ends_it_from_either_side() {
        let mut theirs = callee_dialog();
        feed_request(&mut theirs, &in_dialog_request("BYE", 314_160, ""));
        assert_eq!(theirs.state(), DialogState::Terminated);

        let mut ours = caller_dialog(&ok());
        let answered = response(200, "CSeq: 314160 BYE\r\n");
        assert_eq!(feed_response(&mut ours, &answered), DialogState::Terminated);

        let mut refused = caller_dialog(&ok());
        let refusal = response(500, "CSeq: 314160 BYE\r\n");
        assert_eq!(
            feed_response(&mut refused, &refusal),
            DialogState::Terminated
        );
    }

    #[test]
    fn nothing_moves_a_terminated_dialog() {
        let mut dialog = caller_dialog(&ok());
        dialog.terminate();
        assert_eq!(feed_response(&mut dialog, &ok()), DialogState::Terminated);
    }
}
