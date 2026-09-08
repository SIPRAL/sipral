// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Answering `OPTIONS`, which is not optional.
//!
//! §11.2 says a UAS receiving an OPTIONS outside a dialog "MUST respond", and
//! that the response is built as though the request had been an INVITE: the
//! same `Allow`, `Accept` and `Supported` the endpoint would have offered.
//!
//! It reads like a courtesy and it is not. Asterisk and every PBX built on it
//! send an OPTIONS to each registered contact on a timer, and a contact that
//! does not answer is marked unreachable — after which inbound calls to it are
//! refused with 503 without ever being sent. A stack that ignores OPTIONS
//! registers successfully, places calls happily, and silently never receives
//! one. That is what this stack did until an Asterisk was asked to ring it.
//!
//! It is answered here rather than handed to the application because there is
//! no decision in it. The application cannot know the answer better than the
//! stack does, and one that forgot to reply would look like this one did.

use std::time::Instant;

use sipral_core::endpoint::{Event, OutgoingResponse};
use sipral_core::msg::{HeaderName, Method, StatusCode};

use crate::agent::UserAgent;
use crate::reliable::UNDERSTOOD;
use crate::renegotiate::ALLOW;

/// The body types this end will take in a request. SDP, and nothing else:
/// there is no other body this stack knows how to read.
const ACCEPT: &[u8] = b"application/sdp";

impl UserAgent {
    /// `None` when this was an OPTIONS and has been answered; the event back
    /// when it was anything else.
    pub(crate) fn on_options_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        let Event::IncomingOutOfDialog {
            transaction,
            ref request,
        } = event
        else {
            return Some(event);
        };
        if request.as_raw().method() != Some(Method::Options) {
            return Some(event);
        }
        let supported = UNDERSTOOD.join(&b", "[..]);
        let response = OutgoingResponse::new(StatusCode::OK)
            .header(HeaderName::Allow, ALLOW)
            .header(HeaderName::Accept, ACCEPT)
            .header(HeaderName::Supported, &supported);
        // nothing useful to do if the transaction has gone: the far end will
        // ask again on its own timer, which is the whole point of asking
        self.endpoint.respond(transaction, &response, now).ok();
        None
    }
}
