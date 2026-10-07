// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Answering `OPTIONS`, which is not optional.
//!
//! §11.2: a UAS MUST respond, with the `Allow`, `Accept` and `Supported` an
//! INVITE would get, inside a dialog or outside it.
//!
//! Asterisk qualifies each registered contact with OPTIONS and stops sending
//! calls to one that does not answer, so this is answered here, with no
//! application decision involved.

use std::time::Instant;

use sipral_core::endpoint::{Event, OutgoingResponse};
use sipral_core::msg::{HeaderName, Method, StatusCode};

use crate::agent::UserAgent;
use crate::reliable::UNDERSTOOD;
use crate::renegotiate::ALLOW;

/// The body types this end accepts: SDP only.
const ACCEPT: &[u8] = b"application/sdp";

impl UserAgent {
    /// `None` when this was an OPTIONS and has been answered; the event back
    /// when it was anything else.
    pub(crate) fn on_options_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        let (Event::IncomingOutOfDialog {
            transaction,
            ref request,
        }
        | Event::IncomingInDialog {
            transaction,
            ref request,
            ..
        }) = event
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
        // a gone transaction is fine: the far end asks again on its timer
        self.endpoint.respond(transaction, &response, now).ok();
        None
    }
}
