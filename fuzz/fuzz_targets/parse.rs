// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Anything at all, through the message parser and every typed accessor.
//!
//! The parser is the first code an attacker reaches, and the only guarantee it
//! makes is that no input reaches a panic. Accessors are walked too, because a
//! message that parses can still hold a field nobody can read, and reading it
//! is what the stack does next. What the parser refuses is salvaged the way
//! the endpoint salvages it to write an answer, and walked the same way.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_core::msg::{
    Contacts, Limits, ParseMode, ParseScratch, RawMessage, parse, salvage_request,
};

fuzz_target!(|data: &[u8]| {
    for mode in [ParseMode::Strict, ParseMode::Lenient] {
        let mut scratch = ParseScratch::new();
        if let Ok(message) = parse(data, &mut scratch, mode) {
            let _ = message.validate();
            walk(&message);

            // the one copy in the receive path has to survive it too
            let owned = message.to_owned();
            assert!(owned.len() <= data.len());
            walk(&owned.as_raw());
        } else {
            let mut scratch = ParseScratch::new();
            if let Some(salvaged) = salvage_request(data, &mut scratch, Limits::DEFAULT.max_headers)
            {
                assert!(salvaged.header_slots().len() <= usize::from(Limits::DEFAULT.max_headers));
                walk(&salvaged);
            }
        }
    }
});

fn walk(m: &RawMessage<'_>) {
    let _ = m.kind();
    let _ = m.request_uri();
    let _ = m.reason();
    let _ = m.body();
    let _ = m.transaction_lookup_method();

    for via in m.via().flatten() {
        let _ = via.branch();
        let _ = via.received();
        let _ = via.rport();
        let _ = via.ttl();
        let _ = via.maddr();
        let _ = via.to_string();
    }
    for hop in m.route().chain(m.record_route()).flatten() {
        let _ = hop.is_loose_route();
        let _ = hop.to_string();
    }
    for address in [m.from(), m.to()].into_iter().flatten() {
        let _ = address.display_name();
        let _ = address.tag();
        let _ = address.q();
        let _ = address.expires();
        let _ = address.to_string();
    }
    if let Ok(Contacts::Addrs(addrs)) = m.contact() {
        for contact in addrs.flatten() {
            let _ = contact.display_name();
            let _ = contact.q();
            let _ = contact.expires();
        }
    }
    for challenge in m.www_authenticate().chain(m.proxy_authenticate()).flatten() {
        let _ = challenge.realm();
        let _ = challenge.stale();
        let _ = challenge.qop().count();
        let _ = challenge.domain().count();
        let _ = challenge.to_string();
    }
    for credentials in m.authorization().chain(m.proxy_authorization()).flatten() {
        let _ = credentials.nc();
        let _ = credentials.uri();
        let _ = credentials.response();
        let _ = credentials.to_string();
    }

    let _ = m.cseq();
    let _ = m.rack();
    let _ = m.rseq();
    let _ = m.call_id();
    let _ = m.date();
    let _ = m.expires();
    let _ = m.max_forwards();
    let _ = m.content_length();
    let _ = m.content_type();
    let _ = m.allow().count();
    let _ = m.supported().count();
    let _ = m.require().count();
    let _ = m.accept().count();
    let _ = m.header_names().count();
}
