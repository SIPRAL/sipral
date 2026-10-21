// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Anything at all, through the ISUP reader (ITU-T Q.763), as the body of an
//! `application/ISUP` part would reach it (RFC 3204).
//!
//! Beyond "no panic, on anything", every typed accessor is asked, so each
//! parameter decoder sees whatever content the message carries under its
//! name; and a message of a type whose parts are read is written again from
//! those parts with the builder, which has to read back to the same parts.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_core::isup::{IsupBuilder, parse};

fuzz_target!(|data: &[u8]| {
    let Ok(message) = parse(data) else {
        return;
    };
    let _ = (
        message.nature_of_connection(),
        message.forward_call(),
        message.calling_category(),
        message.transmission_medium(),
        message.backward_call(),
        message.event(),
        message.called_party(),
        message.calling_party(),
        message.original_called(),
        message.redirecting(),
        message.redirection_number(),
        message.connected(),
        message.redirection(),
        message.cause().map(|cause| (cause.name(), cause.class())),
    );
    for generic in message.generic_numbers() {
        let _ = (generic.number.text(), generic.to_bytes());
    }
    if let Some(number) = message.calling_party() {
        let _ = (number.to_calling_party(), number.is_dialable());
    }
    let _ = message.message_type().name();

    let mut builder = IsupBuilder::new(message.message_type()).fixed(message.fixed());
    if let Some(content) = message.variable() {
        builder = builder.variable(content);
    }
    for (name, content) in message.parameters() {
        builder = builder.optional(name, content);
    }
    // a type whose parts are not read, or a mandatory part too long to point
    // past, is a refusal and not a finding
    let Ok(written) = builder.build() else {
        return;
    };
    let again = parse(&written).expect("the builder's own message");
    assert_eq!(again.message_type(), message.message_type());
    assert_eq!(again.fixed(), message.fixed());
    assert_eq!(again.variable(), message.variable());
    assert!(again.parameters().eq(message.parameters()));
});
