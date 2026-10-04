// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! STIR/SHAKEN through the facade: one stack signs the call it places, the
//! other verifies it before its engine is told of the call, and the call
//! then carries audio like any other.

use sipral_stir::testing::credentials;

use crate::codec::CodecCatalog;
use crate::event::{Event, MediaEvent};
use crate::stir::{Signer, Tn, TrustAnchors};
use crate::tests::{Pair, callee_sip, caller_media, caller_sip, uri};
use crate::{
    Account, OutgoingCall, StirConfig, StirSigning, StirVerification, TransportId, UaEvent,
    VerificationOutcome,
};

const UDP: TransportId = TransportId(1);
const X5U: &str = "https://cert.example.org/passport.pem";

#[test]
fn a_signed_call_is_verified_and_then_answered_with_audio() {
    let credentials = credentials(&["12155551212"]);
    let mut pair = Pair::new(CodecCatalog::with_order(&["PCMU"]).expect("an order"));
    let unix = credentials.not_before + 1_000;
    pair.caller.agent.set_wall_clock(pair.now, unix);
    pair.callee.agent.set_wall_clock(pair.now, unix);
    let signer = Signer::new(&credentials.key, X5U).expect("a signer");
    let caller = pair.caller.agent.add_account(
        Account::new(
            uri("sip:12155551212@example.com"),
            uri("sip:example.com"),
            uri("sip:alice@192.0.2.1"),
            UDP,
            callee_sip(),
        )
        .stir_signing(StirSigning::new(
            signer,
            Tn::new("12155551212").expect("a number"),
        )),
    );
    let mut anchors = TrustAnchors::new();
    anchors
        .add(credentials.anchor.as_bytes())
        .expect("the test root");
    pair.callee.agent.set_stir(StirConfig::new(anchors));
    let _callee = pair.callee.agent.add_account(
        Account::new(
            uri("sip:12125551213@example.com"),
            uri("sip:example.com"),
            uri("sip:bob@192.0.2.2"),
            UDP,
            caller_sip(),
        )
        .stir_verification(StirVerification::Strict),
    );

    let placed = pair
        .caller
        .engine
        .place(
            &mut pair.caller.agent,
            caller,
            OutgoingCall::new(uri("sip:12125551213@example.com")).to_address(UDP, callee_sip()),
            caller_media(),
            pair.now,
        )
        .expect("a signed call goes");
    pair.caller.drain(pair.now, false);
    for datagram in pair.caller.outbound() {
        pair.callee.deliver(&datagram, caller_sip(), pair.now);
    }
    pair.callee.drain(pair.now, false);
    let (waiting, url) = pair
        .callee
        .heard
        .iter()
        .find_map(|event| match event {
            Event::Signalling(UaEvent::CertificateWanted { call, url }) => {
                Some((*call, url.to_string()))
            }
            _ => None,
        })
        .expect("the certificate is asked for through the engine's own drain");
    assert_eq!(url, X5U);
    assert!(
        pair.callee.engine.call_catalog(waiting).is_none(),
        "the engine is not told of a call before its verdict"
    );

    pair.callee
        .agent
        .stir_certificate(waiting, Some(credentials.chain.as_bytes()), pair.now)
        .expect("the call was waiting");
    // the drain answers the IncomingCall it now finds
    pair.callee.drain(pair.now, true);
    let verified = pair
        .callee
        .heard
        .iter()
        .find_map(|event| match event {
            Event::Signalling(UaEvent::CallerVerified { verification, .. }) => {
                Some(verification.outcome)
            }
            _ => None,
        })
        .expect("the verdict");
    assert_eq!(verified, VerificationOutcome::Valid);
    pair.settle();
    assert!(
        pair.caller
            .media_events()
            .iter()
            .any(|event| matches!(event, MediaEvent::Started { .. })),
        "the verified call carries audio"
    );
    assert!(pair.caller.engine.session(placed).is_some());
    assert!(pair.callee.engine.session(waiting).is_some());
}
