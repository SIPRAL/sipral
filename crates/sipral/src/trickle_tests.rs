// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Trickle ICE between two stacks in process (RFC 8838, carried by RFC 8840's INFO): what the
//! descriptions say under each stance, a candidate trickled after the call was described reaching
//! the far end's agent and being checked, the end of candidates, and a far end that does not
//! trickle getting regular ICE.
//!
//! The pair and its helpers are `crate::tests`'s, on the same 192.0.2.x addresses.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral_core::msg::HeaderName;
use sipral_core::sdp::SessionDescription;

use crate::tests::{Pair, Stack, callee_media, caller_media, loudness, tone};
use crate::{CallHandle, CodecCatalog, Event, IcePolicy, IceTrickle, MediaError, UaEvent};

/// Where the caller's media socket appears from outside, as its STUN mapping would say.
fn caller_public() -> SocketAddr {
    "203.0.113.1:50000".parse().expect("an address")
}

/// Where the callee's does.
fn callee_public() -> SocketAddr {
    "203.0.113.2:50002".parse().expect("an address")
}

fn catalog(trickle: IceTrickle) -> CodecCatalog {
    CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(IcePolicy::Required)
        .with_ice_trickle(trickle)
}

/// A pair under these two stances, both agents taking the package, connected.
fn trickling(placing: IceTrickle, answering: IceTrickle) -> (Pair, CallHandle, CallHandle) {
    let mut pair = Pair::asymmetric(catalog(placing), catalog(answering));
    pair.caller.agent.accept_trickle_ice(true);
    pair.callee.agent.accept_trickle_ice(true);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee's side of the call");
    (pair, call, remote)
}

fn value<'a>(description: &'a SessionDescription, name: &str) -> Option<&'a str> {
    let stream = description
        .media
        .iter()
        .find(|stream| !stream.is_rejected())?;
    stream
        .attributes
        .iter()
        .find(|attribute| attribute.name == name)
        .map(|attribute| attribute.value.as_deref().unwrap_or_default())
}

/// The INVITE the callee was handed.
fn invite_field(stack: &Stack, name: HeaderName<'_>) -> String {
    stack
        .heard
        .iter()
        .find_map(|event| match event {
            Event::Signalling(UaEvent::IncomingCall { request, .. }) => Some(
                request
                    .as_raw()
                    .header_values(name)
                    .map(|value| String::from_utf8_lossy(value).into_owned())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            _ => None,
        })
        .unwrap_or_default()
}

/// The bodies of every INFO of the package one side heard.
fn trickled_to(stack: &Stack) -> Vec<String> {
    stack
        .heard
        .iter()
        .filter_map(|event| match event {
            Event::Signalling(UaEvent::TrickleIce { body, .. }) => {
                Some(String::from_utf8_lossy(body).into_owned())
            }
            _ => None,
        })
        .collect()
}

/// Every place one side's agent sends checks over `rounds` pacing intervals, the clock moving.
fn checked_from(stack: &mut Stack, now: &mut Instant, rounds: usize) -> Vec<SocketAddr> {
    let mut sent = Vec::new();
    for _ in 0..rounds {
        while let Some((_, destination, _)) = stack.engine.poll_transmit(*now) {
            sent.push(destination);
        }
        *now += Duration::from_millis(50);
        stack.engine.handle_timeout(*now);
    }
    sent
}

#[test]
fn a_full_trickle_offer_goes_at_once_and_says_it_requires_the_far_end_to_trickle() {
    let (pair, _, _) = trickling(IceTrickle::Full, IceTrickle::Full);
    let offer = pair.callee.offer_received().expect("the offer");
    assert_eq!(value(&offer, "ice-options"), Some("trickle ice2"));
    assert_eq!(value(&offer, "mid"), Some("0"), "RFC 8840 §4.1.1's a=mid");
    assert_eq!(
        value(&offer, "end-of-candidates"),
        None,
        "more candidates may follow"
    );
    assert!(invite_field(&pair.callee, HeaderName::Require).contains("trickle-ice"));
    assert!(invite_field(&pair.callee, HeaderName::Supported).contains("trickle-ice"));
    assert_eq!(
        invite_field(&pair.callee, HeaderName::Extension("Recv-Info")),
        "trickle-ice"
    );
    let answer = pair.caller.answer_received().expect("the answer");
    assert_eq!(value(&answer, "ice-options"), Some("trickle ice2"));
    assert_eq!(value(&answer, "mid"), Some("0"), "the offer's tag");
}

#[test]
fn a_half_trickle_offer_is_whole_and_says_so() {
    let (pair, _, _) = trickling(IceTrickle::Half, IceTrickle::Half);
    let offer = pair.callee.offer_received().expect("the offer");
    assert_eq!(value(&offer, "ice-options"), Some("trickle ice2"));
    assert_eq!(value(&offer, "end-of-candidates"), Some(""));
    assert!(
        !invite_field(&pair.callee, HeaderName::Require).contains("trickle-ice"),
        "half trickle assumes nothing of the far end (RFC 8840 §5.3)"
    );
    assert!(invite_field(&pair.callee, HeaderName::Supported).contains("trickle-ice"));
}

#[test]
fn a_reflexive_candidate_learned_after_the_offer_reaches_the_far_end_and_is_checked() {
    let (mut pair, call, remote) = trickling(IceTrickle::Full, IceTrickle::Full);
    let before = trickled_to(&pair.callee).len();
    pair.caller
        .engine
        .trickle_public_address(&mut pair.caller.agent, call, caller_public(), pair.now)
        .expect("trickled");
    pair.settle();
    let bodies = trickled_to(&pair.callee);
    assert!(bodies.len() > before, "an INFO crossed");
    let last = bodies.last().expect("a body");
    assert!(last.contains("typ srflx"), "{last}");
    assert!(last.contains(&format!(
        "{} {}",
        caller_public().ip(),
        caller_public().port()
    )));

    // the callee's agent pairs it and checks it (RFC 8838 §11)
    let mut now = pair.now;
    let checked = checked_from(&mut pair.callee, &mut now, 40);
    assert!(
        checked.contains(&caller_public()),
        "the callee checked the trickled candidate: {checked:?}"
    );
    assert!(
        pair.callee
            .engine
            .session(remote)
            .is_some_and(|session| session
                .path_candidates()
                .iter()
                .any(|path| path.remote == caller_public())),
        "and lists the pair among its paths"
    );
}

#[test]
fn an_answerer_trickles_too_once_the_caller_holds_the_dialog() {
    let (mut pair, _, remote) = trickling(IceTrickle::Half, IceTrickle::Full);
    pair.callee
        .engine
        .trickle_public_address(&mut pair.callee.agent, remote, callee_public(), pair.now)
        .expect("trickled");
    pair.settle();
    let bodies = trickled_to(&pair.caller);
    assert!(
        bodies.iter().any(|body| body.contains("typ srflx")),
        "the caller heard the callee's reflexive candidate: {bodies:?}"
    );
    let mut now = pair.now;
    let checked = checked_from(&mut pair.caller, &mut now, 40);
    assert!(checked.contains(&callee_public()), "{checked:?}");
}

#[test]
fn the_end_of_candidates_goes_once_and_nothing_follows_it() {
    let (mut pair, call, _) = trickling(IceTrickle::Full, IceTrickle::Full);
    pair.caller
        .engine
        .end_of_candidates(&mut pair.caller.agent, call, pair.now)
        .expect("said");
    pair.settle();
    let bodies = trickled_to(&pair.callee);
    assert!(
        bodies
            .last()
            .is_some_and(|body| body.contains("a=end-of-candidates")),
        "{bodies:?}"
    );
    let heard = bodies.len();
    pair.caller
        .engine
        .end_of_candidates(&mut pair.caller.agent, call, pair.now)
        .expect("saying it again is harmless");
    assert_eq!(
        pair.caller.engine.trickle_public_address(
            &mut pair.caller.agent,
            call,
            caller_public(),
            pair.now
        ),
        Err(MediaError::NotTrickling),
        "no candidate after the end of candidates (RFC 8838 §13)"
    );
    pair.settle();
    assert_eq!(
        trickled_to(&pair.callee).len(),
        heard,
        "nothing more crossed"
    );
}

#[test]
fn a_far_end_that_does_not_trickle_gets_regular_ice_and_no_info() {
    // what Asterisk does with a trickle offer: answers without trickle
    let mut pair = Pair::asymmetric(
        catalog(IceTrickle::Half),
        CodecCatalog::with_order(&["PCMU"])
            .expect("an order")
            .with_ice(IcePolicy::Offered),
    );
    pair.caller.agent.accept_trickle_ice(true);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee's side");
    let answer = pair.caller.answer_received().expect("the answer");
    assert_eq!(value(&answer, "ice-options"), Some("ice2"), "no trickle");
    // the tag is echoed by any answerer that reads RFC 5888, trickle or not (§9.1)
    assert_eq!(value(&answer, "mid"), Some("0"), "the offer's tag, echoed");
    assert_eq!(
        pair.caller.engine.trickle_public_address(
            &mut pair.caller.agent,
            call,
            caller_public(),
            pair.now
        ),
        Err(MediaError::NotTrickling),
        "the far end answered regular ICE (RFC 8838 §5)"
    );
    assert!(trickled_to(&pair.callee).is_empty());

    // and the call finds its path and carries the tone as any ICE call does
    let crossed = pair.check_paths(call, remote);
    assert!(crossed > 0);
    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut played = Vec::new();
    for _ in 0..8 {
        tone(&mut samples, 8_000, &mut phase);
        played = pair.exchange(call, remote, &samples);
        pair.advance();
    }
    assert!(loudness(&played) > 4_000, "{}", loudness(&played));
}

#[test]
fn two_trickling_stacks_find_a_path_and_the_tone_crosses_it() {
    let (mut pair, call, remote) = trickling(IceTrickle::Full, IceTrickle::Full);
    for (stack, handle) in [(&mut pair.caller, call), (&mut pair.callee, remote)] {
        stack
            .engine
            .end_of_candidates(&mut stack.agent, handle, pair.now)
            .expect("both ends finished");
    }
    pair.settle();
    let crossed = pair.check_paths(call, remote);
    assert!(crossed > 0);
    let chosen = pair
        .caller
        .engine
        .session(call)
        .and_then(|session| session.ice_path());
    assert_eq!(chosen, Some((caller_media(), callee_media())));
    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut played = Vec::new();
    for _ in 0..8 {
        tone(&mut samples, 8_000, &mut phase);
        played = pair.exchange(call, remote, &samples);
        pair.advance();
    }
    assert!(loudness(&played) > 4_000, "{}", loudness(&played));
}

/// A WebRTC line that also trickles tags its stream once: both write `a=mid` (RFC 8840 §4.1.1,
/// RFC 8843 §7.2), and the offer and the answer each carry the one tag.
#[cfg(feature = "dtls")]
#[test]
fn a_webrtc_line_that_trickles_tags_its_stream_once() {
    let line = |trickle| catalog(trickle).with_webrtc(true);
    let mut pair = Pair::asymmetric(line(IceTrickle::Full), line(IceTrickle::Full));
    pair.caller.agent.accept_trickle_ice(true);
    pair.callee.agent.accept_trickle_ice(true);
    pair.connect();
    let tags = |description: &SessionDescription| {
        description
            .media
            .iter()
            .find(|stream| !stream.is_rejected())
            .map_or(0, |stream| {
                stream
                    .attributes
                    .iter()
                    .filter(|attribute| attribute.name == "mid")
                    .count()
            })
    };
    let offer = pair.callee.offer_received().expect("the offer");
    let answer = pair.caller.answer_received().expect("the answer");
    assert_eq!(tags(&offer), 1, "{offer}");
    assert_eq!(tags(&answer), 1, "{answer}");
}
