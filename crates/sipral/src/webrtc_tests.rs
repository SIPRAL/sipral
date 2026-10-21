// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A WebRTC line between two stacks ([`CodecCatalog::with_webrtc`], `crate::webrtc`), and the
//! offer a PBX's WebRTC endpoint sends answered — by a stack set up as such a line and by one that
//! is not — with no network under either, as in `crate::tests`.

use sipral_core::sdp::{MID_EXTENSION, MediaDescription, SessionDescription, parse};

use crate::IcePolicy;
use crate::codec::CodecCatalog;
use crate::error::MediaError;
use crate::event::MediaEvent;
use crate::keying::{AccountSrtp, SrtpPolicy};
use crate::tests::{Pair, callee_media, caller_media, caller_sip, one_stream};

fn pcmu() -> CodecCatalog {
    CodecCatalog::with_order(&["PCMU"]).expect("an order")
}

fn webrtc() -> CodecCatalog {
    pcmu().with_webrtc(true)
}

/// An account's settings that make it a WebRTC line.
fn line() -> AccountSrtp {
    AccountSrtp {
        webrtc: Some(true),
        ..AccountSrtp::default()
    }
}

fn has(stream: &MediaDescription, name: &str) -> bool {
    stream.attribute(name).is_some()
}

/// The far end's `a=ssrc` value, `<ssrc> cname:<cname>`.
fn ssrc_line(stream: &MediaDescription) -> String {
    stream
        .attribute("ssrc")
        .and_then(|line| line.value.clone())
        .expect("an a=ssrc line")
}

/// What a PBX's WebRTC endpoint offers for one audio stream: BUNDLE with the
/// MID extension, `UDP/TLS/RTP/SAVPF` keyed by DTLS, ICE, mux, the feedback
/// lines and source lines a browser-shaped peer writes. `mux_only` adds RFC
/// 8858's exclusive mux, which a browser writes and Asterisk does not.
fn pbx_offer(mux_only: bool) -> String {
    let fingerprint = (0..32)
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let only = if mux_only { "a=rtcp-mux-only\r\n" } else { "" };
    format!(
        "v=0\r\no=- 7 2 IN IP4 192.0.2.7\r\ns=Asterisk\r\nc=IN IP4 192.0.2.7\r\nt=0 0\r\n\
         a=group:BUNDLE 0\r\na=msid-semantic: WMS *\r\n\
         m=audio 4000 UDP/TLS/RTP/SAVPF 0 101\r\na=mid:0\r\n\
         a=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\n\
         a=ice-ufrag:abcdABCD\r\na=ice-pwd:0123456789abcdefghijklmn\r\n\
         a=candidate:1 1 UDP 2130706431 192.0.2.7 4000 typ host\r\n\
         a=rtcp-mux\r\n{only}a=extmap:4 {MID_EXTENSION}\r\na=rtcp-fb:0 transport-cc\r\n\
         a=fingerprint:sha-256 {fingerprint}\r\na=setup:actpass\r\n\
         a=msid:pbx-stream pbx-track\r\na=ssrc:1111 cname:pbx@192.0.2.7\r\na=sendrecv\r\n"
    )
}

/// `offer` in an INVITE to `bob` at the callee, delivered.
fn invite_bob(pair: &mut Pair, offer: &str) {
    let invite = format!(
        "INVITE sip:bob@192.0.2.2 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.7:5060;branch=z9hG4bKwebrtcline\r\nMax-Forwards: 70\r\n\
From: <sip:pbx@example.com>;tag=pbx1\r\nTo: <sip:bob@example.com>\r\n\
Call-ID: webrtc-line@example.com\r\nCSeq: 1 INVITE\r\nContact: <sip:pbx@192.0.2.7>\r\n\
Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{offer}",
        offer.len()
    );
    pair.callee.deliver(
        invite.as_bytes(),
        "192.0.2.7:5060".parse().expect("an address"),
        pair.now,
    );
}

/// [`pbx_offer`] sent to `bob`, answered, and the description of the
/// response the callee sent.
fn answered_by_callee(pair: &mut Pair, mux_only: bool) -> Option<SessionDescription> {
    invite_bob(pair, &pbx_offer(mux_only));
    pair.callee.drain(pair.now, true);
    pair.callee.outbound().into_iter().find_map(|bytes| {
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if !text.starts_with("SIP/2.0 200") {
            return None;
        }
        let (_, body) = text.split_once("\r\n\r\n")?;
        parse(body.as_bytes()).ok()
    })
}

/// The status line of the final response the callee sent, if any.
fn final_status(pair: &mut Pair) -> Option<String> {
    pair.callee.outbound().into_iter().find_map(|bytes| {
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let line = text.lines().next()?.to_owned();
        (line.starts_with("SIP/2.0 ") && !line.starts_with("SIP/2.0 1")).then_some(line)
    })
}

#[test]
fn a_webrtc_line_offers_what_a_pbx_webrtc_endpoint_expects_and_is_answered_alike() {
    let mut pair = Pair::new(webrtc());
    let call = pair.connect();
    let offer = pair.callee.offer_received().expect("the offer");
    let stream = one_stream(&offer);
    assert_eq!(stream.proto, "UDP/TLS/RTP/SAVPF");
    for name in [
        "fingerprint",
        "setup",
        "ice-ufrag",
        "ice-pwd",
        "candidate",
        "rtcp-mux",
        "rtcp-mux-only",
        "rtcp-fb",
        "msid",
    ] {
        assert!(has(&stream, name), "{name} in the offer");
    }
    assert!(!has(&stream, "crypto"), "a WebRTC line keys by DTLS alone");
    assert_eq!(offer.bundle_group(), Some(vec!["0"]));
    assert_eq!(stream.mid(), Some("0"));
    assert_eq!(stream.extmap_id(MID_EXTENSION), Some(1));
    assert_eq!(
        ssrc_line(&stream).split_once(' ').map(|(_, cname)| cname),
        Some(format!("cname:sipral@{}", caller_media().ip()).as_str()),
        "the CNAME its RTCP will carry"
    );

    let answer = pair.caller.answer_received().expect("the answer");
    let answered = one_stream(&answer);
    assert_eq!(answered.proto, "UDP/TLS/RTP/SAVPF");
    assert_eq!(answer.bundle_group(), Some(vec!["0"]));
    assert_eq!(answered.mid(), Some("0"));
    assert_eq!(answered.extmap_id(MID_EXTENSION), Some(1));
    assert!(has(&answered, "rtcp-mux") && has(&answered, "rtcp-mux-only"));
    assert!(has(&answered, "ice-ufrag") && has(&answered, "fingerprint"));
    assert!(has(&answered, "ssrc") && has(&answered, "msid"));
    assert!(
        pair.caller
            .media_events()
            .iter()
            .any(|event| matches!(event, MediaEvent::Started { .. })),
        "the stream opened on what the two agreed"
    );

    // a hold offers the same line again, BUNDLE and all
    pair.caller.agent.hold(call, pair.now).expect("the hold");
    let held = pair
        .caller
        .outbound()
        .into_iter()
        .find_map(|bytes| {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            let (_, body) = text.split_once("\r\n\r\n")?;
            text.starts_with("INVITE ")
                .then(|| parse(body.as_bytes()).ok())
                .flatten()
        })
        .expect("the hold's re-offer");
    assert_eq!(held.bundle_group(), Some(vec!["0"]));
    assert_eq!(one_stream(&held).mid(), Some("0"));
}

#[test]
fn an_offer_that_bundles_is_answered_as_rfc_8843_asks_by_a_stack_that_is_no_webrtc_line() {
    // DTLS-SRTP on, as `labuser-dtls` has it in the lab, and nothing of WebRTC
    let mut pair = Pair::new(pcmu().with_srtp(SrtpPolicy::DtlsOffered));
    let _ = pair.callee.account("bob", caller_sip());
    let answer = answered_by_callee(&mut pair, true).expect("a 200 with an answer");
    let stream = one_stream(&answer);
    assert_eq!(
        stream.proto, "UDP/TLS/RTP/SAVPF",
        "the profile stays the offer's"
    );
    assert_eq!(answer.bundle_group(), Some(vec!["0"]));
    assert_eq!(stream.mid(), Some("0"));
    assert_eq!(
        stream.extmap_id(MID_EXTENSION),
        Some(4),
        "the offer's own number"
    );
    assert!(
        has(&stream, "rtcp-mux"),
        "mux is not this catalogue's choice, but a bundled stream has no other (RFC 8843 §9.3.1.2)"
    );
    assert!(has(&stream, "rtcp-mux-only"), "said back inside the group");
    assert!(has(&stream, "fingerprint") && !has(&stream, "crypto"));
    assert!(has(&stream, "ssrc"), "a bundled stream names its source");
    assert!(
        !has(&stream, "rtcp-fb"),
        "nothing of the offer's transport-cc: this stack does none of it"
    );
}

#[test]
fn an_account_that_is_a_webrtc_line_answers_with_ice_and_refuses_plain_audio() {
    let mut pair = Pair::new(pcmu());
    let bob = pair.callee.account("bob", caller_sip());
    pair.callee
        .engine
        .set_account_srtp(bob, line())
        .expect("a WebRTC line");
    let catalog = pair.callee.engine.account_catalog(bob);
    assert!(catalog.webrtc());
    assert_eq!(catalog.srtp(), SrtpPolicy::DtlsRequired);
    assert_eq!(catalog.ice(), IcePolicy::Offered);
    assert!(catalog.feedback());

    let answer = answered_by_callee(&mut pair, false).expect("a 200 with an answer");
    let stream = one_stream(&answer);
    assert_eq!(stream.proto, "UDP/TLS/RTP/SAVPF");
    assert!(has(&stream, "ice-ufrag") && has(&stream, "candidate"));
    assert!(
        !has(&stream, "rtcp-mux-only"),
        "the offer did not say it, and an answer never adds it on its own"
    );
    assert!(has(&stream, "rtcp-mux"));
    assert_eq!(answer.bundle_group(), Some(vec!["0"]));
}

#[test]
fn a_webrtc_line_refuses_an_offer_of_plain_audio_with_488() {
    let mut pair = Pair::new(pcmu());
    let bob = pair.callee.account("bob", caller_sip());
    pair.callee
        .engine
        .set_account_srtp(bob, line())
        .expect("a WebRTC line");
    invite_bob(
        &mut pair,
        "v=0\r\no=- 7 2 IN IP4 192.0.2.7\r\ns=-\r\nc=IN IP4 192.0.2.7\r\nt=0 0\r\n\
         m=audio 4000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n",
    );
    pair.callee.drain(pair.now, false);
    let call = pair.callee.call().expect("the INVITE arrived");
    let _ = pair.callee.outbound();
    assert_eq!(
        pair.callee
            .engine
            .answer(&mut pair.callee.agent, call, callee_media(), pair.now),
        Err(MediaError::SrtpRequired)
    );
    assert_eq!(
        final_status(&mut pair).as_deref(),
        Some("SIP/2.0 488 Not Acceptable Here")
    );
}
