// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The INVITE an account places, measured: every codec the default catalogue
//! offers, SDES offered on the plain profile (`SrtpPolicy::BestEffort`),
//! telephone-event on both clocks, and the `Authorization` an Asterisk
//! challenge asks for — in full, and as the endpoint writes it compact
//! before RFC 3261 §18.1.1 would move it off the datagram.

use std::time::Instant;

use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, parse};

use crate::codec::CodecCatalog;
use crate::keying::SrtpPolicy;
use crate::tests::{Pair, Stack, callee_sip, caller_media, caller_sip, one_stream, uri};
use crate::{Account, Compaction, EndpointConfig, Event, OutgoingCall, TransportId, UaEvent};

const UDP: TransportId = TransportId(1);

/// The value of one header field of a message on the wire.
fn field(message: &[u8], name: HeaderName<'_>) -> String {
    let mut scratch = ParseScratch::new();
    parse(message, &mut scratch, ParseMode::Lenient)
        .ok()
        .and_then(|parsed| parsed.header(name).map(<[u8]>::to_vec))
        .map(|value| String::from_utf8_lossy(&value).into_owned())
        .unwrap_or_default()
}

/// The 401 the lab's Asterisk answers an INVITE with: its nonce, its opaque.
fn challenge_to(invite: &[u8]) -> Vec<u8> {
    format!(
        "SIP/2.0 401 Unauthorized\r\nVia: {}\r\nFrom: {}\r\nTo: {};tag=pbx\r\nCall-ID: {}\r\n\
         CSeq: {}\r\nWWW-Authenticate: Digest realm=\"asterisk\", \
         nonce=\"1790633099/25f6972d5eee33b81b72468670c2b3e3\", opaque=\"7defcb0c4fbb9048\", \
         algorithm=MD5, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n",
        field(invite, HeaderName::Via),
        field(invite, HeaderName::From),
        field(invite, HeaderName::To),
        field(invite, HeaderName::CallId),
        field(invite, HeaderName::CSeq),
    )
    .into_bytes()
}

/// What a call placed under `catalog` and `compaction` put on the wire: the
/// first INVITE, and the one answering the challenge — its bytes when it
/// went over the datagram, and the size a stream was asked for at when it
/// did not.
fn placed(catalog: CodecCatalog, compaction: Compaction) -> (Vec<u8>, Result<Vec<u8>, usize>) {
    let now = Instant::now();
    let mut config = EndpointConfig::default();
    config.datagram_limit.compaction = compaction;
    let mut caller = Stack::configured(1, caller_sip(), caller_media(), catalog, config, now);
    let account = caller.agent.add_account(
        Account::new(
            uri("sip:alice@example.com"),
            uri("sip:example.com"),
            uri("sip:alice@192.0.2.1"),
            UDP,
            callee_sip(),
        )
        .credentials(crate::Credentials::new("alice", "open sesame")),
    );
    caller
        .engine
        .place(
            &mut caller.agent,
            account,
            OutgoingCall::new(uri("sip:bob@example.com")),
            caller_media(),
            now,
        )
        .expect("the INVITE goes");
    caller.drain(now, false);
    let invite = caller
        .outbound()
        .into_iter()
        .find(|datagram| datagram.starts_with(b"INVITE "))
        .expect("the INVITE");
    caller.heard.clear();
    caller.deliver(&challenge_to(&invite), callee_sip(), now);
    caller.drain(now, false);
    let answered = caller
        .outbound()
        .into_iter()
        .find(|datagram| datagram.starts_with(b"INVITE "));
    let wanted = caller.heard.iter().find_map(|event| match *event {
        Event::Signalling(UaEvent::Unclaimed(sipral_core::endpoint::Event::TransportWanted {
            request_bytes,
            ..
        })) => Some(request_bytes),
        _ => None,
    });
    match (answered, wanted) {
        (Some(answered), None) => (invite, Ok(answered)),
        (None, Some(request_bytes)) => (invite, Err(request_bytes)),
        (answered, wanted) => panic!(
            "either it went or a stream was asked for: {:?} {wanted:?}",
            answered.map(|bytes| bytes.len())
        ),
    }
}

fn best_effort() -> CodecCatalog {
    CodecCatalog::new().with_srtp(SrtpPolicy::BestEffort)
}

/// The named events go on the clock of each codec offered and no other
/// (RFC 4733 §2.5.1.2): two lines for Opus at 48 kHz beside the 8 kHz
/// codecs, one where only one clock is offered.
#[test]
fn telephone_event_is_offered_only_on_the_clocks_of_the_codecs_offered() {
    let clocks = |catalog: CodecCatalog| {
        let (invite, _) = placed(catalog, Compaction::Never);
        String::from_utf8_lossy(&invite)
            .lines()
            .filter_map(|line| line.split_once(" telephone-event/").map(|(_, clock)| clock))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_eq!(clocks(best_effort()), ["48000", "8000"]);
    let narrow = CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("an order");
    assert_eq!(clocks(narrow), ["8000"]);
    let wide = CodecCatalog::with_order(&["G722"]).expect("an order");
    // G.722's RTP clock is 8000 (RFC 3551 §4.5.2), whatever it samples at
    assert_eq!(clocks(wide), ["8000"]);
}

/// An INVITE of the shape an application reported, measured: in full it is
/// 1082 bytes, and the one answering the lab's Asterisk challenge 1373 — past
/// the 1300 of RFC 3261 §18.1.1, so the endpoint asked for a stream, and a
/// server on UDP alone never got the call. Compact, the first is 1008 and the answer
/// 1298, over the datagram with its `Allow` kept; without `a=rtcp-xr`,
/// 1274. A real INVITE is longer than this one — longer addresses than the
/// documentation ranges', a display name, a `User-Agent` — and the endpoint
/// then takes `Allow` out too, about eighty bytes more, before it gives up
/// on the datagram.
#[test]
fn the_answered_invite_of_a_best_effort_call_fits_a_datagram_once_compact() {
    let (first_full, answered_full) = placed(best_effort(), Compaction::Never);
    let (first_compact, _) = placed(best_effort(), Compaction::Always);
    let (_, answered) = placed(best_effort(), Compaction::WhenOversize);
    let (_, lean) = placed(
        best_effort().with_voip_metrics(false),
        Compaction::WhenOversize,
    );

    assert_eq!(first_full.len(), 1_082);
    assert_eq!(first_compact.len(), 1_008);
    assert_eq!(answered_full, Err(1_373), "in full, a stream is asked for");

    let answered = answered.expect("compact, the answer goes over the datagram");
    assert_eq!(answered.len(), 1_298);
    let text = String::from_utf8_lossy(&answered).into_owned();
    for line in [
        "\r\nv:SIP/2.0/UDP ",
        "\r\nk:timer,replaces,100rel\r\n",
        "\r\nl:556\r\n",
    ] {
        assert!(text.contains(line), "no {line:?} in {text}");
    }
    assert!(text.contains("\r\nAllow:INVITE,ACK,"), "{text}");
    assert!(text.contains("\r\nAuthorization:Digest "), "{text}");
    assert!(text.contains("a=rtcp-xr:voip-metrics\r\n"), "{text}");

    let lean = lean.expect("the answer goes over the datagram");
    assert_eq!(lean.len(), 1_274);
    assert!(!String::from_utf8_lossy(&lean).contains("a=rtcp-xr"));
}

/// A catalogue without the VoIP metrics report leaves the line out of an
/// answer too, and the call still runs; one with it answers an offer that
/// asked with the line, as before.
#[test]
fn a_catalogue_without_voip_metrics_leaves_rtcp_xr_out_of_its_answer() {
    let mut pair = Pair::asymmetric(
        CodecCatalog::new(),
        CodecCatalog::new().with_voip_metrics(false),
    );
    pair.connect();
    let offer = one_stream(&pair.callee.offer_received().expect("the offer"));
    assert!(offer.attribute("rtcp-xr").is_some(), "the caller asked");
    let answer = one_stream(&pair.caller.answer_received().expect("the answer"));
    assert!(answer.attribute("rtcp-xr").is_none());

    let mut both = Pair::new(CodecCatalog::new());
    both.connect();
    let answer = one_stream(&both.caller.answer_received().expect("the answer"));
    assert!(answer.attribute("rtcp-xr").is_some());
}

/// The same call from and to users five characters longer, which are thirty
/// bytes more over the six places an answered INVITE names them: compact
/// with its `Allow` it is over the line, so the endpoint leaves `Allow` out,
/// and the call goes over the datagram rather than waiting for a stream.
#[test]
fn an_answered_invite_compact_alone_does_not_fit_goes_without_its_allow() {
    let now = Instant::now();
    let mut caller = Stack::configured(
        1,
        caller_sip(),
        caller_media(),
        best_effort(),
        EndpointConfig::default(),
        now,
    );
    let account = caller.agent.add_account(
        Account::new(
            uri("sip:alice12345@example.com"),
            uri("sip:example.com"),
            uri("sip:alice12345@192.0.2.1"),
            UDP,
            callee_sip(),
        )
        .credentials(crate::Credentials::new("alice12345", "open sesame")),
    );
    caller
        .engine
        .place(
            &mut caller.agent,
            account,
            OutgoingCall::new(uri("sip:bob12345@example.com")),
            caller_media(),
            now,
        )
        .expect("the INVITE goes");
    caller.drain(now, false);
    let invite = caller
        .outbound()
        .into_iter()
        .find(|datagram| datagram.starts_with(b"INVITE "))
        .expect("the INVITE");
    caller.deliver(&challenge_to(&invite), callee_sip(), now);
    caller.drain(now, false);
    let answered = caller
        .outbound()
        .into_iter()
        .find(|datagram| datagram.starts_with(b"INVITE "))
        .expect("the answer goes over the datagram");
    assert!(answered.len() <= 1_300, "{}", answered.len());
    let text = String::from_utf8_lossy(&answered).into_owned();
    assert!(
        answered.len()
            + "Allow:INVITE,ACK,CANCEL,BYE,OPTIONS,UPDATE,PRACK,REFER,NOTIFY,MESSAGE,INFO\r\n"
                .len()
            > 1_300,
        "with its Allow it would have fitted: {} bytes",
        answered.len()
    );
    assert!(!text.contains("Allow"), "{text}");
    assert!(text.contains("\r\nv:SIP/2.0/UDP "), "{text}");
    assert!(text.contains("\r\nAuthorization:Digest "), "{text}");
}
