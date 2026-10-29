// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The `trickle-ice` Info Package (RFC 8840 §10, RFC 6086), scripted on a
//! fake clock against a far end written here: what an INVITE and its
//! answers say, when an INFO may go, one at a time and newest last, and what
//! an INFO that arrives is answered.
//!
//! The far end is 192.0.2.9 and this end 192.0.2.1, as in `crate::tests`,
//! whose helpers these share.

use std::sync::Arc;
use std::time::Instant;

use sipral_core::msg::HeaderName;

use crate::agent::UserAgent;
use crate::call::{CallHandle, OutgoingCall};
use crate::event::UaEvent;
use crate::signalling_tests::with_field;
use crate::tests::{
    OFFER, account, agent, answered, call_arriving, call_up, deliver, events, in_dialog,
    incoming_invite, reply, reversed, sent, text, transmits, uri, with,
};
use crate::trickle::{INFO_PACKAGE, MEDIA_TYPE, RECV_INFO};

/// An offer that trickles: its candidates may come later (RFC 8838 §3).
const TRICKLING: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 8000 RTP/AVP 0\r\na=mid:0\r\na=ice-ufrag:8hhY\r\n\
a=ice-pwd:asd88fgpdd777uzjYhagZg\r\na=ice-options:trickle ice2\r\n\
a=candidate:1 1 UDP 2130706431 192.0.2.1 8000 typ host\r\n";

/// The far end's answer, trickling too.
const TRICKLING_ANSWER: &[u8] = b"v=0\r\no=- 2 2 IN IP4 192.0.2.9\r\ns=-\r\n\
c=IN IP4 192.0.2.9\r\nt=0 0\r\nm=audio 9000 RTP/AVP 0\r\na=mid:0\r\na=ice-ufrag:9uB6\r\n\
a=ice-pwd:YH75Fviy6338Vbrhrlp8Yh\r\na=ice-options:trickle ice2\r\n\
a=candidate:1 1 UDP 2130706431 192.0.2.9 9000 typ host\r\n";

/// A body with `n` in it, so that which one went can be told.
fn frag(n: u16) -> Arc<[u8]> {
    Arc::from(
        format!(
            "m=audio 9 RTP/AVP 0\r\na=ice-ufrag:8hhY\r\na=ice-pwd:asd88fgpdd777uzjYhagZg\r\n\
a=mid:0\r\na=candidate:1 1 UDP 2130706431 192.0.2.1 {} typ host\r\n",
            8000 + n
        )
        .into_bytes(),
    )
}

fn has(bytes: &[u8], name: HeaderName<'_>) -> bool {
    with(bytes, |message| message.header(name).is_some())
}

fn body_of(bytes: &[u8]) -> Vec<u8> {
    with(bytes, |message| message.body().to_vec())
}

fn infos(written: &[Vec<u8>]) -> Vec<Vec<u8>> {
    written
        .iter()
        .filter(|message| message.starts_with(b"INFO "))
        .cloned()
        .collect()
}

/// A call placed with the trickling offer, its INVITE, and the agent.
fn placed(outgoing: &OutgoingCall, now: Instant) -> (UserAgent, CallHandle, Vec<u8>) {
    let mut agent = agent(now);
    let line = agent.add_account(account());
    let call = agent.call(line, outgoing, now).expect("the INVITE goes");
    let invite = sent(&mut agent);
    (agent, call, invite)
}

fn trickling_call() -> OutgoingCall {
    OutgoingCall::new(uri("sip:bob@example.com")).offer(Arc::from(TRICKLING))
}

/// The far end's response to the INVITE, listing the package it takes.
fn heard(invite: &[u8], status: u16, reason: &str, body: Option<&[u8]>, recv: &str) -> Vec<u8> {
    let response = answered(invite, status, reason, "desk", body);
    if recv.is_empty() {
        response
    } else {
        with_field(&response, &format!("Recv-Info: {recv}"))
    }
}

#[test]
fn an_offer_that_trickles_says_so_and_requires_it_only_when_asked() {
    let t0 = Instant::now();
    let (_, _, invite) = placed(&trickling_call(), t0);
    assert!(
        text(&invite, HeaderName::Supported).contains("trickle-ice"),
        "{}",
        text(&invite, HeaderName::Supported)
    );
    assert_eq!(text(&invite, RECV_INFO), "trickle-ice");
    assert!(!text(&invite, HeaderName::Require).contains("trickle-ice"));

    let (_, _, invite) = placed(&trickling_call().require_trickle_ice(), t0);
    assert!(text(&invite, HeaderName::Require).contains("trickle-ice"));

    // an offer that does not trickle says nothing of the package
    let (_, _, invite) = placed(
        &OutgoingCall::new(uri("sip:bob@example.com")).offer(Arc::from(crate::tests::OFFER)),
        t0,
    );
    assert!(!text(&invite, HeaderName::Supported).contains("trickle-ice"));
    assert!(!has(&invite, RECV_INFO));
}

#[test]
fn candidates_wait_for_the_dialog_and_the_far_ends_recv_info_then_go_one_at_a_time() {
    let t0 = Instant::now();
    let (mut agent, call, invite) = placed(&trickling_call(), t0);
    agent.trickle_ice(call, frag(1), t0).expect("held");
    assert!(transmits(&mut agent).is_empty(), "no dialog yet");

    // a 180 that creates the early dialog and lists the package (RFC 8840
    // §4.3.3): the waiting body goes at once
    deliver(
        &mut agent,
        &heard(&invite, 180, "Ringing", None, "trickle-ice"),
        t0,
    );
    let first = infos(&transmits(&mut agent));
    assert_eq!(first.len(), 1, "one INFO");
    let info = &first[0];
    assert_eq!(text(info, INFO_PACKAGE), "trickle-ice");
    assert_eq!(text(info, HeaderName::ContentType), MEDIA_TYPE);
    assert_eq!(
        text(info, HeaderName::Extension("Content-Disposition")),
        "Info-Package"
    );
    assert_eq!(body_of(info), frag(1).to_vec());
    assert!(!has(info, RECV_INFO), "an INFO never carries Recv-Info");

    // two more while it is in flight: only the newest follows (§10.9)
    agent.trickle_ice(call, frag(2), t0).expect("held");
    agent.trickle_ice(call, frag(3), t0).expect("held");
    assert!(infos(&transmits(&mut agent)).is_empty(), "one at a time");
    deliver(&mut agent, &reply(info, 200, "OK", ""), t0);
    let next = infos(&transmits(&mut agent));
    assert_eq!(next.len(), 1);
    assert_eq!(body_of(&next[0]), frag(3).to_vec());
    assert!(agent.takes_trickle_ice(call));

    // a 469: the far end takes no more of them (RFC 6086 §4.2.1), and the
    // call goes on
    deliver(
        &mut agent,
        &reply(&next[0], 469, "Bad Info Package", ""),
        t0,
    );
    agent.trickle_ice(call, frag(4), t0).expect("held");
    assert!(infos(&transmits(&mut agent)).is_empty());
    assert!(!agent.takes_trickle_ice(call));
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(event, UaEvent::CallEnded { .. }))
    );
}

#[test]
fn a_far_end_that_does_not_list_the_package_is_never_sent_one() {
    let t0 = Instant::now();
    let (mut agent, call, invite) = placed(&trickling_call(), t0);
    deliver(
        &mut agent,
        &heard(&invite, 200, "OK", Some(TRICKLING_ANSWER), ""),
        t0,
    );
    transmits(&mut agent);
    agent.trickle_ice(call, frag(1), t0).expect("held");
    assert!(infos(&transmits(&mut agent)).is_empty());
    assert!(!agent.takes_trickle_ice(call));
}

#[test]
fn an_answer_in_a_2xx_lets_the_offerer_trickle_at_once() {
    let t0 = Instant::now();
    let (mut agent, call, invite) = placed(&trickling_call(), t0);
    agent.trickle_ice(call, frag(1), t0).expect("held");
    deliver(
        &mut agent,
        &heard(&invite, 200, "OK", Some(TRICKLING_ANSWER), "trickle-ice"),
        t0,
    );
    let written = transmits(&mut agent);
    assert!(written.iter().any(|message| message.starts_with(b"ACK ")));
    assert_eq!(infos(&written).len(), 1);
}

/// An INVITE from the far end whose offer trickles and which takes the
/// package.
fn trickling_invite(branch: &str, extra: &str) -> Vec<u8> {
    with_field(
        &with_field(
            &incoming_invite(branch, Some(TRICKLING_ANSWER)),
            "Supported: trickle-ice",
        ),
        &format!("Recv-Info: trickle-ice{extra}"),
    )
}

#[test]
fn an_answerer_announces_the_package_and_trickles_once_the_far_end_holds_the_dialog() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    agent.accept_trickle_ice(true);
    let call = call_arriving(&mut agent, &trickling_invite("tr1", ""), t0);

    agent.ring(call, None, t0).expect("180 goes");
    let ringing = sent(&mut agent);
    assert!(text(&ringing, HeaderName::Supported).contains("trickle-ice"));
    assert_eq!(text(&ringing, RECV_INFO), "trickle-ice");

    agent
        .answer(call, Some(Arc::from(TRICKLING)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    assert!(text(&ok, HeaderName::Supported).contains("trickle-ice"));
    assert_eq!(
        text(&ok, RECV_INFO),
        "trickle-ice",
        "the same in every response"
    );

    // the far end may not hold the dialog yet: nothing goes before its ACK
    agent.trickle_ice(call, frag(1), t0).expect("held");
    assert!(infos(&transmits(&mut agent)).is_empty());
    deliver(&mut agent, &in_dialog(&ok, "ACK", "tr1ack", 1), t0);
    let written = infos(&transmits(&mut agent));
    assert_eq!(written.len(), 1, "the ACK proves the dialog");
    assert_eq!(body_of(&written[0]), frag(1).to_vec());
}

#[test]
fn the_far_ends_own_info_is_taken_and_proves_the_early_dialog() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    agent.accept_trickle_ice(true);
    let call = call_arriving(&mut agent, &trickling_invite("tr2", ""), t0);
    agent.ring(call, None, t0).expect("180 goes");
    let ringing = sent(&mut agent);
    agent.trickle_ice(call, frag(1), t0).expect("held");
    assert!(infos(&transmits(&mut agent)).is_empty());

    let mut info = in_dialog(&ringing, "INFO", "tr2info", 2);
    let theirs = frag(7);
    info = with_field(&info, "Info-Package: trickle-ice");
    let info = String::from_utf8_lossy(&info)
        .replace(
            "Content-Length: 0\r\n\r\n",
            &format!(
                "Content-Type: {MEDIA_TYPE}\r\nContent-Disposition: Info-Package\r\n\
Content-Length: {}\r\n\r\n{}",
                theirs.len(),
                String::from_utf8_lossy(&theirs)
            ),
        )
        .into_bytes();
    deliver(&mut agent, &info, t0);
    let written = transmits(&mut agent);
    assert!(
        written
            .iter()
            .any(|message| message.starts_with(b"SIP/2.0 200 ")
                && text(message, HeaderName::CSeq).ends_with("INFO")),
        "the INFO is answered 200"
    );
    assert_eq!(
        infos(&written).len(),
        1,
        "an in-dialog request proves the far end holds the dialog (RFC 8840 §4.3.2)"
    );
    let taken = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::TrickleIce { call: on, body } => Some((on, body)),
            _ => None,
        });
    assert_eq!(taken, Some((call, theirs)));
}

/// An INFO of the package from the far end, inside the dialog `ours` (a
/// response this end sent) opened, of `content_type`.
fn package_info(ours: &[u8], branch: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let info = with_field(
        &in_dialog(ours, "INFO", branch, 3),
        "Info-Package: trickle-ice",
    );
    String::from_utf8_lossy(&info)
        .replace(
            "Content-Length: 0\r\n\r\n",
            &format!(
                "Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                String::from_utf8_lossy(body)
            ),
        )
        .into_bytes()
}

fn status_of(written: &[Vec<u8>]) -> Option<String> {
    written
        .iter()
        .find(|message| message.starts_with(b"SIP/2.0 "))
        .map(|message| String::from_utf8_lossy(&message[8..11]).into_owned())
}

#[test]
fn an_info_of_the_package_on_a_call_that_did_not_take_it_is_469() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    // the far end trickles; this agent was never told to
    let call = call_arriving(&mut agent, &trickling_invite("tr3", ""), t0);
    agent
        .answer(call, Some(Arc::from(crate::tests::OFFER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    assert!(!text(&ok, HeaderName::Supported).contains("trickle-ice"));
    assert!(
        has(&ok, RECV_INFO) && text(&ok, RECV_INFO).is_empty(),
        "an empty Recv-Info in the 2xx to an INVITE that listed one (RFC 6086 §5.2.3)"
    );
    deliver(&mut agent, &in_dialog(&ok, "ACK", "tr3ack", 1), t0);
    transmits(&mut agent);
    deliver(
        &mut agent,
        &package_info(&ok, "tr3info", MEDIA_TYPE, &frag(1)),
        t0,
    );
    let written = transmits(&mut agent);
    assert_eq!(status_of(&written).as_deref(), Some("469"));
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(event, UaEvent::TrickleIce { .. }))
    );
}

#[test]
fn an_info_of_the_package_with_another_body_is_415_and_a_huge_one_413() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    agent.accept_trickle_ice(true);
    let call = call_arriving(&mut agent, &trickling_invite("tr4", ""), t0);
    agent
        .answer(call, Some(Arc::from(TRICKLING)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "tr4ack", 1), t0);
    transmits(&mut agent);

    deliver(
        &mut agent,
        &package_info(&ok, "tr4a", "application/sdp", b"v=0\r\n"),
        t0,
    );
    let written = transmits(&mut agent);
    assert_eq!(status_of(&written).as_deref(), Some("415"));
    let refusal = written
        .iter()
        .find(|message| message.starts_with(b"SIP/2.0 415"))
        .expect("the 415");
    assert_eq!(text(refusal, HeaderName::Accept), MEDIA_TYPE);

    let huge = vec![b'a'; crate::trickle::MAX_BODY + 1];
    deliver(
        &mut agent,
        &package_info(&ok, "tr4b", MEDIA_TYPE, &huge),
        t0,
    );
    assert_eq!(status_of(&transmits(&mut agent)).as_deref(), Some("413"));
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(event, UaEvent::TrickleIce { .. }))
    );
}

#[test]
fn an_invite_that_requires_trickle_is_refused_unless_the_agent_takes_it() {
    let t0 = Instant::now();
    let requiring = with_field(&trickling_invite("tr5", ""), "Require: trickle-ice");

    let mut refusing = agent(t0);
    refusing.add_account(account());
    deliver(&mut refusing, &requiring, t0);
    let refusal = transmits(&mut refusing)
        .into_iter()
        .find(|message| message.starts_with(b"SIP/2.0 420"))
        .expect("a 420");
    assert_eq!(text(&refusal, HeaderName::Unsupported), "trickle-ice");

    let mut taking = agent(t0);
    taking.add_account(account());
    taking.accept_trickle_ice(true);
    assert!(taking.accepts_trickle_ice());
    call_arriving(&mut taking, &requiring, t0);
}

#[test]
fn options_lists_the_option_tag_once_the_agent_takes_the_package() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let options = |branch: &str| {
        String::from_utf8_lossy(&incoming_invite(branch, None))
            .replace("INVITE sip:", "OPTIONS sip:")
            .replace("1 INVITE", "1 OPTIONS")
            .into_bytes()
    };
    deliver(&mut agent, &options("tr6"), t0);
    assert!(!text(&sent(&mut agent), HeaderName::Supported).contains("trickle-ice"));
    agent.accept_trickle_ice(true);
    deliver(&mut agent, &options("tr7"), t0);
    assert!(text(&sent(&mut agent), HeaderName::Supported).contains("trickle-ice"));
}

/// A far end's trickling description that holds no candidate yet: RFC 8840
/// §4.1.1's `0.0.0.0` and port 9, as a browser writes every one.
fn placeholder(version: u8) -> Vec<u8> {
    format!(
        "v=0\r\no=- 2 {version} IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n\
m=audio 9 RTP/AVP 0\r\na=mid:0\r\na=ice-ufrag:9uB6\r\na=ice-pwd:YH75Fviy6338Vbrhrlp8Yh\r\n\
a=ice-options:trickle ice2\r\n"
    )
    .into_bytes()
}

fn placeholder_invite(branch: &str) -> Vec<u8> {
    with_field(
        &incoming_invite(branch, Some(&placeholder(2))),
        "Supported: trickle-ice",
    )
}

fn held_there(agent: &UserAgent, call: CallHandle) -> Option<bool> {
    agent.hold_state(call).map(|hold| hold.remote)
}

#[test]
fn the_placeholder_holds_nobody_on_a_call_answered_with_ice() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    agent.accept_trickle_ice(true);
    let call = call_arriving(&mut agent, &placeholder_invite("ph1"), t0);
    assert_eq!(held_there(&agent, call), Some(false), "before the answer");

    agent
        .answer(call, Some(Arc::from(TRICKLING)), t0)
        .expect("200 goes");
    assert_eq!(held_there(&agent, call), Some(false), "ICE finds the path");
}

#[test]
fn the_placeholder_holds_a_call_answered_without_ice() {
    // no check runs at this end, so 0.0.0.0 is where the media would go
    // (RFC 3264 §8.4), as the media plan reads it
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    agent.accept_trickle_ice(true);
    let call = call_arriving(&mut agent, &placeholder_invite("ph2"), t0);

    agent
        .answer(call, Some(Arc::from(OFFER)), t0)
        .expect("200 goes");
    assert_eq!(held_there(&agent, call), Some(true));
}

#[test]
fn before_any_answer_the_placeholder_holds_an_agent_that_takes_no_trickled_candidates() {
    // the far end's candidates would be refused 469, so none comes to check
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &placeholder_invite("ph3"), t0);
    assert_eq!(held_there(&agent, call), Some(true));
}

#[test]
fn a_re_offer_of_the_placeholder_holds_a_call_that_answers_it_without_ice() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let line = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, line, t0);

    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "phreoffer", 1, Some(&placeholder(3))),
        t0,
    );
    transmits(&mut agent);
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::Reoffer { .. })),
        "ICE credentials that appear are the application's"
    );
    agent.accept_reoffer(call, OFFER, t0).expect("the 200 goes");
    assert_eq!(held_there(&agent, call), Some(true));
}

#[test]
fn a_refused_info_lets_the_next_body_go() {
    let t0 = Instant::now();
    let (mut agent, call, invite) = placed(&trickling_call(), t0);
    deliver(
        &mut agent,
        &heard(&invite, 200, "OK", Some(TRICKLING_ANSWER), "trickle-ice"),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    agent.trickle_ice(call, frag(1), t0).expect("sent");
    let info = infos(&transmits(&mut agent)).pop().expect("an INFO");
    // the answer to a request inside the dialog this end opened
    let refused = reply(&info, 500, "Server Internal Error", "");
    deliver(&mut agent, &refused, t0);
    agent.trickle_ice(call, frag(2), t0).expect("sent");
    let next = infos(&transmits(&mut agent));
    assert_eq!(next.len(), 1, "a refusal is the transaction's only");
    assert_eq!(body_of(&next[0]), frag(2).to_vec());
}
