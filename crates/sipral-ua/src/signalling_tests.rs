// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a call says about itself beyond its session: why it ended
//! (RFC 3326), who is on it (RFC 3323, RFC 3325), how it asked to be
//! answered (RFC 5373) and where it was sent instead (RFC 3261 §21.3, RFC
//! 5806), scripted on a fake clock against a far end written here.
//!
//! The far end is 192.0.2.9 and this end 192.0.2.1, as in `crate::tests`,
//! whose helpers these share.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::msg::{HeaderName, StatusCode};

use crate::agent::UserAgent;
use crate::answering::{AnswerMode, RingSource};
use crate::call::{CallEndReason, CallIdentity};
use crate::error::UaError;
use crate::event::UaEvent;
use crate::identity::{Privacy, Verstat};
use crate::reason::{Reason, ReasonProtocol};
use crate::redirect::Redirect;
use crate::tests::{
    ANSWER, OFFER, account, agent, answered, call_arriving, call_up, deliver, events,
    incoming_invite, outgoing, registrar, reversed, sent, text, transmits, uri,
};

/// `message` with `line` added among its header fields, before the
/// `Content-Length` every message here ends its header with.
pub(crate) fn with_field(message: &[u8], line: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(message);
    let at = text
        .find("Content-Length:")
        .expect("a message that says how long its body is");
    let mut out = text[..at].to_owned();
    out.push_str(line);
    out.push_str("\r\n");
    out.push_str(&text[at..]);
    out.into_bytes()
}

/// A CANCEL from the far end for the INVITE `incoming_invite(branch, ..)`
/// wrote.
fn cancel_of(branch: &str, reason: &str) -> Vec<u8> {
    format!(
        "CANCEL sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK{branch};rport\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: Alice <sip:alice@example.com>\r\n\
Call-ID: incoming-{branch}\r\n\
CSeq: 1 CANCEL\r\n\
{reason}\
Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

/// The reason and the causes of the one call end among `said`.
fn end_of(said: Vec<UaEvent>) -> (CallEndReason, Box<[Reason]>) {
    said.into_iter()
        .find_map(|event| match event {
            UaEvent::CallEnded { reason, causes, .. } => Some((reason, causes)),
            _ => None,
        })
        .expect("the call ended")
}

#[test]
fn a_cancel_saying_another_phone_answered_ends_the_call_with_that_said() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let _ = call_arriving(&mut agent, &incoming_invite("elsewhere", Some(OFFER)), t0);
    deliver(
        &mut agent,
        &cancel_of(
            "elsewhere",
            "Reason: SIP ;cause=200 ;text=\"Call completed elsewhere\"\r\n",
        ),
        t0,
    );
    let (reason, causes) = end_of(events(&mut agent));
    assert_eq!(reason, CallEndReason::Cancelled);
    assert_eq!(causes.len(), 1);
    assert!(causes[0].is_completed_elsewhere(), "{causes:?}");
    assert_eq!(causes[0].text.as_deref(), Some("Call completed elsewhere"));
}

#[test]
fn a_cancel_that_says_nothing_ends_the_call_with_nothing_said() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let _ = call_arriving(&mut agent, &incoming_invite("silent", Some(OFFER)), t0);
    deliver(&mut agent, &cancel_of("silent", ""), t0);
    let (reason, causes) = end_of(events(&mut agent));
    assert_eq!(reason, CallEndReason::Cancelled);
    assert!(causes.is_empty(), "{causes:?}");
}

#[test]
fn a_bye_from_a_gateway_ends_the_call_with_its_q850_cause() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_, ack) = call_up(&mut agent, id, t0);
    let bye = with_field(
        &reversed(&ack, "BYE", "gwbye", 1, None),
        "Reason: Q.850;cause=16;text=\"Normal call clearing\", SIP;cause=200",
    );
    deliver(&mut agent, &bye, t0);
    let (reason, causes) = end_of(events(&mut agent));
    assert_eq!(reason, CallEndReason::RemoteHangup);
    assert_eq!(causes.len(), 2);
    assert_eq!(causes[0].protocol, ReasonProtocol::Q850);
    assert_eq!(causes[0].cause, Some(16));
    assert_eq!(causes[1].protocol, ReasonProtocol::Sip);
}

#[test]
fn a_refusal_carrying_a_q850_cause_ends_the_call_with_it() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let _ = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &with_field(
            &answered(&invite, 486, "Busy Here", "gw", None),
            "Reason: Q.850;cause=17",
        ),
        t0,
    );
    transmits(&mut agent);
    let (reason, causes) = end_of(events(&mut agent));
    assert_eq!(reason, CallEndReason::Refused);
    assert_eq!(causes.len(), 1);
    assert_eq!(
        (causes[0].protocol.clone(), causes[0].cause),
        (ReasonProtocol::Q850, Some(17))
    );
}

#[test]
fn hanging_up_for_a_reason_writes_it_on_the_cancel_and_on_the_bye() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());

    // before any provisional response the CANCEL is held (RFC 3261 §9.1),
    // and the reason with it
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    agent
        .hangup_for(call, &[Reason::sip(603, "Declined by the user")], t0)
        .expect("the hangup is taken");
    assert!(transmits(&mut agent).is_empty());
    deliver(
        &mut agent,
        &answered(&invite, 180, "Ringing", "desk", None),
        t0,
    );
    let cancel = sent(&mut agent);
    assert!(cancel.starts_with(b"CANCEL "));
    assert_eq!(
        text(&cancel, HeaderName::Extension("Reason")),
        "SIP;cause=603;text=\"Declined by the user\""
    );
    deliver(
        &mut agent,
        &answered(&invite, 487, "Request Terminated", "desk", None),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    let (call, _) = call_up(&mut agent, id, t0);
    agent
        .hangup_for(
            call,
            &[
                Reason::q850(16, ""),
                Reason::sip(200, ""),
                Reason::q850(31, "a second Q.850 value is not written"),
            ],
            t0,
        )
        .expect("the BYE goes");
    let bye = sent(&mut agent);
    assert!(bye.starts_with(b"BYE "));
    assert_eq!(
        text(&bye, HeaderName::Extension("Reason")),
        "Q.850;cause=16, SIP;cause=200"
    );
}

#[test]
fn refusing_a_call_that_came_in_carries_only_the_q850_reason() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_invite("refused", Some(OFFER)), t0);
    agent
        .hangup_for(call, &[Reason::sip(486, ""), Reason::q850(17, "")], t0)
        .expect("the refusal goes");
    let refusal = sent(&mut agent);
    assert!(refusal.starts_with(b"SIP/2.0 486 "), "{refusal:?}");
    assert_eq!(
        text(&refusal, HeaderName::Extension("Reason")),
        "Q.850;cause=17"
    );
}

#[test]
fn a_hangup_with_no_reason_writes_no_reason_field() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _) = call_up(&mut agent, id, t0);
    agent.hangup_for(call, &[], t0).expect("the BYE goes");
    let bye = sent(&mut agent);
    assert_eq!(text(&bye, HeaderName::Extension("Reason")), "");
}

/// RFC 3326 §3.1 has the forking proxy tell the branches that lost; the one
/// branch this end itself ends — a phone that answered after another was
/// kept — is told the same, on the BYE that hangs it up.
#[test]
fn a_branch_that_answers_after_another_was_kept_is_told_the_call_was_completed_elsewhere() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let _ = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    for tag in ["desk", "mobile"] {
        deliver(
            &mut agent,
            &answered(&invite, 180, "Ringing", tag, None),
            t0,
        );
    }
    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "mobile", Some(ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    let bye = out
        .iter()
        .find(|bytes| bytes.starts_with(b"BYE "))
        .expect("the late branch is hung up");
    assert_eq!(
        text(bye, HeaderName::Extension("Reason")),
        "SIP;cause=200;text=\"Call completed elsewhere\""
    );
}

// -- who is calling, and who this end says it is ------------------------------

/// The fields a carrier's INVITE carries about the caller.
const ASSERTING: &str = "P-Asserted-Identity: \"Bob Jones\" <sip:+15551234567;verstat=TN-Validation-Passed@carrier.example;user=phone>\r\n\
Diversion: <sip:desk@example.com>;reason=no-answer\r\n\
Privacy: id\r\n";

/// The identity the `IncomingCall` for `bytes` carried.
fn identity_of(agent: &mut UserAgent, bytes: &[u8], now: Instant) -> Arc<CallIdentity> {
    deliver(agent, bytes, now);
    transmits(agent);
    events(agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall { identity, .. } => identity,
            _ => None,
        })
        .expect("somebody is calling, and who could be read")
}

#[test]
fn a_peer_the_account_trusts_is_believed_about_who_is_calling() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account().trust(registrar().ip()));
    let invite = with_field(
        &incoming_invite("trusted", Some(OFFER)),
        ASSERTING.trim_end(),
    );
    let identity = identity_of(&mut agent, &invite, t0);
    assert!(identity.caller.trusted);
    let shown = identity.caller.shown().expect("an asserted identity");
    assert_eq!(&*shown.display, b"Bob Jones");
    assert_eq!(identity.caller.verstat, Some(Verstat::Passed));
    assert!(identity.caller.privacy.id);
    assert_eq!(identity.caller.diversions.len(), 1);
    assert_eq!(&*identity.from_display, b"Bob", "the From is as written");
}

/// RFC 3325 §8: an asserted identity from a peer the account does not trust
/// is not used "in any way" — and an account that names no trusted peer
/// trusts nobody.
#[test]
fn a_peer_the_account_does_not_trust_is_not_believed() {
    let t0 = Instant::now();
    for account in [
        account(),
        account().trust("198.51.100.7".parse().expect("an address")),
    ] {
        let mut agent = agent(t0);
        agent.add_account(account);
        let invite = with_field(
            &incoming_invite("untrusted", Some(OFFER)),
            ASSERTING.trim_end(),
        );
        let identity = identity_of(&mut agent, &invite, t0);
        assert!(!identity.caller.trusted);
        assert!(identity.caller.asserted.is_empty());
        assert!(identity.caller.shown().is_none());
        assert_eq!(identity.caller.verstat, None);
        assert_eq!(
            identity.caller.diversions.len(),
            1,
            "a diversion has no trust model of its own, and is read"
        );
    }
}

#[test]
fn what_an_incoming_call_carried_stays_the_calls_identity() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account().trust(registrar().ip()));
    let invite = with_field(&incoming_invite("kept", Some(OFFER)), ASSERTING.trim_end());
    deliver(&mut agent, &invite, t0);
    transmits(&mut agent);
    let call = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall { call, .. } => Some(call),
            _ => None,
        })
        .expect("somebody is calling");
    let identity = agent.call_identity(call).expect("the call is known");
    assert!(identity.caller.trusted);
    assert_eq!(identity.caller.asserted.len(), 1);
}

/// RFC 3323 §4.1.1.3 and RFC 3325 §7: an account that withholds its
/// identity is anonymous in `From`, asks for `id` privacy, and says who it
/// is only to the peer it trusts.
#[test]
fn an_account_that_withholds_its_identity_says_who_it_is_only_to_a_trusted_peer() {
    let t0 = Instant::now();
    let mut trusting = agent(t0);
    let id = trusting.add_account(
        account()
            .display_name("Alice")
            .privacy(Privacy::withheld())
            .trust(registrar().ip()),
    );
    trusting.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut trusting);
    assert_eq!(
        text(&invite, HeaderName::From).split(";tag=").next(),
        Some("\"Anonymous\" <sip:anonymous@anonymous.invalid>")
    );
    assert_eq!(text(&invite, HeaderName::Extension("Privacy")), "id");
    assert_eq!(
        text(&invite, HeaderName::Extension("P-Asserted-Identity")),
        "\"Alice\" <sip:alice@example.com>"
    );

    let mut wary = agent(t0);
    let id = wary.add_account(account().privacy(Privacy::withheld()));
    wary.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut wary);
    assert!(text(&invite, HeaderName::From).starts_with("\"Anonymous\""));
    assert_eq!(text(&invite, HeaderName::Extension("Privacy")), "id");
    assert_eq!(
        text(&invite, HeaderName::Extension("P-Asserted-Identity")),
        "",
        "nobody trusted, nobody told"
    );
}

/// RFC 3325 §6: a UA sends an identity field "only ... to proxy servers in a
/// Trust Domain". An account that named one keeps the application's own
/// fields off a call going anywhere else; one that named none made no claim
/// about a trust domain, and they go as written.
#[test]
fn identity_fields_of_the_applications_own_stay_inside_a_trust_domain_the_account_named() {
    let t0 = Instant::now();
    let asserted = HeaderName::Extension("P-Asserted-Identity");
    let preferred = HeaderName::Extension("P-Preferred-Identity");
    let placed = || {
        outgoing()
            .header(asserted, b"<sip:alice@example.com>")
            .header(preferred, b"<tel:+15550001111>")
    };

    let mut outside = agent(t0);
    let id = outside.add_account(account().trust("198.51.100.7".parse().expect("an address")));
    outside.call(id, &placed(), t0).expect("the INVITE goes");
    let invite = sent(&mut outside);
    assert_eq!(text(&invite, asserted), "");
    assert_eq!(text(&invite, preferred), "");

    let mut inside = agent(t0);
    let id = inside.add_account(account().trust(registrar().ip()));
    inside.call(id, &placed(), t0).expect("the INVITE goes");
    let invite = sent(&mut inside);
    assert_eq!(text(&invite, asserted), "<sip:alice@example.com>");
    assert_eq!(text(&invite, preferred), "<tel:+15550001111>");

    let mut unnamed = agent(t0);
    let id = unnamed.add_account(account());
    unnamed.call(id, &placed(), t0).expect("the INVITE goes");
    let invite = sent(&mut unnamed);
    assert_eq!(text(&invite, asserted), "<sip:alice@example.com>");
}

// -- how a call asks to be answered ------------------------------------------

#[test]
fn an_intercom_call_says_it_wants_answering_by_itself_and_how_it_rings() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let invite = with_field(
        &incoming_invite("intercom", Some(OFFER)),
        "Answer-Mode: Auto;require\r\nAlert-Info: <urn:alert:source:internal>\r\nCall-Info: <sip:192.0.2.9>;answer-after=2\r\nRequire: answermode",
    );
    let identity = identity_of(&mut agent, &invite, t0);
    let asked = identity
        .answering
        .answer_mode
        .as_ref()
        .expect("an Answer-Mode");
    assert_eq!(asked.mode, AnswerMode::Auto);
    assert!(asked.required);
    assert_eq!(identity.answering.answer_after, Some(Duration::ZERO));
    assert_eq!(identity.answering.source, Some(RingSource::Internal));
}

/// RFC 5373 §4.3.1's option tag is one this stack reads, so an INVITE that
/// requires it reaches the application rather than a 420.
#[test]
fn an_invite_that_requires_answermode_is_not_refused_as_an_unknown_extension() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let invite = with_field(
        &incoming_invite("required", Some(OFFER)),
        "Answer-Mode: Manual\r\nRequire: answermode",
    );
    deliver(&mut agent, &invite, t0);
    let out = transmits(&mut agent);
    assert!(
        !out.iter().any(|bytes| bytes.starts_with(b"SIP/2.0 420")),
        "refused as unknown: {:?}",
        out.iter()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .collect::<Vec<_>>()
    );
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::IncomingCall { .. }))
    );
}

// -- sending a call somewhere else -------------------------------------------

/// Call forwarding done by the phone: the INVITE is answered 302 with the
/// targets in `Contact`, and a `Diversion` naming the number that was called
/// goes on top of the ones the INVITE already carried.
#[test]
fn a_call_forwarded_by_this_end_is_answered_302_with_where_to_go_and_why() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let invite = with_field(
        &incoming_invite("forwarded", Some(OFFER)),
        "Diversion: <sip:front@example.com>;reason=unconditional;counter=1",
    );
    let call = call_arriving(&mut agent, &invite, t0);
    agent
        .redirect(
            call,
            &Redirect::moved_temporarily()
                .to_preferred(uri("sip:carol@example.com"), 1000)
                .to_preferred(uri("tel:+15550001111"), 500)
                .diverted("no-answer"),
            t0,
        )
        .expect("the 302 goes");
    let answer = sent(&mut agent);
    assert!(answer.starts_with(b"SIP/2.0 302 "), "{answer:?}");
    assert_eq!(
        text(&answer, HeaderName::Contact),
        "<sip:carol@example.com>;q=1, <tel:+15550001111>;q=0.5"
    );
    let diversions: Vec<String> = crate::tests::with(&answer, |message| {
        message
            .field_values(HeaderName::Extension("Diversion"))
            .map(|value| String::from_utf8_lossy(value).into_owned())
            .collect()
    });
    assert_eq!(
        diversions,
        vec![
            "<sip:alice@example.com>;reason=no-answer;counter=1".to_owned(),
            "<sip:front@example.com>;reason=unconditional;counter=1".to_owned(),
        ]
    );
    let (reason, _) = end_of(events(&mut agent));
    assert_eq!(reason, CallEndReason::LocalHangup);
}

#[test]
fn a_redirect_with_nowhere_to_go_or_no_redirection_status_is_refused_and_sends_nothing() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_invite("nowhere", Some(OFFER)), t0);
    let nowhere = agent.redirect(call, &Redirect::moved_temporarily(), t0);
    assert!(matches!(nowhere, Err(UaError::NotARedirection(_))));
    assert_eq!(
        nowhere.map_err(|error| error.to_string()),
        Err("a 302 with no Contact to name is not a redirection".to_owned())
    );
    let refusal = Redirect::with_status(StatusCode::BUSY_HERE);
    assert_eq!(
        refusal.map_err(|error| error.to_string()).err().as_deref(),
        Some("a 486 is not a redirection: those are 300 to 399"),
        "a 486 is a refusal, not a redirection, and is not told it lacks a Contact"
    );
    assert!(transmits(&mut agent).is_empty());
    let alternative = Redirect::with_status(StatusCode::new(380).expect("a status"))
        .expect("380 is a redirection");
    agent
        .redirect(call, &alternative, t0)
        .expect("a 380 names its alternative in its body, not a Contact");
    assert!(sent(&mut agent).starts_with(b"SIP/2.0 380 "));
}
