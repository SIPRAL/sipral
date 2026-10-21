// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A carrier gateway's calls: SIP-T and SIP-I, with the ISUP of the call
//! carried beside the session description (RFC 3204, RFC 3372, ITU-T
//! Q.1912.5), in both directions.

use std::sync::Arc;
use std::time::Instant;

use sipral_core::msg::{HeaderName, MultipartBuilder, Part};

use crate::call::{CallHandle, CallState};
use crate::event::UaEvent;
use crate::isup::{
    BackwardCall, CallEvent, CalledStatus, Cause, EventKind, ForwardCall, GenericNumber,
    IsupBuilder, Location, Nature, NatureOfConnection, Number, NumberQualifier, Presentation,
    RedirectReason, Redirection, Screening,
};
use crate::tests::{
    ACCEPTED, ANSWER, OFFER, account, agent, answered, call_up, deliver, events, header, in_dialog,
    outgoing, registrar, reversed, sent, transmits,
};
use crate::{CallerIdentity, ReasonProtocol, UserAgent};

/// The version a SIP-I gateway names, RFC 3204's Table 1 token for ITU-T
/// ISUP from 1992 on.
const ITU: &str = "application/ISUP;version=itu-t92+";

/// The IAM of a call diverted twice on its way to the gateway, the caller's
/// number withheld: the caller, an additional calling party number, the
/// called number, who it was last and first diverted from, and why.
fn iam() -> Vec<u8> {
    IsupBuilder::initial_address(
        NatureOfConnection::default(),
        ForwardCall {
            isup_all_the_way: true,
            isdn_access: true,
            ..ForwardCall::default()
        },
        0x0a,
        3,
        &Number::new(Nature::National, "5555550102"),
    )
    .calling_party(
        &Number::new(Nature::International, "15555550100")
            .presented(Presentation::Restricted)
            .screened(Screening::Network),
    )
    .generic_number(&GenericNumber::new(
        NumberQualifier::AdditionalCalling,
        Number::new(Nature::International, "15555550199").screened(Screening::UserNotVerified),
    ))
    .redirecting(&Number::new(Nature::International, "15555550101"))
    .original_called(&Number::new(Nature::International, "15555550103"))
    .redirection(Redirection::diverted(
        RedirectReason::NoReply,
        RedirectReason::Unconditional,
        2,
    ))
    .build()
    .expect("an IAM")
}

fn rel(cause: u8) -> Vec<u8> {
    IsupBuilder::release(Cause::new(cause, Location::PublicRemote))
        .build()
        .expect("a REL")
}

/// SDP and ISUP as one `multipart/mixed` body: its `Content-Type`, and the
/// body.
fn beside(sdp: &[u8], isup_type: &str, handling: &str, isup: &[u8]) -> (String, Vec<u8>) {
    let disposition = format!("signal;handling={handling}");
    let built = MultipartBuilder::mixed()
        .part(Part::new("application/sdp", sdp).disposition("session;handling=required"))
        .part(Part::new(isup_type, isup).disposition(&disposition))
        .build()
        .expect("a multipart body");
    (built.content_type().to_owned(), built.into_body())
}

/// The same message with its body replaced by `body` under `content_type`,
/// and `extra` header fields added.
fn with_body(message: &[u8], content_type: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let end = message
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a header section");
    let head = String::from_utf8_lossy(&message[..end]);
    let mut out = String::new();
    for line in head.split("\r\n") {
        if !line.starts_with("Content-Type:") && !line.starts_with("Content-Length:") {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    let mut out = format!(
        "{out}Content-Type: {content_type}\r\n{extra}Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// A gateway's INVITE: an anonymous `From`, as a gateway writes one for a
/// withheld number, and the given body.
fn gateway_invite(branch: &str, content_type: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "INVITE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK{branch};rport\r\n\
Max-Forwards: 70\r\n\
From: \"Anonymous\" <sip:anonymous@anonymous.invalid>;tag=gw{branch}\r\n\
To: <sip:+15555550102@example.com>\r\n\
Call-ID: gateway-{branch}\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:gw@192.0.2.9>\r\n\
Content-Length: 0\r\n\r\n"
    );
    with_body(head.as_bytes(), content_type, extra, body)
}

/// What an INVITE did: the call it rang, and its identity; `None` when it
/// rang nothing.
fn arriving(
    agent: &mut UserAgent,
    bytes: &[u8],
    now: Instant,
) -> Option<(CallHandle, CallerIdentity)> {
    deliver(agent, bytes, now);
    transmits(agent);
    events(agent).into_iter().find_map(|event| match event {
        UaEvent::IncomingCall {
            call,
            identity: Some(identity),
            ..
        } => Some((call, identity.caller.clone())),
        _ => None,
    })
}

fn has_remote(agent: &UserAgent, call: CallHandle) -> bool {
    agent
        .calls
        .get(&call)
        .is_some_and(|held| held.session.has_remote())
}

fn uris(identity: &CallerIdentity) -> (Vec<String>, Vec<String>) {
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    (
        identity
            .asserted
            .iter()
            .map(|party| text(&party.uri))
            .collect(),
        identity
            .diversions
            .iter()
            .map(|diversion| text(&diversion.party.uri))
            .collect(),
    )
}

#[test]
fn a_gateways_invite_is_rung_with_the_offer_beside_the_iam_and_the_caller_read_from_it() {
    // RFC 3204 §4.1's shape: SDP and ISUP in one multipart/mixed, the ISUP
    // marked required. It is understood, so it is taken (RFC 3261 §8.2.3);
    // the SDP part is the offer
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account().trust(registrar().ip()));
    let (content_type, body) = beside(OFFER, ITU, "required", &iam());
    let (call, caller) = arriving(
        &mut agent,
        &gateway_invite("sipi", &content_type, "", &body),
        t0,
    )
    .expect("the call rings");
    assert!(has_remote(&agent, call), "the SDP part is the offer");

    let isup = caller.isup.as_ref().expect("the IAM is read");
    let calling = isup.calling.as_ref().expect("a calling party number");
    assert_eq!(calling.text(), "+15555550100");
    assert_eq!(calling.presentation, Some(Presentation::Restricted));
    assert_eq!(
        isup.called.as_ref().map(Number::text).as_deref(),
        Some("5555550102")
    );
    assert_eq!(isup.additional_calling.len(), 1);
    assert_eq!(isup.additional_calling[0].text(), "+15555550199");
    assert_eq!(isup.category, Some(0x0a));
    assert_eq!(isup.version.as_deref(), Some("itu-t92+"));
    assert_eq!(&*isup.message, iam());

    // RFC 3398 §8.2.1 and Q.1912.5: the network's number is the asserted
    // identity from a trusted gateway, and a withheld one stays withheld
    assert!(caller.trusted);
    assert!(
        caller.privacy.id,
        "presentation restricted asks for Privacy: id"
    );
    let (asserted, diverted) = uris(&caller);
    assert_eq!(asserted, ["tel:+15555550100"]);
    assert_eq!(diverted, ["tel:+15555550101", "tel:+15555550103"]);
    let reasons: Vec<Option<&str>> = caller
        .diversions
        .iter()
        .map(|diversion| diversion.reason.as_deref())
        .collect();
    assert_eq!(reasons, [Some("no-answer"), Some("unconditional")]);
    let counters: Vec<Option<u8>> = caller.diversions.iter().map(|d| d.counter).collect();
    assert_eq!(counters, [Some(1), Some(1)]);
    assert_eq!(caller.diversions[0].privacy.as_deref(), Some("off"));

    // and it is answered as any call is
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("the answer goes");
    let ok = sent(&mut agent);
    assert!(
        ok.starts_with(b"SIP/2.0 200 OK\r\n"),
        "{}",
        String::from_utf8_lossy(&ok)
    );
}

#[test]
fn an_untrusted_gateway_asserts_nothing_and_a_withheld_number_stays_withheld() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (content_type, body) = beside(OFFER, ITU, "optional", &iam());
    let (_, caller) = arriving(
        &mut agent,
        &gateway_invite("untrusted", &content_type, "", &body),
        t0,
    )
    .expect("the call rings");
    let (asserted, diverted) = uris(&caller);
    assert!(asserted.is_empty(), "RFC 3325 §8: {asserted:?}");
    assert!(caller.privacy.id);
    assert_eq!(diverted.len(), 2, "diversions have no trust model");
    assert!(caller.isup.is_some());
}

#[test]
fn what_the_sip_headers_say_comes_before_what_the_isup_says() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account().trust(registrar().ip()));
    let (content_type, body) = beside(OFFER, ITU, "required", &iam());
    let extra = "P-Asserted-Identity: <sip:+15555550177@carrier.example.com>\r\n\
Diversion: <sip:+15555550178@carrier.example.com>;reason=user-busy\r\n";
    let (_, caller) = arriving(
        &mut agent,
        &gateway_invite("headers", &content_type, extra, &body),
        t0,
    )
    .expect("the call rings");
    let (asserted, diverted) = uris(&caller);
    assert_eq!(asserted, ["sip:+15555550177@carrier.example.com"]);
    assert_eq!(diverted, ["sip:+15555550178@carrier.example.com"]);
    // still withheld: restriction is kept, never lifted
    assert!(caller.privacy.id);
}

#[test]
fn a_national_number_stays_in_the_isup_rather_than_becoming_a_uri() {
    // RFC 3966 §5.1.5: a local number's tel: URI needs its context, which the
    // gateway knows and this end does not
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account().trust(registrar().ip()));
    let national = IsupBuilder::initial_address(
        NatureOfConnection::default(),
        ForwardCall::default(),
        0x0a,
        3,
        &Number::new(Nature::National, "5555550102"),
    )
    .calling_party(&Number::new(Nature::National, "5555550100"))
    .build()
    .expect("an IAM");
    let (content_type, body) = beside(OFFER, ITU, "required", &national);
    let (_, caller) = arriving(
        &mut agent,
        &gateway_invite("national", &content_type, "", &body),
        t0,
    )
    .expect("the call rings");
    assert!(caller.asserted.is_empty());
    assert!(!caller.privacy.id);
    let isup = caller.isup.expect("the IAM is read");
    assert_eq!(
        isup.calling.map(|number| number.text()).as_deref(),
        Some("5555550100")
    );
}

#[test]
fn isup_this_agent_does_not_read_is_refused_when_required_and_ignored_when_optional() {
    // RFC 3204 §6: required and not understood, 415; optional, ignored. ANSI
    // ISUP is another format than Q.763's
    let ansi = "application/ISUP;version=ansi00";
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (content_type, body) = beside(OFFER, ansi, "required", &iam());
    deliver(
        &mut agent,
        &gateway_invite("ansi", &content_type, "", &body),
        t0,
    );
    let refusal = transmits(&mut agent)
        .into_iter()
        .find(|bytes| bytes.starts_with(b"SIP/2.0 4"))
        .expect("a refusal");
    assert!(
        refusal.starts_with(b"SIP/2.0 415 "),
        "{}",
        String::from_utf8_lossy(&refusal)
    );
    assert_eq!(header(&refusal, HeaderName::Accept), ACCEPTED);
    assert!(
        !events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::IncomingCall { .. }))
    );

    let (content_type, body) = beside(OFFER, ansi, "optional", &iam());
    let (call, caller) = arriving(
        &mut agent,
        &gateway_invite("ansiopt", &content_type, "", &body),
        t0,
    )
    .expect("the call rings");
    assert!(has_remote(&agent, call));
    assert!(
        caller.isup.is_none(),
        "an ANSI IAM is not read as an ITU-T one"
    );
    assert!(caller.diversions.is_empty() && !caller.privacy.id);
}

#[test]
fn an_invite_carrying_isup_alone_is_an_invite_without_an_offer() {
    // RFC 3204 §6's default handling is required, and ISUP is understood
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (call, caller) = arriving(&mut agent, &gateway_invite("alone", ITU, "", &iam()), t0)
        .expect("the call rings");
    assert!(!has_remote(&agent, call), "no SDP, no offer");
    assert!(caller.isup.is_some());
}

/// The far end's BYE in a call this end placed, carrying `body` beside
/// `extra` fields.
fn bye_carrying(ack: &[u8], content_type: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    with_body(
        &reversed(ack, "BYE", "byerel", 2, None),
        content_type,
        extra,
        body,
    )
}

fn causes_of_end(agent: &mut UserAgent) -> Vec<(ReasonProtocol, Option<u16>, Option<String>)> {
    events(agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::CallEnded { causes, .. } => Some(
                causes
                    .iter()
                    .map(|cause| {
                        (
                            cause.protocol.clone(),
                            cause.cause,
                            cause.text.as_deref().map(str::to_owned),
                        )
                    })
                    .collect(),
            ),
            _ => None,
        })
        .expect("the call ends")
}

#[test]
fn a_bye_carrying_a_rel_ends_the_call_with_the_rels_cause() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_, ack) = call_up(&mut agent, id, t0);
    deliver(&mut agent, &bye_carrying(&ack, ITU, "", &rel(17)), t0);
    let ok = sent(&mut agent);
    assert!(
        ok.starts_with(b"SIP/2.0 200 OK\r\n"),
        "{}",
        String::from_utf8_lossy(&ok)
    );
    assert_eq!(
        causes_of_end(&mut agent),
        [(ReasonProtocol::Q850, Some(17), Some("User busy".to_owned()))]
    );
}

#[test]
fn a_reason_header_comes_before_the_rel_beside_it() {
    // RFC 3398 §7.2.3: "the Reason header value MUST be preferred"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_, ack) = call_up(&mut agent, id, t0);
    let (content_type, body) = beside(ANSWER, ITU, "optional", &rel(17));
    let bye = bye_carrying(&ack, &content_type, "Reason: Q.850;cause=16\r\n", &body);
    deliver(&mut agent, &bye, t0);
    sent(&mut agent);
    assert_eq!(
        causes_of_end(&mut agent),
        [(ReasonProtocol::Q850, Some(16), None)]
    );
}

/// A response to a request this end sent, carrying `body`.
fn answered_carrying(
    request: &[u8],
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> Vec<u8> {
    with_body(
        &answered(request, status, reason, "gw", None),
        content_type,
        "",
        body,
    )
}

fn progress_of(agent: &mut UserAgent) -> Vec<CallState> {
    events(agent)
        .into_iter()
        .filter_map(|event| match event {
            UaEvent::CallProgress { state, .. } => Some(state),
            _ => None,
        })
        .collect()
}

#[test]
fn a_call_placed_to_a_gateway_reads_the_session_beside_the_acm_and_the_anm() {
    // RFC 3398 §7.2.6 and §7.2.7: ACM on a 180 or 183, ANM on the 200. A 180
    // carrying an ACM alone describes no session, so it is ringing, not early
    // media; a 183 with SDP beside a CPG is early media
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    let backward = BackwardCall {
        called_status: CalledStatus::SubscriberFree,
        ..BackwardCall::default()
    };
    let acm = IsupBuilder::address_complete(backward)
        .build()
        .expect("an ACM");
    deliver(
        &mut agent,
        &answered_carrying(&invite, 180, "Ringing", ITU, &acm),
        t0,
    );
    assert_eq!(progress_of(&mut agent), [CallState::Ringing]);

    let cpg = IsupBuilder::call_progress(CallEvent::new(EventKind::InBandInformation))
        .build()
        .expect("a CPG");
    let (content_type, body) = beside(ANSWER, ITU, "optional", &cpg);
    deliver(
        &mut agent,
        &answered_carrying(&invite, 183, "Session Progress", &content_type, &body),
        t0,
    );
    assert_eq!(progress_of(&mut agent), [CallState::EarlyMedia]);
    assert!(
        has_remote(&agent, call),
        "the SDP beside the CPG is the answer"
    );

    let anm = IsupBuilder::answer().build().expect("an ANM");
    let (content_type, body) = beside(ANSWER, ITU, "optional", &anm);
    deliver(
        &mut agent,
        &answered_carrying(&invite, 200, "OK", &content_type, &body),
        t0,
    );
    let ack = sent(&mut agent);
    assert!(ack.starts_with(b"ACK "));
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::CallConfirmed { .. }))
    );
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

#[test]
fn a_refusal_carrying_a_rel_reports_the_rels_cause() {
    // Q.1912.5 carries the REL in the final response it maps it to
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &answered_carrying(&invite, 486, "Busy Here", ITU, &rel(17)),
        t0,
    );
    transmits(&mut agent);
    assert_eq!(
        causes_of_end(&mut agent),
        [(ReasonProtocol::Q850, Some(17), Some("User busy".to_owned()))]
    );
}

#[test]
fn a_reinvite_an_update_and_an_info_carrying_isup_are_taken() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_, ack) = call_up(&mut agent, id, t0);
    let cpg = IsupBuilder::call_progress(CallEvent::new(EventKind::Progress))
        .build()
        .expect("a CPG");

    // a re-INVITE with ISUP alone asks for an offer (RFC 3261 §14.1), and an
    // UPDATE with it only refreshes the target
    for (method, cseq, offers) in [("INVITE", 2, true), ("UPDATE", 3, false)] {
        let request = with_body(
            &reversed(&ack, method, &format!("re{method}"), cseq, None),
            ITU,
            "",
            &cpg,
        );
        deliver(&mut agent, &request, t0);
        let answer = transmits(&mut agent).pop().expect("an answer");
        assert!(
            answer.starts_with(b"SIP/2.0 200 "),
            "{method}: {}",
            String::from_utf8_lossy(&answer)
        );
        assert_eq!(
            header(&answer, HeaderName::ContentType) == b"application/sdp",
            offers,
            "{method}"
        );
        if method == "INVITE" {
            deliver(
                &mut agent,
                &with_body(
                    &reversed(&ack, "ACK", "reack", cseq, None),
                    "application/sdp",
                    "",
                    ANSWER,
                ),
                t0,
            );
        }
        events(&mut agent);
    }

    // RFC 3372 §5.4: mid-call ISUP rides in an INFO
    let info = with_body(&reversed(&ack, "INFO", "isupinfo", 4, None), ITU, "", &cpg);
    deliver(&mut agent, &info, t0);
    let answer = sent(&mut agent);
    assert!(
        answer.starts_with(b"SIP/2.0 200 "),
        "{}",
        String::from_utf8_lossy(&answer)
    );
}

#[test]
fn a_prack_carrying_isup_acknowledges_the_provisional() {
    // the 415 a PRACK with an unreadable body gets (RFC 3261 §8.2.3) is not
    // the answer to one carrying ISUP: it is understood, and acknowledges
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let invite = crate::tests::plus(
        &crate::tests::incoming_invite("relisup", Some(OFFER)),
        "Require: 100rel\r\n",
    );
    let call = crate::tests::call_arriving(&mut agent, &invite, t0);
    agent
        .ring(call, Some(Arc::from(ANSWER)), t0)
        .expect("183 with early media");
    let progress = sent(&mut agent);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("the answer is taken");
    assert!(
        transmits(&mut agent).is_empty(),
        "the 200 waits for the PRACK"
    );
    let rseq = String::from_utf8_lossy(&header(&progress, HeaderName::RSeq)).into_owned();
    let acm = IsupBuilder::address_complete(BackwardCall::default())
        .build()
        .expect("an ACM");
    let prack = with_body(
        &in_dialog(&progress, "PRACK", "isupprack", 2),
        ITU,
        &format!("RAck: {rseq} 1 INVITE\r\n"),
        &acm,
    );
    deliver(&mut agent, &prack, t0);
    let written = transmits(&mut agent);
    for cseq in [&b"2 PRACK"[..], b"1 INVITE"] {
        assert!(
            written
                .iter()
                .any(|bytes| bytes.starts_with(b"SIP/2.0 200 OK\r\n")
                    && header(bytes, HeaderName::CSeq) == cseq),
            "{}",
            String::from_utf8_lossy(cseq)
        );
    }
}
