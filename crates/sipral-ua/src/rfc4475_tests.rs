// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! RFC 4475 §3.2 to §3.4, received the way a peer would send them.
//!
//! `sipral-core/tests/rfc4475.rs` holds the parser to the corpus: every
//! message there either parses or is refused. That says nothing about what
//! the stack *does* with a message that parses, and the "semantic" groups
//! of the RFC are about exactly that: which status a UAS answers an unknown
//! scheme with, what it does with a body it cannot read, which messages it
//! drops. Each test here feeds one of those messages, byte for byte from
//! `fixtures/rfc4475/`, to a user agent over the transport its own `Via`
//! names, and holds what goes back out to the paragraph of the RFC that
//! says what should.
//!
//! The expected values are the RFC's, not this stack's: where the RFC
//! offers a choice the test says which one was taken and why, and where
//! the stack does less than the RFC asks the test says that too.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use sipral_core::endpoint::ReceiveError;
use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, parse};

use crate::account::Account;
use crate::agent::UserAgent;
use crate::call::CallState;
use crate::event::UaEvent;
use crate::{EndpointConfig, Input, TransportId, TransportProtocol, Uri};

const UDP: TransportId = TransportId(1);
const TCP: TransportId = TransportId(2);
const TLS: TransportId = TransportId(3);

const ANSWER: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 4000 RTP/AVP 0\r\n";

/// How a message reaches the agent: the transport its top `Via` names.
#[derive(Clone, Copy)]
enum Over {
    Udp,
    Tcp,
    Tls,
}

fn fixture(file: &str) -> Vec<u8> {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/rfc4475")
        .join(file);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn local() -> SocketAddr {
    "192.0.2.1:5060".parse().expect("an address")
}

fn peer() -> SocketAddr {
    "192.0.2.9:5060".parse().expect("an address")
}

/// A user agent with a datagram, a TCP and a TLS transport bound, and one
/// account whose address of record is `sip:user@example.com` — the one the
/// torture messages are mostly addressed to.
fn agent(now: Instant) -> UserAgent {
    let mut agent = UserAgent::new(EndpointConfig::default(), [11; 32]).expect("an agent");
    for (transport, protocol, remote) in [
        (UDP, TransportProtocol::Udp, None),
        (TCP, TransportProtocol::Tcp, Some(peer())),
        (TLS, TransportProtocol::Tls, Some(peer())),
    ] {
        agent
            .receive(
                Input::TransportBound {
                    transport,
                    protocol,
                    local: local(),
                    remote,
                },
                now,
            )
            .expect("binding a transport");
    }
    agent.add_account(Account::new(
        Uri::parse_str("sip:user@example.com").expect("a URI"),
        Uri::parse_str("sip:example.com").expect("a URI"),
        Uri::parse_str("sip:user@192.0.2.1").expect("a URI"),
        UDP,
        peer(),
    ));
    written(&mut agent);
    events(&mut agent);
    agent
}

fn receive(
    agent: &mut UserAgent,
    bytes: &[u8],
    over: Over,
    now: Instant,
) -> Result<(), ReceiveError> {
    let input = match over {
        Over::Udp => Input::Datagram {
            transport: UDP,
            remote: peer(),
            local: local(),
            data: bytes,
        },
        Over::Tcp => Input::StreamData {
            transport: TCP,
            data: bytes,
        },
        Over::Tls => Input::StreamData {
            transport: TLS,
            data: bytes,
        },
    };
    agent.receive(input, now)
}

fn written(agent: &mut UserAgent) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(transmit) = agent.poll_transmit() {
        out.push(transmit.payload.to_vec());
    }
    out
}

fn events(agent: &mut UserAgent) -> Vec<UaEvent> {
    let mut out = Vec::new();
    while let Some(event) = agent.poll_event() {
        out.push(event);
    }
    out
}

/// A fresh agent fed `file`: what it wrote, and what it reported.
fn fed(file: &str, over: Over) -> (Vec<Vec<u8>>, Vec<UaEvent>) {
    let now = Instant::now();
    let mut agent = agent(now);
    receive(&mut agent, &fixture(file), over, now).expect("a message that parses");
    (written(&mut agent), events(&mut agent))
}

/// The status of a response the agent wrote.
fn status(bytes: &[u8]) -> u16 {
    let mut scratch = ParseScratch::new();
    parse(bytes, &mut scratch, ParseMode::Strict)
        .expect("the agent writes what it can read")
        .status()
        .expect("a response")
        .get()
}

fn header(bytes: &[u8], name: HeaderName<'_>) -> String {
    let mut scratch = ParseScratch::new();
    let message = parse(bytes, &mut scratch, ParseMode::Strict).expect("a message");
    String::from_utf8_lossy(message.header(name).unwrap_or_default()).into_owned()
}

/// The one response the agent wrote, and that the request it answers was not
/// reported upwards as though it had been accepted.
fn only_answer(file: &str, over: Over) -> Vec<u8> {
    let (out, reported) = fed(file, over);
    assert_eq!(
        out.len(),
        1,
        "{file}: {:?}",
        out.iter()
            .map(|m| String::from_utf8_lossy(m).into_owned())
            .collect::<Vec<_>>()
    );
    assert!(
        !reported
            .iter()
            .any(|event| matches!(event, UaEvent::IncomingCall { .. } | UaEvent::Unclaimed(_))),
        "{file}: a refused request still reached the application: {reported:?}"
    );
    out.into_iter().next().unwrap_or_default()
}

/// `bytes` with one header line swapped for another, for a variation on a
/// fixture that keeps every other byte of it.
fn with_line(bytes: &[u8], old: &str, new: &str) -> Vec<u8> {
    let text = String::from_utf8(bytes.to_vec()).expect("the fixture is text");
    assert!(text.contains(old), "no `{old}` to replace");
    text.replacen(old, new, 1).into_bytes()
}

#[test]
fn badbranch_is_answered_by_the_old_rule_and_its_neighbour_is_not_taken_for_it() {
    // §3.2.1: "An element receiving this request could reject the request
    // with a 400 Response ..., or it could fall back to the RFC 2543-style
    // transaction identifier." This one falls back, so it answers, and a
    // second request from the same place with the same empty identifier is
    // a request of its own rather than a retransmission of the first
    let now = Instant::now();
    let mut agent = agent(now);
    let first = fixture("3.2-transaction/badbranch.dat");
    receive(&mut agent, &first, Over::Udp, now).expect("a message that parses");
    let answered = written(&mut agent);
    assert_eq!(answered.len(), 1);
    let answer = answered.first().expect("one");
    assert_eq!(status(answer), 200);
    assert_eq!(header(answer, HeaderName::CSeq), "8 OPTIONS");

    let second = with_line(
        &with_line(
            &first,
            "Call-ID: badbranch.sadonfo23i420jv0as0derf3j3n",
            "Call-ID: badbranch.second",
        ),
        "CSeq: 8 OPTIONS",
        "CSeq: 9 OPTIONS",
    );
    receive(&mut agent, &second, Over::Udp, now).expect("a message that parses");
    let answered = written(&mut agent);
    assert_eq!(answered.len(), 1);
    let answer = answered.first().expect("one");
    assert_eq!(
        header(answer, HeaderName::CallId),
        "badbranch.second",
        "the second request was answered with the first one's response"
    );
    assert_eq!(header(answer, HeaderName::CSeq), "9 OPTIONS");

    // while the first one sent again is a retransmission, and gets its own
    // answer again
    receive(&mut agent, &first, Over::Udp, now).expect("a message that parses");
    let answered = written(&mut agent);
    assert_eq!(answered.len(), 1);
    assert_eq!(
        header(answered.first().expect("one"), HeaderName::CSeq),
        "8 OPTIONS"
    );
}

#[test]
fn insuf_is_refused_400_without_breaking_anything() {
    // §3.3.1: "An element receiving this message must not break because of
    // the missing information. Ideally, it will respond with a 400". It
    // does, statelessly: a response copies `From`, `To` and `Call-ID` from
    // the request (§8.2.6.2) and this one has none of them, so the 400
    // carries what it had — the `Via` it is routed by (§18.2.2) and the
    // `CSeq` the client matches it on (§17.1.3) — and invents nothing for
    // the rest. Nothing reaches the application, and the next request is
    // served as though this one had never come
    let now = Instant::now();
    let mut agent = agent(now);
    receive(
        &mut agent,
        &fixture("3.3-application/insuf.dat"),
        Over::Udp,
        now,
    )
    .expect("a message that parses");
    let answers = written(&mut agent);
    assert_eq!(answers.len(), 1);
    let answer = answers.first().expect("one");
    assert_eq!(status(answer), 400);
    assert_eq!(
        header(answer, HeaderName::Via),
        "SIP/2.0/UDP 192.0.2.95;branch=z9hG4bKkdj.insuf"
    );
    assert_eq!(header(answer, HeaderName::CSeq), "193942 INVITE");
    for name in [HeaderName::From, HeaderName::To, HeaderName::CallId] {
        assert_eq!(header(answer, name), "", "{name:?} was invented");
    }
    assert!(events(&mut agent).is_empty());

    receive(
        &mut agent,
        &fixture("3.3-application/zeromf.dat"),
        Over::Udp,
        now,
    )
    .expect("a message that parses");
    let after = written(&mut agent);
    assert_eq!(after.len(), 1);
    assert_eq!(status(after.first().expect("one")), 200);
}

#[test]
fn unkscm_is_refused_416() {
    // §3.3.2: "An element receiving this request will reject it with a 416
    // Unsupported URI Scheme response." The To is an ordinary SIP URI, and
    // the RFC is explicit that it is not where the request is going
    let answer = only_answer("3.3-application/unkscm.dat", Over::Tcp);
    assert_eq!(status(&answer), 416);
    assert_eq!(
        header(&answer, HeaderName::CallId),
        "unkscm.nasdfasser0q239nwsdfasdkl34"
    );
}

#[test]
fn novelsc_is_refused_416_as_a_scheme_this_agent_never_accepts() {
    // §3.3.3: "If an element will never accept this scheme as meaningful in
    // a Request-URI, it is appropriate to treat it as unknown and return a
    // 416". A user agent is never reached at a soap.beep address
    let answer = only_answer("3.3-application/novelsc.dat", Over::Tcp);
    assert_eq!(status(&answer), 416);
}

#[test]
fn unksm2_is_refused_405_by_an_agent_that_is_no_registrar() {
    // §3.3.4 has a registrar answer 400 for the non-SIP To. This agent keeps
    // no bindings for anyone, and §3.3.7 names what an endpoint that is not
    // a registrar does with a REGISTER: "A 405 Method Not Allowed is
    // appropriate", with the Allow §21.4.6 makes compulsory
    let answer = only_answer("3.3-application/unksm2.dat", Over::Udp);
    assert_eq!(status(&answer), 405);
    let allow = header(&answer, HeaderName::Allow);
    assert!(allow.contains("INVITE"), "{allow}");
    assert!(!allow.contains("REGISTER"), "{allow}");
}

#[test]
fn bext01_is_refused_420_naming_the_require_tokens_and_not_the_proxy_ones() {
    // §3.3.5: a 420 "containing an Unsupported header field listing these
    // features from either the Require or Proxy-Require header field,
    // depending on the role in which the element is responding". The role
    // here is a UAS, and Proxy-Require is a proxy's business (§20.29)
    let answer = only_answer("3.3-application/bext01.dat", Over::Tls);
    assert_eq!(status(&answer), 420);
    let unsupported = header(&answer, HeaderName::Unsupported);
    let listed: Vec<&str> = unsupported.split(',').map(str::trim).collect();
    assert_eq!(
        listed,
        ["nothingSupportsThis", "nothingSupportsThisEither"],
        "{unsupported}"
    );
}

#[test]
fn invut_is_refused_415_with_the_types_this_agent_reads() {
    // §3.3.6: "An endpoint receiving this request would reject it with a 415
    // Unsupported Media Type error", and §8.2.3 has the response "contain an
    // Accept header field listing the types of all bodies it understands"
    let (out, reported) = fed("3.3-application/invut.dat", Over::Udp);
    let refusal = out
        .iter()
        .find(|message| message.starts_with(b"SIP/2.0 4"))
        .expect("a refusal");
    assert_eq!(status(refusal), 415);
    assert_eq!(header(refusal, HeaderName::Accept), "application/sdp");
    assert!(
        !reported
            .iter()
            .any(|event| matches!(event, UaEvent::IncomingCall { .. })),
        "a call the agent cannot read the offer of was rung: {reported:?}"
    );
}

#[test]
fn regaut01_is_refused_405_by_an_endpoint_that_is_no_registrar() {
    // §3.3.7: "Endpoints choosing not to act as registrars will simply reject
    // the request. A 405 Method Not Allowed is appropriate." Its unknown
    // Authorization scheme is never read
    let answer = only_answer("3.3-application/regaut01.dat", Over::Tcp);
    assert_eq!(status(&answer), 405);
    assert!(!header(&answer, HeaderName::Allow).is_empty());
}

#[test]
fn multi01_is_refused_400() {
    // §3.3.8: "An element receiving this request would respond with a 400
    // Bad Request error."
    let answer = only_answer("3.3-application/multi01.dat", Over::Udp);
    assert_eq!(status(&answer), 400);
}

#[test]
fn mcl01_is_refused_as_a_whole_and_on_a_stream_takes_the_connection_with_it() {
    // §3.3.9: "An element receiving this message should respond with an
    // error. This request appeared over UDP, so the remainder of the
    // datagram can simply be discarded. If a request like this arrives over
    // TCP, the framing error is not recoverable, and the connection should
    // be closed."
    //
    // Over UDP the datagram is refused as a message, and the refusal still
    // goes to the caller of `receive`; the peer gets the RFC's error, built
    // statelessly from the fields that can still be read.
    let now = Instant::now();
    let mut agent = agent(now);
    let bytes = fixture("3.3-application/mcl01.dat");
    assert!(matches!(
        receive(&mut agent, &bytes, Over::Udp, now),
        Err(ReceiveError::Malformed(_))
    ));
    let answers = written(&mut agent);
    assert_eq!(answers.len(), 1, "{answers:?}");
    assert_eq!(answers.first().map(|answer| status(answer)), Some(400));
    assert!(events(&mut agent).is_empty());

    // over TCP the connection goes: nothing more is read from it
    assert!(matches!(
        receive(&mut agent, &bytes, Over::Tcp, now),
        Err(ReceiveError::Malformed(_))
    ));
    assert!(written(&mut agent).is_empty());
    assert!(
        matches!(
            receive(
                &mut agent,
                &fixture("3.3-application/unkscm.dat"),
                Over::Tcp,
                now
            ),
            Err(ReceiveError::UnknownTransport)
        ),
        "a stream whose framing broke was read from again"
    );
}

#[test]
fn bcast_is_dropped() {
    // §3.3.10: "an endpoint receiving this message should simply discard
    // it." It answers nothing this agent sent, and it says so twice: its top
    // Via is not ours (§18.1.2) and no transaction has its branch
    let (out, reported) = fed("3.3-application/bcast.dat", Over::Udp);
    assert!(out.is_empty(), "{out:?}");
    assert!(reported.is_empty(), "{reported:?}");
}

#[test]
fn zeromf_is_answered_as_though_max_forwards_were_still_positive() {
    // §3.3.11: "An endpoint should process the request as if the
    // Max-Forwards field value were still positive." No 483: that is a
    // proxy's answer
    let answer = only_answer("3.3-application/zeromf.dat", Over::Udp);
    assert_eq!(status(&answer), 200);
    assert_eq!(header(&answer, HeaderName::CSeq), "39234321 OPTIONS");
    // and it is the answer RFC 3261 §11.2 describes: "Allow, Accept,
    // Accept-Encoding, Accept-Language, and Supported header fields SHOULD be
    // present in a 200 (OK) response to an OPTIONS request". The methods
    // are the ones §11.2 and §8.2.1 have this agent answer, the body type
    // the one it reads, and the options the ones it implements
    let allow = header(&answer, HeaderName::Allow);
    let methods: Vec<&str> = allow.split(',').map(str::trim).collect();
    for method in ["INVITE", "ACK", "CANCEL", "BYE", "OPTIONS"] {
        assert!(methods.contains(&method), "{method} is not in `{allow}`");
    }
    assert!(!methods.contains(&"REGISTER"), "{allow}");
    assert_eq!(header(&answer, HeaderName::Accept), "application/sdp");
    let supported = header(&answer, HeaderName::Supported);
    assert!(
        supported
            .split(',')
            .map(str::trim)
            .any(|tag| tag == "100rel"),
        "{supported}"
    );
}

#[test]
fn the_three_registrations_are_refused_405_by_an_agent_that_keeps_no_bindings() {
    // §3.3.12 to §3.3.14 say what a registrar makes of these: a contact
    // parameter kept apart from a URI parameter, and an escaped header kept
    // in the binding. This agent is not a registrar, and §3.3.7 is the rule
    // for an endpoint: 405
    for file in [
        "3.3-application/cparam01.dat",
        "3.3-application/cparam02.dat",
        "3.3-application/regescrt.dat",
    ] {
        let answer = only_answer(file, Over::Udp);
        assert_eq!(status(&answer), 405, "{file}");
        assert!(!header(&answer, HeaderName::Allow).is_empty(), "{file}");
    }
}

#[test]
fn sdp01_is_refused_406_rather_than_answered_against_its_accept() {
    // §3.3.15: "since the Accept header field does not contain
    // application/sdp, the response may not contain an SDP body. The
    // recipient of this request could respond with a 406 Not Acceptable".
    // Every 2xx to an INVITE carries a session description, so a call rung
    // here could only ever be answered with one the peer said it cannot take
    let (out, reported) = fed("3.3-application/sdp01.dat", Over::Udp);
    let refusal = out
        .iter()
        .find(|message| message.starts_with(b"SIP/2.0 4"))
        .expect("a refusal");
    assert_eq!(status(refusal), 406);
    assert!(
        !reported
            .iter()
            .any(|event| matches!(event, UaEvent::IncomingCall { .. })),
        "{reported:?}"
    );
}

#[test]
fn inv2543_is_refused_400_for_the_contact_it_does_not_name() {
    // §3.4.1: legal RFC 2543 and "should be accepted by RFC 3261 elements
    // that want to maintain backwards compatibility": no branch, no From
    // tag, no Content-Length, no Max-Forwards. It has no Contact either,
    // which the RFC's list does not mention and RFC 3261 §8.1.1.8 makes
    // compulsory on a request that opens a dialog: without one there is no
    // remote target (§12.1.1) for an ACK's dialog or a BYE to be sent to.
    // This stack takes the other four and refuses the fifth, out loud:
    // before, the whole INVITE was dropped without a word, and a call rung
    // and answered with no dialog behind it would be worse than either
    let (out, reported) = fed("3.4-backward-compat/inv2543.dat", Over::Udp);
    let refusal = out
        .iter()
        .find(|message| !message.starts_with(b"SIP/2.0 100 "))
        .expect("a final answer");
    assert_eq!(status(refusal), 400);
    assert!(
        refusal.starts_with(b"SIP/2.0 400 Missing Contact\r\n"),
        "{}",
        String::from_utf8_lossy(refusal)
    );
    assert!(
        !reported
            .iter()
            .any(|event| matches!(event, UaEvent::IncomingCall { .. })),
        "{reported:?}"
    );
}

#[test]
fn inv2543_with_a_contact_is_taken_as_a_call_whose_dialog_has_no_from_tag() {
    // The same INVITE with the one field RFC 3261 cannot do without, and
    // still with no branch and no From tag. §12.1.1: "A UAS MUST be prepared
    // to receive a request without a tag in the From field, in which case
    // the tag is considered to have a value of null." Before this was
    // checked, the missing tag alone made the INVITE unmatchable by the old
    // transaction rule and it was dropped
    let now = Instant::now();
    let mut agent = agent(now);
    let invite = with_line(
        &fixture("3.4-backward-compat/inv2543.dat"),
        "Call-ID: inv2543.1717@ift.client.example.com\r\n",
        "Call-ID: inv2543.1717@ift.client.example.com\r\n\
Contact: <sip:+13035551111@iftgw.example.com;user=phone>\r\n",
    );
    receive(&mut agent, &invite, Over::Udp, now).expect("a message that parses");
    let trying = written(&mut agent);
    assert!(
        trying.iter().any(|message| status(message) == 100),
        "the INVITE was dropped without a word"
    );
    let call = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall { call, account, .. } => {
                // addressed to a number this agent has no account for
                assert_eq!(account, None);
                Some(call)
            }
            _ => None,
        })
        .expect("the call was reported");

    agent.ring(call, None, now).expect("the 180 goes");
    let ringing = written(&mut agent);
    let ringing = ringing.first().expect("a 180");
    assert_eq!(status(ringing), 180);
    // a call for no account still names where this end can be reached:
    // §12.1.1 has the UAS "add a Contact header field to the response", and
    // an empty one is not a Contact at all
    assert_eq!(header(ringing, HeaderName::Contact), "<sip:192.0.2.1:5060>");
    let to = header(ringing, HeaderName::To);
    let tag = to
        .split(";tag=")
        .nth(1)
        .expect("the 180 carries this end's tag")
        .to_owned();

    agent
        .answer(call, Some(Arc::from(ANSWER)), now)
        .expect("the 200 goes");
    let answered = written(&mut agent);
    let ok = answered.first().expect("a 200");
    assert_eq!(status(ok), 200);
    assert_eq!(header(ok, HeaderName::Contact), "<sip:192.0.2.1:5060>");
    events(&mut agent);

    // the ACK an RFC 2543 caller sends: no branch and no From tag either
    let ack = format!(
        "ACK sip:UserB@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP iftgw.example.com\r\n\
From: <sip:+13035551111@ift.client.example.net;user=phone>\r\n\
To: sip:+16505552222@ss1.example.net;user=phone;tag={tag}\r\n\
Call-ID: inv2543.1717@ift.client.example.com\r\n\
CSeq: 56 ACK\r\n\
\r\n"
    );
    receive(&mut agent, ack.as_bytes(), Over::Udp, now).expect("a message that parses");
    events(&mut agent);
    assert_eq!(
        agent.call_state(call),
        Some(CallState::Confirmed),
        "the ACK did not find the dialog whose remote tag is null"
    );

    // and its BYE, written the same way, finds the same dialog and ends it
    let bye = format!(
        "BYE sip:192.0.2.1:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP iftgw.example.com\r\n\
From: <sip:+13035551111@ift.client.example.net;user=phone>\r\n\
To: sip:+16505552222@ss1.example.net;user=phone;tag={tag}\r\n\
Call-ID: inv2543.1717@ift.client.example.com\r\n\
CSeq: 57 BYE\r\n\
Content-Length: 0\r\n\
\r\n"
    );
    receive(&mut agent, bye.as_bytes(), Over::Udp, now).expect("a message that parses");
    let answered = written(&mut agent);
    let ok = answered.first().expect("an answer to the BYE");
    assert_eq!(status(ok), 200);
    assert_eq!(header(ok, HeaderName::CSeq), "57 BYE");
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::CallEnded { call: ended, .. } if *ended == call)),
        "the BYE did not end the call"
    );
}

#[test]
fn a_call_for_no_account_over_a_stream_names_the_stream_in_its_contact() {
    // The Contact above names the address the INVITE arrived on. Over a
    // stream it must also say which kind: §19.1.2 makes UDP the default for
    // a `sip:` URI with no `transport`, so a peer that called over TCP or TLS
    // and is handed a bare address would send its ACK and its BYE over UDP,
    // to a socket this end may not even have
    for (over, via, parameter) in [(Over::Tcp, "TCP", "tcp"), (Over::Tls, "TLS", "tls")] {
        let now = Instant::now();
        let mut agent = agent(now);
        let invite = with_line(
            &with_line(
                &fixture("3.4-backward-compat/inv2543.dat"),
                "Via: SIP/2.0/UDP iftgw.example.com\r\n",
                &format!("Via: SIP/2.0/{via} iftgw.example.com\r\n"),
            ),
            "Call-ID: inv2543.1717@ift.client.example.com\r\n",
            "Call-ID: inv2543.1717@ift.client.example.com\r\n\
Contact: <sip:+13035551111@iftgw.example.com;user=phone>\r\n",
        );
        // and the Content-Length a stream cannot be framed without (§18.3),
        // which inv2543 leaves out as RFC 2543 let it over UDP
        let text = String::from_utf8(invite).expect("the fixture is text");
        let (head, body) = text.split_once("\r\n\r\n").expect("a body");
        let invite = format!("{head}\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        receive(&mut agent, invite.as_bytes(), over, now).expect("a message that parses");
        written(&mut agent);
        let call = events(&mut agent)
            .into_iter()
            .find_map(|event| match event {
                UaEvent::IncomingCall { call, account, .. } => {
                    assert_eq!(account, None, "{via}");
                    Some(call)
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("the call over {via} was reported"));
        agent.ring(call, None, now).expect("the 180 goes");
        let ringing = written(&mut agent);
        let ringing = ringing.first().expect("a 180");
        assert_eq!(status(ringing), 180, "{via}");
        assert_eq!(
            header(ringing, HeaderName::Contact),
            format!("<sip:192.0.2.1:5060;transport={parameter}>"),
            "{via}"
        );
    }
}

// -- §8.2.1 past the corpus: a method nothing here claims --------------------

/// A request outside any dialog of this agent, over UDP: `method`, with
/// `to` as its `To` value.
fn out_of_dialog(method: &str, to: &str, branch: &str) -> Vec<u8> {
    format!(
        "{method} sip:user@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK{branch}\r\n\
Max-Forwards: 70\r\n\
From: <sip:caller@example.net>;tag=from{branch}\r\n\
To: {to}\r\n\
Call-ID: {branch}@192.0.2.9\r\n\
CSeq: 1 {method}\r\n\
Content-Length: 0\r\n\
\r\n"
    )
    .into_bytes()
}

/// The one answer the agent wrote to `request`, and that nothing reached the
/// application.
fn answered(request: &[u8]) -> Vec<u8> {
    let now = Instant::now();
    let mut agent = agent(now);
    receive(&mut agent, request, Over::Udp, now).expect("a message that parses");
    let out = written(&mut agent);
    assert_eq!(out.len(), 1, "{}", String::from_utf8_lossy(request));
    let reported = events(&mut agent);
    assert!(
        !reported
            .iter()
            .any(|event| matches!(event, UaEvent::Unclaimed(_))),
        "a refused request still reached the application: {reported:?}"
    );
    out.into_iter().next().unwrap_or_default()
}

/// The methods of an `Allow`, in order.
fn methods(allow: &str) -> Vec<String> {
    allow.split(',').map(|m| m.trim().to_owned()).collect()
}

#[test]
fn a_method_this_agent_knows_but_does_not_take_outside_a_dialog_is_405_with_allow() {
    // §8.2.1: "If the UAS recognizes but does not support the method of a
    // request, it MUST generate a 405 (Method Not Allowed) response", and
    // §21.4.6 makes the Allow compulsory. It lists what this agent takes,
    // the same list its answer to OPTIONS gives (§20.5), and never the
    // method it refused
    let options = answered(&out_of_dialog("OPTIONS", "<sip:user@example.com>", "opt"));
    assert_eq!(status(&options), 200);
    let advertised = methods(&header(&options, HeaderName::Allow));
    for method in ["SUBSCRIBE", "PUBLISH"] {
        let answer = answered(&out_of_dialog(
            method,
            "<sip:user@example.com>",
            &method.to_lowercase(),
        ));
        assert_eq!(status(&answer), 405, "{method}");
        let allow = methods(&header(&answer, HeaderName::Allow));
        assert_eq!(allow, advertised, "{method}");
        assert_eq!(
            allow,
            [
                "INVITE", "ACK", "CANCEL", "BYE", "OPTIONS", "UPDATE", "PRACK", "REFER", "NOTIFY"
            ],
            "{method}"
        );
        assert!(!allow.iter().any(|listed| listed == method), "{method}");
        assert_eq!(header(&answer, HeaderName::CSeq), format!("1 {method}"));
    }
}

#[test]
fn a_method_this_agent_does_not_recognise_is_501() {
    // §8.2.1: "If the method is not recognized ... the UAS SHOULD generate
    // a 501 (Not Implemented) response" (§21.5.2)
    for method in ["FOO", "NEWMETHOD", "invite"] {
        let answer = answered(&out_of_dialog(
            method,
            "<sip:user@example.com>",
            &format!("x{}", method.len()),
        ));
        assert_eq!(status(&answer), 501, "{method}");
        assert_eq!(header(&answer, HeaderName::CSeq), format!("1 {method}"));
    }
}

#[test]
fn a_request_for_a_dialog_this_agent_does_not_have_is_481() {
    // §12.2.2: a tag in `To` that matches no dialog "MUST" be answered 481,
    // whatever the method, and a method this agent implements only inside a
    // dialog names none of its dialogs without one (§15.1.2 for BYE), so a
    // 405 listing it in Allow would contradict itself
    for (method, to) in [
        ("BYE", "<sip:user@example.com>;tag=gone"),
        ("INFO", "<sip:user@example.com>;tag=gone"),
        ("SUBSCRIBE", "<sip:user@example.com>;tag=gone"),
        ("FOO", "<sip:user@example.com>;tag=gone"),
        ("BYE", "<sip:user@example.com>"),
        ("UPDATE", "<sip:user@example.com>"),
        ("REFER", "<sip:user@example.com>"),
        ("INFO", "<sip:user@example.com>"),
    ] {
        let answer = answered(&out_of_dialog(method, to, &format!("{method}{}", to.len())));
        assert_eq!(status(&answer), 481, "{method} to {to}");
    }
}

#[test]
fn what_a_handler_claims_outside_a_dialog_is_still_its_own() {
    // the refusal runs after every handler: a MESSAGE is taken by the
    // messaging handler and reported, not refused
    let now = Instant::now();
    let mut agent = agent(now);
    let mut message =
        String::from_utf8(out_of_dialog("MESSAGE", "<sip:user@example.com>", "msg")).expect("text");
    message = message.replace(
        "Content-Length: 0\r\n\r\n",
        "Content-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi",
    );
    receive(&mut agent, message.as_bytes(), Over::Udp, now).expect("a message that parses");
    let reported = events(&mut agent);
    assert!(
        reported
            .iter()
            .any(|event| matches!(event, UaEvent::MessageReceived { .. })),
        "{reported:?}"
    );
    assert!(
        written(&mut agent)
            .iter()
            .all(|answer| status(answer) != 405 && status(answer) != 501)
    );
}
