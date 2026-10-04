// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The INVITE sizes `docs/numbers.toml` lists, as the comparison document
//! under `docs/` and the website publish them, rebuilt from the call that
//! measured them: the headless agent registered as `labuser-compare` at the
//! lab's Asterisk, calling `sip:9008@asterisk` from a container address with
//! every codec of the default catalogue, with ICE and without it, and with
//! G.711 alone and ICE.
//! Each first INVITE is challenged the way that Asterisk challenges, and the
//! answer to the challenge is the request the published figures call
//! authenticated.
//!
//! Addresses, user, target and challenge have the lengths the lab's had, so
//! the bytes counted here are the bytes that crossed the wire there. Each
//! test prints a `numbers:` line that `scripts/check.sh --only numbers` holds
//! to `docs/numbers.toml`; the test itself holds the answer to RFC 3261
//! §18.1.1's 1300 bytes, which is what lets it go over UDP at all.

use std::net::SocketAddr;
use std::time::Instant;

use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, parse};

use crate::codec::CodecCatalog;
use crate::tests::{Stack, uri};
use crate::{Account, Credentials, EndpointConfig, Event, OutgoingCall, TransportId, UaEvent};

const UDP: TransportId = TransportId(1);

/// The largest request RFC 3261 §18.1.1 lets go over UDP when the path MTU
/// is unknown.
const DATAGRAM_LIMIT: usize = 1_300;

/// The agent's SIP address in the lab: its container's, on the port the
/// agent binds unless told otherwise.
fn agent_sip() -> SocketAddr {
    "172.18.0.5:5070".parse().expect("an address")
}

/// The agent's RTP address: the same container, an ephemeral port.
fn agent_media() -> SocketAddr {
    "172.18.0.5:40000".parse().expect("an address")
}

/// The lab's Asterisk.
fn asterisk() -> SocketAddr {
    "172.18.0.2:5060".parse().expect("an address")
}

/// The value of one header field of a message on the wire.
fn field(message: &[u8], name: HeaderName<'_>) -> String {
    let mut scratch = ParseScratch::new();
    parse(message, &mut scratch, ParseMode::Lenient)
        .ok()
        .and_then(|parsed| parsed.header(name).map(<[u8]>::to_vec))
        .map(|value| String::from_utf8_lossy(&value).into_owned())
        .unwrap_or_default()
}

/// The 401 Asterisk answers an INVITE with: its realm, a nonce of its own
/// shape (seconds, a slash, 32 hexadecimal digits), its opaque.
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

/// The first INVITE of the lab's call under `catalog`, and the one that
/// answered the challenge, as each went on the wire.
fn lab_call(catalog: CodecCatalog) -> (Vec<u8>, Vec<u8>) {
    let now = Instant::now();
    let mut agent = Stack::configured(
        1,
        agent_sip(),
        agent_media(),
        catalog,
        EndpointConfig::default(),
        now,
    );
    let account = agent.agent.add_account(
        Account::new(
            uri("sip:labuser-compare@asterisk"),
            uri("sip:asterisk"),
            uri(&format!("sip:labuser-compare@{}", agent_sip())),
            UDP,
            asterisk(),
        )
        .credentials(Credentials::new("labuser-compare", "labpass")),
    );
    agent
        .engine
        .place(
            &mut agent.agent,
            account,
            OutgoingCall::new(uri("sip:9008@asterisk")),
            agent_media(),
            now,
        )
        .expect("the INVITE goes");
    agent.drain(now, false);
    let first = agent
        .outbound()
        .into_iter()
        .find(|datagram| datagram.starts_with(b"INVITE "))
        .expect("the first INVITE");
    agent.heard.clear();
    agent.deliver(&challenge_to(&first), asterisk(), now);
    agent.drain(now, false);
    let stream_asked = agent.heard.iter().find_map(|event| match *event {
        Event::Signalling(UaEvent::Unclaimed(sipral_core::endpoint::Event::TransportWanted {
            request_bytes,
            ..
        })) => Some(request_bytes),
        _ => None,
    });
    assert_eq!(
        stream_asked, None,
        "the authenticated INVITE was held back for a stream transport"
    );
    let answered = agent
        .outbound()
        .into_iter()
        .find(|datagram| datagram.starts_with(b"INVITE "))
        .expect("the INVITE answering the challenge");
    assert!(
        String::from_utf8_lossy(&answered).contains("Digest "),
        "the second INVITE carries no credentials"
    );
    (first, answered)
}

/// The size of `message` at its longest. The one field of the INVITE whose
/// length is drawn rather than fixed is the session id on the `o=` line, a
/// random 64-bit number written in decimal: 20 digits, or fewer when the
/// draw is small. Counted as 20 whatever this run drew, so that a figure is
/// never under a budget by the luck of a seed.
fn longest(message: &[u8]) -> usize {
    let text = String::from_utf8_lossy(message);
    let drawn = text
        .lines()
        .find_map(|line| line.strip_prefix("o=- "))
        .and_then(|rest| rest.split(' ').next())
        .map(str::len)
        .expect("an o= line");
    message.len() + 20 - drawn
}

/// Print one call's two sizes for the gate, and hold the answered one to the
/// datagram limit.
fn report(name: &str, (first, answered): &(Vec<u8>, Vec<u8>)) {
    let (first, answered) = (longest(first), longest(answered));
    println!("numbers: invite.{name}.first={first} invite.{name}.authenticated={answered}");
    assert!(
        answered <= DATAGRAM_LIMIT,
        "the authenticated INVITE ({name}) can be {answered} bytes, over RFC 3261 §18.1.1's \
         {DATAGRAM_LIMIT}"
    );
}

/// Every default codec, no ICE: published as 923 and 1222 bytes.
#[test]
fn the_published_invite_without_ice() {
    report("default", &lab_call(CodecCatalog::new()));
}

/// Every default codec and ICE: published as 1088 and 1236 bytes.
#[test]
fn the_published_invite_with_ice() {
    report(
        "default_ice",
        &lab_call(CodecCatalog::new().with_ice(crate::IcePolicy::Offered)),
    );
}

/// G.711 alone and ICE: published on the website as 954 and 1253 bytes,
/// from a run whose session id drew 19 digits; at 20 they are 955 and 1254.
#[test]
fn the_published_invite_of_g711_with_ice() {
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    report("g711_ice", &lab_call(catalog));
}
