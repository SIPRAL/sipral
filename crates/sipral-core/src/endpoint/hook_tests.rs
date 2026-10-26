// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The message hook: every message out passes it in `poll_transmit`, every message in passes it
//! before the parser, on a datagram and on a connection alike, and [`Rewrite`] keeps
//! `Content-Length` true.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::tests::{deliver, endpoint, events, incoming, local, options_request, peer, transmits};
use super::{
    Direction, Endpoint, Event, HookedMessage, Input, Rewrite, RewriteError, TransportId,
    TransportProtocol, Verdict,
};

const TCP: TransportId = TransportId(2);

/// What a hook saw, in order.
type Seen = Arc<Mutex<Vec<(Direction, Vec<u8>)>>>;

/// A hook that writes down what it saw and then decides with `decide`.
fn watching(
    seen: &Seen,
    mut decide: impl FnMut(&HookedMessage<'_>) -> Verdict + Send + 'static,
) -> super::MessageHook {
    let seen = Arc::clone(seen);
    Box::new(move |message| {
        if let Ok(mut seen) = seen.lock() {
            seen.push((message.direction, message.bytes.to_vec()));
        }
        decide(message)
    })
}

fn incoming_invites(endpoint: &mut Endpoint) -> Vec<super::super::msg::OwnedMessage> {
    events(endpoint)
        .into_iter()
        .filter_map(|event| match event {
            Event::IncomingInvite { request, .. } => Some(request),
            _ => None,
        })
        .collect()
}

fn add_header(bytes: &[u8], name: &str, value: &[u8]) -> Verdict {
    let mut message = Rewrite::parse(bytes).expect("a message to edit");
    message.set(name, value);
    Verdict::Replace(message.finish())
}

#[test]
fn an_outgoing_request_carries_the_field_the_hook_adds_and_its_retransmission_too() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let seen = Arc::new(Mutex::new(Vec::new()));
    endpoint.set_message_hook(Some(watching(&seen, |message| {
        add_header(message.bytes, "X-Tenant", b"blue")
    })));
    endpoint
        .request(&options_request(), t0)
        .expect("the OPTIONS goes out");
    let first = transmits(&mut endpoint);
    assert_eq!(first.len(), 1);
    let bytes = first
        .first()
        .map(|t| t.payload.to_vec())
        .unwrap_or_default();
    let message = Rewrite::parse(&bytes).expect("the request as sent");
    assert_eq!(message.values("X-Tenant").collect::<Vec<_>>(), [b"blue"]);
    assert_eq!(message.values("Content-Length").collect::<Vec<_>>(), [b"0"]);

    // timer E: the same request again, through the hook again
    endpoint.handle_timeout(t0 + Duration::from_millis(500));
    let again = transmits(&mut endpoint);
    assert_eq!(
        again.first().map(|t| t.payload.to_vec()),
        Some(bytes),
        "the retransmission is the identical message"
    );
    let directions: Vec<Direction> = seen
        .lock()
        .map(|seen| seen.iter().map(|(direction, _)| *direction).collect())
        .unwrap_or_default();
    assert_eq!(directions, [Direction::Outgoing, Direction::Outgoing]);
}

#[test]
fn an_outgoing_message_the_hook_drops_is_never_handed_to_the_transport() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.set_message_hook(Some(Box::new(|_: &HookedMessage<'_>| Verdict::Drop)));
    endpoint
        .request(&options_request(), t0)
        .expect("the OPTIONS is built");
    assert!(transmits(&mut endpoint).is_empty());

    // taken away, the next retransmission goes out as built
    endpoint.set_message_hook(None);
    assert!(!endpoint.has_message_hook());
    endpoint.handle_timeout(t0 + Duration::from_millis(500));
    assert_eq!(transmits(&mut endpoint).len(), 1);
}

#[test]
fn an_incoming_datagram_is_read_as_the_hook_rewrote_it() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let seen = Arc::new(Mutex::new(Vec::new()));
    endpoint.set_message_hook(Some(watching(&seen, |message| {
        match message.direction {
            // a carrier's header the application should not have to read
            Direction::Incoming => {
                let mut rewrite = Rewrite::parse(message.bytes).expect("a message to edit");
                rewrite
                    .remove("X-Carrier-Route")
                    .set("Subject", b"rewritten");
                Verdict::Replace(rewrite.finish())
            }
            Direction::Outgoing => Verdict::Keep,
        }
    })));
    deliver(
        &mut endpoint,
        &incoming("INVITE", "hook1", "X-Carrier-Route: trunk-7\r\n"),
        t0,
    );
    let invites = incoming_invites(&mut endpoint);
    let invite = invites.first().expect("the INVITE reached the endpoint");
    assert_eq!(invite.header("X-Carrier-Route"), None);
    assert_eq!(invite.header("Subject"), Some(&b"rewritten"[..]));
    assert!(
        seen.lock()
            .is_ok_and(|seen| seen.first().is_some_and(|(direction, bytes)| {
                *direction == Direction::Incoming
                    && bytes.windows(15).any(|window| window == b"X-Carrier-Route")
            })),
        "the hook saw the INVITE as it arrived"
    );
}

#[test]
fn an_incoming_datagram_the_hook_drops_is_not_read_or_answered() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.set_message_hook(Some(Box::new(|message: &HookedMessage<'_>| {
        if message.direction == Direction::Incoming {
            Verdict::Drop
        } else {
            Verdict::Keep
        }
    })));
    deliver(&mut endpoint, &incoming("INVITE", "hook2", ""), t0);
    assert!(incoming_invites(&mut endpoint).is_empty());
    assert!(transmits(&mut endpoint).is_empty(), "no 100 Trying for it");
}

#[test]
fn a_message_framed_off_a_connection_passes_the_hook_and_keep_alives_do_not() {
    let t0 = Instant::now();
    let mut endpoint =
        Endpoint::new(super::EndpointConfig::default(), [9; 32]).expect("an endpoint");
    endpoint
        .receive(
            Input::TransportBound {
                transport: TCP,
                protocol: TransportProtocol::Tcp,
                local: local(),
                remote: Some(peer()),
            },
            t0,
        )
        .expect("binding TCP");
    let seen = Arc::new(Mutex::new(Vec::new()));
    endpoint.set_message_hook(Some(watching(&seen, |message| {
        if message.direction == Direction::Incoming {
            add_header(message.bytes, "Subject", b"from the hook")
        } else {
            Verdict::Keep
        }
    })));
    let invite = String::from_utf8_lossy(&incoming("INVITE", "hook3", ""))
        .replace("SIP/2.0/UDP", "SIP/2.0/TCP");
    // a ping, then the INVITE in two writes
    let mut data = b"\r\n\r\n".to_vec();
    data.extend_from_slice(invite.as_bytes());
    let (head, tail) = data.split_at(40);
    for part in [head, tail] {
        endpoint
            .receive(
                Input::StreamData {
                    transport: TCP,
                    data: part,
                },
                t0,
            )
            .expect("stream data");
    }
    let invites = incoming_invites(&mut endpoint);
    assert_eq!(
        invites.first().and_then(|invite| invite.header("Subject")),
        Some(&b"from the hook"[..])
    );
    let incoming_seen = seen
        .lock()
        .map(|seen| {
            seen.iter()
                .filter(|(direction, _)| *direction == Direction::Incoming)
                .count()
        })
        .unwrap_or_default();
    assert_eq!(incoming_seen, 1, "the INVITE once, the ping never");
}

#[test]
fn a_rewrite_keeps_content_length_true_and_reads_compact_and_folded_fields() {
    let message = b"MESSAGE sip:alice@example.com SIP/2.0\r\n\
v: SIP/2.0/UDP 192.0.2.9;branch=z9hG4bKx\r\n\
Subject: one\r\n two\r\n\
l: 5\r\n\
c: text/plain\r\n\
\r\n\
hello";
    let mut rewrite = Rewrite::parse(message).expect("a message");
    assert_eq!(rewrite.values("Via").count(), 1);
    assert_eq!(rewrite.values("subject").collect::<Vec<_>>(), [b"one two"]);
    rewrite
        .set_body(b"hello, world")
        .add("X-Note", b"a")
        .add("X-Note", b"b");
    let out = rewrite.finish();
    let again = Rewrite::parse(&out).expect("the rewritten message");
    assert_eq!(again.values("Content-Length").collect::<Vec<_>>(), [b"12"]);
    assert_eq!(again.values("X-Note").collect::<Vec<_>>(), [b"a", b"b"]);
    assert_eq!(again.body(), b"hello, world");
    assert_eq!(again.start_line(), b"MESSAGE sip:alice@example.com SIP/2.0");
    assert!(out.ends_with(b"\r\n\r\nhello, world"));
}

#[test]
fn a_rewrite_refuses_what_has_no_header() {
    assert_eq!(
        Rewrite::parse(b"no end of header").err(),
        Some(RewriteError::NoEndOfHeader)
    );
    assert_eq!(
        Rewrite::parse(b"INVITE sip:a@b SIP/2.0\r\nnot a field\r\n\r\n").err(),
        Some(RewriteError::BadHeaderLine)
    );
}
