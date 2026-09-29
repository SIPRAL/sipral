// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Real-time text, RTCP feedback and a recording server, between this
//! harness's own endpoints over real sockets.
//!
//! None of the lab's servers takes part in these: Asterisk, FreeSWITCH and
//! the proxies route a call's signalling but offer no `m=text` of their own,
//! and none of them is a recording server. What the facade's own tests cannot
//! show is the part this crate adds — real UDP sockets for the audio, the
//! text and the copies, and a real TCP connection for the recording session,
//! whose INVITE is too large for a datagram — so that is what runs here, on
//! whatever machine runs the harness's tests.
//!
//! The recording server is a third endpoint of the same kind whose agent takes
//! recording sessions (`UserAgent::accept_recording_sessions`) and answers one
//! with two receive-only streams of its own, the way a recorder does, counting
//! what reaches each.

use std::fmt::Write as _;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral::{
    CallHandle, CallMedia, Event, MediaConfig, MediaEvent, OutgoingCall, RecordTo, UaEvent, Uri,
};
use sipral_core::endpoint::{Input, TransportId, TransportProtocol};
use sipral_core::msg::HeaderName;

use crate::local::{confirmed, endpoint, local_account};
use crate::{Endpoint, catalog, place_call};

const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
const PATIENCE: Duration = Duration::from_secs(10);
/// The recording session's connection, beside each endpoint's own UDP
/// transport (`TransportId(1)`).
const STREAM: TransportId = TransportId(2);

/// A socket on loopback, non-blocking, for a call's text or a copy of its
/// audio.
fn socket() -> UdpSocket {
    let socket = UdpSocket::bind(SocketAddr::new(LOOPBACK, 0)).expect("binding on loopback");
    socket.set_nonblocking(true).expect("a non-blocking socket");
    socket
}

fn address_of(socket: &UdpSocket) -> SocketAddr {
    socket.local_addr().expect("a bound socket")
}

/// Every text datagram `endpoint` has due goes out of `socket`, and every one
/// that arrived on it goes to `call`'s session.
fn carry_text(endpoint: &mut Endpoint, call: Option<CallHandle>, socket: &UdpSocket, now: Instant) {
    while let Some((_, destination, payload)) = endpoint.engine.poll_text(now) {
        let _ = socket.send_to(&payload, destination);
    }
    let mut inbox = [0_u8; 1_500];
    while let Ok((length, from)) = socket.recv_from(&mut inbox) {
        if let Some(mut session) = call.and_then(|call| endpoint.engine.session(call)) {
            let _ = session.receive_text(inbox.get(..length).unwrap_or_default(), from, now);
        }
    }
}

/// What was typed at the far end, in the order it arrived.
fn typed(events: &[Event]) -> String {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Media {
                event: MediaEvent::TextReceived { text, .. },
                ..
            } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

/// The call an incoming INVITE opened, if one did.
fn incoming(events: &[Event]) -> Option<CallHandle> {
    events.iter().find_map(|event| match event {
        Event::Signalling(UaEvent::IncomingCall { call, .. }) => Some(*call),
        _ => None,
    })
}

/// A call placed with text and feedback, answered with both, carries typed
/// text each way over its own sockets and runs RFC 4585's RTCP on its audio.
#[test]
fn text_and_feedback_cross_real_sockets_both_ways() {
    let mut dialling = endpoint(221);
    let mut answering = endpoint(222);
    let _ = answering
        .agent
        .add_account(local_account(&answering, "answering"));
    let account = dialling
        .agent
        .add_account(local_account(&dialling, "dialling"));
    let (dialling_text, answering_text) = (socket(), socket());

    let target = answering.local;
    let outgoing =
        OutgoingCall::new(Uri::parse_str(&format!("sip:answering@{target}")).expect("a URI"))
            .to_address(dialling.transport, target);
    let media = CallMedia::new(catalog().with_feedback(true), MediaConfig::default())
        .text(address_of(&dialling_text));
    let call = place_call(
        &mut dialling,
        account,
        outgoing,
        media,
        target,
        Instant::now(),
    )
    .expect("the INVITE goes");

    let mut far: Option<CallHandle> = None;
    let mut heard_far = String::new();
    let mut heard_near = String::new();
    let mut up = false;
    let mut said = false;
    let mut answered_back = false;
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline && !(heard_far.ends_with("lab\u{2028}") && heard_near == "back")
    {
        let now = Instant::now();
        let near_events = dialling.pump(now);
        let far_events = answering.pump(now);
        if let Some(arrived) = incoming(&far_events) {
            let local = answering
                .open_media(arrived, SocketAddr::new(LOOPBACK, 1), now)
                .expect("a media socket");
            let media = CallMedia::new(catalog().with_feedback(true), MediaConfig::default())
                .text(address_of(&answering_text));
            answering
                .engine
                .answer_with(&mut answering.agent, arrived, local, media, now)
                .expect("the answer goes");
            far = Some(arrived);
        }
        up |= confirmed(&near_events);
        heard_far.push_str(&typed(&far_events));
        heard_near.push_str(&typed(&near_events));
        if up && !said {
            let mut session = dialling.engine.session(call).expect("the call's media");
            assert!(session.has_text(), "the answer took the text stream");
            session.send_text("hello from the lab\r\n").expect("queued");
            said = true;
        }
        if heard_far.ends_with("lab\u{2028}") && !answered_back {
            let far_call = far.expect("the far end's call");
            answering
                .engine
                .session(far_call)
                .expect("the far end's media")
                .send_text("back")
                .expect("queued");
            answered_back = true;
        }
        dialling.run_media(now);
        answering.run_media(now);
        carry_text(&mut dialling, Some(call), &dialling_text, now);
        carry_text(&mut answering, far, &answering_text, now);
        dialling.timers(now);
        answering.timers(now);
        dialling.read_sip(now);
        answering.read_sip(now);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        heard_far, "hello from the lab\u{2028}",
        "what the far end read"
    );
    assert_eq!(heard_near, "back", "what this end read back");

    for (side, session) in [
        ("this end", dialling.engine.session(call)),
        (
            "the far end",
            far.and_then(|far| answering.engine.session(far)),
        ),
    ] {
        let session = session.expect("the call's media");
        let agreed = session.feedback().expect("RTP/AVPF agreed");
        assert!(agreed.generic_nack, "{side}: Generic NACKs agreed");
        assert!(agreed.reduced_size, "{side}: reduced-size RTCP agreed");
    }
}

/// One end of the recording session's connection: what it has read and not
/// yet handed to the agent is the agent's to frame (RFC 3261 §18.3).
fn carry_stream(endpoint: &mut Endpoint, stream: &mut TcpStream, now: Instant) {
    let mut inbox = [0_u8; 4_096];
    loop {
        match stream.read(&mut inbox) {
            Ok(0) => break,
            Ok(length) => {
                let _ = endpoint.agent.receive(
                    Input::StreamData {
                        transport: STREAM,
                        data: inbox.get(..length).unwrap_or_default(),
                    },
                    now,
                );
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) => panic!("the recording session's connection broke: {error}"),
        }
    }
}

/// `Endpoint::pump`, but writing what goes on the connection to it rather
/// than to the UDP socket every other message leaves by.
fn pump_both(endpoint: &mut Endpoint, stream: &mut TcpStream, now: Instant) -> Vec<Event> {
    let mut events = Vec::new();
    loop {
        while let Some(transmit) = endpoint.agent.poll_transmit() {
            if transmit.transport == STREAM {
                stream
                    .write_all(&transmit.payload)
                    .expect("the recording session's connection takes it");
            } else {
                let _ = endpoint
                    .sip
                    .send_to(&transmit.payload, transmit.destination);
            }
        }
        match endpoint.engine.poll_event(&mut endpoint.agent, now) {
            Some(event) => events.push(event),
            None => break,
        }
    }
    events
}

fn bound_stream(endpoint: &mut Endpoint, stream: &TcpStream, now: Instant) {
    stream
        .set_nonblocking(true)
        .expect("a non-blocking connection");
    endpoint
        .agent
        .receive(
            Input::TransportBound {
                transport: STREAM,
                protocol: TransportProtocol::Tcp,
                local: stream.local_addr().expect("a local address"),
                remote: Some(stream.peer_addr().expect("a far end")),
            },
            now,
        )
        .expect("the connection is a transport");
}

/// The recorder's answer: one receive-only stream per label, on the codec
/// the offer names, at the two sockets it counts on.
fn recorder_answer(offer: &str, first: SocketAddr, second: SocketAddr) -> Arc<[u8]> {
    let format = offer
        .lines()
        .find_map(|line| line.strip_prefix("m=audio "))
        .and_then(|line| line.split(' ').nth(2))
        .expect("the offer names a format")
        .to_owned();
    let rtpmap = offer
        .lines()
        .find(|line| line.starts_with(&format!("a=rtpmap:{format} ")))
        .map(|line| format!("{line}\r\n"))
        .unwrap_or_default();
    let mut answer = String::from(
        "v=0\r\no=recorder 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n",
    );
    for (label, socket) in [("1", first), ("2", second)] {
        let _ = write!(
            answer,
            "m=audio {} RTP/AVP {format}\r\n{rtpmap}a=label:{label}\r\na=recvonly\r\n",
            socket.port()
        );
    }
    Arc::from(answer.into_bytes())
}

/// How many RTP packets arrived on `socket` since the last time it was asked.
fn counted(socket: &UdpSocket) -> u32 {
    let mut inbox = [0_u8; 1_500];
    let mut count = 0;
    while let Ok((length, _)) = socket.recv_from(&mut inbox) {
        count += u32::from(length > 12 && inbox[0] >> 6 == 2);
    }
    count
}

/// A call between two endpoints is recorded to a third: the recording
/// session goes over TCP with its metadata and `Require: siprec`, the
/// recorder answers it with a stream per party, both parties' audio reaches
/// it on its own socket, and hanging up the call ends the recording.
#[test]
#[allow(clippy::too_many_lines)]
fn a_call_is_recorded_to_a_recorder_over_real_sockets() {
    let mut dialling = endpoint(231);
    let mut answering = endpoint(232);
    let mut recorder = endpoint(233);
    let _ = answering
        .agent
        .add_account(local_account(&answering, "answering"));
    let _ = recorder
        .agent
        .add_account(local_account(&recorder, "recorder"));
    recorder.agent.accept_recording_sessions(true);
    let account = dialling
        .agent
        .add_account(local_account(&dialling, "dialling"));

    let listener = TcpListener::bind(SocketAddr::new(LOOPBACK, 0)).expect("a listener");
    let recorder_address = listener.local_addr().expect("a listening address");
    let mut to_recorder = TcpStream::connect(recorder_address).expect("a connection");
    let (mut from_dialling, _) = listener.accept().expect("the connection accepted");
    let now = Instant::now();
    bound_stream(&mut dialling, &to_recorder, now);
    bound_stream(&mut recorder, &from_dialling, now);

    let (this_end, far_end) = (socket(), socket());
    let (first, second) = (socket(), socket());

    let target = answering.local;
    let outgoing =
        OutgoingCall::new(Uri::parse_str(&format!("sip:answering@{target}")).expect("a URI"))
            .to_address(dialling.transport, target);
    let media = CallMedia::new(catalog(), MediaConfig::default());
    let call =
        place_call(&mut dialling, account, outgoing, media, target, now).expect("the INVITE goes");

    let mut recording: Option<CallHandle> = None;
    let mut at_the_recorder: Option<CallHandle> = None;
    let mut offer_seen = false;
    let mut recorder_up = false;
    let (mut heard_first, mut heard_second) = (0_u32, 0_u32);
    let mut hung_up = false;
    let mut recording_ended = false;
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline && !recording_ended {
        let now = Instant::now();
        let near = pump_both(&mut dialling, &mut to_recorder, now);
        let far = answering.pump(now);
        let taken = pump_both(&mut recorder, &mut from_dialling, now);
        if let Some(arrived) = incoming(&far) {
            let local = answering
                .open_media(arrived, SocketAddr::new(LOOPBACK, 1), now)
                .expect("a media socket");
            answering
                .engine
                .answer(&mut answering.agent, arrived, local, now)
                .expect("the answer goes");
        }
        for event in &taken {
            if let Event::Signalling(UaEvent::IncomingCall { call, request, .. }) = event {
                let raw = request.as_raw();
                assert_eq!(raw.header(HeaderName::Require), Some(&b"siprec"[..]));
                let body = String::from_utf8_lossy(raw.body()).into_owned();
                assert!(body.contains("application/rs-metadata+xml"), "{body}");
                assert!(
                    body.contains("a=label:1") && body.contains("a=label:2"),
                    "{body}"
                );
                let answer = recorder_answer(&body, address_of(&first), address_of(&second));
                recorder
                    .agent
                    .answer(*call, Some(answer), now)
                    .expect("the recorder answers");
                at_the_recorder = Some(*call);
                offer_seen = true;
            }
            recorder_up |= matches!(event, Event::Signalling(UaEvent::CallConfirmed { call, .. }) if Some(*call) == at_the_recorder);
            recording_ended |= matches!(event, Event::Signalling(UaEvent::CallEnded { call, .. }) if Some(*call) == at_the_recorder);
        }
        if confirmed(&near) && recording.is_none() {
            let to = RecordTo::new(
                Uri::parse_str("sip:recorder@127.0.0.1").expect("a URI"),
                address_of(&this_end),
                address_of(&far_end),
            )
            .to_address(STREAM, recorder_address);
            recording = Some(
                dialling
                    .engine
                    .record_to(&mut dialling.agent, call, to, now)
                    .expect("the recording session goes"),
            );
        }
        dialling.run_media(now);
        answering.run_media(now);
        while let Some((_, from, destination, payload)) = dialling.engine.poll_recording() {
            let out = if from == address_of(&this_end) {
                &this_end
            } else {
                &far_end
            };
            let _ = out.send_to(&payload, destination);
        }
        heard_first += counted(&first);
        heard_second += counted(&second);
        if heard_first >= 25 && heard_second >= 25 && !hung_up {
            let _ = dialling.agent.hangup(call, now);
            hung_up = true;
        }
        for endpoint in [&mut dialling, &mut answering, &mut recorder] {
            endpoint.timers(now);
            endpoint.read_sip(now);
        }
        carry_stream(&mut dialling, &mut to_recorder, now);
        carry_stream(&mut recorder, &mut from_dialling, now);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(offer_seen, "the recorder never saw the recording session");
    assert!(recorder_up, "the recording session never came up");
    assert!(recording.is_some(), "no recording session was placed");
    assert!(
        heard_first >= 25,
        "this end's copy: {heard_first} packets reached the recorder"
    );
    assert!(
        heard_second >= 25,
        "the far end's copy: {heard_second} packets reached the recorder"
    );
    assert!(
        hung_up && recording_ended,
        "hanging up did not end the recording"
    );
}
