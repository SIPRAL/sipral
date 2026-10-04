// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A session recorded, and the same session fed back.
//!
//! The interesting test here is the last one: an endpoint driven through an
//! OPTIONS that is retransmitted once and then answered, written down, and
//! replayed into an endpoint that has never seen any of it. What is compared
//! is not that the replay finished — it is the bytes, the events and the
//! diagnostic record, because a replay that reached the end having decided
//! something else on the way proves nothing at all.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::{Arrival, Payload, Played, ReadError, RecordError, Recorder, Recording, Replay, Step};
use crate::endpoint::{
    Endpoint, EndpointConfig, Event, Input, OutgoingRequest, TransportId, TransportProtocol,
};
use crate::msg::{HeaderName, Method, ParseMode, ParseScratch, Uri, parse};
use crate::transaction::DialogId;

const UDP: TransportId = TransportId(1);
const SEED: [u8; 32] = [23; 32];
/// What the application calls the one thing it does on its own here.
const ASK: &str = "options";

fn local() -> SocketAddr {
    "192.0.2.1:5060".parse().expect("a local address")
}

fn peer() -> SocketAddr {
    "192.0.2.9:5060".parse().expect("the peer's address")
}

fn bound() -> Input<'static> {
    Input::TransportBound {
        transport: UDP,
        protocol: TransportProtocol::Udp,
        local: local(),
        remote: None,
    }
}

/// The one thing the application does that no recording can feed back for it.
fn ask(endpoint: &mut Endpoint, now: Instant) {
    let request = OutgoingRequest::new(
        Method::Options,
        Uri::parse_str("sip:example.com").expect("a URI"),
        UDP,
        peer(),
    )
    .to(b"<sip:example.com>")
    .from(b"<sip:alice@example.com>");
    endpoint.request(&request, now).expect("the OPTIONS goes");
}

/// The 200 the peer answers with, echoing what §8.2.6.2 requires.
fn answer(request: &[u8]) -> Vec<u8> {
    let mut scratch = ParseScratch::new();
    let message = parse(request, &mut scratch, ParseMode::Lenient).expect("a request");
    let mut out = b"SIP/2.0 200 OK\r\n".to_vec();
    for name in [
        HeaderName::Via,
        HeaderName::From,
        HeaderName::To,
        HeaderName::CallId,
        HeaderName::CSeq,
    ] {
        out.extend_from_slice(name.canonical().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(message.header(name).unwrap_or_default());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    out
}

/// A call, for the test that resolves a dialog after it connects.
fn invite_request() -> OutgoingRequest {
    OutgoingRequest::new(
        Method::Invite,
        Uri::parse_str("sip:bob@example.com").expect("a URI"),
        UDP,
        peer(),
    )
    .to(b"<sip:bob@example.com>")
    .from(b"<sip:alice@example.com>")
}

/// The 200 that confirms the dialog `invite_request` opens.
fn invite_ok(request: &[u8]) -> Vec<u8> {
    let mut scratch = ParseScratch::new();
    let message = parse(request, &mut scratch, ParseMode::Lenient).expect("a request");
    let mut out = b"SIP/2.0 200 OK\r\n".to_vec();
    for name in [HeaderName::Via, HeaderName::From] {
        out.extend_from_slice(name.canonical().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(message.header(name).unwrap_or_default());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"To: ");
    out.extend_from_slice(message.header(HeaderName::To).unwrap_or_default());
    out.extend_from_slice(b";tag=desk\r\n");
    for name in [HeaderName::CallId, HeaderName::CSeq] {
        out.extend_from_slice(name.canonical().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(message.header(name).unwrap_or_default());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Contact: <sip:bob@192.0.2.9>\r\nContent-Length: 0\r\n\r\n");
    out
}

/// Everything the stack did, in a shape two runs can be compared in.
#[derive(Debug, Default, PartialEq, Eq)]
struct Trace {
    /// What went on the wire, and how far into the session it went.
    out: Vec<(Duration, Vec<u8>)>,
    /// What the application was told, as it prints.
    events: Vec<String>,
    /// What the endpoint decided (`docs/14-diagnostics.md`), which is the
    /// stack's own answer to "was this the same run".
    decisions: String,
}

impl Trace {
    fn drain(&mut self, endpoint: &mut Endpoint, at: Duration) {
        while let Some(transmit) = endpoint.poll_transmit() {
            self.out.push((at, transmit.payload.to_vec()));
        }
        while let Some(event) = endpoint.poll_event() {
            self.events.push(format!("{event:?}"));
        }
    }

    fn close(&mut self, endpoint: &Endpoint) {
        self.decisions = endpoint.diagnostics_json();
    }

    /// The first thing the endpoint wrote, which is what the peer answers.
    fn first(&self) -> Vec<u8> {
        self.out
            .first()
            .map(|(_, bytes)| bytes.clone())
            .unwrap_or_default()
    }
}

/// A session driven the way an application drives one, with a recorder beside
/// every call into the stack.
fn record() -> (Recording, Trace) {
    let t0 = Instant::now();
    let mut endpoint = Endpoint::new(EndpointConfig::default(), SEED).unwrap();
    let mut recorder = Recorder::new(SEED).about("an OPTIONS retransmitted once, then answered");
    let mut trace = Trace::default();

    recorder.arrived(&bound(), t0);
    endpoint.receive(bound(), t0).expect("binding a transport");
    trace.drain(&mut endpoint, Duration::ZERO);

    recorder.cue(ASK, t0);
    ask(&mut endpoint, t0);
    trace.drain(&mut endpoint, Duration::ZERO);

    // T1, so timer E fires and the identical datagram goes again (§17.1.2.2)
    let at = Duration::from_millis(500);
    recorder.woke(t0 + at);
    endpoint.handle_timeout(t0 + at);
    trace.drain(&mut endpoint, at);

    let at = Duration::from_millis(700);
    let bytes = answer(&trace.first());
    let arrived = Input::Datagram {
        transport: UDP,
        remote: peer(),
        local: local(),
        data: &bytes,
    };
    recorder.arrived(&arrived, t0 + at);
    endpoint.receive(arrived, t0 + at).expect("a 200");
    trace.drain(&mut endpoint, at);

    trace.close(&endpoint);
    (recorder.finish().expect("a recording of it"), trace)
}

/// The same session, fed back into an endpoint that has never seen it.
fn replay(recording: &Recording) -> Trace {
    let origin = Instant::now();
    let mut endpoint = Endpoint::new(EndpointConfig::default(), recording.seed()).unwrap();
    let mut trace = Trace::default();
    let mut replay = Replay::new(recording, origin);

    while let Some(now) = replay.next_at() {
        let at = now.saturating_duration_since(origin);
        let played = replay
            .step(&mut endpoint)
            .expect("the recorded bytes read as they did the first time");
        if let Some(Played::Cue(label)) = played {
            assert_eq!(label, ASK, "the recording names what the application did");
            ask(&mut endpoint, now);
        }
        trace.drain(&mut endpoint, at);
    }

    trace.close(&endpoint);
    trace
}

// -- the whole point ---------------------------------------------------------

#[test]
fn a_recorded_session_replays_to_the_same_bytes_events_and_decisions() {
    let (recording, live) = record();
    let replayed = replay(&recording);

    assert_eq!(
        live.out.len(),
        2,
        "an OPTIONS and the retransmission of it; the 200 is answered by nothing"
    );
    assert_eq!(
        live.out.first().map(|(_, bytes)| bytes),
        live.out.get(1).map(|(_, bytes)| bytes),
        "17.1.1.2: a retransmission is the identical datagram"
    );
    assert_eq!(replayed.out, live.out, "the same bytes at the same offsets");
    assert_eq!(replayed.events, live.events);
    assert_eq!(
        replayed.decisions, live.decisions,
        "the endpoint decided the same things in the same order, at the same offsets"
    );
    assert!(
        live.decisions.contains("request.retransmitted"),
        "the run is worth replaying: {}",
        live.decisions
    );
}

#[test]
fn a_replay_that_ignores_its_cues_is_a_replay_of_a_different_session() {
    // the honest boundary, tested rather than asserted: what the application
    // did on its own is named in the recording and not fed back by it, so a
    // caller that steps past a cue gets a stack with nothing to answer
    let (recording, _) = record();
    let origin = Instant::now();
    let mut endpoint = Endpoint::new(EndpointConfig::default(), recording.seed()).unwrap();
    let mut replay = Replay::new(&recording, origin);
    while replay
        .step(&mut endpoint)
        .expect("the bytes read")
        .is_some()
    {}

    assert!(
        endpoint.poll_transmit().is_none(),
        "nothing was ever sent, so nothing was retransmitted"
    );
    assert_eq!(endpoint.in_flight(), (0, 0));
}

// -- a third way in -----------------------------------------------------

/// `Endpoint::resolved` is a third way into a sans-I/O core, beside `receive`
/// and `handle_timeout`. Unlike a cue it carries data — the addresses a
/// resolver found — so a replay does not have to be told to redo it: it
/// reads the frame and calls `resolved` itself.
#[test]
fn a_resolved_answer_is_captured_and_a_replay_repeats_it_unasked() {
    let elsewhere: SocketAddr = "198.51.100.7:5060".parse().expect("another address");
    let t0 = Instant::now();
    let mut endpoint = Endpoint::new(EndpointConfig::default(), SEED).unwrap();
    let mut recorder =
        Recorder::new(SEED).about("a call whose dialog is re-resolved after it connects");

    recorder.arrived(&bound(), t0);
    endpoint.receive(bound(), t0).expect("binding a transport");

    recorder.cue("invite", t0);
    endpoint
        .invite(&invite_request(), t0)
        .expect("the INVITE goes");
    let invite_bytes = endpoint
        .poll_transmit()
        .expect("the INVITE")
        .payload
        .to_vec();

    let ok = invite_ok(&invite_bytes);
    let arrived = Input::Datagram {
        transport: UDP,
        remote: peer(),
        local: local(),
        data: &ok,
    };
    recorder.arrived(&arrived, t0);
    endpoint.receive(arrived, t0).expect("the 200");
    let dialog = established(&mut endpoint).expect("the call connected");

    recorder.cue("ack", t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK");
    while endpoint.poll_transmit().is_some() {}

    // the answer to an `Event::ResolveNeeded` this test never reads, which is
    // the point: nothing about this call goes through `receive` or
    // `handle_timeout`
    endpoint.resolved(dialog, &[elsewhere], None);
    recorder.resolved(dialog, &[elsewhere], None, t0);

    recorder.cue("bye", t0);
    endpoint.bye(dialog, t0).expect("the BYE goes");
    assert_eq!(
        endpoint.poll_transmit().expect("the BYE").destination,
        elsewhere,
        "resolved moved the dialog's flow before the BYE was built"
    );

    let text = recorder.finish().expect("a recording").to_text();
    assert!(
        text.contains("resolved "),
        "the answer is a frame of its own, not folded into an arrival: {text}"
    );
    let recording = Recording::parse(&text).expect("this build's own text");
    assert_eq!(recording.to_text(), text, "round trips");

    // fed back into an endpoint that never saw the call, and nobody here
    // calls `resolved` a second time
    let origin = Instant::now();
    let mut replayed = Endpoint::new(EndpointConfig::default(), recording.seed()).unwrap();
    let mut dialog_replayed = None;
    let mut replay = Replay::new(&recording, origin);
    while let Some(now) = replay.next_at() {
        match replay
            .step(&mut replayed)
            .expect("the recorded bytes read as they did the first time")
        {
            Some(Played::Cue("invite")) => {
                replayed
                    .invite(&invite_request(), now)
                    .expect("the INVITE goes");
                while replayed.poll_transmit().is_some() {}
            }
            Some(Played::Cue("ack")) => {
                replayed
                    .ack_2xx(
                        dialog_replayed.expect("established before it is acknowledged"),
                        None,
                        now,
                    )
                    .expect("the ACK");
                while replayed.poll_transmit().is_some() {}
            }
            Some(Played::Cue("bye")) => {
                replayed
                    .bye(
                        dialog_replayed.expect("established before the cue that ends it"),
                        now,
                    )
                    .expect("the BYE goes");
            }
            Some(Played::Cue(other)) => panic!("an unnamed cue: {other}"),
            Some(Played::Fed) | None => {}
        }
        if dialog_replayed.is_none() {
            dialog_replayed = established(&mut replayed);
        }
    }

    assert_eq!(
        replayed
            .poll_transmit()
            .expect("the replayed BYE")
            .destination,
        elsewhere,
        "the replay answered `Driven::resolved` from the frame and reached the same address"
    );
}

/// The dialog an `Event::Established` names, draining every event so none of
/// it is left for the next call to see.
fn established(endpoint: &mut Endpoint) -> Option<DialogId> {
    let mut dialog = None;
    while let Some(event) = endpoint.poll_event() {
        if let Event::Established { dialog: id, .. } = event {
            dialog = Some(id);
        }
    }
    dialog
}

// -- the format --------------------------------------------------------------

#[test]
fn a_recording_round_trips_through_its_own_text() {
    let (recording, _) = record();
    let text = recording.to_text();
    let read = Recording::parse(&text).expect("the text this crate just wrote");
    assert_eq!(read, recording);
    assert_eq!(read.to_text(), text);
}

#[test]
fn the_text_holds_the_seed_the_session_was_drawn_from() {
    let (recording, _) = record();
    let text = recording.to_text();
    assert!(text.starts_with("sipral-recording 3\nseed "), "{text}");
    assert!(
        text.contains(&"17".repeat(32)),
        "the seed is the twenty-third byte, sixty-four times over: {text}"
    );
    assert_eq!(Recording::parse(&text).expect("a recording").seed(), SEED);
}

#[test]
fn a_reader_refuses_a_recording_from_a_later_version_and_says_so() {
    let (recording, _) = record();
    let text = recording
        .to_text()
        .replacen("sipral-recording 3", "sipral-recording 4", 1);
    let error = Recording::parse(&text).expect_err("a version this build cannot know");
    assert_eq!(
        error,
        ReadError::Version {
            found: 4,
            supported: 3
        }
    );
    assert_eq!(
        error.to_string(),
        "recording is version 4 and this reader knows 3"
    );
}

#[test]
fn a_reader_refuses_a_file_that_does_not_name_the_format() {
    for text in [
        "",
        "seed 00\n",
        "sipral-recording\n",
        "sipral-recording 0\n",
    ] {
        assert_eq!(
            Recording::parse(text),
            Err(ReadError::NotARecording),
            "{text:?}"
        );
    }
}

#[test]
fn a_recording_with_no_seed_replays_into_nothing_and_is_refused() {
    let text = "sipral-recording 1\n+0.000000000 wake\n";
    assert_eq!(Recording::parse(text), Err(ReadError::NoSeed));
}

#[test]
fn a_frame_stamped_before_the_one_above_it_is_refused() {
    let text = format!(
        "sipral-recording 1\nseed {}\n+1.000000000 wake\n+0.500000000 wake\n",
        "17".repeat(32)
    );
    assert_eq!(
        Recording::parse(&text),
        Err(ReadError::Backwards { line: 4 })
    );
}

#[test]
fn a_payload_with_no_frame_above_it_is_refused() {
    let text = format!(
        "sipral-recording 1\nseed {}\n| SIP/2.0 200 OK\\r\\n\n",
        "17".repeat(32)
    );
    assert_eq!(
        Recording::parse(&text),
        Err(ReadError::StrayPayload { line: 3 })
    );
}

#[test]
fn a_line_a_reader_does_not_understand_stops_the_read() {
    let seed = "17".repeat(32);
    for (text, line) in [
        (format!("sipral-recording 1\nseed {seed}\nsomething\n"), 3),
        (
            format!("sipral-recording 1\nseed {seed}\n+0.000000000 sing\n"),
            3,
        ),
        (format!("sipral-recording 1\nseed {seed}\n+0.00 wake\n"), 3),
        (
            format!("sipral-recording 1\nseed {seed}\n+0.000000000 bound 1 XYZ 192.0.2.1:5060 -\n"),
            3,
        ),
        (
            format!("sipral-recording 1\nseed {seed}\n+0.000000000 wake now\n"),
            3,
        ),
        (
            format!("sipral-recording 1\nseed {seed}\n+0.000000000 wake\nseed {seed}\n"),
            4,
        ),
    ] {
        assert_eq!(
            Recording::parse(&text),
            Err(ReadError::Syntax { line }),
            "{text:?}"
        );
    }
}

// -- no audio, and it is the format that says so -----------------------------

#[test]
fn bytes_that_are_not_text_cannot_be_made_into_a_payload() {
    // one G.711 frame of silence and one of speech: neither is text, and
    // neither has a spelling in this format
    assert_eq!(Payload::new(&[0xff; 160]), None);
    assert_eq!(Payload::new(&[0x7f, 0x80, 0x81, 0xfe]), None);
    // nor has a control character that SIP itself is not made of
    assert_eq!(Payload::new(b"a\x00b"), None);
    assert_eq!(Payload::new(b"a\x07b"), None);
    // what SIP is made of goes in as it stands
    assert!(Payload::new(b"OPTIONS sip:example.com SIP/2.0\r\n\r\n").is_some());
    assert!(Payload::new(b"\t \r\n").is_some());
    assert!(Payload::new(b"").is_some());
}

#[test]
fn a_recorder_handed_a_media_frame_refuses_the_whole_recording() {
    // not the frame: the whole recording. One that quietly lost a packet
    // would replay into a different session and say nothing about it
    let t0 = Instant::now();
    let mut recorder = Recorder::new(SEED);
    recorder.arrived(&bound(), t0);
    let audio = [0xff_u8; 160];
    recorder.arrived(
        &Input::Datagram {
            transport: UDP,
            remote: peer(),
            local: local(),
            data: &audio,
        },
        t0,
    );
    recorder.woke(t0);

    assert_eq!(recorder.spoiled(), Some(RecordError::NotText { frame: 1 }));
    assert_eq!(
        recorder.finish().expect_err("no recording comes of it"),
        RecordError::NotText { frame: 1 }
    );
}

#[test]
fn a_note_or_a_cue_that_is_not_one_line_spoils_the_recording() {
    let t0 = Instant::now();
    let mut recorder = Recorder::new(SEED).about("two\nlines");
    recorder.woke(t0);
    assert_eq!(
        recorder.finish().expect_err("prose has to fit on its line"),
        RecordError::NotOneLine
    );

    let mut recorder = Recorder::new(SEED);
    recorder.cue("answer\tthe call", t0);
    assert_eq!(
        recorder.finish().expect_err("a label is read by a person"),
        RecordError::NotOneLine
    );
}

#[test]
fn a_hand_written_frame_carrying_a_byte_outside_the_alphabet_is_refused() {
    // the other end of the same rule: a file that arrives with something
    // smuggled into a payload line does not become a recording
    let seed = "17".repeat(32);
    for spelling in ["\\x41", "\\u0041", "\\0", "\\"] {
        let text = format!(
            "sipral-recording 1\nseed {seed}\n\
             +0.000000000 datagram 1 192.0.2.9:5060 192.0.2.1:5060\n| {spelling}\n"
        );
        assert_eq!(
            Recording::parse(&text),
            Err(ReadError::NotText { line: 4 }),
            "{spelling:?} is not an escape this format has"
        );
    }
}

#[test]
fn a_note_that_is_not_one_line_is_refused_on_the_way_back_in_too() {
    let text = format!("sipral-recording 1\nseed {}\nnote \x07\n", "17".repeat(32));
    assert_eq!(Recording::parse(&text), Err(ReadError::NotText { line: 3 }));
}

// -- the shapes a session takes ----------------------------------------------

#[test]
fn a_display_name_in_utf8_records_as_it_stands() {
    // above ASCII is text, and a `From` with a name in it is an ordinary
    // message rather than something to escape
    let t0 = Instant::now();
    let mut recorder = Recorder::new(SEED);
    let message =
        "MESSAGE sip:b@example.com SIP/2.0\r\nFrom: \"M\u{fc}ller\" <sip:a@example.com>\r\n\r\n";
    recorder.arrived(
        &Input::Datagram {
            transport: UDP,
            remote: peer(),
            local: local(),
            data: message.as_bytes(),
        },
        t0,
    );
    let recording = recorder.finish().expect("a recording");
    let text = recording.to_text();
    assert!(text.contains("M\u{fc}ller"), "{text}");
    assert_eq!(
        Recording::parse(&text).expect("it reads back"),
        recording,
        "and it comes back the same"
    );
}

#[test]
fn a_stream_read_that_stops_in_the_middle_of_a_message_survives_the_round_trip() {
    // the reason a recording keeps the reads rather than the messages: where
    // a read ended is a fact about the session, and §18.3 framing bugs live
    // exactly there
    let t0 = Instant::now();
    let mut recorder = Recorder::new(SEED);
    for half in ["SIP/2.0 200 OK\r\nCon", "tent-Length: 0\r\n\r\n"] {
        recorder.arrived(
            &Input::StreamData {
                transport: UDP,
                data: half.as_bytes(),
            },
            t0,
        );
    }
    let recording = recorder.finish().expect("a recording");
    let read = Recording::parse(&recording.to_text()).expect("it reads back");
    assert_eq!(read, recording);

    let halves: Vec<&[u8]> = read
        .frames()
        .iter()
        .filter_map(|frame| match frame.step {
            Step::Arrived(ref arrival) => arrival.payload().map(Payload::as_bytes),
            _ => None,
        })
        .collect();
    assert_eq!(
        halves,
        [
            b"SIP/2.0 200 OK\r\nCon".as_slice(),
            b"tent-Length: 0\r\n\r\n"
        ]
    );
}

#[test]
fn every_shape_of_arrival_comes_back_as_the_input_it_was() {
    use crate::endpoint::TransportErrorKind;

    let t0 = Instant::now();
    let mut recorder = Recorder::new(SEED).about("one of each");
    for input in [
        bound(),
        Input::TransportBound {
            transport: TransportId(2),
            protocol: TransportProtocol::Tls,
            local: local(),
            remote: Some(peer()),
        },
        Input::StreamClosed {
            transport: TransportId(2),
        },
        Input::TransportFailed {
            transport: UDP,
            error: TransportErrorKind::Unreachable,
        },
    ] {
        recorder.arrived(&input, t0);
    }
    let recording = recorder.finish().expect("a recording");
    let read = Recording::parse(&recording.to_text()).expect("it reads back");
    assert_eq!(read, recording);
    assert_eq!(read.note(), Some("one of each"));

    let arrivals: Vec<&Arrival> = read
        .frames()
        .iter()
        .filter_map(|frame| match frame.step {
            Step::Arrived(ref arrival) => Some(arrival),
            _ => None,
        })
        .collect();
    assert_eq!(arrivals.len(), 4);
    assert!(matches!(
        arrivals.first().map(|arrival| arrival.as_input()),
        Some(Input::TransportBound { remote: None, .. })
    ));
    assert!(matches!(
        arrivals.get(3).map(|arrival| arrival.as_input()),
        Some(Input::TransportFailed {
            error: TransportErrorKind::Unreachable,
            ..
        })
    ));
}

#[test]
fn the_offsets_are_the_ones_the_session_was_driven_at() {
    let t0 = Instant::now();
    let mut recorder = Recorder::new(SEED);
    recorder.woke(t0);
    recorder.woke(t0 + Duration::from_micros(1));
    recorder.woke(t0 + Duration::from_secs(3_600));
    let recording = recorder.finish().expect("a recording");

    let offsets: Vec<Duration> = recording.frames().iter().map(|frame| frame.at).collect();
    assert_eq!(
        offsets,
        [
            Duration::ZERO,
            Duration::from_micros(1),
            Duration::from_secs(3_600)
        ],
        "the first frame is the origin, and everything is from there"
    );
    assert_eq!(recording.duration(), Duration::from_secs(3_600));
    assert!(
        recording.to_text().contains("+0.000001000 wake"),
        "to the nanosecond: {}",
        recording.to_text()
    );
}
