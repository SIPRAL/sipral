// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The RFC 4317 offer/answer examples, run against the SDP layer.
//!
//! `fixtures/rfc4317/manifest.toml` lists every description in the order the
//! RFC gives it: an offer, then the answer to it, then (where the section goes
//! on) the next offer of the same session and its answer. Each exchange is
//! held to three things:
//!
//! - the example's answer is a legal answer to the example's offer under
//!   RFC 3264 §6 and, from the second exchange on, a legal modification of
//!   the session under §8;
//! - [`SessionDescription::answer`], told only which streams to take and
//!   with which formats, produces an answer that agrees with the example's
//!   stream for stream;
//! - [`SessionDescription::media_plans`] reads the two descriptions and
//!   settles on the codec and direction the section says it should.
//!
//! The examples name their hosts (`host.atlanta.example.com`), which a
//! sans-I/O core does not resolve. The last check substitutes documentation
//! addresses for the two `c=` lines before planning, and nothing else.

// a test says what it means; the no-panic discipline is for the library
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "this is a test binary, not the library"
)]

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use sipral_core::auth::DigestAlgorithm;
use sipral_core::sdp::{
    AcceptedStream, Connection, Direction, MediaPlan, SdpError, SessionDescription, StreamAnswer,
    parse,
};

struct Entry {
    name: String,
    section: String,
    file: String,
    role: String,
    round: String,
    sha256: String,
}

fn fixtures() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/sipral-core
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/rfc4317")
}

/// Read the `[[description]]` blocks: quoted values on lines of their own, as
/// in the RFC 4475 manifest.
fn manifest() -> Vec<Entry> {
    let text = fs::read_to_string(fixtures().join("manifest.toml")).expect("the manifest");
    let mut entries = Vec::new();
    let mut current: Option<Entry> = None;
    for line in text.lines() {
        let line = line.trim();
        if line == "[[description]]" {
            entries.extend(current.take());
            current = Some(Entry {
                name: String::new(),
                section: String::new(),
                file: String::new(),
                role: String::new(),
                round: String::new(),
                sha256: String::new(),
            });
            continue;
        }
        let Some(entry) = current.as_mut() else {
            continue;
        };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_owned();
        match key.trim() {
            "name" => entry.name = value,
            "section" => entry.section = value,
            "file" => entry.file = value,
            "role" => entry.role = value,
            "round" => entry.round = value,
            "sha256" => entry.sha256 = value,
            _ => {}
        }
    }
    entries.extend(current);
    entries
}

fn load(file: &str) -> SessionDescription {
    let bytes = fs::read(fixtures().join(file)).expect("a fixture");
    parse(&bytes).unwrap_or_else(|e| panic!("{file}: {e}"))
}

/// One offer and the answer to it.
struct Exchange {
    section: String,
    round: String,
    offer: SessionDescription,
    answer: SessionDescription,
}

/// The exchanges of one section, in order.
fn exchanges(section: &str) -> Vec<Exchange> {
    all_exchanges()
        .into_iter()
        .filter(|e| e.section == section)
        .collect()
}

fn all_exchanges() -> Vec<Exchange> {
    let entries = manifest();
    let mut out = Vec::new();
    for pair in entries.chunks(2) {
        let [offer, answer] = pair else {
            panic!("an offer without an answer: {}", pair[0].name);
        };
        assert_eq!(offer.role, "offer", "{} is not an offer", offer.name);
        assert_eq!(answer.role, "answer", "{} is not an answer", answer.name);
        assert_eq!(offer.section, answer.section, "{}", answer.name);
        assert_eq!(offer.round, answer.round, "{}", answer.name);
        out.push(Exchange {
            section: offer.section.clone(),
            round: offer.round.clone(),
            offer: load(&offer.file),
            answer: load(&answer.file),
        });
    }
    out
}

/// Whether `answer` is a legal answer to `offer` under RFC 3264 §6, and
/// why not when it is not.
fn check_answer(offer: &SessionDescription, answer: &SessionDescription) -> Result<(), String> {
    // "The answer MUST contain exactly the same number of "m=" lines as the
    // offer"
    if offer.media.len() != answer.media.len() {
        return Err(format!(
            "{} streams offered, {} answered",
            offer.media.len(),
            answer.media.len()
        ));
    }
    // "The "t=" line in the answer MUST equal that of the offer."
    if offer.timing != answer.timing {
        return Err("t= differs".to_owned());
    }
    for (index, (offered, answered)) in offer.media.iter().zip(&answer.media).enumerate() {
        // "the media type of the stream in the answer MUST match that of the
        // offer"
        if offered.media != answered.media || offered.proto != answered.proto {
            return Err(format!(
                "stream {index}: a different media type or transport"
            ));
        }
        if answered.is_rejected() {
            continue;
        }
        // a stream refused in the offer stays refused in the answer
        if offered.is_rejected() {
            return Err(format!(
                "stream {index}: answered a stream the offer refused"
            ));
        }
        // §6.1: at least one format the offer listed
        if !answered.formats.iter().any(|f| offered.formats.contains(f)) {
            return Err(format!("stream {index}: nothing in common with the offer"));
        }
        // §6.1: the direction the offer allows, and no more
        let offered_direction = offer.direction_of(offered);
        let answered_direction = answer.direction_of(answered);
        if Direction::answer_to(offered_direction, answered_direction) != answered_direction {
            return Err(format!(
                "stream {index}: {answered_direction} answers an offer of {offered_direction}"
            ));
        }
        // §6.1: an answer that keeps a dynamic payload type says what it is
        for payload in answered.payload_types().filter(|&p| p >= 96) {
            if answered.rtpmap(payload).is_none() {
                return Err(format!("stream {index}: no rtpmap for {payload}"));
            }
        }
    }
    Ok(())
}

/// Whether `next` is a legal new offer (or answer) of the session `previous`
/// described, under RFC 3264 §8.
fn check_modification(
    previous: &SessionDescription,
    next: &SessionDescription,
) -> Result<(), String> {
    // "the origin line ... MUST be the same as that in the previous SDP,
    // except that the version in the origin field MUST increment by one"
    let (a, b) = (&previous.origin, &next.origin);
    if a.username != b.username
        || a.session_id != b.session_id
        || a.network != b.network
        || a.address_type != b.address_type
        || a.address != b.address
    {
        return Err("the origin changed beyond its version".to_owned());
    }
    if b.version != a.version + 1 {
        return Err(format!("version {} follows {}", b.version, a.version));
    }
    // §8: "the number of m lines MUST NOT be less than the number of m lines
    // in the previous SDP", and the streams that were there keep their media
    // type
    if next.media.len() < previous.media.len() {
        return Err("a stream was removed rather than refused".to_owned());
    }
    for (index, (was, is)) in previous.media.iter().zip(&next.media).enumerate() {
        if was.media != is.media && !was.is_rejected() {
            return Err(format!("stream {index} changed its media type"));
        }
    }
    Ok(())
}

/// Ask the stack for the answer the example gives: the same streams taken or
/// refused, on the same ports, with the same formats in the same order, and
/// the direction the example's answerer wrote.
fn rebuild(exchange: &Exchange) -> SessionDescription {
    let streams: Vec<StreamAnswer> = exchange
        .answer
        .media
        .iter()
        .map(|media| {
            if media.is_rejected() {
                StreamAnswer::Reject
            } else {
                StreamAnswer::Accept(
                    AcceptedStream::new(media.port, media.formats.clone())
                        .with_direction(exchange.answer.direction_of(media)),
                )
            }
        })
        .collect();
    let connection = exchange.answer.connection.clone().expect("a session c=");
    exchange
        .offer
        .answer(exchange.answer.origin.clone(), connection, &streams)
        .unwrap_or_else(|e| {
            panic!(
                "§{} round {}: the stack would not answer: {e}",
                exchange.section, exchange.round
            )
        })
}

/// The two descriptions of an exchange, with the two named hosts replaced by
/// addresses.
fn addressed(exchange: &Exchange) -> (SessionDescription, SessionDescription) {
    let mut offer = exchange.offer.clone();
    let mut answer = exchange.answer.clone();
    offer.connection = Some(Connection::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    answer.connection = Some(Connection::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))));
    (offer, answer)
}

/// The negotiation of one stream, as the offerer sees it.
fn plan(exchange: &Exchange, stream: usize) -> Result<Option<MediaPlan>, SdpError> {
    let (offer, answer) = addressed(exchange);
    offer.media_plan(&answer, stream)
}

/// The negotiation of every stream, each of which has to settle.
fn plans(exchange: &Exchange) -> Vec<Option<MediaPlan>> {
    let (offer, answer) = addressed(exchange);
    offer
        .media_plans(&answer)
        .unwrap_or_else(|e| panic!("§{} round {}: {e}", exchange.section, exchange.round))
}

/// The codec and direction of a stream the plan kept, as the offerer sees
/// them.
fn settled(plan: Option<&MediaPlan>) -> (String, Direction) {
    let plan = plan.expect("the stream is up");
    (plan.codec.rtpmap.encoding.clone(), plan.direction)
}

#[test]
fn every_file_is_the_one_the_manifest_hashed() {
    let entries = manifest();
    assert_eq!(entries.len(), 22, "the manifest lost a description");
    for entry in entries {
        let bytes = fs::read(fixtures().join(&entry.file)).expect("a fixture");
        assert_eq!(
            DigestAlgorithm::Sha256.hash(&bytes),
            entry.sha256,
            "{} has changed",
            entry.file
        );
        assert!(
            bytes.first() != Some(&b'\n')
                && !bytes.windows(2).any(|w| w[1] == b'\n' && w[0] != b'\r'),
            "{} has a bare LF",
            entry.file
        );
    }
}

#[test]
fn every_description_round_trips() {
    for entry in manifest() {
        let bytes = fs::read(fixtures().join(&entry.file)).expect("a fixture");
        let description = parse(&bytes).expect("parses");
        assert_eq!(
            String::from_utf8(description.to_bytes()).expect("utf-8"),
            String::from_utf8(bytes).expect("utf-8"),
            "{}",
            entry.file
        );
    }
}

#[test]
fn every_example_answer_is_a_legal_answer() {
    for exchange in all_exchanges() {
        if let Err(why) = check_answer(&exchange.offer, &exchange.answer) {
            panic!("§{} round {}: {why}", exchange.section, exchange.round);
        }
    }
}

#[test]
fn every_later_exchange_is_a_legal_modification_of_the_one_before() {
    let exchanges = all_exchanges();
    for pair in exchanges.windows(2) {
        let [before, after] = pair else {
            continue;
        };
        if before.section != after.section {
            continue;
        }
        for (what, previous, next) in [
            ("offer", &before.offer, &after.offer),
            ("answer", &before.answer, &after.answer),
        ] {
            if let Err(why) = check_modification(previous, next) {
                panic!("§{} round {} {what}: {why}", after.section, after.round);
            }
        }
    }
}

#[test]
fn the_stack_answers_every_offer_as_the_example_does() {
    for exchange in all_exchanges() {
        let built = rebuild(&exchange);
        let context = format!("§{} round {}", exchange.section, exchange.round);
        check_answer(&exchange.offer, &built).unwrap_or_else(|why| panic!("{context}: {why}"));

        assert_eq!(built.origin, exchange.answer.origin, "{context}");
        assert_eq!(built.timing, exchange.answer.timing, "{context}");
        assert_eq!(built.media.len(), exchange.answer.media.len(), "{context}");
        for (index, (ours, theirs)) in built.media.iter().zip(&exchange.answer.media).enumerate() {
            let context = format!("{context} stream {index}");
            assert_eq!(ours.media, theirs.media, "{context}");
            assert_eq!(ours.port, theirs.port, "{context}");
            assert_eq!(ours.proto, theirs.proto, "{context}");
            if theirs.is_rejected() {
                continue;
            }
            assert_eq!(ours.formats, theirs.formats, "{context}");
            assert_eq!(
                built.direction_of(ours),
                exchange.answer.direction_of(theirs),
                "{context}"
            );
            for payload in theirs.payload_types() {
                assert_eq!(ours.rtpmap(payload), theirs.rtpmap(payload), "{context}");
            }
        }
    }
}

#[test]
fn a_bad_answer_is_told_apart_from_a_good_one() {
    // the checks above are only worth something if they can fail
    let exchange = exchanges("2.4").into_iter().next().expect("§2.4");
    assert_eq!(check_answer(&exchange.offer, &exchange.answer), Ok(()));

    let mut extra = exchange.answer.clone();
    extra.media.push(extra.media[0].clone());
    assert!(
        check_answer(&exchange.offer, &extra).is_err(),
        "a stream too many"
    );

    let mut foreign = exchange.answer.clone();
    foreign.media[0].formats = vec!["8".to_owned()];
    assert!(
        check_answer(&exchange.offer, &foreign).is_err(),
        "no common format"
    );

    // the offer's second stream is sendonly, so the answer cannot send on it
    let mut sending = exchange.answer.clone();
    sending.media[1]
        .attributes
        .retain(|a| a.direction().is_none());
    assert!(
        check_answer(&exchange.offer, &sending).is_err(),
        "sendrecv to sendonly"
    );

    let mut bumped = exchange.answer.clone();
    bumped.origin.version += 2;
    assert!(
        check_modification(&exchange.answer, &bumped).is_err(),
        "version jumps"
    );
    let mut fewer = exchange.offer.clone();
    fewer.origin.version += 1;
    fewer.media.pop();
    assert!(
        check_modification(&exchange.offer, &fewer).is_err(),
        "a stream removed"
    );
}

/// §2.1: several codecs offered, one of each kind kept. "Alice and Bob may
/// send only PCMU audio and MPV video."
#[test]
fn audio_and_video_1() {
    let exchange = exchanges("2.1").into_iter().next().expect("§2.1");
    assert_eq!(exchange.answer.media[0].formats, ["0"]);
    assert_eq!(exchange.answer.media[1].formats, ["32"]);
    let plans = plans(&exchange);
    assert_eq!(
        settled(plans[0].as_ref()),
        ("PCMU".to_owned(), Direction::SendRecv)
    );
    assert_eq!(
        settled(plans[1].as_ref()),
        ("MPV".to_owned(), Direction::SendRecv)
    );
}

/// §2.2: video refused, two audio codecs kept, then a second exchange in
/// which the offerer narrows audio to the one codec it will use.
#[test]
fn audio_and_video_2() {
    let rounds = exchanges("2.2");
    assert_eq!(rounds.len(), 2);

    let first = &rounds[0];
    assert_eq!(first.answer.media[0].formats, ["0", "8"]);
    assert!(first.answer.media[1].is_rejected());
    let plans = plans(first);
    // the answerer's order of preference decides what the offerer sends
    assert_eq!(settled(plans[0].as_ref()).0, "PCMU");
    assert!(plans[1].is_none(), "video was refused");

    let second = &rounds[1];
    assert_eq!(second.offer.media[0].formats, ["0"]);
    assert!(
        second.offer.media[1].is_rejected(),
        "a refused stream stays in the offer"
    );
    let plans = self::plans(second);
    assert_eq!(settled(plans[0].as_ref()).0, "PCMU");
    assert!(plans[1].is_none());
}

/// §2.4: two audio streams, the second carrying only telephone-event and
/// sent one way.
#[test]
fn two_audio_streams() {
    let exchange = exchanges("2.4").into_iter().next().expect("§2.4");
    let offer_events = &exchange.offer.media[1];
    assert_eq!(
        offer_events.rtpmap(98).expect("98").encoding,
        "telephone-event"
    );
    assert_eq!(
        exchange.offer.direction_of(offer_events),
        Direction::SendOnly
    );
    assert_eq!(
        exchange.answer.direction_of(&exchange.answer.media[1]),
        Direction::RecvOnly
    );

    assert_eq!(
        settled(plan(&exchange, 0).expect("audio").as_ref()),
        ("iLBC".to_owned(), Direction::SendRecv)
    );
    // A stream of nothing but named events is legal (the events are the
    // payload), but a MediaPlan holds exactly one codec and RFC 4733 events
    // are deliberately not one, so the planner has nothing to put there.
    // This pins that gap; see the RFC 4317 README.
    assert_eq!(plan(&exchange, 1), Err(SdpError::NoCodec { stream: 1 }));
}

/// §3.1: hold with `sendonly`, answered `recvonly`, then taken off hold.
#[test]
fn hold_and_unhold_1() {
    let rounds = exchanges("3.1");
    assert_eq!(rounds.len(), 3);
    let directions: Vec<Direction> = rounds
        .iter()
        .map(|exchange| settled(plans(exchange)[0].as_ref()).1)
        .collect();
    assert_eq!(
        directions,
        [
            Direction::SendRecv,
            Direction::SendOnly,
            Direction::SendRecv
        ],
        "talking, on hold (Alice still sends music), talking again"
    );

    // and the stack, asked to answer the hold offer as a phone that wants to
    // keep talking, says recvonly and nothing more
    let hold = &rounds[1];
    let built = hold
        .offer
        .answer(
            hold.answer.origin.clone(),
            hold.answer.connection.clone().expect("c="),
            &[StreamAnswer::Accept(
                AcceptedStream::new(49_172, vec!["97".to_owned()])
                    .with_direction(Direction::SendRecv),
            )],
        )
        .expect("an answer");
    assert_eq!(built.direction_of(&built.media[0]), Direction::RecvOnly);
}

/// §4.1: a second audio stream added to a session that had one.
#[test]
fn second_audio_stream_added() {
    let rounds = exchanges("4.1");
    assert_eq!(rounds.len(), 2);
    assert_eq!(rounds[0].offer.media.len(), 1);
    assert_eq!(rounds[1].offer.media.len(), 2);
    assert_eq!(rounds[1].answer.media.len(), 2);
    // the stream that was there is where it was
    assert_eq!(rounds[1].offer.media[0].port, rounds[0].offer.media[0].port);
    assert_eq!(
        rounds[1].answer.media[0].port,
        rounds[0].answer.media[0].port
    );
    assert_eq!(
        settled(plan(&rounds[1], 0).expect("audio").as_ref()).0,
        "iLBC"
    );
    // the added stream is events only; see two_audio_streams
    assert_eq!(plan(&rounds[1], 1), Err(SdpError::NoCodec { stream: 1 }));
}

/// §4.3: a video stream deleted, by setting its port to zero rather than by
/// dropping its `m=` line.
#[test]
fn audio_and_video_then_video_deleted() {
    let rounds = exchanges("4.3");
    assert_eq!(rounds.len(), 2);
    let before = plans(&rounds[0]);
    assert_eq!(settled(before[1].as_ref()).0, "H261");

    let after = plans(&rounds[1]);
    assert_eq!(rounds[1].offer.media.len(), 2, "the m= line stays");
    assert!(rounds[1].offer.media[1].is_rejected());
    assert!(rounds[1].answer.media[1].is_rejected());
    assert_eq!(settled(after[0].as_ref()).0, "PCMU");
    assert!(after[1].is_none(), "video is gone");
}
