// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The RFC 4317 offer/answer examples, run against the SDP layer.
//!
//! `fixtures/rfc4317/manifest.toml` lists every description of every section
//! in the order the RFC gives it: an offer, then the answer to it, then
//! (where the section goes on) the next offer of the same session and its
//! answer. The second offer is not always the first offerer's: in several
//! sections the answerer makes it. Each exchange is held to three things:
//!
//! - the example's answer is a legal answer to the example's offer under
//!   RFC 3264 §6, and every description a party sends after its first is a
//!   legal modification of that party's previous one under §8;
//! - [`SessionDescription::answer`], told only which streams to take and
//!   with which formats, produces an answer that agrees with the example's
//!   stream for stream;
//! - [`SessionDescription::media_plans`] reads the two descriptions and
//!   settles on the codec and direction the section says it should.
//!
//! The examples name their hosts (`host.atlanta.example.com`), which a
//! sans-I/O core does not resolve. The last check substitutes documentation
//! addresses for every `c=` that names a host, and nothing else; the
//! `0.0.0.0` of §5.2 and §5.3 stays what it is.

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
    AcceptedStream, Connection, Direction, MediaDescription, MediaPlan, SdpError,
    SessionDescription, StreamAnswer, parse,
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

impl Exchange {
    fn context(&self) -> String {
        format!("§{} round {}", self.section, self.round)
    }
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

/// The exchanges whose example answer RFC 3264 §6.1 does not allow, with
/// what the check says about it. RFC 4317 has no errata; these are the
/// RFC's own examples as printed, and the checks below prove they can tell
/// them from the rest.
const NOT_LEGAL_ANSWERS: &[(&str, &str, &str)] = &[(
    // "If a stream is offered as sendonly, the corresponding stream MUST be
    // marked as recvonly or inactive in the answer": Bob's second offer
    // holds the first stream sendonly, and Alice "responds with identical
    // SDP to the initial offer", which leaves it sendrecv
    "3.2",
    "2",
    "stream 0: sendrecv answers an offer of sendonly",
)];

fn not_legal(exchange: &Exchange) -> Option<&'static str> {
    NOT_LEGAL_ANSWERS
        .iter()
        .find(|(section, round, _)| *section == exchange.section && *round == exchange.round)
        .map(|(_, _, why)| *why)
}

/// Whether `format` of `answered` names a codec `offered` also lists: the
/// same payload type, or a dynamic one mapped to the same encoding, clock
/// rate and channels. RFC 3264 §6.1 has the answerer keep the offer's
/// number for a codec only as a SHOULD, and §2.3 of RFC 4317 renumbers.
fn in_offer(offered: &MediaDescription, answered: &MediaDescription, format: &str) -> bool {
    if offered.formats.iter().any(|f| f == format) {
        return true;
    }
    let Ok(payload) = format.parse::<u8>() else {
        return false;
    };
    let Some(mapping) = answered.rtpmap(payload) else {
        return false;
    };
    payload >= 96
        && offered.payload_types().any(|theirs| {
            offered.rtpmap(theirs).is_some_and(|m| {
                m.encoding.eq_ignore_ascii_case(&mapping.encoding)
                    && m.clock_rate == mapping.clock_rate
                    && m.parameters == mapping.parameters
            })
        })
}

/// Whether `answer` is a legal answer to `offer` under RFC 3264 §6, and
/// why not when it is not.
fn check_answer(offer: &SessionDescription, answer: &SessionDescription) -> Result<(), String> {
    // "the answer MUST contain exactly the same number of "m=" lines as the
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
        if !answered
            .formats
            .iter()
            .any(|format| in_offer(offered, answered, format))
        {
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

/// Whether `next` is a legal successor, under RFC 3264 §8, of `previous`,
/// the last description the same party sent in the same session.
fn check_modification(
    previous: &SessionDescription,
    next: &SessionDescription,
) -> Result<(), String> {
    // "the "o=" line of the new SDP MUST be identical to that in the
    // previous SDP, except that the version in the origin field MUST
    // increment by one from the previous SDP"
    let (a, b) = (&previous.origin, &next.origin);
    if a.username != b.username
        || a.session_id != b.session_id
        || a.network != b.network
        || a.address_type != b.address_type
        || a.address != b.address
    {
        return Err("the origin changed beyond its version".to_owned());
    }
    // "If the version in the origin line does not increment, the SDP MUST
    // be identical to the SDP with that version number."
    if b.version == a.version {
        if previous.to_bytes() != next.to_bytes() {
            return Err(format!("version {} kept for a changed SDP", b.version));
        }
    } else if b.version != a.version + 1 {
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
/// refused, on the same ports and addresses, with the same formats in the
/// same order, and the direction the example's answerer wrote. A format the
/// example renumbered is asked for under the offer's number, which is what
/// the builder writes and what RFC 3264 §6.1 recommends.
fn rebuild(exchange: &Exchange) -> SessionDescription {
    let streams: Vec<StreamAnswer> = exchange
        .offer
        .media
        .iter()
        .zip(&exchange.answer.media)
        .map(|(offered, media)| {
            if media.is_rejected() {
                StreamAnswer::Reject
            } else {
                let mut accepted = AcceptedStream::new(media.port, offer_numbers(offered, media))
                    .with_direction(exchange.answer.direction_of(media));
                accepted.connection.clone_from(&media.connection);
                StreamAnswer::Accept(accepted)
            }
        })
        .collect();
    let connection = exchange.answer.connection.clone().expect("a session c=");
    exchange
        .offer
        .answer(exchange.answer.origin.clone(), connection, &streams)
        .unwrap_or_else(|e| panic!("{}: the stack would not answer: {e}", exchange.context()))
}

/// The answer's formats, each under the number the offer gave its codec.
fn offer_numbers(offered: &MediaDescription, answered: &MediaDescription) -> Vec<String> {
    answered
        .formats
        .iter()
        .map(|format| {
            if offered.formats.contains(format) {
                return format.clone();
            }
            let mapping = format.parse().ok().and_then(|p| answered.rtpmap(p));
            offered
                .payload_types()
                .find(|&p| {
                    offered.rtpmap(p).is_some_and(|m| {
                        mapping.as_ref().is_some_and(|mapping| {
                            m.encoding.eq_ignore_ascii_case(&mapping.encoding)
                                && m.clock_rate == mapping.clock_rate
                        })
                    })
                })
                .map_or_else(|| format.clone(), |p| p.to_string())
        })
        .collect()
}

/// A `c=` naming a host, given a documentation address; any other left as
/// it is.
fn resolved(connection: &mut Option<Connection>, address: Ipv4Addr) {
    if connection.as_ref().is_some_and(|c| c.ip().is_none()) {
        *connection = Some(Connection::new(IpAddr::V4(address)));
    }
}

/// A description with every host it names given an address: the session's
/// `c=` gets `session`, a stream's own `c=` `192.0.2.100` plus its index.
fn addressed(description: &SessionDescription, session: Ipv4Addr) -> SessionDescription {
    let mut description = description.clone();
    resolved(&mut description.connection, session);
    for (index, media) in description.media.iter_mut().enumerate() {
        let host = Ipv4Addr::new(192, 0, 2, 100 + u8::try_from(index).expect("few streams"));
        resolved(&mut media.connection, host);
    }
    description
}

/// The negotiation of one stream, as the offerer sees it.
fn plan(exchange: &Exchange, stream: usize) -> Result<Option<MediaPlan>, SdpError> {
    let offer = addressed(&exchange.offer, Ipv4Addr::new(192, 0, 2, 1));
    let answer = addressed(&exchange.answer, Ipv4Addr::new(192, 0, 2, 2));
    offer.media_plan(&answer, stream)
}

/// The negotiation of every stream, each of which has to settle, as the
/// offerer sees it.
fn plans(exchange: &Exchange) -> Vec<Option<MediaPlan>> {
    let offer = addressed(&exchange.offer, Ipv4Addr::new(192, 0, 2, 1));
    let answer = addressed(&exchange.answer, Ipv4Addr::new(192, 0, 2, 2));
    offer
        .media_plans(&answer)
        .unwrap_or_else(|e| panic!("{}: {e}", exchange.context()))
}

/// The same, as the answerer sees it.
fn answerer_plans(exchange: &Exchange) -> Vec<Option<MediaPlan>> {
    let offer = addressed(&exchange.offer, Ipv4Addr::new(192, 0, 2, 1));
    let answer = addressed(&exchange.answer, Ipv4Addr::new(192, 0, 2, 2));
    answer
        .media_plans(&offer)
        .unwrap_or_else(|e| panic!("{}: {e}", exchange.context()))
}

/// The codec and direction of a stream the plan kept.
fn settled(plan: Option<&MediaPlan>) -> (String, Direction) {
    let plan = plan.expect("the stream is up");
    (plan.codec.rtpmap.encoding.clone(), plan.direction)
}

#[test]
fn every_file_is_the_one_the_manifest_hashed() {
    let entries = manifest();
    assert_eq!(entries.len(), 54, "the manifest lost a description");
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
fn every_section_of_the_rfc_is_here() {
    let mut sections: Vec<String> = manifest().into_iter().map(|e| e.section).collect();
    sections.dedup();
    assert_eq!(
        sections,
        [
            "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8", "3.1", "3.2", "4.1", "4.2",
            "4.3", "5.1", "5.2", "5.3"
        ]
    );
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
fn every_example_answer_is_a_legal_answer_but_the_ones_known_not_to_be() {
    for exchange in all_exchanges() {
        let result = check_answer(&exchange.offer, &exchange.answer);
        match not_legal(&exchange) {
            None => {
                if let Err(why) = result {
                    panic!("{}: {why}", exchange.context());
                }
            }
            Some(expected) => {
                assert_eq!(result, Err(expected.to_owned()), "{}", exchange.context());
            }
        }
    }
}

#[test]
fn every_later_description_is_a_legal_modification_of_the_same_partys_last() {
    let mut checked = 0;
    let exchanges = all_exchanges();
    for (index, exchange) in exchanges.iter().enumerate() {
        let earlier: Vec<&SessionDescription> = exchanges[..index]
            .iter()
            .filter(|e| e.section == exchange.section)
            .flat_map(|e| [&e.offer, &e.answer])
            .collect();
        for next in [&exchange.offer, &exchange.answer] {
            let previous = earlier
                .iter()
                .rev()
                .find(|d| d.origin.username == next.origin.username);
            if let Some(previous) = previous {
                if let Err(why) = check_modification(previous, next) {
                    panic!("{} ({}): {why}", exchange.context(), next.origin.username);
                }
                checked += 1;
            }
        }
    }
    // two per section that goes on to a second exchange
    assert_eq!(checked, 2 * 11);
}

#[test]
fn the_stack_answers_every_offer_as_the_example_does() {
    for exchange in all_exchanges() {
        if not_legal(&exchange).is_some() {
            // the builder narrows the direction to what the offer allows,
            // which is exactly where the example does not
            continue;
        }
        let built = rebuild(&exchange);
        let context = exchange.context();
        check_answer(&exchange.offer, &built).unwrap_or_else(|why| panic!("{context}: {why}"));

        assert_eq!(built.origin, exchange.answer.origin, "{context}");
        assert_eq!(built.timing, exchange.answer.timing, "{context}");
        assert_eq!(built.media.len(), exchange.answer.media.len(), "{context}");
        for (index, ((ours, theirs), offered)) in built
            .media
            .iter()
            .zip(&exchange.answer.media)
            .zip(&exchange.offer.media)
            .enumerate()
        {
            let context = format!("{context} stream {index}");
            assert_eq!(ours.media, theirs.media, "{context}");
            assert_eq!(ours.port, theirs.port, "{context}");
            assert_eq!(ours.proto, theirs.proto, "{context}");
            if theirs.is_rejected() {
                continue;
            }
            assert_eq!(ours.formats, offer_numbers(offered, theirs), "{context}");
            assert_eq!(ours.connection, theirs.connection, "{context}");
            assert_eq!(
                built.direction_of(ours),
                exchange.answer.direction_of(theirs),
                "{context}"
            );
            for (mine, example) in ours.payload_types().zip(theirs.payload_types()) {
                let (mine, example) = (
                    ours.rtpmap(mine).expect("an rtpmap"),
                    theirs.rtpmap(example).expect("an rtpmap"),
                );
                assert_eq!(
                    (mine.encoding, mine.clock_rate),
                    (example.encoding, example.clock_rate),
                    "{context}"
                );
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
    let mut changed = exchange.answer.clone();
    changed.media[0].port += 2;
    assert!(
        check_modification(&exchange.answer, &changed).is_err(),
        "a change under the same version"
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
    assert_eq!(settled(plans[0].as_ref()).0, "PCMU");
    assert!(plans[1].is_none(), "video was refused");

    let second = &rounds[1];
    assert_eq!(second.offer.media[0].formats, ["0"]);
    // "The declined video stream still present in the second exchange of
    // SDP with ports set to zero."
    assert!(second.offer.media[1].is_rejected());
    assert!(second.answer.media[1].is_rejected());
    let plans = self::plans(second);
    assert_eq!(settled(plans[0].as_ref()).0, "PCMU");
    assert!(plans[1].is_none());
}

/// §2.3: iLBC offered as 97 and answered as 99 ("change of dynamic payload
/// type from 97 to 99 between the offer and the answer is OK since the same
/// codec is referenced"), H261 for video.
#[test]
fn audio_and_video_3() {
    let exchange = exchanges("2.3").into_iter().next().expect("§2.3");
    assert_eq!(
        exchange.offer.media[0].rtpmap(97).expect("97").encoding,
        "iLBC"
    );
    assert_eq!(
        exchange.answer.media[0].rtpmap(99).expect("99").encoding,
        "iLBC"
    );
    assert_eq!(
        settled(plan(&exchange, 1).expect("video").as_ref()),
        ("H261".to_owned(), Direction::SendRecv)
    );
    // RFC 3264 §6.1 makes the same number only a SHOULD, and the planner
    // matches a renumbered dynamic type by what it maps to. Each end sends
    // with the other's number and takes its own (§5.1): Alice sends iLBC as
    // Bob's 99 and receives it as her own 97, and Bob the other way round.
    let alice = plan(&exchange, 0).expect("audio").expect("up");
    assert_eq!(alice.codec.rtpmap.encoding, "iLBC");
    assert_eq!((alice.codec.payload(), alice.codec_in), (99, 97));
    let bob = answerer_plans(&exchange)
        .into_iter()
        .next()
        .flatten()
        .expect("up");
    assert_eq!(bob.codec.rtpmap.encoding, "iLBC");
    assert_eq!((bob.codec.payload(), bob.codec_in), (97, 99));
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

/// §2.5: Bob moves his media to a new address in a second offer of his own;
/// Alice answers with the SDP she sent first, version and all.
#[test]
fn audio_and_video_4() {
    let rounds = exchanges("2.5");
    assert_eq!(rounds.len(), 2);
    let second = &rounds[1];
    assert_eq!(second.offer.origin.username, "bob");
    assert_eq!(
        second.offer.connection.as_ref().expect("c=").address,
        "newhost.biloxi.example.com"
    );
    assert_eq!(second.answer.to_bytes(), rounds[0].offer.to_bytes());
    // Alice now sends to the ports Bob moved to
    let alice = answerer_plans(second);
    let ports: Vec<u16> = alice
        .iter()
        .map(|p| p.as_ref().expect("up").remote.port())
        .collect();
    assert_eq!(ports, [49_178, 49_188]);
}

/// §2.6: two audio streams offered as alternatives; Bob declines the first
/// and takes the second, iLBC with telephone-event beside it.
#[test]
fn audio_only_1() {
    let exchange = exchanges("2.6").into_iter().next().expect("§2.6");
    let plans = plans(&exchange);
    assert!(plans[0].is_none(), "the PCMU stream was declined");
    let events = plans[1].as_ref().expect("the second stream is up");
    assert_eq!(events.codec.rtpmap.encoding, "iLBC");
    assert_eq!(events.dtmf, Some(101));
}

/// §2.7: a second video codec added in the second exchange, which Bob takes
/// too.
#[test]
fn audio_and_video_5() {
    let rounds = exchanges("2.7");
    assert_eq!(rounds.len(), 2);
    assert_eq!(rounds[0].answer.media[1].formats, ["31"]);
    assert_eq!(rounds[1].answer.media[1].formats, ["31", "32"]);
    assert_eq!(settled(plans(&rounds[1])[1].as_ref()).0, "H261");
}

/// §2.8: the answerer wants the video on another host than the audio, with
/// a `c=` of its own in the video stream.
#[test]
fn audio_and_video_6() {
    let exchange = exchanges("2.8").into_iter().next().expect("§2.8");
    let video = &exchange.answer.media[1];
    assert_eq!(
        video.connection.as_ref().expect("a media c=").address,
        "otherhost.biloxi.example.com"
    );
    let plans = plans(&exchange);
    let audio = plans[0].as_ref().expect("audio");
    let video = plans[1].as_ref().expect("video");
    assert_eq!(audio.remote.ip(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)));
    assert_eq!(video.remote.ip(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 101)));
}

/// §3.1: Bob answers the call on hold (`sendonly`, from a placeholder
/// host), then takes Alice off hold with an offer of his own.
#[test]
fn hold_and_unhold_1() {
    let rounds = exchanges("3.1");
    assert_eq!(rounds.len(), 2);
    // Alice's view: on hold, she only receives
    assert_eq!(
        settled(plans(&rounds[0])[0].as_ref()),
        ("iLBC".to_owned(), Direction::RecvOnly)
    );
    // then Bob offers, and both directions flow again
    assert_eq!(rounds[1].offer.origin.username, "bob");
    assert_eq!(
        settled(plans(&rounds[1])[0].as_ref()),
        ("iLBC".to_owned(), Direction::SendRecv)
    );
    // "Alice changes port number in the second exchange"
    assert_eq!(rounds[1].answer.media[0].port, 49_178);
}

/// §3.2: of two streams, Bob holds the audio and leaves the events stream
/// as it was.
#[test]
fn hold_with_two_streams() {
    let rounds = exchanges("3.2");
    assert_eq!(rounds.len(), 2);
    let bob = &rounds[1].offer;
    assert_eq!(bob.direction_of(&bob.media[0]), Direction::SendOnly);
    assert_eq!(bob.direction_of(&bob.media[1]), Direction::RecvOnly);
    // Bob, holding, only sends on the audio stream whatever Alice wrote back
    assert_eq!(
        settled(plan(&rounds[1], 0).expect("audio").as_ref()),
        ("iLBC".to_owned(), Direction::SendOnly)
    );
}

/// §4.1: Bob's media server adds a receive-only telephone-event stream from
/// a host of its own.
#[test]
fn second_audio_stream_added() {
    let rounds = exchanges("4.1");
    assert_eq!(rounds.len(), 2);
    assert_eq!(rounds[0].offer.media.len(), 1);
    assert_eq!(rounds[1].offer.media.len(), 2);
    assert_eq!(rounds[1].offer.origin.username, "bob");
    assert_eq!(
        rounds[1].offer.media[1]
            .connection
            .as_ref()
            .expect("a media c=")
            .address,
        "mediaserver.biloxi.example.com"
    );
    assert_eq!(
        settled(plan(&rounds[1], 0).expect("audio").as_ref()).0,
        "iLBC"
    );
    // the added stream is events only; see two_audio_streams
    assert_eq!(plan(&rounds[1], 1), Err(SdpError::NoCodec { stream: 1 }));
}

/// §4.2: a video stream added to an audio call by the offerer.
#[test]
fn audio_then_video_added() {
    let rounds = exchanges("4.2");
    assert_eq!(rounds.len(), 2);
    assert_eq!(rounds[0].offer.media.len(), 1);
    let plans = plans(&rounds[1]);
    assert_eq!(settled(plans[0].as_ref()).0, "PCMU");
    assert_eq!(settled(plans[1].as_ref()).0, "H261");
}

/// §4.3: Bob deletes the video stream by setting its port to zero in an
/// offer of his own, keeping its `m=` line.
#[test]
fn audio_and_video_then_video_deleted() {
    let rounds = exchanges("4.3");
    assert_eq!(rounds.len(), 2);
    assert_eq!(settled(plans(&rounds[0])[1].as_ref()).0, "H261");

    let second = &rounds[1];
    assert_eq!(second.offer.origin.username, "bob");
    assert_eq!(second.offer.media.len(), 2, "the m= line stays");
    assert!(second.offer.media[1].is_rejected());
    assert!(second.answer.media[1].is_rejected());
    let after = plans(second);
    assert_eq!(settled(after[0].as_ref()).0, "iLBC");
    assert!(after[1].is_none(), "video is gone");
}

/// §5.1: an offer with no media at all, answered with none, then audio.
#[test]
fn no_media_then_audio_added() {
    let rounds = exchanges("5.1");
    assert_eq!(rounds.len(), 2);
    assert!(rounds[0].offer.media.is_empty());
    assert!(plans(&rounds[0]).is_empty());
    assert_eq!(settled(plans(&rounds[1])[0].as_ref()).0, "iLBC");
}

/// §5.2: Alice offers `c=0.0.0.0`, so Bob must not send to her, then gives
/// her real address.
#[test]
fn hold_and_unhold_2() {
    let rounds = exchanges("5.2");
    assert_eq!(rounds.len(), 2);
    let bob = answerer_plans(&rounds[0]);
    assert_eq!(
        settled(bob[0].as_ref()),
        ("iLBC".to_owned(), Direction::RecvOnly),
        "Bob sends nothing into 0.0.0.0"
    );
    let bob = answerer_plans(&rounds[1]);
    assert_eq!(settled(bob[0].as_ref()).1, Direction::SendRecv);
}

/// §5.3: Bob answers with `c=0.0.0.0`, so Alice must not send to him, then
/// offers his real address himself.
#[test]
fn hold_and_unhold_3() {
    let rounds = exchanges("5.3");
    assert_eq!(rounds.len(), 2);
    assert_eq!(
        settled(plans(&rounds[0])[0].as_ref()),
        ("iLBC".to_owned(), Direction::RecvOnly),
        "Alice sends nothing into 0.0.0.0"
    );
    assert_eq!(rounds[1].offer.origin.username, "bob");
    assert_eq!(
        settled(plans(&rounds[1])[0].as_ref()).1,
        Direction::SendRecv
    );
}
