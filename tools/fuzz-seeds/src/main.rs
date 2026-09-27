// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The seed corpus the fuzz targets start from, written out of this
//! repository's own writers.
//!
//! A public clone that gets seventeen targets and no corpus gets seventeen
//! targets that begin from the empty input, and a coverage-guided fuzzer
//! spends its first hours rediscovering that a SIP message starts with a
//! method name. So the seeds are committed -- and because they are committed
//! they are bytes in a repository whose provenance has to be sayable, which
//! is what this program is for.
//!
//! Every seed here is produced by the library's own builders and encoders, or
//! is written out as text in this file, or -- in the one case of `replay` --
//! is a file already in `fixtures/`, which is this project's own. Nothing
//! comes from outside the tree, and nothing is a capture of anyone's traffic.
//! Addresses are from the ranges reserved for documentation: `192.0.2.0/24`
//! (RFC 5737) and `example.com` (RFC 2606).
//!
//! Every seed but one is handed to the same reader its target hands it to
//! before it is written -- the framer through the framer, the protected run
//! through an unprotector with the target's own key, and so on -- so a seed
//! that is not the thing it claims to be fails here rather than sitting in
//! the corpus doing nothing. The exception is `builder`, whose input is not
//! a message at all: the target cuts it into the five field values a caller
//! controls, so what is checked for that one is the cut, which is the thing
//! about it that can be wrong.
//!
//! This program owns the whole of `fuzz/corpus/` except its `README.md`, and
//! sweeps it: what it does not write, it removes. A seed dropped from here
//! and left on disk would otherwise stay in the tree for good, since the
//! check in `scripts/check.sh` asks whether every target has a directory and
//! every directory a target, and a stale file inside a live directory
//! answers yes.
//!
//! ```sh
//! cargo run -p sipral-fuzz-seeds            # rewrite fuzz/corpus/
//! cargo run -p sipral-fuzz-seeds -- <dir>  # write somewhere else instead
//! ```

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use sipral_core::msg::{
    HeaderName, Method, ParseMode, ParseScratch, RequestBuilder, ResponseBuilder, StatusCode,
    StreamFramer, parse,
};
use sipral_core::replay::Recording;
use sipral_core::sdp::{self, Crypto};
use sipral_dtls::handshake::{
    HandshakeMessage, HandshakeType, HelloVerifyRequest, fragments as dtls_fragments,
};
use sipral_dtls::keys::EcdsaKey;
use sipral_dtls::record::{ContentType, ProtocolVersion, records as dtls_records};
use sipral_dtls::x509::{Certificate as DtlsCertificate, CertificateParams};
use sipral_dtls::{Config as DtlsConfig, Connection, Random, Role, State};
use sipral_headless::{ControlMessage, FrameDecoder, write_frame};
use sipral_nat::stun::{
    AttributeType, Class, Message, MessageBuilder, Method as StunMethod, TransactionId,
};
use sipral_nat::turn::{ChannelData, ChannelNumber, StreamFraming, Transport};
use sipral_rtp::srtp::{KEY, Master, Policy, Protector, SALT, SrtpError, Suite, Unprotector};
use sipral_rtp::{
    CNAME, ChunkBuilder, CompoundBuilder, CompoundPacket, GoodbyeBuilder, JitterBufferAdaptive,
    PacketBuilder, PacketLossConcealment, ReceiverReportBuilder, RtpHeader, RtpPacket, RxConfig,
    SdesItem, SenderInfo, SenderOrReceiver, SenderReportBuilder, SourceDescriptionBuilder,
    UNAVAILABLE, VoipMetricsBlock, XrPacketBuilder,
};
use sipral_ua::dtmf::parse_info;
use sipral_ua::{DialogInfo, MessageSummary};

/// Something this program will not write out, because it is not what it says
/// it is.
struct Wrong(String);

impl std::fmt::Display for Wrong {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(&self.0)
    }
}

/// One seed: the name it is filed under, and the bytes.
type Seed = (&'static str, Vec<u8>);

/// Where the repository is, whatever directory this was started from.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// The fixed identity every seed that needs one is built with. None of it is
/// a secret and none of it is anybody's: the addresses are RFC 5737's and the
/// names are RFC 2606's.
const SSRC: u32 = 0x1234_5678;
const DTMF_PAYLOAD_TYPE: u8 = 101;

// ---------------------------------------------------------------- SIP

/// One INVITE with a description in it, as the builder writes one.
fn invite() -> Result<Vec<u8>, Wrong> {
    let body = offer();
    let built = RequestBuilder::new(Method::Invite, b"sip:bob@example.com")
        .via(b"SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds")
        .max_forwards(70)
        .from(b"<sip:alice@example.com>;tag=1928301774")
        .to(b"<sip:bob@example.com>")
        .call_id(b"a84b4c76e66710@192.0.2.1")
        .cseq(314_159)
        .header(HeaderName::Contact, b"<sip:alice@192.0.2.1:5060>")
        .body(b"application/sdp", &body)
        .build()
        .map_err(|why| Wrong(format!("the INVITE seed does not build: {why:?}")))?;
    Ok(built.as_raw().as_bytes().to_vec())
}

/// A REGISTER, which is the other request a stack sends first.
fn register() -> Result<Vec<u8>, Wrong> {
    let built = RequestBuilder::new(Method::Register, b"sip:example.com")
        .via(b"SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK2d4790.1")
        .max_forwards(70)
        .from(b"<sip:alice@example.com>;tag=9fxced76sl")
        .to(b"<sip:alice@example.com>")
        .call_id(b"1j9FpLxk3uxtm8tn@192.0.2.1")
        .cseq(1)
        .header(
            HeaderName::Contact,
            b"<sip:alice@192.0.2.1:5060>;expires=3600",
        )
        .build()
        .map_err(|why| Wrong(format!("the REGISTER seed does not build: {why:?}")))?;
    Ok(built.as_raw().as_bytes().to_vec())
}

/// A 200 OK to the INVITE above, answer and all.
fn ok_response() -> Result<Vec<u8>, Wrong> {
    let raw = invite()?;
    let mut scratch = ParseScratch::new();
    let request = parse(&raw, &mut scratch, ParseMode::Strict)
        .map_err(|why| Wrong(format!("the INVITE seed does not parse back: {why:?}")))?;
    let built = ResponseBuilder::for_request(&request, StatusCode::OK)
        .to_tag(b"a6c85cf")
        .header(HeaderName::Contact, b"<sip:bob@192.0.2.4:5060>")
        .body(b"application/sdp", &answer())
        .build()
        .map_err(|why| Wrong(format!("the 200 OK seed does not build: {why:?}")))?;
    Ok(built.as_raw().as_bytes().to_vec())
}

/// The description the INVITE carries.
fn offer() -> Vec<u8> {
    let mut text = String::new();
    let _ = write!(
        text,
        "v=0\r\n\
         o=alice 2890844526 2890844526 IN IP4 192.0.2.1\r\n\
         s=-\r\n\
         c=IN IP4 192.0.2.1\r\n\
         t=0 0\r\n\
         m=audio 49170 RTP/AVP 0 8 101\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:8 PCMA/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\n\
         a=fmtp:101 0-15\r\n\
         a=sendrecv\r\n"
    );
    text.into_bytes()
}

/// The description the 200 OK carries: one codec, and the direction settled.
fn answer() -> Vec<u8> {
    let mut text = String::new();
    let _ = write!(
        text,
        "v=0\r\n\
         o=bob 2890844527 2890844527 IN IP4 192.0.2.4\r\n\
         s=-\r\n\
         c=IN IP4 192.0.2.4\r\n\
         t=0 0\r\n\
         m=audio 3456 RTP/AVP 0 101\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\n\
         a=sendrecv\r\n"
    );
    text.into_bytes()
}

/// A description with the parts a fuzzer would otherwise take hours to
/// invent: two streams, one of them rejected, and keying.
fn awkward_sdp() -> Vec<u8> {
    let mut text = String::new();
    let _ = write!(
        text,
        "v=0\r\n\
         o=- 0 0 IN IP4 192.0.2.1\r\n\
         s=-\r\n\
         t=0 0\r\n\
         m=audio 0 RTP/AVP 0\r\n\
         c=IN IP4 0.0.0.0\r\n\
         a=inactive\r\n\
         m=audio 49172 RTP/SAVP 8\r\n\
         c=IN IP4 192.0.2.1\r\n\
         a=rtpmap:8 PCMA/8000\r\n\
         a=crypto:1 AES_CM_128_HMAC_SHA1_80 \
         inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:32\r\n\
         a=recvonly\r\n\
         a=ptime:20\r\n"
    );
    text.into_bytes()
}

fn sip_seeds() -> Result<Vec<Seed>, Wrong> {
    let mut out = Vec::new();
    for (name, bytes) in [
        ("invite-with-offer", invite()?),
        ("register", register()?),
        ("ok-with-answer", ok_response()?),
    ] {
        let mut scratch = ParseScratch::new();
        parse(&bytes, &mut scratch, ParseMode::Strict)
            .map_err(|why| Wrong(format!("the {name} seed does not parse: {why:?}")))?;
        out.push((name, bytes));
    }
    Ok(out)
}

/// The framer's input is a read size and then the stream, so one seed covers
/// a message that arrives whole and one that trickles in.
fn framer_seeds() -> Result<Vec<Seed>, Wrong> {
    let request = invite()?;
    let response = ok_response()?;
    let mut whole = vec![255];
    whole.extend_from_slice(&request);
    let mut byte_at_a_time = vec![1];
    byte_at_a_time.extend_from_slice(&response);
    let mut two_in_a_row = vec![64];
    two_in_a_row.extend_from_slice(&request);
    two_in_a_row.extend_from_slice(&response);
    let out = vec![
        ("invite-whole", whole),
        ("ok-one-byte-at-a-time", byte_at_a_time),
        ("two-messages-in-one-read", two_in_a_row),
    ];
    for ((name, bytes), messages) in out.iter().zip([1, 1, 2]) {
        through_framer(name, bytes, messages)?;
    }
    Ok(out)
}

/// The framer's bound, as `fuzz_targets/framer.rs` sets it.
const FRAMER_MAX: u32 = 8192;

/// One framer seed, walked the way the target walks it: the first octet is
/// the read size, the rest is the stream, and what comes out has to be the
/// messages that went in.
fn through_framer(name: &str, seed: &[u8], expected: usize) -> Result<(), Wrong> {
    let Some((&first, rest)) = seed.split_first() else {
        return Err(Wrong(format!("the {name} seed has no read size in front")));
    };
    let chunk = usize::from(first).max(1);
    let mut framer = StreamFramer::new(FRAMER_MAX);
    let mut count = 0;
    for piece in rest.chunks(chunk) {
        framer
            .push(piece)
            .map_err(|why| Wrong(format!("the {name} seed overran the framer: {why:?}")))?;
        while framer
            .next_message(ParseMode::Strict)
            .map_err(|why| Wrong(format!("the {name} seed does not frame: {why:?}")))?
            .is_some()
        {
            count += 1;
        }
    }
    if count == expected {
        return Ok(());
    }
    Err(Wrong(format!(
        "the {name} seed framed into {count} messages and it is meant to be {expected}"
    )))
}

/// The one family whose seed is not put through a parser, because its target
/// does not use one: `builder` cuts its input into five and hands the pieces
/// to `RequestBuilder` as the values a caller controls.
///
/// So what is checked here is the cut, which is the thing about this seed
/// that can be wrong. It is made with the target's own arithmetic --
/// `len / 5 + 1`, which is fifteen for seventy bytes, so four pieces of
/// fifteen and one of ten -- and every piece has to come back out as the
/// whole field it went in as, rather than as half of two.
fn builder_seeds() -> Result<Vec<Seed>, Wrong> {
    let fields: [&[u8]; 5] = [
        b"sip:bob@aa.test",
        b"<sip:a@aa.test>",
        b"<sip:b@aa.test>",
        b"abc123def456789",
        b"a subject!",
    ];
    let mut seed = Vec::new();
    for field in fields {
        seed.extend_from_slice(field);
    }
    let step = seed.len() / 5 + 1;
    let cut: Vec<&[u8]> = seed.chunks(step).collect();
    if cut.as_slice() != fields.as_slice() {
        return Err(Wrong(format!(
            "the builder seed is {} bytes and cuts into {} pieces of {step}, which are not the \
             five fields it is made of",
            seed.len(),
            cut.len()
        )));
    }
    Ok(vec![("five-fields-a-caller-controls", seed)])
}

fn sdp_seeds() -> Result<Vec<Seed>, Wrong> {
    let mut out = Vec::new();
    for (name, bytes) in [
        ("offer", offer()),
        ("answer", answer()),
        ("two-streams-one-rejected", awkward_sdp()),
        ("bare-lf-at-body-limit", bare_lf_at_body_limit()?),
        ("answer-past-body-limit", answer_past_body_limit()?),
        ("answer-past-line-limit", answer_past_line_limit()?),
    ] {
        sdp::parse(&bytes)
            .map_err(|why| Wrong(format!("the {name} seed is not a description: {why:?}")))?;
        out.push((name, bytes));
    }
    Ok(out)
}

/// A description at the parser's own body limit (`sdp::Limits::DEFAULT`),
/// every line closed with a bare LF, which `sdp::parse` tolerates -- RFC
/// 4566's own §5 asks a parser to "accept records terminated with a single
/// newline character". `to_bytes` closes every line with CRLF instead, so
/// writing this back out grows it past the limit it just satisfied: the
/// false crash 8.3.17 fixed in the target.
///
/// Built and checked here rather than by hand, so a change that stopped
/// `to_bytes` from growing the body fails this generator instead of leaving
/// a seed in the corpus that no longer proves anything.
fn bare_lf_at_body_limit() -> Result<Vec<u8>, Wrong> {
    let mut lines = vec![
        "v=0".to_owned(),
        "o=- 0 0 IN IP4 192.0.2.1".to_owned(),
        "s=-".to_owned(),
        "c=IN IP4 192.0.2.1".to_owned(),
        "t=0 0".to_owned(),
        "m=audio 49170 RTP/AVP 0".to_owned(),
        "a=rtpmap:0 PCMU/8000".to_owned(),
    ];
    let target = sdp::Limits::DEFAULT.max_body_bytes as usize;
    // filler attribute lines, one per line so each carries its own LF
    let filler = format!("a={}", "y".repeat(999));
    let mut total: usize = lines.iter().map(|line| line.len() + 1).sum();
    while total + filler.len() < target {
        lines.push(filler.clone());
        total += filler.len() + 1;
    }
    // one more, sized to land on the limit exactly
    let remainder = target - total;
    if remainder > 3 {
        lines.push(format!("a={}", "z".repeat(remainder - 3)));
    } else if remainder > 0 {
        return Err(Wrong(format!(
            "the bare-lf-at-body-limit seed is {remainder} bytes short of the limit, too few to \
             close with one more attribute line"
        )));
    }
    let mut body = lines.join("\n");
    body.push('\n');
    if body.len() != target {
        return Err(Wrong(format!(
            "the bare-lf-at-body-limit seed is {} bytes and the body limit is {target}",
            body.len()
        )));
    }
    let parsed = sdp::parse(body.as_bytes()).map_err(|why| {
        Wrong(format!(
            "the bare-lf-at-body-limit seed does not parse: {why:?}"
        ))
    })?;
    if parsed.to_bytes().len() <= target {
        return Err(Wrong(
            "the bare-lf-at-body-limit seed no longer grows past the body limit once written \
             back out, so it no longer proves 8.3.17"
                .to_owned(),
        ));
    }
    Ok(body.into_bytes())
}

/// The answer the `sdp` target builds to an offer, built the way it builds
/// it: every stream with formats accepted on port 5000 with its first one,
/// every stream without refused, from `192.0.2.1`.
fn answer_as_the_target_builds_it(
    name: &str,
    offer: &[u8],
) -> Result<sdp::SessionDescription, Wrong> {
    let offer = sdp::parse(offer)
        .map_err(|why| Wrong(format!("the {name} seed does not parse: {why:?}")))?;
    let streams: Vec<sdp::StreamAnswer> = offer
        .media
        .iter()
        .map(|media| match media.formats.first() {
            Some(format) => {
                sdp::StreamAnswer::Accept(sdp::AcceptedStream::new(5000, vec![format.clone()]))
            }
            None => sdp::StreamAnswer::Reject,
        })
        .collect();
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    offer
        .answer(
            sdp::Origin::new(1, 1, address),
            sdp::Connection::new(address),
            &streams,
        )
        .map_err(|why| Wrong(format!("the {name} seed cannot be answered: {why:?}")))
}

/// An offer with CRLF endings, within the body limit, whose answer is not.
///
/// "The "t=" line in the answer MUST equal that of the offer" (RFC 3264 §6),
/// and the `r=` lines under it go with it. So an offer made almost entirely
/// of `r=` lines is answered with all of them, under a `c=` line the offer did
/// not have and an origin longer than the offer's: the answer ends up past the
/// limit the offer was held to, with no bare LF anywhere to blame.
fn answer_past_body_limit() -> Result<Vec<u8>, Wrong> {
    let limit = sdp::Limits::DEFAULT.max_body_bytes as usize;
    let mut body = String::from("v=0\r\no=- 0 0 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\n");
    // RFC 4566 §5.10's own example of a weekly repeat
    let repeat = "r=604800 3600 0 90000\r\n";
    while body.len() + repeat.len() <= limit {
        body.push_str(repeat);
    }
    let answer = answer_as_the_target_builds_it("answer-past-body-limit", body.as_bytes())?;
    match sdp::parse(&answer.to_bytes()) {
        Err(sdp::SdpError::BodyTooLarge { .. }) => Ok(body.into_bytes()),
        other => Err(Wrong(format!(
            "the answer to the answer-past-body-limit seed is meant to be refused as too large \
             under the default limits, and reading it gave {other:?}"
        ))),
    }
}

/// An offer whose one `m=` line is exactly as long as the line limit allows,
/// with a port of one digit where the answer writes four: the answer's `m=`
/// line repeats the offer's media type ("MUST match that of the offer", RFC
/// 3264 §6.1), its transport and the format it keeps, and so ends up three
/// bytes past the limit the offer's line met.
fn answer_past_line_limit() -> Result<Vec<u8>, Wrong> {
    let limit = sdp::Limits::DEFAULT.max_line_bytes as usize;
    let start = "m=audio 9 RTP/AVP ";
    let line = format!("{start}{}", "x".repeat(limit - start.len()));
    let body = format!("v=0\r\no=- 0 0 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\n{line}\r\n");
    let answer = answer_as_the_target_builds_it("answer-past-line-limit", body.as_bytes())?;
    match sdp::parse(&answer.to_bytes()) {
        Err(sdp::SdpError::LineTooLong { .. }) => Ok(body.into_bytes()),
        other => Err(Wrong(format!(
            "the answer to the answer-past-line-limit seed is meant to be refused for a line too \
             long under the default limits, and reading it gave {other:?}"
        ))),
    }
}

fn crypto_seeds() -> Result<Vec<Seed>, Wrong> {
    let lines = [
        (
            "aes-cm-128-sha1-80",
            "1 AES_CM_128_HMAC_SHA1_80 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR",
        ),
        (
            "aes-cm-128-sha1-32-with-lifetime",
            "2 AES_CM_128_HMAC_SHA1_32 \
             inline:NzB4d1BINUAvLEw6UzF3WSJ+PSdFcGdUJShpX1Zj|2^20|1:4",
        ),
        (
            "unencrypted-srtcp",
            "3 AES_CM_128_HMAC_SHA1_80 \
             inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR UNENCRYPTED_SRTCP",
        ),
    ];
    let mut out = Vec::new();
    for (name, line) in lines {
        let parsed = Crypto::parse(line)
            .ok_or_else(|| Wrong(format!("the {name} seed is not a crypto line")))?;
        if parsed.policy().is_none() {
            return Err(Wrong(format!("the {name} seed has no policy in it")));
        }
        out.push((name, line.as_bytes().to_vec()));
    }
    Ok(out)
}

/// The one seed that is a file already in the tree: a recording this project
/// wrote, under this project's own licence.
fn replay_seeds() -> Result<Vec<Seed>, Wrong> {
    let path = root().join("fixtures/replay/registration-challenged.sipralrec");
    let text = std::fs::read_to_string(&path)
        .map_err(|why| Wrong(format!("{}: {why}", path.display())))?;
    Recording::parse(&text)
        .map_err(|why| Wrong(format!("the replay fixture does not parse: {why:?}")))?;
    Ok(vec![("registration-challenged", text.into_bytes())])
}

// ---------------------------------------------------------------- headless

/// A control channel's bytes: a read size, then frames one after another.
fn headless_seeds() -> Result<Vec<Seed>, Wrong> {
    let messages: [(&str, u8, &str); 4] = [
        (
            "session-open",
            1,
            r#"{"sample_rate":8000,"frame_duration_ms":20}"#,
        ),
        ("answer", 3, r#"{"call_id":"c1"}"#),
        ("hangup", 5, r#"{"call_id":"c1","reason":"normal"}"#),
        (
            "dtmf-send",
            7,
            r#"{"call_id":"c1","digit":"5","duration_ms":100}"#,
        ),
    ];
    let mut whole = vec![255];
    let mut out = Vec::new();
    for (name, kind, json) in messages {
        ControlMessage::decode(kind, json.as_bytes()).map_err(|why| {
            Wrong(format!(
                "the {name} control message does not decode: {why:?}"
            ))
        })?;
        let mut one = vec![255];
        write_frame(kind, json.as_bytes(), &mut one)
            .map_err(|why| Wrong(format!("the {name} frame does not write: {why:?}")))?;
        out.push((name, one));
        write_frame(kind, json.as_bytes(), &mut whole)
            .map_err(|why| Wrong(format!("the {name} frame does not write: {why:?}")))?;
    }
    // and the whole conversation, arriving one byte at a time
    let mut trickled = vec![1];
    trickled.extend_from_slice(whole.get(1..).unwrap_or_default());
    out.push(("four-frames-in-one-read", whole));
    out.push(("four-frames-one-byte-at-a-time", trickled));
    for ((name, bytes), frames) in out.iter().zip([1, 1, 1, 1, 4, 4]) {
        through_decoder(name, bytes, frames)?;
    }
    Ok(out)
}

/// The payload bound, as `fuzz_targets/headless.rs` sets it.
const HEADLESS_MAX_PAYLOAD: u16 = 65535;

/// One control-channel seed, walked the way the target walks it: the first
/// octet is the read size, then the frames, and every frame that comes out
/// has to decode into a control message.
fn through_decoder(name: &str, seed: &[u8], expected: usize) -> Result<(), Wrong> {
    let Some((&first, rest)) = seed.split_first() else {
        return Err(Wrong(format!("the {name} seed has no read size in front")));
    };
    let chunk = usize::from(first).max(1);
    let mut decoder = FrameDecoder::new(HEADLESS_MAX_PAYLOAD);
    let mut count = 0;
    for piece in rest.chunks(chunk) {
        decoder.push(piece);
        loop {
            let frame = decoder
                .next_frame()
                .map_err(|why| Wrong(format!("the {name} seed does not reassemble: {why:?}")))?;
            let Some(frame) = frame else {
                break;
            };
            ControlMessage::decode(frame.kind(), frame.payload()).map_err(|why| {
                Wrong(format!(
                    "a frame of the {name} seed does not decode: {why:?}"
                ))
            })?;
            count += 1;
        }
    }
    if count == expected {
        return Ok(());
    }
    Err(Wrong(format!(
        "the {name} seed reassembled into {count} frames and it is meant to be {expected}"
    )))
}

// ---------------------------------------------------------------- headless_media

/// `fuzz_targets/headless_media.rs`'s session byte: socket rate, codec rate
/// and frame duration as indices into its own tables, then the capacity.
fn headless_media_setup(socket: u8, codec: u8, duration: u8, capacity: u8) -> u8 {
    (socket & 3) | (codec & 3) << 2 | (duration & 3) << 4 | (capacity & 3) << 6
}

/// One of that target's operations: opcode, length octet, then the samples.
fn push_headless_op(out: &mut Vec<u8>, op: u8, samples: &[i16]) -> Result<(), Wrong> {
    out.push(op);
    push_media_chunk(out, None, samples)
}

/// A call as an agent sees one, and a codec-rate change in the middle of
/// another.
fn headless_media_seeds() -> Result<Vec<Seed>, Wrong> {
    let tone = triangle(160, 20, 12_000);

    // 16 kHz socket, 8 kHz codec, 20 ms frames, three frames a queue: the
    // caller heard for a frame and a half of the filter's own start, two
    // frames of the agent queued, one codec frame out,
    // then a barge-in and a codec frame that has to be silence
    let mut barge = vec![headless_media_setup(1, 0, 1, 3)];
    push_headless_op(&mut barge, 0, &tone)?;
    push_headless_op(&mut barge, 0, &tone)?;
    push_headless_op(&mut barge, 1, &tone)?;
    push_headless_op(&mut barge, 1, &tone)?;
    push_headless_op(&mut barge, 2, &[0; 40])?;
    push_headless_op(&mut barge, 3, &[])?;
    push_headless_op(&mut barge, 2, &[0; 40])?;
    push_headless_op(&mut barge, 5, &[])?;

    // 8 kHz socket in 30 ms frames, a codec that starts at 8 kHz and moves
    // to 48 kHz part-way through a frame the agent has not had yet
    let mut change = vec![headless_media_setup(0, 0, 2, 2)];
    push_headless_op(&mut change, 0, &tone)?;
    push_headless_op(&mut change, 4, &[0; 3])?;
    for _ in 0..4 {
        push_headless_op(&mut change, 0, &triangle(240, 120, 12_000))?;
    }
    push_headless_op(&mut change, 5, &[])?;

    let out = vec![
        ("a-call-with-a-barge-in", barge),
        ("a-codec-change-mid-call", change),
    ];
    // what each seed is for has to be what it does: the first plays a
    // frame and then, after the barge-in, none; the second hands the agent
    // a frame that straddles the change
    for ((name, bytes), (fills, captured)) in out.iter().zip([(vec![true, false], 1), (vec![], 1)])
    {
        let (got_fills, got_captured) = through_headless_media(name, bytes)?;
        if got_fills != fills || got_captured != captured {
            return Err(Wrong(format!(
                "the {name} seed filled {got_fills:?} and read {got_captured} frames"
            )));
        }
    }
    Ok(out)
}

/// A `headless_media` seed, walked the way the target walks it: what each
/// fill returned, and how many frames were read for the agent.
fn through_headless_media(name: &str, seed: &[u8]) -> Result<(Vec<bool>, usize), Wrong> {
    const RATES: [u32; 4] = [8_000, 16_000, 24_000, 48_000];
    const DURATIONS_MS: [u32; 4] = [10, 20, 30, 60];
    let wrong = |what: &str| Wrong(format!("the {name} seed {what}"));
    let (&setup, rest) = seed.split_first().ok_or_else(|| wrong("is empty"))?;
    let pick = |shift: u8| usize::from((setup >> shift) & 3);
    let socket = RATES.get(pick(0)).copied().unwrap_or(8_000);
    let codec = RATES.get(pick(2)).copied().unwrap_or(8_000);
    let duration = DURATIONS_MS.get(pick(4)).copied().unwrap_or(20);
    let rate = sipral_headless::SampleRate::try_from(socket).map_err(|_| wrong("names no rate"))?;
    let audio = sipral_headless::AudioConfig::with_frame_duration_ms(rate, duration)
        .map_err(|_| wrong("names a frame that does not fit"))?;
    let frame_bytes = usize::from(audio.frame_bytes().map_err(|_| wrong("has no frame"))?);
    let mut session =
        sipral::HeadlessSession::open(name.to_owned(), audio, codec, pick(6), pick(6))
            .map_err(|why| wrong(&format!("opens no session: {why}")))?;
    let (mut fills, mut captured) = (Vec::new(), 0);
    let mut cursor = rest;
    while let Some((&[op, len], tail)) = cursor.split_first_chunk::<2>() {
        let take = (usize::from(len) * 2).min(tail.len());
        let (payload, tail) = tail.split_at(take);
        cursor = tail;
        let samples: Vec<i16> = payload.chunks_exact(2).map(sample_from_pair).collect();
        match op % 6 {
            0 => {
                let _ = session.hear(&samples);
            }
            1 => {
                let filled: Vec<i16> = samples
                    .into_iter()
                    .chain(core::iter::repeat(0))
                    .take(frame_bytes / 2)
                    .collect();
                let mut frame = Vec::new();
                sipral_headless::write_samples(&filled, &mut frame);
                session
                    .protocol_mut()
                    .push_playback(frame)
                    .map_err(|why| wrong(&format!("queues no frame: {}", why.message)))?;
            }
            2 => fills.push(session.fill_outbound(&mut vec![0; usize::from(len) * 4])),
            3 => {
                session.protocol_mut().barge_in();
            }
            4 => {
                let rate = RATES.get(usize::from(len & 3)).copied().unwrap_or(8_000);
                session
                    .set_codec_rate(rate)
                    .map_err(|why| wrong(&format!("changes to no rate: {why}")))?;
            }
            _ => captured += usize::from(session.protocol_mut().pop_capture().is_some()),
        }
    }
    Ok((fills, captured))
}

// ---------------------------------------------------------------- dialog-info

fn dialoginfo_seeds() -> Result<Vec<Seed>, Wrong> {
    let documents = [
        (
            "full-one-dialog",
            concat!(
                "<?xml version=\"1.0\"?>\n",
                "<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\" version=\"0\" ",
                "state=\"full\" entity=\"sip:alice@example.com\">\n",
                "  <dialog id=\"as7d900as8\" call-id=\"a84b4c76e66710\" ",
                "local-tag=\"1928301774\" direction=\"initiator\">\n",
                "    <state>confirmed</state>\n",
                "    <local><identity>sip:alice@example.com</identity></local>\n",
                "    <remote><identity>sip:bob@example.com</identity></remote>\n",
                "  </dialog>\n",
                "</dialog-info>\n"
            ),
        ),
        (
            "partial-terminated",
            concat!(
                "<?xml version=\"1.0\"?>\n",
                "<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\" version=\"4\" ",
                "state=\"partial\" entity=\"sip:alice@example.com\">\n",
                "  <dialog id=\"as7d900as8\"><state>terminated</state></dialog>\n",
                "</dialog-info>\n"
            ),
        ),
        (
            "no-dialogs",
            concat!(
                "<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\" version=\"1\" ",
                "state=\"full\" entity=\"sip:alice@example.com\"/>\n"
            ),
        ),
    ];
    let mut out = Vec::new();
    for (name, document) in documents {
        DialogInfo::parse(document.as_bytes())
            .map_err(|why| Wrong(format!("the {name} seed does not parse: {why:?}")))?;
        out.push((name, document.as_bytes().to_vec()));
    }
    Ok(out)
}

// -------------------------------------------------------- message-summary (MWI)

fn mwi_seeds() -> Result<Vec<Seed>, Wrong> {
    let documents = [
        // RFC 3842 §4.1's own sample notification (message A3), verbatim.
        (
            "rfc-sample",
            concat!(
                "Messages-Waiting: yes\r\n",
                "Message-Account: sip:alice@vmail.example.com\r\n",
                "Voice-Message: 2/8 (0/2)\r\n"
            ),
        ),
        // §3.5's own boolean-only case: "the status line allows messaging
        // systems ... to provide the traditional boolean message waiting
        // notification".
        ("boolean-only", "Messages-Waiting: no\r\n"),
        // more than one message-context-class in one body (RFC 3458 §6.2).
        (
            "several-classes",
            concat!(
                "Messages-Waiting: yes\r\n",
                "Voice-Message: 1/0\r\n",
                "Fax-Message: 0/2\r\n"
            ),
        ),
        // §5.2's `opt-msg-headers`: RFC 2822 style headers about individual
        // new messages, after the blank line this reader stops at.
        (
            "with-trailing-headers",
            concat!(
                "Messages-Waiting: yes\r\n",
                "Voice-Message: 4/8 (1/2)\r\n",
                "\r\n",
                "To: <alice@atlanta.example.com>\r\n",
                "From: <bob@biloxi.example.com>\r\n"
            ),
        ),
    ];
    let mut out = Vec::new();
    for (name, document) in documents {
        MessageSummary::parse(document.as_bytes())
            .map_err(|why| Wrong(format!("the {name} seed does not parse: {why:?}")))?;
        out.push((name, document.as_bytes().to_vec()));
    }
    Ok(out)
}

// ---------------------------------------------------------------- RTP, RTCP, SRTP

/// One RTP packet with the header the caller asked for.
fn rtp_packet(header: RtpHeader, payload: &[u8]) -> Result<Vec<u8>, Wrong> {
    let builder = PacketBuilder::new(header, payload);
    let mut out = vec![0; builder.encoded_len()];
    let written = builder
        .write(&mut out)
        .map_err(|why| Wrong(format!("an RTP seed does not write: {why:?}")))?;
    out.truncate(written);
    RtpPacket::parse(&out).map_err(|why| Wrong(format!("an RTP seed does not parse: {why:?}")))?;
    Ok(out)
}

/// One RFC 4733 named event: the digit, the end bit, the volume and the
/// duration, as the four bytes the payload is.
fn dtmf_payload(event: u8, end: bool, duration: u16) -> [u8; 4] {
    let [high, low] = duration.to_be_bytes();
    // the end bit, and a volume of ten dBm0 below full scale
    [event, if end { 0x80 } else { 0x00 } | 0x0a, high, low]
}

/// The DTMF target reads one-octet-length-prefixed datagrams, so a seed is a
/// run of them: one digit begun, held and ended, the way a sender sends it.
fn rtp_dtmf_seeds() -> Result<Vec<Seed>, Wrong> {
    let mut one_digit = Vec::new();
    let mut two_digits = Vec::new();
    for (index, (end, duration)) in [(false, 160), (false, 320), (true, 480)].iter().enumerate() {
        let header = RtpHeader {
            marker: index == 0,
            payload_type: DTMF_PAYLOAD_TYPE,
            sequence: 100 + u16::try_from(index).unwrap_or(0),
            timestamp: 160_000,
            ssrc: SSRC,
        };
        let packet = rtp_packet(header, &dtmf_payload(1, *end, *duration))?;
        push_datagram(&mut one_digit, &packet)?;
        push_datagram(&mut two_digits, &packet)?;
    }
    // a second digit, at a timestamp of its own, without the first's end bit
    // ever being repeated
    for (index, (end, duration)) in [(false, 160), (true, 320)].iter().enumerate() {
        let header = RtpHeader {
            marker: index == 0,
            payload_type: DTMF_PAYLOAD_TYPE,
            sequence: 200 + u16::try_from(index).unwrap_or(0),
            timestamp: 168_000,
            ssrc: SSRC,
        };
        push_datagram(
            &mut two_digits,
            &rtp_packet(header, &dtmf_payload(11, *end, *duration))?,
        )?;
    }
    // and one that is not this receiver's at all, which is the ordinary case
    let audio = rtp_packet(
        RtpHeader {
            marker: false,
            payload_type: 0,
            sequence: 7,
            timestamp: 8_000,
            ssrc: SSRC,
        },
        &[0xff; 160],
    )?;
    // the datagrams are already length-prefixed, so the run of them goes on
    // the end as it is
    let mut mixed = Vec::new();
    push_datagram(&mut mixed, &audio)?;
    mixed.extend_from_slice(&one_digit);
    let out = vec![
        ("one-digit", one_digit),
        ("two-digits", two_digits),
        ("audio-then-an-event", mixed),
    ];
    // the finished run, cut the way the target cuts it: what comes back out
    // of the length prefixes has to be the packets that went in
    for ((name, bytes), packets) in out.iter().zip([3, 5, 4]) {
        let cut = datagrams(bytes);
        if cut.len() != packets {
            return Err(Wrong(format!(
                "the {name} seed cuts into {} datagrams and it is meant to be {packets}",
                cut.len()
            )));
        }
        for datagram in cut {
            RtpPacket::parse(datagram).map_err(|why| {
                Wrong(format!(
                    "a datagram of the {name} seed does not parse: {why:?}"
                ))
            })?;
        }
    }
    Ok(out)
}

/// The one-octet length in front of a datagram, which is how the target cuts
/// its input up.
fn push_datagram(out: &mut Vec<u8>, datagram: &[u8]) -> Result<(), Wrong> {
    let len = u8::try_from(datagram.len()).map_err(|_| {
        Wrong(format!(
            "a datagram of {} octets cannot be length-prefixed with one",
            datagram.len()
        ))
    })?;
    out.push(len);
    out.extend_from_slice(datagram);
    Ok(())
}

fn rtcp_seeds() -> Result<Vec<Seed>, Wrong> {
    let cname = SdesItem {
        kind: CNAME,
        text: b"alice@192.0.2.1",
    };
    let chunks = [ChunkBuilder {
        ssrc: SSRC,
        items: &[cname],
    }];
    let sdes = SourceDescriptionBuilder { chunks: &chunks };
    let sender = SenderOrReceiver::Sender(SenderReportBuilder {
        ssrc: SSRC,
        info: SenderInfo {
            ntp: 0xE4C3_8000_0000_0000,
            rtp_timestamp: 160_000,
            packet_count: 1_000,
            octet_count: 160_000,
        },
        reports: &[],
    });
    let receiver = SenderOrReceiver::Receiver(ReceiverReportBuilder {
        ssrc: SSRC,
        reports: &[],
    });
    let sources = [SSRC];
    let voip_metrics = VoipMetricsBlock {
        ssrc: SSRC,
        loss_rate: 12,
        discard_rate: 3,
        burst_density: 84,
        gap_density: 10,
        burst_duration_ms: 120,
        gap_duration_ms: 520,
        round_trip_delay_ms: 45,
        end_system_delay_ms: 60,
        signal_level_dbm0: -18,
        noise_level_dbm0: -62,
        rerl_db: 40,
        gmin: 16,
        r_factor: 82,
        ext_r_factor: UNAVAILABLE,
        mos_lq: 38,
        mos_cq: 36,
        rx_config: RxConfig {
            plc: PacketLossConcealment::Standard,
            jba: JitterBufferAdaptive::Adaptive,
            jb_rate: 5,
        },
        jb_nominal_ms: 20,
        jb_maximum_ms: 60,
        jb_abs_max_ms: 200,
    };
    let mut out = Vec::new();
    for (name, builder) in [
        (
            "sender-report-and-cname",
            CompoundBuilder::new(sender, sdes),
        ),
        (
            "receiver-report-and-goodbye",
            CompoundBuilder::new(receiver, sdes).with_bye(GoodbyeBuilder {
                sources: &sources,
                reason: b"hangup",
            }),
        ),
        (
            // RFC 3611: the VoIP Metrics Report Block (SS4.7) the far end's
            // negotiated `a=rtcp-xr:voip-metrics` asked this stack to send.
            "receiver-report-and-voip-metrics-xr",
            CompoundBuilder::new(receiver, sdes).with_xr(XrPacketBuilder {
                ssrc: SSRC,
                voip_metrics: Some(voip_metrics),
            }),
        ),
        (
            // RFC 3611 SS2: "report blocks: variable length. Zero or more" --
            // an XR packet is well formed with none, and a peer that only
            // wants the packet type acknowledged sends exactly this.
            "receiver-report-and-empty-xr",
            CompoundBuilder::new(receiver, sdes).with_xr(XrPacketBuilder {
                ssrc: SSRC,
                voip_metrics: None,
            }),
        ),
    ] {
        let mut bytes = vec![0; builder.encoded_len()];
        let written = builder
            .write(&mut bytes)
            .map_err(|why| Wrong(format!("the {name} seed does not write: {why:?}")))?;
        bytes.truncate(written);
        CompoundPacket::parse(&bytes)
            .map_err(|why| Wrong(format!("the {name} seed does not parse: {why:?}")))?;
        out.push((name, bytes));
    }
    Ok(out)
}

/// A run of packets protected with the key the target unprotects with, so
/// that a seed gets past the authentication tag and into the replay window
/// and the rollover estimate behind it.
///
/// A run and not one packet, because those two are the only state an
/// unprotector holds between packets: a corpus of single packets leaves the
/// window empty and the rollover counter at zero on every input, and neither
/// is ever reached. Three in order and then the first one again, which is
/// what makes the window say no.
fn srtp_seeds() -> Result<Vec<Seed>, Wrong> {
    let key = [0x42; KEY];
    let salt = [0x24; SALT];
    let mut out = Vec::new();
    for (name, suite) in [
        ("aes-cm-80", Suite::AesCm80),
        ("aes-cm-32", Suite::AesCm32),
        ("aes-f8", Suite::AesF8),
    ] {
        let mut protector = Protector::new(Policy::new(suite), Master::new(key, salt));
        let mut run = Vec::new();
        let mut first = Vec::new();
        for sequence in 1..=3u16 {
            let plain = rtp_packet(
                RtpHeader {
                    marker: sequence == 1,
                    payload_type: 0,
                    sequence,
                    timestamp: 8_000 + u32::from(sequence) * 160,
                    ssrc: SSRC,
                },
                &[0x55; 160],
            )?;
            // room for whatever the suite appends: the longest tag this ABI
            // has is ten octets, and an MKI would be a few more
            let mut packet = plain.clone();
            packet.resize(plain.len() + 64, 0);
            let written = protector
                .protect_rtp(&mut packet, plain.len())
                .map_err(|why| Wrong(format!("the {name} seed does not protect: {why:?}")))?;
            packet.truncate(written);
            if sequence == 1 {
                first.clone_from(&packet);
            }
            push_datagram(&mut run, &packet)?;
        }
        push_datagram(&mut run, &first)?;
        through_unprotector(name, suite, key, salt, &run)?;
        out.push((name, run));
    }
    Ok(out)
}

/// One protected run, through the door the target puts it through: three
/// packets authenticate and the fourth is refused as a replay, which is the
/// proof that the seed reaches the window rather than dying at the tag.
fn through_unprotector(
    name: &str,
    suite: Suite,
    key: [u8; KEY],
    salt: [u8; SALT],
    run: &[u8],
) -> Result<(), Wrong> {
    let mut unprotector = Unprotector::new(Policy::new(suite), Master::new(key, salt));
    let mut accepted = 0;
    let mut replayed = 0;
    for datagram in datagrams(run) {
        let mut packet = datagram.to_vec();
        match unprotector.unprotect_rtp(&mut packet) {
            Ok(_) => accepted += 1,
            Err(SrtpError::Replayed) => replayed += 1,
            Err(why) => {
                return Err(Wrong(format!(
                    "a datagram of the {name} seed does not unprotect: {why:?}"
                )));
            }
        }
    }
    if accepted == 3 && replayed == 1 {
        return Ok(());
    }
    Err(Wrong(format!(
        "the {name} seed: {accepted} datagrams authenticated and {replayed} were refused as \
         replays, and the run is three and one"
    )))
}

/// Cut a run the way `rtp_dtmf` and `srtp_unprotect` cut their input: one
/// octet of length, then that many bytes.
fn datagrams(run: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = run;
    while let Some((&len, tail)) = rest.split_first() {
        let take = usize::from(len).min(tail.len());
        let (datagram, tail) = tail.split_at(take);
        rest = tail;
        out.push(datagram);
    }
    out
}

// ---------------------------------------------------------------- media

/// One sample out of a byte pair, the same native-endian reading every
/// `media_*` target does. `.get` rather than indexing: the pair a
/// `chunks_exact(2)` iterator hands over is always two bytes, but nothing
/// here needs to lean on that to stay panic-free.
fn sample_from_pair(pair: &[u8]) -> i16 {
    let bytes = [
        pair.first().copied().unwrap_or(0),
        pair.get(1).copied().unwrap_or(0),
    ];
    i16::from_ne_bytes(bytes)
}

/// Appends one length-prefixed chunk of samples the way every `media_*`
/// target but `media_comfort_noise`, `media_g722`, `media_g729`, `media_mix`
/// and `media_opus` cuts its input: one octet holding the sample count, then that
/// many samples in native-endian pairs. `control` is the byte in front of the
/// length for the two targets — `media_plc`, whose control bit chooses
/// `received` or `conceal`, and every other target, which reads nothing there
/// at all and so gets `None`.
fn push_media_chunk(out: &mut Vec<u8>, control: Option<u8>, samples: &[i16]) -> Result<(), Wrong> {
    if let Some(control) = control {
        out.push(control);
    }
    let len = u8::try_from(samples.len()).map_err(|_| {
        Wrong(format!(
            "{} samples do not fit one length octet",
            samples.len()
        ))
    })?;
    out.push(len);
    for sample in samples {
        out.extend_from_slice(&sample.to_ne_bytes());
    }
    Ok(())
}

/// A triangle wave, the same shape `sipral-media`'s own tests build tones
/// from, but written by hand here rather than pulled in from a target's test
/// module: cheap to reason about, and periodic enough to prime a pitch
/// estimate or a resampler's history with something a real voice looks like.
fn triangle(count: usize, period: usize, peak: i16) -> Vec<i16> {
    (0..count)
        .map(|index| {
            let phase = index % period.max(1);
            let half = period / 2;
            let value = if phase < half {
                i32::from(peak) * 2 * i32::try_from(phase).unwrap_or(0)
                    / i32::try_from(half).unwrap_or(1)
                    - i32::from(peak)
            } else {
                i32::from(peak)
                    - i32::from(peak) * 2 * i32::try_from(phase - half).unwrap_or(0)
                        / i32::try_from(period - half).unwrap_or(1)
            };
            i16::try_from(value.clamp(-32_768, 32_767)).unwrap_or(0)
        })
        .collect()
}

fn media_resample_seeds() -> Result<Vec<Seed>, Wrong> {
    // RATES = [8_000, 16_000, 24_000, 32_000, 44_100, 48_000]; index 0 is
    // 8 kHz, index 5 is 48 kHz -- the direction a device's capture crosses
    // most often.
    let mut up = vec![0, 5];
    push_media_chunk(&mut up, None, &triangle(64, 20, 12_000))?;
    push_media_chunk(&mut up, None, &[i16::MAX; 8])?;

    let mut down = vec![5, 0];
    push_media_chunk(&mut down, None, &triangle(200, 37, 20_000))?;

    let mut passthrough = vec![2, 2];
    push_media_chunk(&mut passthrough, None, &triangle(32, 11, 9_000))?;

    let out = vec![
        ("48k-to-8k-with-a-tone", down),
        ("8k-to-48k-then-full-scale", up),
        ("same-rate-is-a-copy", passthrough),
    ];
    for (name, bytes) in &out {
        through_media_resample(name, bytes)?;
    }
    Ok(out)
}

/// Walks a seed the way `fuzz_targets/media_resample.rs` does, so a seed that
/// panics the resampler fails here instead of sitting in the corpus unread.
fn through_media_resample(name: &str, data: &[u8]) -> Result<(), Wrong> {
    const RATES: [u32; 6] = [8_000, 16_000, 24_000, 32_000, 44_100, 48_000];
    let Some((&first, rest)) = data.split_first() else {
        return Err(Wrong(format!("the {name} seed has no rate byte")));
    };
    let Some((&second, mut cursor)) = rest.split_first() else {
        return Err(Wrong(format!("the {name} seed has no second rate byte")));
    };
    let input_rate = *RATES
        .get(usize::from(first) % RATES.len())
        .unwrap_or(&8_000);
    let output_rate = *RATES
        .get(usize::from(second) % RATES.len())
        .unwrap_or(&8_000);
    let mut resampler = sipral_media::resample::Resampler::new(input_rate, output_rate)
        .map_err(|why| Wrong(format!("the {name} seed's rates do not build: {why}")))?;
    let mut produced_anything = false;
    while let Some((&len, tail)) = cursor.split_first() {
        let take = (usize::from(len) * 2).min(tail.len());
        let (bytes, tail) = tail.split_at(take);
        cursor = tail;
        let samples: Vec<i16> = bytes.chunks_exact(2).map(sample_from_pair).collect();
        let mut output = vec![0_i16; resampler.output_capacity(samples.len())];
        let produced = resampler
            .process(&samples, &mut output)
            .map_err(|why| Wrong(format!("the {name} seed does not resample: {why}")))?;
        produced_anything |= produced > 0;
    }
    if produced_anything {
        return Ok(());
    }
    Err(Wrong(format!("the {name} seed never produced a sample")))
}

fn media_plc_seeds() -> Result<Vec<Seed>, Wrong> {
    // op & 1: 0 is `received`, 1 is `conceal`. A primed stream, then a gap
    // long enough to run past MAX_GAP_MS and a real frame that closes it.
    let mut primed_then_gap = Vec::new();
    push_media_chunk(&mut primed_then_gap, Some(0), &triangle(160, 40, 8_000))?;
    push_media_chunk(&mut primed_then_gap, Some(0), &triangle(160, 40, 8_000))?;
    for _ in 0..4 {
        push_media_chunk(&mut primed_then_gap, Some(1), &vec![0_i16; 160])?;
    }
    push_media_chunk(&mut primed_then_gap, Some(0), &vec![20_000_i16; 160])?;

    // no history at all: the cold-start path
    let mut cold = Vec::new();
    push_media_chunk(&mut cold, Some(1), &vec![0_i16; 160])?;

    let out = vec![
        ("cold-conceal", cold),
        ("primed-then-a-gap-that-resumes", primed_then_gap),
    ];
    for (name, bytes) in &out {
        through_media_plc(name, bytes);
    }
    Ok(out)
}

/// Walks a seed the way `fuzz_targets/media_plc.rs` does. The concealer never
/// returns an `Err`, so there is nothing to check here but that it runs.
fn through_media_plc(_name: &str, data: &[u8]) {
    let mut concealer = sipral_media::plc::Concealer::new();
    let mut cursor = data;
    while let Some((&op, tail)) = cursor.split_first() {
        let Some((&len, tail)) = tail.split_first() else {
            break;
        };
        let take = (usize::from(len) * 2).min(tail.len());
        let (bytes, tail) = tail.split_at(take);
        cursor = tail;
        let mut frame: Vec<i16> = bytes.chunks_exact(2).map(sample_from_pair).collect();
        if op & 1 == 0 {
            concealer.received(&mut frame);
        } else {
            let _ = concealer.conceal(&mut frame);
        }
    }
}

fn media_drift_seeds() -> Result<Vec<Seed>, Wrong> {
    // rate byte 18 -> 1_000 + 18*400 = 8_200 Hz, close to the 8 kHz a call
    // actually runs at
    let mut loud_then_quiet = vec![18];
    let mut frame = triangle(160, 23, 20_000);
    frame.truncate(80);
    frame.resize(160, 0);
    push_media_chunk(&mut loud_then_quiet, None, &frame)?;
    push_media_chunk(&mut loud_then_quiet, None, &frame)?;

    let out = vec![("loud-half-then-quiet-half", loud_then_quiet)];
    for (name, bytes) in &out {
        through_media_drift(name, bytes);
    }
    Ok(out)
}

fn through_media_drift(_name: &str, data: &[u8]) {
    let Some((&rate_byte, rest)) = data.split_first() else {
        return;
    };
    let sample_rate = 1_000_u32.saturating_add(u32::from(rate_byte) * 400);
    let mut drift = sipral_media::drift::Drift::new(sample_rate);
    let mut cursor = rest;
    while let Some((&len, tail)) = cursor.split_first() {
        let take = (usize::from(len) * 2).min(tail.len());
        let (bytes, tail) = tail.split_at(take);
        cursor = tail;
        let samples: Vec<i16> = bytes.chunks_exact(2).map(sample_from_pair).collect();
        let mut output = vec![0_i16; samples.len() + 1];
        let _ = drift.process(&samples, &mut output);
        drift.consumed(samples.len());
    }
}

fn media_comfort_noise_seeds() -> Result<Vec<Seed>, Wrong> {
    let zeroth_order = vec![0_u8];
    let mut with_coefficients = vec![30_u8];
    with_coefficients.extend_from_slice(&[0, 64, 127, 200, 255]); // 255 is the reserved index
    let out = vec![
        ("with-coefficients-and-a-reserved-index", with_coefficients),
        ("zeroth-order-full-scale", zeroth_order),
    ];
    for (name, bytes) in &out {
        let noise = sipral_media::comfort_noise::ComfortNoise::decode(bytes)
            .map_err(|why| Wrong(format!("the {name} seed does not decode: {why}")))?;
        let mut wire = vec![0_u8; 1 + noise.order()];
        noise
            .encode_into(&mut wire)
            .map_err(|why| Wrong(format!("the {name} seed does not re-encode: {why}")))?;
    }
    Ok(out)
}

fn media_vad_seeds() -> Result<Vec<Seed>, Wrong> {
    let mut silence_then_burst = vec![15]; // 1_000 + 15*400 = 7_000 Hz
    push_media_chunk(&mut silence_then_burst, None, &vec![0_i16; 160])?;
    push_media_chunk(&mut silence_then_burst, None, &vec![0_i16; 160])?;
    push_media_chunk(&mut silence_then_burst, None, &triangle(160, 25, 18_000))?;

    let out = vec![("silence_then_a_burst", silence_then_burst)];
    for (name, bytes) in &out {
        through_media_vad(name, bytes);
    }
    Ok(out)
}

fn through_media_vad(_name: &str, data: &[u8]) {
    let Some((&rate_byte, rest)) = data.split_first() else {
        return;
    };
    let sample_rate = 1_000_u32.saturating_add(u32::from(rate_byte) * 400);
    let mut vad = sipral_media::vad::Vad::new(sample_rate);
    let mut cursor = rest;
    while let Some((&len, tail)) = cursor.split_first() {
        let take = (usize::from(len) * 2).min(tail.len());
        let (bytes, tail) = tail.split_at(take);
        cursor = tail;
        let frame: Vec<i16> = bytes.chunks_exact(2).map(sample_from_pair).collect();
        let _ = vad.process(&frame);
    }
}

fn media_g722_seeds() -> Result<Vec<Seed>, Wrong> {
    let mut encoder = sipral_media::g722::Encoder::new();
    let samples = triangle(320, 24, 9_000);
    let mut rate64 = vec![0_u8]; // Mode::Rate64
    let mut octets = vec![0_u8; samples.len() / 2];
    encoder.encode_into(&samples, &mut octets);
    rate64.extend_from_slice(&octets);

    let mut rate48 = vec![2_u8]; // Mode::Rate48
    rate48.extend_from_slice(&octets);

    let out = vec![
        ("an-encoded-tone-at-rate64", rate64),
        ("the-same-octets-read-as-rate48", rate48),
    ];
    for (name, bytes) in &out {
        through_media_g722(name, bytes)?;
    }
    Ok(out)
}

fn through_media_g722(name: &str, data: &[u8]) -> Result<(), Wrong> {
    let Some((&mode_byte, rest)) = data.split_first() else {
        return Err(Wrong(format!("the {name} seed has no mode byte")));
    };
    let mode = match mode_byte % 3 {
        0 => sipral_media::g722::Mode::Rate64,
        1 => sipral_media::g722::Mode::Rate56,
        _ => sipral_media::g722::Mode::Rate48,
    };
    let mut decoder = sipral_media::g722::Decoder::new(mode);
    let mut samples = vec![0_i16; rest.len() * 2];
    let written = decoder.decode_into(rest, &mut samples);
    if written == rest.len() * 2 {
        return Ok(());
    }
    Err(Wrong(format!(
        "the {name} seed decoded to {written} samples, not {}",
        rest.len() * 2
    )))
}

/// `media_g729` reads its input twice: as one RTP payload, and as a stream
/// in which a tag octet names what follows — `0` a ten-octet frame, `1` a
/// two-octet SID frame, `2` a lost frame and `3` a frame the far end did
/// not send, neither with anything after it. The seeds are this
/// repository's own encoder's frames, one of them in each shape.
fn media_g729_seeds() -> Result<Vec<Seed>, Wrong> {
    use sipral_media::g729::{Encoder, FRAME_OCTETS};

    let mut encoder = Encoder::new();
    let samples = triangle(240, 20, 9_000);
    let mut payload = vec![0_u8; samples.len() / 8];
    encoder.encode_into(&samples, &mut payload);

    // two frames and a SID at the end: RFC 3551 §4.5.6's whole shape
    let mut with_sid = payload
        .get(..2 * FRAME_OCTETS)
        .map(<[u8]>::to_vec)
        .unwrap_or_default();
    with_sid.extend_from_slice(&[0x00, 0x14]);

    // each frame behind its tag, a SID frame, a frame not sent, a loss in
    // the pause, and one frame more
    let mut stream = Vec::new();
    for frame in payload.chunks_exact(FRAME_OCTETS) {
        stream.push(0);
        stream.extend_from_slice(frame);
    }
    stream.extend_from_slice(&[1, 0x00, 0x14, 3, 2]);
    stream.push(0);
    stream.extend_from_slice(payload.get(..FRAME_OCTETS).unwrap_or_default());

    // forty frames of speech, a quiet SID frame and a pause of a hundred
    // and fifty frames not sent, one of them lost, then speech again: long
    // enough for the target's encoder to reach the part of Annex B's voice
    // activity detector that starts at its 129th frame (the long-term
    // minimum of B.3.3 and the fourth smoothing stage), which a short input
    // never does
    let mut talking = vec![0_u8; 40 * FRAME_OCTETS];
    Encoder::new().encode_into(&triangle(40 * 80, 20, 9_000), &mut talking);
    let mut long_pause = Vec::new();
    for frame in talking.chunks_exact(FRAME_OCTETS) {
        long_pause.push(0);
        long_pause.extend_from_slice(frame);
    }
    // energy index 2, zero decibels
    long_pause.extend_from_slice(&[1, 0x00, 0x04]);
    long_pause.extend((0..150).map(|frame| if frame == 75 { 2 } else { 3 }));
    for frame in talking.chunks_exact(FRAME_OCTETS).take(20) {
        long_pause.push(0);
        long_pause.extend_from_slice(frame);
    }

    let out = vec![
        ("three-encoded-frames", payload),
        ("two-frames-and-a-sid", with_sid),
        ("frames-a-sid-and-a-loss", stream),
        ("speech-and-a-long-pause", long_pause),
    ];
    for (name, bytes) in &out {
        through_media_g729(name, bytes)?;
    }
    Ok(out)
}

/// The two readings `media_g729` gives its input, and the one each seed was
/// written for has to hold: a payload of whole frames and at most one SID,
/// or a stream whose every tag is followed by all of what it names.
fn through_media_g729(name: &str, data: &[u8]) -> Result<(), Wrong> {
    use sipral_media::g729::{Decoder, FRAME_OCTETS, FRAME_SAMPLES, Payload, SID_OCTETS};

    if let Some(payload) = Payload::parse(data) {
        let mut samples = vec![0_i16; payload.frame_count() * FRAME_SAMPLES];
        let written = Decoder::new().decode_into(payload.speech(), &mut samples);
        if written == samples.len() {
            return Ok(());
        }
        return Err(Wrong(format!(
            "the {name} seed decoded to {written} samples, not {}",
            samples.len()
        )));
    }
    let mut rest = data;
    while let Some((&tag, after)) = rest.split_first() {
        let needed = match tag {
            0 => FRAME_OCTETS,
            1 => SID_OCTETS,
            2 | 3 => 0,
            other => {
                return Err(Wrong(format!(
                    "the {name} seed has a tag of {other}, which names nothing"
                )));
            }
        };
        rest = after.get(needed..).ok_or_else(|| {
            Wrong(format!(
                "the {name} seed ends inside what its last tag names"
            ))
        })?;
    }
    Ok(())
}

fn media_mix_seeds() -> Result<Vec<Seed>, Wrong> {
    let mut unity = vec![64_u8]; // Gain::from_q15(64 * 512) is unity
    let a = triangle(40, 17, 12_000);
    let b = triangle(40, 23, 9_000);
    for sample in a.iter().chain(b.iter()) {
        unity.extend_from_slice(&sample.to_ne_bytes());
    }

    let mut loud = vec![255_u8]; // the loudest gain byte can name
    for sample in a.iter().chain(b.iter()) {
        loud.extend_from_slice(&sample.to_ne_bytes());
    }

    let out = vec![
        ("a-loud-gain-that-clips", loud),
        ("two-tones-at-unity", unity),
    ];
    for (name, bytes) in &out {
        through_media_mix(name, bytes)?;
    }
    Ok(out)
}

fn through_media_mix(name: &str, data: &[u8]) -> Result<(), Wrong> {
    let Some((&gain_byte, rest)) = data.split_first() else {
        return Err(Wrong(format!("the {name} seed has no gain byte")));
    };
    let gain = sipral_media::mix::Gain::from_q15(i32::from(gain_byte) * 512);
    let samples: Vec<i16> = rest.chunks_exact(2).map(sample_from_pair).collect();
    if samples.is_empty() {
        return Err(Wrong(format!("the {name} seed has no samples")));
    }
    let mid = samples.len() / 2;
    let (a, b) = samples.split_at(mid);
    let mut mix = a.to_vec();
    sipral_media::mix::add_scaled_into(&mut mix, b, gain);
    Ok(())
}

fn media_opus_seeds() -> Result<Vec<Seed>, Wrong> {
    // SampleRate::Wideband is index 2, FrameDuration::Micros20000 is index 3
    let rate = sipral_media::opus::SampleRate::Wideband;
    let frame = sipral_media::opus::FrameDuration::Micros20000;
    let mut encoder = sipral_media::opus::Encoder::new(rate, frame)
        .map_err(|why| Wrong(format!("the opus encoder does not build: {why}")))?;
    encoder
        .set_bitrate(24_000)
        .map_err(|why| Wrong(format!("the opus bitrate does not set: {why}")))?;
    let samples = triangle(frame.samples(rate), 71, 8_000);
    let mut packet = vec![0_u8; frame.max_packet_bytes()];
    let written = encoder
        .encode(&samples, &mut packet)
        .map_err(|why| Wrong(format!("the opus seed does not encode: {why}")))?;
    packet.truncate(written);

    let mut seed = vec![2, 3]; // Wideband, Micros20000
    seed.extend_from_slice(&packet);

    let out = vec![("an-encoded-wideband-frame", seed)];
    for (name, bytes) in &out {
        through_media_opus(name, bytes)?;
    }
    Ok(out)
}

fn through_media_opus(name: &str, data: &[u8]) -> Result<(), Wrong> {
    const RATES: [sipral_media::opus::SampleRate; 5] = [
        sipral_media::opus::SampleRate::Narrowband,
        sipral_media::opus::SampleRate::Mediumband,
        sipral_media::opus::SampleRate::Wideband,
        sipral_media::opus::SampleRate::SuperWideband,
        sipral_media::opus::SampleRate::Fullband,
    ];
    const DURATIONS: [sipral_media::opus::FrameDuration; 6] = [
        sipral_media::opus::FrameDuration::Micros2500,
        sipral_media::opus::FrameDuration::Micros5000,
        sipral_media::opus::FrameDuration::Micros10000,
        sipral_media::opus::FrameDuration::Micros20000,
        sipral_media::opus::FrameDuration::Micros40000,
        sipral_media::opus::FrameDuration::Micros60000,
    ];
    let Some((&rate_byte, rest)) = data.split_first() else {
        return Err(Wrong(format!("the {name} seed has no rate byte")));
    };
    let Some((&duration_byte, rest)) = rest.split_first() else {
        return Err(Wrong(format!("the {name} seed has no duration byte")));
    };
    let rate = *RATES
        .get(usize::from(rate_byte) % RATES.len())
        .unwrap_or(&sipral_media::opus::SampleRate::Narrowband);
    let frame = *DURATIONS
        .get(usize::from(duration_byte) % DURATIONS.len())
        .unwrap_or(&sipral_media::opus::FrameDuration::Micros20000);
    let mut decoder = sipral_media::opus::Decoder::new(rate, frame)
        .map_err(|why| Wrong(format!("the {name} seed's decoder does not build: {why}")))?;
    let mut samples = vec![0_i16; frame.samples(rate)];
    let sample_count = decoder
        .decode(rest, &mut samples)
        .map_err(|why| Wrong(format!("the {name} seed does not decode: {why}")))?;
    if sample_count == frame.samples(rate) {
        return Ok(());
    }
    Err(Wrong(format!(
        "the {name} seed decoded to {sample_count} samples, not {}",
        frame.samples(rate)
    )))
}

// ---------------------------------------------------------------- STUN, TURN

fn stun_seeds() -> Result<Vec<Seed>, Wrong> {
    let transaction = TransactionId::new([
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ]);
    let mut out = Vec::new();

    let mut request = MessageBuilder::new(Class::Request, StunMethod::BINDING, transaction);
    request
        .add(AttributeType::USERNAME, b"alice:bob")
        .and_then(|()| request.add_u32(AttributeType::PRIORITY, 0x6E00_1EFF))
        .and_then(|()| request.add_message_integrity(b"a password nobody uses"))
        .and_then(|()| request.add_fingerprint())
        .map_err(|why| Wrong(format!("the binding request seed does not build: {why:?}")))?;
    out.push(("binding-request-with-integrity", request.finish()));

    let mut success = MessageBuilder::new(Class::Success, StunMethod::BINDING, transaction);
    success
        .add_xor_address(
            AttributeType::XOR_MAPPED_ADDRESS,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 32_853),
        )
        .and_then(|()| success.add(AttributeType::SOFTWARE, b"sipral"))
        .and_then(|()| success.add_fingerprint())
        .map_err(|why| Wrong(format!("the binding response seed does not build: {why:?}")))?;
    out.push(("binding-success-xor-mapped", success.finish()));

    let mut refused = MessageBuilder::new(Class::Error, StunMethod::BINDING, transaction);
    refused
        .add_error_code(401, b"Unauthorized")
        .and_then(|()| refused.add(AttributeType::REALM, b"example.com"))
        .and_then(|()| refused.add(AttributeType::NONCE, b"f//499k954d6OL34oL9FSTvy64sA"))
        .map_err(|why| Wrong(format!("the error seed does not build: {why:?}")))?;
    out.push(("binding-error-401", refused.finish()));

    for (name, bytes) in &out {
        Message::parse(bytes)
            .map_err(|why| Wrong(format!("the {name} seed does not parse: {why:?}")))?;
    }
    Ok(out)
}

/// The three bytes the `ice` target reads off the front before anything else
/// is a datagram: the shape of the session, how many candidates the peer
/// offered, and how wide a datagram is cut.
///
/// Zero is the ordinary call in every bit of the shape — this end offered, the
/// peer is a full agent that speaks RFC 8445, the stream is not one an ALG
/// rewrote — and the top two bits choose which address the datagrams claim to
/// come from, so zero is the peer's own candidate rather than a stranger's.
const ICE_ORDINARY: [u8; 3] = [0, 1, 255];

/// The password this end publishes in `a=ice-pwd`, and therefore the one a
/// check sent *to* it is signed with (RFC 8445 §7.1.2.3). It has to be the
/// same string the target hands `Credentials::new`, or every signed seed
/// below is an unsigned seed that dies in the agent's authenticator and
/// reaches none of the code the target exists to reach.
const ICE_LOCAL_PWD: &[u8] = b"asd88fgpdd777uzjYhagZg";

/// `USERNAME` on a check arriving here: the fragment of the agent being
/// checked first, then the fragment of the one doing the checking (§7.1.2.3).
const ICE_USERNAME: &[u8] = b"8hhY:9uB6";

/// The first transaction id the target hands the agent, which is how a
/// response seed can be a response to something rather than to nothing.
const ICE_FIRST_ID: [u8; 12] = [
    ICE_ORDINARY[0],
    ICE_ORDINARY[2],
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
];

fn ice_seeds() -> Result<Vec<Seed>, Wrong> {
    let peer = TransactionId::new([
        0x2f, 0x1a, 0x7b, 0x0c, 0x93, 0x44, 0xe1, 0x08, 0x5d, 0xc6, 0x21, 0x3f,
    ]);
    let mut out = Vec::new();

    // a connectivity check from the peer, signed the way the agent will check
    // it. Everything past `server::authenticate` is reached only by a seed
    // that gets this right, which is most of what the target is for.
    let mut check = MessageBuilder::new(Class::Request, StunMethod::BINDING, peer);
    check
        .add(AttributeType::USERNAME, ICE_USERNAME)
        .and_then(|()| check.add_u32(AttributeType::PRIORITY, 0x7E7F_00FF))
        .and_then(|()| check.add(AttributeType::ICE_CONTROLLED, &[0x11; 8]))
        .and_then(|()| check.add_message_integrity(ICE_LOCAL_PWD))
        .and_then(|()| check.add_fingerprint())
        .map_err(|why| Wrong(format!("the ICE check seed does not build: {why:?}")))?;
    out.push(("check-signed", check.finish()));

    // the same, nominating. The peer said ICE-CONTROLLED, so it is not the
    // agent that gets to nominate, and RFC 8445 §7.3.1.5 has this answered
    // with a signed 400 rather than followed -- the refusal is the path worth
    // keeping a seed for.
    let mut nominating = MessageBuilder::new(Class::Request, StunMethod::BINDING, peer);
    nominating
        .add(AttributeType::USERNAME, ICE_USERNAME)
        .and_then(|()| nominating.add_u32(AttributeType::PRIORITY, 0x7E7F_00FF))
        .and_then(|()| nominating.add(AttributeType::ICE_CONTROLLED, &[0x11; 8]))
        .and_then(|()| nominating.add(AttributeType::USE_CANDIDATE, &[]))
        .and_then(|()| nominating.add_message_integrity(ICE_LOCAL_PWD))
        .and_then(|()| nominating.add_fingerprint())
        .map_err(|why| Wrong(format!("the ICE nomination seed does not build: {why:?}")))?;
    out.push(("check-use-candidate", nominating.finish()));

    // an answer to the first check the agent itself sends, carrying a mapped
    // address nobody named: the peer-reflexive path of §7.2.5.2.1
    let mut answered = MessageBuilder::new(
        Class::Success,
        StunMethod::BINDING,
        TransactionId::new(ICE_FIRST_ID),
    );
    answered
        .add_xor_address(
            AttributeType::XOR_MAPPED_ADDRESS,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200)), 51_001),
        )
        .and_then(|()| answered.add_message_integrity(b"YH75Fviy6338Vbrhrlp8Yh"))
        .and_then(|()| answered.add_fingerprint())
        .map_err(|why| Wrong(format!("the ICE response seed does not build: {why:?}")))?;
    out.push(("check-answered-peer-reflexive", answered.finish()));

    // a role conflict: 487, which switches this agent's role and redraws its
    // tiebreaker (§7.2.5.1)
    let mut conflict = MessageBuilder::new(
        Class::Error,
        StunMethod::BINDING,
        TransactionId::new(ICE_FIRST_ID),
    );
    conflict
        .add_error_code(487, b"Role Conflict")
        .and_then(|()| conflict.add_message_integrity(b"YH75Fviy6338Vbrhrlp8Yh"))
        .and_then(|()| conflict.add_fingerprint())
        .map_err(|why| {
            Wrong(format!(
                "the ICE role-conflict seed does not build: {why:?}"
            ))
        })?;
    out.push(("check-refused-role-conflict", conflict.finish()));

    for (name, bytes) in &out {
        Message::parse(bytes)
            .map_err(|why| Wrong(format!("the {name} seed does not parse: {why:?}")))?;
    }

    // and the other half of what arrives on a media socket, which the agent
    // has to hand back rather than read: an RTP packet, and the four bytes a
    // truncated STUN header is
    out.push(("media-not-stun", vec![0x80, 0x00, 0x12, 0x34]));
    out.push(("four-bytes", vec![0x00, 0x01, 0x00, 0x00]));

    Ok(out
        .into_iter()
        .map(|(name, bytes)| {
            let mut seed = ICE_ORDINARY.to_vec();
            seed.extend_from_slice(&bytes);
            (name, seed)
        })
        .collect())
}

/// The two bytes `fuzz_targets/ice_lite.rs` reads off the front before
/// anything else is a datagram: the shape of the session and how wide a
/// datagram is cut.
///
/// Zero is the ordinary call in every bit of the shape -- this end did not
/// offer and the peer is a full agent, so `Role::initial` starts this agent
/// controlled, the shape RFC 8445 §6.1.1 gives the pairing this target
/// exists to hold to.
const LITE_ORDINARY: [u8; 2] = [0, 220];

/// The password this agent publishes in `a=ice-pwd`; has to match what
/// `fuzz_targets/ice_lite.rs` hands `LiteAgent::new`, or every signed seed
/// below dies in the authenticator and reaches none of the code the target
/// exists to reach.
const LITE_LOCAL_PWD: &[u8] = b"asd88fgpdd777uzjYhagZg";

/// `USERNAME` on a check arriving here: this agent's fragment first, then
/// the peer's (RFC 8445 §7.1.2.3, the same order `ice_seeds` uses).
const LITE_USERNAME: &[u8] = b"8hhY:9uB6";

fn ice_lite_seeds() -> Result<Vec<Seed>, Wrong> {
    let peer = TransactionId::new([
        0x4a, 0x1c, 0x87, 0xe2, 0x3f, 0x90, 0xb1, 0x66, 0x0d, 0x5e, 0x2a, 0x71,
    ]);
    let mut out = Vec::new();

    // the ordinary call: a full peer's check, correctly controlling, which
    // is not a conflict for a controlled agent to answer (§6.1.1)
    let mut check = MessageBuilder::new(Class::Request, StunMethod::BINDING, peer);
    check
        .add(AttributeType::USERNAME, LITE_USERNAME)
        .and_then(|()| check.add_u32(AttributeType::PRIORITY, 0x7E7F_00FF))
        .and_then(|()| check.add_u64(AttributeType::ICE_CONTROLLING, 0x1122_3344_5566_7788))
        .and_then(|()| check.add_message_integrity(LITE_LOCAL_PWD))
        .and_then(|()| check.add_fingerprint())
        .map_err(|why| Wrong(format!("the ice_lite check seed does not build: {why:?}")))?;
    out.push(("check-signed", check.finish()));

    // the same, nominating: the pair this agent then holds for the component
    let mut nominating = MessageBuilder::new(Class::Request, StunMethod::BINDING, peer);
    nominating
        .add(AttributeType::USERNAME, LITE_USERNAME)
        .and_then(|()| nominating.add_u32(AttributeType::PRIORITY, 0x7E7F_00FF))
        .and_then(|()| nominating.add_u64(AttributeType::ICE_CONTROLLING, 0x1122_3344_5566_7788))
        .and_then(|()| nominating.add(AttributeType::USE_CANDIDATE, &[]))
        .and_then(|()| nominating.add_message_integrity(LITE_LOCAL_PWD))
        .and_then(|()| nominating.add_fingerprint())
        .map_err(|why| {
            Wrong(format!(
                "the ice_lite nomination seed does not build: {why:?}"
            ))
        })?;
    out.push(("check-use-candidate", nominating.finish()));

    // a full peer with the roles backwards: ICE-CONTROLLED naming a
    // tiebreaker this agent's own (drawn from the shape byte, zero here)
    // would have lost to under the general §7.3.1.1 arithmetic -- the seed
    // the defence in `crates/sipral-nat/src/ice/agent.rs` exists for, since
    // a lite agent must never answer this by switching to controlling
    // (§6.1.1, §8.2)
    let mut backwards = MessageBuilder::new(Class::Request, StunMethod::BINDING, peer);
    backwards
        .add(AttributeType::USERNAME, LITE_USERNAME)
        .and_then(|()| backwards.add_u32(AttributeType::PRIORITY, 0x7E7F_00FF))
        .and_then(|()| backwards.add_u64(AttributeType::ICE_CONTROLLED, u64::MAX))
        .and_then(|()| backwards.add_message_integrity(LITE_LOCAL_PWD))
        .and_then(|()| backwards.add_fingerprint())
        .map_err(|why| {
            Wrong(format!(
                "the ice_lite role-conflict seed does not build: {why:?}"
            ))
        })?;
    out.push(("check-role-conflict-backwards", backwards.finish()));

    for (name, bytes) in &out {
        Message::parse(bytes)
            .map_err(|why| Wrong(format!("the {name} seed does not parse: {why:?}")))?;
    }

    // the other half of what arrives on the socket, which this agent has to
    // leave alone rather than read: a truncated STUN header
    out.push(("not-stun", vec![0x00, 0x01, 0x00, 0x00]));

    Ok(out
        .into_iter()
        .map(|(name, bytes)| {
            let mut seed = LITE_ORDINARY.to_vec();
            seed.push(0); // marker: no restart, RTP, the peer's own source
            seed.extend_from_slice(&bytes);
            (name, seed)
        })
        .collect())
}

fn turn_seeds() -> Result<Vec<Seed>, Wrong> {
    let channel = ChannelNumber::new(0x4001)
        .ok_or_else(|| Wrong("0x4001 is inside the channel range".to_owned()))?;
    let mut stream = vec![255];
    for data in [&b"one"[..], b"two payloads in one stream", b"three"] {
        ChannelData::encode(channel, data, Transport::Tcp, &mut stream)
            .map_err(|why| Wrong(format!("a channel seed does not encode: {why:?}")))?;
    }
    let mut trickled = vec![1];
    trickled.extend_from_slice(stream.get(1..).unwrap_or_default());

    let mut datagram = vec![255];
    ChannelData::encode(channel, &[0x11; 172], Transport::Udp, &mut datagram)
        .map_err(|why| Wrong(format!("a channel seed does not encode: {why:?}")))?;
    ChannelData::parse(datagram.get(1..).unwrap_or_default(), Transport::Udp)
        .map_err(|why| Wrong(format!("the datagram seed does not parse: {why:?}")))?;

    let out = vec![
        ("three-frames-in-one-read", stream),
        ("three-frames-one-byte-at-a-time", trickled),
        ("one-datagram", datagram),
    ];
    // the two stream seeds go through the framer the target drives them
    // through; the third is a datagram and was parsed as one above
    for ((name, bytes), frames) in out.iter().zip([3, 3, 1]) {
        through_stream_framing(name, bytes, frames)?;
    }
    Ok(out)
}

/// One TURN stream seed, walked the way the target walks it.
fn through_stream_framing(name: &str, seed: &[u8], expected: usize) -> Result<(), Wrong> {
    let Some((&first, rest)) = seed.split_first() else {
        return Err(Wrong(format!("the {name} seed has no read size in front")));
    };
    let chunk = usize::from(first).max(1);
    let mut framer = StreamFraming::new();
    let mut count = 0;
    for piece in rest.chunks(chunk) {
        framer.push(piece);
        while framer
            .next_frame()
            .map_err(|why| Wrong(format!("the {name} seed does not frame: {why:?}")))?
            .is_some()
        {
            count += 1;
        }
    }
    if count == expected {
        return Ok(());
    }
    Err(Wrong(format!(
        "the {name} seed framed into {count} frames and it is meant to be {expected}"
    )))
}

// ---------------------------------------------------------------- TURN client

/// The credential and realm `fuzz_targets/turn_client.rs` signs its answers
/// with. A seed that names another realm leaves the key it derives unable to
/// check anything the target signs.
const TURN_USER: &str = "fuzz";
const TURN_PASSWORD: &str = "secret";
const TURN_REALM: &[u8] = b"fuzz.test";

/// The target's instructions, by the opcode it reads modulo six.
const TURN_ANSWER: u8 = 0;
const TURN_RAW: u8 = 1;
const TURN_TIME: u8 = 2;
const TURN_PERMIT: u8 = 3;
const TURN_BIND: u8 = 4;
const TURN_SEND: u8 = 5;

/// An `answer`'s first byte: an error, signed with MESSAGE-INTEGRITY under
/// the MD5 key or MESSAGE-INTEGRITY-SHA256 under the SHA-256 one, and a
/// FINGERPRINT.
const ANSWER_ERROR: u8 = 1;
const ANSWER_MD5: u8 = 1 << 1;
const ANSWER_SHA256: u8 = 2 << 1;
const ANSWER_FINGERPRINT: u8 = 8;

/// The indexes into the target's table of error codes for the two
/// challenges.
const PICK_401: u8 = 2;
const PICK_438: u8 = 6;

/// A turn_client program being written: the configuration byte, then
/// instructions.
struct TurnProgram(Vec<u8>);

impl TurnProgram {
    fn new(shape: u8) -> Self {
        Self(vec![shape])
    }

    fn op(mut self, op: u8, payload: &[u8]) -> Result<Self, Wrong> {
        let len = u8::try_from(payload.len()).map_err(|_| {
            Wrong(format!(
                "a turn_client instruction of {} bytes",
                payload.len()
            ))
        })?;
        self.0.push(op);
        self.0.push(len);
        self.0.extend_from_slice(payload);
        Ok(self)
    }

    fn answer(self, flags: u8, pick: u8, attributes: &[Vec<u8>]) -> Result<Self, Wrong> {
        let mut payload = vec![flags, pick];
        for attribute in attributes {
            payload.extend_from_slice(attribute);
        }
        self.op(TURN_ANSWER, &payload)
    }
}

/// One attribute as an `answer` spells it: a two-byte type, a one-byte
/// length and the value.
fn turn_attribute(kind: AttributeType, value: &[u8]) -> Result<Vec<u8>, Wrong> {
    let len = u8::try_from(value.len())
        .map_err(|_| Wrong(format!("a {kind} of {} bytes", value.len())))?;
    let mut out = kind.code().to_be_bytes().to_vec();
    out.push(len);
    out.extend_from_slice(value);
    Ok(out)
}

/// An address as an `answer` spells one for the target to XOR: the octets
/// and the port.
fn turn_address(kind: AttributeType, address: SocketAddr) -> Result<Vec<u8>, Wrong> {
    let mut value = match address.ip() {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    value.extend_from_slice(&address.port().to_be_bytes());
    turn_attribute(kind, &value)
}

fn turn_client_seeds() -> Result<Vec<Seed>, Wrong> {
    let relayed = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 15)), 50_000);
    let relayed_v6 = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 15)),
        50_001,
    );
    let mapped = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 7_000);
    let lifetime = turn_attribute(AttributeType::LIFETIME, &600_u32.to_be_bytes())?;
    let realm = turn_attribute(AttributeType::REALM, TURN_REALM)?;
    // the peer the target's `peer` reads out of [150, 0x7d, 0x66]
    let peer = [150_u8, 0x7d, 0x66];
    let mut channel_data = Vec::new();
    ChannelData::encode(
        ChannelNumber::new(0x4000).ok_or_else(|| Wrong("0x4000 is a channel".to_owned()))?,
        b"relayed",
        Transport::Udp,
        &mut channel_data,
    )
    .map_err(|why| Wrong(format!("the ChannelData seed does not encode: {why:?}")))?;

    // the whole life of an authenticated allocation: challenged, granted,
    // a channel bound and used, the clock run to the refresh and a stale
    // nonce answered on the way
    let signed = ANSWER_MD5 | ANSWER_FINGERPRINT;
    let lived = TurnProgram::new(0)
        .answer(
            ANSWER_ERROR | ANSWER_FINGERPRINT,
            PICK_401,
            &[
                realm.clone(),
                turn_attribute(AttributeType::NONCE, b"nonce-one")?,
            ],
        )?
        .answer(
            signed,
            0,
            &[
                turn_address(AttributeType::XOR_RELAYED_ADDRESS, relayed)?,
                turn_address(AttributeType::XOR_MAPPED_ADDRESS, mapped)?,
                lifetime.clone(),
            ],
        )?
        .op(TURN_BIND, &peer)?
        .answer(signed, 0, &[])?
        .op(TURN_RAW, &channel_data)?
        .op(TURN_TIME, &5_400_u16.to_be_bytes())?
        .answer(
            ANSWER_ERROR | ANSWER_FINGERPRINT,
            PICK_438,
            &[
                realm.clone(),
                turn_attribute(AttributeType::NONCE, b"nonce-two")?,
            ],
        )?
        .answer(signed, 0, std::slice::from_ref(&lifetime))?;

    // a relay that asks for no credential, handing out both families, and a
    // peer permitted and sent to by indication
    let mut send = peer.to_vec();
    send.extend_from_slice(b"by indication");
    let open = TurnProgram::new(0b0010_0110)
        .answer(
            ANSWER_FINGERPRINT,
            0,
            &[
                turn_address(AttributeType::XOR_RELAYED_ADDRESS, relayed)?,
                turn_address(AttributeType::XOR_RELAYED_ADDRESS, relayed_v6)?,
                lifetime.clone(),
            ],
        )?
        .op(TURN_PERMIT, &peer)?
        .answer(ANSWER_FINGERPRINT, 0, &[])?
        .op(TURN_SEND, &send)?;

    // a challenge offering SHA-256 as well as MD5, which the client has to
    // take and then sign with MESSAGE-INTEGRITY-SHA256 alone (RFC 8489 §9.2.5)
    let offered = TurnProgram::new(0)
        .answer(
            ANSWER_ERROR,
            PICK_401,
            &[
                realm,
                turn_attribute(AttributeType::NONCE, b"nonce-one")?,
                turn_attribute(
                    AttributeType::PASSWORD_ALGORITHMS,
                    &[0, 2, 0, 0, 0, 1, 0, 0],
                )?,
            ],
        )?
        .answer(
            ANSWER_SHA256 | ANSWER_FINGERPRINT,
            0,
            &[
                turn_address(AttributeType::XOR_RELAYED_ADDRESS, relayed)?,
                lifetime,
            ],
        )?;

    // each with whether its ChannelData has to reach the application
    let out = vec![
        ("challenged-allocated-bound-refreshed", lived.0, true),
        ("open-relay-dual-sent-by-indication", open.0, false),
        ("sha256-offered-and-taken", offered.0, false),
    ];
    for (name, seed, delivers) in &out {
        through_turn_client(name, seed, *delivers)?;
    }
    Ok(out
        .into_iter()
        .map(|(name, seed, _)| (name, seed))
        .collect())
}

/// The long-term key `fuzz_targets/turn_client.rs` derives, the same way.
fn turn_key(algorithm: sipral_core::auth::DigestAlgorithm) -> Vec<u8> {
    let hex = algorithm.hash(format!("{TURN_USER}:fuzz.test:{TURN_PASSWORD}").as_bytes());
    hex.as_bytes()
        .chunks(2)
        .filter_map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// One turn_client seed, run the way the target runs it, and required to end
/// with an allocation — which is what every one of them is for, and what a
/// seed that got an instruction's length or an attribute wrong never reaches
/// — and, where it carries one, to have its ChannelData delivered.
fn through_turn_client(name: &str, seed: &[u8], delivers: bool) -> Result<(), Wrong> {
    use sipral_core::auth::DigestAlgorithm;
    use sipral_nat::turn::Input;

    let wrong = |what: &str| Wrong(format!("the {name} seed {what}"));
    let (&shape, mut program) = seed
        .split_first()
        .ok_or_else(|| wrong("has no configuration byte"))?;
    let mut client = turn_client_for(shape);
    let md5 = turn_key(DigestAlgorithm::Md5);
    let sha256 = turn_key(DigestAlgorithm::Sha256);
    let mut now = Instant::now();
    let mut ids = 0_u32;
    turn_feed(&mut client, &mut ids);
    client
        .allocate(now)
        .map_err(|why| wrong(&format!("does not start: {why}")))?;
    let mut last = None;
    let mut delivered = false;
    while let [op, len, rest @ ..] = program {
        while let Some(out) = client.poll_transmit() {
            last = Some(out);
        }
        let (payload, after) = rest
            .split_at_checked(usize::from(*len))
            .ok_or_else(|| wrong("has an instruction longer than what follows it"))?;
        program = after;
        match *op {
            TURN_ANSWER => {
                let request = last
                    .as_deref()
                    .ok_or_else(|| wrong("answers before anything was asked"))?;
                let response = turn_answer(request, payload, &md5, &sha256)
                    .ok_or_else(|| wrong("has an answer that does not build"))?;
                if client.handle_input(&response, now) != Input::Consumed {
                    return Err(wrong("has an answer the client did not take"));
                }
            }
            TURN_RAW => {
                if let Input::Data { .. } = client.handle_input(payload, now) {
                    delivered = true;
                }
            }
            TURN_TIME => {
                let step = payload
                    .get(..2)
                    .and_then(|pair| <[u8; 2]>::try_from(pair).ok())
                    .map_or(1_000, |pair| u64::from(u16::from_be_bytes(pair)));
                now += std::time::Duration::from_millis(step * 100);
                client.handle_timeout(now);
            }
            TURN_PERMIT => client.permit(turn_peer(payload).ip(), now),
            TURN_BIND => {
                client
                    .bind_channel(turn_peer(payload), now)
                    .ok_or_else(|| wrong("binds no channel"))?;
            }
            TURN_SEND => {
                let mut out = Vec::new();
                client
                    .send_to(
                        turn_peer(payload),
                        payload.get(3..).unwrap_or_default(),
                        &mut out,
                    )
                    .map_err(|why| wrong(&format!("cannot send: {why}")))?;
            }
            other => return Err(wrong(&format!("has an opcode {other} it should not"))),
        }
        turn_feed(&mut client, &mut ids);
        while client.poll_event().is_some() {}
    }
    if !program.is_empty() {
        return Err(wrong("ends in the middle of an instruction"));
    }
    if !client.is_allocated() {
        return Err(wrong("does not end with an allocation"));
    }
    if delivers && !delivered {
        return Err(wrong(
            "carries a ChannelData message the client did not deliver",
        ));
    }
    Ok(())
}

/// The client the target configures from its first byte, for the bits the
/// seeds set: whether it has a credential, and which families it asks for.
fn turn_client_for(shape: u8) -> sipral_nat::turn::TurnClient {
    use sipral_nat::stun::LongTermCredentials;
    use sipral_nat::turn::{AddressFamily, FamilyRequest, TurnClient, TurnConfig};

    let families = match (shape >> 1) & 3 {
        0 => FamilyRequest::Whatever,
        1 => FamilyRequest::Only(AddressFamily::V4),
        2 => FamilyRequest::Only(AddressFamily::V6),
        _ => FamilyRequest::Dual,
    };
    TurnClient::new(TurnConfig {
        credentials: (shape & 32 == 0).then(|| LongTermCredentials::new(TURN_USER, TURN_PASSWORD)),
        families,
        ..TurnConfig::default()
    })
}

/// Keep the client's pool full, with the ids the target draws.
fn turn_feed(client: &mut sipral_nat::turn::TurnClient, ids: &mut u32) {
    while client.transaction_ids_wanted() > 0 {
        *ids = ids.wrapping_add(1);
        let mut bytes = [0x5a_u8; 12];
        if let Some(head) = bytes.get_mut(..4) {
            head.copy_from_slice(&ids.to_be_bytes());
        }
        client.supply_transaction_id(TransactionId::new(bytes));
    }
}

/// The peer the target reads out of an instruction's first three bytes.
fn turn_peer(payload: &[u8]) -> SocketAddr {
    let first = payload.first().copied().unwrap_or(0);
    let port = payload
        .get(1..3)
        .and_then(|pair| <[u8; 2]>::try_from(pair).ok())
        .map_or(40_000, u16::from_be_bytes);
    let ip = if first & 0x80 == 0 {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, first))
    } else {
        IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0xdb8,
            0,
            0,
            0,
            0,
            0,
            u16::from(first),
        ))
    };
    SocketAddr::new(ip, port)
}

/// The relay's answer, built the way the target builds it.
fn turn_answer(request: &[u8], payload: &[u8], md5: &[u8], sha256: &[u8]) -> Option<Vec<u8>> {
    const CODES: [u16; 14] = [
        300, 400, 401, 403, 420, 437, 438, 440, 441, 442, 443, 486, 500, 508,
    ];
    let message = Message::parse(request).ok()?;
    let flags = payload.first().copied().unwrap_or(0);
    let error = flags & ANSWER_ERROR != 0;
    let class = if error { Class::Error } else { Class::Success };
    let mut builder = MessageBuilder::new(class, message.method(), message.transaction_id());
    if error {
        let pick = payload.get(1).copied().unwrap_or(0);
        let code = *CODES.get(usize::from(pick) % CODES.len())?;
        builder.add_error_code(code, b"fuzz").ok()?;
    }
    let mut rest = payload.get(2..).unwrap_or_default();
    while let [high, low, len, tail @ ..] = rest {
        let kind = AttributeType::new(u16::from_be_bytes([*high, *low]));
        let (value, after) = tail.split_at_checked(usize::from(*len))?;
        rest = after;
        let address = matches!(
            kind,
            AttributeType::XOR_RELAYED_ADDRESS
                | AttributeType::XOR_MAPPED_ADDRESS
                | AttributeType::XOR_PEER_ADDRESS
        );
        match (address, value.len()) {
            (true, 6 | 18) => {
                let (ip, port) = value.split_at(value.len() - 2);
                let ip = match <[u8; 4]>::try_from(ip) {
                    Ok(v4) => IpAddr::V4(Ipv4Addr::from(v4)),
                    Err(_) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(ip).ok()?)),
                };
                let port = u16::from_be_bytes(<[u8; 2]>::try_from(port).ok()?);
                builder
                    .add_xor_address(kind, SocketAddr::new(ip, port))
                    .ok()?;
            }
            _ => builder.add(kind, value).ok()?,
        }
    }
    if !rest.is_empty() {
        return None;
    }
    match flags & (3 << 1) {
        ANSWER_MD5 => builder.add_message_integrity(md5).ok()?,
        ANSWER_SHA256 => builder.add_message_integrity_sha256(sha256).ok()?,
        _ => {}
    }
    if flags & ANSWER_FINGERPRINT != 0 {
        builder.add_fingerprint().ok()?;
    }
    Some(builder.finish())
}

// ---------------------------------------------------------------- DTLS

/// The seeds of the two ends' random sources, as `dtls_record` has them.
const DTLS_SERVER_SEED: u64 = 0x5E;
const DTLS_CLIENT_SEED: u64 = 0xC1;

/// The random source `fuzz_targets/dtls_record.rs` builds its two ends from,
/// octet for octet. The seeds below are recorded from ends built from it, and
/// an end built from anything else would answer them with other keys.
struct DtlsFixed(u64);

impl Random for DtlsFixed {
    fn fill(&mut self, dest: &mut [u8]) {
        for octet in dest {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let [top, ..] = self.0.to_be_bytes();
            *octet = top;
        }
    }
}

fn dtls_identity(scalar: u8, seed: u64) -> Result<(EcdsaKey, DtlsCertificate), Wrong> {
    let params = CertificateParams {
        common_name: "sipral-fuzz",
        not_before: 1_785_542_400,
        not_after: 1_788_134_400,
    };
    let key = EcdsaKey::from_scalar(&[scalar; 32])
        .map_err(|why| Wrong(format!("the DTLS key does not build: {why:?}")))?;
    let certificate = DtlsCertificate::self_signed(&key, &params, &mut DtlsFixed(seed))
        .map_err(|why| Wrong(format!("the DTLS certificate does not build: {why:?}")))?;
    Ok((key, certificate))
}

/// The server and the client `dtls_record` builds, in that order.
fn dtls_ends(now: Instant) -> Result<(Connection, Connection), Wrong> {
    let (server_key, server_certificate) = dtls_identity(0x5E, DTLS_SERVER_SEED)?;
    let (client_key, client_certificate) = dtls_identity(0xC1, DTLS_CLIENT_SEED)?;
    let mut server = DtlsConfig::new(
        Role::Server,
        server_key,
        server_certificate.clone(),
        vec![client_certificate.fingerprint()],
    );
    server.cookie_exchange = false;
    let client = DtlsConfig::new(
        Role::Client,
        client_key,
        client_certificate,
        vec![server_certificate.fingerprint()],
    );
    let server = Connection::new(server, &mut DtlsFixed(DTLS_SERVER_SEED), now)
        .map_err(|why| Wrong(format!("the DTLS server does not build: {why:?}")))?;
    let client = Connection::new(client, &mut DtlsFixed(DTLS_CLIENT_SEED), now)
        .map_err(|why| Wrong(format!("the DTLS client does not build: {why:?}")))?;
    Ok((server, client))
}

/// The datagrams one end sent, in the order it sent them.
type Datagrams = Vec<Vec<u8>>;

/// A handshake between those two ends over a path that loses nothing: every
/// datagram the client sent, and every datagram the server sent.
fn dtls_handshake_run() -> Result<(Datagrams, Datagrams), Wrong> {
    let now = Instant::now();
    let (mut server, mut client) = dtls_ends(now)?;
    let mut from_client = Vec::new();
    let mut from_server = Vec::new();
    // flights 1 and 4, then 5 and 6, then a round that must carry nothing
    for _ in 0..3 {
        let sent: Vec<Vec<u8>> = std::iter::from_fn(|| client.poll_transmit()).collect();
        for datagram in &sent {
            server.handle_datagram(datagram, now);
        }
        from_client.extend(sent);
        let sent: Vec<Vec<u8>> = std::iter::from_fn(|| server.poll_transmit()).collect();
        for datagram in &sent {
            client.handle_datagram(datagram, now);
        }
        from_server.extend(sent);
    }
    if server.state() != State::Connected || client.state() != State::Connected {
        return Err(Wrong(format!(
            "the DTLS handshake the seeds are cut from did not complete: the server is {:?}, \
             the client {:?}",
            server.state(),
            client.state()
        )));
    }
    Ok((from_client, from_server))
}

/// The two-octet length in front of a datagram, which is how `dtls_record`
/// cuts its input up.
fn push_long_datagram(out: &mut Vec<u8>, datagram: &[u8]) -> Result<(), Wrong> {
    let len = u16::try_from(datagram.len()).map_err(|_| {
        Wrong(format!(
            "a datagram of {} octets cannot be length-prefixed with two",
            datagram.len()
        ))
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(datagram);
    Ok(())
}

/// Each side of a real handshake as a run of datagrams: the client's flights,
/// which take the target's server to its Finished, and the server's, which
/// take the target's client to its own.
fn dtls_record_seeds() -> Result<Vec<Seed>, Wrong> {
    let (from_client, from_server) = dtls_handshake_run()?;
    let mut out = Vec::new();
    for (name, datagrams, finishes) in [
        ("client-flights", &from_client, Role::Server),
        ("server-flights", &from_server, Role::Client),
    ] {
        let mut run = Vec::new();
        for datagram in datagrams {
            push_long_datagram(&mut run, datagram)?;
        }
        through_dtls_ends(name, &run, finishes)?;
        out.push((name, run));
    }
    Ok(out)
}

/// One run, through both ends the target puts it through, cut the way the
/// target cuts it: the end the run was written for has to complete its
/// handshake on it.
fn through_dtls_ends(name: &str, run: &[u8], finishes: Role) -> Result<(), Wrong> {
    let now = Instant::now();
    let (mut server, mut client) = dtls_ends(now)?;
    let mut rest = run;
    while let Some((length, tail)) = rest.split_first_chunk::<2>() {
        let take = usize::from(u16::from_be_bytes(*length)).min(tail.len());
        let (datagram, tail) = tail.split_at(take);
        rest = tail;
        server.handle_datagram(datagram, now);
        client.handle_datagram(datagram, now);
    }
    let end = match finishes {
        Role::Server => &server,
        Role::Client => &client,
    };
    if end.state() == State::Connected {
        return Ok(());
    }
    Err(Wrong(format!(
        "the {name} seed leaves the target's {finishes:?} {:?} rather than connected",
        end.state()
    )))
}

/// Every message of a real handshake the way `dtls_handshake` takes one: the
/// type, then the body. The two Finished messages travel protected, so a
/// Finished is written out by hand instead, and so is a HelloVerifyRequest,
/// which a server without a cookie exchange never sends.
fn dtls_handshake_seeds() -> Result<Vec<Seed>, Wrong> {
    let (from_client, from_server) = dtls_handshake_run()?;
    let mut out: Vec<Seed> = Vec::new();
    for (side, datagrams) in [("client", &from_client), ("server", &from_server)] {
        for datagram in datagrams {
            for record in dtls_records(datagram) {
                let record = record
                    .map_err(|why| Wrong(format!("a {side} datagram does not read: {why:?}")))?;
                if record.header.epoch != 0 || record.header.content_type != ContentType::HANDSHAKE
                {
                    continue;
                }
                for fragment in dtls_fragments(record.fragment) {
                    let fragment = fragment.map_err(|why| {
                        Wrong(format!("a {side} fragment does not read: {why:?}"))
                    })?;
                    let header = fragment.header;
                    if header.fragment_length != header.length {
                        return Err(Wrong(format!(
                            "the {side} sent a {:?} in pieces, and a seed is a whole message",
                            header.msg_type
                        )));
                    }
                    let name = dtls_seed_name(side, header.msg_type).ok_or_else(|| {
                        Wrong(format!(
                            "the {side} sent a {:?}, which no seed is named for",
                            header.msg_type
                        ))
                    })?;
                    let mut seed = vec![header.msg_type.0];
                    seed.extend_from_slice(fragment.body);
                    out.push((name, seed));
                }
            }
        }
    }

    let mut request = vec![HandshakeType::HELLO_VERIFY_REQUEST.0];
    HelloVerifyRequest {
        server_version: ProtocolVersion::DTLS_1_0,
        cookie: vec![0xC0; 32],
    }
    .encode(&mut request)
    .map_err(|why| {
        Wrong(format!(
            "the HelloVerifyRequest seed does not encode: {why:?}"
        ))
    })?;
    out.push(("hello-verify-request", request));
    let mut finished = vec![HandshakeType::FINISHED.0];
    finished.extend_from_slice(&[0xF1; 12]);
    out.push(("finished", finished));

    for (name, seed) in &out {
        let Some((&msg_type, body)) = seed.split_first() else {
            return Err(Wrong(format!("the {name} seed has no message type")));
        };
        let message = HandshakeMessage::parse(HandshakeType(msg_type), body)
            .map_err(|why| Wrong(format!("the {name} seed does not parse: {why:?}")))?;
        let mut written = Vec::new();
        message
            .encode_body(&mut written)
            .map_err(|why| Wrong(format!("the {name} seed does not write back: {why:?}")))?;
        if written != body {
            return Err(Wrong(format!(
                "the {name} seed writes back as other octets than it was read from"
            )));
        }
    }
    Ok(out)
}

fn dtls_seed_name(side: &str, msg_type: HandshakeType) -> Option<&'static str> {
    Some(match (side, msg_type) {
        ("client", HandshakeType::CLIENT_HELLO) => "client-hello",
        ("client", HandshakeType::CERTIFICATE) => "client-certificate",
        ("client", HandshakeType::CLIENT_KEY_EXCHANGE) => "client-key-exchange",
        ("client", HandshakeType::CERTIFICATE_VERIFY) => "certificate-verify",
        ("server", HandshakeType::SERVER_HELLO) => "server-hello",
        ("server", HandshakeType::CERTIFICATE) => "server-certificate",
        ("server", HandshakeType::SERVER_KEY_EXCHANGE) => "server-key-exchange",
        ("server", HandshakeType::CERTIFICATE_REQUEST) => "certificate-request",
        ("server", HandshakeType::SERVER_HELLO_DONE) => "server-hello-done",
        _ => return None,
    })
}

/// The one-octet length in front of the `Content-Type`, which is how the
/// `dtmf_info` target cuts its input into the header and the body.
fn encode_info(content_type: &[u8], body: &[u8]) -> Result<Vec<u8>, Wrong> {
    let len = u8::try_from(content_type.len()).map_err(|_| {
        Wrong(format!(
            "a content type of {} bytes needs a longer prefix than dtmf_info reads",
            content_type.len()
        ))
    })?;
    let mut out = vec![len];
    out.extend_from_slice(content_type);
    out.extend_from_slice(body);
    Ok(out)
}

/// 8.3.11's incoming INFO parser: a `Content-Type` and a body, read the way
/// `dtmf_info` cuts its input. Each seed is checked against
/// `sipral_ua::dtmf::parse_info`'s own answer before it is written, so a
/// case that stopped meaning what its name says fails the generator rather
/// than sitting in the corpus unread — a valid `Signal=` in each of the two
/// bodies this stack takes, and the three ways RFC 3261 §21.4.13 and
/// §21.4.1 refuse one: no `Content-Type` at all, one neither body uses, and
/// the right one naming no digit.
fn dtmf_info_seeds() -> Result<Vec<Seed>, Wrong> {
    let cases: [(&str, &[u8], &[u8], bool); 5] = [
        (
            "relay",
            b"application/dtmf-relay",
            b"Signal=5\r\nDuration=160\r\n",
            true,
        ),
        ("plain", b"application/dtmf", b"5", true),
        ("unsupported-type", b"application/sdp", b"v=0\r\n", false),
        (
            "malformed",
            b"application/dtmf-relay",
            b"Duration=160\r\n",
            false,
        ),
        ("no-content-type", b"", b"5", false),
    ];
    let mut out = Vec::new();
    for (name, content_type, body, accepted) in cases {
        let named = (!content_type.is_empty()).then_some(content_type);
        let read = parse_info(named, body);
        if read.is_ok() != accepted {
            return Err(Wrong(format!(
                "the {name} seed does not read the way it is meant to: {read:?}"
            )));
        }
        out.push((name, encode_info(content_type, body)?));
    }
    Ok(out)
}

// ---------------------------------------------------------------- writing

/// Every target, and the seeds it starts from.
fn corpus() -> Result<Vec<(&'static str, Vec<Seed>)>, Wrong> {
    Ok(vec![
        ("builder", builder_seeds()?),
        ("crypto", crypto_seeds()?),
        ("dialoginfo", dialoginfo_seeds()?),
        ("dtls_handshake", dtls_handshake_seeds()?),
        ("dtls_record", dtls_record_seeds()?),
        ("dtmf_info", dtmf_info_seeds()?),
        ("framer", framer_seeds()?),
        ("headless", headless_seeds()?),
        ("headless_media", headless_media_seeds()?),
        ("ice", ice_seeds()?),
        ("ice_lite", ice_lite_seeds()?),
        ("media_comfort_noise", media_comfort_noise_seeds()?),
        ("media_drift", media_drift_seeds()?),
        ("media_g722", media_g722_seeds()?),
        ("media_g729", media_g729_seeds()?),
        ("media_mix", media_mix_seeds()?),
        ("media_opus", media_opus_seeds()?),
        ("media_plc", media_plc_seeds()?),
        ("media_resample", media_resample_seeds()?),
        ("media_vad", media_vad_seeds()?),
        ("mwi", mwi_seeds()?),
        ("parse", sip_seeds()?),
        ("replay", replay_seeds()?),
        ("rtcp", rtcp_seeds()?),
        ("rtp_dtmf", rtp_dtmf_seeds()?),
        ("sdp", sdp_seeds()?),
        ("srtp_unprotect", srtp_seeds()?),
        ("stun", stun_seeds()?),
        ("turn", turn_seeds()?),
        ("turn_client", turn_client_seeds()?),
    ])
}

/// What the corpus may weigh, all of it, in bytes. A seed corpus is meant to
/// be read by whoever clones this, and something that has to be skimmed past
/// is not being read.
const BUDGET: usize = 200 * 1024;

/// The one file under `fuzz/corpus/` that is not a seed and is not this
/// program's to remove.
const KEPT: &str = "README.md";

/// Take out of `fuzz/corpus/` everything the run above did not just write.
///
/// Without this a seed dropped from `corpus()` stays in the tree for good:
/// the check in `scripts/check.sh` asks whether every target has a directory
/// and every directory a target, and a stale file inside a live directory
/// answers yes to both. What this program writes is the whole of that
/// directory bar its README, so what it does not write, it removes.
fn sweep(here: &Path, corpus: &[(&'static str, Vec<Seed>)]) -> Result<Vec<String>, Wrong> {
    let read = |directory: &Path| {
        std::fs::read_dir(directory)
            .map_err(|why| Wrong(format!("{}: {why}", directory.display())))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|why| Wrong(format!("{}: {why}", directory.display())))
    };
    let remove = |path: &Path| -> Result<(), Wrong> {
        let gone = if path.is_dir() {
            std::fs::remove_dir_all(path)
        } else {
            std::fs::remove_file(path)
        };
        gone.map_err(|why| Wrong(format!("{}: {why}", path.display())))
    };

    let mut removed = Vec::new();
    for entry in read(here)? {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let Some((target, seeds)) = corpus.iter().find(|(target, _)| *target == name) else {
            // not a target of this run: a directory for a target that is
            // gone, or a file dropped at the top of the corpus
            if name != KEPT {
                remove(&path)?;
                removed.push(name);
            }
            continue;
        };
        if !path.is_dir() {
            remove(&path)?;
            removed.push(name);
            continue;
        }
        for file in read(&path)? {
            let seed = file.file_name().to_string_lossy().into_owned();
            if !seeds.iter().any(|(written, _)| *written == seed) {
                remove(&file.path())?;
                removed.push(format!("{target}/{seed}"));
            }
        }
    }
    removed.sort();
    Ok(removed)
}

fn main() -> ExitCode {
    let corpus = match corpus() {
        Ok(corpus) => corpus,
        Err(why) => {
            eprintln!("the seeds are not what they say they are: {why}");
            return ExitCode::FAILURE;
        }
    };
    // Where to write. The repository's own `fuzz/corpus/` unless a directory
    // is named, which is what lets `scripts/check.sh` regenerate somewhere
    // disposable and hold the tracked corpus to what this program produces.
    // Without that, a seed replaced by hand with anything at all passes every
    // check there is: the directory is still a target's, the bytes still
    // carry no address and no Romanian, and nothing ever asked whether they
    // are the seeds this file describes.
    let here = match std::env::args().nth(1) {
        Some(named) => PathBuf::from(named),
        None => root().join("fuzz").join("corpus"),
    };
    let mut total = 0;
    let mut written = 0;
    for (target, seeds) in &corpus {
        let directory = here.join(target);
        if let Err(why) = std::fs::create_dir_all(&directory) {
            eprintln!("{}: {why}", directory.display());
            return ExitCode::FAILURE;
        }
        for (name, bytes) in seeds {
            let path = directory.join(name);
            if let Err(why) = std::fs::write(&path, bytes) {
                eprintln!("{}: {why}", path.display());
                return ExitCode::FAILURE;
            }
            total += bytes.len();
            written += 1;
        }
    }
    let removed = match sweep(&here, &corpus) {
        Ok(removed) => removed,
        Err(why) => {
            eprintln!("fuzz/corpus/ could not be swept: {why}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "{written} seeds for {} targets, {total} bytes",
        corpus.len()
    );
    if !removed.is_empty() {
        println!("{} no longer written, and removed:", removed.len());
        for name in &removed {
            println!("  {name}");
        }
    }
    if total > BUDGET {
        eprintln!("that is over the {BUDGET} bytes a seed corpus is allowed here");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
