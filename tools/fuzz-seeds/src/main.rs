// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The seed corpus the fuzz targets start from, written out of this
//! repository's own writers.
//!
//! A public clone that gets thirteen targets and no corpus gets thirteen
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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sipral_core::msg::{
    HeaderName, Method, ParseMode, ParseScratch, RequestBuilder, ResponseBuilder, StatusCode,
    StreamFramer, parse,
};
use sipral_core::replay::Recording;
use sipral_core::sdp::{self, Crypto};
use sipral_headless::{ControlMessage, FrameDecoder, write_frame};
use sipral_nat::stun::{
    AttributeType, Class, Message, MessageBuilder, Method as StunMethod, TransactionId,
};
use sipral_nat::turn::{ChannelData, ChannelNumber, StreamFraming, Transport};
use sipral_rtp::srtp::{KEY, Master, Policy, Protector, SALT, SrtpError, Suite, Unprotector};
use sipral_rtp::{
    CNAME, ChunkBuilder, CompoundBuilder, CompoundPacket, GoodbyeBuilder, PacketBuilder,
    ReceiverReportBuilder, RtpHeader, RtpPacket, SdesItem, SenderInfo, SenderOrReceiver,
    SenderReportBuilder, SourceDescriptionBuilder,
};
use sipral_ua::DialogInfo;

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
    ] {
        sdp::parse(&bytes)
            .map_err(|why| Wrong(format!("the {name} seed is not a description: {why:?}")))?;
        out.push((name, bytes));
    }
    Ok(out)
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

// ---------------------------------------------------------------- writing

/// Every target, and the seeds it starts from.
fn corpus() -> Result<Vec<(&'static str, Vec<Seed>)>, Wrong> {
    Ok(vec![
        ("builder", builder_seeds()?),
        ("crypto", crypto_seeds()?),
        ("dialoginfo", dialoginfo_seeds()?),
        ("framer", framer_seeds()?),
        ("headless", headless_seeds()?),
        ("parse", sip_seeds()?),
        ("replay", replay_seeds()?),
        ("rtcp", rtcp_seeds()?),
        ("rtp_dtmf", rtp_dtmf_seeds()?),
        ("sdp", sdp_seeds()?),
        ("srtp_unprotect", srtp_seeds()?),
        ("stun", stun_seeds()?),
        ("turn", turn_seeds()?),
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
