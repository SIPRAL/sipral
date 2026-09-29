// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Real-time text in a call (RFC 4103): the `m=text` stream a call offers and
//! answers beside its audio, what two descriptions agreed about it, and the
//! stream that carries it.
//!
//! **A stream of its own, on a socket of its own.** RFC 4103 puts T.140 on an
//! RTP session of its own, so the call's text has its own port: the
//! application binds a second socket for it ([`crate::CallMedia::text`]), and
//! the packets for it come out of [`crate::MediaSession::poll_text`] and go in
//! through [`crate::MediaSession::receive_text`].
//!
//! **What is offered is RFC 4103 §7's own example.** `t140/1000` on 98 inside
//! `red/1000` on 100 with two redundant generations (`a=fmtp:100 98/98/98`),
//! which §4 recommends because a lost packet loses what was typed rather than
//! a few milliseconds of sound. An offer that names only `t140` is answered
//! and sent without redundancy. Each end sends with the numbers the other's
//! description gave (RFC 3264 §5.1), and each receives under its own.
//!
//! **No RTCP.** The stream says so with `b=RS:0` and `b=RR:0` (RFC 3556 §2),
//! sends none, and ignores what arrives: a character stream at a few packets
//! a second has nothing an RTCP report would tell anybody that the call's
//! audio stream does not already report.
//!
//! **Not on a call that keys its audio.** The stream is plain `RTP/AVP`, and
//! what is typed is exactly what an encrypted call is encrypted to hide, so a
//! call whose policy offers or requires SRTP neither offers text nor takes an
//! offered text stream.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral_core::sdp::{
    AcceptedStream, Attribute, Direction, MediaDescription, SessionDescription, StreamAnswer,
};
use sipral_rtp::rtt::{
    DEFAULT_GENERATIONS, ReceiverConfig, Redundancy, SenderConfig, TextEvent, TextReceiver,
    TextSender, parse_cps, parse_red_fmtp,
};
use sipral_rtp::{Frame, RtpPacket};

use crate::error::MediaError;

/// The media type (RFC 4103 §6).
pub(crate) const TEXT: &str = "text";
/// The payload types this end offers, as RFC 4103 §7's example numbers them.
const T140: u8 = 98;
const RED: u8 = 100;
/// The profile the stream runs on: plain RTP, since it is never keyed.
const PROFILE: &str = "RTP/AVP";
/// "b=RS:0 and b=RR:0": no RTCP on this stream (RFC 3556 §2).
const NO_RTCP: [&str; 2] = ["RS:0", "RR:0"];

/// The `m=text` section of an offer, receiving at `port`.
pub(crate) fn offer(port: u16) -> MediaDescription {
    let mut stream =
        MediaDescription::new(TEXT, port, PROFILE, vec![RED.to_string(), T140.to_string()]);
    stream.bandwidth = NO_RTCP.iter().map(|line| (*line).to_owned()).collect();
    stream.attributes = vec![
        Attribute::with_value("rtpmap", &format!("{T140} t140/1000")),
        Attribute::with_value("rtpmap", &format!("{RED} red/1000")),
        Attribute::with_value("fmtp", &format!("{RED} {T140}/{T140}/{T140}")),
        Attribute::flag(Direction::SendRecv.as_str()),
    ];
    stream
}

/// The answer to an offered text stream, receiving at `port`: `t140`, and
/// `red` when the offer carries it over `t140`. Refused when the offer names
/// no `t140` at all.
pub(crate) fn answer(offered: &MediaDescription, port: u16) -> StreamAnswer {
    let Some(t140) = payload_named(offered, "t140") else {
        return StreamAnswer::Reject;
    };
    let red = red_over(offered, t140);
    let formats: Vec<String> = offered
        .formats
        .iter()
        .filter(|format| {
            format.parse::<u8>().ok().is_some_and(|payload| {
                payload == t140 || red.is_some_and(|(red, _)| red == payload)
            })
        })
        .cloned()
        .collect();
    StreamAnswer::Accept(AcceptedStream::new(port, formats).with_direction(Direction::SendRecv))
}

/// Say on a written answer that the text stream at `index` runs no RTCP.
pub(crate) fn no_rtcp(description: &mut SessionDescription, index: usize) {
    if let Some(stream) = description.media.get_mut(index) {
        stream.bandwidth = NO_RTCP.iter().map(|line| (*line).to_owned()).collect();
    }
}

/// The payload type a stream maps to `encoding`, by its `a=rtpmap`.
fn payload_named(stream: &MediaDescription, encoding: &str) -> Option<u8> {
    stream.payload_types().find(|payload| {
        stream
            .rtpmap(*payload)
            .is_some_and(|map| map.encoding.eq_ignore_ascii_case(encoding))
    })
}

/// The `red` payload type carrying `t140`, and its generations, when the
/// stream lists one.
fn red_over(stream: &MediaDescription, t140: u8) -> Option<(u8, u8)> {
    let red = payload_named(stream, "red")?;
    let generations = stream
        .fmtp(red)
        .and_then(|value| parse_red_fmtp(value, t140))?;
    Some((red, generations))
}

/// The first live text stream of a description, and where it is.
fn text_stream(description: &SessionDescription) -> Option<(usize, &MediaDescription)> {
    description
        .media
        .iter()
        .enumerate()
        .find(|(_, stream)| stream.media == TEXT && !stream.is_rejected())
}

/// What our description and the far end's agreed about text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TextPlan {
    /// Where to send it.
    pub(crate) remote: SocketAddr,
    /// The far end's numbers, which this end sends with.
    send_t140: u8,
    send_red: Option<u8>,
    /// This end's numbers, which it receives under.
    receive_t140: u8,
    receive_red: Option<u8>,
    /// The far end's `cps`: the most characters a second it takes.
    cps: Option<u32>,
    /// Which way text may flow, as seen from here.
    pub(crate) direction: Direction,
}

impl TextPlan {
    const fn sends(&self) -> bool {
        matches!(self.direction, Direction::SendRecv | Direction::SendOnly)
    }
}

/// What `ours` and `theirs` agreed about a text stream, or `None` when
/// either has none or refused it.
pub(crate) fn plan(ours: &SessionDescription, theirs: &SessionDescription) -> Option<TextPlan> {
    let (index, mine) = text_stream(ours)?;
    let far = theirs.media.get(index)?;
    if far.media != TEXT || far.is_rejected() {
        return None;
    }
    let address = theirs.connection_of(far)?.ip()?;
    let send_t140 = payload_named(far, "t140")?;
    let receive_t140 = payload_named(mine, "t140")?;
    // redundancy is used only where both descriptions carry it
    let (send_red, receive_red) = match (red_over(far, send_t140), red_over(mine, receive_t140)) {
        (Some((theirs, _)), Some((ours, _))) => (Some(theirs), Some(ours)),
        _ => (None, None),
    };
    let cps = far.fmtp(send_t140).and_then(parse_cps);
    let direction = Direction::answer_to(theirs.direction_of(far), ours.direction_of(mine));
    Some(TextPlan {
        remote: SocketAddr::new(address, far.port),
        send_t140,
        send_red,
        receive_t140,
        receive_red,
        cps,
        direction,
    })
}

/// What one call's text stream received and has not reported yet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Heard {
    /// What was typed, in order: characters as they are, an erasure as
    /// BACKSPACE, a new line as LINE SEPARATOR, an alert as BELL, and
    /// REPLACEMENT CHARACTER where text was lost.
    pub(crate) text: String,
    /// How many blocks of text were lost, one REPLACEMENT CHARACTER each
    /// (RFC 4103 §5.3).
    pub(crate) missing: u32,
}

/// One call's text: the sender, the receiver, and where they talk to.
#[derive(Debug)]
pub(crate) struct TextStream {
    plan: TextPlan,
    sender: TextSender,
    receiver: TextReceiver,
    /// This stream's zero on the RTP clock.
    origin: Instant,
    /// Where the far end's text comes from, once it has: where this end's
    /// goes from then on (symmetric RTP, as the audio does).
    latch: Option<SocketAddr>,
    heard: Heard,
}

impl TextStream {
    /// Open the stream for `plan`, numbering its packets from `ssrc`,
    /// `sequence` and `timestamp`.
    ///
    /// # Errors
    /// [`MediaError::NoText`] for payload types the RTP header cannot carry.
    pub(crate) fn open(
        plan: TextPlan,
        (ssrc, sequence, timestamp): (u32, u16, u32),
        now: Instant,
    ) -> Result<Self, MediaError> {
        let sender = TextSender::new(sender_config(&plan), ssrc, sequence, timestamp)
            .map_err(|_| MediaError::NoText)?;
        let receiver = TextReceiver::new(ReceiverConfig::new(plan.receive_t140, plan.receive_red))
            .map_err(|_| MediaError::NoText)?;
        Ok(Self {
            plan,
            sender,
            receiver,
            origin: now,
            latch: None,
            heard: Heard::default(),
        })
    }

    /// A later offer and answer agreed `plan`: the direction, the far end's
    /// address and either end's numbers may have moved. Nothing typed and
    /// not yet sent is lost; the numbering carries on. A receiver whose
    /// numbers moved starts afresh, after handing on what it had read.
    ///
    /// # Errors
    /// [`MediaError::NoText`] for payload types the RTP header cannot carry;
    /// the stream is left as it was.
    pub(crate) fn update(&mut self, plan: TextPlan) -> Result<(), MediaError> {
        let receiving = (plan.receive_t140, plan.receive_red);
        let receiver = if receiving == (self.plan.receive_t140, self.plan.receive_red) {
            None
        } else {
            Some(
                TextReceiver::new(ReceiverConfig::new(plan.receive_t140, plan.receive_red))
                    .map_err(|_| MediaError::NoText)?,
            )
        };
        let sending = sender_config(&plan);
        if sending != sender_config(&self.plan) {
            self.sender
                .reconfigure(sending)
                .map_err(|_| MediaError::NoText)?;
        }
        if let Some(receiver) = receiver {
            self.collect();
            self.receiver = receiver;
        }
        if plan.remote != self.plan.remote {
            self.latch = None;
        }
        self.plan = plan;
        Ok(())
    }

    /// Queue typed text for the far end.
    ///
    /// # Errors
    /// [`MediaError::TextBufferFull`] when it does not fit; none of it is
    /// queued then.
    pub(crate) fn send(&mut self, text: &str) -> Result<(), MediaError> {
        self.sender
            .push(text)
            .map_err(|full| MediaError::TextBufferFull { room: full.room })
    }

    /// The next packet to send, and where, when one is due at `now`.
    pub(crate) fn poll_transmit(&mut self, now: Instant) -> Option<(SocketAddr, Vec<u8>)> {
        if !self.plan.sends() {
            return None;
        }
        let packet = self.sender.poll(self.elapsed(now))?;
        let datagram = packet.to_datagram().ok()?;
        Some((self.latch.unwrap_or(self.plan.remote), datagram))
    }

    /// Take a datagram off the text socket. `false` when it was not this
    /// stream's: not RTP, another payload type, or from somewhere other than
    /// where the stream has latched.
    pub(crate) fn receive(&mut self, datagram: &[u8], from: SocketAddr, now: Instant) -> bool {
        if self.latch.is_some_and(|latched| latched != from) {
            return false;
        }
        let Ok(packet) = RtpPacket::parse(datagram) else {
            return false;
        };
        let header = packet.header();
        let frame = Frame {
            sequence: header.sequence,
            timestamp: header.timestamp,
            payload_type: header.payload_type,
            marker: header.marker,
            payload: packet.payload(),
        };
        let arrival = self.receiver.receive(frame, self.elapsed(now));
        if matches!(
            arrival,
            sipral_rtp::rtt::Arrival::Foreign | sipral_rtp::rtt::Arrival::Malformed(_)
        ) {
            return false;
        }
        self.latch.get_or_insert(from);
        self.collect();
        true
    }

    /// When [`TextStream::handle_timeout`] has something to do: a packet due,
    /// or a gap waited out.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        let sending = self.sender.next_poll().filter(|_| self.plan.sends());
        let waiting = self.receiver.deadline();
        [sending, waiting]
            .into_iter()
            .flatten()
            .min()
            .and_then(|at| self.origin.checked_add(at))
    }

    /// Give up on the gaps that have waited their time.
    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        self.receiver.poll(self.elapsed(now));
        self.collect();
    }

    /// What arrived since the last time this was asked, if anything did.
    pub(crate) fn take_heard(&mut self) -> Option<Heard> {
        (!self.heard.text.is_empty()).then(|| core::mem::take(&mut self.heard))
    }

    fn collect(&mut self) {
        for event in self.receiver.events() {
            if event == TextEvent::Missing {
                self.heard.missing = self.heard.missing.saturating_add(1);
            }
            self.heard.text.push(event.as_char());
        }
    }

    fn elapsed(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.origin)
    }
}

/// How this end sends to the far end under `plan`.
fn sender_config(plan: &TextPlan) -> SenderConfig {
    let mut config = SenderConfig::new(plan.send_t140, plan.send_red.unwrap_or(plan.send_t140));
    config.redundancy = plan.send_red.map(|payload_type| Redundancy {
        payload_type,
        generations: DEFAULT_GENERATIONS,
    });
    config.cps = plan.cps.or(config.cps);
    config
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use sipral_core::sdp::{SessionDescription, parse};
    use sipral_rtp::RtpPacket;
    use sipral_rtp::rtt::{RedPayload, SenderConfig, TextSender};

    use super::{TextStream, plan};

    /// A description at `host` whose text stream numbers t140 `t140` and
    /// red `red`.
    fn described(host: &str, port: u16, t140: u8, red: u8) -> SessionDescription {
        let text = format!(
            "v=0\r\no=- 1 1 IN IP4 {host}\r\ns=-\r\nc=IN IP4 {host}\r\nt=0 0\r\n\
m=text {port} RTP/AVP {red} {t140}\r\na=rtpmap:{t140} t140/1000\r\n\
a=rtpmap:{red} red/1000\r\na=fmtp:{red} {t140}/{t140}/{t140}\r\n"
        );
        parse(text.as_bytes()).expect("a description")
    }

    #[test]
    fn a_re_offer_that_renumbers_the_text_is_sent_and_read_under_the_new_numbers() {
        let now = Instant::now();
        let first = plan(
            &described("192.0.2.1", 41000, 98, 100),
            &described("192.0.2.2", 41002, 98, 100),
        )
        .expect("text agreed");
        let mut stream = TextStream::open(first, (7, 1, 1), now).expect("the stream");
        // the far end offers again under other numbers, and the answer
        // takes the offer's
        let again = plan(
            &described("192.0.2.1", 41000, 96, 97),
            &described("192.0.2.2", 41002, 96, 97),
        )
        .expect("text agreed again");
        stream.update(again).expect("the new numbers fit");

        stream.send("hi").expect("queued");
        let (_, datagram) = stream.poll_transmit(now).expect("a packet due");
        let packet = RtpPacket::parse(&datagram).expect("RTP");
        assert_eq!(packet.header().payload_type, 97, "red under its new number");
        let red = RedPayload::parse(packet.payload()).expect("a red payload");
        assert_eq!(red.primary_payload_type(), 96, "t140 under its new number");

        let mut far = TextSender::new(SenderConfig::new(96, 97), 9, 1, 1).expect("a sender");
        far.push("ok").expect("queued");
        let arriving = far
            .poll(Duration::ZERO)
            .expect("a packet")
            .to_datagram()
            .expect("written");
        assert!(
            stream.receive(
                &arriving,
                "192.0.2.2:41002".parse().expect("an address"),
                now
            ),
            "the far end's text under the numbers the answer gave"
        );
    }
}
