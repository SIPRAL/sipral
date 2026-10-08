// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What a pre-call network test found, and the one word it comes to.
//!
//! A test asks up to four things: whether a STUN server answers and what that says about the NAT,
//! whether the TURN server grants a relay, whether the account's server answers on the account's
//! transport, and, if the application placed a short call to an echo service, how the returned
//! audio fared. This module holds the findings and the arithmetic; sending and receiving is the
//! stack's (`sipral_stack_network_test` in `sipral-ffi`).
//!
//! # The verdict
//!
//! Each tested part gets a [`Verdict`]; the test's verdict is the worst of them. Untested parts are
//! ignored; a test of nothing is [`Verdict::Unknown`].
//!
//! | Part | Good | Acceptable | Poor |
//! |---|---|---|---|
//! | Account's server | answered | — | timed out, or the transport failed |
//! | STUN | answered | no answer | — |
//! | TURN | relay allocated | refused or no answer | — |
//! | Echo: packet loss | under 1 % | under 3 % | 3 % or more, or no audio came back |
//! | Echo: jitter | 20 ms or less | 50 ms or less | over 50 ms |
//! | Echo: round trip | 300 ms or less | 600 ms or less | over 600 ms |
//! | Echo: MOS (CQ) | 4.0 or more | 3.6 or more | under 3.6 |
//!
//! Why: without the server no call is placed. Without STUN or TURN, calls still work where the far
//! end uses symmetric RTP (every carrier does), but not through every NAT, so it is a warning.
//! ITU-T G.114 sees conversation suffer past 150 ms one way and sets 400 ms as the usual limit; the
//! round-trip bounds are 150 and 300 ms doubled. 1 % loss is about what concealment hides, 3 % is
//! where G.711 drops a category in G.107, and MOS 4.0 and 3.6 are the "satisfied" and "some users
//! dissatisfied" lines of G.107 Annex B.
//!
//! # The echo rating
//!
//! R and MOS come from the simplified G.107 E-model in `sipral-rtp`, always rated for G.711 with
//! concealment (`Ie` 0, `Bpl` 25.1, ITU-T G.113 Appendix I) whatever the echo call negotiated,
//! since the test rates the network, not the codec. The one-way delay is half the RTCP round trip
//! plus the jitter buffer delay, RFC 3611 §4.7.3's symmetric estimate.

use std::net::SocketAddr;
use std::time::Duration;

use sipral_rtp::{
    BurstRatio, CodecFamily, CodecQualityModel, EModelInputs, codec_quality_model, evaluate_e_model,
};

/// ITU-T G.113 Appendix I, G.711 with the packet loss concealment of G.711
/// Appendix I: no impairment of its own, and `Bpl` 25.1 under random loss.
const G711_CONCEALED: CodecQualityModel = codec_quality_model(CodecFamily::G711Concealed);

/// The value `sipral_rtp`'s E-model writes for a figure it cannot rate.
const UNRATED: u8 = 127;

/// The one word a test, or one part of it, comes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    /// Nothing was tested.
    Unknown,
    /// Calls should work and sound right.
    Good,
    /// Calls should work, and may not everywhere or may not sound their best.
    Acceptable,
    /// Calls are likely to fail or to sound bad.
    Poor,
}

impl Verdict {
    /// The worse of the two; [`Verdict::Unknown`] gives way to anything.
    #[must_use]
    pub fn worst(self, other: Self) -> Self {
        self.max(other)
    }
}

/// What a STUN mapping says about the NAT. Approximate: distinguishing RFC 4787 mapping and
/// filtering behaviours needs a server answering from a second address (RFC 5780), which few public
/// servers support.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NatKind {
    /// No answer to read.
    Unknown,
    /// The server saw the socket's own address: no NAT, or one that does
    /// not translate.
    Open,
    /// Address translated, port kept: most home routers, and the easiest to call through.
    PortPreserved,
    /// Port changed too. Calls work via symmetric RTP and `rport`; a relay is needed where the far
    /// end insists on the advertised address.
    PortChanged,
}

impl NatKind {
    /// What a socket bound at `local` being seen at `public` says.
    #[must_use]
    pub fn of(local: SocketAddr, public: Option<SocketAddr>) -> Self {
        match public {
            None => Self::Unknown,
            Some(public) if public == local => Self::Open,
            Some(public) if public.port() == local.port() => Self::PortPreserved,
            Some(_) => Self::PortChanged,
        }
    }
}

/// What the account's server did with the `OPTIONS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerReach {
    /// Answered, with this status, after this long.
    Answered {
        /// The final status code, whatever it was: any answer is the server.
        status: u16,
        /// From sending to the answer.
        round_trip: Duration,
    },
    /// No answer before the transaction timed out.
    TimedOut,
    /// The transport refused the request or failed under it.
    TransportFailed,
}

impl ServerReach {
    /// This part's verdict.
    #[must_use]
    pub const fn verdict(self) -> Verdict {
        match self {
            Self::Answered { .. } => Verdict::Good,
            Self::TimedOut | Self::TransportFailed => Verdict::Poor,
        }
    }
}

/// What came back on an echo call, as the stream's statistics counted it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EchoMeasurement {
    /// Packets that arrived and were held for playout.
    pub received: u64,
    /// Packets lost or too late to play; RFC 3611 §4.7.1 counts both, as they "have equal effect on
    /// the quality of the voice stream".
    pub lost: u64,
    /// Interarrival jitter (RFC 3550 §6.4.1).
    pub jitter: Duration,
    /// The round trip RTCP measured, when a report came back in time.
    pub round_trip: Option<Duration>,
    /// How long the jitter buffer held the audio.
    pub buffer_delay: Duration,
}

/// An echo call's figures, rated.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EchoQuality {
    /// Lost or late, as a percentage of what was due.
    pub loss_percent: f64,
    /// As measured.
    pub jitter: Duration,
    /// As measured, when it was.
    pub round_trip: Option<Duration>,
    /// The one-way delay the rating assumed.
    pub one_way_delay: Duration,
    /// G.107's transmission rating, 0 to 100, for concealed G.711.
    pub r_factor: u8,
    /// The conversational mean opinion score, 1.0 to 4.5, for concealed G.711.
    pub mos: f32,
    /// This part's verdict.
    pub verdict: Verdict,
}

impl EchoMeasurement {
    /// Rate what was measured.
    #[must_use]
    pub fn rate(self) -> EchoQuality {
        let due = self.received.saturating_add(self.lost);
        #[allow(
            clippy::cast_precision_loss,
            reason = "packet counts of a short call are far below 2^52"
        )]
        let loss_percent = if due == 0 {
            100.0
        } else {
            self.lost as f64 * 100.0 / due as f64
        };
        let one_way_delay = self.round_trip.unwrap_or_default() / 2 + self.buffer_delay;
        let report = evaluate_e_model(EModelInputs {
            one_way_delay_ms: u32::try_from(one_way_delay.as_millis()).unwrap_or(u32::MAX),
            packet_loss_percent: loss_percent,
            burst_ratio: BurstRatio::RANDOM,
            codec: Some(G711_CONCEALED),
        });
        let r_factor = if report.r_factor == UNRATED {
            0
        } else {
            report.r_factor
        };
        let mos = if report.mos_cq == UNRATED {
            1.0
        } else {
            f32::from(report.mos_cq) / 10.0
        };
        let verdict = if self.received == 0 {
            Verdict::Poor
        } else {
            [
                band(loss_percent, 1.0, 3.0, true),
                band(millis(self.jitter), 20.0, 50.0, false),
                self.round_trip.map_or(Verdict::Unknown, |rtt| {
                    band(millis(rtt), 300.0, 600.0, false)
                }),
                band(-f64::from(mos), -4.0, -3.6, false),
            ]
            .into_iter()
            .fold(Verdict::Good, Verdict::worst)
        };
        EchoQuality {
            loss_percent,
            jitter: self.jitter,
            round_trip: self.round_trip,
            one_way_delay,
            r_factor,
            mos,
            verdict,
        }
    }
}

fn millis(span: Duration) -> f64 {
    span.as_secs_f64() * 1000.0
}

/// Good up to `good`, acceptable up to `acceptable`, poor past it. `strict`
/// makes the bounds exclusive, the way "under 1 %" is.
fn band(value: f64, good: f64, acceptable: f64, strict: bool) -> Verdict {
    let within = |limit: f64| {
        if strict {
            value < limit
        } else {
            value <= limit
        }
    };
    if within(good) {
        Verdict::Good
    } else if within(acceptable) {
        Verdict::Acceptable
    } else {
        Verdict::Poor
    }
}

/// Whether a STUN or TURN part was tried, and how it went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    /// Not part of this test.
    NotTested,
    /// The server answered as hoped.
    Succeeded,
    /// It did not.
    Failed,
}

impl Probe {
    /// A STUN or TURN part's verdict: a failure is a warning, not a failure.
    #[must_use]
    pub const fn verdict(self) -> Verdict {
        match self {
            Self::NotTested => Verdict::Unknown,
            Self::Succeeded => Verdict::Good,
            Self::Failed => Verdict::Acceptable,
        }
    }
}

/// Everything one test found.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Findings {
    /// Whether a STUN server answered.
    pub stun: Probe,
    /// What its answer says about the NAT.
    pub nat: NatKind,
    /// Where it saw this end, when it answered.
    pub public: Option<SocketAddr>,
    /// Whether the TURN server allocated a relay.
    pub turn: Probe,
    /// What the account's server did, when it was asked.
    pub server: Option<ServerReach>,
    /// How the echo call fared, when there was one.
    pub echo: Option<EchoQuality>,
}

impl Findings {
    /// Nothing tested yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stun: Probe::NotTested,
            nat: NatKind::Unknown,
            public: None,
            turn: Probe::NotTested,
            server: None,
            echo: None,
        }
    }

    /// The worst verdict among the parts that were tested.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        [
            self.stun.verdict(),
            self.turn.verdict(),
            self.server.map_or(Verdict::Unknown, ServerReach::verdict),
            self.echo.map_or(Verdict::Unknown, |echo| echo.verdict),
        ]
        .into_iter()
        .fold(Verdict::Unknown, Verdict::worst)
    }
}

impl Default for Findings {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean() -> EchoMeasurement {
        EchoMeasurement {
            received: 500,
            lost: 0,
            jitter: Duration::from_millis(4),
            round_trip: Some(Duration::from_millis(40)),
            buffer_delay: Duration::from_millis(40),
        }
    }

    #[test]
    fn a_clean_echo_is_good_and_rates_near_the_g711_ceiling() {
        let rated = clean().rate();
        assert_eq!(rated.verdict, Verdict::Good);
        assert!(rated.r_factor >= 90, "{rated:?}");
        assert!(rated.mos >= 4.3, "{rated:?}");
        assert_eq!(rated.one_way_delay, Duration::from_millis(60));
    }

    #[test]
    fn two_percent_loss_is_acceptable_and_five_is_poor() {
        let two = EchoMeasurement {
            received: 490,
            lost: 10,
            ..clean()
        }
        .rate();
        assert!((two.loss_percent - 2.0).abs() < 1e-9);
        assert_eq!(two.verdict, Verdict::Acceptable, "{two:?}");
        let five = EchoMeasurement {
            received: 475,
            lost: 25,
            ..clean()
        }
        .rate();
        assert_eq!(five.verdict, Verdict::Poor, "{five:?}");
    }

    #[test]
    fn jitter_and_round_trip_each_move_the_verdict_on_their_own() {
        let jittery = EchoMeasurement {
            jitter: Duration::from_millis(35),
            ..clean()
        }
        .rate();
        assert_eq!(jittery.verdict, Verdict::Acceptable);
        let far = EchoMeasurement {
            round_trip: Some(Duration::from_millis(700)),
            ..clean()
        }
        .rate();
        assert_eq!(far.verdict, Verdict::Poor);
        assert!(far.mos < clean().rate().mos, "delay costs score");
    }

    #[test]
    fn an_echo_with_no_report_back_is_rated_without_a_round_trip() {
        let rated = EchoMeasurement {
            round_trip: None,
            ..clean()
        }
        .rate();
        assert_eq!(rated.round_trip, None);
        assert_eq!(rated.verdict, Verdict::Good);
    }

    #[test]
    fn nothing_came_back_is_poor() {
        let rated = EchoMeasurement::default().rate();
        assert_eq!(rated.verdict, Verdict::Poor);
        assert!((rated.loss_percent - 100.0).abs() < 1e-9);
    }

    #[test]
    fn the_nat_is_read_from_one_mapping() {
        let local: SocketAddr = "192.168.1.20:5060".parse().unwrap();
        assert_eq!(NatKind::of(local, None), NatKind::Unknown);
        assert_eq!(NatKind::of(local, Some(local)), NatKind::Open);
        assert_eq!(
            NatKind::of(local, Some("203.0.113.9:5060".parse().unwrap())),
            NatKind::PortPreserved
        );
        assert_eq!(
            NatKind::of(local, Some("203.0.113.9:40112".parse().unwrap())),
            NatKind::PortChanged
        );
    }

    #[test]
    fn the_verdict_is_the_worst_part_and_nothing_tested_is_unknown() {
        let mut findings = Findings::new();
        assert_eq!(findings.verdict(), Verdict::Unknown);
        findings.stun = Probe::Succeeded;
        assert_eq!(findings.verdict(), Verdict::Good);
        findings.turn = Probe::Failed;
        assert_eq!(findings.verdict(), Verdict::Acceptable);
        findings.server = Some(ServerReach::TimedOut);
        assert_eq!(findings.verdict(), Verdict::Poor);
        findings.server = Some(ServerReach::Answered {
            status: 401,
            round_trip: Duration::from_millis(30),
        });
        assert_eq!(
            findings.verdict(),
            Verdict::Acceptable,
            "a 401 is a server that is there"
        );
    }
}
