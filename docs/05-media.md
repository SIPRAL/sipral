<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Media: sipral-rtp and sipral-media

Signalling either works or it does not, and when it does not there is a trace
that says why. Media is different: it degrades, and the user calls it "the app
sounds bad". This is where a SIP stack is actually judged, and it is the part
that is written in-house rather than assembled.

## What crosses the seam

`sipral-ua` and `sipral-media` do not call each other and do not depend on each
other ([01-architecture.md](01-architecture.md)). Two values pass between them,
and the application carries both:

```rust
/// What the negotiation settled on. Built in `sipral-core::sdp` out of the
/// offer and the answer, and consumed by whatever owns the media — in this
/// tree that is `MediaSession` in the `sipral` facade, which is what turns a
/// plan into an RTP session and a codec. Emitted again, unchanged but for the
/// fields that moved, after every re-INVITE or UPDATE that changes the
/// session.
pub struct MediaPlan {
    pub local: SocketAddr,          // where to receive; the caller chose it
    pub remote: SocketAddr,         // where to send, from the answer's c= and m=
    pub codec: NegotiatedCodec,     // payload type, clock rate, channels, fmtp
    pub direction: Direction,       // sendrecv, sendonly, recvonly, inactive
    pub dtmf: Option<u8>,           // telephone-event payload type, when agreed
    pub rtcp: RtcpPlan,             // muxed, a second port, or off
    pub keying: Option<Keying>,     // SDES material, or a DTLS fingerprint
}

/// And back the other way, before an offer is written: what this build can
/// actually do. An agent build has no device and no device rate, so it answers
/// a shorter list than a softphone does.
pub struct MediaCapabilities {
    pub codecs: Vec<NegotiatedCodec>,
    pub dtmf: bool,
    pub rtcp_mux: bool,
    pub srtp: SrtpSupport,
}
```

Neither mentions a socket, a device, a thread or a codec implementation, which
is what lets one `sipral-ua` drive a softphone and an agent that puts PCM on a
socket. Both live in `sipral-core::sdp`, next to the offer/answer machinery that
produces them. The media crates do not read them: `sipral-media` and
`sipral-rtp` name no Sipral crate in their manifests at all, and the `sipral`
facade is what turns a plan into the arguments they take. That is what keeps
the seam a shared vocabulary rather than a call.

## sipral-rtp

### RTP

RFC 3550. Sequence numbers with wraparound, timestamps per clock rate,
contributing sources parsed and ignored. Marker bit on talk spurt start, which
is the audio profile's rule (RFC 3551 §4.1), not RFC 3550's. There is no SSRC
collision handling (§8.2): the two directions of a call are keyed apart, so a
collision is not a reuse of keystream, and a stream follows the one remote
source it latched onto.

**Symmetric RTP always.** Send from the port we receive on, and latch onto the
source address of the first valid packet. This single behaviour, together with
`rport`, is what makes most NAT traversal unnecessary.

Validation before anything else: version, payload type in the negotiated set,
plausible SSRC, length. The one widening of that set is G.711's other law: a
call agreed on one companding law also takes the other's static payload type,
because a peer that answers with one law and sends the other is real, and
`sipral::MediaSession` decodes such a frame with the law its payload type
names rather than refusing it as silence. Packets from an unexpected source after latching are
dropped, not merged — and dropped first, ahead of that validation and ahead of
SRTP, since the address is the one check that reads nothing out of the
datagram. A copy that SRTP had already taken would have spent its index in the
replay list, and the genuine packet from the peer would then be the one refused.

### RTCP

The wire format — SR, RR, SDES, BYE, the compound-packet rules of §6.1, and
telling RTCP apart from RTP on a muxed socket (RFC 5761 §4) — is
`sipral-rtp::rtcp`. Deciding when to send one and what to make of one that
arrived is `RtpSession` in `sipral-rtp::endpoint`, backed by two modules that do
the RFC's own bookkeeping: `rtcp_timer::IntervalTimer` for §6.2's transmission
interval and §6.3's join/leave/reconsideration state machine, and
`rtcp_stats::ReceptionTracker` for §6.4.1's report-block arithmetic and the
round-trip calculation of A.3 and A.8. Driving both, per call, is `MediaSession`
and `MediaEngine` in the `sipral` facade.

**What is generated.** `RtpSession::build_report` writes one compound packet:
an SR when this session has sent RTP since the previous report
(`Outbound::sent_since_report`), an RR otherwise — never both, and never an SR
from a stream that sent nothing in the last interval, which is one interval
stricter than §6.4 (see the departures below) — carrying a
reception report block for the remote source once one is known
(`ReceptionTracker::block`: fraction lost and cumulative lost over the
interval since the last report per §6.4.1/A.3, interarrival jitter per A.8,
and LSR/DLSR from the last SR heard from that source), plus an SDES chunk
naming this session's own CNAME (`StreamConfig::cname`, defaulted to
`sipral@<local-ip>` in `sipral::session` when the application does not choose
one — RFC 3550 §6.5.1's "user@host" form). The CNAME chunk is unconditional:
every compound packet built here carries one, which is what §6.1 requires of
all of them. Hanging up sends one more packet that is not on this schedule:
`RtpSession::send_bye` builds a BYE (§6.6) for this stream's own SSRC with an
empty reason, from `MediaSession::goodbye`, queued in
`MediaEngine::farewells` because the call and its session are already gone by
the time there is anything left to send it from (see the doc comment on
`MediaEngine::poll_farewell`). §6.3.7 lets a session below fifty members send
that BYE immediately without resetting who it counts as members and senders
(`IntervalTimer::sent_bye`); only a session past that threshold executes the
full reset the RFC also allows (`IntervalTimer::leaving`) — a distinction
`RtpSession::bye_should_back_off` exposes, though a two-party call never
crosses it.

**When, and how often.** `MediaEngine::poll_rtcp` asks each call in turn
whether its deadline has passed (`MediaSession::rtcp_deadline_passed`); the
actual send-or-wait decision, with the reconsideration §6.3.6 describes, is
`RtpSession::rtcp_due` over `IntervalTimer`, which is §6.2's calculated
interval and §6.3's state for it: the sender share of §6.3.1 point 1 (A.7's
`RTCP_SENDER_BW_FRACTION`: a quarter of the RTCP bandwidth divided among
senders and the rest among everyone else while senders are at most a quarter
of the members, all of it divided among every member once they are more — so
on a two-party call the split holds only until either side sends RTP), a
five-second floor once the session is no longer new and half of that for the
very first report (§6.2), a running average of compound-packet sizes that both
sent and received packets fold into (`IntervalTimer::observe`, counting the
UDP payload only — see the departures below), the interval's own random draw
scaled to
`[0.5, 1.5)` and divided by `e - 3/2` to undo reconsideration's bias (§6.3.1
point 5, A.7), and reverse reconsideration — pulling the next deadline
forward — when a member's BYE arrives (§6.3.4, `IntervalTimer::remove_member`).
The random draw itself is `Draws::unit` in `sipral::session`: a seeded
SplitMix64 generator, deliberately not a source of secrecy, since a
predictable report time leaks nothing but when the next report goes. That
includes the very first report: `MediaSession::open` draws from it before
`RtpSession::new`/`RtpSession::protected` are ever called, rather than
handing the constructor a fixed number, so the first interval is randomised
exactly like every later one and two calls opened from the same catalogue do
not schedule their first report at the same point in it.
The one number that scaling starts from is fixed: `RTCP_BANDWIDTH` in
`sipral::session`, five hundred octets per second — five percent of a
two-party narrowband call's roughly ten-kilo-octet-a-second wire rate, which
is also small enough that the five-second §6.2 floor, not the
bandwidth-derived figure, is what actually sets the cadence for a call this
size. In practice that puts a report on the wire roughly every two to a
little over six seconds once the session has settled — the exact figure moves
with each random draw and with which side has sent since the last one — and
the very first one sooner, inside half that span.

**What it reads back.** `RtpSession::rtcp_receive` parses the compound packet
and refuses to believe any of it unless it came from the address this stream
has latched RTCP onto (`rtcp_origin_accepted` — see its doc comment for why
that check runs before anything in the packet is trusted). For every SR or RR
inside, the block naming this session's own SSRC gives the round-trip time
(`RtpSession::note_round_trip`, `rtcp_stats::round_trip_time`, §6.4.1's
`A - LSR - DLSR` from A.3, `None` until the peer has echoed an SR of ours); an
SR from the remote source is separately remembered
(`ReceptionTracker::on_sender_report`) so this session's own next report can
carry that source's LSR and DLSR. A BYE naming the remote SSRC — matched
against whichever identifier this session actually has for it,
`Inbound::source` when RTP set one or `Inbound::rtcp_source` when only RTCP
ever has, which is all a recvonly peer or a call on hold ever gives it —
drops it from the interval timer's membership and sender counts once
(§6.3.4) and is reported to the caller as `Arrival::Goodbye` from
`MediaSession::receive_control`
(or from `MediaSession::receive`, which hands it RTCP on a muxed socket) —
audio is assumed to stop, but the call itself ends only when signalling says
so, which is `sipral-ua`'s decision, not this crate's. "Once" is load-bearing:
`Inbound::departed` marks the source as gone (§6.2.1's "the entry SHOULD be
marked as having received a BYE") so a repeated BYE for it — a retransmission,
or a duplicate the network made — is still reported but no longer removes
anything: not a second member, and not a second sender, which on a call this
end is sending on would be this end's own entry. Underneath that,
`IntervalTimer::remove_member` never counts below one, the local participant
itself (§6.3.2). Once this end has sent its own BYE, though, a BYE arriving
afterwards is not removed at all: §6.3.4's own rule for a received BYE
excludes "the case when an RTCP BYE is to be transmitted", and
`IntervalTimer::is_departing` — set by `RtpSession::send_bye`, whichever of
its two branches ran — switches the handling to §6.3.7 bullet two instead,
which counts the departure up rather than down
(`IntervalTimer::note_bye_while_departing`): a far end's BYE crossing ours on
the wire grows the count the next interval is computed from, rather than
shrinking it. An incoming SDES is parsed
(`rtcp::SourceDescription`) but nothing here reads its content; only its
presence is required, to keep the compound packet the shape §6.1 demands.

**What reaches the application.** `MediaSession::statistics` returns
`StreamStatistics`: the negotiated codec, `Quality` from the jitter buffer
(packet counts, loss, jitter and delay, measured from arrival times rather
than from RTCP, so it stands even on a call that negotiated none), the
`round_trip: Option<Duration>` read back above, and this session's own send
counters. `StreamStatistics::score` folds the worst of loss, round trip and
buffer delay into one 0-to-100 number for a screen — explicitly not a MOS,
which its doc comment says outright — and `StreamStatistics::is_suffering`
answers whether the call is in trouble right now. None of this arrives as an
event on its own: it is polled, cheaply, at whatever rate the application
wants, except at the end of a call, where `MediaEvent::Ended` carries one
final `StreamStatistics` snapshot so the record of how a call sounded outlives
the session. The one thing that does arrive as news mid-call is
`Arrival::Goodbye` above, and — correlated with RTCP's silence but not derived
from it — `MediaEvent::Stalled` when audio itself stops arriving.

**Whether it happens at all.** RFC 3556's `b=RS:0` and `b=RR:0`, on either
side, turn RTCP off for a stream entirely (`sdp::plan::rtcp_refused`), the
same as a media port of 65535 with no `a=rtcp` line to say where RTCP would
go. `a=rtcp-mux`, agreed by both sides, shares the RTP port instead of the
classic even/odd pair (`RtcpPlan::Muxed`, RFC 5761 §4) — told apart from RTP
on the wire by `rtcp::is_rtcp`'s read of §4's reserved packet-type span.
`sdp::plan::RtcpPlan` carries the outcome into `MediaPlan::rtcp`.

**Where this departs from RFC 3550 §6.2 and the rules built on it.** Four
places, plainly:

1. §6.2 sizes the RTCP bandwidth as a fraction of the session's own bandwidth
   — the bit rate the negotiated codec actually uses. This stack does not read
   that back out of the negotiation: `RTCP_BANDWIDTH` is one constant, sized
   for a 64 kbit/s codec (G.711, or G.722 at the same bit rate), not derived
   per call from `MediaPlan::codec` — so not re-derived when Opus, the default
   build's first choice, is negotiated at whatever rate its encoder runs — nor
   from a negotiated `b=AS`, `b=RS` or `b=RR`; of those, only `b=RS:0` together
   with `b=RR:0` is read, and only as "off". A stream running at a very
   different rate would need a bandwidth figure of its own, and nothing here
   computes one automatically.
2. §6.2 counts the UDP and IP headers in every bandwidth and packet-size
   figure, and §6.3.1 defines `avg_rtcp_size` to include them. The sizes
   `IntervalTimer` averages do not: `RtpSession::rtcp_receive` hands
   `IntervalTimer::observe` the datagram's length, and
   `RtpSession::build_report` hands `IntervalTimer::sent` the octets it wrote,
   so the average runs 28 octets (IPv4) or 48 (IPv6) short of what §6.2 means,
   while `RTCP_BANDWIDTH` is derived from a rate that does include headers. On
   a two-party call this changes nothing observable — the size-derived
   interval is well under the five-second floor either way — but the two
   figures are not in the same units.
3. §6.3.5 ("Timing Out an SSRC") asks a participant assumed gone — nothing
   heard from it in five calculated intervals — to be dropped from membership
   even without a BYE, and a sender silent for two intervals to be dropped
   from the sender count. Nothing here runs either sweep: `IntervalTimer` only
   loses a member or a sender when a BYE actually arrives (§6.3.4, above), and
   this session's own `we_sent`, which §6.3.8 clears after two intervals
   without RTP, is set by `IntervalTimer::note_local_sender` and cleared only
   by `IntervalTimer::leaving` — the branch of `RtpSession::send_bye` reserved
   for a session past the fifty-member backoff threshold; the ordinary path,
   `IntervalTimer::sent_bye`, leaves `we_sent` as it was, since nothing below
   that threshold asks a session to forget who was sending. The consequence
   is bounded for the two-party
   call this crate targets — a far end that stops sending without a BYE is
   `MediaEvent::Stalled`'s job to notice, not the RTCP scheduler's — but the
   interval timer's own counts will not reflect it, which matters the day this
   scheduling code is asked to serve more than two members.
4. §6.4 issues an SR when a site "has sent any data packets during the
   interval since issuing the last report or the previous one". The choice in
   `RtpSession::build_report` looks at the last interval only, because every
   report clears `Outbound::sent_since_report`: a stream that falls silent
   sends RRs one interval sooner than §6.4 says.

### RTCP XR and voice quality reports (task 8.6.9)

RFC 3611 defines the Extended Report packet type (§2, `rtcp::XR` = 207 in
the compound) and the VoIP Metrics Report Block it carries (§4.7):
`rtcp_xr::VoipMetricsBlock`, read and written by `rtcp_xr::XrPacket` and
`rtcp_xr::XrPacketBuilder` the same way every other RTCP packet type in
this crate is. `RtcpPacket::ExtendedReport` is its own variant rather than
folded into `RtcpPacket::Other`, so a peer's XR packet can be told apart
from one this crate does not define, though nothing here reads the far
end's own block back into anything the application sees — see below.

**Negotiation.** §5's `a=rtcp-xr` attribute, with the `voip-metrics` token,
decides whether a stream sends the block at all: `sipral-core`'s
`sdp::plan::MediaCapabilities::voip_metrics_xr` writes it into every offer
this stack makes (on by default — every build of this crate can generate
and read the block), `sdp::plan::MediaPlan::voip_metrics_xr` reads it back
off whichever description asked for it — the peer's, since §5.2 has each
side's own line request the block *from the other party* — falling back
from the media level to the session level per §5.1, and
`sipral-ua::session::carried` repeats this end's own line across a hold or
an unrelated re-INVITE the same way `rtcp-mux` already is.
`RtpSession::build_report` reads the negotiated flag off `StreamConfig`
and appends an XR packet to the compound only when it is set.

**What the block reports, and how it is measured.** `voip_metrics::GminTracker`
implements RFC 3611 Appendix A.2's event-driven burst/gap classification
verbatim — the state names (`c11`, `c13`, ...) match the appendix's own
pseudocode so a reviewer can check the two side by side — fed by
`playout::JitterBuffer` exactly once per sequence number as its fate is
resolved: `Received` or `Lost` at `JitterBuffer::pull`, `Discarded` or
`Lost` at a window jump in `JitterBuffer::slide`. `Gmin` is fixed at its
RFC-recommended 16 for the life of a buffer (§4.7.2). Round-trip delay is
this session's own `round_trip_time`; end-system delay is always `0`
(§4.7.3's own fallback: this crate has no visibility into the sending
side's encode-and-accumulate delay); jitter buffer sizing comes from
`playout::Quality`; every signal-related field (§4.7.4) is RFC 3611's own
`127` "unavailable" sentinel, since nothing in this crate measures a
signal or noise level over decoded audio.

**The R factor and MOS.** `emodel::evaluate` is a simplified ITU-T G.107
E-model: it takes G.107's own default value for every transmission
parameter this crate cannot observe (§7.7's own "R = 93.2" baseline at
every default) and computes only what a call actually measured — the
delay impairment `Id` from one-way delay, and the codec/loss impairment
`Ie,eff` from the codec's G.113 Appendix I `Ie`/`Bpl` pair and the
measured loss rate. `emodel::codec_quality_model` tabulates G.113 Table
I.4 for the one codec family it covers (G.711); the facade
(`Codec::quality_model` in `sipral`) maps this crate's own codec catalogue
onto it, `None` for G.722 and Opus, which G.113 does not tabulate — RFC
3611 §4.7.5's own answer for a metric this stack cannot honestly compute
is the sentinel, not a guess, and `emodel::evaluate` returns exactly that
when handed `None`.

**Where it surfaces.** `RtpSession::voip_metrics` assembles the whole
block — independent of whether XR reporting was negotiated, since the
same figures also feed the RFC 6035 quality report below — and
`MediaSession::statistics` carries it as `StreamStatistics::voip_metrics`,
`None` until a source is known. `sipral-ffi`'s `sipral_stream_stats_t`
carries the same figures at its tail, each `voip_*` member paired with a
`has_voip_*` flag for the fields RFC 3611 can report as unavailable.

**The RFC 6035 report.** When a call ends, `MediaEngine::release` builds
`sipral_ua::QualityReportMetrics` from the stream's `VoipMetricsBlock` and
its own wall-clock span (`MediaSession::quality_report_metrics`,
`MediaSession::session_span`) and hands it to
`UserAgent::send_quality_report`, which publishes it as a `VQSessionReport:
CallTerm` (RFC 6035 §4.6.1) over a PUBLISH (RFC 3903) with `Event:
vq-rtcpxr`, `Content-Type: application/vq-rtcpxr`, when the call's account
named a collector (`Account::quality_report_uri`) — a no-op otherwise, so
nothing is sent for the common case of an account that never asked. The
PUBLISH's own `Expires: 0` closes its published state at once: the report
describes a call that has already ended and nothing refreshes it, and a
collector that never answers has cost this end one datagram, never a
retry. `MediaEvent::QualityReportSent` says whether the attempt went out,
raised only when there was a collector to publish to at all. Only
`LocalMetrics` is written; `RemoteMetrics` would be what the far end
measured about this stream, and this crate has no channel to receive it.

### Jitter buffer

The component that decides whether calls sound good, and therefore ours.

Adaptive, not fixed. It tracks the arrival-time distribution and targets the
delay that keeps the underrun rate below a threshold, rather than a delay
someone configured once. Design targets:

- **Target delay** is a high percentile of recent jitter, with fast growth on
  a burst and slow shrink after it, so a single bad second does not cost a
  minute of extra latency.
- **Adjustment happens in silence.** Time scaling during talk spurts is audible;
  stretching or dropping a pause is not. Silence detection drives the
  adjustment schedule.
- **A pause is not path delay.** Some senders stop their RTP clock while they
  are quiet, against RFC 3550 §5.1, so every packet after the pause looks late
  by all of it. The first packet of a talk spurt (the marker bit, RFC 3551
  §4.1) that looks later than the target allows for is taken as a new start
  for the delay measurement: its own lateness can only lengthen a pause the
  sender chose. Seen from FreeSWITCH at the start of a DTLS-SRTP call.
- **A stream that comes back further on starts there.** When playout has run
  dry and the next packet is some sequence numbers ahead, those numbers are
  counted lost and playout starts at the packet, rather than concealing the
  gap and keeping it as delay. A packet stranded in front of such a gap, one
  that came too early to start on and is then older than anything after it
  by more than the target, is dropped unplayed for the same reason. Packets
  held together with no such gap are all played, however many. Seen from
  Asterisk on a DTLS-SRTP call, at the start and again after a resume.
- **Reordering is normal**, not an error. Late packets that still fit the window
  are inserted.
- **Duplicates are dropped** on sequence number, cheaply.
- **The buffer never grows without bound.** A stalled consumer discards, and
  reports it.

Measured against the exit criterion in [10-roadmap.md](10-roadmap.md): mean
opinion score under simulated loss and jitter, compared side by side with a
reference stack on the same impaired network, using `tc netem` profiles that are
committed with the tests.

The algorithm is derived from the published literature on adaptive playout,
including the NetEq design as described in its papers. No implementation is
read while writing it; see [02-clean-room.md](02-clean-room.md).

### Packet loss concealment

Loss on a real mobile network is not exceptional. Concealment is per codec:

- Opus has in-band forward error correction and its own concealment; use them.
- G.711 has neither. Pitch-based waveform extension for short gaps, with
  amplitude decay into silence for long ones, and a smoothed cross-fade when the
  stream resumes. Bounded: past a few frames, concealment sounds worse than
  comfort noise.

### DTMF

RFC 4733 telephone-event: correct event codes, volume, duration, the end bit and
its two retransmissions (the final packet goes out three times in total, RFC
4733 §2.5.1.4). On receive, the redundant packets for one event
collapse into a single reported digit, which is the bug everyone ships at least
once.

**What the schedule costs, and where it lives.** `sipral-rtp` writes the packet
and knows what §2.1 does to the sequence number and the timestamp; it never
sees a frame boundary, so it cannot know when the next one is due. The facade
does, and drives it one packet per captured frame — which §2.5.1.2 names as the
natural choice, "the spacing between non-event audio packets". Two consequences
are properties rather than details:

- **A digit replaces the audio for as long as it lasts.** §2.1 has an event use
  the audio stream's own sequence numbers and timestamps, so both cannot be on
  the wire at once. The two repeats of the closing packet report a duration
  already reported and so move the audio clock by nothing; the frame of real
  time each takes is accounted for as silence.
- **Keys queue.** Somebody entering an extension presses four of them faster
  than four digits can be sent, and all four have to arrive. So a key pressed
  while another is going out waits its turn, and the pause between them —
  40 ms is the floor RFC 4733 §2.5.2.1 takes from ITU-T Q.24, and 60 is what is
  held — needs no timer in the application. The queue is bounded at
  thirty-two, and a dial string with a character no keypad has queues nothing
  at all, because half an extension is worse than none: it reaches somebody.

A digit shorter than 40 ms is refused where it is asked for rather than sent
and not heard, as is one longer than ten seconds, and a call whose
negotiation settled on no telephone-event payload type says so instead of
swallowing the key. Both bounds are read through `sipral_ua::dtmf`, the same
validation a digit sent by INFO goes through, so neither sending form takes a
length the other refuses; a digit *received* by INFO shares only the ceiling
(`docs/04-ua.md`), because reading how long a peer already held a key needs
no floor of its own. The hundred-millisecond default a length of zero asks
for is shared the same way sending's bounds are — `sipral_ua::dtmf`'s own
`DEFAULT_DTMF_MS`, which `sipral::DEFAULT_DIGIT` reads rather than keeping a
copy of the same number (8.3.11-bis).

**The other way a digit crosses, and where the two meet.** 8.3.11 gives
`sipral-ua` its own INFO-based DTMF (`docs/04-ua.md`), sent and received
without ever touching the media path this crate owns. What `sipral-ua`
raises for an incoming one is `UaEvent::DtmfReceived`, not a `MediaEvent` —
that layer has no media of its own to make one of. This crate is what joins
the two: `MediaEngine::poll_event` reads that event off the signalling
stream before it ever reaches the application, folds it into the same
`MediaEvent::DigitReceived` an RFC 4733 event produces, and queues it where
the media events already are — so the `UaEvent` itself is never forwarded as
`Event::Signalling`. One new member, `DigitSource`, says which of the two
carried it; everything else about the event — `digit`, `event`, `held` — reads
the same regardless, with `held` at `None` for the one INFO body that carries
no duration at all (`application/dtmf`) — not `Duration::ZERO`, which stays
what a peer sending the other body actually said with its own `Duration=0`
(8.3.11-ter). An application that only ever watched `MediaEvent::DigitReceived`
for RFC 4733 keeps working unchanged: the new member is additive, and nothing
changes what was already there.

### SRTP

Written in-tree from RFC 3711, over one borrowed primitive: the `aes` block
cipher, for the reason `THIRD-PARTY-NOTICES.md` gives. Counter mode and f8,
HMAC-SHA-1, the key derivation, the implicit packet index of §3.3.1 and the
replay window of §3.3.2 are all here, proved against the test vectors in the
RFC's own Appendix B. Linking libsrtp2 was the earlier plan and was dropped:
it is C, this crate denies `unsafe`, and a memory-safe stack that hands every
arriving packet to a C parser is not one.

The three suites RFC 4568 defines — `AES_CM_128_HMAC_SHA1_80`,
`AES_CM_128_HMAC_SHA1_32` and `F8_128_HMAC_SHA1_80` — with the first as the
baseline. `UNENCRYPTED_SRTP`, `UNENCRYPTED_SRTCP` and `UNAUTHENTICATED_SRTP`
are honoured where a peer insists; SRTCP's tag stays at eighty bits whatever
the suite says about SRTP's, because §5.2 forbids shortening it. Key material
is zeroised on drop. Unencrypted RTP arriving on a secured session is dropped,
never accepted as a fallback.

The session owns it rather than the caller. `RtpSession::protected` takes the
two master keys the negotiation produced — one for each direction, because RFC
4568 §7.1.1 forbids using one key for both — and from then on everything built
goes out protected and everything arriving is verified before any of it is
believed. The caller's only new obligation is a buffer larger by
`rtp_overhead()`, and a buffer that is not is refused before a sequence number
is spent. Leaving protect and unprotect to the caller would have been less
code here and one more thing for every integrator to get wrong in the same
way.

SDES key exchange through `a=crypto` in SDP for the common case, and
DTLS-SRTP for the peers that require it and refuse SDES — a browser talking
WebRTC directly, and some carrier session border controllers. Both are
reachable from a call; which one a call uses is `SrtpPolicy`, and the two
never appear in the same description, because a description carrying both has
agreed to neither.

The way in was decided on 10 September 2026: **written in-tree**, because
`rustls` carries no DTLS and the alternatives are single-maintainer crates. The DTLS 1.2 state machine comes from RFC 6347 — both roles
per `a=setup` (RFC 4145), the record layer with its epoch and anti-replay
window, fragmentation and retransmission of the handshake flights, the
`use_srtp` extension and the key export of RFC 5705, the peer's self-signed
certificate checked against `a=fingerprint` and against nothing else, no
renegotiation and no resumption. The primitives it needs — P-256 for ECDHE and
ECDSA, AES-GCM, SHA-256, HMAC, and checking an RSA signature — are not written
here: a constant-time
elliptic curve is the one place a home-grown implementation is a risk rather
than a virtue, so they come from the permissively licensed crate family that
already supplies AES, each listed in the notices. The random values a
handshake needs come from the engine's own seed, which the application draws
from the operating system's entropy; a seed that is not is a handshake that
is not. The code is reviewed adversarially before it ships under the
commercial licence. An application that already runs DTLS of its own can
still export its keys per RFC 5705 and hand them to the engine through the
seam SDES uses, which costs one function and keeps the gateway case cheap.

**What the handshake is made of.** `crates/sipral-dtls` holds DTLS 1.2 for
either end of a DTLS-SRTP call, and a call reaches it through the facade's
`dtls` feature. Underneath, each piece
tested on its own: the TLS 1.2 PRF with SHA-256, the master secret and RFC
7627's extended master secret, the Finished `verify_data` and the record key
block; the RFC 5705 exporter and the key layout of RFC 5764 §4.2 for
`SRTP_AES128_CM_HMAC_SHA1_80` and `_32`; the record layer with its epoch and
48-bit sequence number, AES-128-GCM protection per RFC 5288 and the
anti-replay window of RFC 6347 §4.1.2.6; handshake fragmentation to a path MTU
and reassembly bounded in message length, pieces and memory; strict codecs for
every message of an `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` or
`ECDHE_RSA_WITH_AES_128_GCM_SHA256` handshake, with
HelloVerifyRequest cookies and the `use_srtp`, `supported_groups`,
`ec_point_formats`, `signature_algorithms`, `extended_master_secret` and
`renegotiation_info` extensions; P-256 keys made from randomness the caller
supplies; and a self-signed certificate written in DER, the key — P-256 or
RSA — read out of a peer's, and fingerprints — `sha-256` written, `sha-1` also read — compared in
constant time.

On top of that, `Connection`: the client and server state machines, sans-I/O
in the shape of the rest of the tree — datagrams and the time in; datagrams, a
timeout and events out. It does what DTLS-SRTP needs and nothing more. Both
ends present a certificate (RFC 5763 §5): a server always asks for the
client's, a client refuses a server that does not ask, and each checks the
other's against the fingerprints its signalling carried — those under the
most preferred hash offered, as RFC 8122 §5.1 has it — and against nothing
else. A server exchanges a stateless HelloVerifyRequest cookie before doing
any work, and until the cookie comes back reads nothing but a whole
ClientHello and answers nothing that does not parse. `use_srtp` is required in
both hellos; the server chooses, in its own order of preference, from the
client's list, and no MKI is ever agreed. Flights go out again on RFC 6347
§4.2.4.1's timer — one second, doubled, capped at sixty, six attempts — and a
peer that sends its previous flight again is answered with the last flight
sent, never by processing its flight a second time. Finished is the only
handshake message accepted protected and the only one not accepted in the
clear, so it can only come from whoever holds the keys, and the SRTP keys and
any application data are released only once the peer's Finished has been
verified against the transcript. A failure sends one fatal alert naming why;
`close_notify` is answered; renegotiation is refused with `no_renegotiation`,
as RFC 8827 §6.5 requires; an invalid record is dropped without a word. Which
end is the client comes from `a=setup` through `setup::dtls_role`, a pure
function of RFC 4145's table: the active end sends the ClientHello.

This end's own key is always P-256, and it signs with nothing else; the
peer's may be RSA as well. FreeSWITCH, left as it ships, certifies its
DTLS-SRTP end with an RSA-4096 key, and a peer like that cannot be keyed with
at all otherwise: as a client it withholds its certificate from a request
that names ECDSA alone, and as a server it can choose no suite a client
offering only `ECDHE_ECDSA` would take. So a server asks for either kind
(`ecdsa_sign` and `rsa_sign`, each with SHA-256), and a client offers
`ECDHE_RSA_WITH_AES_128_GCM_SHA256` after the ECDSA suite and holds the
server's certificate to the kind of key the suite it chose names (RFC 8422
§2.1, §2.2). An RSA signature is checked as RSASSA-PKCS1-v1_5 over SHA-256,
by rebuilding the whole padded block and comparing it rather than parsing
it, under a key of 2048 bits at least (RFC 9325 §4.5) and 8192 at most. The
arithmetic is the `rsa` crate's, which is used to verify and never to sign
or decrypt.

The join — the `a=fingerprint` and `a=setup` lines, the RFC 7983
demultiplexing, `SrtpPolicy` and `MediaSession` — is described in the sections
that follow, and the lab keys calls with it against both Asterisk and
FreeSWITCH. One choice shapes every peer the join meets: the extended master secret is required, because RFC 7627 §5.4 requires
a session without it to disable RFC 5705, the exporter every DTLS-SRTP key
comes out of. RFC 5764 and RFC 8827 never mention the extension, so a peer
whose TLS library predates RFC 7627 is one this crate will not key SRTP with.

Two choices in the layers below the handshake go the way a reader might not
expect. When two fragments of one handshake message disagree — and in epoch 0
neither is authenticated — the later one replaces what was held: keeping the
first would let one forged fragment arriving ahead of the genuine message
refuse that message and every retransmission of it, whereas now an injector
has to keep pace with every retransmission instead of winning once. For the
same reason, when the octets reassembly holds run out, a message takes its
room from messages held further ahead, the furthest first: two forged
fragments announcing the longest message allowed, numbered past the flight,
would otherwise fill the budget and refuse the genuine flight for good. And a
hello's extensions are checked for a duplicate type by sorting the types
once, not by searching the list per extension, which on a 64 KiB block of
empty extensions was a hundred million comparisons for one datagram.

### SRTP through the facade

Everything above is the crate. The `sipral` crate is what joins it to a call:
`CodecCatalog::with_srtp` says what one call does about keys, and it sits on
the catalogue rather than on `MediaConfig` because it decides what goes into
an offer, which is what the rest of the catalogue is. Per call, not per stack,
for the reason D6 gives in
[13-client-requirements.md](13-client-requirements.md), which is where every
letter-and-number requirement this page cites is written out: an attended
transfer holds two calls at once and the consultation leg does not have to
agree with the call it stands in for.

| `SrtpPolicy` | The offer this end writes | A plain offer arriving | An offer arriving on `RTP/SAVP` |
|---|---|---|---|
| `NotOffered` — **the default** | `RTP/AVP`, no key in the body | answered plainly | answered, with a key of our own |
| `Offered` | `RTP/SAVP`, one `a=crypto` | answered plainly | answered, with a key of our own |
| `Required` | `RTP/SAVP`, one `a=crypto` | **not answered at all** | answered, with a key of our own |

**Why the default is off.** `a=crypto` carries the master key in the SDP body,
so over plain UDP or TCP it travels in the clear and anyone on the path can
decrypt the media — RFC 4568 §7 makes the mechanism depend on the signalling
being protected. Whether it is protected, this crate cannot see: `sipral-ua`
offers no way to ask which protocol a bound transport speaks, and the
application, which bound it, is the only one that knows. The second half is
`docs/06-nat.md`'s rule — a mechanism that only helps against a peer that
supports it is negotiated, never assumed. An offer on `RTP/SAVP` to a PBX that
does not do SRTP has its stream refused outright, and the PBX this project is
tested against is such a PBX, so the call that was meant to be encrypted is a
call with no audio in it. The offer is therefore off until an application
turns it on, per call.

**Why answering is not off with it.** The default is about what this end
writes. A peer that has already put `RTP/SAVP` and a key in front of us has
asked for encryption; refusing there would turn a call that would have worked,
encrypted, into a silent one, and buys nothing. So every policy answers a
secure offer with a key, and only `Required` refuses a plain one.

**Why `Offered` and `Required` are two settings.** They write the same offer,
and a peer that refuses `RTP/SAVP` leaves the call with no audio under both —
this stack does not follow a refusal with a plain re-offer. They differ in one
place, and it is the place where a downgrade would otherwise be silent: an
offer that arrives without keys. Under `Offered` it is answered, and a caller
who would rather have a plain call than none gets one. Under `Required` it is
not: `MediaEngine::answer` returns `MediaError::SrtpRequired` without sending
anything, so the call is still ringing and the application picks the status
code; and a plain re-offer inside a live call is rejected with 488 rather than
accepted, which is the case that matters, because the alternative is a call
that started encrypted, stopped being encrypted, and told nobody.

**Where the key comes from.** The engine's own seed, and not the endpoint's.
`MediaEngine::new` takes thirty-two bytes of its own; each key is one block of
`SHA-256(media seed || counter)`, with a counter that never repeats, which is
also what RFC 4568 §7.1.2 needs when it requires the answer's key to differ
from the offer's.

They are a second draw rather than a slice of the first because the endpoint's
seed is written in clear into every replay recording (`docs/18-replay.md`).
One generator for both would have put every key the stack will ever offer into
every recording it makes — including recordings taken to diagnose something
else entirely, by somebody who was told the file holds only what a capture
holds. The C ABI refuses the two seeds being equal, since `sipral_stack_create`
is the one place that can see both.

**Nothing that carries key material derives `Debug`.** RFC 4568 §9.2 says the
SDP "MUST be protected", and a `{:?}` on a live stack is not protection — it
reaches every call at once, and it lands in a file that is kept. The rule is
not "remember to redact when you print a description": that is a rule a user
agent, a call, an engine and an event each have to follow, and the first one
that forgets prints every key on the machine.

So the redaction sits at the bottom, on the four types that actually hold the
material, and every holder above them may derive `Debug` freely. `Attribute`
prints an `a=crypto` line with its tag and suite and `<redacted>` where the key
was — the line is worth seeing when a negotiation has gone wrong, and neither
of those two is secret. `KeyLine` is the deprecated `k=` line (§5.12), which
this stack never writes and never reads a meaning from, but which a
description parsed from a peer keeps: it prints nothing at all. `KeySalt` is
the key itself. `Push` is not key material but is the same shape of secret — a
token that wakes a device, which RFC 8599 §4.1 keeps off every request but
REGISTER for that reason. `scripts/check.sh` refuses a build in which any of
the four grows a derive or loses its own.

`Display` on the SDP types is a different matter and does write the key: that
is the wire format, and the wire format is what these values came from.

**A poor media seed costs the whole of the encryption** — an attacker who can
guess those thirty-two bytes can derive every master key this stack will ever
offer — and nothing about a call made with one looks wrong. That is the same
bargain the rest of the tree makes about entropy, and this is the place where
losing it is silent. The key itself lives in `KeySalt`, which has no `Debug` worth the name
and zeroises on drop; the engine's own `Debug` prints every `a=crypto` line
with its keying information replaced, since that is the last place the same
material is still text.

**When a re-negotiation moves the keys.** RFC 4568 §7.1.4 makes a re-offer an
opportunity to re-key, and the new keys reach the running stream: `adopt`
compares each direction against the one it is running and hands `RtpSession`
what moved, so the far end's answer to a hold, a resume or a session refresh
is heard, and so is a far end that re-keys in a re-offer of its own — which
this facade answers, as "Re-offers on a secured call are answered here" below
explains. Three things about the answer direction are worth stating, because
getting any of them wrong is silent.

*It is per direction.* Each end keys what it sends, so an answer that moves
only the far end's key must leave our own sending context alone, and the other
way round. A comparison on the whole of the keying restarts the untouched half.

*It compares the key material, not the terms around it.* A line may keep its
`inline:` and change only the crypto suite — `AES_CM_128_HMAC_SHA1_80` giving
way to `_32` keeps all thirty octets and shortens only the tag. §4.3.1 derives
the session keys from the master key, the salt and the packet index and from
nothing else, so those two lines produce the same keystream. The transform
follows; the packet index does not restart, because restarting it would spend
that keystream a second time. A new master key is the opposite case: the index
starts again, since §9.1 asks only that (key, SSRC, index) never repeat and a
key that has never been used cannot repeat one.

*The key being replaced outlives the answer by a little.* The far end names
its new key in SDP and then starts using it, and the two cross on the wire, so
everything still in flight is under the key being replaced. The receive
context that was replaced keeps opening packets for 250 of them and is dropped
the moment one authenticates under the new key. Trying twice is sound only
because a failed attempt leaves the datagram untouched — §3.3's order is
replay window, then tag, then decrypt — and a change that decrypted first
would break this without any test noticing.

**DTLS-SRTP, and the window it opens.** The handshake in `sipral-dtls` is
joined to a call behind the `dtls` feature, which is on by default. A
catalogue set to `SrtpPolicy::DtlsOffered` or `DtlsRequired` writes
`UDP/TLS/RTP/SAVP` with `a=fingerprint` and `a=setup`, the handshake runs on
the media path, and the keys it exports open the same `Security` an
`a=crypto` line would have. Which of the two transforms it opens is the
handshake's to choose (RFC 5764 §4.1.2), not the signalling's, which is why
`MediaEvent::Secured` carries it.

What is new about it is the window. SDES keys a stream before its session is
opened; DTLS-SRTP agrees in the signalling that a stream is protected and
produces the keys a round trip later. So `RtpSession` has a third state
between "in the clear" and "keyed": `awaiting`, in which nothing goes out and
nothing arriving is believed. Every builder answers `BuildError::NotKeyed` and
every arrival is dropped as `Discard::NotKeyed`, and the refusal is decided
before the packet is written rather than after, so a refused frame never sits
in the caller's buffer in the clear. `MediaSession::is_encrypted` reads that
state rather than the plan: for the length of a handshake it says no, because
for the length of a handshake nothing has been encrypted.

Three refusals go with it, each for a failure that would otherwise be silent.
Two `a=setup` values RFC 4145 §4.1 has no row for are refused where they are
read, because two ends that both believe they are the server wait for each
other until the handshake gives up. A call that agreed DTLS-SRTP and did not
agree `a=rtcp-mux` is refused with `MediaError::DtlsNeedsRtcpMux`: RFC 5764
§4.2 would put a second association on the RTCP port and this stack runs one.
And a DTLS server has no flight to retransmit, so its connection would never
time out at all — the facade gives every handshake the budget the client's own
schedule spends, and reports `MediaError::DtlsHandshake` when it runs out.
Inside `sipral-dtls` a flight the far end retransmits is answered by sending
this end's again, and it does not move the point at which this end gives up:
that prompt arrives in the clear, before there are keys, so anybody who can
send from the far end's address could forge it, and a stream of them used to
hold a handshake open for ever.

**Whose records the handshake takes.** Nothing before the fingerprint check
authenticates anything, so the first handshake record decides whom the
handshake is run with, and the session latches on its address. Without ICE only
the host the signalling named may close that latch — any port on it, the rule
RTCP already keeps — because one octet from anywhere used to be enough: a
stranger who read the port out of the description closed it on their own address, and the
far end's records were dropped until the handshake gave up. This end's flights
go to the latched address while RTP has no latch of its own, which it cannot
have before there are keys to authenticate a packet with; they used to go to
the signalled port whatever port the far end was sending from. The latch
follows the pair ICE selects, and a re-negotiation that moves the far end's
media address opens it again. `docs/06-nat.md` says what is left and why only
ICE closes it.

**A far end that starts over.** Some peers begin a new DTLS association on
every re-negotiation — Asterisk does, with a fresh ClientHello on the hold and
`a=connection:new` on the resume — and RFC 6347 §4.2.8 says what a server does
then: it "SHOULD proceed with a new handshake but MUST NOT destroy the existing
association until the client has demonstrated reachability". The session runs
the new handshake beside the old one, the cookie exchange first, so nothing
costly is spent on a ClientHello whose sender cannot receive; the call keeps
the old keys throughout; and when the new one finishes, with the far end's
certificate checked against the same fingerprint, each direction moves to its
new key the way a re-key does, the old receive context kept for the packets
already in flight under it. One that never finishes is dropped without a word,
the call still on the keys it had: its prompt arrives in the clear, and
reporting it would hand anybody who can send from the far end's address a way
to fail any call. The running connection used to take that ClientHello and
ignore it, and the far end waited for a handshake that never came, with the
call silent from the first re-offer on. Only as the server: a client whose
server wants a new association is not told so by anything it could act on.

**One certificate per call.** The engine makes its key and certificate once and
renews them a day before they run out, which a desk phone or an agent running
for months reaches every month. A call keeps the one it first described itself
with for as long as it lasts: its handshake presents that certificate and every
later description of it names that fingerprint. A renewal between a call's
offer and its answer used to hand the handshake the new certificate, whose hash
was not the fingerprint the far end had been given (RFC 8122 §5.1: the far end
"MUST NOT establish the connection"), and a running call's next re-offer
named a certificate RFC 8842 §3.1 reads as a new association.

Without the `dtls` feature there is no handshake and no certificate: a plan
that comes back keyed that way is refused with `MediaError::NoDtlsSrtp` rather
than opened in the clear on a secure profile, and `Capabilities::srtp_keying`
says so before a call is placed rather than after one has failed.

Nor does it half-honour a crypto line. One master key to a line, because one
context opens one key; and RFC 4568 §6.3's defaults, so `UNENCRYPTED_SRTP`,
`UNENCRYPTED_SRTCP`, `UNAUTHENTICATED_SRTP` and a key derivation rate are
refused where they are read rather than ignored where they would matter. `WSH`
is allowed through and ignored, which §6.3.6 permits in as many words.

**Re-offers on a secured call are answered here.** Whatever the far end
re-offers on a secured call — a hold, a resume, a session refresh, a codec
change — `sipral-ua` hands it up instead of answering it itself, because the
answer has to carry something only the holder of the keys can write. Under
SDES that is a crypto line naming the tag it accepted, with this end's own key
(§5.1.2), and the key is the one this end is already sending under: §7.1.4
lets an answerer change its key and warns in the same breath that the offerer
cannot read it until the answer arrives, and a hold is no reason to open that
window. Under DTLS-SRTP it is this end's fingerprint and the role the running
association gives it (RFC 8842 §5.3; see "The DTLS roles" below). The user
agent's own answer used to carry neither. The end that asked for the hold then
read a secured stream with no key on it: the hold never reached its media, and
on the wire the answer had withdrawn the key or the certificate.

The direction stays the user agent's. It narrows whatever answer it is handed
to a hold this end has asked for, so a codec change or a session refresh from
the far end does not take a call off hold behind its user's back — the answer
this facade writes is `sendrecv` narrowed by the offer (RFC 3264 §6.1), and
without that second narrowing it would say this end was listening again, and
the stream here would start sending into a call its user believed was on
hold.

Among the re-offers handed up are the ones that change the security of a call
in progress: a transport profile that moved, an `a=crypto` line that appeared
or disappeared. An account under a *required* policy refuses them with 488
rather than finding out afterwards. Only the presence of the line counts, not
its value: a peer is entitled to re-key on a re-offer, and a re-key reaches
the media session by its own path.

One consequence of that, real and not hidden. A re-offer that keeps `RTP/SAVP`
and drops the crypto line is refused — 488, the session standing — under
*every* policy, not only *required*, where once the audio limped on under the
keys already in use. Such an offer is malformed in any case (§5.1.2 requires
the attribute on a secure profile), so refusing it is the honest answer, but a
peer that used to get away with it is now told no.

**A running stream keeps its kind of keying.** In the clear, by SDES keys from
the descriptions, or by a DTLS-SRTP handshake: each is a different state of the
stream, and one that has sent under one of them has no way to carry on under
another. A re-offer that would move it — encryption turned off under a policy
that only offered it, a plain call re-offered DTLS-SRTP, SDES giving way to a
handshake — is answered 488 and reported as `MediaError::KeyingChanged`, and an
answer that does the same is not adopted. They used to be adopted: the stream
went on sending SRTP to a far end now expecting RTP, or answered as a DTLS
client and never sent a ClientHello, and the plan later certificates are
compared against was left with nothing in it, so a certificate that went away
in one re-offer came back as another in the next without being refused.

## Ringing with media (task 8.4.9)

`MediaEngine::ring` and `MediaEngine::ring_with` are `MediaEngine::place` and
`MediaEngine::place_with`'s mirror on the other side of the call: an incoming
INVITE this stack has not answered yet, put through the same offer/answer
machinery `answer`/`answer_with` use, and sent in a 183 rather than a 200 OK.
The session opens the moment `ring_with` returns — not on the ACK, which is
how `answer_with` opens one, because a 183 is never acknowledged the way a
2xx is and there is no later event to hang it on — so the far end hears
whatever the application plays on the session before anybody answers, and
`MediaEvent::Started` follows exactly as it does after `answer`.

`UserAgent::ring` already decides, from the INVITE's own `Require` or
`Supported`, whether the 183 goes out reliably (RFC 3262 §3); `ring_with`
does not add a policy of its own here, it only writes what goes in the body.

**An INVITE that carried no offer is not rung with media**:
`MediaError::NoDescription`, with nothing sent. The offer this end would
have to make instead has one legal place among the responses, RFC 3261
§13.2.1's "first reliable non-failure message", and RFC 6337 §3.1.2 keeps
it out of every other response — so an unreliable 183 may not carry it at
all. A reliable one may, but then RFC 3262 §5 puts the far end's answer in
the PRACK, and nothing hands a PRACK's body to this engine: the session
would never open, and nothing would say so. `answer`/`answer_with` stay the
way to take such a call.

**A later `answer` or `answer_with` on the same call reuses that session and
that description.** There is no second negotiation: the catalogue and the
configuration `ring_with` recorded stay this call's own, the `o=` session id
and version are unmoved, and neither `local` nor `media` given to `answer`/
`answer_with` at that point is read — ringing with media already settled
both. What changes is only whether anything goes in the 200 OK, and that is
exactly what RFC 3262 §5 and RFC 6337 §3.1.1 say, for the two ways the 183
could have gone out:

- **Sent reliably.** §5: "the UAS MUST delay sending the 2xx until the
  provisional response is acknowledged" — `UserAgent::answer` already does
  that regardless of what body it is given, holding the 2xx until the PRACK
  arrives. RFC 6337 §3.1.1's UAS rule #2 covers the body: "After the UAS has
  sent the answer in a reliable provisional response ... the UAS should not
  include any SDPs in subsequent responses." The 183 already carried the
  real answer, so the 200 OK that follows the PRACK carries none.
- **Sent unreliably.** RFC 3261 §13.2.1 makes the answer to an offer real
  only in a reliable non-failure message; an unreliable 183 is, in RFC
  6337's words, "only a preview of the answer that will be coming." The
  offer/answer exchange is not complete yet, and the 200 OK — the exchange's
  first reliable non-failure response — is where it has to finish: it
  repeats the same description, unchanged, rather than writing a new one.

Both cases end with exactly one session for the call and exactly one
`MediaEvent::Started`, whichever of `ring_with`/`ring` or `answer`/
`answer_with` came first. The ACK that confirms the call does not also
produce a `MediaEvent::Changed`: `settle` compares the plan already running
against the one the confirmation leaves in place, and an ACK that carries no
body of its own — the ordinary case, since the description was already
settled — leaves that comparison equal. A `Changed` still follows whenever a
description that arrives afterward actually disagrees with what is running,
the 200 OK that repeats a different body after an unreliable 183 included.

**Ringing with media twice on one call is refused**, with the same error
`answer` uses for a call in the wrong state: once early media has been
offered, that is a one-way door, not a value to keep changing while the
call is still ringing. A plain `UserAgent::ring` with no description — a
180 — first is no obstacle. One that carried a description the application
wrote itself is, and for the RFC's reason rather than this engine's: RFC 3261
§13.2.1 allows only "that same exact answer" in any other response to the
INVITE, and RFC 6337 §3.1.1 has every description in those responses
identical, so an answer this engine writes after it would be a second,
different one. `UserAgent::has_described` is what `ring_with` asks, and the
refusal is the same error, with nothing sent.

`sipral_call_ring_media` (`docs/08-ffi.md`) is the C entry point, and the one
place SRTP on an incoming call's own terms was still missing after 8.4.6:
`sipral_call_answer_media` reads no configuration of its own, so a call this
stack describes the media of had no way to choose anything but the stack's
SRTP policy until it could ring with one first.

## Transfers with media (task 8.4.4)

`MediaEngine::accept_transfer` and `MediaEngine::accept_transfer_with` are
`MediaEngine::place` and `MediaEngine::place_with`'s mirror for the call a
transfer becomes: an offer written from a catalogue — this engine's default,
or one `accept_transfer_with`'s `CallMedia` names for this call alone, D6's
reason — against `local`, and `UserAgent::accept_transfer` placing it. The new
call is managed exactly as one `place` placed: nothing about how its session
opens or how `MediaEvent::Started` follows is different, because nothing
downstream of `UserAgent::accept_transfer` returning a `CallHandle` can tell
the two apart.

The one thing `place`'s caller has that `accept_transfer`'s does not is a
target: `place` reads it from wherever the application keeps a directory,
`accept_transfer`'s comes from the REFER that was accepted, before either
engine method runs. That is why the destination override, fork policy and
header fields that ride on `place`'s `OutgoingCall` reach `accept_transfer`
through `OutgoingExtras` instead (`sipral-ua`, `docs/04-ua.md`) — the same
three fields, without the target `OutgoingCall` requires and `accept_transfer`
has no legitimate value to put in it. `sipral_call_accept_transfer`
(`docs/08-ffi.md`) is the C entry point, reading `sipral_call_config_t` the
same way `sipral_call_place` does apart from `target`, which the REFER already
named and a second one from `config` is refused.

## What the end of a call sends

RFC 3550 §6.6 has a participant that leaves send an RTCP BYE, and the engine
produces it at the moment the call ends rather than leaving it to the
application. It has to be that moment: a call that ends is taken out of the
engine in the same breath as the event reporting it, so a packet still held in
its session is one nobody can reach afterwards. The bytes are copied out and
wait in `MediaEngine::poll_farewell`, which hands over one at a time like every
other poll here, alongside the handle of the call that has ended. A goodbye
that is never polled is a far end left to wait out its own timeout.

Across the C ABI this is `sipral_stack_poll_farewell(stack, out_call,
out_packet)` (task 8.4.21), a stack-level call rather than one more of the
four on a media handle: by the time there is a goodbye to hand over, the call
it belonged to has already ended, its media handle already answers
`SIPRAL_STATUS_WRONG_STATE`, and only the stack still knows the call was ever
there. `crates/sipral-ffi/src/stack.rs` gathers what `poll_farewell` produced
into a queue of its own during every `sipral_stack_poll`, before the ended
call's handle is forgotten — which is also where the `CallHandle` a farewell
names becomes the `sipral_handle_t` the application already has for that call,
stale as it now is. `docs/08-ffi.md` says when to call it.

## What a re-negotiation keeps

A re-INVITE settles on a plan, and one of two things happens to the media.

If the codec did not move, the running session takes the new plan in place —
the address, the direction, the record of what became of each candidate, and
whatever keys moved, on the terms the SRTP section above sets out.

If the codec did move, the session is **re-formatted, not replaced**. The
stream carries on: the same synchronization source, the sequence number and
timestamp it has reached, both SRTP contexts with their rollover counter and
SRTCP index, the octet and packet totals, the reception tracker, the RTCP
interval and the CNAME. Everything measured in the old codec's units is
rebuilt — the coder, the frame length, the payload buffer, the voice
detectors, the de-jitter buffer — and the cumulative counters inside the
buffer survive that rebuild, because they belong to the call.

Two of those are not housekeeping, and both fail silently:

- RFC 3550 §5.1 has a source that resets its counters read as a different
  source. A stream that rewound its sequence number is heard as somebody else
  arriving mid-call.
- Under SRTP the packet index is `2^16 · ROC + SEQ`. A rewind under an
  unchanged master key hands a second packet a keystream already spent, which
  is the two-time pad RFC 3711 §9.1 calls catastrophic. Nothing about it is
  audible and nothing about it shows in a capture.

Carried across too, because they are the call's and not the negotiation's: the
render delay and the device the application set at run time, the events it has
not collected yet, the digits this end still owes — rescaled into the new
clock's ticks, since a digit measured in the old one would last half as long
or twice as long — and the processor the application attached, which it has no
second chance to hand over because nothing warns it a re-negotiation is
coming. The processor is kept and `reset`, which is the case
`Processor::reset` names: the echo path it has learned describes a signal that
no longer exists.

The recording is the one thing that cannot always follow. A WAVE header names
the playback rate once, at the front of the file, so a recording survives every
codec change that keeps the rate and the frame length — the three
eight-kilohertz codecs are interchangeable under one header — and is closed
properly when one of them moves, with `MediaEvent::RecordingStopped` carrying
`MediaError::CodecChanged` and the length written so far. The file is
playable; whether to open a second one is the application's to decide.

The timestamp continues in the new clock rate rather than being converted,
which is RFC 7160's case. The source has not changed, so a receiver reads the
discontinuity as one; drawing a fresh source to announce it would cost an
RTCP BYE and explain less. Early media is the same path and not a rarity: a
183 with SDP opens the session and the 200 OK naming another codec
re-formats it seconds later.

**Buffers.** A session holds two 1500-octet scratch buffers. No RTP packet
this build produces gets past twelve octets of header, 1275 of payload and ten
of tag — 1297 at the top, and that top is the largest Opus frame, so it is the
bound where the codec is linked and a generous one where it is not: twenty
milliseconds of G.711 is 160 octets of payload. A protected compound report is
thirty-nine octets under the same roof, so SRTP fits in what was already
there. `RtpSession` subtracts its
own overhead from whatever buffer it is handed and refuses a short one before
a sequence number is spent, so a buffer that stopped being big enough would be
a refused frame with a reason on it rather than a truncated packet.

## A codec change this end asks for

`MediaEngine::change_codecs(agent, call, codecs, now)` offers a live call again
on another codec list (RFC 3264 §8.3.2), and `sipral_call_change_codecs` is the
same from C. Only the codecs move. The offer is the description this end last
wrote for the call with its `m=` formats and its `a=rtpmap` and `a=fmtp` lines
replaced, so everything else is carried as it stands: the address, the
transport profile, the SDES key or the DTLS fingerprint, the ICE credentials
and candidates, multiplexing. A key drawn afresh would be a re-key nobody
asked for, in the middle of a change about something else; a fingerprint
written afresh is what RFC 8842 §3.1 reads as asking for a new DTLS
association, which this stack does not start; new ICE credentials are a
restart. A hold carries all of them unchanged for the same reasons, and the
codec change is the second re-offer this end writes, so it behaves the same —
down to the one line both rewrite, `a=setup`, which the next paragraph is
about. Which way the call flows is the user agent's to write
(`UserAgent::change_formats`): a held call stays held through the change, and
`resume` takes it off hold on the new list.

**The DTLS roles.** RFC 8842 §5.5 asks every subsequent offer for
`a=setup:actpass`, and every re-offer this stack writes carries it — the hold,
the resume and the codec change alike — including one made from a
description that was last an answer and so said `active` or `passive`.
`actpass` hands the far end the choice again, and §5.3 has an answerer that
keeps the association answer with "an attribute value that does not change
the previously negotiated DTLS roles". This stack answers the far end's
re-offers the same way, which to `actpass` is simply the role it has; a fresh
answer to `actpass` says `active`, and a server that said so would be asking
to become the client.

A far end that takes the other role is asking for a new association (§3.1),
which this stack, running one per call, does not start, and it is refused by
name as a moved certificate is. An answer that takes it is reported as
`MediaError::DtlsRoleChanged` and not adopted, so the stream keeps running on
the association it has. A re-offer that leaves this end only the other role —
the concrete value an older peer still writes, which §5.3 asks an answerer to
understand — is answered 488 and reported by the same name, and the session
stands (RFC 3261 §14.2). A re-offer naming another certificate is refused the
same way, as `MediaError::DtlsFingerprintChanged`; §5.3 has an answerer that
will not start the association the offer asks for refuse it, and answering it
and then declining to follow would leave the far end on an association this
end never joined.

The one description that goes out with a concrete role is a session refresh.
RFC 4028 §7.4 has it repeat the last description byte for byte, `o=` version
included, so a refresh made from an answer carries the role that answer took —
and a concrete role in an offer leaves RFC 4145 §4.1 exactly one answer, the
role already in force.

**Payload types keep their codec.** §8.3.2: "the mapping from a particular
dynamic payload type number to a particular codec within that media stream
MUST NOT change for the duration of a session." A catalogue numbers its
dynamic formats from 96 in order, which is right for a call's first
description and wrong for a later one — the same list without Opus hands
Opus's number to whatever comes next, and `telephone-event` moves whenever the
list in front of it does. So each call keeps every binding either end has
written on its stream, those in an offer that was refused included, and the
change is renumbered against them before it goes: a codec already bound keeps
its number, and one new to the call gets a number nothing has had.
`telephone-event` on another clock is another format and gets its own. All
thirty-two dynamic numbers taken is `MediaError::NoPayloadType`, never a
number reused.

**The list becomes the call's own when the far end accepts it.** A refusal
(`UaEvent::SessionChangeFailed`) leaves the call on the list it had, as RFC 3261
§14.1 leaves the session; a 491 goes out again by itself, and the change is
still on its way while it does. What the answer settled on arrives the way any
re-negotiation's does, as `MediaEvent::Changed` with the codec on it.

**A re-offer this end can take nothing from is refused.** The same exchange
from the other side: an offer from the far end naming no codec this call's
catalogue holds is answered 488, which is what RFC 3261 §14.2 has a UAS do with
a session description it cannot accept, and the session stands. Answering it
with the stream refused instead — port zero, which RFC 3264 §6 allows for a
stream — would be accepting it, and would leave the call without audio for the
rest of its life over a codec the far end merely proposed. An offer that took
the stream away itself is still answered, because that one asked for it.

## sipral-media

The pipeline between the codec and whatever produces or consumes samples.

- **Resampling** between the device rate and the codec rate, with a fixed-quality
  polyphase filter. Rate mismatch, not bandwidth, is what usually makes a call
  sound thin.
- **Clock drift correction.** The capture device and the far end do not agree
  on what a second is. Left uncorrected, the buffer drifts to an underrun over
  a long call.
- **Mixing** for conferencing and for local tones — the arithmetic lives here
  (`sipral_media::mix`), and the facade's own use of it, joining two calls
  into a local conference of three, is below ("A local conference of two
  calls").
- **Codecs.** G.711 A-law and µ-law written in-tree, a couple of hundred lines
  and public domain as an algorithm. G.722 written in-tree as well: this used
  to say "linked from an unrestricted implementation", and there is not one.
  The library everyone reaches for is spandsp's, which `docs/02-clean-room.md`
  forbids by name; the Rust crate that looks free of it keeps spandsp's
  headers and its comments word for word. So it is implemented from the
  Recommendation, which is what a specification is for — a filter pair, two
  ADPCM sub-bands and about a dozen tables. Opus linked, and the codec worth
  defaulting to where the far end has it — behind a compile-time feature that
  is on, for the reason below. G.729 follows in phase 2 for the carrier that
  insists, written in-tree the same way, because the common implementation is
  GPL and the base patents are reported expired; it is never in the default
  offer.

  G.722's RTP clock rate is 8000 while it samples at 16000 (RFC 3551 §4.5.2),
  so a twenty-millisecond frame is 320 samples, 160 octets and 160 timestamp
  ticks. Any code that keeps one constant for "samples in a frame" and "ticks
  in a frame" is correct for G.711 and wrong here.
- **Echo cancellation, gain control, noise suppression** are attached at a seam,
  not implemented here. This is signal processing research, it exists under a
  permissive licence, and rewriting it would buy nothing that a customer pays
  for. What that costs is described below, because a seam nothing can reach is
  not a seam.
- **Voice activity detection and comfort noise**, needed by the jitter buffer's
  adjustment schedule and by silence suppression where a carrier expects it.

### Opus is behind a feature, and the feature is on

libopus is the one part of the audio path that is licensed rather than
written, and the licence that matters is not the BSD one on the source. Three
companies run a patent pool over Opus; the list of patents is public, it names
IP phones as a category, and it is priced per unit. A library distributed on
its own is not who that pool says it approaches — a desk phone with this stack
inside it is, and the exposure there is the customer's. So the codec is a
Cargo feature: `opus` on `sipral-media`, carried up by `sipral` and by
`sipral-ffi`, so that a product which must not contain libopus leaves it out
when it compiles rather than turns it off when it runs.
`THIRD-PARTY-NOTICES.md` carries the licensing position itself.

On by default, because a default decides only for whoever did not choose, and
whoever did not choose is either an open-source user or a licensee who
configures the build anyway. The one place where leaving it on would put the
codec into a product quietly is the precompiled artefacts — the binaries
somebody downloads instead of compiling — and there are none: nothing in this
tree packages, signs or publishes one yet. When that work happens the default
there is off, or two variants labelled clearly enough that nobody ships the
wrong one without noticing. It is written down where the packaging is — the
artefact bullet of phase 3 in `docs/10-roadmap.md` — and not decided here.

A build without it offers G.722 and the two G.711 laws, and it needs no cmake
and no C++ toolchain, because nothing compiles libopus from source: on a bare
machine that build is a Rust compiler and nothing else. Nothing else about it
is a special case. There is no `sipral_media::opus` and nothing links
libopus; `Codec::ALL` is three long; a codec order naming `opus` is refused
where it is set, by name, exactly as one naming G.729 is; and an offer that
names Opus and nothing else ends as no common codec, on the ordinary path.
Across the C ABI the `SIPRAL_FEATURE_OPUS` bit is clear and
`sipral_codec_count` answers three, while `SIPRAL_CODEC_OPUS` is still 4: a
number that has left the header is spent for good, whatever the build behind
it can encode. The bit, the name `sipral_codec_name` gives 4 and the number a
stream reports are all read from the codec catalogue and never from
`sipral-ffi`'s own copy of the feature — that copy can be off over a facade
that linked the codec, and an ABI that answered from it would deny a codec the
build can negotiate.

## The processor seam, and the frame that is hard to produce

`sipral-media`'s `Processor` is one attachment point for all three of echo
cancellation, gain control and noise suppression, because a real
implementation is usually one component: gain control has to run on what
cancellation left behind, not on the raw capture, and noise suppression the
same.

A processor is `Send`. The session it is attached to has a lock of its own and
is reached from the threads that carry the call's audio as well as from the one
that runs signalling, so whatever the processor owns has to be able to move
between them; `docs/08-ffi.md` has the reasoning. It runs with that session
held, so a processor that reaches back into its own call through the C ABI — by
the call's media handle or by its stack — is refused rather than left waiting
for itself.

**Through a `MediaEngine` it can reach, and there it would wait for itself, and
must not.** That is a rule of the `Processor` trait itself, stated in its own
doc comment, and not a check the engine makes: `MediaEngine::session` and
`SessionShare::with` refuse a thread that is already inside the call's own
session, but `MediaEngine::handle_timeout`, `MediaEngine::poll_rtcp` and
anything else that walks every session in turn to do its own work take each
one's lock without asking whether the calling thread already holds it, because
that is not a question those methods have ever had reason to ask — the poll
thread that ordinarily calls them is never also inside a frame. A processor
that keeps a handle on the engine and calls one of them from inside `process`
or `reset` is the one caller that changes that, and it deadlocks: the session
its own frame is running on is in that walk too, and the lock it would wait for
is the one it is already holding, with no status to say so the way the C ABI's
`SIPRAL_STATUS_BUSY` does.

The trait takes two frames covering the same span of time — the microphone's,
and the far end's audio as it left the loudspeaker while that microphone was
open. Only the second is hard to produce, and producing it is the work this
project has to do whoever writes the canceller:

- The far-end frame was handed out by `MediaSession::playback` some
  milliseconds ago, through a device ring, a driver and whatever the hardware
  adds. The echo in the microphone is *that* frame, not the one about to be
  played next.
- Handing a canceller the wrong frame is not weaker cancellation, it is none.
  An adaptive filter given a reference that does not correlate with its input
  diverges, and the call gets worse than it would have been with nothing
  attached.

So `MediaSession` keeps the recent past of the loudspeaker and hands back the
slice that lines up, at a distance the application sets with
`set_render_delay`. That number is the device's render-to-capture delay, which
only the platform knows, and neither of them reports it the same way: WASAPI
answers it per stream in one call, while CoreAudio has four properties per
direction spread over two kinds of object and a rate to convert them by.
`sipral-io-coreaudio` assembles it; `sipral-io-wasapi` reads it.
There is no portable guess worth making, so the stack does not make one — the
default is zero, which pairs a capture with the frame played immediately
before it, and a delay above half a second is refused rather than believed,
because nothing between a loudspeaker and a microphone in the same room takes
that long.

Everything is allocated when a processor is attached and not before. A build
with nothing attached — which is every headless one, where there is no
loudspeaker and therefore no echo — keeps no history and copies no frames.

Two consequences worth stating, because they are the kind of thing that is
discovered from a complaint:

- **Silence suppression and the recording tap both see the processed audio**,
  not the raw microphone. Suppression measuring uncancelled echo would hold
  the stream open through the far end's own talking, and a recording of the
  raw capture would not be a recording of the call.
- **The application's own capture buffer is never edited.** The processed
  frame comes back from the session's buffer, so whatever the application
  metered, drew or kept is what it handed over.

### Where the canceller itself comes from

Not from this tree, and on two of the three desktop platforms not from a
dependency either:

| Platform | Where it comes from |
|---|---|
| macOS, iOS | The voice-processing audio unit `sipral-io-coreaudio` is built on. It is the unit or it is nothing, so it is there whenever a stream is, and nothing reaches the seam |
| Windows | The endpoint's own capture-side processing, which applies to a stream declared `AudioCategory_Communications` and to no other kind. `sipral-io-wasapi` declares it on every stream it opens, in both directions, and reports whether Windows accepted the declaration — but no further, because no further is reportable |
| Linux, and any build wanting its own | The seam. A permissively licensed component is attached by the application, and `THIRD-PARTY-NOTICES.md` grows a row for it |

The seam exists for the third row and for anyone who wants a different one
from what the platform provides. It is not a placeholder for work this project
owes on the first two.

The first two rows are not the same kind of certainty, and an application that
treats them as one will ship an echo it cannot explain. On Apple's platforms
the canceller is the unit the device crate opens. On Windows the processing
belongs to the endpoint and its driver: the category is set with
`IAudioClient2::SetClientProperties`, between activating the client and
initialising it, which is the only window in which it is accepted — and after
that Windows has no per-stream way of saying whether anything is cancelling. A
person can switch the enhancements off in the sound settings, and an endpoint
whose driver ships none reports nothing missing. So `CaptureStream::category`
says what was asked and what Windows said to the asking, and stops there;
anything but `Category::Communications` means there is no system processing at
all, and the application's own is the only kind there will be.

The delay the seam needs comes from the same two crates and is not assembled
the same way. WASAPI keeps it in one property per stream,
`IAudioClient::GetStreamLatency`, and a call wants both directions added.
CoreAudio has no such property at all: the figure is the device's own latency,
its safety offset, the frames in its IO buffer, and the latency of the stream
on that side — four properties, asked per direction, with the header explicit
that the device's and the stream's are summed rather than one standing for the
other. `sipral_io_coreaudio::Stream::latency` does that arithmetic for the two
device objects the unit reports it is on — the speaker's output side at the
speaker's rate, and the microphone's input side at the microphone's, because on
a Mac those are usually two objects — and `RenderDelay` keeps the parts, so
that a device which answered for three of them can be told from one that
answered for four. A device that answers for none gives zero, which is what a
session that was never told a delay already assumes.

The figure is what the devices say, not a timed acoustic round trip, and it
moves with the machine and with the stream. Read through `Stream::render_delay`
on an Intel MacBook Pro running macOS 12.7, with a narrowband stream open on its
built-in speakers and built-in microphone — two device objects, both at
44.1 kHz — it comes to 115 ms: 21 ms out (930 frames: 325 of device latency, a
safety offset of 93, an IO buffer of 512) and 94 ms in (4,162 frames: 9, 57 and
4,096). The same two devices report 34 ms while nothing has them open. The
difference is the microphone's IO buffer, which the voice-processing unit
raises from 512 frames to the 4,096 the stream sets as its largest slice. An
earlier reading on a MacBook Air, with nothing open, came to about a hundred
milliseconds, most of it the two streams' own latency, with the speakers at
44.1 kHz and the microphone at 48 kHz, so even the arithmetic has to be done per
direction. That is the case for asking the devices rather than assuming a
number.

## What device I/O owns, and does not

`sipral-io-*` crates deliver and consume frames at a fixed size and rate, and
nothing else. Device enumeration, hot-plug, default-device changes, Bluetooth
hands-free transitions, `AVAudioSession` categories and interruptions, WASAPI
exclusive mode: all of that is platform work, and all of it is where time
disappears on this kind of project. It is budgeted as such and it is kept out of
every other crate.

### Volume, mute and the level meter

They live here, and they are applied to the frames rather than to the operating
system's own volume control. Every platform offers one — CoreAudio's device
volume, WASAPI's `IAudioEndpointVolume` and `ISimpleAudioVolume` — and none of
them belongs to a call: the first two are shared with everything else the person
is listening to, the third is one setting for a whole process however many
streams it has, and all of them are remembered after the call ends and after the
process dies. Turning a call down should not turn a film down, and it should not
still be down tomorrow. What this crate does to the samples belongs to the stream
and goes when the stream goes.

It is applied at the device end of the ring rather than at the caller's. The
rings hold sixteen frames, so a gain applied on the way in would be heard a third
of a second after the slider moved, and a mute has to be silent on the next frame
the device asks for. The cost is one multiply, one shift and one clamp per sample,
in the loop that was copying them anyway.

Gain saturates, and says how often. Above unity a loud sample leaves the
sixteen-bit range; it stops at the end rather than wrapping round it, and the
samples that landed there are counted, because a gain set too high is otherwise
a distortion nobody can attribute to the setting that caused it. The range
itself is clamped rather than refused: below zero is silence, above four is four.

A muted direction keeps running. The microphone still fills the ring, with
silence, and the speaker still drains it. Stopping the frames instead would make
unmuting replay everything that had piled up behind the mute, and would starve
whatever above is pacing itself on frames arriving.

The meter is the loudest sample over a tenth of a second, held for between one
window and two, and the caller polls it — nothing is pushed. Reporting the peak
since the last poll would make the number depend on how often the interface
asks, which is how a bar ends up flickering on one machine and never falling on
another. Per frame it costs a comparison per sample, in the same pass the gain
is already making, and four relaxed atomic operations; a poll is two atomic
loads and changes nothing, so any number of callers at any rate see the same
answer.

### When the device goes

A stream reports the loss of the device under it as an event the caller polls
for, and stops. On Windows this is exact: every WASAPI call answers
`AUDCLNT_E_DEVICE_INVALIDATED` once the endpoint has gone, and the audio thread
writes that down before it leaves — starting and stopping included, so an
endpoint that went while the stream was stopped is reported by the start that
finds it gone, not only by a buffer pass that never comes. On macOS the stream
asks the hardware layer whether each of the two device objects under it is
still alive — the speaker's and the microphone's, which on a Mac are usually
not the same object — and losing either is losing the stream. That is a
property read rather than an inference from silence. On iOS it reports nothing,
because there
the route belongs to `AVAudioSession` and its changes are delivered to the
application; anything else would be a guess dressed as a fact.

What follows is defined rather than silent. The stream stops: what the
microphone had already captured can still be read out, nothing further arrives,
and the speaker's ring fills up and takes no more — a caller that ignores the
event finds a stream that has plainly stopped, not one that appears to be
working. Recovering reopens on the stream's own device choice, resolved against
the machine as it is then, and carries the volume, the mute and the meter handle
across. It is a call the application makes rather than something the crate does
by itself, because whether the audio should move to the laptop speaker, wait for
the headset to come back, or end the call is the application's decision.

### Saved selections

A device is chosen one of three ways, and what separates them is what happens
when it is not there. The system's route is whatever the operating system is
routing calls to. A named device is that device or nothing. A *preference* is a
saved identity — `Device::uid` on macOS, the endpoint identifier on Windows,
both of which survive a replug and a reboot where a device number does not — and
falls back to the system's route when the machine does not have it. On Windows
that includes an endpoint the machine still knows but cannot play through:
unplugged, disabled and absent endpoints keep their identifiers in the registry,
so the preference asks the endpoint's state rather than only whether the
identifier resolves. A preference is what a selection read out of a
configuration file should be, and it is what makes recovery from an unplugged
headset land somewhere instead of failing.

What the crate does not promise: it cannot stop the operating system changing
the default device behind the application's back, and it cannot move a running
stream onto another device. CoreAudio accepts a device only on an uninitialised
unit, and a WASAPI client is bound to the endpoint it was activated on. Both are
answered the same way — the default-changed event says the machine moved, and
reopening is what re-applies the selection.

## Per call, not per process (D6)

`sipral` never opens a device, so it cannot enumerate one or answer "which
headset is this call on" from a device object. What it *can* do is carry the
identity the application already has for one — `MediaConfig::device` is an
opaque string, set once when a call is placed or answered
(`MediaEngine::place_with`, `MediaEngine::answer_with`) and changeable mid-call
with `MediaSession::set_device`, the same shape as
`MediaSession::set_render_delay` and for the same reason: a Bluetooth headset
reconnects mid-call, not only before one starts. Reading it back is
`MediaSession::device`, on the call's own session — not a side table an
application would otherwise have to keep from drifting out of step with the
call table itself.

The codec catalogue and the rest of `MediaConfig` — the render delay, the
stall threshold, the RTCP bandwidth share — follow the same rule. An engine
keeps one of each as its site policy, and every call takes it by default;
`MediaEngine::place_with` and `MediaEngine::answer_with` name a catalogue and
a configuration for one call alone. This is what an attended transfer needs:
`UserAgent::consult` holds two calls on one engine at once, and a global codec
order or a global device identity would make the second call a race against
whichever one touches the global last. A call's recording sink
(`MediaSession::start_recording`) and its stall watchdog were already per-call
in storage, one instance per session; what device selection needed was
somewhere to carry an identity that never existed at all.

## The engine explains its negotiations (D5)

A live call already reports what it settled on
(`MediaEvent::Started`/`MediaEvent::Changed`, and `MediaSession::codec`). What
it did not say is why every other candidate was not it, and "PCMU was chosen"
by itself does not distinguish a peer that never offered anything better from
a site policy that ranked something better below it — which is exactly the
distinction B6's failure story turns on.

`MediaSession::codec_candidates` answers this per call, from
`CodecCatalog::candidates`: for every codec the call's own catalogue could
have offered, whether it is the one chosen, was never named by the far end's
own description of the stream, or was named but ranked below the codec that
won (RFC 3264 §6.1's rule on the far end's listed order). It is computed once,
at the point `MediaEngine` works out the plan, from the two descriptions and
the catalogue that produced them — not reconstructed afterwards from
whatever state happens to still be around, which is the one place a
reconstruction could disagree with what the negotiation actually did.

The transport half of D5 — which flow a request left on, and why a request
was promoted onto a stream transport or refused — is `sipral-core`'s
diagnostic record (`docs/14-diagnostics.md`), already answered without this
crate's help. Which port carries RTCP, muxed or its own, is already on
`MediaSession::plan().rtcp`. The NAT half has nothing to answer yet:
`sipral-nat` exists as a crate but nothing in `sipral` or `sipral-core` calls
into it, so there is no NAT strategy decision anywhere in this tree to
explain.

## A local conference of two calls

Nothing like a SIP conference server, and nothing that reaches `sipral-ua`:
`MediaEngine::join(a, b)` pairs two calls this engine already placed or
answered, and from the next frame each one's own driving loop pumps through
`MediaEngine::mix` instead of `MediaSession::playback`/`MediaSession::capture`
directly, each far end hears the other's far end and this end's own
microphone, mixed. Neither far end's own signalling ever names the other —
from either one's dialog, this still looks like an ordinary two-party call —
and this stack sends no `Refer-To` and opens no third dialog. `MediaEngine`'s
own module doc calls itself "the join" for a different reason entirely (the
seam between signalling and media); this is a second, unrelated use of the
word, and `crate::join`'s own doc comment says so before anything else.

`MediaEngine::join` refuses a pair whose two sessions do not share a sample
rate and a frame length (`MediaError::JoinIncompatible`). Nothing in the
mixer resamples: the samples it decodes out of one session have to line up,
index for index, with the ones it decodes out of the other, and two codecs
only agree on that when they cut a frame the same way. The check runs once,
when the pair is made — the same moment a call's catalogue and configuration
are otherwise fixed for its whole life (D6, above) — not on every frame.

### Levels

Every sum the mixer forms is two sources at half scale apiece, which is the
reasoning `crate::record::Recorder` (this crate's own call recorder) already
carries for the same problem: two full-scale sources summed at unity is a
sum that does not fit in the sixteen bits a sample has, and a mixer that let
it clip could never undo the clip afterwards. Halved first, the loudest two
sources can ever sum to is full scale, never past it, at the cost of six
decibels nobody notices on a phone call — and, unlike a limiter that eases a
gain toward the level that would have fit over some tens of milliseconds,
with no state that has to be carried from one frame to the next to get
there. `sipral_media::mix::sum_scaled_into` is the primitive this reduces
to, the same one that had been sitting in `sipral-media` unused until this.

### Recording

A joined call's own recording, if one is running
(`MediaSession::start_recording`), keeps a recording of the conference it
was actually in rather than of the two legs it would have carried alone: the
mixer sends each far end `mic` mixed with the *other* far end's decoded
frame, through the same `MediaSession::capture` a recording's `captured`
half is always fed from, so what the file keeps is what actually went out
rather than the raw microphone.

### Ending

A call that ends while it is still joined takes the pairing down with it —
`MediaEngine::release` un-pairs both calls before anything else, the moment
`UaEvent::CallEnded` arrives, and tells the surviving call with
`MediaEvent::Unjoined` — rather than leaving `MediaEngine::mix` to discover
later that half a pair is gone. `MediaEngine::leave` does the same thing on
request, for a pairing that is still ending on purpose rather than because a
call did.

### Across the C ABI

`sipral_call_join`/`sipral_call_leave` record the pairing, on the stack's own
call handles, the same shape as `sipral_call_change_codecs` and every other
entry point that reaches `MediaEngine` through the stack's lock. Driving a
frame does not: `sipral_media_mix` takes two *media* handles, the same kind
`sipral_media_playback`/`sipral_media_capture` do, and never touches the
stack — checking that the pair named was actually joined would mean taking
the stack's lock on every frame, which is exactly what a media handle exists
to avoid (`docs/08-ffi.md`), so it trusts the caller the same way every other
media entry point already does. The two sessions it does lock are locked in
a fixed order, by handle value rather than by which one the caller named
first, so that two threads mixing the same pair with the arguments swapped
wait for each other instead of deadlocking.

`MediaEvent::Unjoined` crosses too, as `SIPRAL_EVENT_KIND_MEDIA_UNJOINED` on
the survivor's own `call`: an application driving the pair through
`sipral_media_mix` alone, with no reason to touch the stack's own event
queue otherwise, still gets told the moment it needs to stop calling
`sipral_media_mix` on that pair and go back to driving the survivor directly.
