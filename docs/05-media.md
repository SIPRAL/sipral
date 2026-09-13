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

### RTP and RTCP

RFC 3550. Sequence numbers with wraparound, timestamps per clock rate, SSRC
collision handling, contributing sources parsed and ignored. Marker bit on talk
spurt start, which is the audio profile's rule (RFC 3551 §4.1), not RFC 3550's.

RTCP sender and receiver reports on the standard interval, because carriers use
them for quality reporting and their absence is noticed. RTCP-mux when
negotiated, a separate port when not.

**Symmetric RTP always.** Send from the port we receive on, and latch onto the
source address of the first valid packet. This single behaviour, together with
`rport`, is what makes most NAT traversal unnecessary.

Validation before anything else: version, payload type in the negotiated set,
plausible SSRC, length. Packets from an unexpected source after latching are
dropped, not merged.

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
and not heard, and a call whose negotiation settled on no telephone-event
payload type says so instead of swallowing the key.

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

SDES key exchange through `a=crypto` in SDP for the common case. DTLS-SRTP is
deliberately not here yet: it needs a DTLS implementation, `rustls` has none,
and the alternatives are single-maintainer crates. The cost of the delay is
that peers who require DTLS-SRTP and refuse SDES — a browser talking WebRTC
directly, and some carrier session border controllers — cannot be reached.

The way in was decided on 10 September 2026: **written in-tree**, as the last
item of phase 2. The DTLS 1.2 state machine comes from RFC 6347 — both roles
per `a=setup` (RFC 4145), the record layer with its epoch and anti-replay
window, fragmentation and retransmission of the handshake flights, the
`use_srtp` extension and the key export of RFC 5705, the peer's self-signed
certificate checked against `a=fingerprint` and against nothing else, no
renegotiation and no resumption. The primitives it needs — P-256 for ECDHE and
ECDSA, AES-GCM, SHA-256, HMAC — are not written here: a constant-time
elliptic curve is the one place a home-grown implementation is a risk rather
than a virtue, so they come from the permissively licensed crate family that
already supplies AES, each listed in the notices. The random values a
handshake needs come from the engine's own seed, which the application draws
from the operating system's entropy; a seed that is not is a handshake that
is not. The code is reviewed adversarially before it ships under the
commercial licence. An application that already runs DTLS of its own can
still export its keys per RFC 5705 and hand them to the engine through the
seam SDES uses, which costs one function and keeps the gateway case cheap.

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
is heard. A crypto-only re-offer arriving here is the other direction and does
not get this far — see "One known gap" below. Three things about the answer
direction are worth stating, because getting any of them wrong is silent.

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

**What it deliberately does not do.** DTLS-SRTP. `sipral-core` reads an
`a=fingerprint` and carries it through, and there is no DTLS in this tree at
all, so an offer arriving on `UDP/TLS/RTP/SAVP` has its stream refused rather
than answered, and a plan that comes back keyed that way is refused with
`MediaError::NoDtlsSrtp` rather than opened in the clear on a secure profile.
`Capabilities::srtp_keying` names SDES and not DTLS-SRTP, so an application
can grey the control out instead of finding out from a support ticket.

Nor does it half-honour a crypto line. One master key to a line, because one
context opens one key; and RFC 4568 §6.3's defaults, so `UNENCRYPTED_SRTP`,
`UNENCRYPTED_SRTCP`, `UNAUTHENTICATED_SRTP` and a key derivation rate are
refused where they are read rather than ignored where they would matter. `WSH`
is allowed through and ignored, which §6.3.6 permits in as many words.

**One known gap.** When the far end puts a secured call on hold, `sipral-ua`
answers that re-INVITE itself — the streams and the formats have not moved, so
there is nothing for an application to decide — and the answer it writes keeps
the `RTP/SAVP` profile without the `a=crypto` line §5.1.2 requires on it. The
negotiation that follows reports `SdpError::CryptoMissing` rather than a hold,
and the audio carries on under the keys already in use. It is a defect in the
user agent's own answer writer, not in the facade, and it is not papered over
here: carrying the key forward locally would make this end believe a
negotiation the far end saw fail.

What the user agent no longer answers by itself is a re-offer whose transport
profile moved, or one where the `a=crypto` line appeared or disappeared. Those
are a change to the security of a call in progress, and they are handed up, so
that an account under a *required* policy refuses them with 488 rather than
finding out afterwards. Only the presence of the line counts, not its value: a
peer is entitled to re-key on a re-offer, and a re-key reaches the media
session by its own path.

Two consequences of that, both real and neither hidden. A re-offer that keeps
`RTP/SAVP` and drops the crypto line is now refused at the stream — port zero
in the answer — under *every* policy, not only *required*, where before the
audio limped on under the keys already in use. Such an offer is malformed in
any case (§5.1.2 requires the attribute on a secure profile), so refusing it is
the honest answer, but a peer that used to get away with it will now hear
silence. And the answer this facade writes for a re-offer it was handed is
always `sendrecv`, so a peer that both holds a stream and moves its profile in
one re-INVITE gets an answer RFC 3264 §6.1 would not have written. It cannot
happen under *required*, where the offer is refused before an answer is
composed; under the other two it is a shape nothing has been seen to send.

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

## sipral-media

The pipeline between the codec and whatever produces or consumes samples.

- **Resampling** between the device rate and the codec rate, with a fixed-quality
  polyphase filter. Rate mismatch, not bandwidth, is what usually makes a call
  sound thin.
- **Clock drift correction.** The capture device and the far end do not agree
  on what a second is. Left uncorrected, the buffer drifts to an underrun over
  a long call.
- **Mixing** for conferencing and for local tones.
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
other. `sipral_io_coreaudio::Stream::latency` does that arithmetic for both
directions of the device the unit landed on, and `RenderDelay` keeps the parts,
so that a device which answered for three of them can be told from one that
answered for four. A device that answers for none gives zero, which is what a
session that was never told a delay already assumes.

Measured on a MacBook Air, its own speakers and microphone come to a hundred
milliseconds of that, most of it the two streams' own processing rather than
the buffers, and the two devices do not run at the same rate — 44.1 kHz out and
48 kHz in — so even the arithmetic has to be done per direction. That is the
case for asking the device rather than assuming a number.

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
writes that down before it leaves. On macOS the stream asks the hardware layer
whether the device object it opened is still alive, which is a property read
rather than an inference from silence. On iOS it reports nothing, because there
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
falls back to the system's route when the machine does not have it. A preference
is what a selection read out of a configuration file should be, and it is what
makes recovery from an unplugged headset land somewhere instead of failing.

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
