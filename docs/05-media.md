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
/// What the negotiation settled on. Produced by `sipral-ua` from the answer,
/// consumed by whatever owns the media: `sipral-media` for a device build,
/// `sipral-headless` for an agent. Emitted again, unchanged but for the fields
/// that moved, after every re-INVITE or UPDATE that changes the session.
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
produces them; the media crates depend on `sipral-core` for these two types and
nothing else, which keeps the seam a shared vocabulary rather than a call.

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

SDES only over a secured signalling channel. `a=crypto` carries the master key
in the SDP body, so over plain UDP or TCP it travels in the clear and anyone on
the path can decrypt the media — RFC 4568 §7 is explicit that the mechanism
depends on the signalling being protected. The offer is therefore made only on
a TLS transport; on anything else the choice is DTLS-SRTP or no SRTP, and
saying so is better than an `a=crypto` that looks like encryption and is not.

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
  and public domain as an algorithm. Opus linked, and the only wideband codec
  worth defaulting to. G.722 linked from an unrestricted implementation. G.729
  only if a carrier forces it, and then written in-tree, because the common
  implementation is GPL.
- **Echo cancellation, gain control, noise suppression** are attached at a seam,
  not implemented here. This is signal processing research, it exists under a
  permissive licence, and rewriting it would buy nothing that a customer pays
  for.
- **Voice activity detection and comfort noise**, needed by the jitter buffer's
  adjustment schedule and by silence suppression where a carrier expects it.

## What device I/O owns, and does not

`sipral-io-*` crates deliver and consume frames at a fixed size and rate, and
nothing else. Device enumeration, hot-plug, default-device changes, Bluetooth
hands-free transitions, `AVAudioSession` categories and interruptions, WASAPI
exclusive mode: all of that is platform work, and all of it is where time
disappears on this kind of project. It is budgeted as such and it is kept out of
every other crate.
