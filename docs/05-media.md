<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Media: sipral-rtp and sipral-media

Signalling either works or it does not, and when it does not there is a trace
that says why. Media is different: it degrades, and the user calls it "the app
sounds bad". This is where a SIP stack is actually judged, and it is the part
that is written in-house rather than assembled.

## sipral-rtp

### RTP and RTCP

RFC 3550. Sequence numbers with wraparound, timestamps per clock rate, SSRC
collision handling, marker bit on talk spurt start, contributing sources parsed
and ignored.

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
its three retransmissions. On receive, the redundant packets for one event
collapse into a single reported digit, which is the bug everyone ships at least
once.

### SRTP

Via libsrtp2. SDES key exchange through `a=crypto` in SDP for the common case,
DTLS-SRTP where the peer requires it. `AES_CM_128_HMAC_SHA1_80` as the baseline
suite, with the AES-GCM suites where offered. Key material is zeroised on drop.
Unencrypted RTP arriving on a secured session is dropped, never accepted as a
fallback.

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
