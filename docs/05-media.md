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
  and public domain as an algorithm. G.722 written in-tree as well: this used
  to say "linked from an unrestricted implementation", and there is not one.
  The library everyone reaches for is spandsp's, which `docs/02-clean-room.md`
  forbids by name; the Rust crate that looks free of it keeps spandsp's
  headers and its comments word for word. So it is implemented from the
  Recommendation, which is what a specification is for — a filter pair, two
  ADPCM sub-bands and about a dozen tables. Opus linked, and the codec worth
  defaulting to where the far end has it. G.729 only if a carrier forces it,
  and then written in-tree too, because the common implementation is GPL.

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
only the platform knows: CoreAudio reports it per device, WASAPI per stream.
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
| macOS, iOS | The operating system's voice-processing audio unit, below `sipral-io-coreaudio`. Nothing reaches the seam, and nothing needs to |
| Windows | The operating system's own capture-side processing, below `sipral-io-wasapi`, for a stream opened as communications |
| Linux, and any build wanting its own | The seam. A permissively licensed component is attached by the application, and `THIRD-PARTY-NOTICES.md` grows a row for it |

The seam exists for the third row and for anyone who wants a different one
from what the platform provides. It is not a placeholder for work this project
owes on the first two.

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
