<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# sipral-ffi and the language bindings

## The shape

One narrow C ABI, and one idiomatic wrapper per language written on top of it.
The C layer is not meant to be pleasant. It is meant to be stable and small.

Rules for the ABI:

- **Opaque handles only.** No Rust type crosses the boundary. Structs that do
  cross are `#[repr(C)]`, POD, and versioned by a `size` field as the first
  member.
- **Explicit ownership.** Every allocation the library returns has exactly one
  matching free function. Strings are UTF-8, length-delimited, never assumed
  null-terminated on input.
- **No panics across the boundary.** Every entry point catches unwinding and
  turns it into an error code. A panic that reaches an `extern "C"` boundary
  uncaught aborts the whole host process (defined behaviour since Rust 1.24, but
  not something the caller can recover from), and a SIP stack sees malformed
  input for a living. This is why the release profile keeps `panic = "unwind"`:
  with `panic = "abort"` there is nothing to catch, and Cargo does not allow a
  per-crate override of that setting.

  Held up by two things rather than by care. The `entry!` macro is the only way
  to declare an entry point, and each of its three shapes reaches for a
  wrapper that catches; a test panics inside one of each shape and asserts the
  status that comes back instead. And `scripts/check.sh` fails if any file
  outside the macro's own module exports a symbol, so an entry point written by
  hand does not reach a release.
- **Errors are integer codes** plus a thread-local last-error string. No
  errno-style globals shared between handles.
- **Events arrive on one callback**, registered per stack handle, carrying a
  tagged union. The callback may be invoked from the caller's own polling
  thread only, so the language side never has to reason about which thread it
  is on.
- **Nothing is added to a released ABI except at the end of a struct**, guarded
  by the `size` field, or as a new function. Nothing is removed or reordered.
  Ever.
- **A numbered space has one declaration, and disagreeing with it is a build
  failure.** The event kinds are declared once, by the `event_kinds!` macro in
  `crates/sipral-ffi/src/event.rs`. The enum, the name a kind prints in a log
  line, and the number that indexes both are generated from that single list, so
  a kind cannot be added to one of them and missed in another. A number is spent
  by appearing in the list, and a generated assertion says the list runs
  `1, 2, 3, …` with nothing repeated, nothing moved, and no hole.

  The hole is what this exists to close. Two features written in two branches
  each take the number after the last kind, each builds, and the one that lands
  second has quietly renumbered an event that a shipped binding already knows —
  B7's failure, one layer down, and permanent because the number is the ABI. So
  the numbers of the features already committed to are spent now, as `reserved`
  lines naming the requirement each belongs to. Taking one means turning that
  line into a kind in place: the number is read rather than chosen, and two
  features cannot read the same one.

  Live and reserved lines interleave, in number order, in one run. That is what
  makes "in place" literal, and it is not cosmetic: a list that made every live
  kind come first would force a feature that wants the sixth reserved number to
  also take the five in front of it, and a number taken by a feature that does
  not exist is exactly the lie the reservation was meant to prevent. The media
  surface took 17 and 19 this way and left 15, 16, 18 and 20 where they were.

  Where a number cannot be generated — `SipralStatus`, which C switches on and
  whose zero is load-bearing — the equivalent is a test that writes out every
  value rather than deriving it, so a declaration that moved would disagree with
  a test that did not.

## Media across the boundary

The ABI is built over `crates/sipral`, the facade that joins signalling to
media, and not over `sipral-ua` alone. Until it was, a client on the other side
of this boundary had to parse its own descriptions, run its own RTP and own its
own audio — which is to say it had to bring a second stack in order to use this
one.

**A call is described one way or the other, never both.** Set `media_address` in
`sipral_call_config_t` and the offer is written from this stack's codec order,
the answer is read, and the call gets a media session; answer an incoming one
with `sipral_call_answer_media` for the same. Set `sdp` instead and the
application describes its own session and runs its own audio, exactly as before.
Setting both is `SIPRAL_STATUS_INVALID_ARGUMENT`: two descriptions of one
session is one too many.

**A managed call answers its own re-offers.** The engine writes the answer, from
the same codec order, inside the poll that saw the request — so
`SIPRAL_EVENT_KIND_SESSION_OFFERED` never arrives for one, and
`sipral_call_accept_session` on it is `SIPRAL_STATUS_WRONG_STATE`. The
application hears the outcome as `SIPRAL_EVENT_KIND_MEDIA_CHANGED`.

**Four calls carry the packets**, and none of them opens a socket or touches a
device: `sipral_call_media_receive` for a datagram that arrived,
`sipral_call_playback` for the frame due for the earpiece, `sipral_call_capture`
for one from the microphone, and `sipral_stack_poll_rtcp` for the control
traffic RFC 3550 §6.3 schedules. Samples are 16-bit mono at
`sipral_media_info_t::sample_rate`, a frame is exactly `frame_samples` of them,
and outgoing packets are written into buffers the caller brings — checked before
anything is built, so a frame is never encoded and then dropped for want of
somewhere to put it.

**Recording is where a path becomes a file**, and the file belongs to the media
session from then on. C never sees the handle, so it cannot leak it or close it
underneath the stack. The one thing that had to be arranged rather than
inherited is the WAVE header: it carries two lengths that are not known until
the recording stops, so every way a recording can end closes it properly —
`sipral_call_record_stop`, the call ending, and the stack being destroyed,
including from inside its own event callback. Destroying a stack mid-recording
leaves a playable file, not a repair job.

**Configuration is answered, never absorbed.** A codec name this build has no
encoder for is `SIPRAL_STATUS_NOT_SUPPORTED` where the order is set, with the
names it does have in the last error; a stall threshold set while the watchdog
is off is `SIPRAL_STATUS_INVALID_ARGUMENT`, the same shape as a retransmission
timer set on a transport that retransmits nothing. Every boolean media setting
is a three-valued `sipral_toggle_t` — default, on, off — because a zeroed struct
cannot otherwise tell "off" from "nothing was said", and
`sipral_stack_settings_t` reads back what each of them came to.

**The header is not generated yet, and neither are the bindings.** There is no
C header in the tree and the .NET package is a name reservation. That is the
state, not the intent: `docs/13-client-requirements.md` B7 makes one source of
truth for this ABI a requirement, with the Swift, Kotlin and .NET bindings
generated from it and `scripts/check.sh` failing when one of them is missing a
function. It is scheduled early in phase 2 for a reason that will not improve
with waiting — it is cheapest to do while there is one binding to bring into
line rather than three.

## Swift

A Swift Package wrapping the C target. `async`/`await` over the event callback,
`Sendable` types, errors as a Swift `Error`, and no exposed pointers.

The platform work is what the binding actually earns its place for: `CallKit`
for call UI and audio session priority, `PushKit` for waking on an incoming call,
and `AVAudioSession` category and interruption handling. An iOS softphone that
gets these wrong does not work, regardless of how good the stack is.

## .NET

A NuGet package with native assets for `osx-arm64`, `osx-x64`, `win-x64`,
`win-arm64` and `linux-x64`. `Task`-based API, `IAsyncEnumerable` for event
streams, `IDisposable` mapped to the handle free functions, and a `SafeHandle`
so a missed `Dispose` leaks rather than crashes.

## Kotlin

An AAR over JNI, coroutines and `Flow` for events. `ConnectionService` for
integration with the system dialer, and a foreground service for the call
lifetime, because Android will otherwise stop the process mid-call.

## Versioning

The C ABI carries its own version, independent of the crate version. It is
reported by a function, checked by every binding at load, and a mismatch is a
hard failure with a legible message rather than a crash later.
