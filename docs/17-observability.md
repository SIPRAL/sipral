<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Observability: counters and capabilities

Two questions an operator and an application ask that neither a log file nor
a single call's statistics answers. "Is this deployment healthy" is D3, and it
wants a handful of numbers read by asking rather than by grepping. "What can
this build actually do" is D8, and it wants one answer an application reads
once, at start-up, instead of shipping a control and finding out from a
support ticket that it does nothing. Both live in `crates/sipral/src/counters.rs`
and `crates/sipral/src/capabilities.rs`, carried across the C ABI by
`crates/sipral-ffi/src/counters.rs` and `crates/sipral-ffi/src/capabilities.rs`.

## D3: health counters

`sipral::MediaEngine::counters` returns a `sipral::Counters` — a struct
copy, cheap enough to sample on a timer and ship as telemetry, because nothing
behind it walks the call table or a session to answer. It is fed from exactly
the events `sipral::MediaEngine::poll_event` already drains, at the two
places it hands one out: nothing here opens a second path to the layers below
to learn something the event stream does not already say.

The full list, and what each one is:

| Counter | Kind | Fed by |
|---|---|---|
| `registrations_attempted` | counter | `UaEvent::Registering`, once per attempt including a retry |
| `registrations_succeeded` | counter | `UaEvent::Registered` |
| `registrations_failed.rejected` | counter | `UaEvent::RegistrationFailed { reason: RegistrationFailure::Rejected, .. }` |
| `registrations_failed.bad_credentials` | counter | … `RegistrationFailure::BadCredentials` |
| `registrations_failed.unreachable` | counter | … `RegistrationFailure::Unreachable` |
| `registrations_failed.redirected` | counter | … `RegistrationFailure::Redirected` |
| `calls_ended.local_hangup` | counter | `UaEvent::CallEnded { reason: CallEndReason::LocalHangup, .. }` |
| `calls_ended.remote_hangup` | counter | … `CallEndReason::RemoteHangup` |
| `calls_ended.refused` | counter | … `CallEndReason::Refused` |
| `calls_ended.cancelled` | counter | … `CallEndReason::Cancelled` |
| `calls_ended.unreachable` | counter | … `CallEndReason::Unreachable` |
| `calls_ended.fork_lost` | counter | … `CallEndReason::ForkLost` |
| `calls_ended.abandoned` | counter | … `CallEndReason::Abandoned` |
| `calls_ended.expired` | counter | … `CallEndReason::Expired` |
| `media_gaps` | counter | `MediaEvent::Stalled` (B5's watchdog) |
| `jitter_buffer_events` | counter | `sipral_rtp::Quality::shrunk + Quality::stretched`, folded in from `MediaEvent::Ended` as each call finishes |
| `stream_transport_wanted` | counter | `UaEvent::Unclaimed(sipral_core::endpoint::Event::TransportWanted { .. })` — B1. Named for what it counts: a request that would not fit a datagram **and had no stream to the destination to go on**. One promoted onto a connection that already existed raises nothing, because nothing was asked for; those are `transport.promoted.size` in the diagnostic record (`docs/14-diagnostics.md`). Read as "how often does promotion happen" it would read low and say the path is fine |
| `active_calls` | gauge | `+1` on `MediaEvent::Started`, `-1` on `MediaEvent::Ended` |

Across the C ABI, `sipral_stack_counters` writes the same numbers into a flat
`sipral_counters_t`: the nested `registrations_failed.*` and `calls_ended.*`
become `registrations_failed_rejected`, `calls_ended_local_hangup` and so on,
because C has no tuple struct to nest one `struct` inside another for free
and a longer field name costs nothing a binding was not already going to
spend regrouping them.

Two members of `sipral_counters_t` are not one of these, and have no
`sipral::Counters` field behind them: `events_dropped` and
`farewells_dropped`, both from task 8.4.21 — the second closing a gap its own
review left open — each appended at the struct's tail when it was added.
Neither comes from `MediaEngine::poll_event` — both count
something about the C ABI's own queues rather than about a call or a
registration, and both are fed by `crates/sipral-ffi/src/stack.rs` rather
than by anything the facade drains: `events_dropped` from the outbox a slow
callback can leave full, `farewells_dropped` from the RTCP goodbyes queued
for `sipral_stack_poll_farewell`, which an application that never calls it
leaves to grow unless something bounds it. `docs/08-ffi.md` says what each
one counts and why the queue behind it has a ceiling at all.

### Counters are monotonic, gauges are not — in the type, not only here

`sipral::Counter` only grows; `sipral::Gauge` moves both ways. The
distinction is not decoration. `Counters` implements `Sub`, so a later reading
minus an earlier one turns every counter into how much it grew across the
interval — saturating at zero rather than panicking if the two readings are
handed in the wrong order — and leaves `active_calls` exactly where it reads
now, because a gauge does not have a "how much" between two points, only a
"what, currently". An application samples `Counters` on a timer, keeps the
previous reading, and ships `later - earlier` as the interval's telemetry.

### Why a reason split, and not just a count

A count of failed registrations says a deployment is unwell. It does not say
whether the fix is "check the password", "check the network path to the
registrar" or "wait, the account is genuinely rejected and retrying will not
help" — three different pages to three different people, collapsed into one
number nobody can act on without a packet capture. The reason vocabularies
are not invented for this: `registrations_failed` reuses
`sipral_ua::RegistrationFailure` and `calls_ended` reuses
`sipral_ua::CallEndReason`, the same enums the event stream already carries,
so a counter and a live event about the same failure are never able to
disagree about its name.

### What is deliberately not counted here: retransmissions

D3's own list includes "retransmissions", and this is the one number on it
that `Counters` does not have. `sipral-core` keeps a retransmission count
privately, inside the client transaction state machine that paces timer A
(`crates/sipral-core/src/transaction/invite_client.rs`), and never raises it
as an event — nothing passes through `poll_event` that says "a request was
retransmitted", only ever "a request was sent" or, on the far side of 64·T1,
"the transaction gave up". Counting it here would mean reading that private
state through a path this crate does not have, which is exactly the second
path this design avoids everywhere else. The number is not missing by
oversight; it is missing because raising it as an event is `sipral-core` and
`sipral-ua` work this observability layer does not do, and a counter that
always reads zero because nothing ever feeds it would be worse than no
counter at all — a number that looks measured and is not.

## D8: capability reporting

`sipral::Capabilities::of_this_build` answers "what can this build do" with
one struct: which codecs this build contains, which transports its signalling
can carry, and which optional features are compiled in. It takes no `&self`
and reads no running stack, because a build's capabilities do not change
between two engines in the same process — only between two builds of the
library.

```rust
use sipral::Capabilities;

let capabilities = Capabilities::of_this_build();
if !capabilities.subscriptions {
    // grey out the presence / busy-lamp-field toggle in the settings screen —
    // this build genuinely cannot honour it, and shipping the control anyway
    // is how an application finds out from a support ticket instead
}
```

Across the C ABI, `sipral_capabilities` answers the same question as
`sipral_capabilities_t`: `codec_count` (the same number `sipral_codec_count`
gives; `sipral_codec_at` says which codecs and in what order), and two
bitmasks, `transports` and `features`, named `SIPRAL_TRANSPORT_BIT_*` and
`SIPRAL_FEATURE_*` in `crates/sipral-ffi/src/capabilities.rs`. A bitmask
rather than one field per capability, for the same reason `sipral_status_name`
takes a number instead of switching on a growing enum: a binding compiled
against an older header reads the bits it has names for and the rest as
zero, rather than failing to compile against a struct that grew a member.

### Never hand-maintained

Every field is read from a fact that already exists rather than copied from
one. `codecs` is `&Codec::ALL` — the same compile-time list
`sipral_codec_count` and `sipral_codec_at` already report from — so a codec
added to the build changes what this answers without a second list to update
by hand. `opus` is that same list walked for one codec, and the C ABI's
`SIPRAL_FEATURE_OPUS` bit is set from it rather than from a `cfg` in
`sipral-ffi`: a Cargo feature belongs to the crate that declares it and
features are additive, so `sipral-ffi` compiled without its own `opus` over a
`sipral` that linked libopus is a real configuration, and a bit copied from
the wrong crate's flag would deny a codec that build can negotiate.
`transports` names the protocols `sipral-core`'s endpoint has
framing and timers for, not a socket this crate has ever opened: no build of
`sipral` opens one, so "this build supports TLS" and "this process can open a
TLS connection" are two different questions, and this answers only the first.
A capability list that can drift from the build it describes is worse than
none, because it is believed.

### One capability that answers differently at the two layers, on purpose

`sipral_ua::UserAgent::subscribe` is implemented — RFC 6665 subscriptions and
the busy-lamp field built on top of them — so
`Capabilities::of_this_build().subscriptions` reads `true`. The C ABI's
`SIPRAL_FEATURE_SUBSCRIPTIONS` bit is never set, because `sipral-ffi` has no
entry point that reaches a subscription yet: `SIPRAL_EVENT_KIND` 15 is still
reserved for it (`docs/08-ffi.md`), and an application built against this ABI
genuinely cannot subscribe to anything, whatever the Rust crate underneath can
do. This is the case D8 exists for — two honest answers about two different
surfaces of the same build, rather than one aspirational answer that is
believed by whichever side turns out to be wrong.

## B2, audited

B2 requires that every configuration entry point answer `applied`, `rejected`
or `not supported in this build`, and never a fourth thing that looks like
success and silently does nothing. `MediaConfig`, `EndpointConfig` and the FFI
setters were read against that rule, one entry point at a time. What that
found:

**Compliant already**, and worth naming because the pattern is the one to
copy: `CodecCatalog::with_order` and `CodecCatalog::with_frame_length`
(`crates/sipral/src/codec.rs`) reject a codec this build has no encoder for,
by name, rather than dropping it from the offer silently. The FFI's
`sipral_stack_create` (`crates/sipral-ffi/src/stack.rs`, `timers_for` and
`media_for`) rejects `timer_t2_ms` / `timer_t4_ms` on a transport that
retransmits nothing and `media_stall_ms` with the watchdog switched off,
rather than accepting a figure nothing will ever read. `sipral_call_place`
(`crates/sipral-ffi/src/call.rs`, `managed_media`) rejects `sdp` and
`media_address` both set, rather than picking one and ignoring the other.
Every `sipral_*_config_t` struct is size-versioned, so a member a caller set
that this build has never heard of is `SIPRAL_STATUS_NOT_SUPPORTED` rather
than silence (`crates/sipral-ffi/src/versioned.rs`).

**No violation found, but also no validation**: `MediaConfig`
(`crates/sipral/src/session.rs`) and `EndpointConfig`
(`crates/sipral-core/src/endpoint/config.rs`) are plain public structs with no
setter methods, so every field that is set is read somewhere — confirmed
field by field while building the counters this document describes — but
nothing rejects a value that is merely absurd on its own terms: a negative or
`NaN` `MediaConfig::rtcp_bandwidth`, a `MediaConfig::stall_after` of zero, an
`EndpointConfig::max_dialogs` of zero. That is a narrower question than B2 —
B2 is about a value that is accepted and then ignored by a neighbour, not
about a value that was never checked for being sensible on its own — so
nothing here is a B2 violation, but a future validating constructor for either
type would have a starting list.

**One coercion rather than a rejection, since fixed**: `sipral_ua::screening::
Rate::new` used to read `burst: 0` as `1` and `every: Duration::ZERO` as "no
limit". Both were documented and deliberate, but B2's three-way split
(applied / rejected / not supported) has no fourth answer for "the value you
gave is not the value that took effect", which is what a coercion is one step
short of. `Rate::new` now answers `Result<Rate, RateError>` and refuses both;
`Rate::unlimited` is how a deployment asks for no floor on purpose, and
`UserAgent::invite_limit` reads back what took effect.

No entry point in `crates/sipral/` or `crates/sipral-ffi/` was found to accept
a setting and then ignore it while reporting success — the specific failure
B2 names.
