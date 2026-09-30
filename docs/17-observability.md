<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Observability: counters, capabilities, the log and the state snapshot

Two questions an operator and an application ask that neither a log file nor
a single call's statistics answers. "Is this deployment healthy" is D3, and it
wants a handful of numbers read by asking rather than by grepping. "What can
this build actually do" is D8, and it wants one answer an application reads
once, at start-up, instead of shipping a control and finding out from a
support ticket that it does nothing. Both live in `crates/sipral/src/counters.rs`
and `crates/sipral/src/capabilities.rs`, carried across the C ABI by
`crates/sipral-ffi/src/counters.rs` and `crates/sipral-ffi/src/capabilities.rs`.

Two more come after them, once something has already gone wrong in the field.
"What was the stack doing" is the engine's log, handed to a callback the
application installs; "what was it holding when it crashed" is one snapshot
of its state, taken on demand from any thread. Both are in
`crates/sipral/src/log.rs` and `crates/sipral/src/state.rs`, carried across the
C ABI by `crates/sipral-ffi/src/log.rs`, and both are under "The engine's log"
and "The state snapshot" below.

D3, D8, B1, B2 and B5 are requirement ids from
[13-client-requirements.md](13-client-requirements.md), which says what each
one asks for.

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

Six members of `sipral_counters_t` have no `sipral::Counters` field behind
them, each appended at the struct's tail when it was added. `events_dropped`
and `farewells_dropped` count the C ABI's own queues, as above: neither comes
from `MediaEngine::poll_event` — both are fed by `crates/sipral-ffi/src/stack.rs`
rather than by anything the facade drains — `events_dropped` from the outbox a
slow callback can leave full, `farewells_dropped` from the RTCP goodbyes
queued for `sipral_stack_poll_farewell`, which an application that never
calls it leaves to grow unless something bounds it. `docs/08-ffi.md` says
what each one counts and why the queue behind it has a ceiling at all.
`screened_refused_by_policy`, `screened_refused_by_rate`,
`screened_refused_by_crowding` and `screened_refused_by_replaces` count
INVITEs refused before the application ever saw them, read from
`sipral_ua::UserAgent::refusals`; a Rust caller reads that method directly
rather than going through a counter meant for the C ABI. Four more, appended
in ABI 0.30 — `requests_retransmitted`, `responses_retransmitted`,
`transactions_timed_out` and `requests_refused_at_limit` — are read from the
endpoint underneath, `Endpoint::retransmissions` and `Endpoint::refused`,
below.

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

### Retransmissions are the endpoint's to count

D3's own list includes "retransmissions", and `Counters` still does not have
them: nothing passes through `poll_event` that says "a request was
retransmitted", and raising one event per repeated datagram would put the
busiest path of a lossy link through the event queue. The endpoint counts
them where they happen instead. `sipral_core::endpoint::Endpoint::retransmissions`
returns `Retransmissions { requests, responses, timeouts }`, each only ever
growing:

- `requests`: timers A and E, and an ACK sent again because the 2xx it
  acknowledges arrived again (RFC 3261 §13.2.2.4);
- `responses`: timer G, a reliable provisional response's own timer
  (RFC 3262 §3), and the last response of a server transaction sent again
  because its request arrived again;
- `timeouts`: timers B, F, H and L with no answer or no ACK, and a reliable
  provisional response never PRACKed within 64·T1.

`Endpoint::transaction_retransmissions` answers the same for one live
transaction. The C ABI copies the three, and `Endpoint::refused` beside them,
into `sipral_counters_t`. Over TCP and TLS the first two stay at zero, since
nothing retransmits at the transaction layer there. The D1 record carries the
same events one by one (`request.retransmitted`, `response.retransmitted`,
`transaction.unacknowledged`), so a figure that moved can be traced to the
calls it moved on.

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

### The two layers may answer differently, on purpose

Every bit `sipral_capabilities` reports is the facade's own answer today, but
it is not required to be: a feature `sipral_ua::UserAgent` has and this ABI has
no entry point in front of reads absent here, whatever the crate underneath
says. `SIPRAL_FEATURE_SUBSCRIPTIONS` was that case for two phases —
`UserAgent::subscribe` was implemented, `Capabilities::of_this_build()
.subscriptions` read `true`, and an application built against the C ABI
genuinely could not subscribe to anything, so the bit stayed clear. It is set
now that `sipral_account_subscribe` exists with event kind 15 behind it.

This is the case D8 exists for, and the rule outlives the example: two honest
answers about two different surfaces of the same build beat one aspirational
answer that is believed by whichever side turns out to be wrong. The next
feature built below before it is built here gets the same treatment.

## The engine's log

A diagnostic record (`docs/14-diagnostics.md`) says what the stack decided
about one call. The log says what the whole engine is doing, as it does it,
for the application's own log file: `sipral::Log` in Rust, `sipral_stack_log`
across the C ABI, `SIPRAL_FEATURE_LOGGING` (bit 14) in `sipral_capabilities`.

| Level | Number | What it carries | Targets |
|---|---|---|---|
| error | 1 | Something failed and the application is likely to see the effect. | — |
| warn | 2 | Something the stack worked around, or is about to matter: a registration refused, inbound audio that stopped arriving. | `registration`, `media` |
| info | 3 | What an operator wants in a file: a registration granted or dropped, a call arriving, confirmed or ending, media starting, resuming and ending with its packet counts. | `registration`, `call`, `media` |
| debug | 4 | Every other event the engine hands out, by name and not by content; every decision the diagnostic record writes down, with its reason code, sizes and addresses; and every call into the C ABI that was refused, with the sentence `sipral_last_error_message` gives. | `signalling`, `media`, `decision`, `api` |
| trace | 5 | Every SIP message in and out, whole. | `sip` |

A level includes every level below it. The target is a short fixed word,
never data, so a sink can route on it.

Four properties hold it up, each with a test in `crates/sipral/src/log.rs` and
again across the C ABI in `crates/sipral-ffi/src/log.rs`:

- **Off by default, and free when off.** A stack starts with no sink and no
  level. Whether a level is on is one atomic load, and a line for a level
  that is off is never formatted or redacted.
- **A flood cannot stall the stack.** Lines pass a token bucket —
  `sipral::BURST` (200) at once, then `sipral::PER_SECOND` (100) a second, on
  the stack's own clock — and wait in a queue of at most
  `sipral::QUEUE_CEILING` (1024). What either turns away is counted, never
  waited for, and the next line delivered carries the count in `suppressed`.
  Ten thousand refusals at one instant reach the sink as one burst and one
  count.
- **The sink is never called with a lock held that it could re-enter.**
  Producing a line only queues it. `Log::flush` takes the queue out under the
  log's own lock, lets it go, and only then calls the sink. The engine never
  flushes — it runs inside its owner's locks — so its owner does: the C ABI
  flushes at the end of every entry point, once the stack has been let go, on
  the thread that made the call. A callback may therefore call back into the
  library, this stack included, as an ordinary call. One flush delivers at a
  time, so lines arrive in order and never on two threads at once.
- **No line carries a secret or a person.** Every line goes through
  `sipral_diag::redact_text` before it is queued, and a whole message at
  trace through `sipral_diag::redact_message`: a URI's user part and every
  IP literal become a pseudonym, and `Authorization`, `Proxy-Authorization`,
  a digest and an SDES `inline:` key are dropped outright. The pseudonyms are
  keyed HMAC-SHA256, so one value reads as one pseudonym for the life of the
  log and a call can be followed through the file. Across the C ABI the key
  is derived from the stack's `media_seed` under a label of its own — never
  from `entropy`, which a replay recording carries in clear, so an address
  pseudonym could otherwise be reversed by trying every address. Bytes the
  parser cannot read are logged by their size only. That key is drawn fresh
  per start, so the same address — `127.0.0.1` most visibly — reads as a
  different pseudonym in every run. `Log::from_salt` keys the pseudonyms
  with a salt the application keeps for the installation instead
  (`sipral::pseudonym_key`, at least `sipral::MIN_SALT` bytes), and two runs
  of one installation then pseudonymise alike and compare line by line.
- **A diagnostic trace, only when asked for.** `Log::set_diagnostic(true)`
  writes every message at trace whole — users, names, numbers and addresses
  as they went, and the peer's own address — for an operator comparing two
  runs, and prose lines lose only their credentials. Secrets never appear in
  either mode: `sipral_diag::strip_secrets` takes every `Authorization` and
  `Proxy-Authorization` value (a folded second line included), every
  `a=crypto` `inline:` key however many one line lists, every `k=` key and
  every `a=key-mgmt` payload out of each message, by line, so bytes the
  parser refuses are stripped and written rather than withheld. It is off
  by default and nothing but that call turns it on.

The level is set at run time, as often as wanted: `Log::enable`,
`Log::set_level` and `Log::disable` in Rust; in C, `sipral_stack_log(stack,
level, callback, user_data)` again, with `SIPRAL_LOG_LEVEL_OFF` or a null
callback to turn it off. Turning it off drops what was waiting. The bindings
carry it as `setLog`/`SetLog`/`set_log` on each stack class
(`docs/08-ffi.md`).

## The state snapshot

A crash report wants what the engine was holding at the moment it was
written. `MediaEngine::state` answers with a `sipral::EngineState` — every
account with its address of record and registration state, every call with
its state and the local address its media is described at, every media
session with its codec, destination and packet counts, and the D3 counters —
and `EngineState::render` writes it as text with two promises: **bounded**,
at most `sipral::LISTED` (32) rows a section with the rest counted, and the
whole cut at the byte limit given, on a character boundary, with a line
saying so; and **redacted**, through the same `redact_text` as the log.

`sipral_stack_state(stack, buffer, capacity, &len)` is the C ABI's, and adds
what only that layer holds: the transports bound, the last eight calls into
the stack that were refused (when, with what status, and the sentence), the
event and farewell queues, the signalling counters of ABI 0.30 (requests and
responses sent again, transactions timed out, requests refused at a limit),
the RTP port range with how many pairs are
reserved, and the log's own level and suppressed count. It is never longer
than `SIPRAL_STATE_TEXT_MAX` (16384) bytes with its NUL, so a buffer that size
always fits it, and it shares the log's pseudonym key, so an address reads the
same in both.

It is safe from any thread and never waits, which is the one thing a crash
handler cannot do without. When no other thread is inside the stack the
snapshot is taken there and then. When one is — or when it is asked from
inside a callback the stack is running — what comes back is the last
snapshot a poll kept, and its first line says so and when it was taken: a
poll that raised anything keeps one, at most once a second. A media session a
thread is in the middle of a frame on is listed as busy rather than waited
for.

## The RTP port range

A deployment behind a firewall opens a range of UDP ports for media and
needs every call inside it. The application owns every socket, so the range
opens nothing: `sipral::RtpPorts` is the rule, `MediaEngine::reserve_rtp_port`
hands ports out by it, and `sipral_stack_config_t`'s `rtp_port_min` and
`rtp_port_max` set it across the C ABI (`sipral_stack_rtp_port_reserve`,
`sipral_stack_rtp_port_release`; `docs/08-ffi.md`). RFC 3550 §11 as the stack
uses it: RTP on an even port, RTCP on the odd port above it — where the stack
sends and expects RTCP unless the far end said otherwise with `a=rtcp` — and
the pair reserved whole even when this end offers `rtcp-mux`, because the far
end may decline it. So an odd lower bound starts at the even port above it, an
even upper bound is never handed out, and a range holding no such pair is
refused when it is set.

A port is free when it is neither reserved nor described by a call the engine
still holds. A reservation a call takes stays taken while the call describes
its media there and comes back by itself when the call ends or moves off it;
one no call took — the bind failed, the call was refused — is handed back
explicitly. Ports go round the range rather than lowest first, so a port just
let go is the last reused while its stragglers may still arrive. With every
pair in use the reservation is refused — `sipral::PortsExhausted` in Rust,
`SIPRAL_STATUS_EXHAUSTED` in C with a last error naming how many pairs the
range has — and nothing is reserved. With a range set, the C ABI refuses a
call described at a port the range does not hand out, so a firewall rule and
the ports in use cannot drift apart. The bindings bind their media sockets
from the range themselves when a stack is created with one.

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
