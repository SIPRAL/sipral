<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# 16 — A lifecycle model for a machine that suspends

`docs/13-client-requirements.md` D4, and the general form of A7, B3 and C4. It
is here as its own document because it is the one place where the requirement
is not "implement the RFC": no specification says what a user agent should
believe after eight hours of being switched off, and every one that answers it
badly answers it the same way — by believing what it believed before.

The failure being designed against, as `docs/13-client-requirements.md` B3
records it: *the worst recurring crash of a production softphone fires
during wake-from-sleep or a network change, on a background timer, while
subscriptions are being refreshed over a transport that is no longer alive. In
one shape the machine had lost name resolution while asleep and a cached
registration still read as valid, so no amount of "are we registered?" checking
could have prevented it. The process terminated.*

Two things follow from that sentence, and everything below is one of them.

## The clock cannot tell you that you slept

A monotonic clock does not advance while the machine is suspended. That is what
monotonic means on every platform this stack runs on, and it is normally the
property you want: nothing this stack schedules can be moved by somebody
changing the time zone.

The consequence here is severe. A stack that slept for eight hours comes back
believing that eight milliseconds passed. The binding granted an hour ago has
fifty minutes to run. The refresh is scheduled for forty-two minutes from now.
The subscription is `active` and its table still says the colleague is on a
call. Every one of those is wrong, and none of them is *detectably* wrong —
there is no measurement the stack can take that contradicts any of it.

So the operating system has to say so, and these entry points are how. They are
the application's to call, on the notification the platform already delivers,
and nothing else in this stack can substitute for them.

## The states

One machine, on `UserAgent`, read with `lifecycle()`.

```
                    suspending()
       Running ─────────────────────► Suspending
          ▲                                │
          │                                │ resumed()
          │  a registrar answered          ▼
          ├──────────────────────────  Recovering ◄──── network_changed()
          │                                │                  │
          │                                │ ladder ran out   │ to.link == Down
          │                                ▼                  ▼
          │                             GaveUp          InterfaceLost
          │                                                   │
          └───────────────────────  ResolutionLost ◄──────────┘
                                    name_resolution_lost()      network_changed()
```

`Running` is the ordinary state and the only one in which what this stack
believes is what it last proved. Every other state is a claim that something
believed is no longer evidence, and every one of them is left the same way: a
registrar answered a REGISTER, which proves the path.

**One account is enough to prove it.** The ladder is about whether anything can
leave this machine and come back, not about whether every account is happy. An
account that still fails against a working path is a registrar problem and it
has its own RFC 5626 §4.5 schedule for that — which is the reason the two
back-offs are in different layers and neither doubles the other's wait.

**An account without a registrar takes no part in it.** A trunk
(`Account::unregistered`) has no binding, so `Distrust` has nothing of its to
demote and `Reregister` nothing of its to send, and it is never counted as
unverified; its subscriptions are not a binding, and are demoted and sent again
like anybody's. It cannot prove the path either. A stack whose every account is
one of these climbs a ladder the way a stack with no accounts does: it still
asks for a transport or an address, which its calls need as much as any
registration would, and when the rungs run out it reports `RecoveryGaveUp` with
nothing unverified, because nothing it holds is something a registrar can
answer.

## The state a wake produces

`RegistrationState::Unverified`: a binding the registrar really did grant, over
a transport this process has since suspended or lost, that nothing has proved
since.

It is not `Registered`, because it is not evidence. It is not `Failed`, because
nothing refused it. It is not `Idle`, because a REGISTER really did go out and
a `Call-ID` and a sequence number really are in use. Having a name for it is the
fix for the sentence at the top of this document: after a wake, "are we
registered?" answers *unverified*, and an application that renders a green dot
from it is making a decision rather than being misled by one.

It is said, not only readable. The moment a binding becomes unverified,
`UaEvent::Unverified` names its account — `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED`
with the state `SIPRAL_REGISTRATION_STATE_UNVERIFIED` across the C ABI — so a
line whose resolver died after it registered goes grey on the next poll rather
than staying green until a refresh fails minutes later.

The FFI enum carries it as `SIPRAL_REGISTRATION_STATE_UNVERIFIED`, beside
`SIPRAL_REGISTRATION_STATE_RESTORED`. `crates/sipral-ffi/src/lifecycle.rs` is
where both become producible from C: `sipral_stack_suspending`,
`sipral_stack_resumed`, `sipral_stack_network_changed`,
`sipral_stack_interface_lost`, `sipral_stack_name_resolution_lost` and
`sipral_account_rebind` are their counterparts in `sipral.h`, and
`SIPRAL_EVENT_KIND_RECOVERY` is the event that says a ladder ended — by
proving the path again or by giving up.

## suspending — a hard deadline, and what fits inside it

Entered from an operating-system notification. The process is stopped shortly
afterwards and **nothing waits for us**, so everything reachable from
`UserAgent::suspending` is synchronous, bounded by the number of accounts and
subscriptions, allocates nothing that grows, and cannot fail. It returns a
fixed-size `Suspending` report rather than a list, for that reason.

**It sends nothing, and that is a decision.** The obvious thing to attempt is a
REGISTER with `Expires: 0`, so that the registrar stops offering calls to a
phone that cannot answer them. It is wrong twice over:

- nothing waits for us. The datagram is handed to a socket the operating system
  is about to stop servicing, and whether it left is not knowable from inside
  the process. An operation whose success cannot be observed is not a
  guarantee, it is a hope with a cost;
- and if it *does* leave, the damage is worse than the failure it was meant to
  avoid. A de-registered device cannot be woken by a push notification
  (`docs/13`, C2), so the polite thing to do on the way out is precisely the
  thing that makes the phone unreachable until somebody unlocks it.

An application that genuinely wants a de-registration on the way out — a
desktop client being quit, rather than a laptop whose lid is closing — calls
`unregister` and drains `poll_transmit`, which is a different intention and has
a different entry point.

**Calls that are up are left exactly as they are.** A lid closing and opening
again is seconds. Hanging up a live call because the machine blinked is worse
than finding out a few seconds later that it is gone, and the two things that
do find out — RFC 4028's session timer and the media stall watchdog of
`docs/13` B5 — are already the right ones to find out.

| | |
|---|---|
| **Deadline** | the platform's. Everything here is straight-line work over two maps |
| **Ladder** | `Distrust`. There is no second rung: nothing that needs an answer can be attempted in this window |
| **Sends** | nothing |
| **Leaves scheduled** | nothing. `poll_timeout()` answers `None` |
| **Gives up** | not applicable; nothing was attempted |

## resumed — arbitrary time has passed and every transport may be dead

`Recovery::Reprove`:

| Rung | What it does | Then |
|---|---|---|
| `Distrust` | every live or restored binding becomes `Unverified`, forgetting any transaction from before the sleep too; every live subscription stops being evidence and its own timers go with it; nothing stays scheduled | at once |
| `Reregister` | a REGISTER for each unverified binding and a SUBSCRIBE for each subscription `Distrust` demoted, both out of dialog with a fresh `Call-ID`, on the transport the account already has | 64·T1 if one went out, at once if none could be sent |
| `WantTransport` | an event: the transport cannot be written to and nothing here opens a socket | 64·T1, or at once when `rebind` is called |
| `Reregister` | again, on whatever the application bound | 64·T1 |
| `GiveUp` | `UaEvent::RecoveryGaveUp` with a reason code and the count of bindings left unproved | — |

The existing transport is used *first* and deliberately. Most wakes are short
and the socket survived them; asking the application to rebuild on every lid
opening is a cost paid a hundred times for the one occasion it was needed. When
it has not survived, `UserAgent::register` fails before anything reaches a
socket, no transaction exists, and the ladder climbs to `WantTransport` in the
same microsecond rather than waiting out a transaction that was never created.

What is believed on the way out of it:

- **registrations** — nothing. Every one that claimed something is `Unverified`
  until a registrar answers;
- **subscriptions** — nothing about the resource. A live one is demoted, so
  `dialog_info` answers `None` from the instant of the wake: a lamp showing a
  colleague as free because a NOTIFY said so an hour and one suspend ago is the
  one wrong answer a busy lamp field must never give. Its own deadlines go with
  it, the same as a registration's — `suspending` still sends nothing, so
  re-proving it waits for whatever calls `resumed` next, and the next section
  says how bounded that wait now is;
- **dialogs and calls** — kept. See above;
- **timers** — this layer's are cleared and rearmed by what follows. The
  endpoint's transaction timers are not touched, because a transaction that was
  running when the machine slept still has to conclude, and it concludes as a
  failure with a reason code.

## network_changed(from, to) — enough detail to choose

Both sides are a `Network`: a `Link` kind, the local address, the platform's own
identity for the interface, and whether names resolve on it. Three facts and a
label, because three facts are what the decision needs.

- the **address** is the one every `Via` and every `Contact` this stack writes
  carries, so a change of it invalidates every transport and every binding at
  once;
- the **interface** is needed because two networks hand out the same private
  address all the time, and a phone that walks from one office to another gets
  away with it until a call comes in;
- **whether names resolve**, because that is the one failure that leaves
  everything else looking healthy.

The decision, in order, and the order is the argument:

| Condition | Answer | Why |
|---|---|---|
| `to.link == Down` | `Detach` | there is no path; see below |
| address or interface differs | `Rebuild` | a transport bound to an address that no longer exists carries nothing, resolver or no resolver |
| `!to.resolves` | `Resolve` | packets leave and no name can be turned into an address |
| link kind differs, or `!from.resolves` | `Reregister` | the path stands; what is upstream of it does not. A roam between access points on one subnet is exactly this, and so is a tunnel coming up |
| otherwise | `Nothing` | nothing this stack uses is different, and a laptop that flips between two access points all day must not produce a re-registration storm |

`Reregister`'s ladder is `Distrust, Reregister, Reregister, GiveUp`; `Rebuild`'s
is `Distrust, WantTransport, Reregister, WantAddress, Reregister, GiveUp`. The
answer is returned from the call as well as reported as an event, so an
application does not have to read an event to find out whether anything
happened.

### A call in progress moves with the address

The ladders are about bindings; a call up at the moment of a `Rebuild` has a
problem none of them touches. Its media was described at the old address, and
the far end goes on sending the audio there — to a socket that no longer
exists. A stack that only registers again keeps the call up and silent in one
direction, which is what a laptop moving from Wi-Fi to a tethered phone did
until 8.10.

So a `Rebuild` also raises `UaEvent::CallAddressWanted` for every call that
can still be offered a new description: up, or early in a dialog that allows
UPDATE. A roam that keeps the address raises nothing, because every socket
bound to it still receives. What the application does, in this order:

1. bind the SIP transport at the new address and say so
   (`Input::TransportBound`, same `TransportId`), and answer the ladder's
   `WantTransport` with `rebind(account, transport, remote, contact)`;
2. bind a media socket for each named call on the new network;
3. hand its address to `MediaEngine::readdress(call, local, public)`
   (`sipral_call_media_readdress` in C).

The re-INVITE is the call's last description with only `c=` and the port on
`m=` moved: codecs, direction, keys and fingerprint stay, `o=` keeps its
address (RFC 3264 §8 wants it identical but for the version), and a DTLS
association outlives the move because a datagram transport lets one span
several 5-tuples (RFC 8842 §3.2). It carries the account's `Contact` as it is
then — which is why `rebind` goes first — so the far end addresses the rest of
the dialog, the BYE included, to the new target. The new socket is the call's
from the moment it is handed over, whatever the far end answers: the old one
names nothing any more.

A call running ICE is refused (`MediaError::MovesWithIce`): its candidates
were gathered on the old socket, and moving it is a restart gathered on the
new one. A call that offered ICE to a peer that answered without it is an
ordinary call, and its re-offer leaves the ICE lines out.

The lab proves it against Asterisk on its default endpoint settings, which
send RTP to the `c=` they were given and nowhere else (`scripts/lab.sh move`):
the harness's container is taken off the lab network mid-call and connected
again at another address, and the echo comes back after the re-INVITE. A
re-INVITE that refreshed the target and kept the old `c=` was answered 200 and
brought back no audio at all, which is the difference `readdress` makes.

## interface_lost — nothing is tried, and that is the recovery

`Recovery::Detach`. One rung, `Distrust`, and then the machine rests.

There is no probe and no back-off, because a retry is not a smaller version of
working: with no interface, nothing leaves, and a stack that keeps trying is a
stack that keeps a phone warm in a pocket for no result. `poll_timeout()` stops
offering deadlines of this layer's, which is the cheapest the stack ever is.

It is also the one ladder with no `GiveUp` rung, and that absence is the
design. There is nothing to give up on. The way out is the application saying
the network is back, with `network_changed`, which is a notification every
platform delivers.

## name_resolution_lost — the dangerous one

`Recovery::Resolve`, and it is a separate state from `interface_lost` because
the recovery is the opposite one. The interface is up and packets leave, so
everything reads healthy — while every address this stack learned from a name
may now stand for somewhere else, or for nothing.

**It distinguishes accounts.** Only bindings whose registrar was written as a
name needed a resolver to become an address at all; an account pointed at a
literal `sip:192.0.2.9` never did, and is left running, refreshing, and
believed — as is an account with no registrar, whose outbound proxy is an
address and never a name. That distinction is the whole reason this is not just a flavour of
`interface_lost`.

| Rung | What it does | Then |
|---|---|---|
| `Distrust` | bindings and subscriptions that needed a name stop being evidence, timers included | at once |
| `WantAddress` | an event: the address held was learned from a name, and the application owns the resolver; an account located by RFC 3263 (`Account::located`) is looked up again through `UaEvent::LookupWanted` | 64·T1, or at once on `rebind` or once every such lookup has answered and one named an address |
| `Reregister` | try the address already held, and resubscribe whatever `Distrust` demoted | 64·T1 |
| `WantAddress` | ask again | 64·T1 |
| `Reregister` | try again, and resubscribe whatever is still owed one | 64·T1 |
| `GiveUp` | `RecoveryFailure::Unresolved` when nothing was ever supplied | — |

The cached address is asked about before it is used, and used before the ladder
gives up. A resolver usually dies while the registrar stays exactly where it
was, so one datagram to the address already held is the cheapest thing that can
end this — but it goes out only after the application has been asked for a
better one and has not produced one.

## The back-off, and why there is only one number

Every rung waits **64·T1, drawn uniformly between half of it and all of it**.

64·T1 is not a number chosen here. RFC 3261 §17.1.2.2 gives a non-INVITE client
transaction exactly that long to conclude, so a rung never fires while the
request the rung before it sent is still trying, and the ladder cannot outrun
itself. With the default T1 of 500 ms that is 32 seconds, and a resume that
recovers nothing at all reports `RecoveryGaveUp` after about a minute and a
half.

The ladder does **not** double. Doubling on top of that would only add dead time
to a wake, where somebody is waiting for their phone to work — and the doubling
that a registrar needs protecting by already exists one layer down, on the
RFC 5626 §4.5 schedule that every registration failure goes on. The draw between
half and whole is that schedule's idea, and it is here for its reason: a fleet
of phones waking from the same outage must not come back in the same
millisecond.

Two things shorten a rung. A `Reregister` that could not put anything on a
transport climbs immediately, because there is nothing in flight to wait for. A
`WantTransport` or `WantAddress` that the application answers with
`UserAgent::rebind` climbs immediately, because the answer is the thing the
wait was for.

`rebind` is this end's own address changing — the answer to `WantTransport` or
`WantAddress` — and carries a new `Contact` because of it, and it is this
ladder's own recovery. `UserAgent::retarget` (`docs/04-ua.md`) looks similar
but answers a different question: the registrar itself moved under an account
this ladder has no complaint about. It never climbs a rung and is not one of
these two answers, even where both could in principle be triggered by the same
DNS record changing underneath a name.

## The guarantee, and what it does not cover

**No failure of a network operation terminates the process.** Not on a
background timer, not on a dead transport, not during suspend, not when name
resolution has gone. Each is a `UaEvent` with a reason code.

The mechanism is the workspace lint set: `unsafe_code = "deny"` outside the FFI
and device crates, and `clippy::panic`, `unwrap_used`, `expect_used` and
`indexing_slicing` denied through `scripts/check.sh`. That is what makes the
guarantee structural rather than a matter of care. The tests are what make it a
guarantee rather than an aspiration, and they drive the stack through the
adverse paths rather than the working one — a dead transport mid-refresh,
resolution gone while a cached registration still reads valid, a timer firing
after a suspend that never resumed, several accounts of which some are healthy
and some are not.

What it does **not** cover, stated plainly because a guarantee with unstated
edges is worse than none:

- **Aborts the process cannot catch.** Allocation failure, stack exhaustion
  from a deeply recursive application callback, and a `SIGKILL` from the
  platform for missing a deadline. None of these is a network operation and
  none is catchable in a library.
- **The application's own code.** A `Handler` (the reference loop's callback
  trait, `sipral_ua::Handler`, behind the `reference-loop` feature) that
  panics panics on its own thread; nothing here catches it. The FFI boundary is the one place that must
  catch, and it does — `crates/sipral-ffi` routes every entry point through one
  macro, and `scripts/check.sh` fails the build if a symbol is exported around
  it.
- **Platform code below the socket.** A device driver or a TLS library the
  application linked is outside this guarantee entirely.
- **`crates/sipral-io-*` and `crates/sipral-ffi`.** They re-enable `unsafe`
  deliberately, and they have their own arguments to make.
- **Liveness, as distinct from safety.** Nothing here promises that a
  registration comes back. It promises that every attempt and every failure is
  an event with a reason code, and that the stack ends in a state that can be
  asked about. `GaveUp` is a documented outcome, not a bug.
- **A subscription is dark, not wrong, for up to one `Reregister` rung-wait
  after a wake.** See the next section.

### Re-proving a subscription after a wake

`Distrust` demotes a live subscription so that `dialog_info` stops being
evidence at once, which is the safety-critical half, and clears its own
`due`, `lapses_at` and `forks_until` in the same pass — a refresh or a lapse
scheduled against a clock that stopped while the machine slept is not
evidence of anything either, and left alone it would fire against a
wall-clock reading it was never measured for. `Reregister` is what re-proves
it: a fresh, out-of-dialog SUBSCRIBE with a new `Call-ID`, for every
subscription `Distrust` demoted and nothing has touched since, on the same
rung and the same 64·T1 bound as the registrations climbing beside it.

Dark rather than wrong is still the failure direction while that SUBSCRIBE is
in flight — nothing here claims a lamp state a moment before the notifier
confirms it. What changed is how long dark can last: bounded by the rung
wait now, not by whatever the subscription's own refresh interval happened
to be when the machine went to sleep. An application that wants its lamps
back sooner than that still has `unsubscribe` and `subscribe` for the
handles it cares about, which cost two calls and no round trips on the way
out; the rung above reaches for the same mechanism internally, through
`crates/sipral-ua/src/subscription.rs`'s own re-arm rather than the
application's pair of calls, which is why it costs nothing extra on the
wire.

## C5 — cheap when idle

A polled architecture suits a phone only if the polling can become cheap or stop
entirely while the application is backgrounded with no call. That has to be
answerable rather than asserted, so it is: `UserAgent::idle()` returns what is
scheduled, when the next deadline is, and whether there is anything at all to
do.

```rust
pub struct Idle {
    pub next: Option<Instant>,   // the same instant poll_timeout() answers with
    pub registrations: usize,    // bindings with something scheduled
    pub subscriptions: usize,    // subscriptions being kept alive
    pub calls: usize,
    pub transactions: usize,     // still running in the endpoint
    pub dialogs: usize,
}

impl Idle {
    pub const fn is_quiet(&self) -> bool;  // no deadline, no call, no transaction
}
```

`next.is_none()` is the whole answer to "may this loop stop?". Nothing in the
stack has a deadline, so nothing can happen until a packet arrives or the
application asks for something.

### What runs, and how often

| What | Cost when idle | May it be stopped? |
|---|---|---|
| Registration refresh | one wake per account per binding lifetime, at 0.85 of what the registrar granted. An hour granted is **one wake per hour**, at 3060 s | not without losing the binding |
| Subscription refresh | the same fraction of the same default hour: **one wake per subscription per hour**. Thirty lamps are thirty wakes an hour, and they land near the registration's because both ask for an hour | yes, by unsubscribing |
| Transaction timers | only while a transaction is running. A non-INVITE over UDP holds Timer K for 5 s after its final response and then there is nothing | no, and there is nothing to stop |
| Session timer (RFC 4028) | only while a call has one. 1800 s negotiated means the refresher wakes at 900 s and the other end at 1768 s. A call that is not up by the refresh time (a retry after a 422 still ringing, a 2xx still waiting for its ACK) wakes once every quarter of the interval until it is up or over | no; a call with no timer is a line billed for nothing |
| Stream keepalive | a 4-byte ping every 25 s per **stream** transport, jittered. Datagram transports have none | yes: `EndpointConfig::keepalive_interval = None`. It exists to keep a NAT binding open, so stopping it costs reachability on that flow |
| Reference loop tick | 200 ms by default, so 5 turns a second on a line where nothing happens | yes: `Runtime::idle_cap(None)` (reference loop only), and then a turn waits for a deadline or a packet |

### The floor

Three states have no deadline at all, and in each of them `poll_timeout()`
answers `None` and `idle().is_quiet()` is true:

- **`Suspending`** — nothing is scheduled, so a timer that fires after a suspend
  that never resumed does nothing at all. That is a test;
- **`InterfaceLost`** — nothing is tried, so nothing is scheduled;
- **`GaveUp`** — the ladder is over. Bindings whose REGISTER reached a transport
  are still on their own back-off; the ones that never got that far are counted
  in the event, and nothing is retrying them.

Combined with `Runtime::idle_cap(None)`, an idle backgrounded stack with no call
performs **no work between packets**: no timer fires, no allocation happens, and
the loop sits in one blocking read.

### The tests that produce those numbers

All of them in `crates/sipral-ua/src/lifecycle.rs`, on the fake clock, so a day
of a phone's life runs in microseconds:

- `an_idle_stack_wakes_once_an_hour_per_account_and_for_nothing_else` — one
  binding granted an hour, next deadline at exactly 3060 s, zero transactions
  once Timer K has run out;
- `nothing_registered_and_nothing_dialled_is_nothing_to_do` — `is_quiet`,
  `next == None`;
- `a_suspended_stack_has_no_deadline_left_to_fire` — `poll_timeout() == None`
  after `suspending`;
- `a_timer_that_fires_after_a_suspend_that_never_resumed_does_nothing` — eight
  hourly timeouts on a suspended stack: no bytes, no events;
- `losing_the_interface_stops_everything_and_tries_nothing` — and an hour later
  it is still true;
- `what_is_scheduled_is_answerable_without_reading_an_event` — the counts;
- in `crates/sipral-ua/src/runtime.rs`,
  `a_stack_with_nothing_scheduled_and_no_cap_waits_for_a_packet` — the
  arithmetic of the loop's wait, tested without waiting for any of it.
