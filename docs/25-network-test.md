<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# The network test before a call

A softphone that says "your network is fine" or "calls from here will break up"
before the user dials saves the support call that follows a bad one. The stack
asks the questions whose answers decide that, without placing a call of its own,
and comes back with one structured result and one word: good, acceptable or
poor.

## What is asked

Four parts, each one left out unless asked for (`sipral_stack_network_test`,
`sipral_network_test_config_t`):

| Part | Asked how | Needs |
|---|---|---|
| STUN | A Binding request (RFC 8489) from a socket the application binds for the test, `probe_socket`, handled exactly as a call's socket named with `sipral_stack_nat_map`; without one, the answer the signalling socket was last given | `nat` set to `SIPRAL_NAT_STUN` |
| TURN | An Allocate (RFC 8656) for the probe socket, over the stack's `turn_transport` (UDP, or a TCP or TLS connection the application opens when `SIPRAL_EVENT_KIND_TURN_STREAM` asks), given back with a Refresh of lifetime zero when the test ends | a `turn_server`, and the probe socket |
| The account's server | An `OPTIONS` (RFC 3261 §11) on the account's own transport, to its registrar, or for an account that does not register to its address of record; timed from the request to its final answer | `account` |
| Echo | A call the application placed to an echo service (an extension that plays back what it hears, configured on the PBX): its received stream measured for `echo_ms` from the moment its media starts, then hung up by the test | `echo_call` |

Any final answer to the `OPTIONS` is a server that is there: a 401 or 407 is
reported as answered and is not answered with credentials, since a server that
locks an account after failed attempts would count a probe that spent one.

The parts run side by side. The result is one `SIPRAL_EVENT_KIND_NETWORK_TEST`,
raised once every part has answered or `timeout_ms` (30 s by default) has
passed; a part still waiting then counts as failed. Several tests may run at
once, each named by the number `sipral_stack_network_test` returned.

## What comes back

`sipral_network_test_event_t`:

- `stun` (`sipral_network_probe_t`) and `nat` (`sipral_nat_kind_t`): whether
  the server answered, and what the one answer says — `OPEN` when the server
  saw the socket's own address, `PORT_PRESERVED` when the address was
  translated and the port kept, `PORT_CHANGED` when both were; `local` and
  `mapped` are the two addresses. Approximate on purpose: telling RFC 4787's
  mapping and filtering behaviours apart needs a server that answers from a
  second address (RFC 5780), which few public servers do.
- `turn` and `turn_protocol`: whether a relay was allocated, and over what.
- `server`, `server_status`, `server_round_trip_ms`: answered (with what, and
  how fast), timed out, or the transport failed.
- `echo`, `echo_verdict`, `loss_percent`, `jitter_ms`, `has_round_trip` and
  `round_trip_ms`, `one_way_delay_ms`, `r_factor`, `mos`: what came back on the
  echo call.
- `verdict`: the worst of the parts that were tested, `UNKNOWN` when nothing
  was.

## The echo rating

R and the MOS are the simplified ITU-T G.107 E-model `sipral-rtp` already
computes for RTCP XR (`sipral_rtp::evaluate_e_model`), rated for G.711 with
packet loss concealment — `Ie` 0 and `Bpl` 25.1, G.113 Appendix I — whatever the
echo call negotiated: the test rates the network, and a codec's own impairment
is not the network's. The packet loss is what never arrived and what arrived
too late to play, as RFC 3611 §4.7.1 counts it. The one-way delay is half the
round trip RTCP measured plus the delay the jitter buffer held the audio for;
a call too short for an RTCP report to come back is rated without the round
trip, and says so with `has_round_trip` at zero. Eight seconds, the default
`echo_ms`, leaves room for the first report, which RFC 3550 §6.2 delays.

## The verdict, and why each line is where it is

| Part | Good | Acceptable | Poor |
|---|---|---|---|
| Account's server | answered | — | timed out, or the transport failed |
| STUN | answered | no answer | — |
| TURN | relay allocated | refused or no answer | — |
| Echo: packet loss | under 1 % | under 3 % | 3 % or more, or no audio came back |
| Echo: jitter | 20 ms or less | 50 ms or less | over 50 ms |
| Echo: round trip | 300 ms or less | 600 ms or less | over 600 ms |
| Echo: MOS (CQ) | 4.0 or more | 3.6 or more | under 3.6 |

- A server that does not answer means no call is placed at all: poor.
- A STUN or TURN server that does not answer leaves calls working wherever the
  far end sends its media back to where this end's came from — symmetric RTP,
  which every carrier does — but not through every NAT: a warning, not a
  failure.
- ITU-T G.114 sees conversation start to suffer past 150 ms one way and calls
  400 ms the limit for most uses; the round-trip lines are 150 and 300 ms one
  way, doubled.
- About 1 % loss is what concealment hides from a listener; at 3 % G.711 drops
  a whole category in G.107's ratings.
- MOS 4.0 and 3.6 are G.107 Annex B's "satisfied" and "some users
  dissatisfied" lines.

The thresholds live in `sipral::network_test`, which the C ABI and every layer
read; they are not configurable, so that "good" means the same thing in every
application that shows it.

## In the layers

| Layer | Start | Read |
|---|---|---|
| C | `sipral_stack_network_test` | `SIPRAL_EVENT_KIND_NETWORK_TEST`, `payload.network_test` |
| Rust | `UserAgent::probe_server` and `UaEvent::ServerProbed` for the `OPTIONS`; `sipral::network_test` for the rating | — |
| Python | `Stack.network_test(account, probe=True, echo_call=..., echo_ms=..., timeout_ms=...)`, which opens and closes the probe socket itself | `EventKind.NETWORK_TEST`, `fields["verdict"]` and the rest |
| Swift | `SipralStack.networkTest(account:echoCall:echoMs:timeoutMs:)` | `SipralEvent.networkTestData` |
| .NET | `SipralStack.NetworkTest` | `SipralEventArgs.NetworkTest` |
| Kotlin, JVM | `SipralClient.networkTest`, `SipralJava.networkTest` | `networkTestOf(event)` |
| Dart | `SipralStack.networkTest` | `SipralStackEvent.networkTest` |
| React Native | `client.networkTest({account, echoCall})` | the client's `networkTest` event |

Python's layer is the one that binds a probe socket for the STUN and TURN
parts; the others ask about the signalling socket's mapping and test no relay,
and an application that wants both binds a socket and passes its address
through the C entry point.
