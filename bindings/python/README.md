<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# The Python binding

Two layers, the way every binding here is two layers:

- `sipral/_sipral_cffi.py` — printed by `tools/abi-gen`'s Python back end
  from `sipral_ffi::abi::SURFACE`, the same declarations the header and the
  Swift, .NET and Kotlin bindings are printed from. `ffi` and `lib`: a
  `cffi` ABI-mode `cdef` naming the same types, constants and entry points
  `bindings/c/include/sipral.h` does, and the `dlopen` that turns it into
  `lib`. ABI mode needs no C compiler at install time — cffi lays every
  struct out for itself from the `cdef` text, so the `cdef` has to be
  exact; `tests/test_abi.py` checks it against `bindings/c/abi-sizes.txt`
  and against the header's own numbers.
- `sipral/stack.py`, `sipral/account.py`, `sipral/call.py`,
  `sipral/media.py`, `sipral/events.py`, `sipral/enums.py`, `sipral/errors.py`
  — written by hand against `ffi`/`lib` directly, the way `SipralAbi.swift`
  is the base the Swift package is written against. `Stack`, `Account` and
  `Call` are what an application reaches for.

## Install

```sh
cd bindings/python
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

`cffi` is the only dependency. The native library is found through
`SIPRAL_LIBRARY` (a path to the file itself, or to the directory holding
it), then beside this package, then the repository's own `target/release`
and `target/debug` — build it first with `cargo build --release -p
sipral-ffi`, or point `SIPRAL_LIBRARY` at a checkout's `target/debug`
while developing against one. To build a platform wheel with the native
library inside, run `scripts/package/wheels.sh` from the repository root.

## Use

```python
import asyncio
from sipral import Stack

async def main():
    loop = asyncio.get_running_loop()
    with Stack(bind_host="192.0.2.10", loop=loop) as stack:
        account = stack.add_account(
            "sip:alice@example.invalid",
            registrar_address="203.0.113.10:5060",
            registrar="sip:example.invalid",
            auth_user="alice",
            auth_password=secret,
        )
        account.register()

        # Without `registrar` the account never registers: registering
        # throws, and the registrar address is only the outbound proxy.
        # The stack and media sockets default to 127.0.0.1, so name an
        # address the registrar can reach.

        call = stack.place_call(account, "sip:bob@example.invalid", media_host="192.0.2.10")
        while call.media is None:
            event = await call.events.get()
            print(event.kind_name)

        call.media.send_audio(pcm_bytes)      # 16-bit mono, one call at a time
        frame = await call.media.frames.get()  # the far end's own audio back

asyncio.run(main())
```

An incoming call has no `Call` until the application decides what to do
with it: read `SIPRAL_EVENT_KIND_INCOMING_CALL` off `stack.events` and
call `stack.answer_call(event)` or `stack.reject_call(event)`. `call.dtmf`
is an `asyncio.Queue` of the digits the far end sent; `call.media.statistics()`
is `sipral_media_statistics`, as a `dict`. See `examples/agent.py` for a
complete voice agent that answers, talks and hears DTMF.

Every idiomatic method raises `sipral.SipralError` on anything but
`SIPRAL_STATUS_OK`, except an ordinary `SIPRAL_STATUS_BUSY` from another
thread racing the stack's own poll loop, which is retried for up to half a
second before it is raised as anything else
(`docs/08-ffi.md`, "Signalling on one stack is one thread at a time").

### Behind a NAT

`Stack(nat=Nat.STUN, stun_server="203.0.113.5:3478")` (`sipral.enums.Nat`)
asks that server where this stack's sockets appear from; nothing else in
an application's own code changes for the *signalling* socket, whose
mapping is `stack.events`' own `SIPRAL_EVENT_KIND_NAT_MAPPING` and every
account's `Contact` besides. A *media* socket is the application's and
exists before its call, so `Stack.place_call`/`Stack.answer_call`
themselves block the calling thread — never the poll thread — until that
socket's own mapping answers, which is what lets the offer or answer they
write carry the public address from the first packet
(`docs/06-nat.md`, `docs/08-ffi.md` "Behind a NAT"). `turn_server`,
`turn_username` and `turn_password` add a relay on the same server to the
same socket, and the same two calls then wait out its
`SIPRAL_EVENT_KIND_NAT_RELAY` too. Both credentials stay out of every log,
event and error this package raises. `ice=Ice.OFFERED`/`Ice.REQUIRED`
(`sipral.enums.Ice`), per stack or per `place_call`, is what actually puts
a relay to use — off by default, the same as `nat`, which
`docs/06-nat.md` explains. `turn_transport=Transport.TCP` reaches the TURN
server over TCP, for the network that lets no UDP out, and `Transport.TLS`
over TLS (RFC 8656 Section 3.1), 5349 being the port for it: the stack opens
the connection per media socket when `SIPRAL_EVENT_KIND_TURN_STREAM` asks,
carries everything for the relay on it and closes it when told. Over TLS
the certificate is checked against `turn_server_name` — the host part of
`turn_server` when left out — with `turn_tls_context`, or with the
platform's default trust when none is given; `ssl.create_default_context(
cafile=...)` is how a private CA or a self-signed server is trusted. `Ice.LITE` is the server's value, never the
phone's: an ICE-lite endpoint (RFC 8445 §2.5) for a host reachable at the
address it advertises, answering full ICE peers — a voice agent in a data
centre answering a WebRTC gateway. `g729_annex_b=False` on the stack turns off
G.729's Annex B silence compression (`annexb=no`) if that codec runs at
all.

Behind a NAT, every account `stun_server` showed to be behind one keeps its
registrar's flow open: a double CRLF, alone in a datagram, every 20 to 25
seconds, so that a NAT filtering by address and port keeps letting the
registrar's INVITE in long after the REGISTER (`docs/06-nat.md`).
`registrar_keepalive=False` turns it off and `registrar_keepalive_ms` sets
the interval, 1 000 to 120 000; nothing goes while the stack is suspended.
`tests/test_nat.py` proves both on the wire.

## A REFER from outside any call

`Stack(referrals=True)` hands a REFER that names no dialog — click-to-dial
from a switchboard or a CRM, RFC 3515 §4.1 — to the application as
`EventKind.REFERRAL`, with `event.fields["target"]`, `["attended"]` and
`["referred_by"]`, and `event.account` the line it arrived for.
`stack.accept_referral(event)` answers 202, reports on the call to whoever
asked and places it from that line, returning the placed `Call` with a media
socket of its own; `stack.reject_referral(event, 603)` refuses it. **Off by
default, and then every one is refused 403**: a peer that can make a phone
dial can make it dial a premium-rate number, and `referred_by` is what the
sender wrote, so taking one is the application's decision each time. One left
unanswered comes back as a second `EventKind.REFERRAL` with
`fields["status_code"]` set to the 408 the stack answered it with.

## Test

```sh
python3 -m unittest discover -s tests
```

Standard library `unittest` only, no `pytest`. `tests/test_abi.py` needs
`bindings/c/include/sipral.h` and `bindings/c/abi-sizes.txt` from this
checkout; `tests/test_call.py` runs two stacks against each other on
`127.0.0.1`, with no registrar and no network beyond loopback.
`tests/test_nat.py` runs a STUN responder of its own (RFC 5389 Section
15.2's `XOR-MAPPED-ADDRESS`, answering on loopback) to prove a stack built
with `nat=Nat.STUN` learns and advertises the mapping, records what a
`turn_server` gets as far as an Allocate request leaving for it, and runs
two stacks with `ice=Ice.REQUIRED` against each other on this host's own
routable address (never `127.0.0.1` — RFC 8445 Section 5.1.1.1 rules a
loopback address out as a host candidate) to prove media starts, both
ways, through a full ICE checklist and nomination. `tests/test_turn_stream.py`
runs a TURN server of its own on a TCP port, over TLS with a certificate made
for the run by the `openssl` command, and proves the relay made and given
back on its connection, and refused over TLS to a certificate nobody vouches
for. `tests/test_referral.py`
sends a REFER from outside any call by hand, from a plain socket, and proves
the 403 without `referrals=True` and, with it, the 202, the NOTIFYs from
`100 Trying` to the placed call's `200 OK` and the call itself; and puts an
`Ice.LITE` stack under one that requires ICE, audio crossing both ways.

`examples/agent.py` is also run by the interop lab (`scripts/lab.sh`), as
its own docstring says to run it: registered at the lab's Asterisk, called
by it, hearing a tone, echoing it back and hanging up on the `#` the
dialplan sends.

## What is not here

`numpy` support
for `call.media` (accepted wherever `bytes`/`memoryview` is, but never
required — `array.array('h', ...)` or a `numpy` array's `.tobytes()` work
today); a DNS resolver for `SIPRAL_EVENT_KIND_RESOLVE_NEEDED`, which is
delivered and left unanswered, so that a dialog stays on the path its
INVITE took (see `Stack._on_event`).
