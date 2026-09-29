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
  `sipral/media.py`, `sipral/audio.py`, `sipral/events.py`,
  `sipral/enums.py`, `sipral/errors.py` — written by hand against `ffi`/`lib` directly, the way `SipralAbi.swift`
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
        while not call.ended:
            event = await call.events.get()
            print(event.kind_name)

asyncio.run(main())
```

That is a whole softphone on macOS and Windows: the stack is in **device
mode** there by default, so the library opens the machine's own microphone
and loudspeaker and pumps the call through them, and the code above has no
audio in it at all. `stack.audio` is what a person still decides (see "The
devices" below). Where the library has no audio backend — Linux, or a build
without one; `sipral.features()` has `Feature.AUDIO_DEVICE` exactly where it
does — the default is **application mode**, and so is
`Stack(audio=AudioMode.APPLICATION)` anywhere: the frames are the
application's, which is what a voice agent, a recorder or a server wants:

```python
        call.media.send_audio(pcm_bytes)      # 16-bit mono, one call at a time
        frame = await call.media.frames.get()  # the far end's own audio back
```

An incoming call has no `Call` until the application decides what to do
with it: read `SIPRAL_EVENT_KIND_INCOMING_CALL` off `stack.events` and
call `stack.answer_call(event)`, `stack.reject_call(event)` or
`stack.redirect_call(event, targets)`. `call.dtmf` is an `asyncio.Queue` of
the digits the far end sent; `call.media.statistics()` is
`sipral_media_statistics`, as a `dict`. `examples/softphone.py` is a
terminal softphone in device mode, with no audio code; `examples/agent.py`
a voice agent in application mode that answers, talks and hears DTMF.

## The devices

`stack.audio` (`sipral.audio.Audio`) is the library's audio engine, in
device mode. `stack.audio.devices()` lists every device as an `AudioDevice`
— `id`, `name`, `input_channels`, `output_channels`, whether it is the
system's default either way, and whether it is still `present`; an id is
the engine's, survives `refresh()` and is never reused, so a device
unplugged keeps its row. `select(AudioRole.MICROPHONE | SPEAKER | RINGER,
device)` puts one role on a device and `select(role, None)` back on the
system's route; `selection(role)` reads back what was chosen and what the
role is running on, which differ while a chosen device is unplugged — the
choice is kept and comes back with the device. macOS runs the microphone
and the loudspeaker as one unit, so there only the speaker is chosen and
the others raise `SIPRAL_STATUS_NOT_SUPPORTED`; Windows takes all three.
`set_gain(direction, ratio)` (`microphone_gain` and `volume` as
properties; 1.0 is unity, 4.0 the most) and `set_muted(direction, muted)`
belong to the direction and survive every device change; `level(direction)`
is the meter, 0 to 32767, cheap enough for a window's timer.
`Stack(audio_activation=AudioActivation.MANUAL)` opens the devices only
between `activate()` and `deactivate()` — what CallKit or a telecom
framework's audio focus asks for — instead of with the first call and the
last; `ring(pcm, rate)` plays a tone on the ringer until `stop_ringing()`;
`info()` says what is open, whether the platform's own echo cancellation
sits behind the microphone, and the render delay. A device arriving or
leaving, or the default moving, is `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED`
on `stack.events`, typed as `event.audio` (`AudioNotice`): react to an
`AudioOrigin.SYSTEM` one, never re-select on an `ENGINE` one.

In device mode `call.media.pumped` is true, `call.media.frames` stays
empty and `send_audio` raises: the packets the engine encodes are handed
back to this package, which sends them from the call's own media socket.

## Who is calling, why a call ended, where it went

Every call event carries `event.identity` (`CallerIdentity`: the
`P-Asserted-Identity` and `verstat` — believed only from an address in the
account's `trusted_peers`, and `trusted` says whether this call came from
one — the caller's `Privacy`, the top `Diversion` and how many `Diversion`
and `History-Info` entries there were) and `event.answering` (`Answering`:
`Answer-Mode`, `Priv-Answer-Mode`, `answer_after_ms` when the call asks to
be answered by itself — whether to is the application's policy — the ring
source and the `Alert-Info` URI). `call.identity(IdentityText.DIVERSION)`
or `stack.call_identity(event, which)` reads a whole list.
`SIPRAL_EVENT_KIND_CALL_ENDED` carries `event.cause` (`EndCause`), the
`Reason` of the BYE, CANCEL or refusal: `sip == 200` on a CANCEL is
another phone answering, not a missed call. `call.hangup_for(q850_cause=16,
text=...)` ends a call with a `Reason` of its own, and
`stack.redirect_call(event, ["sip:desk@example.com"], reason="no-answer")`
answers an incoming call 302 with a `Diversion`.

`add_account` takes the per-account options: `session_timer` and
`session_interval_seconds` (RFC 4028), `privacy` (`Privacy.ID` places every
call anonymous in `From`) and `trusted_peers`, the addresses whose asserted
identity the account believes and toward which alone it asserts its own.

## STIR/SHAKEN, SRTP per account and the encryption report

`add_account(..., stir_key=key, stir_certificate_url=url)` signs every call
the account places (RFC 8224, with RFC 8588's `attest` and `origid`); the
key is the bare 32 bytes or SEC1 or PKCS #8 in DER or PEM, and the stack
needs the time first: `stack.stir(None)` on one that only signs. A signed INVITE
is some five hundred octets longer, and past RFC 3261's 1300 over UDP it
needs a stream transport. `stack.stir(anchors)` verifies the callers of
every account that reports (the default) or is `StirVerification.STRICT`:
`EventKind.CALLER_VERIFICATION` with `event.verification.stage ==
CERTIFICATE_WANTED` asks for the chain at `certificate_url`, which
`stack.stir_certificate(event.call, chain)` hands over (`None` for one that
could not be had); the verdict follows as the same kind, just before the
call, and `event.identity.verification` carries it on every call event.

`add_account(..., srtp=lib.SIPRAL_SRTP_REQUIRED, srtp_suites=[...])` holds
every call of one account to its own SRTP policy and suites; a call may ask
for more and never less. `call.media.encryption()` is the encryption report
(`Protection`: how the keys were exchanged, encrypted, the suite, and
whether the exchange authenticated the far end), and `event.protection`
carries it on media started, changed and secured.

## A call that moves with the network

`stack.move_to(host)` is what an application calls when the platform says
the address changed: the signalling socket is bound again there, the change
reported, and every account added without a `contact` pointed at the new
address (`Account.rebind` does one by hand). On `Recovery.REBUILD` each call
whose media was described at the old address gets
`SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED`, and `call.readdress(host)` offers it
again from a socket there — a re-INVITE moving only `c=` and the `m=` port —
so the far end sends its audio where this machine now is. A call running ICE
is moved with `call.restart_ice()` instead.

`call.srtp_suite` is the transform a DTLS-SRTP handshake settled on, from
`SIPRAL_EVENT_KIND_MEDIA_SECURED` — `SrtpSuite.AEAD_AES256_GCM` between two
ends of this stack, RFC 6188's and RFC 7714's suites included.

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

`stun_fallbacks=["198.51.100.2:3478", ...]` names the STUN servers to turn
to, in order, when `stun_server` stops answering; every socket moves on by
itself, and an `EventKind.STUN_SERVER` event (`fields["state"]` a
`StunServerState`, `fields["server"]`, `fields["previous"]`) says when the
server in use changed or every one failed (`docs/06-nat.md`, "More than one
server"). `stack.set_stun_servers([...])` replaces the list on a running
stack, and turns STUN on for one created without it; an empty list turns it
off again.

Behind a NAT, every account `stun_server` showed to be behind one keeps its
registrar's flow open: a double CRLF, alone in a datagram, every 20 to 25
seconds, so that a NAT filtering by address and port keeps letting the
registrar's INVITE in long after the REGISTER (`docs/06-nat.md`).
`registrar_keepalive=False` turns it off and `registrar_keepalive_ms` sets
the interval, 1 000 to 120 000; nothing goes while the stack is suspended.
`tests/test_nat.py` proves both on the wire.

A stack holds 128 calls at once unless `max_dialogs` says otherwise: past
it an incoming call is answered 503 and `place_call` raises with
`SIPRAL_STATUS_LIMIT_REACHED`. `max_server_transactions` (256),
`diagnostic_decisions` (64) and `diagnostic_records` (32) are the other
ceilings, zero for the default each (`docs/08-ffi.md`, "Limits, and what
went out twice").

## The log, the state and the counters

```python
import logging

logging.basicConfig(level=logging.INFO)
stack.log_to()                      # the "sipral" logger, at its own level
logging.getLogger("sipral.sip").setLevel(sipral.TRACE)   # whole SIP messages
print(stack.counters().requests_retransmitted)
print(stack.state())                # for a crash report
```

`stack.log_to(logger=None, level=None)` sends the stack's log to the
standard `logging` module: each line to the child logger of the part of the
stack that wrote it (`sipral.call`, `sipral.registration`, `sipral.sip`,
`sipral.api`, ...), `ERROR`/`WARN`/`INFO`/`DEBUG` as their `logging`
namesakes and `TRACE` as `sipral.TRACE` (5). Left out, `level` follows the
logger's effective level, so lines nobody keeps are never formatted.
`stack.set_log(level, handler)` takes a plain callable instead. Every line is
redacted before it leaves the library: no user part, number, IP address or
credential (`docs/17-observability.md`).

`stack.counters()` is a frozen `sipral.Counters`: registrations, how calls
ended, what screening refused, and, since ABI 0.30, `requests_retransmitted`,
`responses_retransmitted`, `transactions_timed_out` and
`requests_refused_at_limit`. `stack.state()` is the redacted text snapshot
of everything the stack holds, safe from any thread. `Stack(rtp_port_min=...,
rtp_port_max=...)` keeps every media socket this package opens inside a
firewall's range. `tests/test_logging.py` and `tests/test_nat.py` prove each.

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

## What a call carries in its audio, and recording it

A digit the far end leaves in the audio arrives as `EventKind.IN_BAND_DIGIT`
and on `call.dtmf` like any other: by default on a call that negotiated no
telephone event, and on every call or none with
`Stack(dtmf_detection=DtmfDetection.ALWAYS)` / `.OFF` or
`call.set_dtmf_detection(...)`. `call.send_dtmf(digits)` writes the tones
into the audio where the far end took no telephone event, and
`via=DtmfVia.IN_BAND` does so on any call. `call.detect_progress(...)`,
straight after `place_call`, reports the network's tones, who answered and
the machine's beep as `EventKind.PROGRESS_DETECTED`, `fields["what"]` a
`ProgressKind` and every limit a keyword. `call.set_consent_tone(...)` beeps
while the call is recorded. `call.media.record(path, format=..., layout=...,
sample_rate=..., bitrate=..., checkpoint_ms=...)` writes WAV or Ogg Opus,
mixed or stereo with this end on the left, and `stop_recording()` /
`recording` stop it and say how far it got. `tests/test_inband.py` proves
each over two stacks on loopback.

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
`tests/test_audio.py` proves which mode a stack gets, and — on a platform
with devices, always under manual activation so no microphone is opened —
the device list, the roles, gain, mute, the meter and a device-mode call the
application pumps nothing into; it also hands the engine's transmit callback
a packet of its own and proves it leaves from the call's socket.
`tests/test_identity.py` plays the far end by hand for the caller's identity
behind the trust gate, Answer-Mode and Alert-Info, `Reason` read and
written, a 302 and the per-account options; `tests/test_move.py` moves a
call from loopback to this host's routable address and hears it both ways
after, and reads the suite a DTLS-SRTP call settled on.

`examples/agent.py` is also run by the interop lab (`scripts/lab.sh`), as
its own docstring says to run it: registered at the lab's Asterisk, called
by it, hearing a tone, echoing it back and hanging up on the `#` the
dialplan sends. It runs in application mode on purpose, being a voice agent
in a container with no sound device.

## What is not here

`numpy` support
for `call.media` (accepted wherever `bytes`/`memoryview` is, but never
required — `array.array('h', ...)` or a `numpy` array's `.tobytes()` work
today); a DNS resolver for `SIPRAL_EVENT_KIND_RESOLVE_NEEDED`, which is
delivered and left unanswered, so that a dialog stays on the path its
INVITE took (see `Stack._on_event`).
