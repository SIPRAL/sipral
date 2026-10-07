<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# The Python binding

Two layers, the way every binding here is two layers:

- `sipral/_sipral_cffi.py` — printed by `tools/abi-gen`'s Python back end
  from `sipral_ffi::abi::SURFACE`, the same declarations the header and the
  Swift, .NET, Kotlin and Dart bindings are printed from. `ffi` and `lib`: a
  `cffi` ABI-mode `cdef` naming the same types, constants and entry points
  `bindings/c/include/sipral.h` does, and the `dlopen` that turns it into
  `lib`. ABI mode needs no C compiler at install time — cffi lays every
  struct out for itself from the `cdef` text, so the `cdef` has to be
  exact; `tests/test_abi.py` checks it against the layout table the same
  file carries, against the library's own `sipral_abi_struct_size` and
  against the header's own numbers.
- every other file in `sipral/` — `stack.py`, `account.py`, `call.py`,
  `media.py`, `audio.py`, `events.py`, `conference.py`, `locate.py`,
  `signalling.py` and the rest — written by hand against `ffi`/`lib` directly, the way `SipralAbi.swift`
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
        # Left out, `bind_host` and `media_host` are the address of the
        # route toward the registrar (see "Where a stack is reached").

        call = stack.place_call(account, "sip:bob@example.invalid", media_host="192.0.2.10")
        while not call.ended:
            event = await call.events.get()
            print(event.kind_name)

asyncio.run(main())
```

A server that signs its users in with OAuth 2.0 (RFC 8898) challenges with
`Bearer`; the stack raises `SIPRAL_EVENT_KIND_TOKEN_REQUIRED`, whose fields
name the `authz_server` and the `scope`. Check the server against the ones
the application trusts, fetch the token, and hand it over with
`account.set_access_token(token)`; `register()` again registers at once, and
a token the server called `TokenError.INVALID_TOKEN` raises the event again
(`docs/08-ffi.md`, "What ABI 1.2 added").

Before a call, `stack.network_test(account, echo_call=call)` asks the
STUN and TURN servers (from a socket it opens and closes itself), the
account's server and, given a call placed to an echo service, the audio
that comes back; `SIPRAL_EVENT_KIND_NETWORK_TEST` carries every part and
`fields["verdict"]`, a `NetworkVerdict` (`docs/25-network-test.md`).

`stack.ring_call(event)` sends a 180 for an incoming call (`media=True`, a 183
with this stack's audio) and `stack.answer_call(event)` answers it later;
`stack.place_call(..., headers={"X-Ticket": "42"})` puts fields on the
INVITE, `call.set_headers(...)` on what the call sends next, the BYE of a
hangup among it, and the far end's BYE is `message` on its `CALL_ENDED`.
`call.transfer(target)` REFERs the far end, a refusal arriving as
`TRANSFER_DONE` with its status; a `TRANSFER_REQUESTED` is taken with
`stack.accept_referral`, refused with `stack.reject_referral`, or taken with
a call of the application's own with `stack.accept_transfer_placed(event, call)`.

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

The frames are at the codec's rate unless the application asks for its own:
`call.media.set_app_rate(24000)` (8000, 16000, 24000 or 48000; 0 is the
codec's) has the library convert both ways, and `sample_rate` and
`frame_samples` say the rate and the frame's length from then on — a speech
service fed at its own rate whatever the far end negotiated
(`docs/08-ffi.md`, "What ABI 1.1 added").

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
choice is kept and comes back with the device. macOS and Windows take all
three: on macOS the microphone is chosen apart from the speaker without
moving the system's default input, and a ringer on another device plays
through an output of its own. iOS raises `SIPRAL_STATUS_NOT_SUPPORTED` for
the microphone and the ringer, whose route is the audio session's.
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

Each call has a gain, a mute and a meter of its own on top of the
direction's: `set_gain`, `gain`, `set_muted`, `muted` and `level` take
`call=`. The input direction is what the microphone sends that call alone
and the output how loud it is in the loudspeaker beside the others — mute
the call being spoken about in a consultation, turn one conference member
down. They hold from the moment the call's media starts to its end, through
a hold or a local conference and back, and raise
`SIPRAL_STATUS_WRONG_STATE` outside that. `Stack(system_echo_cancellation=False)`
opens the devices past the platform's echo cancellation, for a headset,
which has no echo to cancel, or an application that cancels it on each call
itself; `info()` says what the platform did.
`stack.audio.set_system_echo_cancellation(on)` switches it on the running
stack (ABI 1.1): open devices are reopened at once, where they were and with
their gain and mute, and a call keeps its media through the short gap.

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
A certificate covers the numbers its TNAuthList names (RFC 8226 §9); one that
names a service provider code instead, as a SHAKEN certificate does, covers
no caller until `stack.stir(anchors, accept_service_provider_codes=True)`
says the deployment trusts its certified providers that far.
`tests/test_security.py` proves both verdicts with the chain in
`bindings/fixtures/stir-provider-709J`.

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
address (`Account.rebind` does one by hand). A stack created with no
`bind_host` keeps its socket on every interface, and its port, and goes on
choosing its own address: it advertises the route toward its first account's
server again, and each account the route toward its own, rather than taking
`host` as fixed. On `Recovery.REBUILD` each call
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
it an incoming call is answered 503 with `Retry-After: 2` and `place_call` raises with
`SIPRAL_STATUS_LIMIT_REACHED`. `max_server_transactions` (256),
`diagnostic_decisions` (64) and `diagnostic_records` (32) are the other
ceilings, zero for the default each (`docs/08-ffi.md`, "Limits, and what
went out twice").

## Where a stack is reached, and where its server is

`Stack()` with no `bind_host` listens on every interface and advertises the
address of the operating system's route toward the server of its first
account (`sipral.advertised_address`, `sipral_advertised_address`): the
address a PBX on the network reaches this machine at, and `127.0.0.1` for a
server on this machine. Each account is reached at the route toward its own
server, and a call's media socket, without `media_host`, at the route toward
the far end or the account's server. The library refuses to advertise a
loopback address to a peer elsewhere: `SIPRAL_STATUS_UNREACHABLE_ADDRESS`
from the call that would have, and `RegistrationFailure.UNREACHABLE_CONTACT`
for a REGISTER it sends on its own.

`add_account(aor, server_uri="sip:pbx.example.com")` names the server by a
URI whose host RFC 3263 locates, in place of `registrar_address`; exactly
one of the two is given. The stack's `resolver` answers each
`SIPRAL_EVENT_KIND_LOOKUP_WANTED` on a thread of its own:
`sipral.locate.lookup` by default, which asks `socket.getaddrinfo` for A and
AAAA records and answers SRV and NAPTR "nothing" — this package depends on
no DNS library, and the procedure then goes on to the host's own addresses.
An application whose server publishes SRV records passes a resolver that
reads them (dnspython's, say): a callable `(name, record) -> (answer,
records)`, each record its time-to-live and its data as a zone file writes
it. `LOCATED` says where the server was found (`account.registrar_address`
follows it) and `LOCATE_FAILED` why not (`LocateFailure`).

`keepalive_ms` keeps an account's flow to its server open whatever STUN
found, for a NAT that forgets a flow sooner than the REGISTER refresh comes
round. `TlsTrust.pinned("SHA256=AB:CD:...")` trusts the one certificate with
that fingerprint on a TLS signalling connection, whoever signed it and
whatever name it carries; an account's `tls_pin` and
`Account.check_certificate(der)` are the same verdict for an application
that runs the account's TLS itself.

`Stack(srtp=Srtp.BEST_EFFORT)` offers SDES on plain RTP/AVP, for a PBX that
answers an RTP/SAVP offer with 488; `srtp_suites` names the suites every
call offers. `path_mtu` tells RFC 3261 §18.1.1 the path's MTU, and
`datagram_without_stream_bytes` sends a request over UDP anyway once no
stream to a UDP-only server can be had — a deliberate deviation, written to
`stack.diagnostics_json()` as `transport.kept.datagram`.
`pseudonym_salt` keys the log's pseudonyms so that two runs compare, and
`diagnostic_trace` (or `stack.set_diagnostic_trace(True)`) writes whole SIP
messages at the trace level, credentials and keys taken out.

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
each over two stacks on loopback. `Stack(codecs="L16/16000")` (or
`L16/8000`) offers the samples themselves, and `Codec(info()["codec"])` says
`Codec.L16_WIDEBAND` once both ends took it. `place_call(..., codecs="PCMA,PCMU")`
and `answer_call(event, codecs="PCMA,PCMU")` give one call its own codecs in
place of the stack's; an answer keeps the offer's order (RFC 3264 §6.1), so
answering it chooses which codecs rather than which comes first
(`tests/test_call.py`).

## Real-time text, RTCP feedback, conferences, presence and recording servers

```python
from sipral.enums import Activity, Basic, EventKind

call = stack.place_call(account, "sip:bob@example.com", text=True, feedback=True)
...
call.send_text("On my way\u2028")        # RFC 4103, once media started
typed = await call.text.get()            # what the far end typed

room = call.subscribe_conference()        # the far end answered as a focus
event = await stack.events.get()          # EventKind.CONFERENCE_CHANGED
picture = room.conference()               # subject, users, where each one is

buddy = account.watch_presence("sip:bob@example.com")
account.publish_presence(Basic.OPEN, Activity.ON_THE_PHONE, "In a call")
event = await stack.events.get()          # EventKind.PRESENCE_CHANGED
print(event.presence)
```

`text=True` on `place_call` or `answer_call` opens a second socket and puts
a real-time text stream (RFC 4103, T.140 with redundancy) beside the audio:
`call.send_text(...)` queues what the user typed, `call.text` has what the
far end typed with BACKSPACE, LINE SEPARATOR and a REPLACEMENT CHARACTER per
lost block left in, and `event.text` has the same with `missing` counted. A
call that agreed no text stream answers `send_text` with
`Status.NOT_NEGOTIATED`; one keyed by SRTP or gathering ICE never offers
one. `feedback=True` offers RTP/AVPF with Generic NACKs and reduced-size
RTCP (RFC 4585, RFC 5506): `info()` says `feedback`, `generic_nack` and
`reduced_size`, and `statistics()["feedback"]` counts the NACKs and early
packets, `None` on a call that runs none. `focus=True` answers (or places)
as a conference focus (RFC 4579), and `call.set_focus(...)` says so later;
on the other end `call.conference_uri` names the conference, `None` when
the far end is no focus, and `call.subscribe_conference()` watches it.

`account.subscribe(target, package)` watches any event package and hands
back a `Subscription` — `handle`, `state`, `end()` — and
`account.watch_presence(target)` is it for `presence`: each document
arrives as `EventKind.PRESENCE_CHANGED`, whose `event.presence` is a
`Presence` with `basic`, `activity`, `note` and `entity`. A conference
subscription raises `EventKind.CONFERENCE_CHANGED` (`event.conference`:
applied or ended, the version, how many users), and `subscription.conference()`
reads the picture whole as a `ConferencePicture` of `Participant`s.
`account.publish_presence(basic, activity, note)` publishes this account's
own (RFC 3903), modifies it on every later call and keeps it refreshed until
`unpublish_presence()`; `EventKind.PRESENCE_CHANGED` with
`PresenceKind.PUBLICATION` says what the compositor did, its
`publication_state`, `failure` and `status_code`.

`call.record_to("sip:srs@example.com")` records a call to a recording
server (SIPREC, RFC 7866): two sockets are opened beside the media one, a
recording session carrying the metadata goes from the call's account — over
a stream, since that INVITE is too large for a datagram, so on a stack
signalling over TCP or TLS to the server — and once it answers, the copies
of this end's audio and the far end's leave from them as the call runs.
`call.recording_session` is its handle, and `call.stop_recording_to()` hangs
it up. The copies of an encrypted call are offered as SRTP with SDES keys of
their own (RFC 7866 §12.2), and a stream the server will not take that way
gets nothing; `add_account(..., recording_in_clear=True)` lets that
account's encrypted calls be recorded as plain RTP instead. `tests/test_protocols.py` proves each: text and feedback between two
stacks on loopback, and the conference, presence and recording server
played by hand.

## A local conference

`LocalConference(stack)` mixes any number of this stack's calls, each on its
own codec and rate, so that every member hears everybody but itself -- this
end too, unless it is made with `local=False`. `add(call)` and
`remove(call)` take calls in and out (a full conference, a call already in
one, or a codec it cannot mix raise with `Status.CONFERENCE_REFUSED`);
`set_muted` and `set_gain` act on one way of a member, `None` naming this
end; `members()` and `talkers()` say who is in it and who is talking,
loudest first; `record(path)` records the whole mix. In device mode the
library's engine carries it; in application mode its own thread does, with
`send_audio` as this end's microphone and `frames` what it hears.
`EventKind.LOCAL_CONFERENCE_CHANGED` on `stack.events`, read with
`event.local_conference`, says who joined or left and why and who is
talking. `tests/test_local_conference.py` bridges two calls between three
stacks on loopback.

## SIP over TCP or TLS

```python
from sipral import InviteLimit, Stack, TlsTrust
from sipral.enums import EventKind, TlsFailure, Transport

stack = Stack(
    bind_host="192.0.2.20",
    signalling=Transport.TLS,
    signalling_server="198.51.100.10:5061",
    tls_server_name="pbx.example.com",
    tls_trust=TlsTrust.only_authority("pbx-ca.pem"),
)
account = stack.add_account(
    "sip:alice@example.com", registrar="sip:example.com", registrar_address="198.51.100.10:5061"
)
account.register()
event = await stack.events.get()
if event.kind == EventKind.TRANSPORT_FAILED:
    print(TlsFailure(event.fields["tls"]).name, event.fields["detail"])
```

`signalling` is `Transport.UDP` (the default), `TCP` or `TLS`. Over either of
the last two the stack keeps one connection to `signalling_server`, the
registrar or the outbound proxy, and every account and call rides on it; a
`Contact` this package writes names the transport. Over TLS, Python's `ssl`
checks the certificate against `tls_server_name` (the server's host when
left out) with `tls_trust`: `TlsTrust.platform()` (the default),
`TlsTrust.private_authority(cafile)` beside it, `TlsTrust.only_authority(cafile)`
alone, or `TlsTrust.from_context(context)` for a context that verifies.
The first connection is made in the constructor. One that fails, or breaks
later, arrives as `EventKind.TRANSPORT_FAILED` with `fields["tls"]` —
`TlsFailure.UNTRUSTED`, `NAME_MISMATCH`, `EXPIRED` or `HANDSHAKE_REFUSED` —
`fields["error"]` and OpenSSL's own sentence in `fields["detail"]`, and the
stack connects again, one second later and up to thirty seconds apart,
registering every account again once it is back. `stack.connected` says
whether it is up; `Account.register()` asked meanwhile is kept for then.
`docs/22-tls.md` has the whole mapping.

An account can have a connection of its own on a stack that signals over
UDP, so that one stack and one audio engine hold an account on UDP with one
PBX and another on TCP or TLS with a second:

```python
stack = Stack(loop=loop)
office = stack.add_account("sip:alice@office.example", registrar="sip:office.example",
                           registrar_address="192.0.2.10:5060")
carrier = stack.add_account("sip:+15550100@carrier.example", registrar="sip:carrier.example",
                            registrar_address="198.51.100.20:5061",
                            tls_pin="sha256 Fingerprint=AB:CD:...", stream_protocol=Transport.TLS)
```

The stack asks for the connection with `EventKind.TRANSPORT_WANTED`,
nothing outgrown, and this package opens it to the account's server
whatever `stream_fallback` says: a TLS one held to the account's `tls_pin`
when it has one, to `tls_trust` under `tls_server_name` otherwise. The
account's REGISTER and every request of its calls go over it, its `Contact`
names the protocol, and a connection that closes is opened again and the
account registered again. Until it is open a call the account places
raises `SIPRAL_STATUS_TRANSPORT_DOWN`.

`stack.settings()` reads back what the stack runs with, every default
filled in (`sipral.Settings`): the timers, the codecs' count, the SRTP
suites its calls offer in order, whether a pseudonym salt was given, whether
the diagnostic trace is whole now, and whether the platform's echo
cancellation is asked for.

`invite_limit` is how fast one address may ring the stack: every stack
starts at `InviteLimit.DEFAULT`, ten INVITEs at once and one every two
seconds, past which a call is answered 480. A voice agent behind a trunk
takes `InviteLimit.VOICE_AGENT`, a hundred and twenty-eight at once and
twenty a second.

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
