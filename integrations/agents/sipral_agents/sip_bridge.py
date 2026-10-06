# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""A bridge from a PBX to a voice agent that answers SIP itself.

A hosted realtime model or an agent platform's SIP trunk is just a SIP
address here: this registers on the PBX as an extension, answers each
caller, calls the agent, and joins the two calls in a local conference
without this end in it -- each on its own codec and rate. The caller hears
a ringback tone until the agent answers. A digit either side sends is sent
on to the other, either side hanging up ends the other, and the PBX hears
how the agent's part ended -- ``human``, ``callback``, ``resolved``,
``unresolved`` or ``expired`` -- on the BYE (``X-Sipral-Outcome``) or as a
REFER of the caller's call to an address set for that outcome.

A REFER from the agent goes to one function, :func:`decide`: by default a
user part naming an outcome other than ``human`` ends the call with it, and
anything else is a transfer to that user at the PBX -- a REFER of the
caller's call, so the PBX places the new call and owns it
(``SIPRAL_TRANSFER=bridge`` places it from here and bridges it instead).

    SIPRAL_AOR=sip:bridge@pbx.example \\
    SIPRAL_REGISTRAR=sip:pbx.example \\
    SIPRAL_REGISTRAR_ADDRESS=192.0.2.10:5060 \\
    SIPRAL_AUTH_USER=bridge SIPRAL_AUTH_PASSWORD=secret \\
    SIPRAL_AGENT_URI='sip:agent@203.0.113.7:5060' \\
    python3 -m sipral_agents.sip_bridge

:class:`BridgedCall` is one caller's bridge, for an application that
answers its calls itself; ``python -m sipral_agents`` runs it for every
account of a configuration file whose agent is a SIP address.

An agent address that asks for TLS (``sips:`` or ``;transport=tls``) or
TCP (``;transport=tcp``) is called over a connection of its own; over TLS
it is checked against ``SIPRAL_TLS_CA`` when set and the platform's
authorities otherwise, under the address's host name.
``SIPRAL_AGENT_ADDRESS`` (``host:port``) names where the agent's server is
when the address's host is not it. ``SIPRAL_OUTCOMES=refer`` with
``SIPRAL_OUTCOME_URIS=callback=sip:800@pbx.example,expired=sip:801@pbx.example``
returns the caller to the PBX by REFER for those outcomes.
``SIPRAL_AGENT_MAX_SECONDS`` hangs the agent up after that long, as
``expired``. ``SIPRAL_COPY_HEADERS`` (default ``X-*``) names the PBX
INVITE's fields that make up the caller's context, with its number and name.
``SIPRAL_INVITE_LIMIT=voice-agent`` takes a PBX's rush of calls the default
rate floor would answer 480.

This binding's ``Call`` has no ``ring``, ``transfer`` or ``set_headers`` and
``Stack.place_call`` no ``headers``, though the C ABI has all four
(``sipral_call_ring``, ``sipral_call_transfer``, ``sipral_call_set_headers``,
``sipral_call_config_t::headers``). So the caller is answered at once and
hears a tone from here rather than the PBX's own ringback, the REFER and the
outcome field go through the two C entry points directly (:func:`refer`,
:func:`set_headers`), and the caller's context is printed rather than sent:
``crates/sipral/examples/agent-bridge.rs`` sends it.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import socket
from dataclasses import dataclass, field

from sipral import Call, InviteLimit, LocalConference, Stack, TlsTrust
from sipral._sipral_cffi import ffi, lib
from sipral.enums import AudioMode, Codec, EventKind, Transport
from sipral.errors import SipralError
from sipral.errors import call as abi_call

_log = logging.getLogger("sipral_agents.sip_bridge")

OUTCOMES = ("human", "callback", "resolved", "unresolved", "expired")
OUTCOME_HEADER = "X-Sipral-Outcome"
# A REFER refused outright is not reported by the stack -- only the NOTIFYs
# of one it took are -- so this long without a word is read as a refusal.
REFER_PATIENCE = 10.0


@dataclass
class Transfer:
    """Put the caller through to ``target``."""

    target: str


@dataclass
class End:
    """End the caller's call with ``outcome``, playing nothing first."""

    outcome: str


def user_of(uri: str) -> str | None:
    """A ``sip:``/``sips:`` URI's user part, or a ``tel:`` URI's number."""
    uri = uri.strip().strip("<>")
    scheme, _, rest = uri.partition(":")
    if scheme.lower() == "tel":
        return rest.split(";")[0] or None
    if scheme.lower() not in ("sip", "sips") or "@" not in rest:
        return None
    return rest.split("@")[0].split(";")[0] or None


def decide(target: str, pbx_domain: str) -> Transfer | End | None:
    """What a REFER from the agent does -- the one function to replace.

    ``None`` refuses it and the caller stays with the agent.
    """
    user = user_of(target)
    if user is None:
        return None
    if user.lower() in OUTCOMES and user.lower() != "human":
        return End(user.lower())
    return Transfer(f"sip:{user}@{pbx_domain}")


def refer(call: Call, target: str) -> None:
    """`sipral_call_transfer`: REFER the call's far end to ``target``."""
    encoded = target.encode("utf-8")
    abi_call(
        lambda: lib.sipral_call_transfer(
            call.stack.handle, call.handle, encoded, len(encoded), call.stack.now_ms()
        ),
        "sipral_call_transfer",
    )


def set_headers(call: Call, fields: list[tuple[str, str]]) -> None:
    """`sipral_call_set_headers`: fields on what this call sends next,
    the BYE of a hangup among it."""
    kept = [(name.encode("utf-8"), value.encode("utf-8")) for name, value in fields]
    # the buffers outlive the call: the array only points at them
    buffers = [(ffi.new("char[]", name), ffi.new("char[]", value)) for name, value in kept]
    array = ffi.new("sipral_header_t[]", len(kept))
    for i, ((name, value), (name_buf, value_buf)) in enumerate(zip(kept, buffers)):
        array[i].name, array[i].name_len = name_buf, len(name)
        array[i].value, array[i].value_len = value_buf, len(value)
    abi_call(
        lambda: lib.sipral_call_set_headers(call.stack.handle, call.handle, array, len(kept)),
        "sipral_call_set_headers",
    )


def caller_context(invite: bytes | None, copy: list[str]) -> list[tuple[str, str]]:
    """The caller's number and display name, and the INVITE's fields
    ``copy`` names (a name ending in ``*`` is a prefix)."""
    fields: list[tuple[str, str]] = []
    text = (invite or b"").decode("utf-8", "replace")
    head = text.split("\r\n\r\n", 1)[0].split("\r\n")[1:]
    for line in head:
        name, colon, value = line.partition(":")
        if not colon or line[:1] in (" ", "\t"):
            continue
        name, value = name.strip(), value.strip()
        if name.lower() in ("from", "f"):
            display, _, rest = value.partition("<")
            uri = rest.split(">")[0] if rest else value.split(";")[0]
            number = user_of(uri)
            if number:
                fields.append(("X-Sipral-Caller-Number", number))
            if rest and display.strip().strip('"'):
                fields.append(("X-Sipral-Caller-Name", display.strip().strip('"')))
        wanted = any(
            name.lower().startswith(pattern[:-1].lower())
            if pattern.endswith("*")
            else name.lower() == pattern.lower()
            for pattern in copy
        )
        if wanted:
            fields.append((name, value))
    return fields


def domain_of(uri: str) -> str:
    """The host (and port) a ``sip:`` URI names."""
    rest = uri.split(":", 1)[1] if ":" in uri else uri
    return rest.split("@")[-1].split(";")[0]


def resolve(address: str) -> str:
    """``host:port`` with the host as an address."""
    host, _, port = address.rpartition(":")
    found = socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_DGRAM)
    return f"{found[0][4][0]}:{port}"


def agent_target(uri: str, address: str | None = None) -> tuple[str, int, str]:
    """Where the agent's address says to go, as ``host:port`` -- or
    ``address`` when the address's host is not where its server is --, over
    what (``0`` for UDP, or a :class:`sipral.enums.Transport`), and the name
    its certificate is checked against. Nothing is looked up."""
    scheme, _, rest = uri.partition(":")
    hostport = rest.split("@")[-1].split(";")[0]
    params = [p.lower() for p in rest.split(";")[1:]]
    if scheme.lower() == "sips" or "transport=tls" in params:
        over = Transport.TLS
    elif "transport=tcp" in params:
        over = Transport.TCP
    else:
        over = 0
    host, colon, port = hostport.partition(":")
    port = port if colon else ("5061" if over == Transport.TLS else "5060")
    return address or f"{host}:{port}", over, host


def agent_server(uri: str, address: str | None = None) -> tuple[str, int, str]:
    """:func:`agent_target` with the host looked up to an address."""
    target, over, host = agent_target(uri, address)
    return resolve(target), over, host


@dataclass
class BridgeConfig:
    """How one line's callers reach one agent: the PBX's domain (where
    transfers go), the agent's SIP address and the account its calls go out
    on, the line's own account, and what to do with a transfer
    (``"refer"`` or ``"bridge"``) and with an outcome (``"header"`` or
    ``"refer"``, to ``outcome_uris``)."""

    pbx_domain: str
    agent_uri: str
    agent_account: object
    line: object
    transfer: str = "refer"
    outcomes: str = "header"
    outcome_uris: dict[str, str] = field(default_factory=dict)
    max_seconds: float | None = None
    copy: list[str] = field(default_factory=lambda: ["X-*"])


async def ringback(call: Call) -> None:
    """A 425 Hz tone, one second on and four off (ITU-T E.180), until
    cancelled."""
    while call.media is None:
        await asyncio.sleep(0.02)
    media = call.media
    rate, frame = media.sample_rate, media.frame_samples
    step = 2 * math.pi * 425 / rate
    played = 0
    while not media.pumped:
        on = (played // rate) % 5 == 0
        samples = (
            int(4000 * math.sin(step * (played + i))) if on else 0 for i in range(frame)
        )
        media.send_audio(b"".join(s.to_bytes(2, "little", signed=True) for s in samples))
        played += frame
        await asyncio.sleep(frame / rate)


class BridgedCall:
    """One caller and whoever it is bridged to: ``await run()`` until the
    caller's call ends."""

    def __init__(self, stack: Stack, cfg: BridgeConfig, caller: Call, invite: bytes | None) -> None:
        self.stack = stack
        self.cfg = cfg
        self.caller = caller
        self.invite = invite
        self.agent: Call | None = None
        self.agent_up = False
        self.person: Call | None = None
        self.person_up = False
        self.referred = False
        self.refer_heard = False
        self.outcome: str | None = None
        self.refer_event = None
        self.conference: LocalConference | None = None
        self.bridged_with: int | None = None
        self.tone: asyncio.Task | None = None
        #: What each leg negotiated, for the application to read.
        self.codecs: dict[str, str] = {}
        self.inbox: asyncio.Queue = asyncio.Queue()
        self.tasks: list[asyncio.Task] = []

    def watch(self, call: Call, role: str) -> None:
        async def events() -> None:
            while True:
                await self.inbox.put((role, call, await call.events.get()))

        async def digits() -> None:
            while True:
                await self.inbox.put((role, call, ("dtmf", await call.dtmf.get())))

        self.tasks += [asyncio.create_task(events()), asyncio.create_task(digits())]

    def far(self) -> Call | None:
        return self.person if self.person_up else self.agent

    def join(self) -> None:
        """Bridge the caller to whoever it talks to, once both have media;
        a new conference for each new pair."""
        far = self.far()
        if far is None or self.caller.media is None or far.media is None:
            return
        if self.bridged_with == far.handle:
            return
        if self.tone is not None:
            self.tone.cancel()
        if self.conference is not None:
            self.conference.close()
        self.conference = LocalConference(self.stack, max_members=2, local=False)
        self.conference.add(self.caller)
        self.conference.add(far)
        self.bridged_with = far.handle
        _log.info(f"bridged {self.caller.handle:x} with {far.handle:x}")
        if self.person_up and self.agent is not None and not self.agent.ended:
            _log.info(f"transferred {self.caller.handle:x}: hanging the agent up")
            self.agent.hangup()

    def refer_caller(self, target: str, outcome: str) -> None:
        """REFER the caller's call to the PBX, and give up on it after
        :data:`REFER_PATIENCE` with no word from the PBX."""
        refer(self.caller, target)
        self.referred, self.refer_heard, self.outcome = True, False, outcome

        async def patience() -> None:
            await asyncio.sleep(REFER_PATIENCE)
            await self.inbox.put(("timer", None, ("refer-silent", None)))

        self.tasks.append(asyncio.create_task(patience()))

    def refused(self, status: int) -> None:
        """The PBX did not take the REFER: the caller stays with the agent,
        which hears its own REFER failed, or -- the agent gone -- ends."""
        _log.info(f"the PBX did not take the REFER of {self.caller.handle:x}: {status}")
        self.referred = False
        if self.agent is not None and not self.agent.ended:
            self.outcome = None
            self.stack.reject_referral(self.refer_event, status)
        else:
            self.end_caller(self.outcome or "unresolved", by_refer=False)

    def end_caller(self, outcome: str, by_refer: bool = True) -> bool:
        """End the caller's call with ``outcome``; ``True`` while it goes on,
        REFERred to the outcome's address."""
        uri = self.cfg.outcome_uris.get(outcome)
        if by_refer and self.cfg.outcomes == "refer" and uri:
            try:
                self.refer_caller(uri, outcome)
                _log.info(f"returning {self.caller.handle:x} to the PBX at {uri}: {outcome}")
                return True
            except SipralError as error:
                _log.info(f"cannot refer {self.caller.handle:x} to {uri}: {error!r}")
        _log.info(f"ending {self.caller.handle:x} with {OUTCOME_HEADER}: {outcome}")
        try:
            set_headers(self.caller, [(OUTCOME_HEADER, outcome)])
            self.caller.hangup()
        except SipralError:
            pass
        return False

    def transfer_asked(self, event) -> None:
        target = event.fields.get("target", "")
        if self.referred or self.person is not None:
            self.stack.reject_referral(event, 491)
            return
        action = decide(target, self.cfg.pbx_domain)
        _log.info(f"agent asked for {target}: {action}")
        if action is None:
            self.stack.reject_referral(event, 603)
        elif isinstance(action, End):
            self.outcome = action.outcome
            self.agent.hangup()
        elif self.cfg.transfer == "refer":
            self.refer_event = event
            self.refer_caller(action.target, "human")
            _log.info(f"referred {self.caller.handle:x} to {action.target}")
        else:
            self.person = self.stack.place_call(self.cfg.line, action.target)
            self.watch(self.person, "person")
            self.outcome, self.refer_event = "human", event
            _log.info(f"calling {action.target} as {self.person.handle:x}")

    async def expire(self) -> None:
        await asyncio.sleep(self.cfg.max_seconds)
        await self.inbox.put(("timer", None, ("expired", None)))

    async def run(self) -> None:
        self.watch(self.caller, "caller")
        context = caller_context(self.invite, self.cfg.copy)
        _log.info(f"incoming {self.caller.handle:x}: context {context}")
        try:
            self.agent = self.stack.place_call(self.cfg.agent_account, self.cfg.agent_uri)
        except SipralError as error:
            _log.info(f"cannot call the agent: {error!r}")
            self.end_caller("unresolved")
            return
        self.watch(self.agent, "agent")
        self.tone = asyncio.create_task(ringback(self.caller))
        try:
            while not self.caller.ended:
                role, call, event = await self.inbox.get()
                if isinstance(event, tuple):
                    self.on_signal(role, event)
                else:
                    if role == "agent" and event.kind == EventKind.CALL_CONFIRMED:
                        self.agent_up = True
                        _log.info(f"agent answered {call.handle:x}")
                        if self.cfg.max_seconds:
                            self.tasks.append(asyncio.create_task(self.expire()))
                    self.on_event(role, call, event)
                self.join()
        finally:
            self.tone.cancel()
            for task in self.tasks:
                task.cancel()
            if self.conference is not None:
                self.conference.close()
            for call in (self.caller, self.agent, self.person):
                if call is not None and not call.ended:
                    try:
                        call.hangup()
                    except SipralError:
                        pass

    def on_signal(self, role: str, signal: tuple) -> None:
        kind, value = signal
        if kind == "dtmf":
            to = self.far() if role == "caller" else self.caller
            if to is not None and to.media is not None:
                to.send_dtmf(value)
                _log.info(f"dtmf {value} from {role}")
        elif kind == "refer-silent" and self.referred and not self.refer_heard:
            self.refused(480)
        elif kind == "expired" and self.agent is not None and not self.agent.ended:
            if not self.referred and self.person is None:
                _log.info(f"the agent's call {self.agent.handle:x} ran its time: hanging it up")
                self.outcome = "expired"
                self.agent.hangup()

    def on_event(self, role: str, call: Call, event) -> None:
        if event.kind == EventKind.MEDIA_STARTED and call.media is not None:
            codec = Codec(call.media.info()["codec"]).name
            self.codecs[role] = f"{codec}/{call.media.sample_rate}"
            _log.info(f"codec {call.handle:x} {role} {self.codecs[role]}")
        elif event.kind == EventKind.TRANSFER_REQUESTED and role == "agent":
            self.transfer_asked(event)
        elif event.kind == EventKind.TRANSFER_PROGRESS and role == "caller":
            self.refer_heard = True
            _log.info(f"the PBX is transferring {call.handle:x}: {event.fields.get('status_code')}")
        elif event.kind == EventKind.TRANSFER_DONE and role == "caller":
            status = int(event.fields.get("status_code", 0))
            if 200 <= status < 300:
                self.referred = False
                _log.info(f"the PBX took {call.handle:x}: {status}")
            else:
                self.refused(status)
        elif event.kind == EventKind.CALL_CONFIRMED and role == "person":
            self.person_up = True
        elif event.kind == EventKind.CALL_ENDED:
            self.ended(role, call)

    def ended(self, role: str, call: Call) -> None:
        call.close()
        if role == "agent":
            if self.person is not None or self.referred:
                _log.info(f"ended {call.handle:x}: the agent left during its transfer")
                return
            outcome = self.outcome or ("resolved" if self.agent_up else "unresolved")
            _log.info(f"ended {call.handle:x}: the agent hung up, outcome {outcome}")
            self.end_caller(outcome)
        elif role == "person":
            if self.person_up:
                self.caller.hangup()
            elif self.agent is not None and not self.agent.ended:
                _log.info("the transfer failed: the caller stays with the agent")
                self.person, self.outcome = None, None
                self.stack.reject_referral(self.refer_event, 480)
            else:
                self.end_caller("unresolved")
        else:
            _log.info(f"ended {call.handle:x}: the caller's call is over")


async def main() -> None:
    loop = asyncio.get_running_loop()
    registrar_address = os.environ["SIPRAL_REGISTRAR_ADDRESS"]
    agent_uri = os.environ["SIPRAL_AGENT_URI"]
    agent_address, over, agent_host = agent_server(
        agent_uri, os.environ.get("SIPRAL_AGENT_ADDRESS")
    )
    tls = over == Transport.TLS
    trusted = os.environ.get("SIPRAL_TLS_CA")
    stack = Stack(
        loop=loop,
        audio=AudioMode.APPLICATION,
        tls_server_name=os.environ.get("SIPRAL_TLS_SERVER_NAME", agent_host) if tls else None,
        tls_trust=TlsTrust.only_authority(trusted) if trusted else None,
        invite_limit=InviteLimit.VOICE_AGENT
        if os.environ.get("SIPRAL_INVITE_LIMIT") == "voice-agent"
        else None,
    )
    aor = os.environ.get("SIPRAL_AOR", "sip:bridge@example.invalid")
    line = stack.add_account(
        aor,
        registrar=os.environ.get("SIPRAL_REGISTRAR"),
        registrar_address=registrar_address,
        auth_user=os.environ.get("SIPRAL_AUTH_USER"),
        auth_password=os.environ.get("SIPRAL_AUTH_PASSWORD"),
    )
    if os.environ.get("SIPRAL_REGISTRAR"):
        line.register()
    agent_account = stack.add_account(
        aor,
        registrar_address=agent_address,
        stream_protocol=over,
    )
    uris = os.environ.get("SIPRAL_OUTCOME_URIS", "")
    max_seconds = os.environ.get("SIPRAL_AGENT_MAX_SECONDS")
    cfg = BridgeConfig(
        pbx_domain=domain_of(os.environ.get("SIPRAL_REGISTRAR") or aor),
        agent_uri=agent_uri,
        agent_account=agent_account,
        line=line,
        transfer=os.environ.get("SIPRAL_TRANSFER", "refer"),
        outcomes=os.environ.get("SIPRAL_OUTCOMES", "header"),
        outcome_uris=dict(item.split("=", 1) for item in uris.split(",") if "=" in item),
        max_seconds=float(max_seconds) if max_seconds else None,
        copy=[p.strip() for p in os.environ.get("SIPRAL_COPY_HEADERS", "X-*").split(",") if p.strip()],
    )
    _log.info(f"listening on {stack.bind_address}; calls go to {agent_uri} at {agent_address}")
    pairs: set[asyncio.Task] = set()
    try:
        while True:
            event = await stack.events.get()
            if event.kind == EventKind.REGISTRATION_CHANGED:
                _log.info(f"registration {event.fields.get('state')}")
            if event.kind == EventKind.INCOMING_CALL:
                caller = stack.answer_call(event)
                pair = BridgedCall(stack, cfg, caller, event.message)
                task = asyncio.create_task(pair.run())
                pairs.add(task)
                task.add_done_callback(pairs.discard)
    finally:
        for task in pairs:
            task.cancel()
        stack.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    asyncio.run(main())
