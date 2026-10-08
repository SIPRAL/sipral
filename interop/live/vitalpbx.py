# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Two extensions of a test tenant on a live VitalPBX 4.5 (Asterisk 20):
`scripts/lab.sh vitalpbx-live` runs this, by hand only, never as part of a
run that names nothing.

Two Python ``Stack`` objects in one process, one per extension, each on a
socket of its own, so the PBX sees two phones. Two calls, each short:

1. 101 calls 102 and 102 answers. Each end sends a tone of its own
   (400 Hz from 101, 1000 Hz from 102) and listens for the other's, frame
   by frame, so audio is measured both ways rather than counted in packets.
   If the PBX re-INVITEs the media to go straight between the two stacks
   (``direct_media``), that is reported, and the tones are listened for
   again after it. Then 101 sends the digit 5 as an RFC 4733 event and 102
   has to receive it as one; 101 holds and resumes, and the tones are
   listened for once more; 101 hangs up.
2. 102 calls 101, 101 answers, the tones are listened for, and 101 -- the
   callee -- hangs up.

Both extensions are unregistered at the end (``Expires: 0``).

The account details come from one file only, whose path is
``VITALPBX_LIVE_ENV`` (``KEY=value`` lines). Its keys share one prefix,
whatever it is: ``<PREFIX>_HOST``, ``<PREFIX>_101_USER``,
``<PREFIX>_101_SECRET``, ``<PREFIX>_102_USER`` and ``<PREFIX>_102_SECRET``.
The host is the SIP domain and the registrar, on UDP 5060; each user is
also its own authentication user name. Nothing dialled is anything but the
two extension numbers, 101 and 102.

Everything this process writes passes through a filter that replaces the
two secrets, the host name and its addresses with placeholders, whatever
printed them: the lines below or a traceback. The stack's own log is not
turned on, so no SIP message is printed at all.

Lines, flushed as they happen, for the step to read:

    note <text>
    registered <ext>
    result ok|FAIL <label>: <detail>
    not run: <why>

Exit status: 0 when every result is ok, 1 when one is not, 3 when the step
could not run at all (no file, a key missing, a name that does not resolve),
which the step reports as not run rather than as anything else.
"""

from __future__ import annotations

import asyncio
import io
import math
import os
import socket
import struct
import sys
import time

NOT_RUN = 3

# What each extension sends, and so what the other listens for: whole
# cycles in a 20 ms frame, and nowhere near a DTMF frequency.
TONES = {"101": 400.0, "102": 1000.0}

# A tone heard in at least this many frames of a window counts as heard:
# 0.4 s of it, at 20 ms a frame.
HEARD_FRAMES = 20

# How long each window the tones are listened for runs.
WINDOW_S = 3.0

# How long anything asked of the PBX is waited for.
PATIENCE_S = 8.0

# No call is let run past this.
LONGEST_CALL_S = 15.0


class Observed:
    """What reaches each call's media socket, before the stack judges it.

    ``sipral.media`` hands every datagram its socket reads to
    ``sipral_media_receive``; this stands in for the library object that
    module calls through, passes every call on unchanged, and counts per
    media handle the datagrams, the ones the stack dropped, and the RTP
    sources (SSRCs) they came from. Packets counted by the stack's own
    statistics are only the ones it took, so this is what tells a PBX that
    stopped sending from one whose packets were refused.
    """

    def __init__(self) -> None:
        self._real = None
        self._tallies: dict[int, list] = {}

    def install(self) -> None:
        import sipral.media

        self._real = sipral.media.lib
        sipral.media.lib = self

    def __getattr__(self, name: str):
        return getattr(self._real, name)

    def sipral_media_receive(self, media, data, length, source, source_len, now, out):
        status = self._real.sipral_media_receive(media, data, length, source, source_len, now, out)
        tally = self._tallies.setdefault(int(media), [0, 0, set()])
        tally[0] += 1
        if out[0] == self._real.SIPRAL_ARRIVAL_DROPPED:
            tally[1] += 1
        packet = bytes(data[:12])
        # RTP version 2, and not RTCP (packet types 200 to 204)
        if len(packet) == 12 and packet[0] >> 6 == 2 and not 200 <= packet[1] <= 204:
            tally[2].add(packet[8:12])
        return status

    def tally(self, media: int) -> tuple[int, int, set]:
        arrived, dropped, sources = self._tallies.get(int(media), [0, 0, set()])
        return arrived, dropped, sources


OBSERVED = Observed()


class Redacting(io.TextIOBase):
    """A text stream that replaces every secret in what is written to it."""

    def __init__(self, inner, replacements: list[tuple[str, str]]) -> None:
        super().__init__()
        self._inner = inner
        # longest first, so a secret that contains another is replaced whole
        self._replacements = sorted(
            ((text, label) for text, label in replacements if text),
            key=lambda pair: -len(pair[0]),
        )

    def write(self, text: str) -> int:
        for secret, label in self._replacements:
            text = text.replace(secret, label)
        self._inner.write(text)
        return len(text)

    def flush(self) -> None:
        self._inner.flush()


def say(text: str) -> None:
    print(text, flush=True)


def read_env(path: str) -> dict[str, str]:
    """``KEY=value`` lines; ``export`` and surrounding quotes allowed."""
    values: dict[str, str] = {}
    with open(path, encoding="utf-8") as lines:
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :].lstrip()
            key, sep, value = line.partition("=")
            if not sep:
                continue
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[key.strip()] = value
    return values


def account_details(values: dict[str, str]) -> tuple[str, dict[str, tuple[str, str]]] | str:
    """The host and each extension's (user, secret), or why not."""
    hosts = [key for key in values if key.endswith("_HOST")]
    if len(hosts) != 1:
        return f"the file names {len(hosts)} keys ending in _HOST, not one"
    prefix = hosts[0][: -len("_HOST")]
    host = values[hosts[0]]
    if not host:
        return "the host is empty"
    extensions = {}
    for extension in ("101", "102"):
        user = values.get(f"{prefix}_{extension}_USER", "")
        secret = values.get(f"{prefix}_{extension}_SECRET", "")
        if not user or not secret:
            return f"extension {extension}'s user or secret is missing"
        extensions[extension] = (user, secret)
    return host, extensions


def route_to(address: tuple[str, int]) -> str:
    """The address of this host a datagram to ``address`` leaves from."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(address)
        return probe.getsockname()[0]


def tone_frame(hz: float, samples: int, rate: int) -> bytes:
    """One frame of a tone at a quarter of full scale, 16-bit mono."""
    return b"".join(
        int(8192 * math.sin(2 * math.pi * hz * n / rate)).to_bytes(2, "little", signed=True)
        for n in range(samples)
    )


def hears(pcm: bytes, hz: float, rate: int) -> bool:
    """Whether most of a frame's energy is at ``hz`` (Goertzel): the share
    is 1 for a pure tone there, near 0 for silence-level noise or another
    tone."""
    count = len(pcm) // 2
    if count == 0:
        return False
    samples = struct.unpack(f"<{count}h", pcm[: count * 2])
    energy = float(sum(sample * sample for sample in samples))
    # below about -50 dBFS is silence, whatever its spectrum
    if energy < count * 100.0 * 100.0:
        return False
    coefficient = 2.0 * math.cos(2.0 * math.pi * hz / rate)
    previous = before = 0.0
    for sample in samples:
        previous, before = sample + coefficient * previous - before, previous
    power = previous * previous + before * before - coefficient * previous * before
    return 2.0 * power / (count * energy) > 0.5


def media_endpoint(sdp: bytes | None) -> str | None:
    """``address:port`` of the first audio stream a description names."""
    if not sdp:
        return None
    session_address = None
    media_address = None
    port = None
    in_audio = False
    for raw in sdp.decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if line.startswith("m="):
            if port is not None:
                break
            fields = line[2:].split()
            in_audio = bool(fields) and fields[0] == "audio"
            if in_audio and len(fields) > 1:
                port = fields[1]
        elif line.startswith("c="):
            address = line.split()[-1]
            if in_audio:
                media_address = address
            elif port is None:
                session_address = address
    address = media_address or session_address
    if address is None or port is None:
        return None
    return f"{address}:{port}"


class Leg:
    """One end of a call: what it heard, and where its far end was moved."""

    def __init__(self, extension: str, call, other: str) -> None:
        self.extension = extension
        self.call = call
        self.other = other
        self.heard: list[float] = []
        self.far: str | None = None
        self.moves: list[tuple[float, bool]] = []
        self.digits: list[tuple[str, int]] = []
        self.ended: tuple[str, int] | None = None
        self.confirmed = False
        self.held = False
        self.resumed = False
        self.codec: str | None = None
        self.task: asyncio.Task | None = None
        self.placed = False

    def heard_between(self, start: float, end: float) -> int:
        return sum(1 for at in self.heard if start <= at <= end)

    def describe(self) -> str:
        """What this end's media did, for a note line: what the stack took
        and what reached its socket, sources counted by SSRC."""
        media = self.call.media
        if media is None:
            return f"{self.extension}: no media started"
        try:
            stats = media.statistics()
        except Exception as refused:  # noqa: BLE001 -- a note, never a verdict
            return f"{self.extension}: statistics refused ({type(refused).__name__})"
        arrived, dropped, sources = OBSERVED.tally(media.handle)
        return (
            f"{self.extension}: sent {stats['packets_sent']}, took {stats['packets_received']} "
            f"of {arrived} datagrams ({dropped} dropped by the stack), "
            f"from {len(sources)} RTP source(s)"
        )


async def carry(leg: Leg) -> None:
    """Send this end's tone for as long as the call has media, and note
    every frame in which the other end's is heard."""
    from sipral.errors import SipralError

    call = leg.call
    while call.media is None and not call.ended:
        await asyncio.sleep(0.02)
    if call.media is None:
        return
    media = call.media
    rate = media.sample_rate
    frame = tone_frame(TONES[leg.extension], media.frame_samples, rate)
    listening = TONES[leg.other]
    while not call.ended:
        try:
            received = await asyncio.wait_for(media.frames.get(), 0.5)
        except TimeoutError:
            continue
        if hears(received, listening, rate):
            leg.heard.append(time.monotonic())
        try:
            media.send_audio(frame)
        except (SipralError, RuntimeError):
            return


class Run:
    """The two stacks, their events in one queue, and the results."""

    def __init__(self, host: str, address: tuple[str, int], extensions) -> None:
        self.host = host
        self.address = address
        self.extensions = extensions
        self.stacks: dict[str, object] = {}
        self.accounts: dict[str, object] = {}
        self.registration: dict[str, str] = {}
        self.legs: dict[tuple[str, int], Leg] = {}
        self.events: asyncio.Queue = asyncio.Queue()
        self.forwarders: list[asyncio.Task] = []
        self.failed = False
        self.refused = False
        self.unregistering: set[str] = set()

    def result(self, ok: bool, label: str, detail: str) -> None:
        say(f"result {'ok' if ok else 'FAIL'} {label}: {detail}")
        if not ok:
            self.failed = True

    async def forward(self, extension: str, stack) -> None:
        while True:
            event = await stack.events.get()
            await self.events.put((extension, event))

    def start(self) -> None:
        from sipral import Stack
        from sipral.enums import AudioMode

        OBSERVED.install()
        bind_host = route_to(self.address)
        loop = asyncio.get_running_loop()
        for extension, (user, secret) in self.extensions.items():
            stack = Stack(
                loop=loop,
                bind_host=bind_host,
                audio=AudioMode.APPLICATION,
                codecs="PCMA",
            )
            self.stacks[extension] = stack
            self.accounts[extension] = stack.add_account(
                f"sip:{user}@{self.host}",
                registrar=f"sip:{self.host}",
                registrar_address=f"{self.address[0]}:{self.address[1]}",
                auth_user=user,
                auth_password=secret,
                expires_seconds=300,
            )
            self.forwarders.append(asyncio.create_task(self.forward(extension, stack)))

    async def until(self, done, seconds: float) -> bool:
        """Handle events until ``done()`` holds or ``seconds`` pass."""
        deadline = time.monotonic() + seconds
        while not done():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                extension, event = await asyncio.wait_for(self.events.get(), remaining)
            except TimeoutError:
                return done()
            self.handle(extension, event)
        return True

    def handle(self, extension: str, event) -> None:
        from sipral.enums import (
            CallEndReason,
            Codec,
            DigitSource,
            EventKind,
            RegistrationState,
        )

        kind = event.kind
        fields = event.fields
        if kind == EventKind.REGISTRATION_CHANGED:
            state = RegistrationState(fields["state"])
            if state == RegistrationState.REGISTERED:
                if self.registration.get(extension) != "registered":
                    say(f"registered {extension}")
                self.registration[extension] = "registered"
            elif state in (RegistrationState.FAILED, RegistrationState.RETRYING):
                # never let the stack try again: a server that refused the
                # credentials once counts every retry against the address
                self.registration[extension] = f"refused {fields['status_code']}"
                self.refused = True
            elif extension in self.unregistering:
                self.registration[extension] = (
                    f"unregistered ({state.name}, status {fields['status_code']})"
                )
            return

        if kind == EventKind.INCOMING_CALL:
            stack = self.stacks[extension]
            other = "102" if extension == "101" else "101"
            call = stack.answer_call(event, codecs="PCMA")
            leg = Leg(extension, call, other)
            leg.far = media_endpoint(fields.get("remote_sdp"))
            self.legs[(extension, call.handle)] = leg
            leg.task = asyncio.create_task(carry(leg))
            return

        leg = self.legs.get((extension, event.call)) if event.call else None
        if leg is None:
            return
        if kind in (EventKind.CALL_PROGRESS, EventKind.CALL_CONFIRMED):
            far = media_endpoint(fields.get("remote_sdp"))
            if far is not None and leg.far is None:
                leg.far = far
            if kind == EventKind.CALL_CONFIRMED:
                if far is not None:
                    leg.far = far
                leg.confirmed = True
        elif kind == EventKind.SESSION_CHANGED:
            far = media_endpoint(fields.get("remote_sdp"))
            if fields.get("held_here"):
                leg.held = True
            elif leg.held:
                leg.resumed = True
            direct = far is not None and self.is_other_stack(leg, far)
            # the first description a change carries is only a move when it
            # names the other stack: the earlier ones may not have been read
            if far is not None and far != leg.far and (leg.far is not None or direct):
                leg.moves.append((time.monotonic(), direct))
                say(
                    f"note {leg.extension}: the PBX moved its far end "
                    + (
                        "straight to the other stack's own socket"
                        if direct
                        else "to an address that is not the other stack's"
                    )
                )
            if far is not None:
                leg.far = far
        elif kind == EventKind.MEDIA_STARTED and leg.codec is None:
            try:
                leg.codec = Codec(fields.get("codec", 0)).name
            except ValueError:
                leg.codec = str(fields.get("codec"))
        elif kind == EventKind.DIGIT_RECEIVED:
            try:
                source = DigitSource(fields.get("source", -1)).name
            except ValueError:
                source = str(fields.get("source"))
            leg.digits.append((fields.get("digit") or "?", source))
        elif kind == EventKind.CALL_ENDED:
            leg.ended = (CallEndReason(fields["end_reason"]).name, fields["status_code"])

    def is_other_stack(self, leg: Leg, far: str) -> bool:
        for (extension, _), other in self.legs.items():
            if extension == leg.other and other.call.media_address == far:
                return True
        return False

    async def register(self) -> bool:
        for account in self.accounts.values():
            account.register()
        await self.until(
            lambda: self.refused or len([s for s in self.registration.values() if s == "registered"]) == 2,
            PATIENCE_S,
        )
        both = all(self.registration.get(e) == "registered" for e in ("101", "102"))
        if both:
            self.result(True, "both extensions registered at a live VitalPBX", "digest answered, 200 for each")
        else:
            said = ", ".join(f"{e} {self.registration.get(e, 'no answer')}" for e in ("101", "102"))
            self.result(False, "both extensions registered at a live VitalPBX", said)
        return both

    def place(self, caller: str, callee: str) -> Leg:
        stack = self.stacks[caller]
        # only ever the other extension of the two
        call = stack.place_call(self.accounts[caller], f"sip:{callee}@{self.host}", codecs="PCMA")
        leg = Leg(caller, call, callee)
        leg.placed = True
        self.legs[(caller, call.handle)] = leg
        leg.task = asyncio.create_task(carry(leg))
        return leg

    async def listen(self, a: Leg, b: Leg | None, seconds: float) -> tuple[int, int, float, float]:
        start = time.monotonic()
        await self.until(lambda: a.ended is not None, seconds)
        end = time.monotonic()
        return a.heard_between(start, end), (b.heard_between(start, end) if b else 0), start, end

    async def first_call(self) -> None:
        """101 calls 102: tones both ways, the PBX's own re-INVITE if it
        sends one, a digit, hold and resume, the caller's BYE."""
        began = time.monotonic()
        caller = self.place("101", "102")
        await self.until(lambda: caller.confirmed or caller.ended is not None, PATIENCE_S)
        callee = next((leg for (ext, _), leg in self.legs.items() if ext == "102"), None)
        if not caller.confirmed or callee is None:
            self.result(
                False,
                "a call between two extensions, answered, audio both ways",
                f"never answered ({caller.ended or 'no answer'})",
            )
            await self.end(caller, callee)
            return

        # the window opens once the PBX has had a moment to move the media,
        # which it does right after the answer when it does it at all
        heard_caller, heard_callee, _, _ = await self.listen(caller, callee, WINDOW_S)
        say(f"note {caller.describe()}")
        say(f"note {callee.describe()}")
        codec = caller.codec or "?"
        self.result(
            heard_caller >= HEARD_FRAMES and heard_callee >= HEARD_FRAMES and caller.ended is None,
            "a call between two extensions, answered, audio both ways",
            f"101 to 102 on {codec}; 102's tone heard at 101 in {heard_caller} frames, "
            f"101's at 102 in {heard_callee} (of {int(WINDOW_S * 50)})",
        )

        moved = caller.moves + callee.moves
        direct = [m for m in moved if m[1]]
        if direct:
            last = max(at for at, _ in direct)
            after_caller = caller.heard_between(last, time.monotonic())
            after_callee = callee.heard_between(last, time.monotonic())
            self.result(
                after_caller >= HEARD_FRAMES and after_callee >= HEARD_FRAMES,
                "the media moved straight between the two stacks by the PBX's re-INVITE",
                f"{len(direct)} end(s) moved to the other stack's own socket; after it, "
                f"tones heard in {after_caller} and {after_callee} frames",
            )
        else:
            say("note no direct-media re-INVITE: the PBX kept the media through itself")

        if caller.ended is None:
            caller.call.send_dtmf("5")
            await self.until(lambda: bool(callee.digits) or caller.ended is not None, 3.0)
            got = callee.digits[0] if callee.digits else None
            self.result(
                got is not None and got[0] == "5" and got[1] == "RTP",
                "an RFC 4733 digit carried end to end",
                f"5 sent by 101 as an event, 102 received {got[0] + ' as ' + got[1] if got else 'nothing'}",
            )

        if caller.ended is None and time.monotonic() - began < LONGEST_CALL_S - 6:
            caller.call.hold()
            await self.until(lambda: caller.held or caller.ended is not None, 3.0)
            caller.call.resume()
            await self.until(lambda: caller.resumed or caller.ended is not None, 3.0)
            left = max(1.0, min(WINDOW_S, LONGEST_CALL_S - 2 - (time.monotonic() - began)))
            # the first half second after the resume is the PBX moving things
            # back; listen over what follows it
            await self.until(lambda: caller.ended is not None, 0.5)
            heard_caller, heard_callee, _, _ = await self.listen(caller, callee, left)
            self.result(
                caller.held and caller.resumed and caller.ended is None
                and heard_caller >= HEARD_FRAMES // 2 and heard_callee >= HEARD_FRAMES // 2,
                "held and resumed by the caller",
                f"held={int(caller.held)} resumed={int(caller.resumed)}; after the resume, tones heard "
                f"in {heard_caller} and {heard_callee} frames of {int(left * 50)}",
            )

        await self.end(caller, callee)
        self.result(
            caller.ended is not None and caller.ended[0] == "LOCAL_HANGUP"
            and callee.ended is not None and callee.ended[0] == "REMOTE_HANGUP",
            "a call ended by the caller",
            f"101 {caller.ended[0] if caller.ended else 'still up'}, "
            f"102 {callee.ended[0] if callee.ended else 'still up'}",
        )

    async def second_call(self) -> None:
        """102 calls 101; 101, the callee, hangs up."""
        caller = self.place("102", "101")
        await self.until(lambda: caller.confirmed or caller.ended is not None, PATIENCE_S)
        callee = next(
            (leg for (ext, _), leg in self.legs.items() if ext == "101" and leg.ended is None and leg is not caller),
            None,
        )
        if not caller.confirmed or callee is None:
            self.result(
                False,
                "a call ended by the callee",
                f"102 to 101 never answered ({caller.ended or 'no answer'})",
            )
            await self.end(caller, callee)
            return
        heard_caller, heard_callee, _, _ = await self.listen(caller, callee, WINDOW_S)
        say(f"note {caller.describe()}")
        say(f"note {callee.describe()}")
        callee.call.hangup()
        await self.until(lambda: caller.ended is not None and callee.ended is not None, PATIENCE_S)
        self.result(
            heard_caller >= HEARD_FRAMES and heard_callee >= HEARD_FRAMES
            and callee.ended is not None and callee.ended[0] == "LOCAL_HANGUP"
            and caller.ended is not None and caller.ended[0] == "REMOTE_HANGUP",
            "a call ended by the callee",
            f"102 to 101, tones heard in {heard_caller} and {heard_callee} frames; "
            f"101 {callee.ended[0] if callee.ended else 'still up'}, "
            f"102 {caller.ended[0] if caller.ended else 'still up'}",
        )

    async def end(self, caller: Leg, callee: Leg | None) -> None:
        if caller.ended is None:
            try:
                caller.call.hangup()
            except Exception:  # noqa: BLE001 -- the call may already be on its way down
                pass
        await self.until(
            lambda: caller.ended is not None and (callee is None or callee.ended is not None),
            PATIENCE_S,
        )

    async def unregister(self) -> None:
        from sipral.errors import SipralError

        asked = []
        for extension, account in self.accounts.items():
            if self.registration.get(extension) != "registered":
                continue
            try:
                self.unregistering.add(extension)
                account.unregister()
                asked.append(extension)
            except SipralError:
                pass
        await self.until(
            lambda: all(self.registration.get(e, "").startswith("unregistered") for e in asked),
            5.0,
        )
        for extension in asked:
            say(f"note {extension}: {self.registration.get(extension, 'no answer to the un-REGISTER')}")

    async def close(self) -> None:
        for leg in self.legs.values():
            if leg.task is not None:
                leg.task.cancel()
        for task in self.forwarders:
            task.cancel()
        for stack in self.stacks.values():
            await asyncio.to_thread(stack.close)


async def main() -> int:
    path = os.environ.get("VITALPBX_LIVE_ENV", "")
    if not path:
        say("not run: VITALPBX_LIVE_ENV names no file")
        return NOT_RUN
    try:
        values = read_env(path)
    except OSError as error:
        say(f"not run: the file VITALPBX_LIVE_ENV names could not be read ({error.strerror})")
        return NOT_RUN
    details = account_details(values)
    if isinstance(details, str):
        say(f"not run: {details}")
        return NOT_RUN
    host, extensions = details

    replacements = [(host, "<pbx>")]
    replacements += [(secret, "<secret>") for _, secret in extensions.values()]
    try:
        found = socket.getaddrinfo(host, 5060, socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        sys.stdout = Redacting(sys.__stdout__, replacements)
        sys.stderr = Redacting(sys.__stderr__, replacements)
        say("not run: the PBX's name did not resolve")
        return NOT_RUN
    addresses = sorted({entry[4][0] for entry in found})
    replacements += [(address, "<pbx-address>") for address in addresses]
    sys.stdout = Redacting(sys.__stdout__, replacements)
    sys.stderr = Redacting(sys.__stderr__, replacements)

    run = Run(host, (addresses[0], 5060), extensions)
    try:
        run.start()
        if await run.register():
            await run.first_call()
            await run.second_call()
        else:
            say("note registration refused or unanswered: no call placed, nothing retried")
        await run.unregister()
    finally:
        await run.close()
    return 1 if run.failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
