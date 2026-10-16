# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""The flows a live PBX carries between its own extensions, beyond the two
calls of `interop/live/vitalpbx.py`: `scripts/lab.sh vitalpbx-live` runs
this after it, by hand only. Nothing dialled is anything but the
extensions the account file names, and nothing on the PBX is changed.

Four Python ``Stack`` objects in one process, one per extension: 101, 102,
and the first two other extensions the file names, in number order (A and B
below). Each scenario is short:

1. Blind transfer: 101 calls 102, then REFERs it to A. A answers, and 102
   and A have to hear each other's tone; 101's REFER has to end in a 2xx
   and its call has to end.
2. Attended transfer: 101 calls 102, holds it, calls A, then hands 102 to A
   (REFER with Replaces, RFC 3891). 102 and A have to hear each other, and
   both of 101's calls have to end.
3. A digit by SIP INFO: 101 calls 102 and sends 7 as an INFO; 102 has to
   receive a 7, however the PBX passes it on.
4. MESSAGE (RFC 3428): 101 sends a text to 102, which has to receive it.
5. Message waiting (RFC 3842): B subscribes to its own message-summary,
   101 calls B, B refuses the call busy so the PBX sends it to voicemail,
   101 leaves four seconds of tone and hangs up, and B's new-message count
   has to rise.

A scenario the PBX does not carry -- no MESSAGE routing, no voicemail on B
-- fails with what the PBX answered, and the next one runs.

The file is the one `vitalpbx.py` reads (``VITALPBX_LIVE_ENV``), with two
more extensions: ``<PREFIX>_<N>_USER`` and ``<PREFIX>_<N>_SECRET`` for each.
Lines, the redaction and the exit status are `vitalpbx.py`'s.
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
import time

import vitalpbx as base
from vitalpbx import HEARD_FRAMES, NOT_RUN, PATIENCE_S, WINDOW_S, Leg, Redacting, say

# whole cycles in 20 ms, away from 101's and 102's and from every DTMF
# frequency
EXTRA_TONES = (2200.0, 600.0)


def account_details(values: dict[str, str]):
    """The host, each extension's (user, secret), the two extra extensions
    and the codec, or why not."""
    first = base.account_details(values)
    if isinstance(first, str):
        return first
    host, extensions, codec = first
    prefix = next(key for key in values if key.endswith("_HOST"))[: -len("_HOST")]
    numbers = sorted(
        {
            key[len(prefix) + 1 : -len("_USER")]
            for key in values
            if key.startswith(prefix + "_") and key.endswith("_USER")
        }
        - set(extensions),
        key=lambda n: (len(n), n),
    )
    extra = []
    for number in numbers:
        user = values.get(f"{prefix}_{number}_USER", "")
        secret = values.get(f"{prefix}_{number}_SECRET", "")
        if user and secret:
            extensions[number] = (user, secret)
            extra.append(number)
        if len(extra) == 2:
            break
    if len(extra) < 2:
        return f"the file names {len(extra)} extension(s) besides 101 and 102, not two"
    return host, extensions, extra, codec


class Features(base.Run):
    """`vitalpbx.Run` with four extensions, and the events it ignores."""

    def __init__(self, host, address, extensions, extra, codec) -> None:
        super().__init__(host, address, extensions, codec)
        self.a, self.b = extra
        self.peer: dict[str, str] = {}
        self.refuse: set[str] = set()
        self.transfers: dict[int, tuple[int, bool]] = {}
        self.sent: dict[int, int] = {}
        self.received: list[tuple[str, str, bytes]] = []
        self.waiting: list[tuple[float, bool, int]] = []

    def handle(self, extension: str, event) -> None:
        from sipral.enums import EventKind

        kind = event.kind
        fields = event.fields
        if kind == EventKind.INCOMING_CALL:
            stack = self.stacks[extension]
            if extension in self.refuse:
                stack.reject_call(event, 486)
                return
            call = stack.answer_call(event, codecs=self.codec)
            leg = Leg(extension, call, self.peer.get(extension, "101"))
            leg.far = base.media_endpoint(fields.get("remote_sdp"))
            self.legs[(extension, call.handle)] = leg
            leg.task = asyncio.create_task(base.carry(leg))
            return
        if kind == EventKind.TRANSFER_DONE and event.call:
            self.transfers[event.call] = (fields["status_code"], fields["attended"])
        elif kind == EventKind.MESSAGE_SENT:
            self.sent[fields["message"]] = fields["status_code"]
        elif kind == EventKind.MESSAGE_RECEIVED:
            self.received.append((extension, fields["content_type"], fields["body"]))
        elif kind == EventKind.MESSAGES_WAITING:
            self.waiting.append((time.monotonic(), fields["waiting"], fields["new_messages"]))
        super().handle(extension, event)

    async def register(self) -> bool:
        for account in self.accounts.values():
            account.register()
        everyone = list(self.extensions)
        await self.until(
            lambda: self.refused or all(self.registration.get(e) == "registered" for e in everyone),
            base.PATIENCE_S,
        )
        ok = all(self.registration.get(e) == "registered" for e in everyone)
        said = ", ".join(f"{e} {self.registration.get(e, 'no answer')}" for e in everyone)
        self.result(ok, "four extensions registered at the live PBX", said)
        return ok

    def answered(self, extension: str, besides: Leg | None = None) -> Leg | None:
        return next(
            (
                leg
                for (ext, _), leg in self.legs.items()
                if ext == extension and leg.ended is None and not leg.placed and leg is not besides
            ),
            None,
        )

    async def call(self, caller: str, callee: str) -> tuple[Leg, Leg | None]:
        self.peer[callee] = caller
        leg = self.place(caller, callee)
        await self.until(lambda: leg.confirmed or leg.ended is not None, PATIENCE_S)
        return leg, (self.answered(callee) if leg.confirmed else None)

    async def heard(self, one: Leg, other: Leg) -> tuple[int, int]:
        start = time.monotonic()
        await self.until(lambda: one.ended is not None or other.ended is not None, WINDOW_S)
        end = time.monotonic()
        return one.heard_between(start, end), other.heard_between(start, end)

    async def hang_up_all(self) -> None:
        for leg in self.legs.values():
            if leg.ended is None:
                try:
                    leg.call.hangup()
                except Exception:  # noqa: BLE001 -- the call may already be on its way down
                    pass
        await self.until(lambda: all(leg.ended is not None for leg in self.legs.values()), PATIENCE_S)

    async def blind(self) -> None:
        label = "a blind transfer"
        first, second = await self.call("101", "102")
        if second is None:
            self.result(False, label, f"101 to 102 never answered ({first.ended or 'no answer'})")
            return await self.hang_up_all()
        self.peer[self.a] = "102"
        first.call.transfer(f"sip:{self.a}@{self.host}")
        await self.until(
            lambda: self.answered(self.a) is not None or first.call.handle in self.transfers,
            PATIENCE_S,
        )
        target = self.answered(self.a)
        await self.until(lambda: first.call.handle in self.transfers and first.ended is not None, PATIENCE_S)
        status = self.transfers.get(first.call.handle, (0, False))[0]
        if target is None:
            self.result(False, label, f"{self.a} never rang; the REFER ended {status or 'unanswered'}")
            return await self.hang_up_all()
        second.other = self.a
        at_second, at_target = await self.heard(second, target)
        self.result(
            200 <= status < 300 and first.ended is not None
            and at_second >= HEARD_FRAMES and at_target >= HEARD_FRAMES,
            label,
            f"101 sent 102 to {self.a}: REFER {status}, 101 {first.ended[0] if first.ended else 'still up'}; "
            f"{self.a}'s tone heard at 102 in {at_second} frames, 102's at {self.a} in {at_target} "
            f"(of {int(WINDOW_S * 50)})",
        )
        await self.hang_up_all()

    async def attended(self) -> None:
        from sipral._sipral_cffi import lib
        from sipral.errors import call as checked

        label = "an attended transfer"
        held, second = await self.call("101", "102")
        if second is None:
            self.result(False, label, f"101 to 102 never answered ({held.ended or 'no answer'})")
            return await self.hang_up_all()
        held.call.hold()
        await self.until(lambda: held.held or held.ended is not None, 3.0)
        consult, target = await self.call("101", self.a)
        if target is None:
            self.result(False, label, f"101 to {self.a} never answered ({consult.ended or 'no answer'})")
            return await self.hang_up_all()
        stack = self.stacks["101"]
        checked(
            lambda: lib.sipral_call_transfer_to(stack.handle, held.call.handle, consult.call.handle, stack.now_ms()),
            "sipral_call_transfer_to",
        )
        await self.until(lambda: held.ended is not None and consult.ended is not None, PATIENCE_S)
        status = self.transfers.get(held.call.handle, (0, False))
        second.other = self.a
        target.other = "102"
        at_second, at_target = await self.heard(second, target)
        self.result(
            held.ended is not None and consult.ended is not None
            and at_second >= HEARD_FRAMES and at_target >= HEARD_FRAMES,
            label,
            f"101 handed 102 to {self.a}: REFER {status[0] or 'unanswered'} (attended={int(status[1])}), "
            f"101's calls {held.ended[0] if held.ended else 'up'} and {consult.ended[0] if consult.ended else 'up'}; "
            f"{self.a}'s tone heard at 102 in {at_second} frames, 102's at {self.a} in {at_target} "
            f"(of {int(WINDOW_S * 50)})",
        )
        await self.hang_up_all()

    async def info_digit(self) -> None:
        from sipral.enums import DtmfVia

        label = "a digit by SIP INFO carried end to end"
        caller, callee = await self.call("101", "102")
        if callee is None:
            self.result(False, label, f"101 to 102 never answered ({caller.ended or 'no answer'})")
            return await self.hang_up_all()
        await self.until(lambda: caller.ended is not None, 1.0)
        caller.call.send_dtmf("7", via=int(DtmfVia.INFO_RELAY))
        await self.until(lambda: bool(callee.digits) or caller.ended is not None, 3.0)
        got = callee.digits[0] if callee.digits else None
        self.result(
            got is not None and got[0] == "7",
            label,
            f"7 sent by 101 as an INFO, 102 received {got[0] + ' as ' + got[1] if got else 'nothing'}",
        )
        await self.hang_up_all()

    async def message(self) -> None:
        from sipral._sipral_cffi import ffi, lib
        from sipral.errors import call as checked

        label = "MESSAGE between two extensions"
        stack = self.stacks["101"]
        account = self.accounts["101"]
        target = f"sip:102@{self.host}".encode()
        kind = b"text/plain"
        body = b"sipral live check"
        out = ffi.new("sipral_handle_t *")
        checked(
            lambda: lib.sipral_account_message(
                stack.handle, account.handle, target, len(target), kind, len(kind),
                body, len(body), out, stack.now_ms(),
            ),
            "sipral_account_message",
        )
        handle = int(out[0])
        await self.until(
            lambda: handle in self.sent and any(r[0] == "102" for r in self.received)
            or (handle in self.sent and not 200 <= self.sent[handle] < 300),
            PATIENCE_S,
        )
        got = next((r for r in self.received if r[0] == "102"), None)
        status = self.sent.get(handle, 0)
        self.result(
            200 <= status < 300 and got is not None and body in got[2],
            label,
            f"101 to 102: answered {status or 'nothing'}; 102 received "
            + (f"{got[1]}, {len(got[2])} bytes" if got else "nothing"),
        )

    async def mwi(self) -> None:
        label = "message waiting on a message left by voicemail"
        b = self.b
        account = self.accounts[b]
        user = self.extensions[b][0]
        account.subscribe(f"sip:{user}@{self.host}", "message-summary")
        await self.until(lambda: bool(self.waiting), PATIENCE_S)
        if not self.waiting:
            self.result(False, label, f"{b}'s subscription to its own message-summary was never notified")
            return
        before = self.waiting[-1][2]
        self.refuse.add(b)
        caller, _ = await self.call("101", b)
        if not caller.confirmed:
            self.result(
                False, label,
                f"{b} refused busy and nothing answered for it (no voicemail?): 101 {caller.ended or 'no answer'}",
            )
            return await self.hang_up_all()
        await self.until(lambda: caller.ended is not None, 6.0)
        left_at = time.monotonic()
        await self.hang_up_all()
        await self.until(lambda: any(at > left_at and n > before for at, _, n in self.waiting), 15.0)
        after = max((n for at, _, n in self.waiting if at > left_at), default=None)
        self.result(
            after is not None and after > before,
            label,
            f"{b} had {before} new message(s); after 101 left one, "
            + (f"{after}" if after is not None else "no NOTIFY came"),
        )


async def main() -> int:
    path = os.environ.get("VITALPBX_LIVE_ENV", "")
    if not path:
        say("not run: VITALPBX_LIVE_ENV names no file")
        return NOT_RUN
    try:
        values = base.read_env(path)
    except OSError as error:
        say(f"not run: the file VITALPBX_LIVE_ENV names could not be read ({error.strerror})")
        return NOT_RUN
    details = account_details(values)
    if isinstance(details, str):
        say(f"not run: {details}")
        return NOT_RUN
    host, extensions, extra, codec = details
    for number, hz in zip(extra, EXTRA_TONES):
        base.TONES[number] = hz

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

    run = Features(host, (addresses[0], 5060), extensions, extra, codec)
    try:
        run.start()
        if await run.register():
            for scenario in (run.blind, run.attended, run.info_digit, run.message, run.mwi):
                await scenario()
        else:
            say("note registration refused or unanswered: no call placed, nothing retried")
        await run.unregister()
    finally:
        await run.close()
    return 1 if run.failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
