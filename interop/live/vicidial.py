# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""An agent's phone on a live ViciBox 12 (VICIdial, Asterisk 18, chan_sip):
`scripts/lab.sh vicidial-live` runs this, by hand only, never as part of a
run that names nothing.

The two extensions are the ones `interop/live/vitalpbx.py` uses, and so is
everything that carries a call: the stacks, the tones, the listening. What
is VICIdial's own is the agent's session. An agent logs in on the web page
with a phone and a campaign, and the dialer then calls that phone and puts
it in a conference of its own, where every call the agent takes is joined
to it. So, with 101 as the agent's phone:

1. The agent logs in, as the page's form does, and the dialer's call to
   101 has to arrive and be answered without anyone choosing to.
2. 102 dials the conference the dialer gave the agent, as a caller joined
   to the session would be, and each end listens for the other's tone
   through it, both ways.
3. 102 sends the digit 5; the conference passes digits on, and 101 has to
   receive it.
4. 102 hangs up and 101's session has to stay up.
5. The agent is logged out from the administration page, and the dialer
   has to end 101's session call itself.

The account file is the same ``KEY=value`` file, named by
``VICIDIAL_LIVE_ENV``, with the keys `interop/live/vitalpbx.py` reads
(``<PREFIX>_CODEC=PCMU`` for a ViciBox, which allows ``ulaw`` alone) and
five more: ``<PREFIX>_AGENT_USER`` and ``<PREFIX>_AGENT_PASS``, the agent;
``<PREFIX>_CAMPAIGN``, a manual-dial campaign that lets an agent log in
with no leads; ``<PREFIX>_ADMIN_USER`` and ``<PREFIX>_ADMIN_PASS``, a user of
level 7 or more allowed to view reports and modify users, which looks the
agent's session up and logs the agent out. Phone 101's login password on
the agent page is its SIP secret. Every secret, the host and its addresses
are masked in everything this process writes, and the requests go as form
posts, so no secret is in a URL either.

Lines and exit status as `interop/live/vitalpbx.py` writes them.
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vitalpbx import (  # noqa: E402 -- the directory is put on the path first
    HEARD_FRAMES,
    NOT_RUN,
    PATIENCE_S,
    WINDOW_S,
    Leg,
    Redacting,
    Run,
    account_details,
    carry,
    read_env,
    say,
)

AGENT_KEYS = ("AGENT_USER", "AGENT_PASS", "CAMPAIGN", "ADMIN_USER", "ADMIN_PASS")


def agent_details(values: dict[str, str]) -> dict[str, str] | str:
    """The agent, campaign and administrator keys, or why not."""
    hosts = [key for key in values if key.endswith("_HOST")]
    prefix = hosts[0][: -len("_HOST")]
    found = {}
    for key in AGENT_KEYS:
        value = values.get(f"{prefix}_{key}", "")
        if not value:
            return f"{key.lower().replace('_', ' ')} is missing"
        found[key] = value
    return found


class Dialer:
    """The two web pages the agent and the administrator would use."""

    def __init__(self, host: str, agent: dict[str, str], phone_secret: str) -> None:
        self.base = f"http://{host}"
        self.agent = agent
        self.phone_secret = phone_secret

    def post(self, path: str, fields: dict[str, str]) -> str:
        body = urllib.parse.urlencode(fields).encode()
        with urllib.request.urlopen(f"{self.base}{path}", body, timeout=PATIENCE_S) as answer:
            return answer.read().decode("utf-8", "replace")

    def log_in(self) -> str:
        return self.post(
            "/agc/vicidial.php",
            {
                "phone_login": "101",
                "phone_pass": self.phone_secret,
                "VD_login": self.agent["AGENT_USER"],
                "VD_pass": self.agent["AGENT_PASS"],
                "VD_campaign": self.agent["CAMPAIGN"],
            },
        )

    def status(self) -> list[str] | str:
        """The agent's status fields, or the dialer's answer when it gave none."""
        answer = self.post(
            "/vicidial/non_agent_api.php",
            {
                "source": "sipral",
                "user": self.agent["ADMIN_USER"],
                "pass": self.agent["ADMIN_PASS"],
                "function": "agent_status",
                "agent_user": self.agent["AGENT_USER"],
                "stage": "pipe",
            },
        ).strip()
        if answer.startswith("ERROR"):
            return answer
        return answer.splitlines()[-1].split("|")

    def session(self) -> str | None:
        """The conference the dialer gave the agent: the session_id field."""
        fields = self.status()
        if isinstance(fields, str) or len(fields) < 13:
            return None
        return fields[12].split(",")[0] or None

    def log_out(self) -> str:
        """The administration page's emergency logout of the agent."""
        manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        manager.add_password(None, self.base, self.agent["ADMIN_USER"], self.agent["ADMIN_PASS"])
        opener = urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(manager))
        body = urllib.parse.urlencode(
            {"user": self.agent["AGENT_USER"], "stage": "log_agent_out", "submit": "EMERGENCY LOG AGENT OUT"}
        ).encode()
        with opener.open(f"{self.base}/vicidial/user_status.php", body, timeout=PATIENCE_S) as answer:
            return answer.read().decode("utf-8", "replace")


class Session(Run):
    """The two stacks, with 101 as the agent's phone."""

    def __init__(self, host, address, extensions, codec, dialer: Dialer) -> None:
        super().__init__(host, address, extensions, codec)
        self.dialer = dialer
        self.logged_in = False

    def agent_leg(self) -> Leg | None:
        return next((leg for (ext, _), leg in self.legs.items() if ext == "101" and not leg.placed), None)

    def dial_session(self, conference: str) -> Leg:
        stack = self.stacks["102"]
        # the conference number the dialer itself handed out, nothing else
        call = stack.place_call(self.accounts["102"], f"sip:{conference}@{self.host}", codecs=self.codec)
        leg = Leg("102", call, "101")
        leg.placed = True
        self.legs[("102", call.handle)] = leg
        leg.task = asyncio.create_task(carry(leg))
        return leg

    async def agent_session(self) -> None:
        label = "the agent's login rang the phone into its session, answered"
        try:
            await asyncio.to_thread(self.dialer.log_in)
        except (OSError, urllib.error.URLError) as error:
            self.result(False, label, f"the agent page could not be reached ({error})")
            return
        self.logged_in = True
        await self.until(lambda: (leg := self.agent_leg()) is not None and leg.codec is not None, PATIENCE_S)
        agent = self.agent_leg()
        conference = await asyncio.to_thread(self.dialer.session)
        if agent is None or agent.codec is None or conference is None:
            self.result(
                False,
                label,
                f"call to 101 {'arrived' if agent else 'never arrived'}, "
                f"media {agent.codec if agent and agent.codec else 'not started'}, "
                f"session {conference or 'not given'}",
            )
            return
        self.result(True, label, f"the dialer called 101 on {agent.codec}, session conference {conference}")

        caller = self.dial_session(conference)
        await self.until(lambda: caller.confirmed or caller.ended is not None, PATIENCE_S)
        if not caller.confirmed:
            self.result(
                False,
                "a caller joined to the agent's session, audio both ways",
                f"the conference never answered ({caller.ended or 'no answer'})",
            )
            await self.end(caller, None)
            return
        # the conference answers at once but joins the caller only after its
        # announcements, about three seconds in which the agent hears the
        # prompts and the caller silence; the window opens once each end
        # has heard the other in a few frames, since a lone frame of the
        # first burst can pass for a tone
        answered = time.monotonic()

        def both_joined() -> bool:
            now = time.monotonic()
            return agent.heard_between(answered, now) >= 5 and caller.heard_between(answered, now) >= 5

        # what is heard is no event, so it is looked at between them
        while not both_joined() and caller.ended is None and time.monotonic() - answered < PATIENCE_S:
            await self.until(lambda: caller.ended is not None, 0.05)
        joined = time.monotonic() - answered
        heard_agent, heard_caller, _, _ = await self.listen(agent, caller, WINDOW_S)
        say(f"note {agent.describe()}")
        say(f"note {caller.describe()}")
        self.result(
            heard_agent >= HEARD_FRAMES and heard_caller >= HEARD_FRAMES and agent.ended is None,
            "a caller joined to the agent's session, audio both ways",
            f"joined {joined:.1f} s after the answer; 102's tone heard at 101 in {heard_agent} frames, "
            f"101's at 102 in {heard_caller} (of {int(WINDOW_S * 50)}), through conference {conference}",
        )

        if caller.ended is None:
            caller.call.send_dtmf("5")
            await self.until(lambda: bool(agent.digits) or agent.ended is not None, 3.0)
            got = agent.digits[0] if agent.digits else None
            self.result(
                got is not None and got[0] == "5",
                "a caller's digit passed through the session to the agent",
                f"5 sent by 102 as an event, 101 received {got[0] + ' as ' + got[1] if got else 'nothing'}",
            )

        await self.end(caller, None)
        await self.until(lambda: agent.ended is not None, 2.0)
        self.result(
            caller.ended is not None and caller.ended[0] == "LOCAL_HANGUP" and agent.ended is None,
            "the caller left and the agent's session stayed up",
            f"102 {caller.ended[0] if caller.ended else 'still up'}, "
            f"101 {agent.ended[0] if agent.ended else 'still in the session'}",
        )

        await self.log_out()
        await self.until(lambda: agent.ended is not None, PATIENCE_S)
        after = await asyncio.to_thread(self.dialer.status)
        self.result(
            agent.ended is not None and agent.ended[0] == "REMOTE_HANGUP"
            and isinstance(after, str) and "NOT LOGGED IN" in after,
            "the agent's logout ended the session call from the dialer's side",
            f"101 {agent.ended[0] if agent.ended else 'still up'}; "
            f"the dialer says {after if isinstance(after, str) else 'still ' + after[0]}",
        )

    async def log_out(self) -> None:
        if not self.logged_in:
            return
        try:
            await asyncio.to_thread(self.dialer.log_out)
            self.logged_in = False
        except (OSError, urllib.error.URLError) as error:
            say(f"note the agent could not be logged out ({error}); it stays logged in")


async def main() -> int:
    path = os.environ.get("VICIDIAL_LIVE_ENV", "")
    if not path:
        say("not run: VICIDIAL_LIVE_ENV names no file")
        return NOT_RUN
    try:
        values = read_env(path)
    except OSError as error:
        say(f"not run: the file VICIDIAL_LIVE_ENV names could not be read ({error.strerror})")
        return NOT_RUN
    details = account_details(values)
    if isinstance(details, str):
        say(f"not run: {details}")
        return NOT_RUN
    host, extensions, codec = details
    agent = agent_details(values)
    if isinstance(agent, str):
        say(f"not run: {agent}")
        return NOT_RUN

    replacements = [(host, "<pbx>")]
    replacements += [(secret, "<secret>") for _, secret in extensions.values()]
    replacements += [(agent["AGENT_PASS"], "<secret>"), (agent["ADMIN_PASS"], "<secret>")]
    try:
        found = socket.getaddrinfo(host, 5060, socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        sys.stdout = Redacting(sys.__stdout__, replacements)
        sys.stderr = Redacting(sys.__stderr__, replacements)
        say("not run: the dialer's name did not resolve")
        return NOT_RUN
    addresses = sorted({entry[4][0] for entry in found})
    replacements += [(address, "<pbx-address>") for address in addresses]
    sys.stdout = Redacting(sys.__stdout__, replacements)
    sys.stderr = Redacting(sys.__stderr__, replacements)

    dialer = Dialer(host, agent, extensions["101"][1])
    run = Session(host, (addresses[0], 5060), extensions, codec, dialer)
    try:
        run.start()
        if await run.register():
            await run.agent_session()
        else:
            say("note registration refused or unanswered: no login, nothing retried")
    finally:
        # an agent left logged in holds the session's conference: whatever
        # failed, log it out before anything else is let go
        await run.log_out()
        await run.unregister()
        await run.close()
    return 1 if run.failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
