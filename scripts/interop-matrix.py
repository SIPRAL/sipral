#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# Turns one scripts/lab.sh run's own stdout into the generated half of
# docs/11-testing.md's "Interoperability matrix" section: a results table
# (peer, peer version, flow, result, date) and a feature status table built
# from the same results plus interop/features.toml. `scripts/lab.sh --matrix`
# calls this after a live run; `scripts/check.sh` calls it with `--check`
# against interop/fixtures/lab-run.log, so the committed section cannot drift
# from what a real run produced without the gate saying so.
#
# Python 3 standard library only, on purpose: this is a small, single-purpose
# tool, not a dependency to pin and vet.
#
# WHAT IS PARSED. `scripts/lab.sh` prints its own section headers and pass/
# fail lines (its step()/pass()/fail() helpers), and inherits stdout for the
# containers it runs, so the harness's own "lab: ..." line and its own
# "  pass  <flow>" / "  FAIL  <flow> — <reason>" lines (interop/harness/src/
# main.rs) land in the same stream, interleaved exactly as a terminal would
# show them. Nothing here re-implements lab.sh's control flow; it recognises
# the literal section headers lab.sh's own step() calls print (a small,
# closed list — see SECTIONS below) and, inside each one, the harness's own
# two line shapes. A header lab.sh has not printed simply produces no rows,
# which is the correct reading of a peer or driver a given run did not reach
# (`SIPRAL_HARNESS_C` unset skips every "through the C ABI" section, for one)
# rather than an error.
#
# WHAT IS NOT PARSED. Everything from "the capture" on: the pcap directory
# listing and, on a live run, the raw `docker compose logs` tail teardown()
# prints after it. That text is for a person reading the run by eye, not
# structured for this, and the fixture this ships with is trimmed at "the
# lab agrees" for exactly that reason.

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BEGIN_MARKER = "<!-- BEGIN GENERATED interop-matrix -->"
END_MARKER = "<!-- END GENERATED interop-matrix -->"

# The section headers scripts/lab.sh's own step() calls print, each mapped to
# the peer it exercises and which driver (the Rust facade, or the C ABI) ran
# it. Kept literal rather than pattern-matched: a header that changes wording
# is a header this file has to be told about too, the same way a flow lab.sh
# stops printing is a flow this file stops seeing, and a silent guess at
# either would be worse than the KeyError a stale entry gives below.
FLOW_SECTIONS = {
    "register, call, hold, resume, transfer -- through the proxy": ("kamailio", "rust"),
    "the same, through the C ABI -- through the proxy": ("kamailio", "c"),
    "register, call, hold, resume, transfer -- through OpenSIPS": ("opensips", "rust"),
    "the same, through the C ABI -- through OpenSIPS": ("opensips", "c"),
    "register, call, hold, resume, transfer -- straight at Asterisk": ("asterisk", "rust"),
    "the same, through the C ABI -- straight at Asterisk": ("asterisk", "c"),
    "phone to phone -- baresip through the proxy": ("baresip", "rust"),
    "the same, through the C ABI -- baresip through the proxy": ("baresip", "c"),
    "behind a NAT -- STUN against coturn, then register and call Asterisk, in C": ("nat_stun", "c"),
    "called behind a NAT -- STUN against coturn, then Asterisk calls in, in C": ("nat_stun", "c"),
    "ICE-lite -- a call that requires ICE, placed at the headless agent answering as lite": (
        "ice_lite",
        "rust",
    ),
    "ICE-lite -- the same call, placed at a C ABI stack answering as lite": ("ice_lite", "c"),
    "a REFER from outside any call -- refused by a C ABI stack that does not take them": (
        "asterisk",
        "c",
    ),
    "a REFER from outside any call -- taken by a C ABI stack, calling Asterisk's echo": (
        "asterisk",
        "c",
    ),
    "full ICE -- two stacks, each behind a NAT of its own, on what STUN gave them": ("full_ice", "rust"),
}
# The one FLOW_SECTIONS header lab.sh runs through nat_pair_call (ice_nat_flow)
# rather than a single harness process: parse_log() reads it with
# parse_nat_pair_flow_lines() instead of plain parse_flow_lines(), the same
# way TURN_RELAY_BLOCKS's own five markers already have to.
NAT_PAIR_FLOW_SECTIONS = {
    "full ICE -- two stacks, each behind a NAT of its own, on what STUN gave them",
}
# Sections shaped like an example agent's own transcript rather than the
# harness's flow output: nobody here prints a "pass"/"FAIL" line of the shape
# FLOW_PASS_RE/FLOW_FAIL_RE read, only lab.sh's own closing `ok`/`FAIL` line,
# because the agent (or, for ICE-lite, Asterisk itself) is the one placing or
# answering the call rather than the harness driving a flow. One dict, in the
# order lab.sh prints them, each mapped to the peer that called or was
# called and the flow name this file reports the result under -- a name this
# file invents, the way "Python agent example" already was before this dict
# existed, since none of these sections prints one in the shape a feature's
# `flows` entry expects.
AGENT_SECTIONS = {
    "the Python example agent, called by Asterisk": ("asterisk", "Python agent example"),
    "the socket-framed agent, called by Asterisk": ("asterisk", "headless socket agent example"),
    "the Swift binding's example agent, called by Asterisk": ("asterisk", "Swift agent example"),
    "the Kotlin idiomatic-layer agent, called by Asterisk": ("asterisk", "Kotlin agent example"),
    "the .NET sample agent, called by Asterisk": ("asterisk", ".NET agent example"),
    "ICE-lite -- Asterisk's own ICE calling the headless agent": (
        "asterisk",
        "ICE-lite, Asterisk's ICE calling in",
    ),
}
NETEM_SECTION = "the same call, over a bad network"
TURN_RELAY_SECTION = "full ICE through a relay -- the path between the two NATs blocked, coturn as TURN"
STOP_SECTION = "the capture"

# What each row's "Peer" column reads, and which of the versions read_versions()
# collects belongs beside it. Kamailio's and OpenSIPS's own rows report two
# versions -- the proxy's and the FreeSWITCH behind it -- because both are on
# the wire for every flow in those two sections; baresip's report its own and
# the Kamailio it registers through, for the same reason.
PEER_LABELS = {
    "kamailio": "Kamailio \u2192 FreeSWITCH",
    "opensips": "OpenSIPS \u2192 FreeSWITCH",
    "asterisk": "Asterisk",
    "baresip": "baresip (phone to phone, via Kamailio)",
    "nat_stun": "Asterisk, from behind a NAT (STUN)",
    "ice_lite": "headless agent (ICE-lite)",
    "full_ice": "sipral, self-to-self (each behind its own NAT)",
}

# Named by the owner (root CLAUDE.md, intern/TASKS.md 8.6.8): every peer worth
# an eventual row that this lab cannot reach yet, because reaching it needs an
# account, a licence or a partner's own access grant nobody here holds today.
# Listed rather than left out, so the table says "not yet" instead of saying
# nothing -- a peer this file forgets to mention and a peer nobody has asked
# about read the same to somebody skimming the table, and only one of those
# is true.
UNTESTED_PEERS = [
    "Carrier A",
    "Carrier B",
    "Commercial SBC",
    "3CX",
    "Teams Direct Routing",
    "AudioCodes",
    "Ribbon",
]

LAB_LINE_RE = re.compile(r"^lab: (\S+):(\d+) at (\S+), extension (\S+), as (\S+)$")
FLOW_PASS_RE = re.compile(r"^  pass  (.+)$")
# Only the harness's own FAIL lines carry " — <reason>" (the em dash main.rs
# prints it with); lab.sh's own fail() line closing a section never does, so
# requiring the dash is what keeps that closing line from being read as a
# flow of its own if a section's terminator ("every flow passed" / "N flow(s)
# failed") is ever missing from what was captured.
FLOW_FAIL_RE = re.compile(r"^  FAIL  (.+?) \u2014 (.+)$")
EVERY_PASSED_RE = re.compile(r"^every flow passed$")
N_FAILED_RE = re.compile(r"^\d+ flow\(s\) failed$")
LAB_SH_LINE_RE = re.compile(r"^  (?:ok|FAIL)  +(.+)$")
# `scripts/lab.sh`'s own fail() closing a nat_pair_call-backed step or block --
# never the harness's own FAIL line, which always carries the em dash above;
# a lab.sh message never does, so excluding it is what tells the two apart.
LAB_SH_FAIL_RE = re.compile(r"^  FAIL  (?!.*\u2014 )(.+)$")
# `nat_pair_call` (scripts/lab.sh) runs the harness twice, caller and callee,
# each in its own container; `docker logs $ICE_CALLEE_NAME | sed 's/^/    callee  /'`
# is how the callee's stdout reaches this log, so its own "  pass  "/"  FAIL  "
# lines -- printed in the identical shape by the same main.rs -- show up with
# this exact twelve-character prefix in front of them.
CALLEE_PREFIX = "    callee  "


@dataclass
class Row:
    peer_key: str
    peer: str
    version: str
    flow: str
    result: str
    detail: str | None
    date: str


def md_cell(text: str) -> str:
    """Escapes a value for a Markdown table cell: no bare '|' or newline."""
    return text.replace("|", "\\|").replace("\n", " ").strip()


def split_flow_line(text: str) -> tuple[str, str | None]:
    """Splits 'flow name   (stats)[; trailing text]' into (name, stats),
    stats being None when there is no parenthesized block at all. The split
    lands at the first run of three spaces before '(' -- correct as long as
    no flow name itself contains that run, which none do. Stats can nest
    parentheses of their own ("300 frame(s) mixed, ..."), so the *last* ')'
    in the line, not the first, is the real close; the two ICE-through-NATs
    flows also print a clause after that close ("...audible); this end at
    172.19.0.3:57095, mapped to ..."), which is neither name nor stats and
    nothing here needs, since a passing flow's stats are never rendered
    (render_result() reads `detail` only for a fail, and split_flow_line is
    never called for one -- FLOW_FAIL_RE's own em-dash line carries the
    reason directly).
    """
    marker = "   ("
    idx = text.find(marker)
    if idx == -1:
        return text, None
    name = text[:idx]
    close = text.rfind(")")
    if close <= idx:
        return name, text[idx + len(marker) :]
    return name, text[idx + len(marker) : close]


def split_sections(text: str) -> list[tuple[str, list[str]]]:
    """Splits the log into (header, body) pairs at the known section headers,
    stopping at STOP_SECTION. Text before the first known header (docker and
    readiness noise) and after STOP_SECTION (the pcap listing, and on a live
    run the raw container log tail) is not part of any section and is
    dropped.
    """
    headers = set(FLOW_SECTIONS) | set(AGENT_SECTIONS) | {NETEM_SECTION, TURN_RELAY_SECTION}
    sections: list[tuple[str, list[str]]] = []
    header: str | None = None
    body: list[str] = []
    for line in text.split("\n"):
        if line == STOP_SECTION:
            break
        if line in headers:
            if header is not None:
                sections.append((header, body))
            header, body = line, []
        elif header is not None:
            body.append(line)
    if header is not None:
        sections.append((header, body))
    return sections


def parse_flow_lines(lines: list[str]) -> list[tuple[str, str, str | None]]:
    """Reads the harness's own "  pass"/"  FAIL" lines up to its terminator,
    from the line after its "lab: ..." line. Returns (flow, result, detail)
    triples, result being "pass" or "fail". Lines before "lab: ..." (lab.sh's
    own container-readiness notes) and after the terminator (lab.sh's own
    closing pass/fail line for the section) are not the harness's and are
    never reached: the loop returns as soon as the terminator is seen.
    """
    out: list[tuple[str, str, str | None]] = []
    started = False
    for line in lines:
        if LAB_LINE_RE.match(line):
            started = True
            continue
        if not started:
            continue
        if EVERY_PASSED_RE.match(line) or N_FAILED_RE.match(line):
            break
        m = FLOW_PASS_RE.match(line)
        if m:
            name, stats = split_flow_line(m.group(1))
            out.append((name, "pass", stats))
            continue
        m = FLOW_FAIL_RE.match(line)
        if m:
            out.append((m.group(1), "fail", m.group(2)))
    return out


def parse_callee_flow_lines(lines: list[str]) -> list[tuple[str, str | None]]:
    """The callee's own pass/FAIL results, in the order its container printed
    them: (result, detail) pairs, result being "pass" or "fail". Read by
    stripping CALLEE_PREFIX and matching what is left against FLOW_PASS_RE/
    FLOW_FAIL_RE directly, rather than through parse_flow_lines -- the
    callee's own "lab: ..." line and terminator are real lines of the same
    shape those functions key off, but reachable only through this prefix,
    never through the caller's own unprefixed loop above.
    """
    out: list[tuple[str, str | None]] = []
    for line in lines:
        if not line.startswith(CALLEE_PREFIX):
            continue
        rest = line[len(CALLEE_PREFIX) :]
        if FLOW_PASS_RE.match(rest):
            out.append(("pass", None))
            continue
        m = FLOW_FAIL_RE.match(rest)
        if m:
            out.append(("fail", m.group(2)))
    return out


def closing_lab_fail(lines: list[str]) -> str | None:
    """lab.sh's own closing fail() line for a nat_pair_call-backed step, if
    one was printed anywhere in `lines` -- not only at the end, since
    TURN_RELAY_BLOCKS splits one such step into several marker blocks and
    only the last one holds the step's own closing line.
    """
    for line in lines:
        m = LAB_SH_FAIL_RE.match(line)
        if m:
            return m.group(1)
    return None


def parse_nat_pair_flow_lines(lines: list[str]) -> list[tuple[str, str, str | None]]:
    """parse_flow_lines(), widened for a flow lab.sh runs through
    nat_pair_call: two harness processes, caller and callee, each in its own
    container, and lab.sh's own step that can fail before either one prints
    anything (the callee never comes up, the SIP forward could not be set
    up). The caller's own line is only one of three ways this can fail, and
    reading only it -- what parse_flow_lines alone did -- is what let a
    failed callee, or a failed nat_pair_call itself, render as a passing row.
    A caller's "pass" is downgraded to "fail" when the callee failed or
    lab.sh's own closing line did, keeping the caller's own detail unless it
    is the callee's or lab.sh's own reason that explains it; a caller
    already reporting "fail" is left as it is.
    """
    flows = parse_flow_lines(lines)
    callee = parse_callee_flow_lines(lines)
    lab_fail = closing_lab_fail(lines)
    out: list[tuple[str, str, str | None]] = []
    for index, (name, result, detail) in enumerate(flows):
        callee_result, callee_detail = callee[index] if index < len(callee) else (None, None)
        if result == "pass" and callee_result == "fail":
            result, detail = "fail", callee_detail
        if result == "pass" and lab_fail is not None:
            result, detail = "fail", lab_fail
        out.append((name, result, detail))
    return out


def with_driver(flow: str, driver: str) -> str:
    return f"{flow} (C ABI)" if driver == "c" else flow


def base_flow_name(flow: str) -> str:
    """The name interop/features.toml matches against: the driver suffix
    with_driver() adds is stripped again, so one entry there covers the flow
    under both drivers.
    """
    suffix = " (C ABI)"
    return flow[: -len(suffix)] if flow.endswith(suffix) else flow


def parse_agent_section(
    lines: list[str], peer_key: str, flow_label: str, versions: dict[str, str], date: str, rows: list[Row]
) -> None:
    """The *last* `ok`/`FAIL` line in the section is its verdict, not the
    first: the ICE-lite section where Asterisk calls in prints an earlier,
    unrelated `ok` (a container-readiness note carried over from the step
    before it, "asterisk: Asterisk Ready") ahead of the agent's own
    transcript, and only the closing line is the result this row reports.
    Every other section in AGENT_SECTIONS has exactly one such line, so
    taking the last is the same as taking the only one there.
    """
    found: tuple[str, str] | None = None
    for line in lines:
        m = LAB_SH_LINE_RE.match(line)
        if not m:
            continue
        result = "pass" if line.lstrip().startswith("ok") else "fail"
        found = (result, m.group(1))
    if found is None:
        print(f"warning: the {flow_label!r} section had no closing ok/FAIL line", file=sys.stderr)
        return
    result, detail = found
    rows.append(
        Row(
            peer_key,
            PEER_LABELS[peer_key],
            peer_version_label(peer_key, versions),
            flow_label,
            result,
            None if result == "pass" else detail,
            date,
        )
    )


def impairment_profiles() -> list[str]:
    """The impairment profiles this run could have exercised, read off
    interop/impairment/*.sh rather than kept as a list here, so a profile
    added there is a profile this file finds without being told.
    """
    return sorted(p.stem for p in (ROOT / "interop/impairment").glob("*.sh"))


def parse_netem_section(
    lines: list[str], versions: dict[str, str], date: str, rows: list[Row]
) -> None:
    profiles = impairment_profiles()
    if not profiles:
        print("warning: no interop/impairment/*.sh profiles found", file=sys.stderr)
        return
    # Split the body at each profile's own "  <profile>  <why>" line (bad_network()
    # in scripts/lab.sh), identified by its first word being a known profile
    # name -- distinct from every other two-space-indented line this section
    # can hold ("pass", "FAIL", "note", "qdisc") because no profile is named
    # any of those.
    blocks: list[tuple[str, list[str]]] = []
    current: str | None = None
    body: list[str] = []
    for line in lines:
        first = line[2:].split(None, 1)[0] if line.startswith("  ") and line[2:].strip() else ""
        if first in profiles:
            if current is not None:
                blocks.append((current, body))
            current, body = first, []
        elif current is not None:
            body.append(line)
    if current is not None:
        blocks.append((current, body))

    for profile, block in blocks:
        label = f"over a bad link ({profile})"
        if "IMPAIRMENT-NOT-APPLIED" in block:
            rows.append(
                Row(
                    "kamailio",
                    PEER_LABELS["kamailio"],
                    versions["kamailio"],
                    f"call, {label}",
                    "inconclusive",
                    "impairment not applied on this kernel",
                    date,
                )
            )
            continue
        flows = parse_flow_lines(block)
        if not flows:
            print(f"warning: netem profile {profile} had no flow results", file=sys.stderr)
            continue
        for name, result, detail in flows:
            rows.append(
                Row(
                    "kamailio",
                    PEER_LABELS["kamailio"],
                    versions["kamailio"],
                    f"{name}, {label}",
                    result,
                    detail,
                    date,
                )
            )


# The runs TURN_RELAY_SECTION prints, each under its own literal marker
# line lab.sh prints before it -- a closed, ordered list for the same reason
# FLOW_SECTIONS's own headers are one: a marker whose wording changes is a
# marker this file has to be told about too. Five of them print the identical
# flow name ("full ICE through two NATs, calling"), since it is the same
# harness flow run five ways, so the qualifier here is what tells those
# rows apart in the Results table; the forked call prints its own name. The
# qualifier is also what keeps the two
# "blocked without TURN" runs, negative controls proving the block holds
# before TURN is offered (see invert_negative_control()), out of every
# feature's `flows` list: a passing TURN relay must never read "partial"
# because of a negative control that held.
TURN_RELAY_BLOCKS = {
    "  without TURN: the call has to find no path": ("rust", "blocked without TURN"),
    "  with TURN: the call has to go through coturn": ("rust", "via TURN"),
    "  forked through the proxy to two phones behind the NAT, every end relayed: media on both branches until one answers": (
        "rust",
        "via TURN",
    ),
    "  without TURN, through the C ABI: the call has to find no path": ("c", "blocked without TURN"),
    "  with TURN, through the C ABI: the call has to go through coturn": ("c", "via TURN"),
    "  with TURN at the C caller alone: the call has to go through its own relay": (
        "c",
        "via TURN, caller relay only",
    ),
}
# The qualifier that marks the two negative controls above: a run meant to
# fail (see NEGATIVE_CONTROL_QUALIFIER's own use below).
NEGATIVE_CONTROL_QUALIFIER = "blocked without TURN"
# ice_turn_flow's own note (scripts/lab.sh) when one of the two negative
# controls breaks -- the call connected with the path between the two NATs
# blocked, which the harness itself reports as a "pass" (it placed and heard
# a call), and is what invert_negative_control() below reads for the reason.
BLOCK_DOES_NOT_HOLD_RE = re.compile(
    r"^  the call(?: through the C ABI)? connected with the path between the NATs blocked: .+$"
)


def invert_negative_control(
    lines: list[str], flows: list[tuple[str, str, str | None]]
) -> list[tuple[str, str, str | None]]:
    """The two 'blocked without TURN' runs prove a negative: the harness
    failing to place the call is the block holding, which is what a normal
    run looks like, and the harness succeeding is the block not holding, a
    real regression. Read literally, like every other flow, the two read
    backwards -- passing exactly when something is wrong. Inverted here,
    once, rather than at every reader of a Row's `result`.
    """
    reason = next((line.strip() for line in lines if BLOCK_DOES_NOT_HOLD_RE.match(line)), None)
    out: list[tuple[str, str, str | None]] = []
    for name, result, detail in flows:
        if result == "fail":
            out.append((name, "pass", None))
        else:
            out.append((name, "fail", reason or detail or "the block does not hold"))
    return out


def parse_turn_relay_section(lines: list[str], versions: dict[str, str], date: str, rows: list[Row]) -> None:
    blocks: list[tuple[str, list[str]]] = []
    current: str | None = None
    body: list[str] = []
    for line in lines:
        if line in TURN_RELAY_BLOCKS:
            if current is not None:
                blocks.append((current, body))
            current, body = line, []
        elif current is not None:
            body.append(line)
    if current is not None:
        blocks.append((current, body))

    version = peer_version_label("full_ice", versions)
    for marker, block in blocks:
        driver, qualifier = TURN_RELAY_BLOCKS[marker]
        flows = parse_nat_pair_flow_lines(block)
        if not flows:
            print(f"warning: TURN relay run {marker!r} had no flow results", file=sys.stderr)
            continue
        if qualifier == NEGATIVE_CONTROL_QUALIFIER:
            flows = invert_negative_control(block, flows)
        for name, result, detail in flows:
            rows.append(
                Row(
                    "full_ice",
                    PEER_LABELS["full_ice"],
                    version,
                    with_driver(f"{name}, {qualifier}", driver),
                    result,
                    detail,
                    date,
                )
            )


def read_versions(root: Path) -> dict[str, str]:
    """Peer versions, read from the same files that pin them for the lab
    itself rather than kept here a second time: interop/compose.yaml's own
    image tags for the three servers built as images, and the two Dockerfiles
    for the two peers built from source. A version not found is an empty
    string rather than a guess, and shows in the table as "unknown" -- read
    as "the pin moved and this file was not told", not as "untested".
    """
    compose = (root / "interop/compose.yaml").read_text(encoding="utf-8")
    versions: dict[str, str] = {}
    for service in ("kamailio", "freeswitch", "asterisk"):
        m = re.search(
            rf"^  {re.escape(service)}:\n(?:.*\n)*?    image:\s*(\S+)", compose, re.M
        )
        tag = m.group(1) if m else ""
        v = re.match(r"^[^:]*:([0-9]+(?:\.[0-9]+){1,3})", tag)
        versions[service] = v.group(1) if v else ""

    opensips = (root / "interop/opensips/Dockerfile").read_text(encoding="utf-8")
    m = re.search(r"opensips-auth-modules=([0-9]+(?:\.[0-9]+){1,3})", opensips)
    versions["opensips"] = m.group(1) if m else ""

    baresip = (root / "interop/baresip/Dockerfile").read_text(encoding="utf-8")
    m = re.search(r"baresip/baresip/archive/refs/tags/v([0-9]+(?:\.[0-9]+){1,3})", baresip)
    versions["baresip"] = m.group(1) if m else ""

    return versions


def peer_version_label(peer_key: str, versions: dict[str, str]) -> str:
    def v(key: str) -> str:
        return versions.get(key) or "unknown"

    if peer_key == "kamailio":
        return f"{v('kamailio')} (proxy) / {v('freeswitch')} (FreeSWITCH)"
    if peer_key == "opensips":
        return f"{v('opensips')} (proxy) / {v('freeswitch')} (FreeSWITCH)"
    if peer_key == "asterisk":
        return v("asterisk")
    if peer_key == "baresip":
        return f"{v('baresip')} (baresip) / {v('kamailio')} (proxy)"
    if peer_key == "nat_stun":
        return v("asterisk")
    if peer_key in ("ice_lite", "full_ice"):
        # Neither is a third-party peer with a version of its own to read
        # off compose.yaml or a Dockerfile -- both are this stack calling
        # itself, or being called by the same Asterisk container already
        # versioned above.
        return "n/a"
    raise ValueError(peer_key)


def parse_log(text: str, versions: dict[str, str], date: str) -> list[Row]:
    rows: list[Row] = []
    for header, body in split_sections(text):
        if header in FLOW_SECTIONS:
            peer_key, driver = FLOW_SECTIONS[header]
            parser = parse_nat_pair_flow_lines if header in NAT_PAIR_FLOW_SECTIONS else parse_flow_lines
            flows = parser(body)
            if not flows:
                print(f"warning: section {header!r} had no flow results", file=sys.stderr)
                continue
            version = peer_version_label(peer_key, versions)
            for name, result, detail in flows:
                rows.append(
                    Row(
                        peer_key,
                        PEER_LABELS[peer_key],
                        version,
                        with_driver(name, driver),
                        result,
                        detail,
                        date,
                    )
                )
        elif header in AGENT_SECTIONS:
            peer_key, flow_label = AGENT_SECTIONS[header]
            parse_agent_section(body, peer_key, flow_label, versions, date, rows)
        elif header == NETEM_SECTION:
            parse_netem_section(body, versions, date, rows)
        elif header == TURN_RELAY_SECTION:
            parse_turn_relay_section(body, versions, date, rows)
    return rows


def render_result(result: str, detail: str | None) -> str:
    if result == "pass":
        return "pass"
    reason = (detail or "no reason given").strip()
    if len(reason) > 80:
        reason = reason[:79] + "\u2026"
    return f"{result} ({reason})"


def render_results_table(rows: list[Row]) -> list[str]:
    out = ["| Peer | Version | Flow | Result | Date |", "|---|---|---|---|---|"]
    for r in rows:
        out.append(
            "| "
            + " | ".join(
                md_cell(c)
                for c in (r.peer, r.version, r.flow, render_result(r.result, r.detail), r.date)
            )
            + " |"
        )
    for peer in UNTESTED_PEERS:
        out.append(f"| {md_cell(peer)} | \u2014 | \u2014 | untested | \u2014 |")
    return out


# --- interop/features.toml: a small, fixed shape, read without a TOML library
# (Python's own tomllib needs 3.11, and this file is deliberately flatter than
# general TOML anyway -- see its own header comment for exactly what is read).

FEATURE_BLOCK_RE = re.compile(
    r'\[\[feature\]\]\s*\n'
    r'name\s*=\s*"([^"]*)"\s*\n'
    r"implemented\s*=\s*(true|false)\s*\n"
    r"unit_tested\s*=\s*(true|false)\s*\n"
    r"flows\s*=\s*\[(.*?)\]",
    re.S,
)


@dataclass
class Feature:
    name: str
    implemented: bool
    unit_tested: bool
    flows: list[str]


FLOW_STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def parse_features(text: str) -> list[Feature]:
    features = []
    for name, implemented, unit_tested, flows_raw in FEATURE_BLOCK_RE.findall(text):
        # Quoted strings, not a naive split on ",": several flow names of
        # their own contain a comma ("DTMF, RFC 4733", "SRTP, phone to
        # phone"), and splitting the array's text on every comma would cut
        # those in two instead of at the entries between them.
        flows = FLOW_STRING_RE.findall(flows_raw)
        features.append(Feature(name, implemented == "true", unit_tested == "true", flows))
    return features


def interop_tested(feature: Feature, rows: list[Row]) -> str:
    if not feature.flows:
        return "n/a"
    matched = [r for r in rows if base_flow_name(r.flow) in feature.flows]
    if not matched:
        return "not yet"
    passing = [r for r in matched if r.result == "pass"]
    if len(passing) == len(matched):
        return "yes"
    if passing:
        return "partial"
    return "no"


def render_feature_table(features: list[Feature], rows: list[Row]) -> list[str]:
    out = [
        "| Feature | Implemented | Unit-tested | Interop-tested |",
        "|---|---|---|---|",
    ]
    for f in features:
        out.append(
            "| "
            + " | ".join(
                md_cell(c)
                for c in (
                    f.name,
                    "yes" if f.implemented else "no",
                    "yes" if f.unit_tested else "no",
                    interop_tested(f, rows),
                )
            )
            + " |"
        )
    return out


def render_block(rows: list[Row], features: list[Feature], log_path: Path, date: str) -> str:
    lines = [
        BEGIN_MARKER,
        "",
        f"*Generated by `scripts/interop-matrix.py` from `{log_path.name}`, a "
        f"`scripts/lab.sh` run recorded {date}. Edit `interop/features.toml` or "
        "the source data, then regenerate with `scripts/lab.sh --matrix` — not "
        "this block, which `scripts/check.sh` checks against "
        "`interop/fixtures/lab-run.log` and overwrites otherwise.*",
        "",
        "### Results",
        "",
        *render_results_table(rows),
        "",
        "### Feature status",
        "",
        *render_feature_table(features, rows),
        "",
        END_MARKER,
    ]
    return "\n".join(lines)


def replace_block(doc_text: str, new_block: str) -> str:
    pattern = re.compile(
        re.escape(BEGIN_MARKER) + r".*?" + re.escape(END_MARKER), re.S
    )
    if not pattern.search(doc_text):
        raise SystemExit(
            f"error: {BEGIN_MARKER!r} / {END_MARKER!r} not found in the doc; "
            "add the markers once by hand, where the generated section belongs"
        )
    return pattern.sub(lambda _m: new_block, doc_text, count=1)


def current_block(doc_text: str) -> str | None:
    pattern = re.compile(
        re.escape(BEGIN_MARKER) + r".*?" + re.escape(END_MARKER), re.S
    )
    m = pattern.search(doc_text)
    return m.group(0) if m else None


def resolve_date(args: argparse.Namespace, log_path: Path) -> str:
    if args.date:
        return args.date
    sidecar = log_path.with_suffix(log_path.suffix + ".date")
    if sidecar.is_file():
        return sidecar.read_text(encoding="utf-8").strip()
    import datetime

    today = datetime.date.today().isoformat()
    print(f"note: no --date given and no {sidecar.name}; using today, {today}", file=sys.stderr)
    return today


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="a scripts/lab.sh run, captured as text")
    parser.add_argument(
        "--date",
        help="the run's own date (YYYY-MM-DD); defaults to <log>.date, then today",
    )
    parser.add_argument(
        "--doc",
        type=Path,
        default=ROOT / "docs/11-testing.md",
        help="the doc whose generated block is written or checked",
    )
    parser.add_argument(
        "--features",
        type=Path,
        default=ROOT / "interop/features.toml",
        help="the feature-to-flows mapping file",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare against --doc's current block instead of writing it",
    )
    args = parser.parse_args()

    date = resolve_date(args, args.log)
    versions = read_versions(ROOT)
    rows = parse_log(args.log.read_text(encoding="utf-8"), versions, date)
    features = parse_features(args.features.read_text(encoding="utf-8"))
    new_block = render_block(rows, features, args.log, date)

    doc_text = args.doc.read_text(encoding="utf-8")
    if args.check:
        existing = current_block(doc_text)
        if existing is None:
            print(f"error: no generated block found in {args.doc}", file=sys.stderr)
            return 1
        if existing == new_block:
            return 0
        import difflib

        diff = difflib.unified_diff(
            existing.splitlines(keepends=True),
            new_block.splitlines(keepends=True),
            fromfile=f"{args.doc} (committed)",
            tofile=f"{args.log} (generated)",
        )
        sys.stdout.writelines(diff)
        return 1

    args.doc.write_text(replace_block(doc_text, new_block), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
