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
}
AGENT_SECTION = "the Python example agent, called by Asterisk"
NETEM_SECTION = "the same call, over a bad network"
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
    """Splits 'flow name   (stats)' into (name, stats), stats being None when
    there is none. Lazy on the name so the split lands at the first run of
    three spaces before '(' rather than consuming into the stats text --
    correct as long as no flow name itself contains that run, which none do.
    """
    m = re.match(r"^(.*?)(?:\s{3}\((.*)\))?$", text)
    assert m is not None
    return m.group(1), m.group(2)


def split_sections(text: str) -> list[tuple[str, list[str]]]:
    """Splits the log into (header, body) pairs at the known section headers,
    stopping at STOP_SECTION. Text before the first known header (docker and
    readiness noise) and after STOP_SECTION (the pcap listing, and on a live
    run the raw container log tail) is not part of any section and is
    dropped.
    """
    headers = set(FLOW_SECTIONS) | {AGENT_SECTION, NETEM_SECTION}
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
    lines: list[str], versions: dict[str, str], date: str, rows: list[Row]
) -> None:
    for line in lines:
        m = LAB_SH_LINE_RE.match(line)
        if not m:
            continue
        result = "pass" if line.lstrip().startswith("ok") else "fail"
        rows.append(
            Row(
                "asterisk",
                PEER_LABELS["asterisk"],
                versions["asterisk"],
                "Python agent example",
                result,
                None if result == "pass" else m.group(1),
                date,
            )
        )
        return
    print("warning: the Python agent section had no closing ok/FAIL line", file=sys.stderr)


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
    raise ValueError(peer_key)


def parse_log(text: str, versions: dict[str, str], date: str) -> list[Row]:
    rows: list[Row] = []
    for header, body in split_sections(text):
        if header in FLOW_SECTIONS:
            peer_key, driver = FLOW_SECTIONS[header]
            flows = parse_flow_lines(body)
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
        elif header == AGENT_SECTION:
            parse_agent_section(body, versions, date, rows)
        elif header == NETEM_SECTION:
            parse_netem_section(body, versions, date, rows)
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
