#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
"""What the comparison reads off the wire, and the one rating it applies.

interop/compare/compare.sh captures every client under comparison the same
way -- tcpdump in the network namespace the client runs in -- and reads the
numbers out of those captures with this file, so that no figure in
docs/23-compared-with-pjsip.md depends on what either client says about
itself. Standard library only; it runs in the comparison's own capture
container.

    wire.py register CAPTURE CLIENT_IP
    wire.py invite-out CAPTURE CLIENT_IP
    wire.py invite-in CAPTURE CLIENT_IP
    wire.py move CAPTURE NEW_IP PEER_IP MOVED_AT
    wire.py rate LOSS_PCT JITTER_MS RTT_MS
    wire.py channelstats FILE ENDPOINT
    wire.py pjsua-dq LOG
    wire.py sipral-ended LOG

The last three read what each end said about the call's audio -- Asterisk's
`pjsip show channelstats`, pjsua's own `dq` dump, the Sipral agent's `ended`
line -- into the same four figures, and rate them with `rate`.

Each prints `name=value` pairs on one line, `-` for what the capture does
not hold, and exits non-zero only when the capture itself cannot be read.
"""

import re
import struct
import sys

# pcap link types tcpdump writes for `-i any` (Linux cooked capture, v1 and
# v2) and for one Ethernet interface
LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

SIP_METHODS = (
    b"INVITE", b"ACK", b"BYE", b"CANCEL", b"REGISTER", b"OPTIONS", b"PRACK",
    b"UPDATE", b"INFO", b"SUBSCRIBE", b"NOTIFY", b"REFER", b"MESSAGE", b"PUBLISH",
)


def datagrams(path):
    """Every IPv4 UDP datagram in a pcap file: (time, src, sport, dst, dport,
    payload), a datagram the sender's IP layer fragmented read whole."""
    with open(path, "rb") as handle:
        data = handle.read()
    if len(data) < 24:
        raise ValueError(f"{path}: not a capture ({len(data)} bytes)")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError(f"{path}: not a pcap file")
    nanos = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    offset = 24
    pending = {}
    while offset + 16 <= len(data):
        seconds, fraction, captured, _ = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        frame = data[offset:offset + captured]
        offset += captured
        when = seconds + fraction / (1e9 if nanos else 1e6)
        if linktype == LINKTYPE_ETHERNET:
            ethertype, ip = frame[12:14], frame[14:]
        elif linktype == LINKTYPE_LINUX_SLL:
            ethertype, ip = frame[14:16], frame[16:]
        elif linktype == LINKTYPE_LINUX_SLL2:
            ethertype, ip = frame[0:2], frame[20:]
        else:
            raise ValueError(f"{path}: link type {linktype} is not read here")
        if ethertype != b"\x08\x00" or len(ip) < 20 or ip[9] != 17:
            continue
        header = (ip[0] & 0x0F) * 4
        total = struct.unpack(">H", ip[2:4])[0]
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        flags = struct.unpack(">H", ip[6:8])[0]
        more, at = flags & 0x2000, (flags & 0x1FFF) * 8
        udp = ip[header:total]
        if more or at:
            # a fragment: kept until the one without "more fragments"
            # arrives and every octet before it is there (RFC 791 section
            # 3.2), and the datagram is read as sent when its first part
            # was: the sender let go of all of it at once
            key = (src, dst, ip[4:6])
            parts = pending.setdefault(key, {"at": when})
            parts[at] = udp
            if not more:
                parts["end"] = at + len(udp)
            if "end" not in parts:
                continue
            joined = b""
            while len(joined) in parts:
                joined += parts[len(joined)]
            if len(joined) < parts["end"]:
                continue
            when = pending.pop(key)["at"]
            udp = joined
        if len(udp) < 8:
            continue
        sport, dport, length = struct.unpack(">HHH", udp[:6])
        yield when, src, sport, dst, dport, udp[8:length]


def sip(payload):
    """(start line, headers, body) of a SIP message, or None."""
    if not (payload.startswith(b"SIP/2.0 ") or payload.split(b" ", 1)[0] in SIP_METHODS):
        return None
    head, _, body = payload.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        name = name.strip().lower()
        name = {"i": "call-id", "c": "content-type", "l": "content-length"}.get(name, name)
        headers.setdefault(name, value.strip())
    return lines[0], headers, body


def cseq_method(headers):
    return headers.get("cseq", "").split(" ")[-1]


def rtp(payload):
    """Whether a datagram that is not SIP reads as an RTP packet: version 2,
    and a payload type in the ranges RFC 3551 assigns rather than the RTCP
    packet types (RFC 5761 section 4)."""
    if len(payload) < 12 or payload[0] >> 6 != 2:
        return False
    return not 72 <= payload[1] & 0x7F <= 76


def messages(path):
    for when, src, sport, dst, dport, payload in datagrams(path):
        parsed = sip(payload)
        if parsed:
            yield when, src, dst, payload, parsed


def fmt(seconds):
    return "-" if seconds is None else f"{seconds * 1e3:.1f}"


def register(path, client):
    """From the client's first REGISTER to the 200 that accepted one: what
    registering took, and how many REGISTERs it sent to get there."""
    first = accepted = None
    sent = 0
    for when, src, _, _, (start, headers, _) in messages(path):
        if src == client and start.startswith("REGISTER "):
            sent += 1
            first = first if first is not None else when
        elif (first is not None and accepted is None and src != client
              and start.startswith("SIP/2.0 200") and cseq_method(headers) == "REGISTER"):
            accepted = when
            break
    took = None if first is None or accepted is None else accepted - first
    print(f"register_ms={fmt(took)} registers_sent={sent}")


def candidates(body):
    return sum(1 for line in body.split(b"\r\n") if line.startswith(b"a=candidate:"))


def invite_out(path, client):
    """The client's first INVITE, as sent: its size and its candidates, and
    how long it took from that INVITE to the 200 that answered its call."""
    first = answered = None
    call_id = None
    size = count = None
    for when, src, _, payload, (start, headers, body) in messages(path):
        if src == client and start.startswith("INVITE ") and first is None:
            first, call_id = when, headers.get("call-id")
            size, count = len(payload), candidates(body)
        elif (first is not None and src != client and start.startswith("SIP/2.0 200")
              and cseq_method(headers) == "INVITE" and headers.get("call-id") == call_id):
            answered = when
            break
    took = None if first is None or answered is None else answered - first
    print(f"invite_bytes={size if size is not None else '-'} "
          f"candidates={count if count is not None else '-'} setup_ms={fmt(took)}")


def invite_in(path, client):
    """From the first INVITE that reached the client to its 200: how long the
    client took to answer, with nobody deciding in between."""
    first = answered = None
    call_id = None
    for when, src, dst, _, (start, headers, _) in messages(path):
        if dst == client and start.startswith("INVITE ") and first is None:
            first, call_id = when, headers.get("call-id")
        elif (first is not None and src == client and start.startswith("SIP/2.0 200")
              and cseq_method(headers) == "INVITE" and headers.get("call-id") == call_id):
            answered = when
            break
    took = None if first is None or answered is None else answered - first
    print(f"answer_ms={fmt(took)}")


def move(path, new_ip, peer, moved_at):
    """After the address moved at MOVED_AT (Unix time, the same clock the
    capture keeps): when the client first spoke SIP from the new address,
    what it sent first, when its audio first left from there, and when the
    peer's audio first reached it there -- the call heard both ways again."""
    moved_at = float(moved_at)
    sip_at = rtp_out = rtp_in = None
    first_request = "-"
    for when, src, _, dst, _, payload in datagrams(path):
        if when < moved_at:
            continue
        parsed = sip(payload)
        if parsed:
            if src == new_ip and sip_at is None:
                sip_at = when
                first_request = parsed[0].split(" ", 1)[0]
            continue
        if not rtp(payload):
            continue
        if src == new_ip and dst == peer and rtp_out is None:
            rtp_out = when
        if src == peer and dst == new_ip and rtp_in is None:
            rtp_in = when

    def since(when):
        return None if when is None else when - moved_at

    print(f"first_sip_ms={fmt(since(sip_at))} first_sip={first_request} "
          f"audio_out_ms={fmt(since(rtp_out))} audio_back_ms={fmt(since(rtp_in))}")


def rating(loss_pct, jitter_ms, rtt_ms):
    """ITU-T G.107's E-model, reduced to what both clients and Asterisk all
    report -- loss, jitter and round trip -- for G.711 with packet loss
    concealment (Ie 0, Bpl 25.1, ITU-T G.113 Appendix I), random loss, and a
    one-way delay taken as half the round trip, one 20 ms packet and twice
    the jitter for the buffer. The same arithmetic for every row, so what
    differs between two rows is what was measured, not how it was scored."""
    loss, jitter = float(loss_pct), float(jitter_ms)
    rtt = 0.0 if rtt_ms in ("-", "") else float(rtt_ms)
    delay = rtt / 2 + 20 + 2 * jitter
    idd = 0.024 * delay + (0.11 * (delay - 177.3) if delay > 177.3 else 0.0)
    ie_eff = 95 * loss / (loss + 25.1)
    r = max(0.0, min(100.0, 93.2 - idd - ie_eff))
    mos = 1.0 if r <= 0 else 4.5 if r >= 100 else 1 + 0.035 * r + r * (r - 60) * (100 - r) * 7e-6
    return f"r={r:.1f} mos={mos:.2f}"


def rate(loss_pct, jitter_ms, rtt_ms):
    print(rating(loss_pct, jitter_ms, rtt_ms))


def figures(received, loss_pct, jitter_ms, rtt_ms):
    """The four figures every end is read into, and their rating."""
    rated = rating(loss_pct, jitter_ms, rtt_ms) if loss_pct != "-" and jitter_ms != "-" else "r=- mos=-"
    return f"received={received} loss_pct={loss_pct} jitter_ms={jitter_ms} rtt_ms={rtt_ms} {rated}"


def channelstats(path, endpoint):
    """Asterisk's own view of the call, from `pjsip show channelstats`: what
    it received from the client (count, lost, per cent, jitter) and the
    round trip. Its jitter and round trip are printed in seconds, and a round
    trip of zero is one it has not measured."""
    with open(path, encoding="latin-1") as handle:
        for line in handle:
            tokens = line.split()
            for index, token in enumerate(tokens):
                if not token.startswith(endpoint):
                    continue
                values = tokens[index + 1:index + 12]
                if len(values) < 11:
                    continue
                received, lost, jitter, rtt = values[2], values[3], values[5], values[10]
                count = int(received) + int(lost)
                loss = 0.0 if count == 0 else int(lost) * 100.0 / count
                # a round trip it never measured is printed as zero
                rtt = "-" if float(rtt) == 0 else f"{float(rtt) * 1e3:.1f}"
                print(figures(received, f"{loss:.2f}", f"{float(jitter) * 1e3:.2f}", rtt))
                return
    print(figures("-", "-", "-", "-"))


def pjsua_dq(path):
    """pjsua's own view, from the last `dq` it printed: its receiving side's
    packets (as pjsua prints them: "1.4K" past a thousand), loss and mean
    jitter, and the mean round trip."""
    with open(path, encoding="latin-1") as handle:
        text = handle.read()
    start = text.rfind("RX pt=")
    if start < 0:
        print(figures("-", "-", "-", "-"))
        return
    block = text[start:]
    tx = block.find("TX pt=")
    rx = block[:tx] if tx >= 0 else block
    total = re.search(r"total ([\d.]+[KM]?)pkt", rx)
    loss = re.search(r"pkt loss=\d+ \(([\d.]+)%\)", rx)
    jitter = re.search(r"jitter\s*:\s*[\d.]+\s+([\d.]+)", rx)
    rtt = re.search(r"RTT msec\s*:\s*[\d.]+\s+([\d.]+)", block)
    print(figures(total.group(1) if total else "-", loss.group(1) if loss else "-",
                  jitter.group(1) if jitter else "-", rtt.group(1) if rtt else "-"))


def sipral_ended(path):
    """The Sipral agent's own view, from the last `ended` line it printed,
    with its own E-model rating beside the one `rate` gives every end."""
    with open(path, encoding="latin-1") as handle:
        ended = [line for line in handle if line.startswith("ended ")]
    if not ended:
        print(figures("-", "-", "-", "-") + " own_r=- own_mos=-")
        return
    fields = dict(pair.split("=", 1) for pair in ended[-1].split() if "=" in pair)
    print(figures(fields.get("received", "-"), fields.get("loss_pct", "-"),
                  fields.get("jitter_ms", "-"), fields.get("rtt_ms", "-"))
          + f" own_r={fields.get('r', '-')} own_mos={fields.get('mos', '-')}")


def main(argv):
    commands = {
        "register": (register, 2),
        "invite-out": (invite_out, 2),
        "invite-in": (invite_in, 2),
        "move": (move, 4),
        "rate": (rate, 3),
        "channelstats": (channelstats, 2),
        "pjsua-dq": (pjsua_dq, 1),
        "sipral-ended": (sipral_ended, 1),
    }
    if len(argv) < 2 or argv[1] not in commands or len(argv) - 2 != commands[argv[1]][1]:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    function, _ = commands[argv[1]]
    try:
        function(*argv[2:])
    except (OSError, ValueError) as error:
        print(f"cannot read: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
