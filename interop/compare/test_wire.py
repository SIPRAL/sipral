# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
"""interop/compare/wire.py against captures and logs written here, byte by
byte, so what it reads out of a real run is known to be what the wire held.

    python3 -m unittest discover -s interop/compare
"""

import contextlib
import io
import os
import struct
import tempfile
import unittest

import wire

CLIENT = "172.18.0.3"
MOVED = "172.18.255.246"
PBX = "172.18.0.2"


def udp(src, sport, dst, dport, payload):
    """One IPv4 UDP datagram behind a Linux cooked (v2) header, the frame
    `tcpdump -i any` writes."""
    body = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, 17, 0,
        bytes(int(part) for part in src.split(".")),
        bytes(int(part) for part in dst.split(".")),
    )
    cooked = struct.pack(">HHIHBB8s", 0x0800, 0, 2, 1, 0, 6, b"\0" * 8)
    return cooked + ip + body


def fragmented(src, sport, dst, dport, payload, mtu=1500):
    """The same datagram as `udp`, split the way a sender's IP layer splits
    one larger than the link's MTU (RFC 791 section 3.2): every fragment
    carries the one identification, offsets in eight-octet units, and all
    but the last say more fragments follow."""
    body = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    step = (mtu - 20) // 8 * 8
    frames = []
    for start in range(0, len(body), step):
        chunk = body[start:start + step]
        more = 0x2000 if start + step < len(body) else 0
        ip = struct.pack(
            ">BBHHHBBH4s4s", 0x45, 0, 20 + len(chunk), 0x1234, more | (start // 8), 64, 17, 0,
            bytes(int(part) for part in src.split(".")),
            bytes(int(part) for part in dst.split(".")),
        )
        cooked = struct.pack(">HHIHBB8s", 0x0800, 0, 2, 1, 0, 6, b"\0" * 8)
        frames.append(cooked + ip + chunk)
    return frames


def capture(frames):
    """A pcap file of (time, frame) pairs, microsecond resolution."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, wire.LINKTYPE_LINUX_SLL2)
    for when, frame in frames:
        seconds = int(when)
        micros = round((when - seconds) * 1e6)
        out += struct.pack("<IIII", seconds, micros, len(frame), len(frame)) + frame
    handle = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    handle.write(out)
    handle.close()
    return handle.name


def request(method, cseq_method, call_id, body=b""):
    return (f"{method} sip:x SIP/2.0\r\nCall-ID: {call_id}\r\nCSeq: 1 {cseq_method}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n").encode() + body


def response(code, cseq_method, call_id):
    return (f"SIP/2.0 {code} X\r\nCall-ID: {call_id}\r\nCSeq: 1 {cseq_method}\r\n"
            "Content-Length: 0\r\n\r\n").encode()


def rtp_packet(pt=0):
    return bytes([0x80, pt]) + b"\0" * 10 + b"\xff" * 160


def run(function, *args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        function(*args)
    return dict(pair.split("=", 1) for pair in out.getvalue().split())


class Captures(unittest.TestCase):
    def setUp(self):
        self.paths = []

    def tearDown(self):
        for path in self.paths:
            os.unlink(path)

    def pcap(self, frames):
        path = capture(frames)
        self.paths.append(path)
        return path

    def test_registering_is_the_first_register_to_the_200_that_accepted_one(self):
        path = self.pcap([
            (100.000, udp(CLIENT, 5060, PBX, 5060, request("REGISTER", "REGISTER", "r"))),
            (100.002, udp(PBX, 5060, CLIENT, 5060, response(401, "REGISTER", "r"))),
            (100.004, udp(CLIENT, 5060, PBX, 5060, request("REGISTER", "REGISTER", "r"))),
            (100.0065, udp(PBX, 5060, CLIENT, 5060, response(200, "REGISTER", "r"))),
            (100.010, udp(PBX, 5060, CLIENT, 5060, response(200, "OPTIONS", "o"))),
        ])
        self.assertEqual(run(wire.register, path, CLIENT),
                         {"register_ms": "6.5", "registers_sent": "2"})

    def test_a_long_runs_registrations_and_calls_are_all_counted(self):
        path = self.pcap([
            (100.0, udp(CLIENT, 5060, PBX, 5060, request("REGISTER", "REGISTER", "r"))),
            (100.1, udp(PBX, 5060, CLIENT, 5060, response(401, "REGISTER", "r"))),
            (100.2, udp(CLIENT, 5060, PBX, 5060, request("REGISTER", "REGISTER", "r"))),
            (100.3, udp(PBX, 5060, CLIENT, 5060, response(200, "REGISTER", "r"))),
            (150.0, udp(PBX, 5060, CLIENT, 5060, request("INVITE", "INVITE", "c"))),
            (150.1, udp(CLIENT, 5060, PBX, 5060, response(200, "INVITE", "c"))),
            (160.0, udp(CLIENT, 5060, PBX, 5060, request("REGISTER", "REGISTER", "r"))),
            (160.1, udp(PBX, 5060, CLIENT, 5060, response(200, "REGISTER", "r"))),
            (170.0, udp(PBX, 5060, CLIENT, 5060, response(200, "OPTIONS", "o"))),
        ])
        self.assertEqual(run(wire.registrations, path, CLIENT), {
            "registers_sent": "3", "registers_accepted": "2", "invites_in": "1",
        })

    def test_an_invite_is_measured_as_sent_and_to_its_own_200(self):
        body = (b"v=0\r\nm=audio 4000 RTP/AVP 0\r\n"
                b"a=candidate:1 1 UDP 2130706431 172.18.0.3 4000 typ host\r\n"
                b"a=candidate:1 2 UDP 2130706430 172.18.0.3 4001 typ host\r\n")
        invite = request("INVITE", "INVITE", "c", body)
        path = self.pcap([
            (5.0, udp(CLIENT, 5060, PBX, 5060, invite)),
            (5.001, udp(PBX, 5060, CLIENT, 5060, response(401, "INVITE", "c"))),
            (5.003, udp(CLIENT, 5060, PBX, 5060, request("INVITE", "INVITE", "c", body))),
            (5.004, udp(PBX, 5060, CLIENT, 5060, response(200, "INVITE", "other"))),
            (5.012, udp(PBX, 5060, CLIENT, 5060, response(200, "INVITE", "c"))),
        ])
        self.assertEqual(run(wire.invite_out, path, CLIENT),
                         {"invite_bytes": str(len(invite)), "candidates": "2", "setup_ms": "12.0"})

    def test_an_invite_larger_than_the_link_is_read_whole_from_its_fragments(self):
        body = b"v=0\r\nm=audio 4000 RTP/AVP 0\r\n" + b"a=x:" + b"y" * 1600 + b"\r\n" + b"".join(
            f"a=candidate:{n} 1 UDP 2130706431 172.18.0.3 400{n} typ host\r\n".encode()
            for n in range(3)
        )
        invite = request("INVITE", "INVITE", "f", body)
        first, second = fragmented(CLIENT, 5060, PBX, 5060, invite)
        path = self.pcap([
            (6.0, first),
            (6.0001, second),
            (6.010, udp(PBX, 5060, CLIENT, 5060, response(200, "INVITE", "f"))),
        ])
        self.assertEqual(run(wire.invite_out, path, CLIENT),
                         {"invite_bytes": str(len(invite)), "candidates": "3", "setup_ms": "10.0"})

    def test_answering_is_the_first_invite_in_to_the_clients_200(self):
        path = self.pcap([
            (7.0, udp(PBX, 5060, CLIENT, 5060, request("INVITE", "INVITE", "a"))),
            (7.0005, udp(CLIENT, 5060, PBX, 5060, response(100, "INVITE", "a"))),
            (7.0021, udp(CLIENT, 5060, PBX, 5060, response(200, "INVITE", "a"))),
        ])
        self.assertEqual(run(wire.invite_in, path, CLIENT), {"answer_ms": "2.1"})

    def test_a_move_is_timed_from_when_the_address_changed(self):
        path = self.pcap([
            (9.0, udp(CLIENT, 4000, PBX, 10000, rtp_packet())),
            (10.2, udp(MOVED, 4000, PBX, 10000, bytes([0x80, 200]) + b"\0" * 26)),
            (10.3, udp(MOVED, 4000, PBX, 10000, rtp_packet())),
            (10.5, udp(MOVED, 5060, PBX, 5060, request("REGISTER", "REGISTER", "r"))),
            (10.9, udp(PBX, 10000, MOVED, 4000, rtp_packet(8))),
        ])
        self.assertEqual(run(wire.move, path, MOVED, PBX, "10.0"), {
            "first_sip_ms": "500.0", "first_sip": "REGISTER",
            "audio_out_ms": "300.0", "audio_back_ms": "900.0",
        })

    def test_what_a_capture_lacks_is_a_dash(self):
        path = self.pcap([(1.0, udp(CLIENT, 5060, PBX, 5060, request("REGISTER", "REGISTER", "r")))])
        self.assertEqual(run(wire.register, path, CLIENT)["register_ms"], "-")
        self.assertEqual(run(wire.move, path, MOVED, PBX, "0")["audio_back_ms"], "-")


class Rating(unittest.TestCase):
    def test_a_clean_link_rates_near_the_g711_ceiling(self):
        self.assertEqual(wire.rating("0", "0", "0"), "r=92.7 mos=4.40")

    def test_loss_and_delay_both_cost(self):
        self.assertEqual(wire.rating("5", "10", "100"), "r=75.3 mos=3.83")
        self.assertEqual(wire.rating("0", "0", "600"), "r=69.8 mos=3.59")


class Views(unittest.TestCase):
    def text(self, content):
        handle = tempfile.NamedTemporaryFile("w", delete=False)
        handle.write(content)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_asterisks_channelstats_are_read_in_seconds(self):
        path = self.text(
            " BridgeId ChannelId ........ UpTime.. Codec.   Count    Lost Pct  Jitter"
            "   Count    Lost Pct  Jitter RTT....\n"
            "          labuser-compare-00 00:00:31 ulaw     1470      30    2   0.012"
            "   1500      18    1   0.004   0.081\n"
        )
        # the jitter under "Receive" is the client's report of Asterisk's
        # audio; Asterisk's own reading of the client's is under "Transmit"
        self.assertEqual(run(wire.channelstats, path, "labuser-compare"), {
            "received": "1470", "loss_pct": "2.00", "jitter_ms": "4.00", "rtt_ms": "81.0",
            "r": "84.5", "mos": "4.18",
        })

    def test_a_round_trip_asterisk_never_measured_is_not_read_as_zero(self):
        path = self.text(
            "          labuser-compare-00 00:00:13 ulaw      664       0    0   0.000"
            "    664       0    0   0.000   0.000\n"
        )
        view = run(wire.channelstats, path, "labuser-compare")
        self.assertEqual((view["rtt_ms"], view["r"]), ("-", "92.7"))

    def test_pjsuas_last_quality_dump_is_the_one_read(self):
        # past a thousand, pjsua counts packets the way it counts bytes,
        # "1.4Kpkt", and the count is kept as printed rather than guessed at
        dump = """
       RX pt=0, last update:00h:00m:01.000s ago
          total {rx}pkt 96.8KB (121.0KB +IP hdr) @avg=63.9Kbps/79.9Kbps
          pkt loss={lost} ({pct}%), discrd=0 (0.0%), dup=0 (0.0%), reord=0 (0.0%)
                (msec)    min     avg     max     last    dev
          loss period:   0.000   0.000   0.000   0.000   0.000
          jitter     :   0.000   {jitter}   0.125   0.000   0.013
       TX pt=0, ptime=20, last update:00h:00m:02.088s ago
          total 605pkt 96.8KB (121.0KB +IP hdr) @avg=63.9Kbps/79.9Kbps
          pkt loss=9 (9.9%), dup=0 (0.0%), reorder=0 (0.0%)
          jitter     :   0.250   9.999   0.375   0.375   0.062
       RTT msec      :   0.411   {rtt}   0.961   0.411   0.275
"""
        path = self.text(
            dump.format(rx=100, lost=50, pct="50.0", jitter="7.000", rtt="1.000")
            + dump.format(rx="1.4K", lost=20, pct="1.3", jitter="11.500", rtt="80.500")
        )
        view = run(wire.pjsua_dq, path)
        self.assertEqual(
            {name: view[name] for name in ("received", "loss_pct", "jitter_ms", "rtt_ms")},
            {"received": "1.4K", "loss_pct": "1.3", "jitter_ms": "11.500", "rtt_ms": "80.500"},
        )

    def test_baresips_last_receive_statistics_and_its_round_trip_are_read(self):
        # as baresip 4.11 prints them with `rtp_stats yes` and rtcpsummary:
        # one block a call, the log of the whole client, the last one read
        block = """EX=BareSip;CS=0;CD=30;PR={rx};PS=1476;PL={lost},49;PD=1,0;JI={jitter},9.5;DL={rtt};
audio           Transmit:     Receive:
packets:           1525         {rx}
avg. bitrate:      64.0         61.6  (kbit/s)
errors:               0           27
pkt.report:        1502         1446
lost:                49           {lost}
jitter:            19.1         {jitter}  (ms)
"""
        path = self.text(block.format(rx=1375, lost=125, jitter="11.2", rtt="74.9")
                         + block.format(rx=1468, lost=55, jitter="33.3", rtt="102.6"))
        view = run(wire.baresip_stats, path)
        self.assertEqual(
            {name: view[name] for name in ("received", "loss_pct", "jitter_ms", "rtt_ms")},
            {"received": "1468", "loss_pct": "3.61", "jitter_ms": "33.3", "rtt_ms": "102.6"},
        )

    def test_linphonecs_rtp_statistics_carry_no_jitter_so_no_rating(self):
        stamp = "2026-10-08 14:31:42:734 ortp-message- "
        path = self.text(
            "2026-10-08 14:31:40:000 mediastreamer-message- rt_prop=0.124329 sec\n"
            "2026-10-08 14:31:41:000 mediastreamer-message- rt_prop=0.101410 sec\n"
            + "".join(stamp + line + "\n" for line in (
                "                     RTP STATISTICS",
                "sent                                       1527 packets",
                "received                                   1476 packets",
                "                                               0 duplicated packets",
                "incoming cumulative lost                     46 packets",
                "incoming received too late                    2 packets",
            ))
        )
        self.assertEqual(run(wire.linphone_stats, path), {
            "received": "1476", "loss_pct": "3.02", "jitter_ms": "-", "rtt_ms": "101.4",
            "r": "-", "mos": "-",
        })

    def test_the_agents_last_ended_line_keeps_its_own_rating_beside(self):
        path = self.text(
            "registered\n"
            "ended CallHandle(0) codec=PCMU sent=10 received=10 lost=0 loss_pct=0.00 late=0 "
            "reordered=0 jitter_ms=0.50 delay_ms=40.0 rtt_ms=- r=93 mos=4.4\n"
            "ended CallHandle(1) codec=PCMU sent=1500 received=1470 lost=30 loss_pct=2.00 "
            "late=1 reordered=2 jitter_ms=12.00 delay_ms=80.0 rtt_ms=81.0 r=80 mos=4.0\n"
        )
        view = run(wire.sipral_ended, path)
        self.assertEqual(view["received"], "1470")
        self.assertEqual(view["r"], "84.2")
        self.assertEqual((view["own_r"], view["own_mos"]), ("80", "4.0"))


if __name__ == "__main__":
    unittest.main()
