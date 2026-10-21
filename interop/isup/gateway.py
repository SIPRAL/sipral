# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""A carrier gateway's half of SIP-I, for `scripts/lab.sh isup`.

The gateway between SIP and the telephone network carries the ISUP of each
call inside the SIP that carries the call (RFC 3372, ITU-T Q.1912.5), as
RFC 3204's ``application/ISUP``, beside the SDP in ``multipart/mixed``.
This script plays that gateway on one UDP socket, toward the C harness
(``harness-c isup``), which registers with it. Its ISUP is written here,
octet by octet, from ITU-T Q.763's formats -- not with the library's own
writer, so the stack under test reads what someone else wrote.

What it does, in order, once the harness has registered:

1. An INVITE from the network: an anonymous ``From``, the IAM beside the
   offer (``handling=required``): the calling party number +15555550100
   with presentation restricted and screened by the network, an additional
   calling party number, the called number, and a call diverted twice --
   the redirecting number +15555550101 (no reply), the original called
   number +15555550103 (unconditional). It has to be answered 200 with an
   SDP answer, not refused 415. Then a BYE carrying a REL, cause 16 at the
   public network serving the remote user, and no ``Reason``.
2. An INVITE whose ISUP says it is ANSI (``version=ansi00``) and is
   required: it has to be refused 415, with an ``Accept`` that names
   ``application/isup``.
3. The harness's first call out: 180 carrying an ACM alone, 183 with SDP
   beside a CPG (in-band information), 200 with SDP beside an ANM; after
   the ACK, a BYE carrying a REL, cause 31 at a transit network.
4. Its second: 486 carrying a REL, cause 17.

Lines, one each, flushed as they happen, for the step to read:

    gateway listening on <address>
    gateway ok <what>
    gateway FAIL <what>

Exits 0 when every expectation held.
"""

import socket
import sys
import time

PATIENCE_S = 20.0
BOUNDARY = "sipi-lab-boundary"

FAILURES = []


def say(line):
    print(f"gateway {line}", flush=True)


def expect(held, what):
    if held:
        say(f"ok {what}")
    else:
        FAILURES.append(what)
        say(f"FAIL {what}")
    return held


# -- ISUP, from ITU-T Q.763 --------------------------------------------------

# Parameter name codes (Table 5).
CALLED = 0x04
CALLING = 0x0A
REDIRECTING = 0x0B
BACKWARD_CALL = 0x11
CAUSE = 0x12
REDIRECTION_INFORMATION = 0x13
ORIGINAL_CALLED = 0x28
GENERIC_NUMBER = 0xC0

INTERNATIONAL = 0x04
NATIONAL = 0x03


def signals(digits):
    """The address signals (§3.9 e), two to an octet, the first in the low
    half; an odd count ends with the filler 0000 (§3.9 f)."""
    values = [int(digit) for digit in digits]
    out = bytearray()
    for at in range(0, len(values), 2):
        low = values[at]
        high = values[at + 1] if at + 1 < len(values) else 0
        out.append(high << 4 | low)
    return bytes(out)


def number(nature, digits, second):
    """A number parameter's content: O/E and nature, the second octet as
    the parameter has it, the signals."""
    odd = len(digits) % 2
    return bytes([odd << 7 | nature, second]) + signals(digits)


def calling_number(nature, digits, presentation, screening):
    """§3.10: NI 0, ISDN plan (001), presentation, screening."""
    return number(nature, digits, 0x10 | presentation << 2 | screening)


def redirecting_number(nature, digits, presentation):
    """§3.39 and §3.44: ISDN plan, presentation, the rest spare."""
    return number(nature, digits, 0x10 | presentation << 2)


def called_number(nature, digits):
    """§3.9: INN 1 (routing to an internal network number not allowed),
    ISDN plan."""
    return number(nature, digits, 0x80 | 0x10)


def cause(value, location):
    """§3.12, as Q.850 codes it: ext 1, ITU-T standard, the location; ext 1,
    the value."""
    return bytes([0x80 | location, 0x80 | value])


def optional_part(parameters):
    """Each optional parameter as name, length, content, then the end of
    optional parameters octet (§1.7, §1.8)."""
    out = bytearray()
    for name, content in parameters:
        out += bytes([name, len(content)]) + content
    return bytes(out + b"\x00")


def iam(called, parameters):
    """Table 32: nature of connection 0, forward call indicators with ISUP
    used all the way and an ISDN originating access, an ordinary calling
    subscriber, 3.1 kHz audio; the pointer to the called party number, two
    octets on, and to the optional part past it (§2.3)."""
    fixed = bytes([0x01, 0x00, 0x20, 0x01, 0x0A, 0x03])
    return (
        fixed
        + bytes([2, 2 + len(called), len(called)])
        + called
        + optional_part(parameters)
    )


def acm(called_status):
    """Table 21: backward call indicators -- no charge indication, the
    called party's status, an ordinary subscriber; ISUP all the way and an
    ISDN terminating access -- and no optional part."""
    return bytes([0x06, called_status << 2 | 0x10, 0x14, 0x00])


def cpg(event):
    """Table 23: the event information, and no optional part."""
    return bytes([0x2C, event, 0x00])


def anm():
    """Table 22: nothing but the empty optional part."""
    return bytes([0x09, 0x00])


def rel(value, location):
    """Table 33: the pointer to the cause indicators, an empty optional
    part, the cause."""
    content = cause(value, location)
    return bytes([0x0C, 0x02, 0x00, len(content)]) + content


# -- SIP, as little of it as a gateway needs ---------------------------------


class Message:
    def __init__(self, data):
        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.decode("utf-8", "replace").split("\r\n")
        self.start = lines[0]
        self.fields = []
        for line in lines[1:]:
            name, _, value = line.partition(":")
            self.fields.append((name.strip().lower(), value.strip()))
        length = int(self.field("content-length") or "0")
        self.body = rest[:length]

    def field(self, name):
        for found, value in self.fields:
            if found == name:
                return value
        return None

    def all(self, name):
        return [value for found, value in self.fields if found == name]

    @property
    def is_request(self):
        return not self.start.startswith("SIP/2.0 ")

    @property
    def method(self):
        return self.start.split(" ", 1)[0] if self.is_request else None

    @property
    def status(self):
        return None if self.is_request else int(self.start.split(" ")[1])

    @property
    def cseq_method(self):
        return (self.field("cseq") or " ").split()[-1]


def uri_of(value):
    """The URI between the angle brackets of a name-addr."""
    start = value.find("<")
    end = value.find(">", start)
    return value[start + 1 : end] if start >= 0 and end > start else value


def with_tag(value, tag):
    return value if ";tag=" in value else f"{value};tag={tag}"


def multipart(sdp, isup_type, handling, isup):
    body = (
        f"--{BOUNDARY}\r\nContent-Type: application/sdp\r\n"
        f"Content-Disposition: session;handling=required\r\n\r\n"
    ).encode() + sdp
    body += (
        f"\r\n--{BOUNDARY}\r\nContent-Type: {isup_type}\r\n"
        f"Content-Disposition: signal;handling={handling}\r\n\r\n"
    ).encode() + isup
    body += f"\r\n--{BOUNDARY}--\r\n".encode()
    return f"multipart/mixed;boundary={BOUNDARY}", body


ITU = "application/ISUP;version=itu-t92+"


class Gateway:
    def __init__(self, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((host, port))
        self.socket.settimeout(0.05)
        self.address = f"{host}:{port}"
        self.host = host
        self.harness = None
        self.contact = None
        self.sequence = 0
        self.pending = []
        # the harness's calls already taken, so a retransmitted INVITE of one
        # is never mistaken for the next
        self.taken = set()

    def sdp(self, port):
        return (
            f"v=0\r\no=gw 1 1 IN IP4 {self.host}\r\ns=-\r\nc=IN IP4 {self.host}\r\n"
            f"t=0 0\r\nm=audio {port} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n"
            f"a=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n"
        ).encode()

    def next(self, what):
        self.sequence += 1
        return f"{what}{self.sequence}"

    def send(self, text, body=b"", to=None):
        data = text.encode() + body
        self.socket.sendto(data, to or self.harness)

    def receive(self, wanted, patience=PATIENCE_S):
        """The next message `wanted` takes, answering what it does not: a
        retransmitted request is answered again by whoever is waiting for it,
        and any other request gets a 200 so the harness is never left
        waiting on this side."""
        for held in list(self.pending):
            if wanted(held):
                self.pending.remove(held)
                return held
        deadline = time.monotonic() + patience
        while time.monotonic() < deadline:
            try:
                data, source = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            message = Message(data)
            if self.harness is None:
                self.harness = source
            if wanted(message):
                return message
            if message.is_request and message.method not in ("ACK", "INVITE"):
                self.respond(message, 200, "OK")
            elif message.is_request and message.method == "INVITE":
                self.pending.append(message)
        return None

    def respond(self, request, status, reason, extra="", content_type=None, body=b""):
        lines = [f"SIP/2.0 {status} {reason}"]
        for via in request.all("via"):
            lines.append(f"Via: {via}")
        lines.append(f"From: {request.field('from')}")
        to = request.field("to")
        lines.append(f"To: {to if status == 100 else with_tag(to, 'gwtag')}")
        lines.append(f"Call-ID: {request.field('call-id')}")
        lines.append(f"CSeq: {request.field('cseq')}")
        if request.method == "REGISTER" and status == 200:
            contact = request.field("contact") or ""
            # a binding given back (RFC 3261 §10.2.2) is answered with none
            if request.field("expires") != "0" and "expires=0" not in contact:
                lines.append(f"Contact: {contact};expires=300")
        elif status != 100:
            lines.append(f"Contact: <sip:gw@{self.address}>")
        text = "\r\n".join(lines) + "\r\n" + extra
        if content_type:
            text += f"Content-Type: {content_type}\r\n"
        text += f"Content-Length: {len(body)}\r\n\r\n"
        self.send(text, body)

    def request(self, method, target, from_, to, call_id, cseq, branch, extra="", content_type=None, body=b""):
        text = (
            f"{method} {target} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {self.address};branch=z9hG4bK{branch};rport\r\n"
            f"Max-Forwards: 70\r\nFrom: {from_}\r\nTo: {to}\r\nCall-ID: {call_id}\r\n"
            f"CSeq: {cseq} {method}\r\nContact: <sip:gw@{self.address}>\r\n{extra}"
        )
        if content_type:
            text += f"Content-Type: {content_type}\r\n"
        text += f"Content-Length: {len(body)}\r\n\r\n"
        self.send(text, body)

    # -- the steps --

    def registered(self):
        register = self.receive(lambda m: m.method == "REGISTER")
        if not expect(register is not None, "the harness registered"):
            return False
        self.contact = uri_of(register.field("contact"))
        self.respond(register, 200, "OK")
        return True

    def final_to(self, call_id):
        return self.receive(
            lambda m: not m.is_request
            and m.field("call-id") == call_id
            and m.cseq_method == "INVITE"
            and m.status >= 200
        )

    def ack(self, response, branch, target):
        self.request(
            "ACK", target, response.field("from"), response.field("to"),
            response.field("call-id"), 1, branch,
        )

    def network_call(self):
        call_id = f"{self.next('sipi')}@{self.host}"
        from_ = '"Anonymous" <sip:anonymous@anonymous.invalid>;tag=gwfrom1'
        to = "<sip:+15555550102@sipral.invalid>"
        isup = iam(
            called_number(NATIONAL, "5555550102"),
            [
                (CALLING, calling_number(INTERNATIONAL, "15555550100", 1, 3)),
                (GENERIC_NUMBER, b"\x06" + calling_number(INTERNATIONAL, "15555550199", 0, 0)),
                (REDIRECTING, redirecting_number(INTERNATIONAL, "15555550101", 0)),
                (ORIGINAL_CALLED, redirecting_number(INTERNATIONAL, "15555550103", 0)),
                # diverted (011), first unconditional (0011); counter 2, last no reply (0010)
                (REDIRECTION_INFORMATION, bytes([0x33, 0x22])),
            ],
        )
        content_type, body = multipart(self.sdp(40070), ITU, "required", isup)
        branch = self.next("invite")
        self.request(
            "INVITE", self.contact, from_, to, call_id, 1, branch,
            content_type=content_type, body=body,
        )
        final = self.final_to(call_id)
        if not expect(final is not None, "the IAM's INVITE was answered"):
            return False
        expect(final.status == 200, f"the IAM's INVITE got {final.status}, 200 wanted")
        expect(
            (final.field("content-type") or "").startswith("application/sdp") and b"m=audio" in final.body,
            "the 200 carries an SDP answer to the SDP beside the IAM",
        )
        target = uri_of(final.field("contact") or f"<{self.contact}>")
        self.ack(final, self.next("ack"), target)
        if final.status != 200:
            return False
        time.sleep(1.0)
        self.request(
            "BYE", target, final.field("from"), final.field("to"), call_id, 2,
            self.next("bye"), content_type=ITU, body=rel(16, 0x04),
        )
        ended = self.receive(
            lambda m: not m.is_request and m.field("call-id") == call_id and m.cseq_method == "BYE"
        )
        return expect(ended is not None and ended.status == 200, "the BYE carrying a REL was answered 200")

    def ansi_call(self):
        call_id = f"{self.next('ansi')}@{self.host}"
        content_type, body = multipart(
            self.sdp(40072), "application/ISUP;version=ansi00", "required", iam(called_number(NATIONAL, "5555550102"), [])
        )
        branch = self.next("invite")
        self.request(
            "INVITE", self.contact, "<sip:gw@sipral.invalid>;tag=gwfrom2",
            "<sip:+15555550102@sipral.invalid>", call_id, 1, branch,
            content_type=content_type, body=body,
        )
        final = self.final_to(call_id)
        if not expect(final is not None, "the ANSI INVITE was answered"):
            return False
        # the ACK for a non-2xx is the INVITE's own transaction (RFC 3261 §17.1.1.3)
        self.ack(final, branch, self.contact)
        accept = (final.field("accept") or "").lower()
        expect(final.status == 415, f"ANSI ISUP marked required got {final.status}, 415 wanted")
        return expect("application/isup" in accept, f"the 415 lists application/isup in Accept: {accept!r}")

    def placed(self):
        """The next call the harness places that has not been taken."""
        invite = self.receive(lambda m: m.method == "INVITE" and m.field("call-id") not in self.taken)
        if invite is not None:
            self.taken.add(invite.field("call-id"))
        return invite

    def placed_answered(self):
        invite = self.placed()
        if not expect(invite is not None, "the harness placed its first call"):
            return False
        call_id = invite.field("call-id")
        self.respond(invite, 100, "Trying")
        self.respond(invite, 180, "Ringing", content_type=ITU, body=acm(1))
        time.sleep(0.3)
        content_type, body = multipart(self.sdp(40074), ITU, "optional", cpg(3))
        self.respond(invite, 183, "Session Progress", content_type=content_type, body=body)
        time.sleep(0.3)
        content_type, body = multipart(self.sdp(40074), ITU, "optional", anm())
        self.respond(invite, 200, "OK", content_type=content_type, body=body)
        ack = self.receive(lambda m: m.method == "ACK" and m.field("call-id") == call_id)
        if not expect(ack is not None, "the 200 carrying an ANM was acknowledged"):
            return False
        time.sleep(1.0)
        self.request(
            "BYE", uri_of(invite.field("contact")), with_tag(invite.field("to"), "gwtag"),
            invite.field("from"), call_id, 1, self.next("bye"), content_type=ITU, body=rel(31, 0x03),
        )
        ended = self.receive(
            lambda m: not m.is_request and m.field("call-id") == call_id and m.cseq_method == "BYE"
        )
        return expect(ended is not None and ended.status == 200, "the BYE carrying a REL was answered 200")

    def placed_busy(self):
        invite = self.placed()
        if not expect(invite is not None, "the harness placed its second call"):
            return False
        call_id = invite.field("call-id")
        self.respond(invite, 486, "Busy Here", content_type=ITU, body=rel(17, 0x04))
        ack = self.receive(lambda m: m.method == "ACK" and m.field("call-id") == call_id)
        return expect(ack is not None, "the 486 carrying a REL was acknowledged")

    def drain(self, seconds):
        """Answer whatever the harness still sends -- the binding given
        back -- for a moment."""
        self.receive(lambda m: False, patience=seconds)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5070
    gateway = Gateway(host, port)
    say(f"listening on {gateway.address}")
    if gateway.registered():
        gateway.network_call()
        gateway.ansi_call()
        gateway.placed_answered()
        gateway.placed_busy()
        gateway.drain(2.0)
    if FAILURES:
        say(f"FAIL {len(FAILURES)} expectation(s) did not hold")
        return 1
    say("ok every expectation held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
