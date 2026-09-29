# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""The far end `scripts/lab.sh robust` points the C harness at.

It says nothing, ever: it takes UDP datagrams and TCP connections on one
port, and prints one line for each thing that reached it, so the step can
tell afterwards what arrived and in what shape. A server that accepts a
connection and never answers is the black hole a Timer B has to end a call
on; a peer that only listens is enough for "did the INVITE get here whole".

Lines, one each, flushed as they happen:

    udp <bytes> <first line>
    tcp <bytes> <first line> complete|partial

A TCP message is framed on its `Content-Length` (RFC 3261 section 18.3):
`complete` when the head and as many body bytes as it declares arrived,
`partial` when the connection closed or the run ended first.
"""

from __future__ import annotations

import selectors
import socket
import sys


def first_line(data: bytes) -> str:
    return data.split(b"\r\n", 1)[0].decode("utf-8", "replace")[:80]


def declared_length(head: bytes) -> int:
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() in (b"content-length", b"l"):
            try:
                return int(value.strip())
            except ValueError:
                return 0
    return 0


def frame(pending: bytearray) -> list[bytes]:
    """Every whole message at the front of `pending`, taken off it."""
    out = []
    while True:
        while pending[:2] == b"\r\n":
            del pending[:2]
        end = pending.find(b"\r\n\r\n")
        if end < 0:
            return out
        whole = end + 4 + declared_length(bytes(pending[: end + 4]))
        if len(pending) < whole:
            return out
        out.append(bytes(pending[:whole]))
        del pending[:whole]


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5060
    selector = selectors.DefaultSelector()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", port))
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("0.0.0.0", port))
    tcp.listen(16)
    selector.register(udp, selectors.EVENT_READ, "udp")
    selector.register(tcp, selectors.EVENT_READ, "accept")
    pending: dict[socket.socket, bytearray] = {}
    print(f"listening on {port}", flush=True)
    while True:
        for key, _ in selector.select():
            if key.data == "udp":
                data, _ = udp.recvfrom(65535)
                print(f"udp {len(data)} {first_line(data)}", flush=True)
            elif key.data == "accept":
                connection, peer = tcp.accept()
                pending[connection] = bytearray()
                selector.register(connection, selectors.EVENT_READ, "stream")
                print(f"accepted {peer[0]}:{peer[1]}", flush=True)
            else:
                connection = key.fileobj
                data = connection.recv(65535)
                held = pending[connection]
                if data:
                    held.extend(data)
                    for message in frame(held):
                        print(f"tcp {len(message)} {first_line(message)} complete", flush=True)
                    continue
                if held.strip(b"\r\n"):
                    print(f"tcp {len(held)} {first_line(bytes(held))} partial", flush=True)
                selector.unregister(connection)
                del pending[connection]
                connection.close()


if __name__ == "__main__":
    main()
