#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# The lab's digit echo for baresip, which has no dialplan to echo a digit
# with: connected to the baresip-dtmf container's ctrl_tcp, it reads the
# events baresip writes there (netstring-wrapped JSON) and answers every
# CALL_DTMF_START with the same digit, sent by `sndcode`, which baresip
# sends the way the call's account says: an RFC 4733 event for
# baresip-dtmf, a SIP INFO for baresip-dtmfinfo
# (interop/baresip/config-dtmf/accounts). Standard library only; runs until
# scripts/lab.sh stops its container.

import json
import socket
import sys
import time


def netstrings(sock):
    """Each netstring payload baresip writes, as it arrives."""
    buffer = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return
        buffer += chunk
        while True:
            colon = buffer.find(b":")
            if colon < 0:
                break
            length = int(buffer[:colon])
            end = colon + 1 + length
            if len(buffer) < end + 1:
                break
            yield buffer[colon + 1:end]
            buffer = buffer[end + 1:]


def send(sock, command, params):
    payload = json.dumps({"command": command, "params": params, "token": "echo"}).encode()
    sock.sendall(str(len(payload)).encode() + b":" + payload + b",")


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    for _ in range(60):
        try:
            sock = socket.create_connection((host, port))
            break
        except OSError:
            time.sleep(1)
    else:
        print("dtmf_echo: baresip's control port never answered", flush=True)
        return 1
    print("dtmf_echo: connected", flush=True)
    for payload in netstrings(sock):
        message = json.loads(payload)
        if message.get("event") and message.get("type") == "CALL_DTMF_START":
            digit = message.get("param", "")
            print(f"dtmf_echo: heard {digit!r}, sending it back", flush=True)
            send(sock, "sndcode", digit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
