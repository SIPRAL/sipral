# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Where this end is reached, and where a server named by a name is.

:func:`lookup` is the default resolver. With no DNS library dependency it
answers A/AAAA via `socket.getaddrinfo` and NAPTR/SRV with "nothing", which
RFC 3263 treats as a domain without them. Pass a real resolver (e.g.
dnspython) as ``Stack(resolver=...)`` for SRV.
"""

from __future__ import annotations

import socket
from typing import Callable

from ._sipral_cffi import ffi, lib
from .errors import check

__all__ = ["ADDRESS_TTL", "Resolver", "advertised_address", "lookup"]

#: ``(name, record_type) -> (answer, records)``; each record is its TTL then
#: its zone-file data, ``"300 192.0.2.40"`` or
#: ``"300 10 60 5060 sip1.example.com"``.
Resolver = Callable[[str, int], "tuple[int, list[str]]"]

#: TTL :func:`lookup` reports, since the platform does not give the zone's.
ADDRESS_TTL = 60

_ADDRESS_BYTES = 128

#: `getaddrinfo` errors meaning "no such address" (an answer, not a failure).
_NO_SUCH_NAME = frozenset(
    getattr(socket, code)
    for code in ("EAI_NONAME", "EAI_NODATA", "EAI_ADDRFAMILY")
    if hasattr(socket, code)
)


def advertised_address(bound: str, peer: str) -> str:
    """The ``host:port`` to advertise for a socket bound at ``bound`` talking
    to ``peer`` (both addresses). A wildcard bind gives the route toward
    ``peer``. Loopback toward a remote peer raises
    ``SIPRAL_STATUS_UNREACHABLE_ADDRESS``; no route,
    ``SIPRAL_STATUS_TRANSPORT_DOWN``."""
    bound_bytes = bound.encode("utf-8")
    peer_bytes = peer.encode("utf-8")
    buffer = ffi.new(f"char[{_ADDRESS_BYTES}]")
    needed = ffi.new("size_t *")
    check(
        lib.sipral_advertised_address(
            bound_bytes, len(bound_bytes), peer_bytes, len(peer_bytes), buffer, _ADDRESS_BYTES, needed
        ),
        "sipral_advertised_address",
    )
    return ffi.string(buffer).decode("utf-8")


def lookup(name: str, record: int) -> tuple[int, list[str]]:
    """A/AAAA from the platform; NAPTR/SRV and unknown names are
    ``SIPRAL_DNS_ANSWER_NOTHING``, resolver errors ``FAILED``."""
    if record == lib.SIPRAL_DNS_RECORD_TYPE_A:
        family = socket.AF_INET
    elif record == lib.SIPRAL_DNS_RECORD_TYPE_AAAA:
        family = socket.AF_INET6
    else:
        return lib.SIPRAL_DNS_ANSWER_NOTHING, []
    try:
        found = socket.getaddrinfo(name, None, family, socket.SOCK_DGRAM)
    except socket.gaierror as error:
        if error.errno in _NO_SUCH_NAME:
            return lib.SIPRAL_DNS_ANSWER_NOTHING, []
        return lib.SIPRAL_DNS_ANSWER_FAILED, []
    addresses = list(dict.fromkeys(str(entry[4][0]).split("%")[0] for entry in found))
    if not addresses:
        return lib.SIPRAL_DNS_ANSWER_NOTHING, []
    return lib.SIPRAL_DNS_ANSWER_RECORDS, [f"{ADDRESS_TTL} {address}" for address in addresses]
