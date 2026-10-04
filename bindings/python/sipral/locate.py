# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Where this end is reached, and where a server named by a name is.

:func:`advertised_address` is `sipral_advertised_address`: the address a
peer can reach a socket at. :func:`lookup` is the resolver a
:class:`sipral.stack.Stack` answers `SIPRAL_EVENT_KIND_LOOKUP_WANTED` with
when the application gives it none: this package does not depend on a DNS
library, so it asks the platform (`socket.getaddrinfo`) for A and AAAA
records and answers every NAPTR and SRV query "nothing", which RFC 3263's
procedure takes as a domain that publishes none, going on to the host's own
addresses. An application with a resolver that reads SRV -- dnspython, say
-- passes one to the stack as ``resolver``.
"""

from __future__ import annotations

import socket
from typing import Callable

from ._sipral_cffi import ffi, lib
from .errors import check

__all__ = ["ADDRESS_TTL", "Resolver", "advertised_address", "lookup"]

#: A resolver: given the name and the `sipral_dns_record_type_t` a lookup
#: asks for, the `sipral_dns_answer_t` and, with ``SIPRAL_DNS_ANSWER_RECORDS``,
#: the records -- each its time-to-live in seconds and then its data as a
#: zone file writes it, ``"300 192.0.2.40"`` or ``"300 10 60 5060
#: sip1.example.com"`` (`sipral_account_looked_up`).
Resolver = Callable[[str, int], "tuple[int, list[str]]"]

#: The time-to-live :func:`lookup` gives an address, in seconds: the
#: platform's lookup does not say what the zone's was, and a minute is how
#: soon a moved server is looked up again.
ADDRESS_TTL = 60

_ADDRESS_BYTES = 128

#: What `getaddrinfo` raises for a name with no address of the family asked
#: for, or no such name at all: an answer, where anything else is a failure.
_NO_SUCH_NAME = frozenset(
    getattr(socket, code)
    for code in ("EAI_NONAME", "EAI_NODATA", "EAI_ADDRFAMILY")
    if hasattr(socket, code)
)


def advertised_address(bound: str, peer: str) -> str:
    """`sipral_advertised_address`: the ``host:port`` to advertise for a
    socket bound at ``bound`` whose traffic goes to ``peer``. A wildcard
    bind (``0.0.0.0:5060``) gives the address of the route toward ``peer``;
    a loopback bind toward a peer that is not raises ``SipralError`` with
    ``SIPRAL_STATUS_UNREACHABLE_ADDRESS``, and no route at all
    ``SIPRAL_STATUS_TRANSPORT_DOWN``. Both are addresses, not names."""
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
    """The platform's answer for ``name``: its IPv4 addresses for an A
    query, its IPv6 ones for AAAA, and ``SIPRAL_DNS_ANSWER_NOTHING`` for
    NAPTR and SRV, which the platform's lookup cannot ask for. A name that
    does not exist, or has no address of that family, is nothing; a
    resolver that could not answer is ``SIPRAL_DNS_ANSWER_FAILED``."""
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
