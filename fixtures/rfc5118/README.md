<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# RFC 5118 IPv6 torture test corpus

The twelve messages of RFC 5118, *Session Initiation Protocol (SIP) Torture
Test Messages for Internet Protocol Version 6 (IPv6)*, one file per message,
named as the RFC names them.

## Where the bytes come from

RFC 5118 Appendix A contains a base64-encoded, gzip-compressed tar archive of
every message, as RFC 4475 does. Each file here is the file of the same name
in that archive, decoded and unpacked, with `.dat` added to the name and
nothing else changed. `manifest.toml` records the SHA-256 of the decoded
archive and of every file, and `crates/sipral-core/tests/rfc5118.rs`
recomputes the latter.

The archive is not quite a set of messages as they travel, and the test says
so rather than editing the files:

- every line ends in a bare LF, where RFC 3261 §7 has CRLF;
- `ipv6-bug-abnf-3-colons` and `ipv6-correct-abnf-2-colons` end without the
  empty line that closes a header section;
- two of the three bodies are not the length their `Content-Length` says:
  `ipv6-in-sdp` says 268 and its body is 242 octets, `mult-ip-in-sdp` says
  181 and its body is 180 (`ipv4-mapped-ipv6` agrees, at 236).

The test's `wire` function turns each file into the message it describes —
CRLF line ends, the header section closed, `Content-Length` counted from the
body — before anything reads it, and a test of its own pins each of the
three points above.

## Layout and outcomes

| File | RFC section | Outcome |
|---|---|---|
| `ipv6-good.dat` | 4.1 | accept |
| `ipv6-bad.dat` | 4.2 | reject: the Request-URI carries an IPv6 address without brackets |
| `port-ambiguous.dat` | 4.3 | accept: `[2001:db8::10:5070]` is an address with no port |
| `port-unambiguous.dat` | 4.4 | accept: `[2001:db8::10]:5070` is an address and a port |
| `via-received-param-with-delim.dat` | 4.5 | accept: `received=[2001:db8::9:255]` |
| `via-received-param-no-delim.dat` | 4.5 | accept: `received=2001:db8::9:255` |
| `ipv6-in-sdp.dat` | 4.6 | accept, and the SDP body carries IPv6 addresses |
| `mult-ip-in-header.dat` | 4.7 | accept: IPv6 and IPv4 in the same Via list |
| `mult-ip-in-sdp.dat` | 4.8 | accept: one stream on IPv4 and one on IPv6 |
| `ipv4-mapped-ipv6.dat` | 4.9 | accept: `::ffff:192.0.2.2` in Via, Contact and SDP |
| `ipv6-bug-abnf-3-colons.dat` | 4.10 | accept: `2001:db8:::192.0.2.1`, tolerated |
| `ipv6-correct-abnf-2-colons.dat` | 4.10 | accept |

On 4.5: RFC 3261's grammar gives `received` as `IPv4address / IPv6address`,
which has no brackets, while implementations send both forms. RFC 5118
asks for both to be accepted, and the test holds the stack to that.

On 4.10: RFC 3261's `IPv6address` production admits the three-colon form,
which RFC 4291 does not. RFC 5118 says that "following the Robustness
Principle [RFC1122], an implementation must tolerate both of the above
constructs", and the stack reads `2001:db8:::192.0.2.1` as the address
`2001:db8::192.0.2.1`; the test holds it to that.

## Licence

IETF Trust material, reproduced under the IETF Trust Legal Provisions. It does
not carry the project licence and is not part of the shipped product.
