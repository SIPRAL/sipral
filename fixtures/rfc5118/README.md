<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# RFC 5118 IPv6 torture test corpus

The twelve messages of RFC 5118, *Session Initiation Protocol (SIP) Torture
Test Messages for Internet Protocol Version 6 (IPv6)*, one file per message,
named as the RFC names them.

## Where the bytes come from

Unlike the RFC 4475 corpus next door, these files were not extracted from an
archive. They were written from the message text of RFC 5118 §4, one header
per line, each line ended with `\r\n`, a blank line after the headers, and no
leading indentation (the RFC indents every message by three spaces for
layout, which is not part of the message).

Two things follow from that, and anyone updating the corpus needs both:

- Each file was typed from the RFC text rather than decoded, and at the time
  it was written the RFC was not available to diff against byte for byte.
  Compare every file with the published text before relying on anything
  beyond the property each test checks.
- `Content-Length` in the three messages with a body (4.6, 4.8, 4.9) is the
  length of the body as it is in the file, counted after the body's lines
  were given `\r\n` endings. It is not copied from the RFC, so the file is
  self-consistent whether or not the printed figure is.

`manifest.toml` records the SHA-256 of every file, and
`crates/sipral-core/tests/rfc5118.rs` recomputes them, so an editor that
normalises line endings fails the build.

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
| `ipv6-bug-abnf-3-colons.dat` | 4.10 | reject: `2001:db8:::192.0.2.1` is not an IPv6 address |
| `ipv6-correct-abnf-2-colons.dat` | 4.10 | accept |

On 4.5: RFC 3261's grammar gives `received` as `IPv4address / IPv6address`,
which has no brackets, while implementations send both forms. RFC 5118
asks for both to be accepted, and the test holds the stack to that.

On 4.10: RFC 3261's `IPv6address` production admits the three-colon form,
which RFC 4291 (and RFC 3986 §3.2.2) do not. The stack follows RFC 4291, and
the test holds it to rejecting the message.

## Licence

IETF Trust material, reproduced under the IETF Trust Legal Provisions. It does
not carry the project licence and is not part of the shipped product.
