<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# RFC 4475 torture test corpus

The 49 messages of RFC 4475, *Session Initiation Protocol (SIP) Torture Test
Messages*, byte for byte as the RFC ships them.

## Where the bytes come from

RFC 4475 Appendix A contains a base64-encoded, gzip-compressed tar archive of
every message, so that the ones with non-printable or ambiguous bytes survive
the text format of an RFC. The corpus here is that archive, decoded and laid out
by section. Nothing was retyped, re-encoded or normalised: `\r\n` line endings
and every odd byte are as the authors intended.

`manifest.toml` records the SHA-256 of the decoded archive and of every file.
`scripts/check.sh` recomputes the file hashes, so an editor that quietly
normalises line endings fails the build instead of silently turning a
"must reject" case into a "must accept" one.

The archive also contains a 50th file, `test.dat`, which no section of the RFC
refers to. It is a leftover from the authors' own testing (a request line with no
SIP version, a real domain) and is excluded here.

## Layout

| Directory | RFC section | Outcome |
|---|---|---|
| `3.1.1-valid/` | 3.1.1 Parser tests, valid messages (13) | must parse and round trip |
| `3.1.2-invalid/` | 3.1.2 Parser tests, invalid messages (19) | must be rejected without panic or unbounded work |
| `3.2-transaction/` | 3.2 Transaction layer semantics (1) | well formed; behaviour per the RFC section |
| `3.3-application/` | 3.3 Application layer semantics (15) | well formed; behaviour per the RFC section |
| `3.4-backward-compat/` | 3.4 Backward compatibility, RFC 2543 syntax (1) | well formed; behaviour per the RFC section |

Each `[[message]]` entry in the manifest carries the RFC section number and
title, so a failing test can point at the paragraph that defines the expected
behaviour.

The "semantic" groups are not parser tests. A message in `3.3-application/` is
syntactically fine; what the RFC checks is what a user agent *does* with it —
reject an unknown scheme with a specific status, ignore an unknown extension,
and so on. Those expectations belong to the transaction and UA test suites, not
to the parser's.

## Licence

IETF Trust material, reproduced under the IETF Trust Legal Provisions. It does
not carry the project licence and is not part of the shipped product.

## What does not go here

Captures from live traffic. They hold real numbers, real addresses and real
Call-IDs, they live in a separate permanently private repository, and only
anonymised subsets reach this tree after review by hand. `.gitignore` and
`scripts/check.sh` both enforce that.
