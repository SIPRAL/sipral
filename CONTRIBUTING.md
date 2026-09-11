<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Contributing

## Code contributions are closed until 1.0

Sipral is dual-licensed, and the commercial arm only exists because one party
holds every copyright in the tree. A single merged patch without a signed
agreement takes that away and cannot be undone without rewriting the code.
Before 1.0 the cost of getting that wrong is higher than the value of the
patches, so the answer is a flat no rather than a case-by-case one.

After 1.0, code is accepted under a contributor licence agreement. That
agreement is not written yet; it will be published in this file before the first
patch is taken, and a signature is confirmed before a merge.

## What is welcome right now

**Interoperability reports.** The most useful thing anyone can send. A registrar
or a carrier that Sipral gets wrong, with the SIP trace, is worth more than a
patch.

**Anonymised captures.** Strip real numbers, real IPs and real Call-IDs before
you attach anything. If you cannot strip them, describe the exchange instead.

**Bug reports** with the Sipral version, the platform, what you expected and the
trace.

**Documentation corrections**, including where the design docs disagree with the
code.

## Provenance

Sipral is written clean-room from the RFCs. Nothing derived from pjproject,
sofia-sip, oSIP, eXosip, Linphone, bcg729 or any other GPL or LGPL project
enters this tree, in any form, including a snippet pasted from a mailing list
or produced by an AI assistant that memorised one.

If you send a patch after 1.0, you are stating that you wrote it, from the
specification, and that you did not have another implementation's source open
while doing so. Reading BSD-licensed code for architectural ideas is fine, but
copying it is not, even where the licence would allow it: the tree stays free of
third-party notices so it can be relicensed without asking anyone.

The rules are spelled out in [`docs/02-clean-room.md`](docs/02-clean-room.md).

## Conventions

- Code, comments, documentation and commit messages: English.
- Identifiers: English, always.
- Commit subjects: conventional prefix, imperative, lower case after the colon.
  `feat(core): parse Via headers with unknown parameters`
- Every source file carries the SPDX header. `scripts/check.sh` rejects files
  without it.
- `cargo fmt` and `cargo clippy -- -D warnings` pass before a commit exists.
- No commit that does not build.
