<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# Clean-room rules

Read this before writing code in this repository. It applies to every
contributor and to every line of code, however it was produced.

## Why the rules exist

Sipral is dual-licensed. The commercial arm can only be offered by a party that
holds every copyright in the tree. Copyright protects expression, not ideas: any
algorithm described in an RFC or a paper may be implemented freely. What may not
happen is code, file structure, identifier names or comments being carried over
from a GPL or LGPL project and then presented as ours.

A single reproduced function would not merely be a licence problem. It would
make the commercial licence undeliverable, and the fix would be rewriting
whatever depends on it.

So the rules are stricter than the law requires. The margin is the point.

## The rules

**1. The specification is the source of truth.** Implement from the RFC. The
full list is in [09-rfc-index.md](09-rfc-index.md). IETF documents may be quoted
in tests and documentation.

**2. Do not open the source of another implementation of these protocols while
writing the equivalent code.** Named explicitly: pjproject, sofia-sip, oSIP,
eXosip, Linphone, belle-sip, bcg729, spandsp, libnice, Janus, libsrtp — the same
eleven that [`CLEANROOM_AUDIT.md`](../CLEANROOM_AUDIT.md) records as never
opened. All but the last are GPL or LGPL; libsrtp is permissive and on the list
anyway, because it is an implementation of RFC 3711 rather than an architecture
to learn from, so rule 3 does not reach it. Using such a library as a consumer,
and knowing its public API, is fine. Reading its internals while writing ours
creates the argument that ours is derived.

If an idea is needed from such a project, write it down in your own words in a
design document, dated, and close the source before implementing.

**3. BSD-licensed code may be read for architecture, and still not copied.**
baresip and libre, reSIProcate. Their licences would allow copying with
attribution. We decline, so no third-party source is copied into the tree and
none of it needs relicensing; the notices in THIRD-PARTY-NOTICES.md cover
linked dependencies only. Structural ideas, such as separating transaction from
dialog, or the sans-I/O boundary, are not copyrightable and are free to use.

**4. Provenance is demonstrable.** One repository, from commit zero, complete
history, never squashed. Two commit messages have been rewritten, and no
commit's content ever has: on 4 September 2026, when the repository held a
single commit and no protocol code, to take a private address out of its
metadata; and on 11 September 2026, one line of one message. Both times every
tree and every blob came out byte for byte the same, which is the part that is
evidence. The code history is not touched. Design documents dated and
committed before the code they describe. If the question is ever asked, this is
the answer.

**5. Test vectors are ours or are public.** Captures from our own lab, the RFC
4475 corpus, the public SIPit bug list. SIPp is a tool we run, not code we ship.

One exception, recorded in [`CLEANROOM_AUDIT.md`](../CLEANROOM_AUDIT.md): the
numeric values of G.729's trained tables, which the Recommendation's text does
not print, were extracted by a script from the table files of the ITU software
attachment, without anyone reading those files. No other file of the
attachment, and no C source, was opened.

**6. When unsure about the provenance of a pattern, write it differently.** The
cost of a second implementation of a small function is an hour. The cost of the
other outcome is the product.

## Code that arrives already written

A generator, a template, a snippet from a mailing list and a language model all
produce code with no provenance attached to it. Verbatim reproduction of
someone else's expression is a real failure mode in each case, not a theoretical
one, and it does not announce itself. The rules below are about the code,
whatever produced it.

Working rules:

- Implement from the RFC text, quoted in the design document. Do not open any
  GPL or LGPL implementation while the equivalent code is being written.
- Do not reproduce identifier names, file layouts or comment wording from
  another stack. If a name feels like the obvious one because it was seen
  before, choose another.
- Anything that arrives already written, rather than reasoned out from the
  specification, is suspect. Say so instead of committing it.
- Constants defined by the RFC are facts, not expression: `T1 = 500 ms`, timer
  names A through K, header field names, status codes. Use them.

## Review

Any pull request that adds a state machine, a parser or a codec gets a
provenance pass before a correctness pass: where did this come from, and is
there an RFC section number to hang it on.

Files carry the SPDX header and the copyright line. `scripts/check.sh` rejects
the ones that do not, and fails when a source file names one of the projects it
screens for, in any capitalisation. The list it matches is in
[`CLEANROOM_AUDIT.md`](../CLEANROOM_AUDIT.md); it is a backstop for rule 2, not
a substitute for it.

## The record

This document is the rule. [`CLEANROOM_AUDIT.md`](../CLEANROOM_AUDIT.md) at the
root is the record of how it was kept: what each component was written from,
which permissively licensed projects were read for architecture and when, and
the four-line procedure that applies to the one component where a specification
alone may not settle every detail, and why it needs no machinery. Someone
deciding whether to buy a licence reads that file; this one tells them what it
is a record of.
