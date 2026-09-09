<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Clean-room rules

Read this before writing code in this repository. It applies to every
contributor and to every AI assistant used on the tree.

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

**2. Do not open the source of a GPL or LGPL implementation while writing the
equivalent code.** Named explicitly: pjproject, sofia-sip, oSIP, eXosip,
Linphone, bcg729, spandsp, libnice, Janus. Knowing the pjsua2 API from having
used it is fine. Reading its internals while writing ours creates the argument
that ours is derived.

If an idea is needed from such a project, write it down in your own words in a
design document, dated, and close the source before implementing.

**3. BSD-licensed code may be read for architecture, and still not copied.**
baresip and libre, reSIProcate. Their licences would allow copying with
attribution. We decline, so the tree carries no third-party notice inside it and
can be relicensed without asking anyone. Structural ideas, such as separating
transaction from dialog, or the sans-I/O boundary, are not copyrightable and are
free to use.

**4. Provenance is demonstrable.** One repository, from commit zero, complete
history, never squashed, never force-pushed on `main`, commits signed. Design
documents dated and committed before the code they describe. If the question is
ever asked, this is the answer.

**5. Test vectors are ours or are public.** Captures from our own lab, the RFC
4475 corpus, the public SIPit bug list. SIPp is a tool we run, not code we ship.

**6. When unsure about the provenance of a pattern, write it differently.** The
cost of a second implementation of a small function is an hour. The cost of the
other outcome is the product.

## For AI assistants

Every model that writes SIP code has read pjproject. Verbatim reproduction is a
real failure mode, not a theoretical one.

Working rules:

- Implement from the RFC text, quoted in the prompt or in the design document.
  Do not fetch, paste or read any GPL or LGPL implementation into context.
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

Files carry the SPDX header and the copyright line. `scripts/check.sh` rejects the ones that do
not, and also fails on references to the forbidden projects appearing in source
files.
