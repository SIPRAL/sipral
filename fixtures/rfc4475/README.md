<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# RFC 4475 torture test corpus

Empty at this commit. The corpus is extracted and committed in phase 1,
alongside the parser it tests.

## What goes here

RFC 4475, *Session Initiation Protocol (SIP) Torture Test Messages*, contains
messages designed to break parsers: absurd but valid constructions in section 3.1
that must be handled, and invalid ones in section 3.2 that must be rejected
cleanly. It is IETF Trust material and may be reproduced.

The messages are embedded in the RFC in an escaped form, because several contain
bytes that cannot appear literally in a text document. Extraction is mechanical
but must be exact: a corpus that silently unescapes one byte wrongly turns a
"must reject" case into a "must accept" case, and the test then proves nothing.

Layout, once extracted:

```
valid/<name>.dat      section 3.1, must parse and round trip
invalid/<name>.dat    section 3.2, must be rejected without panic or hang
manifest.toml         one entry per message: section, name, expected outcome
```

Files are byte-exact, `\r\n` line endings preserved, no trailing newline added.
Anything that normalises them makes them useless.

## What does not go here

Captures from live traffic. They hold real numbers, real addresses and real
Call-IDs, they live in a separate permanently private repository, and only
anonymised subsets reach this tree after review by hand. `.gitignore` and
`scripts/check.sh` both enforce that.
