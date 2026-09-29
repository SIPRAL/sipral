<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# RFC 4317 offer/answer examples

Session descriptions from RFC 4317, *Session Description Protocol (SDP)
Offer/Answer Examples*, one file per description, as Alice (the offerer) and
Bob (the answerer) exchange them.

## Where the bytes come from

These files were written from the examples of RFC 4317, not extracted from a
published archive, and at the time they were written the RFC was not
available to diff against. They follow the scenario each section describes
(which streams are offered, which codecs and directions are kept or refused,
what changes from one exchange to the next). Treat the literal values as
this corpus's own, not as the RFC's: ports, session IDs and versions, and the
choice of codecs within a scenario. Compare them with the published text
before relying on them byte for byte.

Every line ends with `\r\n`, and the RFC's layout indentation is not part of
a description. `manifest.toml` records the SHA-256 of every file, and
`crates/sipral-core/tests/rfc4317.rs` recomputes them.

## Layout

`<section>-offer.dat` and `<section>-answer.dat` are the first exchange of a
section; `-offer-2`, `-answer-2` and so on are the later ones in the same
session.

| Section | Title | Exchanges | What is checked |
|---|---|---|---|
| 2.1 | Audio and Video 1 | 1 | one codec per stream kept: PCMU and MPV |
| 2.2 | Audio and Video 2 | 2 | video refused with port 0; audio then narrowed to PCMU |
| 2.4 | Two Audio Streams | 1 | a second, `sendonly` stream of `telephone-event` answered `recvonly` |
| 3.1 | Hold and Unhold 1 | 3 | `sendonly` hold answered `recvonly`, then back to `sendrecv` |
| 4.1 | Second Audio Stream Added | 2 | a stream appended in a new offer |
| 4.3 | Audio and Video, Then Video Deleted | 2 | a stream deleted by port 0, its `m=` line kept |

For every exchange the test checks that the answer is legal under RFC 3264
§6, that each later offer and answer is a legal modification under §8, that
the stack's own answer builder, given the same decisions, writes the same
streams, and that the planner settles on the codec and direction the section
describes.

## Not here

The other sections of RFC 4317 (among them 2.3, 2.5 onward, 3.2 onward, 4.2
and the third-party call control examples) are not encoded: their literal
content could not be reconstructed with enough confidence without the RFC
text at hand.

## Known gap

A stream carrying only `telephone-event` (§2.4 and the added stream of §4.1)
is a legal stream, but `MediaPlan` holds exactly one codec and named events
are not one, so `SessionDescription::media_plan` returns `NoCodec` for it.
The test pins that behaviour rather than hiding it.

## Licence

IETF Trust material, reproduced under the IETF Trust Legal Provisions. It does
not carry the project licence and is not part of the shipped product.
