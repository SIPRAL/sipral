<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# RFC 4317 offer/answer examples

Every session description of RFC 4317, *Session Description Protocol (SDP)
Offer/Answer Examples*, one file per description, as Alice and Bob exchange
them.

## Where the bytes come from

RFC 4317 carries no archive; its descriptions exist only as the RFC's text.
Each file is one of them as printed, with the six columns of page
indentation removed, page breaks skipped and every line ended with `\r\n`.
Nothing else was changed: ports, session IDs, versions, host names and the
order of lines are the RFC's. `manifest.toml` records the SHA-256 of the RFC
text the files were taken from and of every file, and
`crates/sipral-core/tests/rfc4317.rs` recomputes the latter.

## Layout

`<section>-offer.dat` and `<section>-answer.dat` are the first exchange of a
section; `-offer-2` and `-answer-2` are the second, when the section has one.
The second offer is not always Alice's: in §2.5, §3.1, §3.2, §4.1, §4.3 and
§5.3 Bob makes it.

| Section | Title | Exchanges |
|---|---|---|
| 2.1 | Audio and Video 1 | 1 |
| 2.2 | Audio and Video 2 | 2 |
| 2.3 | Audio and Video 3 | 1 |
| 2.4 | Two Audio Streams | 1 |
| 2.5 | Audio and Video 4 | 2 |
| 2.6 | Audio Only 1 | 1 |
| 2.7 | Audio and Video 5 | 2 |
| 2.8 | Audio and Video 6 | 1 |
| 3.1 | Hold and Unhold 1 | 2 |
| 3.2 | Hold with Two Streams | 2 |
| 4.1 | Second Audio Stream Added | 2 |
| 4.2 | Audio, then Video Added | 2 |
| 4.3 | Audio and Video, Then Video Deleted | 2 |
| 5.1 | No Media, Then Audio Added | 2 |
| 5.2 | Hold and Unhold 2 | 2 |
| 5.3 | Hold and Unhold 3 | 2 |

For every exchange the test checks that the answer is legal under RFC 3264
§6, that every description a party sends after its first is a legal
modification of that party's previous one under §8, that the stack's own
answer builder, given the same decisions, writes the same streams, and that
the planner settles on the codec and direction the section describes.

## What the examples show about the RFCs and the stack

- §3.2's second answer is not a legal answer: Bob's second offer holds the
  first stream `sendonly`, and Alice "responds with identical SDP to the
  initial offer", which leaves it `sendrecv` where RFC 3264 §6.1 requires
  `recvonly` or `inactive`. The RFC has no erratum for it; the test names it
  and holds the check to finding it.
- §2.3 answers iLBC as payload type 99 where the offer had 97, which RFC
  3264 §6.1 allows. The answer builder writes the offer's number, as that
  section recommends; the planner matches formats by number and finds no
  codec in common, a gap the test pins.
- A stream carrying only `telephone-event` (§2.4 and the added stream of
  §4.1) is a legal stream, but `MediaPlan` holds exactly one codec and named
  events are not one, so `SessionDescription::media_plan` returns `NoCodec`
  for it. The test pins that too.

## Licence

IETF Trust material, reproduced under the IETF Trust Legal Provisions. It does
not carry the project licence and is not part of the shipped product.
