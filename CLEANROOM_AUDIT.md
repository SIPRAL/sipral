<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Clean-room audit

Sipral is offered under AGPL-3.0-only or under a commercial licence. That second
arm exists only if one party holds every right in the code, which in turn means
no part of it may be derived from anyone else's implementation. The rules are in
[`docs/02-clean-room.md`](docs/02-clean-room.md); this file is the record of how
they were kept, component by component, so that the question can be answered
with a document rather than with a reassurance.

It is written for someone deciding whether to depend on this library, or to buy
a licence for it, and who needs to know where the code came from.

## The rule

Protocol code is written from the specification: the RFC text, or the ITU
Recommendation, read from the document rather than recalled. No source of
pjproject, sofia-sip, oSIP, eXosip, Linphone, belle-sip, bcg729, spandsp,
libnice, Janus or libsrtp is opened by anyone working on this tree, at any time,
for any reason. Those are copyleft implementations of the same protocols, and
several of their owners sell commercial licences of their own.

Permissively licensed projects may be read for architecture and never copied.
Where that happened it is recorded below.

When a pattern feels familiar and its origin is not certain, it is written a
different way and the fact is written down. An hour spent on a second
implementation is cheaper than the alternative.

## The record

| Component | Written from | Implementation consulted |
|---|---|---|
| SIP messages, transactions, dialogs, SDP, authentication | RFC 3261 and the RFCs in [`docs/09-rfc-index.md`](docs/09-rfc-index.md), read as text | none |
| Registration, calls, hold, transfer, subscriptions, lifecycle | the same | none |
| RTP, RTCP, jitter buffer, loss concealment, DTMF | RFC 3550, 3551, 4733 | none |
| SRTP and its SDES keying | RFC 3711, 4568, with errata 3712 and 6808 | none |
| STUN, TURN, ICE-lite | RFC 8489, 8656, 8445 | none |
| G.711 A-law and µ-law | ITU-T G.711, and the companding law itself | none |
| G.722 | the text of ITU-T G.722, with its tables read from the printed Recommendation and two of its own printing errors corrected against the closed form | none |
| Opus | not implemented here; libopus is linked, see [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) | not applicable |
| Device I/O for macOS, iOS and Windows | the platform's own published headers and documentation | none |
| The C ABI and the bindings printed from it | written for this project; no other stack's ABI was examined | none |

Three permissively licensed projects were read for architecture, in September
2026, before the corresponding code was written, and nothing was copied from
them: **str0m** (MIT/Apache-2.0) for the shape of a sans-I/O design, **baresip
and libre** (BSD-3-Clause) for how a SIP stack divides into modules, and
**reSIProcate** (Vovida, a BSD-style licence) for the same. Their third-party
directories were not opened.

## The evidence

The history of this repository has never been rewritten and never will be. It is
the record: the design document for a component is committed before the code
that implements it, dated, and the reasoning behind each judgement call is
written next to the decision rather than kept in someone's head. A file that
disagrees with its design document is a bug in one of the two.

`scripts/check.sh` fails the build on any reference to a forbidden project
appearing in source files, in any capitalisation. It is a backstop for the rule
above, not a substitute for it.

## The exception, and how it is contained

One component is planned that a specification alone may not fully settle: the
G.729 codec, where an implementation is published by the ITU alongside the
Recommendation. The procedure below applies to it, and to anything else in the
same position. It has not yet been used, because the component is not yet
written; when it is, this file records the outcome.

1. The component is written from the **text of the Recommendation** first, and
   its correctness is judged against the **conformance vectors the ITU
   publishes**, never against what the reference implementation happens to
   output. That distinction carries most of the weight here: a codec specified
   to the bit converges structurally in every conforming implementation,
   and where the standard dictates the result, the resemblance is evidence of
   the standard rather than of copying. Validating against the vectors is what
   makes that provable rather than merely arguable.
2. The reference implementation is consulted only for passages where the text
   is genuinely ambiguous, those passages are named in advance, and the list of
   them is kept short enough to be read. "Consulted where necessary" is not a
   record; a numbered list of ambiguities is.
3. Whoever reads the reference implementation **writes no production code for
   that component, then or later**. They produce a functional specification in
   prose and mathematics, carrying no identifier, no file layout, no comment and
   no fragment of the original.
4. That specification is checked by a third party who has not seen the reference,
   looking for expression that survived, and is returned for rewriting if any is
   found.
5. Whoever implements the component receives only the checked specification and
   the Recommendation, and **never sees the reference implementation**.
6. Whoever integrates the result does not open the reference implementation
   either.
7. The reference implementation is read on storage that does not persist, and is
   never placed in this repository or in any working copy of it.
8. When the component is finished, whoever already has access to the reference
   runs a **mechanical similarity scan** of the result against it. Discipline
   catches what someone notices; a scan catches what nobody did. Anything
   literal above the threshold is rewritten. The narrow places worth looking
   hardest at are the ones a standard does not dictate: identifier names,
   comments, the order of operations where the order is free, and constants
   that appear in no table of the Recommendation.

The three sources are not in the same position and are not treated as though
they were. The **text of the Recommendation** is the primary and legitimate
source, and naming it is what explains why any two conforming implementations
resemble each other at all. The **ITU's reference code** is published by the
standards body and licensed for implementing the Recommendation, so consulting
it within the procedure above is a licensed use of public material rather than
something to be quiet about. **bcg729 remains outside all of it**: it is not
consulted under any procedure, by anyone, at any stage, and that is the
statement in this file that carries the most weight, because it is the one
implementation whose owner both sells the same thing and could be harmed by us.

## What this file does not contain

The detailed log of the procedure above — which document was read, by whom, on
what date, and which component resulted — is kept privately rather than
published. Publishing a method is a statement about how the work is done;
publishing a reading log is a different thing, of use mainly to someone building
a case. The log exists, it is contemporaneous, and it is available to a
counterparty performing due diligence under the confidentiality such a review
carries.

## Reporting a concern

If you believe you recognise code in this repository, please say so through the
security contact in [`SECURITY.md`](SECURITY.md) rather than in a public issue,
and name the file and the lines. It will be examined, and if the concern is
sound the code will be rewritten and the fact recorded here.
