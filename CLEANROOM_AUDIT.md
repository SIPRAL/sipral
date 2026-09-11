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
for any reason. Most of them are copyleft implementations of the same protocols
and several of their owners sell commercial licences of their own; libsrtp is
permissive and is on the list anyway, because it is an implementation of RFC
3711 rather than an architecture to learn from.

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

The history of this repository is the record: the design document for a
component is committed before the code that implements it, dated, and the
reasoning behind each judgement call is written next to the decision rather than
kept in someone's head. A file that disagrees with its design document is a bug
in one of the two.

`main` has been rewritten twice, both times to change a commit message and
never a commit's content: on 4 September 2026, when the repository held a
single commit and no protocol code, to take a private address out of its
metadata; and on 11 September 2026, one line of one message. Each rewrite is
checkable for what it claims — every tree object came out identical, so no
blob moved and the code history is the same history. It is not squashed and
not rebased, and what is evidence about it has never been altered.

`scripts/check.sh` fails the build when a source file contains pjproject,
pjsip, pjmedia, sofia-sip, osip2, exosip, linphone, bcg729, spandsp, libnice or
janus, in any capitalisation. It matches those strings and nothing cleverer, so
it is a backstop for the rule above and not a substitute for it.

## The one component a specification might not settle alone

G.729 is the codec where this gets tested, because the ITU publishes reference
code in C alongside the Recommendation and the obvious move is to read it. We
do not read it, and the reason is not the one most people would guess.

**The Recommendation grants no software licence.** Its only statement of rights
is a complete reservation: no part of the publication may be reproduced by any
means without the ITU's prior written permission. Its scope clause then says
that the reference C source and the test vectors are provided as an integral
part of that publication. So the reference implementation is not public-domain
material that happens to sit next to a standard. It is the standard, and it is
reserved.

That closes the question rather than complicating it. **The reason anyone wants
the reference code is to settle places where the text is ambiguous, and there is
an official document that exists to do exactly that**: the Implementers' Guide,
G.Imp729, which the ITU keeps in force alongside the Recommendation. The
Recommendation's own revision history shows the kind of thing it carries — the
2012 edition records the correction of a discrepancy found between one of its
equations and the C code. A discrepancy of that sort is precisely what would
otherwise send someone to the implementation, and the Guide answers it in prose.

So the procedure has four lines and no machinery:

1. Implement from the **text of the Recommendation**.
2. Settle ambiguities from the **Implementers' Guide**, not from code.
3. Judge correctness against the **ITU's conformance vectors**.
4. **Never open the reference implementation**, and never bcg729.

There is no two-team compartmentalisation here, no reading log, no isolation
procedure, because none of it has anything to act on. Nobody opens anyone's
implementation, which is the same rule the rest of this repository already
follows.

**The test vectors do not enter this repository.** They are ITU material under
the same reservation, so they are used on a machine and not committed:
reproducing and distributing them here is the thing the reservation forbids.
What is published instead is ours — the conformance results, and the script that
produces them. Anyone can obtain the vectors from the ITU and re-run it.

This is why `fixtures/` holds the RFC 4475 corpus and nothing from the ITU. That
corpus is IETF Trust material, reproduced under the IETF Trust Legal Provisions,
and `fixtures/rfc4475/README.md` says so.

## Reporting a concern

If you believe you recognise code in this repository, please say so privately
rather than in a public issue, and name the file and the lines: use GitHub's
private vulnerability reporting on this repository — the Security tab, then
"Report a vulnerability" — which is the route [`SECURITY.md`](SECURITY.md)
describes and is private between you and the maintainer. It will be examined,
and if the concern is sound the code will be rewritten and the fact recorded
here.
