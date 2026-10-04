<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# Sipral design documents

These are written before the code, and updated in the same commit as the code
that contradicts them. A design document that disagrees with the tree is a bug
report against one of the two.

They also serve a second purpose. Sipral is written clean-room, and dated design
documents in the repository history are the evidence that its state machines
were derived from the specifications rather than from another implementation.
That is why the history is not squashed and not rewritten. It was rewritten
twice, both times a commit message and never a commit's content: on
4 September 2026, to take a private address out of the metadata of the only
commit there was, and on 11 September 2026, one line of one message. Every
tree object survived both unchanged, so the code history is untouched.

| Document | Covers |
|---|---|
| [01-architecture.md](01-architecture.md) | layering, the sans-I/O boundary, what lives in which crate |
| [02-clean-room.md](02-clean-room.md) | provenance rules, what may not be read, what to do when unsure |
| [03-core-signalling.md](03-core-signalling.md) | parser, transactions, dialogs, SDP, authentication |
| [04-ua.md](04-ua.md) | registration, calls, hold, transfer, subscriptions, locating a server by RFC 3263, an account on a transport of its own |
| [05-media.md](05-media.md) | RTP, jitter buffer, loss concealment, DTMF, SRTP, codecs |
| [06-nat.md](06-nat.md) | STUN, TURN, ICE in the lite and full roles, and what carriers actually need |
| [07-headless.md](07-headless.md) | the PCM socket endpoint for AI voice agents |
| [08-ffi.md](08-ffi.md) | C ABI rules, versioning and the freeze, and the Swift, .NET, Kotlin (Android and a server JVM), Python, Dart and React Native bindings |
| [09-rfc-index.md](09-rfc-index.md) | every specification implemented, and by which crate |
| [10-roadmap.md](10-roadmap.md) | phases and their exit criteria |
| [11-testing.md](11-testing.md) | test corpus, fixtures, the interoperability matrix |
| [12-core-api.md](12-core-api.md) | the public surface of `sipral-core`, signatures only, with walkthroughs and what was rejected |
| [13-client-requirements.md](13-client-requirements.md) | what a production softphone asks of this stack, and in what order |
| [14-diagnostics.md](14-diagnostics.md) | the diagnostic record: reason codes, the memory bound, the JSON a bug report carries; exporting a call as pcapng and redacting it for GDPR |
| [15-mobile.md](15-mobile.md) | a call announced by a push before it arrives, and a registration that freezes and thaws |
| [16-lifecycle.md](16-lifecycle.md) | suspend, resume, a network that changed, and what the stack costs when idle |
| [17-observability.md](17-observability.md) | health counters, capability reporting, and the B2 audit of configuration entry points |
| [18-replay.md](18-replay.md) | the recorded-session format, what it cannot hold, and what a replay reproduces |
| [19-numbers.md](19-numbers.md) | measured size, per-frame cost, call set-up time and memory, and how `scripts/bench.sh` produces each |
| [20-security-model.md](20-security-model.md) | the threat model: what a hostile peer can do, what refuses it, where the keys come from, what is not read yet |
| [21-migrating-from-pjsip.md](21-migrating-from-pjsip.md) | moving a pjsua or pjsua2 application onto Sipral: each concept's equivalent, in C and in Python, and what works differently |
| [22-tls.md](22-tls.md) | TLS per platform: who checks the certificate, what RFC 5922 adds, the default trust anchors, a private CA, pinning one authority or a PBX's own certificate, and the failures an application sees |
| [23-compared-with-pjsip.md](23-compared-with-pjsip.md) | the same scenarios run for Sipral's headless agent and for pjsua against one Asterisk: registration, call set-up, memory, CPU, bad links, a moved address, the INVITE with ICE |

## Conventions

Present tense describes what the code does. Future tense describes what is not
written yet, and every such statement names the phase from `10-roadmap.md` that
delivers it.

Anything that is a judgement call is written down with its reason. Six months
later the reason is the only thing that stops someone undoing the decision by
accident.
