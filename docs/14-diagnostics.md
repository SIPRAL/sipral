<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# 14 — The diagnostic record

`docs/13-client-requirements.md` calls this D1 and says of it: if one thing in
that document gets built, it is this one. This is what got built.

## The problem it replaces

A call failed. Diagnosing it today means asking somebody who does not read logs
for a text log, often megabytes of it, then reading timestamps by eye until the
shape of the failure appears. The expensive part of a support incident is that
reconstruction, not the bug at the end of it.

So the stack writes down what it decided, as it decides it. Every call carries
an ordered **record**; every entry is a **decision** with a machine-readable
**reason**, the message that caused it, how far into the call it happened, and
the sizes and addresses it turned on. The record is readable while the call is
still up, it outlives the call, and it serialises to JSON that goes into a bug
report unchanged.

**This is not a message trace.** A trace says what arrived, and a packet
capture says that better. A record says what was *decided* about it, which
nothing else says at all. The two numbers from the incident B1 describes — a
request of 1785 bytes against the 1300 §18.1.1 allows before a stream is
required — are one entry here and are in no log anywhere. Note that they are
not the physical path: that was a 1500-byte link, and the reason the request
fragmented rather than being refused is that nothing was applying the smaller
number the RFC names. The record carries the number the decision was taken on,
which is the one worth having.

Most of this is not new work. The decisions were already made and already
named; what was missing was that the naming be stable and the memory bounded.

## What a stable reason code means

The reason is the part that leaves the process. It goes into JSON, into a bug
report, into whatever somebody greps six months later, and into the condition
of somebody's alert. Two rules hold for the life of the crate, and breaking
either is a breaking change of the same weight as removing a public function:

- **A wire form never changes.** `transport.promoted.size` means today what it
  meant the day it was written. The Rust variant may be renamed; the string it
  answers with may not.
- **A wire form is never reused for a different meaning.** A decision that is
  retired keeps its string reserved rather than handing it to the next thing
  that looks similar. A reader cannot tell which version produced the record in
  front of them, so the string has to mean one thing across all of them.

The form is a lower-case dotted slug and not a number, and that is the same
rule seen from the other side: a number has to be looked up in a table that
matches the build, and the build is the one thing a bug report never comes
with.

**Adding one** is deliberately cheap, because the layers above `sipral-core`
will each want their own. `Reason` is `#[non_exhaustive]`, so a new variant
does not break a caller that matches on it. Adding one is: a variant, an arm in
`Reason::as_str` whose string is not already in the list, and a row in the
table below. Nothing else moves, and nothing that already exists is touched.

## The vocabulary `sipral-core` emits

Twenty-three codes, every one of them written at the decision site it names.
All but the two `unreadable` ones were written at sites that existed before
this document did; those two came with the answer the endpoint now gives a
message its parser refuses.

| Code | The decision |
|---|---|
| `transport.selected` | The flow a request is about to leave on: which address, which protocol. |
| `transport.promoted.size` | §18.1.1: the request would not fit a datagram, so it went over a stream instead. Carries **size and limit**. |
| `transport.refused.size` | The same rule with nowhere to go. The request was **not emitted**; the caller was asked to open a connection. Carries size and limit. |
| `transport.lost` | A transport closed or failed, and what was running on it was failed with it. |
| `transport.flow.dead` | RFC 5626 §4.4.1: ten seconds with no pong, so the flow was taken down. |
| `request.sent` | A request went on the wire, at the size the caller writes. |
| `request.retransmitted` | A timer fired and the identical bytes went again. |
| `request.refused.overload` | A stranger's request was answered 503 for want of room. |
| `request.refused.dialog` | A peer already inside a dialog was answered 503 for want of room in that one dialog's own, smaller ceiling — distinct from `request.refused.overload`, which a request inside a dialog is never refused with. |
| `request.refused.unreadable` | A request the parser refused — past a `msg::Limits` bound, or not well formed — was answered from the fields that could still be read: 513 past the message bound, 400 naming the fault otherwise. Carries **size and limit** when a bound on bytes refused it. |
| `message.dropped.unreadable` | Bytes the parser refused that no answer could be written to — a response, an ACK, a request with no readable `Via`, `From`, `To`, `Call-ID` or `CSeq`, or a stream whose framing was lost with it. Dropped, and this is the trace. |
| `response.sent` | A response went on the wire. |
| `response.retransmitted` | A timer fired and the same response went again — which means the acknowledgement is not arriving. |
| `transaction.unacknowledged` | §17.2.1, timer H: a final response was repeated for 64·T1 and never acknowledged. Nothing above hears about this; the record is the only place it exists. |
| `request.answered.timeout` | A non-INVITE server transaction's application never answered within 64·T1, so the endpoint answered 408 in its place. §17.2.2 gives that state no timer of its own; nothing above hears about this either. |
| `dialog.fork.dropped` | A 2xx to a forked INVITE found no room under `max_dialogs`, so it was silently neither reported nor acknowledged — the far end gives the call up with a `BYE` of its own. |
| `auth.challenge.received` | A refusal arrived carrying a challenge this stack can answer. |
| `auth.challenge.answered` | The request went again with credentials — the send that is certain to have grown, and the one that fragmented in the field. |
| `dialog.created` | A dialog was created (§12.1). |
| `dialog.destroyed` | A dialog is over and its handle is stale. |
| `failure.refused` | A final response of 300 or above ended a request or a call. |
| `failure.timeout` | Nothing came back within 64·T1. |
| `failure.transport` | The transport could not deliver. |

Two of these carry the numbers B1 asks for, and one of them answers B1's
literal requirement: **the on-wire byte size of every request this endpoint
emits is in the record**, without a capture and without the application having
to instrument its own socket writes.

`sipral-ua` and the facade add their own codes as they are written; the phases
are in `docs/10-roadmap.md`. Registration, subscription and media decisions do
not appear here because `sipral-core` does not make them.

## The vocabulary `sipral-ua` emits

Three codes, all about what a registrar said beside a binding it granted
(`docs/04-ua.md`). Each is written into the REGISTER's record, against the 2xx
that carried the field, when the field could not be read or was larger than the
stack carries; the field is then left out whole, and the binding still stands.
They reach the record through `Endpoint::note_arrival`, which takes a code and
the message it is about and nothing else, so the entry names the response by
status and size and never the value that was refused.

| Code | The decision |
|---|---|
| `registration.service_route.ignored` | RFC 3608: a `Service-Route` with an entry that does not parse, is not a loose route, carries URI headers, holds a byte no SIP URI is written with, or runs past eight hops or 512 bytes a hop. No service route was taken from that response. |
| `registration.gruu.ignored` | RFC 5627 §4.2: a `pub-gruu` or `temp-gruu` on this instance's `Contact` that is not a quoted SIP URI with a `gr` parameter, is written twice, carries URI headers, holds a byte no SIP URI is written with, or runs past 512 bytes. That GRUU was not used. |
| `registration.associated_uri.ignored` | RFC 7315 §4.1: a `P-Associated-URI` entry that is not a name-addr, or more than thirty-two of them. No associated identity was reported from that response. |

## What an entry carries

Only what applies to it. A `Decision` has the reason and the offset always, and
then whichever of these the decision turned on:

- the **wire event** that caused it — a method or a status, a direction, and
  the on-wire byte count;
- a **socket address**, and the **transport protocol** that was going to carry
  it;
- a **size and a limit**, together and never apart. A size on its own says
  nothing, which is exactly how a request that fragmented read as
  "authentication is broken" for two days.

The offset is a `Duration` from the record's own first entry, not an instant.
Nothing in the protocol crates reads a clock (`docs/11-testing.md`), so the
time comes from the caller: every entry point that takes a `now` stamps it, and
every decision made during that call into the endpoint shares it. That is not
an approximation — inside one call into a sans-I/O core, no time passes.

## The memory bound, and what happens at it

Two ceilings, both configurable through `EndpointConfig::diagnostics`:

- **64 decisions per record.** Past that the oldest go.
- **32 records at once.** Past that the least recently written goes — least
  recently *written*, not oldest, so that an hour-long call is not thrown away
  by two registrations that happened to start after it.

A decision is a hundred and twenty bytes and holds no message, so the
whole thing is about a quarter of a megabyte at the defaults. A caller on a
device where that matters turns them down; a media server turns them up.

**What is dropped is counted, and the count is in the JSON.** A record that
quietly forgot its first twenty entries and said nothing would answer "what
happened first?" with a lie, and a diagnostic that can lie is worse than none.
`Record::dropped` counts decisions lost from one record;
`Endpoint::records_dropped` counts whole records evicted.

One record is never evicted: the endpoint's own, which is where anything that
belongs to no call is written — a transport that failed before a call existed,
a keep-alive flow that died, a stranger refused for want of room. That last one
is deliberate rather than incidental. A scanner arrives with a fresh `Call-ID`
every time, and refusals that made records of their own would be exactly the
eviction the scanner was after.

## The JSON

Written by hand: this crate has no dependencies and is not growing one for a
format that fits on a page. Quotation marks, reverse solidi and control
characters are escaped as RFC 8259 §7 requires, and a `Call-ID` byte that is
not valid UTF-8 becomes U+FFFD — a `Call-ID` is a `word` in the grammar and is
ASCII in every message anybody has sent, but the parser is lenient by
configuration and a diagnostic that will not parse is no diagnostic.

`Endpoint::diagnostics_json()` is the whole endpoint as one document;
`Record::to_json()` is one call. Below is the shape of the B1 story, with
numbers of its own: a REGISTER that fitted, a challenge, and the retry with
credentials that did not fit and was therefore never emitted.

```json
{"records_dropped":0,"records":[
  {"call_id":null,"dropped":0,"decisions":[]},
  {"call_id":"f222a20b21927d88e72377031f01efe0","dropped":0,"decisions":[
    {"at_us":0,"reason":"transport.selected","address":"192.0.2.9:5060","protocol":"UDP"},
    {"at_us":0,"reason":"request.sent","direction":"out","method":"REGISTER","bytes":1216,"address":"192.0.2.9:5060","protocol":"UDP"},
    {"at_us":38000,"reason":"auth.challenge.received","direction":"in","status":401,"bytes":416,"address":"192.0.2.9:5060","protocol":"UDP"},
    {"at_us":4112000,"reason":"transport.refused.size","address":"192.0.2.9:5060","protocol":"UDP","size":1478,"limit":1300}]}]}
```

Whitespace added here for the page; the output is one line. The last two
entries are the refusal: 1478 bytes against a limit of 1300, and the 262 bytes
between the first REGISTER and the retry are the credentials. Reading that
takes seconds. In the incident B1 records, inferring the same thing from a log
took two days.

`at_us` is microseconds from the record's first entry. `dropped` and
`records_dropped` are always present, whatever their value. A field that does
not apply is absent rather than null; `call_id` is null on the endpoint's own
record and never elsewhere.

## Reading it

```rust
impl Endpoint {
    pub fn call_record(&self, call: &CallId) -> Option<&Record>;
    pub fn endpoint_record(&self) -> &Record;
    pub fn recorded_calls(&self) -> impl Iterator<Item = &CallId>;
    pub fn records_dropped(&self) -> u64;
    pub fn diagnostics_json(&self) -> String;
}
```

Records are found by `Call-ID`, which is the only name a call has that both
ends, every proxy and every capture agree on. `recorded_calls` hands them back
least recently written first, so the front of it is what the endpoint is about
to forget.

The fields of `Decision` are public, so a binding walks them without going
through JSON. There is no public constructor: a decision this crate did not
make is not a decision.

## What it deliberately does not contain

No message bodies. No headers. No credentials, no nonce, no `Authorization`.
No SDP, no addresses out of a session description, no audio. A record names a
method, a status, a size, a socket address and a `Call-ID`, and that is the
whole list.

The reason is the use it is for. It is meant to be sent by a user who cannot be
asked to read it first, which means it has to be safe to send **without** being
read. Anything that would make somebody check before forwarding it does not
belong in it.

It is also not a replacement for a capture, and does not try to be. D2 in
`docs/13-client-requirements.md` — the recorded session that replays
deterministically — is the artefact that holds messages, and it is a separate
thing with a separate format and its own rules about what it may carry.
