<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial -->
<!-- Copyright (c) 2026 Tiberiu Balasea -->

# The seed corpus

One directory per fuzz target, holding the inputs a run starts from. They are
committed, which the rest of a fuzzing corpus is not, for one reason: a clone
that gets thirteen targets and no corpus gets thirteen targets that begin from
the empty input, and a coverage-guided fuzzer then spends its first hours
rediscovering that a SIP message starts with a method name.

## Where these bytes come from

All of them are this project's. Nothing here is a capture of anybody's
traffic, and nothing came from another codebase.

- **Written by `tools/fuzz-seeds`**, which builds each seed with the library's
  own builders and encoders — `RequestBuilder`, `CompoundBuilder`,
  `PacketBuilder`, `MessageBuilder`, `ChannelData::encode`, `Protector` — or
  writes it out as text in that file, from the RFC. A seed is then handed to
  the same reader its target hands it to before it is written out, so one
  that is not the thing it claims to be fails the generator instead of
  sitting here doing nothing: the framer seeds go through the framer, the
  control-channel seeds through the frame decoder and the JSON, the protected
  runs through an unprotector holding the target's own key.
- **One family is not read that way, and it is `builder`.** Its target does
  not parse its input at all: it cuts it into the five field values a caller
  controls and hands them to `RequestBuilder`. So what the generator checks
  for that seed is the cut — that the five pieces land on whole fields rather
  than halves of two — which is the thing about it that can be wrong.
- **One exception, `corpus/replay/registration-challenged`**, which is a copy
  of `fixtures/replay/registration-challenged.sipralrec`. That file is this
  project's own, under this project's licence, and the generator copies it
  rather than inventing a second recording.

Addresses and names come from the ranges reserved for documentation:
`192.0.2.0/24` (RFC 5737) and `example.com` (RFC 2606). No key material here
is a secret: the SRTP seeds are protected with the same fixed key the
`srtp_unprotect` target unprotects with, which is in the target's source.

```sh
cargo run -p sipral-fuzz-seeds     # write this directory again
```

`tools/fuzz-seeds` owns this directory, README apart: what it does not write,
it removes. A seed dropped from the generator and left on disk would otherwise
stay in the tree for good, because the directory-level check below is happy as
long as every target has a directory and every directory a target.

## What does not belong here

What a run finds. `scripts/fuzz.sh` points libFuzzer at a scratch corpus under
`fuzz/target/`, so a run adds to that and leaves this directory alone; a
corpus that grew with every run would grow without bound and would be the
reason this directory used to be ignored. An input worth keeping — one that
reached something new, or one that crashed a target and has a fix beside it —
is copied in on purpose, with the commit that explains it.

`scripts/check.sh` reads this directory twice over. Its shape: every
subdirectory here has to be a target `fuzz/Cargo.toml` declares, every target
has to have one, and the whole of it has to stay under 200 KB. And its
content: every byte of every seed is read for the four things the rest of the
tree is read for — an address somebody could harvest, a forbidden project's
name, an assistant trace, and Romanian. A seed is a datagram as often as it is
a message, so the scan reads bytes rather than lines; the step in `check.sh`
says which of the four is matched how, and why the Romanian one needs an ASCII
letter on either side of the letter it is looking for.
