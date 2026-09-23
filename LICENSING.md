<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Licensing in plain words

Sipral is dual-licensed. You pick the arm that fits what you are building.

In the SPDX header of every file, `LicenseRef-Sipral-Commercial` stands for a
signed commercial agreement, described in
[`LICENSE-COMMERCIAL.md`](LICENSE-COMMERCIAL.md). Without one, the AGPL-3.0 is
the licence you have.

## The free arm — AGPL-3.0-only

Use Sipral at no cost under the AGPL-3.0. If you give your application to anyone
else, the whole application, Sipral included, has to reach them under the
AGPL-3.0 with its source (section 13 also lets you combine it with code under the
GPL-3.0). If you modify Sipral and people use it over a network, section 13
applies as well. That covers students, research, hobby projects, and any open
source product that is itself copyleft.

The AGPL adds one obligation over the plain GPL: if you run a modified Sipral as
a **network service**, the people using that service must be able to get your
source. Running a SIP endpoint on your server for someone else to call counts.
See section 13 of `LICENSE`.

## The paid arm — commercial licence

You need a commercial licence if any of the following is true:

- your application is closed source, or under a licence that is not
  AGPL-compatible, and you distribute it to others;
- you ship it through the App Store, Google Play, or any store whose terms
  conflict with the AGPL;
- you run Sipral, modified, as part of a service and do not want to publish
  your source;
- you embed Sipral into a product you resell without releasing that product's
  own source, including your modifications, under the AGPL-3.0. Charging for a
  copy is not the trigger; the AGPL allows that. Withholding the source is.

Terms are in [`LICENSE-COMMERCIAL.md`](LICENSE-COMMERCIAL.md): one price per
company, perpetual for the versions delivered during the maintenance term, no
royalties, no per-seat and no per-channel counting, no NDA required, no
obligation to disclose your source, and an explicit right to distribute through
app stores.

There is **no licence check inside the library**. The commercial arm is a
contract, not a runtime lock.

## Quick table

| What you are building | Arm |
|---|---|
| Open source app under AGPL-3.0 | Free |
| Research, teaching, evaluation, a prototype you do not ship | Free |
| Closed source desktop, mobile or on-premises server product that you distribute | Commercial |
| App Store / Google Play distribution | Commercial |
| Hosted service using a modified Sipral, source not published | Commercial |
| SDK or library you resell with Sipral inside, its own source not under AGPL-3.0 | Commercial, under an OEM agreement |

## Third-party code

Sipral links only permissively licensed dependencies (MIT, BSD, Apache-2.0,
ISC, Zlib). None of them restricts either arm. Their attributions are in
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) and must ship with your
binaries. The dependency allow-list is enforced by `cargo deny`, which
`scripts/check.sh` runs.

### Patents, and one codec in particular

A licence on source and a patent reading on what that source does are different
things, and a permissive licence settles only the first. Nothing in this file,
and nothing in either arm, is a representation that Sipral infringes no patent.

One dependency is worth knowing about before you build on it. Opus is the
subject of a patent pool licensing for Dolby, Fraunhofer and NTT, which names
**IP phones** among the product categories it pursues and publishes a per-unit
rate. The pool states that it does not direct the programme at open source
software distributed independently of a hardware device. Read that for what it
is: a statement of aim, revisable, granting nobody anything. It is not a
licence and it is not cover.

So the two situations are not the same. Sipral shipped as software, on its own,
is outside what the programme says it currently pursues. A handset with Sipral
inside is in a category the pool names by name. That exposure is yours rather
than ours, and it is written here so that it is a decision you make rather than
something you discover later.

Two things follow. [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) sets out
the pool, its licensors, what it claims to cover and where to read the primary
sources, at `opuspool.com`. And if your product cannot carry that exposure,
build without the codec: Opus sits behind a Cargo feature that is on by
default, and `--no-default-features` on `sipral` — or on `sipral-ffi`, if what
you ship is the C library — links no libopus at all and leaves you G.711 and
G.722. What such a build offers is in
[`docs/05-media.md`](docs/05-media.md).

## The name

The licence covers the code, not the name. Read [`TRADEMARK.md`](TRADEMARK.md)
before calling something "Sipral"; it also carries the additional terms under
section 7 of the AGPL-3.0 that come with every file.

## Getting a commercial licence

Through the contact form at <https://sipral.org>. It is private, and it is the route
we prefer: you should not have to announce in public that your product is closed
source in order to ask a question about licensing it.

If you would rather ask in the open, there is a
[commercial licence enquiry](../../issues/new?template=commercial-licence.yml)
issue template. That thread is public, so use it only if you do not mind.

There is deliberately no email address anywhere in this repository. Published
addresses get harvested, and the resulting spam buries the enquiries that
matter. Security reports have their own private route, in
[`SECURITY.md`](SECURITY.md).
