<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Third-party notices

Ship [`THIRD-PARTY-LICENSES.txt`](THIRD-PARTY-LICENSES.txt), or an equivalent
notice screen, with any binary that contains Sipral. Both licence arms
require it, because the components below require it themselves: that file
carries every one of their own licence texts, generated from the dependency
graph by `tools/license-gen` and kept current by `scripts/check.sh`. This
file is the plain-language explanation beside it, and the place where a
question a licence text does not answer -- a component's patent position, in
particular -- is written down.

The protocol core is written from the RFCs and depends on nothing. Components
are added only as the phases in `docs/10-roadmap.md` reach them, and each
addition lands here in the same commit that adds it to a `Cargo.toml`.

## Components linked into Sipral

### Opus

`sipral-media` links libopus. It is the only codec in that crate that is not
written in-tree, for the reason `docs/05-media.md` gives: a competitive Opus
implementation is years of signal-processing work, and the reference one is
permissively licensed. Three components, one chain, each licence read from the
component's own file:

| Component | What it is | Licence |
|---|---|---|
| `opus` 0.4.0 | safe Rust bindings, the only thing `sipral-media` names | MIT OR Apache-2.0 |
| `opusic-sys` 0.7.5 | the raw declarations, and the build that produces the library | BSD-3-Clause |
| libopus 1.6.1 | the codec itself, vendored inside `opusic-sys` | BSD-3-Clause |

The `opus` crate declares its licence in the deprecated `MIT/Apache-2.0` form,
which is the dual licence and is read as such; its own `LICENSE-MIT` and
`LICENSE-APACHE` files are both present.

libopus's `COPYING` is a **single BSD-3-Clause block**, not one licence per
contributor. Its copyright line reads:

> Copyright 2001-2023 Xiph.Org, Skype Limited, Octasic, Jean-Marc Valin,
> Timothy B. Terriberry, CSIRO, Gregory Maxwell, Mark Borgerding,
> Erik de Castro Lopo, Mozilla, Amazon

So one reproduction of that notice and the three BSD conditions discharges the
obligation for all of them at once. `opusic-sys` ships the same block as its
own `LICENSE`. A binary containing Sipral must reproduce it, which is what the
"or an equivalent notice screen" at the top of this file means.

`opusic-sys` builds the vendored source with CMake; a build host needs `cmake`
on its path. Its `build-bindgen` feature is deliberately left off — the
bindings ship pre-generated, and enabling it would pull `bindgen` and a
libclang dependency into every build for nothing.

#### Patent position

This is the question a commercial licensee's lawyer asks, so it is written
down rather than assumed.

libopus's `COPYING` points at three IPR disclosures on the IETF datatracker:
Xiph.Org (1524), Broadcom (1526) and Microsoft (1914). The Xiph.Org and
Broadcom grants are word for word the same: a perpetual, worldwide,
non-exclusive, no-charge, royalty-free, irrevocable licence to make, have made,
use, offer to sell, sell, import, transfer, run, modify and reproduce any
implementation that complies with the specification. Both terminate
retroactively if the licensee files a patent infringement claim against an
implementation — defensive termination, and the reason the grants are safe to
rely on. Microsoft's grant, which came with its purchase of Skype, is worded
differently and split between the decoder specification and the reference
implementation, but is likewise perpetual, worldwide, no-charge, royalty-free
and irrevocable, and terminates on litigation or on an attempt to license the
same claims on a royalty-bearing basis.

Four companies that did not take part in developing Opus — Qualcomm, Huawei,
France Telecom and Ericsson — filed IPR disclosures with potentially
royalty-bearing terms. The only statement worth recording about those is the
one that is attributable: the licence page at `opus-codec.org/license` states
that external counsel Dergosits & Noah advised the Opus authors that Opus can
be implemented without needing to license the patents disclosed by those four.
That is advice given to them, not to this project, and it is recorded here as
what it is. IETF rules require a disclosure to name actual patent numbers, so a
licensee who needs more than that can have their own counsel read them.

Since 2025 that picture is no longer complete, and a licensee should know it
before shipping. **Dolby, Fraunhofer-Gesellschaft and NTT are asserting patents
against Opus implementations**, through a licensing vehicle trading as Vectis at
`opuspool.com`, reading on RFC 6716, 8251 and 8486 and on the reference
software. The pool names the official libopus releases up to 1.3.1; the one
linked here is 1.6.1, which implements the same RFCs, so a later version number
is not a way out of the pool's claims. The pool publishes its patent list: as it stood on
1 June 2026 it ran to several hundred entries across more than forty
jurisdictions, Romania among them. The published rate is **0.15 € per unit**.
The actions on record are Dolby against Acer, filed at the Unified Patent
Court's local division in The Hague on 10 December 2025 and pending; Dolby
against Arçelik, pending; and settlements with Optoma and with Epson, the
latter in September 2025.

The programme names **manufacturers of devices** as its targets — handsets,
tablets, computers, televisions, smart speakers, consoles, and **IP telephones
by name**. It also says it does not aim at open source software distributed
independently of hardware.

That last sentence is worth reading carefully, because it is easy to mistake
for something it is not. **It describes who the programme chooses to approach.
It is not a licence, and it grants nobody anything.** A statement of aim can be
revised, and it binds no one; a patent licence is an instrument, and this is
not one. Treat it as useful context and not as cover.

So the two arms of this project are not in the same position, and neither is
safe by virtue of a policy. A library distributed on its own is outside what
the programme says it currently pursues. **A licensee who puts Sipral into an
IP telephone is inside a category it names**, at a rate that turns into real
money on any volume: a hundred thousand handsets is fifteen thousand euro. That is their exposure rather than ours, and it is written here so that
it is a decision they make rather than a thing they discover. Nothing in this
file, and nothing in either licence, is a representation that Sipral infringes
no patent; see `LICENSE-COMMERCIAL.md`.

Opus is therefore built behind a feature rather than linked unconditionally, so
that a product which cannot take that exposure can ship G.711 and G.722 and
link nothing. The feature is on by default, because for everyone else Opus is
the codec worth having. The packaged artefacts `scripts/package/` builds are
the exception: they leave it out unless built with `--with-opus`, and the
variant that carries libopus says so in its name (`docs/05-media.md`).

### AES

`sipral-rtp` links the `aes` crate, and nothing else of SRTP is borrowed:
SHA-1, HMAC, counter mode, f8, the key derivation, the packet index and the
replay list are written in-tree from RFC 3711, RFC 3174 and RFC 2104, and
proved against those documents' own test vectors.

The block cipher is the exception because a table-driven AES leaks its key
through the CPU cache, and the headless mode is meant to run on machines
shared with strangers. This crate reaches for the AES-NI and ARMv8 crypto
instructions and falls back to a bitsliced implementation, so it is
constant-time on every target Sipral ships to. Writing that by hand would be
slower and worse.

RFC 7714's `AEAD_AES_128_GCM` and `AEAD_AES_256_GCM` are the same kind of
exception, for the same reason: `sipral-rtp` links `aes-gcm` 0.11.1 rather
than writing GCM's own carry-less multiplication by hand. It is the exact
version "The primitives under DTLS" below already vets and lists in full —
`sipral-dtls` links it first, for its own record protection — so `sipral-rtp`
reaches for an already-audited dependency rather than a second copy of one.
Everything RFC 7714-specific — the IV formation, the associated data, the
SRTCP E bit and index placement, and the RFC 6188 key derivation the two GCM
suites and the two wider `AES_CM` ones share — is written in-tree from the
RFC and proved against its own §16–§17 test vectors.

| Component | What it is | Licence |
|---|---|---|
| `aes` 0.9.3 | the block cipher | MIT OR Apache-2.0 |
| `cipher` 0.5.2 | the traits `aes` implements | MIT OR Apache-2.0 |
| `crypto-common` 0.2.2 | shared key and block types | MIT OR Apache-2.0 |
| `hybrid-array` 0.4.15 | const-generic arrays behind those types | MIT OR Apache-2.0 |
| `typenum` 1.20.1 | type-level integers `hybrid-array` uses | MIT OR Apache-2.0 |
| `inout` 0.2.2 | in-place buffer views | MIT OR Apache-2.0 |
| `cpufeatures` 0.3.1 | runtime detection of the AES instructions | MIT OR Apache-2.0 |
| `cpubits` 0.1.1 | the bit twiddling that detection needs | MIT OR Apache-2.0 |
| `libc` 0.2.189 | how `cpufeatures` asks the operating system | MIT OR Apache-2.0 |
| `zeroize` 1.9.0 | wiping keys on drop | Apache-2.0 OR MIT |

All ten are permissive and dual-licensed the same way, so one MIT notice
covers the set. `zeroize` is named directly as well as through `aes`: keys
have to be wiped where they are held, and the write that survives the
optimiser needs `unsafe`, which `sipral-rtp` denies. `sipral` itself names the
same version directly too, for the SRTP master key and salt `draw_key` hands
out in `crates/sipral/src/engine.rs`, for the same reason: this crate also
denies `unsafe`.

#### Build-time only

`cmake` 0.1.58, `cc` 1.4.5, `shlex` 2.0.1 and `find-msvc-tools` 0.1.12 arrive
through `opusic-sys`. All four are MIT OR Apache-2.0, all four run during the
build, and none of them is linked into anything that ships.

### The primitives under DTLS

`sipral-dtls` is DTLS 1.2 for DTLS-SRTP, and everything in it that is protocol
— the record layer, the handshake framing and messages, the PRF and the
exporter, the certificate writer and reader — is written in-tree from the
RFCs. The primitives are not: P-256 for ECDHE and ECDSA, AES-GCM, SHA-256,
HMAC, and the check of a peer's RSA signature come from the same RustCrypto
family that supplies `aes`, because a constant-time elliptic curve is the one
place an implementation of our own would be a risk rather than a virtue, and
big-integer arithmetic is the one next to it. SHA-1, used only to read an old
certificate fingerprint, is written in-tree like the other two copies.

The facade depends on `sipral-dtls` behind the `dtls` feature, which is on by
default, so these crates are in a binary built from it unless that feature is
turned off. A build with `--no-default-features` has none of them:
`cargo tree` is where that is checked, and `scripts/check.sh` checks it there
on every run.

The crate names five of them — `p256`, `aes-gcm`, `sha2`, `hmac`, `rsa` — and
`zeroize`; the rest arrive through those. `rsa` is a release candidate, pinned
exactly: its last stable release belongs to the previous generation of these
crates and would bring a second SHA-2 in with it. It is used to verify and
nothing else, which is why `deny.toml` sets aside the advisory about its
private-key operations (RUSTSEC-2023-0071): no RSA private key is ever held. Every licence below was read from
the component's own manifest, and every component ships its licence files
beside it.

| Component | What it is | Licence |
|---|---|---|
| `p256` 0.14.0 | the NIST P-256 curve: ECDH and ECDSA | Apache-2.0 OR MIT |
| `ecdsa` 0.17.0 | ECDSA, with the deterministic nonces of RFC 6979 | Apache-2.0 OR MIT |
| `rfc6979` 0.6.0 | those nonces | Apache-2.0 OR MIT |
| `elliptic-curve` 0.14.1 | keys, points and ECDH over any curve | Apache-2.0 OR MIT |
| `primeorder` 0.14.0 | complete point formulas for prime-order curves | Apache-2.0 OR MIT |
| `primefield` 0.14.0 | arithmetic in the curve's prime fields | Apache-2.0 OR MIT |
| `wnaf` 0.14.1 | windowed scalar multiplication | Apache-2.0 OR MIT |
| `ff` 0.14.0 | finite field traits | MIT OR Apache-2.0 |
| `group` 0.14.0 | elliptic curve group traits | MIT OR Apache-2.0 |
| `crypto-bigint` 0.7.5 | constant-time big integers | Apache-2.0 OR MIT |
| `num-traits` 0.2.19 | numeric traits `crypto-bigint` uses | MIT OR Apache-2.0 |
| `sec1` 0.8.1 | SEC1 point encoding | Apache-2.0 OR MIT |
| `der` 0.8.2 | the DER types `sec1` and `ecdsa` use | Apache-2.0 OR MIT |
| `base16ct` 1.0.0 | constant-time hexadecimal `sec1` uses | Apache-2.0 OR MIT |
| `hkdf` 0.13.0 | HKDF, arriving with the curve crates' ECDH; unused here | MIT OR Apache-2.0 |
| `signature` 3.0.0 | the signing and verifying traits | Apache-2.0 OR MIT |
| `aes-gcm` 0.11.1 | AES-GCM record protection | Apache-2.0 OR MIT |
| `aead` 0.6.1 | AEAD traits | MIT OR Apache-2.0 |
| `ctr` 0.10.1 | counter mode | MIT OR Apache-2.0 |
| `ghash` 0.6.0 | GHASH, GCM's authenticator | Apache-2.0 OR MIT |
| `polyval` 0.7.3 | POLYVAL, which `ghash` is built on | Apache-2.0 OR MIT |
| `universal-hash` 0.6.1 | universal hash traits | MIT OR Apache-2.0 |
| `sha2` 0.11.0 | SHA-256 | MIT OR Apache-2.0 |
| `hmac` 0.13.0 | HMAC | MIT OR Apache-2.0 |
| `digest` 0.11.3 | hash function traits | MIT OR Apache-2.0 |
| `block-buffer` 0.12.1 | the block buffering of the hashes | MIT OR Apache-2.0 |
| `const-oid` 0.10.2 | object identifiers the hash traits carry | Apache-2.0 OR MIT |
| `cfg-if` 1.0.4 | compile-time selection inside `sha2` | MIT OR Apache-2.0 |
| `ctutils` 0.4.2 | constant-time comparison and selection | Apache-2.0 OR MIT |
| `cmov` 0.5.4 | constant-time conditional moves `ctutils` uses | Apache-2.0 OR MIT |
| `rsa` 0.10.0-rc.18 | RSA public keys and RSASSA-PKCS1-v1_5 verification; its signing and decryption are never called | MIT OR Apache-2.0 |
| `crypto-primes` 0.7.2 | prime generation, arriving with `rsa`; unused here, since no key is generated | Apache-2.0 OR MIT |
| `rand_core` 0.10.1 | randomness traits the curve crates name; no generator is linked | MIT OR Apache-2.0 |
| `subtle` 2.6.1 | constant-time comparison and selection | BSD-3-Clause |

`ff` and `group` write their licence in the deprecated `MIT/Apache-2.0` form,
which is the dual licence and is read as such. `aes`, `cipher`,
`crypto-common`, `hybrid-array`, `typenum`, `inout`, `cpufeatures`, `cpubits`
and `zeroize` are shared with SRTP and listed above.

All but one are dual-licensed like the rest, and one MIT notice covers them.
`subtle` is the exception: BSD-3-Clause, whose second condition requires a
binary to reproduce its notice. Its `LICENSE` reads:

> Copyright (c) 2016-2017 Isis Agora Lovecruft, Henry de Valence. All rights
> reserved.
> Copyright (c) 2016-2024 Isis Agora Lovecruft. All rights reserved.

followed by the three BSD conditions and the disclaimer, which a binary
containing Sipral must carry once this crate is linked into it.

### Certificates under STIR

`sipral-stir` is STIR/SHAKEN caller authentication, and everything in it
that is protocol -- the PASSporT and its deterministic JSON, the Identity
header field, the TNAuthList extension, the path from a signing certificate
to a trust anchor and the rules it is held to, PEM, Base64 -- is written
in-tree from the RFCs. Two things are not. The signatures are ECDSA over
P-256 with SHA-256, from the same `p256` the table under DTLS above lists,
at the same exact version and for the same reason. And an X.509 certificate
is read with the RustCrypto `x509-cert` crate: the structure is large, it is
where a hand-written reader would most likely be wrong, and `der`, the DER
layer it is built on, is already in the tree beneath `p256`.

The crate names three dependencies, `p256`, `x509-cert` and `zeroize` (the
last already under `p256`, at the version `sipral-rtp` pins); the rest arrive
through them. `sipral-ua` reaches it behind its `stir` feature, and the
facade and the C ABI turn that feature on by default, so the components
below are in every default build of `sipral` and `sipral-ffi` and in none
built without `stir`. Every licence below was read from the component's own
manifest, and every component ships its licence files beside it.

| Component | What it is | Licence |
|---|---|---|
| `x509-cert` 0.3.0 | X.509 certificates, read | Apache-2.0 OR MIT |
| `spki` 0.8.0 | the SubjectPublicKeyInfo and AlgorithmIdentifier types `x509-cert` uses | Apache-2.0 OR MIT |
| `der_derive` 0.8.0 | the derive macros `x509-cert` builds its types with; build time only | Apache-2.0 OR MIT |
| `flagset` 0.4.7 | the bit-flag type of the key usage extension | Apache-2.0 |
| `base64ct` 1.8.3 | named by `spki` for its optional `base64` feature, which nothing enables; in the lockfile, never built | Apache-2.0 OR MIT |

`der`, `const-oid`, `zeroize` and everything under `p256` are listed with the
DTLS primitives above; building `x509-cert` turns on further features of
`der` (its derive macros and `flagset`) and of `const-oid` (its database of
names), which adds the crates in this table and no second copy of any. The
derive macros run inside the compiler, through `proc-macro2`, `quote`, `syn`
and `unicode-ident`, which are already in the tree for other crates' macros,
and none of the four is linked into what ships.

All but `flagset` are dual-licensed like the rest, and the one MIT notice
covers them. `flagset` is Apache-2.0 alone; it ships no NOTICE file, so what
section 4 of that licence asks of a binary is a copy of the licence itself.
`THIRD-PARTY-LICENSES.txt` is generated from the graphs of `sipral` and
`sipral-ffi`, which reach this crate by default, and carries every one of
these components' licences.

### PipeWire

`sipral-io-pipewire`, the Linux device crate, links `libpipewire-0.3`
dynamically: the machine's own copy, the one its desktop already runs, found
at load time. Nothing of PipeWire is vendored, built or shipped by this
repository.

| Component | What it is | Licence |
|---|---|---|
| libpipewire-0.3 | the PipeWire client library: the connection, the registry, streams and thread loops. Tested against 1.4.2, Debian 13's | MIT |
| SPA headers (`spa-0.2`) | the plugin API's structures and constants — pods, buffers, hooks, dictionaries — which are all `static inline` or plain declarations, so there is no SPA library to link | MIT |

Every header this crate was written from carries `SPDX-License-Identifier:
MIT`. The declarations in `crates/sipral-io-pipewire/src/sys.rs` and
`abi.rs` are written by hand from them, prototype by prototype and field by
field, rather than generated — `docs/02-clean-room.md` has the rule — so no
PipeWire source is copied into this tree, and a binary that links the
system's library carries no PipeWire code of its own to give notice of. A
distributor that ships `libpipewire` alongside an application ships its MIT
notice with it, as with any MIT library.

The ALSA and PulseAudio client libraries, `alsa-lib` and `libpulse`, are LGPL
and are not linked, and nothing here reaches either through PipeWire:
Debian's `libpipewire-0.3.so.0` itself depends on the C library and nothing
else, and talks to the daemon over its own socket.

## A component an application attaches, not linked by Sipral itself

### webrtc-audio-processing

`crates/sipral-aec-webrtc` is a `Processor` — `docs/05-media.md`'s echo
cancellation, gain control and noise suppression seam — over this library.
Nothing else in this workspace names that crate: it is excluded from the
workspace `cargo build --workspace` and `--all-features` build (its
`Cargo.toml` says why), and reaches an application's binary only when that
application chooses to depend on it. A binary built from `sipral`/
`sipral-ffi` alone, which is every default build, carries none of it.

| Component | What it is | Licence |
|---|---|---|
| `webrtc-audio-processing` 2.1.0 | the safe Rust wrapper | BSD-3-Clause |
| `webrtc-audio-processing-sys` 2.1.0 | the raw declarations and the build that vendors and compiles the C++ library below | BSD-3-Clause |
| `webrtc-audio-processing-config` 2.1.0 | the configuration structs, split out so a WASM caller need not pull in the FFI crate | BSD-3-Clause |
| libwebrtc-audio-processing 2.1 | PulseAudio's repackaging of Google's WebRTC audio processing module, vendored by `webrtc-audio-processing-sys`'s `bundled` feature and built with meson and ninja | BSD-3-Clause |
| rnnoise | a noise-suppression model, bundled inside libwebrtc-audio-processing at `webrtc/third_party/rnnoise` and linked into the same static library — vendored, not a separate crate or subproject, so it ships whenever the component above does | BSD-3-Clause |
| pffft | the FFT `webrtc/third_party/pffft` runs, bundled the same way as rnnoise | a custom permissive licence, derived from FFTPACKv5's |
| abseil-cpp 20240722.0 | one meson subproject of the above, fetched by its own `subprojects/abseil-cpp.wrap` when no system copy is found by `pkg-config` | Apache-2.0 |

All four crates carry the same `COPYING`, a single BSD-3-Clause block
copyright the WebRTC project authors — one reproduction of it and the three
conditions discharges the obligation for all of them, the same shape
libopus's notice above takes. The vendored library's own `webrtc/LICENSE` is
the identical text under Google's copyright, and its `webrtc/PATENTS` is a
separate, perpetual patent grant over the implementation it ships with —
read before this component reaches a commercial build, the same as Opus's
patent position above, though not reproduced in full here since it is not a
licence this file exists to discharge. rnnoise's own `COPYING` and pffft's
own `LICENSE`, at the root of each one's own directory inside the vendored
tree, are two more BSD-family blocks the same shape covers.

Building it needs `meson`, `ninja` and a C++ compiler on the machine, which
the rest of this tree does not ask for; `scripts/check.sh` has its own step
for it, and does not skip that step when those tools are missing.

**Licence texts**, unlike the six components above: not this file, and not
the workspace's own `THIRD-PARTY-LICENSES.txt`, which `tools/license-gen`
generates from `cargo tree` over `sipral`/`sipral-ffi` and which this crate
is deliberately outside of (its own `Cargo.toml` says why). All seven
components above — the three crates.io wrappers, libwebrtc-audio-processing,
its two bundled third-party components, and abseil-cpp — have their full
licence texts in `crates/sipral-aec-webrtc/THIRD-PARTY-LICENSES.txt`
instead, generated by the same tool's `--aec` mode
(`cargo run -p sipral-license-gen -- --aec`) and kept current by
`scripts/check.sh`'s own step for this crate, once it has built it —
abseil-cpp's text does not exist on disk anywhere before that build fetches
it. Ship that file, or an equivalent notice screen, alongside a binary that
links this crate, the same way `THIRD-PARTY-LICENSES.txt` at the workspace
root is shipped alongside one built from `sipral`/`sipral-ffi`.

## A dependency of a binding, not of the library

### Kotlin binding (kotlinx.coroutines)

`bindings/kotlin`'s idiomatic layer (`org.sipral.idiomatic`, over the
generated `org.sipral.Sipral`/`SipralAbi.kt`) uses `kotlinx-coroutines-core`
for its events `Flow` and its suspend functions — a call placed or a
registration asked for that only completes once the matching event arrives.
It is a test and build dependency of the binding, never of the Rust
workspace, and never shipped inside `libsipral_ffi`.

| Component | What it is | Licence |
|---|---|---|
| `kotlinx-coroutines-core-jvm` 1.11.0 | structured concurrency, channels and `Flow` for the JVM | Apache-2.0 |

Fetched once from Maven Central into a cache outside the repository
(`~/.cache/sipral/maven/org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/1.11.0/`),
verified against the sha256 Maven Central itself publishes for the jar
(`d1d75aa01dffbb4d1c520e67e4c4e7f5f6174718e7cb4632412503f2f0e604fa`), and
reused from there by `scripts/check.sh` on every run after — the gate never
downloads it, and fails naming the expected path and checksum if it is not
there. `kotlinx-coroutines-core-jvm`'s own `LICENSE.txt` is the standard
Apache-2.0 text with JetBrains s.r.o. as the copyright holder.

### The Android ConnectionService helper and sample

`bindings/kotlin/android` -- the helper's Android library (`:telecom`) and the
Compose sample (`:sample`) -- is built with Gradle by
`scripts/package/android.sh`. Everything below is a dependency of those two
and of their build, never of `libsipral_ffi` or of `sipral.aar`, which carries
only this repository's own classes and natives. An application that ships the
helper ships the two runtime dependencies in its first table; the sample
ships the rest of them too.

| Component | What it is | Used by | Licence |
|---|---|---|---|
| `kotlinx-coroutines-android` 1.11.0 | coroutines' Android main dispatcher, over `kotlinx-coroutines-core` | helper, at run time | Apache-2.0 |
| Kotlin standard library 2.4.20 | what compiled Kotlin calls into | helper and sample, at run time | Apache-2.0 |
| Jetpack Compose (`compose-bom` 2026.09.00: `ui`, `material3` and what they bring) | the sample's user interface | sample, at run time | Apache-2.0 |
| `androidx.activity:activity-compose` 1.13.0 | a Compose screen in an activity | sample, at run time | Apache-2.0 |
| `androidx.lifecycle:lifecycle-runtime-compose` 2.11.0 | lifecycle-aware state for Compose | sample, at run time | Apache-2.0 |

Those five bring in the rest of AndroidX, JetBrains' annotations and JSpecify
with them -- 96 artefacts on the sample's runtime classpath as of this
writing.

The helper's unit tests (`bindings/kotlin/android/telecom/src/test`) run on
the following, which is test only: nothing built from this repository ships
it.

| Component | What it is | Licence |
|---|---|---|
| TestNG 7.12.0 | the test runner the helper's unit tests are written for (JUnit's licence, EPL, is not one this repository takes) | Apache-2.0 |
| JCommander (with TestNG) | TestNG's command-line parsing | Apache-2.0 |
| SLF4J API (with TestNG) | TestNG's logging facade | MIT |
| jQuery webjar (with TestNG) | TestNG's HTML report | MIT |

`scripts/package/android.sh` lists every artefact Gradle resolved for the
helper at run time, the sample at run time and the helper's unit tests, reads
the licence each one's own POM declares (or its parent's), and fails on any
that is not one `deny.toml` allows.

| Build tool | What it is | Licence |
|---|---|---|
| Gradle 9.7.1 | the build, and the wrapper `android.sh` generates from it | Apache-2.0 |
| Android Gradle Plugin 9.4.1 | Android builds under Gradle | Apache-2.0 |
| Kotlin Gradle plugin and Compose compiler plugin 2.4.20 | the Kotlin compiler under Gradle, and Compose's compiler step | Apache-2.0 |
| Kotlin compiler 2.4.20 | `kotlinc`, which `aar.sh` compiles `sipral.aar`'s classes with | Apache-2.0 |
| `cargo-ndk` 4.1.2 | drives `cargo` for Android's ABIs | Apache-2.0 OR MIT |

The two plugins bring 115 artefacts onto the build's own classpath
(`./gradlew buildEnvironment`), and not all of them are under a licence
`deny.toml` allows: `juniversalchardet` is MPL-1.1, JAXB and Jakarta
Activation are EDL-1.0, Bouncy Castle has its own MIT-style licence, JDOM its
own Apache-style one, and JNA is LGPL-2.1 or Apache-2.0. They run inside
Gradle while it builds and nothing of them is in any artefact, which is why
`android.sh` holds only what the helper, the sample and the tests resolve to
the allow-list.

The Android SDK and NDK the image installs are under the Android SDK licence,
not an open-source one. They are tools and are not redistributed: nothing of
the SDK is in this repository or in any artefact built from it except what the
NDK's compiler puts into every shared object it links, its compiler runtime,
which is LLVM's (Apache-2.0 WITH LLVM-exception, whose exception removes the
attribution requirement for object code). `libsipral_ffi.so` and
`libsipral_jni.so` need nothing from the device but Bionic's `libc`, `libm`
and `libdl`, which `scripts/package/android.sh` checks. Whoever builds the
image accepts the SDK licence themselves, by passing
`--accept-android-sdk-licenses`; nothing here accepts it for them.

The Gradle wrapper's jar is not committed, because it is a binary and nothing
binary is carried in this tree: `android.sh` generates it from the Gradle
distribution in the image, whose SHA-256 is pinned, and checks that it
reproduces the committed `gradle-wrapper.properties`.

### The React Native package

`bindings/react-native` has no runtime dependency of its own
(`dependencies` in its `package.json` is empty, and `scripts/check.sh` fails
when it is not): React Native and React are the application's, named as peer
dependencies, and an application that ships the package ships them under
its own terms. What the package's Android library adds to the application
is what the Kotlin binding already needs.

| Component | What it is | Used by | Licence |
|---|---|---|---|
| React Native 0.87.1, with `com.facebook.react:react-android` | the framework the module is written for, the application's own | the application, at run time | MIT |
| React 19.3.0 | React Native's peer | the application, at run time | MIT |
| `kotlinx-coroutines-android` 1.11.0 | the Android half's event collection | the Android half, at run time | Apache-2.0 |

Everything else under `devDependencies` builds and tests the package and is
in no artefact: TypeScript 7.0.2 (Apache-2.0) for the type check, Jest 30.5.2
with `babel-jest`, Babel 8 (`@babel/core`, `@babel/preset-typescript`,
`@babel/plugin-transform-modules-commonjs`) and `@types/jest` for the tests,
`@react-native/codegen` 0.87.1 for the spec, all MIT unless named. Every
package in the tree they resolve to, `package-lock.json`, declares MIT, ISC,
Apache-2.0, BSD-2-Clause, BSD-3-Clause, 0BSD, BlueOak-1.0.0 or CC-BY-4.0
(the browser table `caniuse-lite` carries), or a choice between MIT and
CC0-1.0 or Apache-2.0. The lockfile is committed without npm's
deprecation notices, one of which carries an address.

The Android library builds with the pair React Native 0.87.1 builds with
itself: Gradle 9.4.1, which the wrapper in `android/gradle/wrapper` pins,
and the Android Gradle Plugin 9.2.1 (both Apache-2.0). Not the newest, and
for a reason: React Native's Gradle plugin is compiled by Kotlin 2.2, which
cannot read the Kotlin 2.4 metadata of the standard library Gradle 9.7 and
later embed, and the Android Gradle Plugin 9.4 needs Gradle 9.6 or later.

## Allowed licences

`deny.toml` holds the machine-readable allow-list, which `scripts/check.sh`
enforces. It permits
MIT, MIT-0, BSD-2-Clause, BSD-3-Clause, Apache-2.0 (including the
`WITH LLVM-exception` variant), ISC, Zlib, Unicode-3.0, CC0-1.0 and BSL-1.0
(Boost, not Business Source).

Anything under GPL, LGPL, MPL, SSPL, BUSL, CDDL or a non-commercial clause is
refused. A single LGPL dependency would make the commercial arm undeliverable,
which is why the check fails the build rather than warning.

## Components planned, and why each one is safe

These are the components the roadmap intends to link. None of them is present
yet. Each is listed with the licence verified from its own LICENSE file.

| Component | Use | Licence |
|---|---|---|
| libvpx, libaom | video codecs, phase 6, after 1.0 | BSD-3-Clause / BSD-2-Clause |

## Written in-tree rather than linked

Audio device I/O is written in-tree per platform rather than taken from a
portable library, because the render-to-capture delay and the device-loss
behaviour the design needs are per platform.

G.711, G.722 and G.729 are written in-tree. G.711 is a couple hundred lines
and is public domain as an algorithm; G.722 is written from the ITU
Recommendation, because the C implementation everyone links is one the
clean-room rules forbid and the Rust crate that looks free of it is that
implementation with the comments intact. G.729 is written the same way, from
the Recommendation and its Implementers' Guide; the common implementation is
GPL-3 and is never opened, and what the ITU's own software attachment
contributed — the numbers of its trained tables and nothing else — is in
`CLEANROOM_AUDIT.md`.

**What is implemented of G.722 is the 1988 base and nothing else**, and that
boundary is deliberate rather than incidental. The base is clean on primary
sources rather than on inference: the declarations filed with the ITU in 1986,
and AT&T's express waiver of July 2001 of any essential patent right in it.
It is the one codec here whose patent position can be stated with the documents
in hand. The parts added later are a different question — the
superwideband extension, the two appendices carrying loss concealment, and the
2012 amendment attracted patent declarations as late as 2014, on applications
filed between 2009 and 2011, which on the ordinary term would run into the
2029 to 2031 range. None of that is here: the tree carries the filter pair of
§5, the two sub-bands of §6 at six bits and two, and the three modes of 64, 56
and 48 kbit/s, all of which are in the original Recommendation. The loss
concealment in `sipral-media` is written for linear PCM from G.711 and derives
from no ITU appendix. Anyone extending this codec should know they would be
crossing out of the clean part.

#### G.729's patent position

G.729 was a pooled codec for most of its life, and a licensee's lawyer will
ask about it before any other codec here, so the position is written down
rather than assumed.

The essential patents on G.729 and on its Annexes A and B were licensed
through a pool administered by Sipro Lab Telecom, and they are reported
expired: the administrator announced the end of its G.729 licensing
programme as of 1 January 2017, on the ground that the patents in it had
expired. That is the administrator's statement about the patents it
licensed, as reported. It has not been checked here patent by patent or
country by country, and it is confirmed in writing before the codec ships
under the commercial licence.

What that statement is about, and what it is not about, matters more than
the date. **What is implemented here is G.729 with Annexes A and B**: Annex
A's encoder, and a decoder of the bitstream the main body and Annex A share,
with Annex A's postfilter, and over them Annex B's voice activity detector,
discontinuous transmission and comfort-noise generator, bit-exact against the
ITU Annex A and Annex B conformance streams.
**Not here, and not covered by anything above**: G.729.1, the embedded
wideband codec, whose patent declarations are far later; the later annexes
of G.729 — the 6.4 and 11.8 kbit/s extensions (Annexes D and E) and every
annex after them; and G.729's own appendices. Anyone extending this codec
into any of those is outside the position this section describes.

Nothing in this file, and nothing in either licence, is a representation
that Sipral, or G.729 as it is implemented here, infringes no patent; see
`LICENSE-COMMERCIAL.md`. G.729 is also never in the default offer
(`docs/05-media.md`): a call carries it only where the application names
it.

## Test tooling

SIPp, Wireshark, Kamailio, FreeSWITCH and Asterisk are used to test Sipral.
None of them is linked into it, none ships with it, and their licences do not
reach the product.

The fuzz harness under `fuzz/` links `libfuzzer-sys` and, through it,
`arbitrary`, `libc`, `cc`, `jobserver` and `shlex`. That crate is a separate
workspace with its own lockfile and its own nightly pin, it is never published
and never linked into anything shipped, and `scripts/check.sh` runs
`cargo deny` over it too. Its targets also reach into the workspace they test,
so that lockfile carries whatever those crates carry as well — today `aes`,
`zeroize` and the RustCrypto support crates named further up. None of that is
new to the product: every one is already in the shipped graph and already
attributed above, which is why the five named at the start of this
paragraph are the harness's own and not a second copy of that list. All of them are MIT or Apache-2.0, except
`libfuzzer-sys` itself, which is `(MIT OR Apache-2.0) AND NCSA` — NCSA is
LLVM's old permissive licence, and `deny.toml` allows it by name for that one
crate rather than opening the allow-list.

`bindings/dotnet/Sipral.Tests` carries its own test-only NuGet dependencies,
declared in that project alone and never referenced from `bindings/dotnet/Sipral`
itself, so none of them reaches an application that only links the package
that ships: `xunit` 2.9.2, `xunit.runner.visualstudio` 2.8.2 and the packages
either pulls in (`xunit.core`, `xunit.assert`, `xunit.extensibility.core`,
`xunit.extensibility.execution`, `xunit.analyzers`, `xunit.abstractions`), all
Apache-2.0, plus `Microsoft.NET.Test.Sdk` 17.11.1, MIT.

The RFC 4475 torture test corpus under `fixtures/rfc4475/` is IETF Trust
material, reproduced under the IETF Trust Legal Provisions.

`crates/sipral`'s own `[dev-dependencies]` carry `rcgen` 0.14.10 (MIT OR
Apache-2.0) and, through it, `yasna`, `pem`, `time` and a handful of smaller
crates, all MIT or Apache-2.0 or both. It mints a throwaway, self-signed TLS
certificate inside `examples/tls.rs`'s own test, for a local server that
exists for the length of that one test and nowhere else; nothing it generates
is committed, and `cargo test -p sipral` compiles it whether or not
`example-tls` is enabled, but exercises it only from that one test.

`rcgen` needs a crypto backend to actually sign a certificate, and its default
features choose `ring` for it — the same `ring` (Apache-2.0 AND ISC) and
`untrusted` (ISC) named in the table below, not a second copy. That makes
`ring` reach this crate's dev-profile on its own, whether or not `example-tls`
is enabled: `cargo test -p sipral` and `cargo build --examples` need a C
compiler for it regardless of feature flags, the same way they already need
one for `opusic-sys` under the default `opus` feature. Nothing here is a
licensing exception — `ring` is already allowed — but it is a second, separate
reason a build with no matching C toolchain (a cross-compile target with none
installed, say) cannot check this crate's tests or examples, distinct from the
`example-tls`-gated reason below.

The same `[dev-dependencies]` name `getrandom` 0.2.17 (MIT OR Apache-2.0),
the copy `ring` already brings in, for the examples' seeds: every example
draws the two seeds a `UserAgent` and a `MediaEngine` are built with from the
operating system, which is the part of using the library an example has to
show. It is linked into the examples and tests alone.

## Examples only, never shipped

`crates/sipral/examples/tls.rs` is the one place in this repository that
links a TLS implementation, behind the `example-tls` feature, off by default
and reached by nothing else in the crate — `docs/01-architecture.md` explains
why `sipral` itself never will. `cargo build --workspace` does not compile it,
and a product embedding this crate does not link it either, unless it goes out
of its way to enable the feature and depend on the example's own code.

| Component | What it is | Licence |
|---|---|---|
| `rustls` 0.23.45 | the TLS 1.2/1.3 client, `default-features = false` plus `ring`/`std`/`tls12` | MIT OR Apache-2.0 OR ISC |
| `rustls-native-certs` 0.8.4 | reads the platform's trust store into a `rustls::RootCertStore` | MIT OR Apache-2.0 OR ISC |
| `rustls-pki-types` 1.15.1 | the certificate and server-name types both of the above share | MIT OR Apache-2.0 |
| `ring` (via `rustls`'s `ring` feature) | the cryptographic provider `rustls` calls into; chosen over the default `aws_lc_rs` because it needs only a C compiler, not `cmake` | Apache-2.0 AND ISC |

`ring` pulls in `untrusted` (ISC) and the usual `cfg-if`/`getrandom` layer,
already in the allowed set. `rustls-native-certs` reaches `security-framework`
and `security-framework-sys` on macOS (both MIT OR Apache-2.0), and
`openssl-probe`, `home` or `rustls-pemfile` depending on platform, all of them
MIT OR Apache-2.0. Every one of them is in `deny.toml`'s allow-list; nothing
here needed an exception.
