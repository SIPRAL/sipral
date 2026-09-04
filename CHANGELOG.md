<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is semantic once 1.0 exists; before that, minor versions may break.

## [Unreleased]

### Changed

- Phase 1 readiness review, nine gaps closed: WebSocket scoped to phase 2 and
  its framing corrected (one SIP message per WebSocket message, never the
  `Content-Length` framer); keepalive given a home in `EndpointConfig`; the
  `sipral-ua` call handle renamed away from the core's `CallId`; a fuzzing
  plan and a per-flow interoperability pass bar in `docs/11-testing.md`; the
  `sipral` facade crate inheriting version, licence and lints from the
  workspace; `scripts/check.sh` failing on version drift between the
  workspace and the .NET package.
- Design and licensing documents checked claim by claim against the RFC text
  and the primary sources; 20 corrections applied. The ones that change
  behaviour: the release profile no longer sets `panic = "abort"`, because the
  FFI layer has to catch unwinding at the C boundary; `sipral-ffi` and
  `sipral-io-coreaudio` now carry the `unwrap`/`expect`/`panic`/indexing lints
  they were silently missing; phase 1 explicitly includes the minimal RTP and
  G.711 slice a bidirectional call needs; `LICENSING.md` no longer implies that
  charging for a product is by itself what triggers the commercial arm. CI
  installs the toolchain from `rust-toolchain.toml` instead of pinning a second
  time in the workflow, and runs the gitleaks binary (pinned, checksum
  verified) instead of the marketplace action, which requires a paid licence
  on organisation repositories.

### Added

- Workspace skeleton: the eight crates from `docs/01-architecture.md`, each with
  its scope documented and nothing implemented.
- Design documents for phase 0: architecture, clean-room rules, signalling
  core, user agent, media, NAT, headless endpoint, FFI, RFC index, roadmap,
  testing.
- Licensing set: AGPL-3.0-only alongside a commercial arm, with `LICENSING.md`,
  `LICENSE-COMMERCIAL.md`, `TRADEMARK.md`, `AUTHORS`, `THIRD-PARTY-NOTICES.md`,
  and SPDX headers on every source file.
- `deny.toml` with a permissive-only allow-list, enforced in CI.
- `scripts/check.sh`: licence headers, provenance, published-tree language,
  internal files and captures, build, lints, tests, dependency licences,
  secrets.
- CI on Linux, macOS and Windows, plus separate licence and hygiene jobs.
- `crates/sipral`: the facade crate, for now a name reservation on crates.io
  that exports a version constant. The only crate with `publish = true`.
- `bindings/dotnet/Sipral`: the .NET package, for now a name reservation
  published to NuGet as `Sipral` 0.0.1.
- `docs/12-core-api.md`: the public surface of `sipral-core` as signatures,
  merged from four independent proposals scored by three reviewers, with
  register, call, CANCEL-race and fork walkthroughs, a fake-clock test, the C
  projection, and a record of what was rejected and why. Adds the RFC 6026
  `Accepted` state to both INVITE machines, which every proposal had missed on
  the client side.
- RFC 4475 torture corpus under `fixtures/rfc4475/`: the 49 messages decoded
  byte for byte from the archive in Appendix A, laid out by RFC section, with
  a manifest carrying section, title, expected outcome and SHA-256 per file.
  `scripts/check.sh` verifies the hashes so line-ending normalisation cannot
  silently alter a test.
- `SECURITY.md`, pointing at GitHub private vulnerability reporting, and an
  issue template for commercial licence enquiries. No email address appears
  anywhere in the repository, by design: `scripts/check.sh` fails on one, in a
  file or in commit metadata.
