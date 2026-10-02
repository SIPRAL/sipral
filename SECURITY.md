<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Security policy

The threat model this policy's scope is drawn from — what a hostile peer, a
rewriting proxy, a flood or a replay can do against this tree, what already
refuses each, and what has not been read for this yet — is
`docs/20-security-model.md`.

## Reporting a vulnerability

Do not open a public issue for a vulnerability, on this repository or, once it
exists, its public successor.

GitHub only offers private vulnerability reporting on a public repository.
This one is private for now, and the only people who can see it were invited
by the maintainer, so report the same way you were invited: through that
channel, to the maintainer directly. GitHub's **private vulnerability
reporting** — the Security tab on the repository, then "Report a
vulnerability" — is switched on the day this repository turns public, and
becomes the channel from that day on: private between you and the
maintainer, and the one this
policy's own time commitments below are measured against from then on.

## What happens after a report

1. **Acknowledgement.** The maintainer confirms the report arrived and is
   being read.
2. **Triage.** The report is reproduced against the code it names, or the
   reporter is asked for what is missing to reproduce it; scope is checked
   against "What is in scope" below, and a severity is assigned.
3. **Fix.** A fix is written and tested the way every change to this tree
   is (`scripts/check.sh`, the lab where the change touches signalling or
   media) before anything about the report becomes public.
4. **Coordinated disclosure.** The report, and what depends on it, stays
   private until a fix has shipped, or the disclosure deadline below is
   reached — whichever comes first. A reporter who wants a different
   timeline says so when they report; the maintainer agrees to a change in
   writing before it applies.
5. **Advisory and CVE.** A GitHub Security Advisory is published once
   public disclosure is due, describing the vulnerability, the versions it
   affects and the fixed version. GitHub is a CVE Numbering Authority (CNA)
   for repositories it hosts advisories for; a CVE ID is requested through
   that program for anything that qualifies, rather than left unassigned.
6. **Credit.** The reporter is named in the advisory, unless they ask to
   stay anonymous or to be named differently.

**Time commitments** — the maintainer's own promise, not a guarantee of
outcome, and the standard this small a vendor can actually hold:

| From | To | Within |
|---|---|---|
| Report received | Acknowledgement | 3 business days |
| Acknowledgement | Triage (reproduced, scoped, severity assigned) | 10 business days |
| Triage | A fix, for **critical** or **high** severity | 30 days |
| Triage | A fix, for **medium** or **low** severity | No fixed deadline; tracked to closure, not silently dropped |
| Acknowledgement | Public disclosure, fixed or not | 90 days, unless the maintainer and reporter agree in writing to extend it |

A report that turns out to need more than these to fix correctly is not
rushed past them; the reporter is told why, and given a revised estimate,
before any deadline above passes silently.

## What is in scope

A SIP endpoint parses hostile input for a living. Anything reachable from the
network is in scope, and the parser especially:

- memory safety or a panic reachable from a received message, in any crate;
- a hang or unbounded allocation triggered by a crafted message;
- authentication that accepts what it should reject, including digest
  verification and SRTP key handling;
- credentials, keys or media leaking into logs or error messages;
- media accepted from a source that should not be able to inject it.

## What is not

- Denial of service that needs traffic volume rather than a crafted message.
- Findings against a peer implementation we interoperate with. Report those to
  their maintainers.
- Anything requiring the attacker to already control the process.

## Known advisories that do not apply

A dependency scanner run over this tree will report these. Each is set aside in
`deny.toml`, with the reason beside it, and the reason is repeated here for
whoever reads a scan without reading the configuration.

- **RUSTSEC-2023-0071 / CVE-2023-49092, `rsa` (the Marvin attack).** A timing
  side channel in operations with an RSA *private* key — decryption and
  signing — that leaks that key. `sipral-dtls` uses the crate only to verify a
  peer's signature with the peer's *public* key, and holds no RSA private key
  at all: this end's own key is P-256. There is no secret for the channel to
  reach. Any use of an RSA private key added later removes the exception from
  `deny.toml` first.

## Supported versions

From 1.0.0 on, security fixes reach the current minor release and the one
before it: at 1.0.0, that is 1.0.x alone. The supported artefacts are the C
library and the language packages a release publishes; the Rust crates are
not part of a release (`docs/11-testing.md`, "Releasing"). A fix that reaches
only the current minor still reaches every application: the C ABI is at 1.0,
and a binding built against any 1.x ABI loads against a later 1.x library
(`docs/08-ffi.md`, "ABI 1.0"), so updating the native library alone takes
the fix.
