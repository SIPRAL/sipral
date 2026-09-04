<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Security policy

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository: the
Security tab, then "Report a vulnerability". It is private between you and the
maintainer, and it does not require an email address from either side.

Do not open a public issue for a vulnerability.

GitHub only offers private vulnerability reporting on public repositories. While
this repository is private, the only people who can see it were invited by the
maintainer; report through the channel you were invited by.

Expect an acknowledgement within a few days, an assessment within two weeks, and
credit in the advisory unless you prefer otherwise.

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

## Supported versions

Before 1.0, only the latest release. After 1.0, the current minor and the one
before it.
