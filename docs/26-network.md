<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# The networking component

The core opens no socket and links no TLS library (`01-architecture.md`, "Who
owns the sockets, the resolver and TLS"). Every binding fills that gap with the
platform's own APIs. A program that calls the C ABI or the Rust crates directly
used to fill it itself: a socket per transport, a TLS library, a resolver that
can ask NAPTR and SRV, and the loop that joins them to the stack. The
networking component is that layer, written once, in Rust and behind the C ABI,
and optional: an application that brings its own networking links none of it.

It is two things:

- **`sipral-net`**, a crate beside the core, with no Sipral dependency but
  `sipral-core`. `Network` binds UDP sockets, opens TCP and TLS connections,
  answers the core's lookups and hands everything that arrived back as a
  `Happening`; `Resolver` asks NAPTR, SRV, A and AAAA and can run the core's
  own `Locator` to the end; `Trust` and `ClientCertificate` are the TLS
  choices; `Failure` and `TlsFailure` say why a connection failed. A Rust
  application drives its `UserAgent` with it the way `crates/sipral-ua`'s
  reference loop does, without that loop's limits.
- **`sipral_network_*`** in the C ABI (ABI 1.6), behind `sipral-ffi`'s
  `network` feature: the same crate running a stack's whole loop, so that a C
  or C++ program has no networking code at all.

## What it runs, and with what

| Piece | Done with | Licence |
|---|---|---|
| UDP, TCP | `std::net`, a thread per socket | — |
| TLS 1.2 and 1.3 | `rustls` 0.23 with the `ring` provider | Apache-2.0 / ISC / MIT |
| The platform's trust store | `rustls-native-certs` 0.8, checked by `rustls-webpki`; on Android the system's certificate directory, read in-tree; on iOS the Security framework's own evaluation, through `security-framework` 3.7 | Apache-2.0 / ISC / MIT |
| NAPTR, SRV, A, AAAA | `hickory-resolver` 0.26 on a current-thread `tokio` runtime of its own | MIT / Apache-2.0 |
| What to ask, in what order, how to rank it | the core's `Locator` (RFC 3263 §4, RFC 2782) | ours |

Every crate under these is inside the licence set `deny.toml` allows, and
`cargo deny` checks it with every feature on. `rustls-platform-verifier`, the
obvious way to reach the platform's verifier, is not used: its dependency graph
carries `webpki-root-certs`, whose licence (CDLA-Permissive-2.0) is not in that
set, on the one target it builds it for.

The resolver reads the system's configuration — `/etc/resolv.conf` on Linux,
the System Configuration framework on Apple platforms, the adapters on Windows —
or asks only the name servers the application names
(`sipral_network_config_t::name_servers`). A name the hosts file knows is
answered from it.

## The C ABI

```c
sipral_network_config_t net = { .size = sizeof net };     /* platform trust, system resolver */
char found[256], local[64];
sipral_network_locate(&net, "sips:example.com", 16, SIPRAL_TRANSPORT_TLS,
                      found, sizeof found, NULL);         /* RFC 3263 before any stack */
sipral_advertised_address("0.0.0.0:0", 9, found, strcspn(found, ","), local, sizeof local, NULL);

/* the stack on UDP at `local`; an account with server_uri "sips:example.com"
   and stream_protocol SIPRAL_TRANSPORT_TLS */
sipral_stack_create(&config, &stack);
sipral_network_start(stack, &net, now_ms());
sipral_account_add(stack, &line, &account);
sipral_account_register(stack, account, now_ms());
for (;;)
    sipral_network_run(stack, now_ms(), 20);
```

| Entry point | Does |
|---|---|
| `sipral_network_start(stack, config, now_ms)` | binds the stack's UDP socket at its `bind_address`, starts the resolver, and from then on reads every event before the callback |
| `sipral_network_run(stack, now_ms, wait_ms)` | one turn: poll, write what the stack queued, open the connections and make the lookups it asked for, wait up to `wait_ms` (less when a timer is due) for anything to arrive, hand it in, poll and write again |
| `sipral_network_stop(stack)` | closes everything the component opened; `sipral_stack_destroy` does the same |
| `sipral_network_locate(config, server_uri, len, protocol, buffer, capacity, out_needed)` | RFC 3263 for a URI before any stack exists, NAPTR first: every address, comma-separated |
| `sipral_network_media_open(stack, buffer, capacity, out_needed)` | a UDP socket for one call's media, on the stack's address, at a port from its RTP range when it has one |
| `sipral_network_media_attach(stack, address, len, call, media)` | the call's media handle on that socket: what arrives goes to `sipral_media_receive`, what the handshake, the checks, RTCP and the goodbye produce leaves from it |
| `sipral_network_media_capture(stack, media, now_ms, samples, count)` | `sipral_media_capture`, and the packet sent |
| `sipral_network_media_close(stack, address, len)` | a socket whose call never reached media; one whose call ended closed with it |

The stack it runs is created on `SIPRAL_TRANSPORT_UDP` at an address that names
an interface (`sipral_advertised_address` finds it toward the server
`sipral_network_locate` found); `sipral_network_start` refuses any other with
`SIPRAL_STATUS_WRONG_STATE`, because a message for a main transport nobody
writes would be lost without a word. Accounts on TCP, TLS, WS or WSS reach
their servers on connections of their own (`stream_protocol`): every
`SIPRAL_EVENT_KIND_TRANSPORT_WANTED` is answered with a connection bound under
a number from 2^31 up, a WebSocket's handshake and frames staying the stack's.
Every `SIPRAL_EVENT_KIND_LOOKUP_WANTED` is answered with what the name servers
said, a failure included, so an account's `server_uri` is located by NAPTR
(with `server_naptr` on), SRV and A or AAAA with nothing asked of the
application. The events still reach the application's callback, after the
component has read them.

The callback runs inside `sipral_network_run`, as it does inside
`sipral_stack_poll`, and may call any entry point but `sipral_network_run`
itself, which answers `SIPRAL_STATUS_BUSY` there. `SIPRAL_FEATURE_NETWORK` says
whether a library has the component; one built without it has every
`sipral_network_*` entry point and answers `SIPRAL_STATUS_NOT_SUPPORTED`. The
bindings' packages are built without it, because each binding opens its own
connections with the platform's APIs.

## What a TLS connection is checked against

| `sipral_network_config_t::trust` | Trusted |
|---|---|
| `SIPRAL_NETWORK_TRUST_PLATFORM` (0) | the authorities in the platform's trust store: the keychain's on macOS, the system store on Windows, on Android the system's certificate directory (the updatable Conscrypt module's from Android 14), on iOS whatever the Security framework trusts, the system's CA bundle elsewhere, or the file `SSL_CERT_FILE` names |
| `SIPRAL_NETWORK_TRUST_PLATFORM_AND_AUTHORITY` (1) | those, and the PEM certificates in `authority_pem` |
| `SIPRAL_NETWORK_TRUST_ONLY_AUTHORITY` (2) | the certificates in `authority_pem` alone |
| `SIPRAL_NETWORK_TRUST_PINNED` (3) | the one certificate whose SHA-256 fingerprint is `pin_sha256`, read as `tls_pin_sha256` is (`22-tls.md`, "A PBX's own certificate, pinned") |

An account's own `tls_pin_sha256` wins over the configured trust for the
connections to its server. The name is checked by the rules HTTPS uses, as
every binding checks it: `tls_server_name` when the configuration gives one;
else the host of the `server_uri` of the account whose located addresses
include the one connected to — the SIP domain the user configured, not the
host its SRV record named (RFC 5922 §7.3); else the address itself. A `sip:`
URI in `subjectAltName` naming that domain is accepted besides (RFC 5922
§7.1), and with `domain_rules` `SIPRAL_DOMAIN_RULES_RFC5922` the name is read
by RFC 5922 alone, which refuses a wildcard (`22-tls.md`, "What the platform
checks, and what RFC 5922 adds").

A client certificate (`client_certificate_pem`, `client_key_pem`) is presented
when a server asks for one; read before every connection, a key that does not
load or match is `SIPRAL_TLS_FAILURE_CLIENT_KEY_UNAVAILABLE` and a certificate
out of its dates `SIPRAL_TLS_FAILURE_CLIENT_CERTIFICATE_EXPIRED`, and neither
reaches the server. After a TLS 1.3 handshake the connection waits, twice what
connecting took and between a quarter of a second and three seconds, for the
server's verdict on the certificate, as the bindings do.

## Failures, as the bindings report them

A connection that cannot be made, or breaks, is told to the stack with
`sipral_stack_transport_failed_with`, and reaches the application as
`SIPRAL_EVENT_KIND_TRANSPORT_FAILED` with the reason in `tls` and a sentence in
`detail` ("TLS to 192.0.2.10:5061 refused: invalid peer certificate:
UnknownIssuer"):

| What happened | `error` | `tls` |
|---|---|---|
| nothing listens | `CONNECTION_REFUSED` | none |
| no route | `UNREACHABLE` | none |
| no answer within `connect_timeout_ms` (8000 by default) | `TIMED_OUT` | none |
| the server's certificate chains to nothing trusted, or is not the pinned one | `CONNECTION_RESET` | `UNTRUSTED` |
| it names another server | `CONNECTION_RESET` | `NAME_MISMATCH` |
| it is out of its dates | `CONNECTION_RESET` | `EXPIRED` |
| the server asked for a client certificate and none was configured: its `certificate_required` or another certificate alert, `handshake_failure` once it asked, or a close with nothing said | `CONNECTION_RESET` | `CLIENT_CERTIFICATE_REQUIRED` |
| it refused the one presented, by an alert or by closing before answering | `CONNECTION_RESET` | `CLIENT_CERTIFICATE_REFUSED` |
| the configured key cannot be used | `OTHER` | `CLIENT_KEY_UNAVAILABLE` |
| the configured certificate is out of its dates, or the server said so | `OTHER` / `CONNECTION_RESET` | `CLIENT_CERTIFICATE_EXPIRED` |
| any other handshake failure | `CONNECTION_RESET` | `HANDSHAKE_REFUSED` |

A connection that was never bound reads `protocol` zero in the event, as it does
from a binding.

## Media

A call's socket is the component's when the application asks for one
(`sipral_network_media_open`) and attaches the call's media handle to it once
`SIPRAL_EVENT_KIND_MEDIA_STARTED` has come and `sipral_call_media` has minted
it. What arrives before that goes to `sipral_stack_receive_stun`, which keeps
what the call will need — the STUN and TURN servers' answers, the far end's
early checks — and refuses the rest, which is dropped. Capture and playback
stay the application's — PCM in with `sipral_network_media_capture`, out with
`sipral_media_playback` — or the built-in audio engine's in device mode, whose
transmit callback the application still writes.

### STUN and TURN

On a stack created with `SIPRAL_NAT_STUN` (ABI 1.9) the component carries what
`06-nat.md` has an application carry for each media socket. The turn after
`sipral_network_media_open` names the socket with `sipral_stack_nat_map`;
every turn sends what `sipral_stack_poll_stun` queued, from the socket it
names, and hands what the socket hears to `sipral_stack_receive_stun` until
the call's handle is attached. The application places or answers the call on
the socket once `SIPRAL_EVENT_KIND_NAT_MAPPING` about it has come, and, with a
`turn_server`, `SIPRAL_EVENT_KIND_NAT_RELAY` too: the stack refuses a call
described on a socket still being asked about. `sipral_network_media_close`
on a socket with no call releases it at the next turn with
`sipral_stack_nat_unmap`, so that its relay is given back with a Refresh of
lifetime zero (RFC 8656 §8) from the socket before it closes.

With `turn_transport` TCP or TLS the relay is reached over a connection of the
socket's own (RFC 8656 §3.1). The component opens it when
`SIPRAL_EVENT_KIND_TURN_STREAM` asks, says so with
`sipral_stack_turn_connected`, hands everything it carries to
`sipral_stack_turn_receive`, writes on it every packet the stack marks for it
— the Allocate and its refreshes, the permissions, the call's checks and audio,
RTCP and the goodbye, a frame `sipral_network_media_capture` encodes included
— and closes it when the stack says `SIPRAL_TURN_STREAM_CLOSE`, after what was
queued for it. A connection that cannot be made, or breaks, is
`sipral_stack_turn_closed`, which costs the socket its relay. Over TLS the
TURN server is not a SIP server and its certificate names a host, so it is
checked as HTTPS checks one, by trust members of its own:

| Member | For the TURN server |
|---|---|
| `turn_trust` | a `sipral_network_trust_t`, as `trust` is for the SIP servers; zero is the platform's |
| `turn_authority_pem`, `turn_pin_sha256` | as `authority_pem` and `pin_sha256` |
| `turn_server_name` | the name its certificate must carry; null for the address `turn_server` names |
| `turn_client_certificate_pem`, `turn_client_key_pem` | the client certificate presented when it asks for one |

The signalling socket needs nothing of the component: its requests and their
answers go through the stack's own queue and receive call, as `06-nat.md`
says.

## Not yet

- **A main transport on TCP or TLS**, as above.
- **`ResolveNeeded`** is left to the application: a dialog keeps the flow its
  INVITE used, which is the one that survives a NAT.

## Proven

`crates/sipral-net/tests/local.rs` runs the crate against a TLS server and a
name server of its own on loopback: messages both ways over TLS and TCP, every
refusal above with its reason, a pin that ignores name and dates, a server that
requires a client certificate at TLS 1.2 and 1.3, and a domain with no address
located by SRV and reached over TLS checked against the domain.
`crates/sipral-ffi/src/network/tests.rs` does the same through the C ABI:
a stack registers over TLS at a domain only an SRV record names, places a call,
carries its audio both ways, holds it, resumes it and hangs up, everything over
the one connection the component opened, with no socket of the test's own. Its
`relayed` tests run a STUN server and a TURN server of their own: a media
socket is mapped, its relay allocated on the TCP connection the component
opened, and given back on it with a Refresh of lifetime zero before the
connection closes; over TLS the same, the TURN server trusted by its own
authority and checked against its own name while the SIP servers' trust is
the platform's, and the same server held to a name its certificate does not
carry gives no relay and is asked nothing.

`scripts/lab.sh network` runs `interop/network/register-and-hold.c` — a C
program with no socket, TLS or resolver of its own — against Asterisk: the
domain published by a name server beside it as a NAPTR record, an SRV record
and the SRV target's address only, the program registers over TLS 1.2 checked
against the lab authority and the domain, calls the tone, hears it, holds,
resumes, hears it again, hangs up and unregisters.

`scripts/lab.sh turn` runs `interop/network/relayed-call.c`, a C program with
no networking code either, as one more caller across the NAT pair whose block
leaves no path but a relay (`06-nat.md`, "Proven in the lab"): without TURN
its call finds no path; with a relay at both ends over UDP the tone crosses
coturn; and from behind a NAT that drops every datagram to coturn, its relay
reached over TCP and then over TLS — coturn's certificate trusted from the
run's own authority and checked against its name — carries the call, and
coturn's log counts the relay given back.
