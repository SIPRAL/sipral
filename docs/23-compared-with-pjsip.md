<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# Compared with PJSIP, baresip and Linphone

The same scenarios, run one after the other for Sipral's headless agent and
for three other clients, each the binary a Linux distribution ships:
`pjsua`, PJSIP's own command-line client; baresip; and `linphonec`,
Linphone's console client — against the same Asterisk in the lab. Every
time below is read off a packet capture taken in the client's own network
namespace, never off what a client says about itself; memory and CPU are
read from the same `/proc` files for every one; a call's quality is reported
as both ends measured it and rated by one formula for every row. Beside them:
what an application ships to make calls with each, and the four taking calls
side by side for three hours.

The latest runs are two, on one machine, 8 October 2026; the earlier runs,
Sipral and pjsua alone from 29 September to 7 October, follow them. They are
here so anybody can run them again and get their own numbers, not so the
numbers below can be quoted without the conditions beside them.

## Run it

On a Linux machine with Docker, from the repository root:

```bash
cargo build --release -p sipral --example headless-agent
cargo build --release -p sipral-ffi
./scripts/lab.sh compare
SIPRAL_HEADLESS_AGENT=target/release/examples/headless-agent ./scripts/soak.sh compare 3
```

`scripts/lab.sh compare` builds a capture container (Debian trixie with
`tcpdump`, `tc` and `python3`) and one image per client from its
distribution's own packages and nothing else — `apk add pjsua` on Alpine,
`dnf install baresip baresip-opus baresip-g722` on Fedora, `apt-get install
linphone-cli` on Debian — brings the lab's Asterisk up, measures what each
ships, and runs every scenario for each client in turn. It takes about half
an hour. The scenario script is `interop/compare/compare.sh`; what it reads
out of each capture and each client's log is `interop/compare/wire.py`,
whose own tests run in `scripts/check.sh` against captures and logs they
write byte by byte. Every result is printed on a line that starts `cmp`;
captures and each client's log are kept in `interop/pcap/compare/`.
`scripts/soak.sh compare` is the endurance run ("Three hours side by side"
below); it takes no lab lock and runs under a Compose project of its own.

A machine whose Rust build is not Linux names a Linux build of the agent
instead, and the run can be narrowed:

```bash
SIPRAL_HEADLESS_AGENT=/path/to/linux/headless-agent \
SIPRAL_FFI_LIB=/path/to/linux/libsipral_ffi.so \
SIPRAL_COMPARE_CLIENTS="sipral pjsua baresip linphone" \
SIPRAL_COMPARE_PHASES="size plain ice netem move" \
SIPRAL_COMPARE_CALLS="1 4 10 100" \
SIPRAL_COMPARE_PROFILES="lossy mobile satellite" \
SIPRAL_COMPARE_HOLD_S=30 SIPRAL_COMPARE_WINDOW_S=20 \
    ./scripts/lab.sh compare
```

The values shown are the defaults.

## What was run

| | |
|---|---|
| Host | Debian 13, Linux 6.12.95, 32 cores, 62 GB, x86-64, a virtual machine doing other work at the same time |
| PBX | Asterisk 22.10.1 (`interop/compose.yaml`), one account `labuser-compare`, G.711 only, one contact at a time |
| Sipral | the headless agent (`crates/sipral/examples/headless-agent.rs`) at `9d75da6`, the 1.1 tree, release build, Rust 1.99.0, in `debian:trixie-slim`; `libsipral_ffi.so` from the same tree |
| PJSIP | `pjsua` 2.17 from Alpine 3.24's package `pjsua-2.17-r0` (PJ_VERSION 2.17), run as shipped |
| baresip | 4.11.0 from Fedora 44's packages `baresip-4.11.0-1.fc44`, `baresip-opus` and `baresip-g722` of the same version |
| Linphone | `linphonec` 5.3.105 from Debian 13's package `linphone-cli 5.3.105-5`, with `liblinphone12 5.3.105-5`, `libbellesip3 5.3.105+dfsg-4`, `libmediastreamer2-14 1:5.3.105+dfsg-5` |

The three are the newest each distribution had on 8 October 2026: Alpine
edge carries the same `pjsua-2.17-r0`, Fedora 44 the same baresip, Debian 13
the same `linphone-cli`.

**Why these distributions.** Neither Debian 13 nor Ubuntu 24.04 packages
PJSIP at all (`apt-cache search pjproject` and `apt-cache search pjsua` both
come back empty); Alpine's package is the closest thing to "PJSIP as a user
installs it" on a Linux server. Fedora packages baresip with its codec
modules split out, and Debian packages Linphone's console client. Every
client is used only as a binary its distribution ships: no source of any of
them is fetched, built or read.

**How each client was run.** The agent:

```text
headless-agent --register labuser-compare@asterisk --registrar <asterisk>:5060 \
    --pass labpass --invite-burst 200 [--ice] [--codecs PCMU,PCMA] [--call sip:9008@asterisk]
```

It answers every call and plays back what it hears, one frame later.
`pjsua`, with its console on a named pipe so the script can type at it
(`interop/compare/pjsua.sh`):

```text
pjsua --null-audio --auto-answer=200 --auto-loop --max-calls=4 --no-tcp \
    --no-color --log-level=3 --app-log-level=3 --registrar=sip:asterisk \
    --id=sip:labuser-compare@asterisk --realm=* --username=labuser-compare \
    --password=labpass [--use-ice] [--dis-codec=* --add-codec=PCMA --add-codec=PCMU]
```

`--auto-loop` sends back what it receives, the same echo. baresip, with a
configuration `interop/compare/baresip.sh` writes and its console on a UDP
port the script types at:

```text
sip_listen 0.0.0.0:5060   call_max_calls 200   call_hold_other_calls no
audio_player aubridge,nil   audio_source aubridge,nil   rtp_stats yes
modules: opus g722 g711 auconv auresamp aubridge stun turn ice cons
         account menu echo netroam rtcpsummary
account: <sip:labuser-compare@asterisk>;auth_pass=labpass;outbound="sip:<asterisk>"
         [;medianat=ice] [;audio_codecs=PCMU/8000/1,PCMA/8000/1]
```

Its `echo` module answers every call and sends back what it receives. The
registrar is given by address, as to the agent: by name, baresip spends
about ten seconds on SRV and NAPTR lookups through Docker's resolver first.
`linphonec`, answering by itself, with the account and `max_calls=200` in a
linphonerc and its console on a named pipe (`interop/compare/linphone.sh`):

```text
linphonec -a -c linphonerc -d 0        # -d 5 for the bad-link calls, whose
                                       # statistics it prints only at that level
soundcard use files
play /usr/share/sounds/linphone/hello8000.wav
[codec disable 7, 2, 1, 0]             # G.711 alone: Opus, Speex 16k and 8k, G.729
[stun <coturn>:3478, firewall ice]     # ICE needs a STUN server named first
```

`linphonec` has no echo: it plays a file it ships to every call, so audio
still flows both ways. Every client runs in a container that shares the
capture container's network namespace, so the capture sees exactly what the
client sent and received, and moving that container moves the client.

Settings that are not defaults, each there so the clients are asked the
same thing:

- `pjsua --max-calls=4`. Alpine's build was compiled with
  `PJSUA_MAX_CALLS=4`; `pjsua --max-calls=5` refuses to start ("maximum call
  setting exceeds compile time limit"). Its rows past four calls therefore
  say how many came up, and its per-call figures stop at four.
- `headless-agent --invite-burst 200`. The stack refuses INVITEs from one
  address past ten at once and then one every two seconds, answering 480,
  as a guard against scanners (`sipral::Rate`). Asterisk offering a hundred
  calls within a second is exactly the switchboard that guard's own
  documentation says to loosen it for; left at the default, 90 of the
  hundred were refused. The flag changes the burst and nothing else.
- baresip `call_max_calls 200` (its default is 4) and
  `call_hold_other_calls no`, so a second call does not hold the first.
- `linphonec max_calls=200`. Answering by itself it still holds one call at
  a time and answers the others `486 Busy here`; and it refuses a second
  call from an address it already has a call with, so Asterisk places its
  calls from call files, the same channel and extension, each with a caller
  of its own, where every other client's come from `channel originate`.
- The `ifb` device the bad-link phase needs for netem's ingress side is
  made before the client starts, for that phase only: baresip's `netroam`
  reads an interface appearing mid-call as a network change and resets its
  SIP transport, and present during the other phases, pjsua offers ICE
  candidates on it too.

The agent holds 128 calls at once, the stack's default ceiling
(`EndpointConfig::max_dialogs`): a second run on 2 October, with Asterisk
offering two hundred calls at once, brought 128 up and answered the other
72 `503 Service Unavailable`, and its INVITE guard at `--invite-burst 200`
refused 40 of the two hundred with 480 when they came within a second of
the hundred-call row. The agent has since taken `--max-calls N`, which
raises the ceiling and what grows with it, and lets the guard's burst
follow it when `--invite-burst` is not given (the agent's own
documentation); the refusal at the ceiling now carries `Retry-After: 2`.

## Results, 8 October 2026: four clients

Two full runs, one after the other, 17:10 to 17:33 and 17:54 to 18:17 EEST,
with this document's harness and the agent of `9d75da6`. Each cell gives the
second run, then the first. The
endurance run below was taking calls on the same machine throughout, under a
Compose project and an Asterisk of its own; see "Memory and CPU" for the one
column that changes.

### Registering and calling

From the first request to the `200` that accepted it, every client
challenged once by Asterisk:

| | Sipral | pjsua | baresip | linphonec |
|---|---|---|---|---|
| Registration, first REGISTER to its 200 | 3.1, 3.8 ms | 12.8, 12.2 ms | 4.4, 5.4 ms | 25.0, 25.2 ms |
| Outgoing call to Asterisk's echo, first INVITE to its 200 | 5.3, 5.2 ms | 5.6, 4.9 ms | 4.2, 5.2 ms | 7.0, 7.9 ms |
| Incoming call, INVITE to the client's 200 | 0.9, 1.0 ms | 3.3, 3.3 ms | 2.4, 3.5 ms | 14.9, 27.2 ms |
| Outgoing call with ICE, every codec | 3.5, 3.6 ms | 4.9, 4.3 ms | 4.3, 4.7 ms | 31.0, 28.7 ms |

Sipral answers first; the outgoing call is the server's time more than the
client's (the 7 October capture under "Earlier runs" says so for Sipral and
pjsua), and the four are within a millisecond or two of each other.
linphonec asks the STUN server for its candidates before it sends an ICE
INVITE, which is most of its 28 to 31 ms.

### Memory and CPU

Read from the client's own `/proc/1`, as before; a call is one Asterisk
originated to a cadenced tone, G.711 both ways, echoed (linphonec: a file
played back).

**Resident and anonymous memory, MB** (anonymous: the `Anonymous:` line of
`smaps_rollup`, what the client itself allocated):

| Calls offered | Sipral | pjsua | baresip | linphonec |
|---|---|---|---|---|
| idle | 5.8 / 0.7 | 12.7 / 2.4 | 12.2 / 2.0 | 57.7 / 9.9 |
| 1 | 5.9 / 0.7 | 13.7 / 3.4 | 12.2 / 2.0 | 58.8 / 10.9 |
| 4 | 6.2 / 1.0 | 16.7 / 6.4 | 12.8 / 2.6 | 1 up: 58.9 / 10.9 |
| 10 | 6.7 / 1.5 | 4 up: 16.8 / 6.5 | 14.0 / 3.8 | 1 up: 59.1 / 11.1 |
| 100 | 14.1 / 8.9 | 4 up: 16.7 / 6.4 | 30.5 / 20.3 | 1 up: 60.6 / 12.7 |

The first run is within about 0.1 MB of the second in every cell. Growth per call
from ten to a hundred, anonymous: Sipral 84 kB, baresip 188 kB; pjsua 1.0 MB
a call from idle to four.

The private column of the earlier tables is not given: it counts a shared
library's pages as a client's own whenever no other process maps them, and
with the endurance run's four clients mapping the same libraries the
private figures of pjsua, baresip and linphonec fell by 9 to 43 MB between
two readings of the same process. Resident and anonymous memory do not move
with what else runs.

**CPU, % of one core over 20 s:**

| Calls offered | Sipral | pjsua | baresip | linphonec |
|---|---|---|---|---|
| idle | 0.05, 0.00 | 0.60, 0.55 | 0.05, 0.05 | 0.35, 0.40 |
| 1 | 1.10, 1.00 | 6.95, 6.20 | 2.20, 2.35 | 1.55, 1.60 |
| 4 | 1.95, 1.95 | 19.20, 19.25 | 7.55, 7.90 | 1 up: 1.70, 1.60 |
| 10 | 3.90, 3.90 | 4 up: 20.15, 20.75 | 16.85, 17.45 | 1 up: 1.80, 1.80 |
| 100 | 30.20, 30.50 | 4 up: 21.50, 20.60 | 150.75, 150.80 | 1 up: 2.10, 2.00 |

Per call above idle: Sipral 0.48 % of a core at four calls and 0.30 % at a
hundred; baresip 1.9 % and 1.5 %, past a whole core at about 65 calls;
pjsua 4.7 % at four. linphonec answering by itself carries one call and
answers the rest `486 Busy here`, so its rows past one are one call.

**What got worse for Sipral, and why.** Against the 2 October run of the
same harness (the site's figures until now), the agent's idle memory went
from 5.4 to 5.8 MB resident and from 0.6 to 0.7 MB anonymous, 13.7 to 14.1
MB at a hundred calls, and a hundred calls from 27.45 to 30.2 % of a core.
The agent of 2 October (`8687d1c` in today's history, built here with Rust
1.95.0) was run again beside today's in the same harness, twice each:

| | 2 October agent | Today's agent, Rust 1.95.0 | Today's agent, Rust 1.99.0 |
|---|---|---|---|
| Idle, resident / anonymous | 5.3 / 0.58, 5.5 / 0.58 MB | 5.8 / 0.70 MB | 5.8 / 0.70, 5.9 / 0.70 MB |
| A hundred calls, resident / anonymous | 13.6 / 8.8, 13.7 / 8.8 MB | 14.0 / 8.9 MB | 14.2 / 8.9, 14.1 / 8.9 MB |
| A hundred calls, CPU | 30.20, 28.35 % | 28.70 % | 29.35, 27.30 % |

The processor time is the machine's, not the agent's: the 2 October agent
reads 28 to 30 % on it today. One processor figure did move with the agent:
a single call above idle, 0.55 % of a core on 2 October and 1.00 to 1.10 %
now. The 2 October agent spent 0.65 % idle, polling its socket every 5 ms,
and 1.10 to 1.25 % with one call; today's spends nothing idle and wakes on a
10 ms grid only while a call has audio (`docs/19-numbers.md`, 4 October), so
it reads 1.00 to 1.10 % with one call — the same total, all of it now the
call's. From four calls up the two agents cost the same per call. The memory is the agent's, and not the
compiler's: about 0.5 MB more resident and 0.12 MB more anonymous, idle and
at a hundred calls alike, so a fixed cost rather than a cost per call. The
agent reads its SIP socket on a thread of its own since 4 October (two
threads where it had one; `docs/19-numbers.md`, 4 October), and the agent
binary grew from 4 329 800 to 4 527 896 bytes with what 1.1 added; the 4 October runs below
already read 5.8 MB.

### The INVITE

The client's first INVITE and the one it sent again after Asterisk's 401,
as captured; "fragmented" is a datagram over the 1472 bytes a 1500-byte
link carries in one IPv4 packet, which the sender's IP layer split:

| | Sipral | pjsua | baresip | linphonec |
|---|---|---|---|---|
| No ICE | 923 / 1222 B | 1371 / 1670 B, fragmented | 943 to 945 / 1226 to 1228 B | 1134 / 1419 B |
| ICE, every default codec | 1088 / 1236 B, 1 candidate | 1570 / 1869 B, both fragmented, 2 candidates | 1189 to 1196 / 1472 to 1479 B, fragmented in one run of two, 2 candidates | 1309 / 1594 B, fragmented, 2 candidates |
| ICE, G.711 alone | 955 / 1254 B, 1 candidate | 1165 / 1463 B, 2 candidates | 1108 / 1391 B, 2 candidates | 1213 / 1498 B, fragmented, 2 candidates |
| Requests over 1300 bytes sent over UDP | none | yes | yes | yes |

The same sizes as 2 October within a few bytes (the session identifier's
digits). Only Sipral keeps every request under the 1300 bytes RFC 3261
§18.1.1 allows a datagram when the path's MTU is unknown.

### A moved address

As below, the time counted from the moment the new address existed; first
SIP from there, then audio heard there again:

| | Sipral | pjsua, alone | pjsua, told (`I`) | baresip, alone | baresip, told (`/netchange`) | linphonec, alone |
|---|---|---|---|---|---|---|
| First SIP from the new address | 999, 404 ms, a REGISTER | never | 122, 115 ms, a re-INVITE | 1971, 1971 ms, a REGISTER | 1112, 1149 ms, a REGISTER | 1838, 1848 ms, a re-INVITE |
| Audio heard there again | 1013, 420 ms | never | 126, 131 ms | 1991, 1977 ms | 1126, 1170 ms | 1854, 1856 ms |
| Call still up after 20 s | yes | yes, one way | yes | yes | yes | yes |

Read from the cut instead (the last audio that reached the client before a
silence of over 100 ms, off the same captures, Docker's 190 to 240 ms to
give the container its new address inside every figure): Sipral 1240 and
640 ms, pjsua told 360 and 340, baresip 2220 and 2200 alone and 1360 and
1420 told, linphonec 2100 and 2100. linphonec has no command to be told.

Sipral's 999 ms is the slowest move it has been measured at. Its route is
read every half second, and in that run it sent no audio for 1.2 s after
the cut where in every other run its audio left from the new address within
20 ms of it existing. The move alone was then run six more times, the
2 October agent and today's alternately on the same machine: 387, 432 and
435 ms for the first, 370, 393 and 397 ms for today's, a REGISTER first each
time and audio back 10 to 15 ms after it. A hundred more moves, run on
8 October, found it once, at 983 ms against 165 to 408 ms for the rest, and
the agent was not what held it: its own log had followed the move at 400 ms
and its loop kept turning, but its REGISTER and every audio packet it had
sent since the address existed reached the wire together at 983 ms. Linux
holds a datagram until it has the next hop's link-layer address and asks
for it again a second after an ARP request goes unanswered, so the second
was the container's network, not the agent.

### What each ships

What an application has to ship to make calls on Linux x86-64, counted by
`interop/compare/size.sh` in the images the clients ran from: the stack's
library — PJSIP's `libpjsua.so.2`; baresip's `libbaresip.so.28` with the
modules a call needs, the codecs, NAT traversal and media encryption
Sipral's library carries (`g711 g722 opus stun turn ice srtp dtls_srtp`);
Linphone's `liblinphone.so.12` — and every shared library those load, by
`ldd`, each file once, as installed. Left out for every one alike: the C and
C++ runtimes and the loader (glibc's or musl's libraries, `libgcc_s`,
`libstdc++`), which any Linux machine has. "The project's own" are the
libraries its own packages install: PJSIP's `pjproject`, baresip's and
`libre`, and for Linphone the Belledonne Communications projects it is made
of (`liblinphone`, `belle-sip`, `mediastreamer2`, `ortp`, `bctoolbox`,
`belr`, `belcard`, `bzrtp`, `lime`, `bcg729`, `bcmatroska2`).

| MB of 10^6 bytes | Sipral | PJSIP | baresip | Linphone |
|---|---|---|---|---|
| Everything, as installed | 6.36 MB, 1 file | 11.38 MB, 22 files | 13.22 MB, 22 files | 208.50 MB, 173 files |
| The project's own libraries | 6.36 MB | 1.94 MB, 11 files | 1.38 MB, 10 files | 18.84 MB, 11 files |

`libsipral_ffi.so` is the release build of this tree (stripped, as the
release profile builds it, as distribution libraries are), with Opus, the
cryptography and everything else it needs linked in, so its one file is
both rows. The others' own libraries load OpenSSL (5.8 and 6.8 MB of the
PJSIP and baresip totals), Opus, Speex, SRTP and audio-device libraries from the distribution;
Debian's Linphone is built with video and loads FFmpeg, x264, x265, AV1
codecs, ICU and more besides, most of its 208 MB. A build of any of them
configured for audio alone would ship less, and is not what a distribution
installs. Every file counted is listed in `size-<client>.txt` beside the
captures.

## Three hours side by side, 8 October 2026

`scripts/soak.sh compare 3`, 17:23 to 20:27 EEST, on the same machine and
with the same binaries as the runs above: the four clients registered at
once, each with an account of its own on one Asterisk, each in a network
namespace of its own, each taking one call after another for three hours.
A call is the endurance run's (`scripts/soak.sh endurance`): three minutes
of cadenced tone, a DTMF `#`, then Asterisk hangs up — here for every
client, since the others do not hang up on a digit. The registration is held
to one or two minutes, so each client registers again all through the run.
Every minute, from each client's own process: resident and anonymous memory,
processor time, open descriptors, threads (`interop/compare/endurance.sh`).
The raw samples, a row a minute a client, are
`interop/fixtures/compare-endurance-2026-10-08/`; `interop/compare/
endurance.py` reads the table below out of them, and its tests hold it to
these figures. Growth is read as the endurance run reads its own: from the
end of the first hour, by least squares over every row after it.

| | Sipral | pjsua | baresip | linphonec |
|---|---|---|---|---|
| Calls placed / answered / held to the end | 59 / 59 / 59 | 59 / 59 / 59 | 59 / 59 / 59 | 60 / 59 / 59 |
| Registrations accepted (each challenged once) | 123 | 96 | 103 | 103 |
| Resident memory at one hour, at three hours | 6.1, 6.2 MB | 13.8, 13.9 MB | 12.4, 12.5 MB | 57.8, 58.1 MB |
| Anonymous memory at one, two and three hours | 832, 848, 848 kB | 3360, 3380, 3424 kB | 2316, 2340, 2380 kB | 11204, 11532, 11572 kB |
| Anonymous growth after the first hour, per hour | 8.6 kB | 23.4 kB | 30.6 kB | 105.8 kB |
| The same, per call | 0.45 kB | 1.18 kB | 1.54 kB | 5.33 kB |
| Open descriptors, threads | 7, 2 throughout | 6, 5 throughout | 16, 7 throughout | 15 and 5, then 12 and 3 in the last minutes |
| Processor, mean over the three hours | 0.95 % of a core | 5.65 % | 2.21 % | 1.53 % |
| Processor per call | 1.77 s | 10.46 s | 4.08 s | 2.84 s |

None of the four grows in a way three hours can tell from noise: Sipral's
anonymous memory rose 16 kB in the second hour and not at all in the third,
pjsua's and baresip's 20 to 44 kB in each, linphonec's 328 kB in the second
hour and 40 kB in the third. At the rates measured, a day adds 0.2 MB to
Sipral, 0.6 to pjsua, 0.7 to baresip and 2.5 to linphonec; three hours is
not a day, and `scripts/soak.sh endurance` holds Sipral to a week on its own.
No client lost a call, ended one early or stopped registering; descriptors
and threads did not grow. The one call linphonec did not answer was the
harness's: its reading of Asterisk's channels missed linphonec's call in
progress, placed the next one over it, and linphonec answered that one
`486 Busy here`, as it answers any second call. The harness now reads again
when a reading fails rather than taking it for an empty list. For their
first 65 minutes or so the four shared the machine with the runs, builds and
probes above; after that, only with the lab's own week-long run.

## Earlier runs: Sipral and pjsua, 29 September to 7 October

### Registering and calling

From the first request to the `200` that accepted it, both clients
challenged once by Asterisk (two REGISTERs, two INVITEs each):

| | Sipral | pjsua |
|---|---|---|
| Registration, first REGISTER to its 200 | 7.7 ms | 10.3 ms |
| Outgoing call to Asterisk's echo, first INVITE to its 200 | 10.8 ms | 4.6 ms |
| Incoming call from Asterisk, INVITE to the client's 200 | 9.5 ms | 4.2 ms |
| First INVITE, no ICE, size on the wire | 869 bytes | 1373 bytes |

These are single samples on a loaded machine and the difference between the
two is a few milliseconds either way; the agent measured here read its socket
in a loop that slept 5 ms when there was nothing to read, which is where most
of its extra answering time went. It has since stopped sleeping and waits on
the socket instead (unreleased, for 1.1). The same flow run again for Sipral
alone on 3 October, with that agent against the same Asterisk 22.10.1, read
registration 3.5 ms, the outgoing call 5.5 ms, the incoming call answered in
0.7 ms, no measurable processor time idle, and 0.90, 1.70, 3.05 and 26.30 % of
a core at 1, 4, 10 and 100 calls; no log of that run was kept.

**Run again on 4 October, with the logs kept.** The waiting agent (`0939022`)
twice, and the 1.1 agent, whose audio leaves on a steady clock
(`docs/19-numbers.md`, 4 October), twice, the same harness and Asterisk:

| | Waiting agent, two runs | 1.1 agent, two runs | pjsua, two runs |
|---|---|---|---|
| Registration, first REGISTER to its 200 | 3.3, 6.7 ms | 3.3, 3.3 ms | 11.8, 12.1 ms |
| Outgoing call, first INVITE to its 200 | 5.2, 7.6 ms | 5.2, 5.4 ms | 3.9, 4.1 ms |
| Incoming call, INVITE to the client's 200 | 0.7, 0.7 ms | 1.1, 0.7 ms | 3.3, 3.8 ms |
| CPU registered and idle, % of one core | 0.00, 0.00 | 0.00, 0.05 | 0.50, 0.60 |
| CPU at 1, 4, 10 and 100 calls | 1.00, 1.70, 3.30, 27.45; 1.00, 2.00, 3.30, 26.50 | 1.15, 2.15, 3.95, 27.40; 1.35, 1.95, 3.85, 29.15 | 5.15, 17.65, 4 up 18.45, 4 up 18.40; 5.15, 17.95, 4 up 18.25, 4 up 18.75 |
| Resident and private memory, idle | 5.8 / 3.8 MB; 5.8 / 3.8 MB | 5.8 / 3.8 MB; 5.9 / 3.9 MB | 13.1 / 12.5 MB; 13.0 / 12.5 MB |

The 3 October figures sit inside what two runs differ by — registration and
the outgoing call at the low end of their spread, which a single run on a
shared machine moves by 2 to 3 ms — and stand as that run's. Idle, 0.05 % is
one tick of the process's 10 ms clock in the 20 seconds measured. The agent's
memory, 5.8 MB resident and 3.8 MB private idle, is above the 29 September
agent's below; the 1.0.0 agent and this one measure the same on the host (4.4
to 4.6 MB idle), so that growth is older than the change to the loop. The bad
links and the moved address came out within what two draws of the same
profiles differ by. The outgoing call's gap to pjsua is on the server's side:
in a 7 October capture Sipral's authenticated INVITE left 0.17 to 0.23 ms
after the 401 (pjsua's 0.24 to 0.34 ms), and the rest of the time to the 200
was Asterisk's, 3.0 to 5.5 ms for Sipral's calls and 2.4 to 3.4 ms for pjsua's.
`docs/19-numbers.md` has the set-up time on loopback,
before and after. The INVITE sizes are not noise: pjsua offers every
codec its build has (Speex three ways, iLBC, GSM, G.722, Opus, G.711) and
Sipral its default catalogue (Opus, G.722, G.711, telephone-event).

### Memory and CPU

Read from the client's own `/proc/1`: `VmRSS` and the private part of it from
`smaps_rollup`, and user plus system time over 20 seconds with the calls up,
as a share of one core. The idle row is registered with no call; a call is
one Asterisk originated to a cadenced tone, G.711 both ways, echoed back.

| Calls up | Sipral RSS / private | Sipral CPU | pjsua RSS / private | pjsua CPU |
|---|---|---|---|---|
| idle | 4.6 MB / 2.8 MB | 0.65 % | 13.3 MB / 12.7 MB | 0.65 % |
| 1 | 4.7 MB / 2.9 MB | 1.40 % | 14.2 MB / 13.7 MB | 6.55 % |
| 4 | 4.9 MB / 3.1 MB | 2.30 % | 17.3 MB / 16.8 MB | 20.15 % |
| 10 | 5.4 MB / 3.5 MB | 4.35 % | 4 up of 10: 17.4 MB / 16.9 MB | 22.70 % |
| 100 | 12.2 MB / 10.3 MB | 28.65 % | 4 up of 100: 17.3 MB / 16.7 MB | 20.95 % |

Per call, above idle: Sipral 0.41 % of a core at four calls and 0.28 % at a
hundred; pjsua 4.9 % at four. Sipral's memory grows by about 76 kB per call
from ten to a hundred.

What this does and does not say. RSS counts every shared-library page a
process touched, and pjsua is linked dynamically against musl and its own
libraries while the agent links the stack statically, so the private column
is the fairer one. pjsua's CPU is its whole process as configured here,
including its conference bridge, which mixes on a clock whether or not a
device is attached; a PJSIP application built without the bridge would cost
less, and that application is not what a distribution ships.

### A bad link

One call Asterisk originated, held 30 seconds, over each of the lab's
`interop/impairment/` profiles applied both ways on the client's link with
`tc netem` (the egress directly, the ingress through an `ifb` device):

| Profile | netem |
|---|---|
| lossy | `delay 40ms 15ms loss gemodel 4% 40% 60% 2% reorder 1% 30%` |
| mobile | `delay 60ms 30ms distribution normal loss gemodel 2% 40% 60% 1%` |
| satellite | `delay 250ms 10ms distribution normal loss 0.5%` |

Each end's view of the audio it received: Asterisk's from
`pjsip show channelstats`, pjsua's from its own `dq` dump, the agent's from
the line it prints when a call ends. Every row is rated by the same reduced
E-model (ITU-T G.107: G.711 with loss concealment, Bpl 25.1, random loss,
one-way delay as half the round trip plus one packet plus twice the jitter),
so the R and MOS columns differ only by what was measured. Run on 7 October
at `d41dcd0` (Rust 1.95.0, release build), Asterisk and pjsua as above: three
runs of the mobile profile, two of the others, each cell the lowest and the
highest of them:

| Profile | Measured at | Received | Loss | Jitter | RTT | R | MOS |
|---|---|---|---|---|---|---|---|
| lossy | Asterisk, from Sipral | 1447 to 1450 | 7.64 to 7.72 % | 8 to 9 ms | 76 to 79 ms | 69.0 to 69.2 | 3.55 to 3.56 |
| lossy | Sipral | 1468 to 1472 | 7.36 to 7.85 % | 11.8 to 14.3 ms | 66 to 87 ms | 68.7 to 69.5 | 3.54 to 3.57 |
| lossy | Asterisk, from pjsua | 1453 to 1521 | 6.74 to 7.57 % | 9 to 10 ms | 89 to 90 ms | 69.2 to 71.1 | 3.56 to 3.65 |
| lossy | pjsua | 1.5K | 7.0 to 7.8 % | 8.7 ms | 86 to 88 ms | 68.8 to 70.5 | 3.54 to 3.62 |
| mobile | Asterisk, from Sipral | 1496 to 1533 | 2.42 to 4.47 % | 19 to 28 ms | 106 to 137 ms | 76.2 to 81.8 | 3.87 to 4.09 |
| mobile | Sipral | 1517 to 1532 | 3.28 to 4.05 % | 27.6 to 33.6 ms | 93 to 121 ms | 76.5 to 78.8 | 3.89 to 3.98 |
| mobile | Asterisk, from pjsua | 1490 to 1526 | 3.11 to 5.16 % | 18 to 21 ms | 124 to 147 ms | 73.9 to 79.9 | 3.77 to 4.02 |
| mobile | pjsua | 1.5K | 3.0 to 4.1 % | 18.1 to 19.8 ms | 120 to 138 ms | 77.0 to 80.1 | 3.91 to 4.03 |
| satellite | Asterisk, from Sipral | 1590 to 1593 | 0.38 to 0.50 % | 9 ms | 506 to 510 ms | 71.6 to 72.3 | 3.67 to 3.70 |
| satellite | Sipral | 1627 to 1633 | 0.24 to 0.25 % | 12.1 to 12.6 ms | 503 to 515 ms | 71.3 to 72.1 | 3.66 to 3.69 |
| satellite | Asterisk, from pjsua | 1610 to 1617 | 0.43 to 0.49 % | 8 to 9 ms | 499 to 502 ms | 72.4 to 72.6 | 3.71 to 3.72 |
| satellite | pjsua | 1.6K | 0.7 % | 8.5 to 9.1 ms | 500 to 505 ms | 71.2 to 71.7 | 3.65 to 3.68 |

pjsua prints its packet count rounded past a thousand ("1.5Kpkt"), and it is
kept as printed. netem draws its loss at random, so two 30-second calls over
the same profile do not lose the same packets, and the loss of one run says
little about the next: Asterisk lost 2.4 to 4.5 % of Sipral's audio on the
mobile profile and 3.1 to 5.2 % of pjsua's. What the two clients sent was
rated alike by Asterisk on every profile, the jitter included: 19 to 28 ms
on Sipral's audio and 18 to 21 ms on pjsua's over the mobile profile, and a
clean link (netem's `delay 0ms`, two runs) read 0 ms on both.

**Which of Asterisk's two jitter columns is its own.** Until 7 October the
comparison read the jitter under "Receive" in `pjsip show channelstats`,
and the mobile profile read 27 to 40 ms on Sipral's audio against 14 to 23
on pjsua's over six runs between 2 and 7 October (35.0 against 22.0 in the
table this one replaces). That column is not Asterisk's measurement. Read
once a second through a call, beside a capture, the "Receive" jitter changes
only when the client's RTCP report arrives, and then to the jitter that
report carries — the client's reading of Asterisk's audio, 34.2, 36.6, 28.4,
35.2, 28.2 and 30.4 ms in turn for the agent, the value printed each time;
in three earlier runs it was the agent's last report to the tenth of a
millisecond (35.0, 33.0 and 37.2). The "Transmit" jitter moves with every
packet and stays near what Asterisk's own reports to the client say of the
client's audio. So the old rows compared the agent's reading of a link with
Asterisk's, which differ for the reason below, and `interop/compare/wire.py`
now reads the "Transmit" one. The counts are the right way round.

**Why the agent reads more jitter than pjsua.** The two clients estimate it
differently, not hear different links. Over the mobile profile netem's 30 ms
of normal spread puts about a third of the packets behind a later one. By
RFC 3550's estimator (§6.4.1, A.8), applied to every packet in the order it
arrived, the audio Asterisk sent read 29.8 to 33.9 ms on the agent's side of
the link and 33.4 to 35.5 ms on pjsua's, in the captures taken after the
impairment; the agent reported 27.6 to 33.6 ms, which is that estimator, and
pjsua 18.1 to 19.8 ms. pjsua's reports follow the same estimator with every
packet that arrives behind a later one left out — 20.4 to 23.4 ms on the same
captures — and Asterisk's own reading of either client's audio does the same.
Neither way is a fault: the RFC's counts every packet, and the other says
more about what a jitter buffer has to absorb. The agent's lower R and MOS
on the audio it received come from that higher jitter in the rating's delay
term (twice the jitter) and from its round trip, the last RTCP exchange's
rather than pjsua's average over the call; what its jitter buffer and loss
concealment made of the audio is not what this table measures. The agent's
own rating, from its RTCP XR VoIP metrics block (RFC 3611), read lower again
in these runs — R 32 to 34, 48 to 53 and 83 to 84 over the three profiles —
because the stack rated G.711 with the Bpl of 4.3 that G.113 gives it
without concealment, where the stack conceals every lost frame and the
uniform rating assumes it does. It now rates G.711 with the Bpl of 25.1 for
G.711 with concealment (`sipral-rtp`'s `emodel.rs`, as G.107's Table 3 asks:
the Bpl must match the concealment in use); run again on 8 October, the same
profiles read R 70 to 72, 82 to 84 and 81 to 83. Its delay term now takes
the end system delay of RFC 3611 §4.7.3 too, the jitter buffer's nominal
delay and one packet, and one later run that day read R 69, 80 and 80,
beside the uniform 66.6, 76.5 and 71.7. It is printed beside the
uniform one in the `cmp` lines (`own_r`, `own_mos`).

**The senders, 4 October.** The bad-link phase was run with a capture in
each client's network namespace, the profiles' rules unchanged, beside a
call over a clean link. The agent's frames did leave unevenly: 16, 24 or
28 ms apart rather than 20 on a clean link, a standard deviation of 5.7 ms
where pjsua's was 0.5 to 0.7. The 1.1 agent sends on a steady clock
(`docs/19-numbers.md`, 4 October): 0.05 to 0.20 ms. Read where the packets
leave the impaired link, the audio each client sent carries the same jitter
by RFC 3550's estimator — a mean of 34.3 to 36.1 ms for the agent before and
after the change, 33.7 to 35.3 ms for pjsua — and 29.9 to 33.9 ms against
35.1 to 41.9 ms in the 7 October runs above.

### A moved address

One call up, then the client's container taken off the lab network and put
back at a different address, as a laptop or a phone changes networks.
Measured from the moment the new address existed:

| | Sipral | pjsua, left alone | pjsua, told (`I`) |
|---|---|---|---|
| First SIP from the new address | 394 ms, a REGISTER | never | 123 ms, a re-INVITE |
| First audio sent from there | 3 ms | 17 ms | 1 ms |
| First audio received there again | 417 ms | never | 126 ms |
| Call still up after 20 s | yes | yes, one way | yes |

The agent notices the move itself: it asks every half second which address
the route to its registrar leaves from, and when that changes it binds its
signalling there, re-registers, and offers every call again from there
(`UserAgent::network_changed`, `docs/16-lifecycle.md`). Most of its 394 ms
is that half-second poll; a platform that announces a network change saves
it. pjsua does nothing about a new address on its own — its audio keeps
leaving from the new address and Asterisk keeps sending to the old one — and
recovers in 126 ms once its console's `I` ("IP change") is typed, which is
what an application built on PJSIP does when the platform tells it the
network changed. Told the same thing, both do the same work; pjsua's
re-INVITE comes first and its registration after, Sipral's the other way
round. The agent has since taken the same word from its platform: a line
`netchange` on its standard input reads the route at once rather than at the
next half-second look, and tells the stack the network changed even when the
address did not (it registers again then).

**Read from the cut.** Counting from the new address existing leaves out the
time the link was down, and a client that moved before the measurement's own
clock started reads as faster than it was. The 2 October run read the move a
second way off the same captures: from the last audio packet that reached the
client before the first silence over 100 ms — the cut — to the first SIP and
the first audio heard at the new address. The 190–240 ms Docker takes to
give the container its new address is inside every figure alike.

| From the cut, two runs | Sipral | pjsua, left alone | pjsua, told (`I`) |
|---|---|---|---|
| First SIP from the new address | 197, 219 ms, a REGISTER | never | 349, 388 ms, a re-INVITE |
| First audio received there again | 220, 240 ms | never | 360, 400 ms |

Read from the new address existing, the same runs gave the agent's first
REGISTER 17 ms after it and its audio back at 38 ms: the half-second poll
happened to fall just after the move, which is why the cut is the fairer
clock for it.

### The INVITE with ICE

| | Sipral | pjsua |
|---|---|---|
| Every default codec, ICE | 1034 bytes, 1 candidate; with credentials 1333 bytes, not sent over UDP | 1570 bytes, 2 candidates, sent over UDP as two IP fragments; call set up in 6.1 ms |
| The same, 2 October | 1088 bytes, 1 candidate; with credentials **1236 bytes, sent over UDP whole**; call set up in 8.0–8.4 ms | 1570 bytes; with credentials 1868 bytes; both sent as IP fragments |
| G.711 alone, ICE | 954 bytes, 1 candidate; call set up in 9.2 ms | 1164 bytes, 2 candidates; call set up in 4.1 ms |

Sipral offers one candidate per stream because it multiplexes RTCP with RTP
where the answer allows (RFC 5761); pjsua offers RTP and RTCP as two
components. The larger row is where the two differ in behaviour: RFC 3261
§18.1.1 says a request within 200 bytes of the path MTU, or over 1300 bytes
when the MTU is unknown, goes over a congestion-controlled transport, and
Sipral holds to that — its core refuses to put the 1333-byte authenticated
INVITE in a datagram and asks the application for TCP
(`transport wanted: Tcp ... for a request of 1333 bytes, over the 1300 a
datagram may carry`). The headless agent opens no TCP transport, so that call
does not happen from it; an application that opens one when asked places it.
pjsua was run with `--no-tcp`, as UDP alone is what it is being compared on,
and sends its 1570-byte INVITE over UDP regardless, which the IP layer
fragments; on a path with a NAT or firewall that drops fragments, that
INVITE is lost. (The run's own `cmp` line read that INVITE as 1472 bytes with
one candidate, its first fragment; the figures above were read again from
the kept capture once `wire.py` reassembled fragments, which its tests now
cover.)

This run predates the compact form: the endpoint now writes a request that
is over the datagram limit compact first (RFC 3261 §7.3.3,
`docs/03-core-signalling.md`), then without its `Allow`, and asks for a
stream only if it is still over. Against the live PBX in
`docs/11-testing.md`, that took a challenged INVITE from 1389 bytes to 1239,
sent over UDP with no stream asked for. The same scenarios run again on
2 October (the agent at `bb8435b`, the same `pjsua`, the same lab) read the
authenticated INVITE with ICE and every default codec at 1236 bytes: under
1300, so it went over UDP in one datagram, unfragmented, and the call came
up from the agent with no TCP asked for. Its first INVITE was 1088 bytes;
without ICE, 923 and 1222. pjsua's authenticated INVITE left in IP
fragments in that run with ICE (1868 bytes) and without it (1670).

## What is not compared

- More than four simultaneous calls in pjsua, which its packaged build does
  not allow, or more than one in linphonec answering by itself.
- TLS, SRTP and TCP: the other three clients have them, the agent does not
  open a stream transport, and a comparison of one side's handshake with the
  other's absence would say nothing.
- Audio quality as heard: the clients echo a tone (linphonec plays a file)
  and nobody listens. The figures are the transport's.
- Sofia-SIP and reSIProcate: no distribution checked on 2 October 2026
  (Debian 13, Ubuntu 24.04 and 25.04, Fedora 44, Alpine 3.24) ships a SIP user agent built on either, and
  the comparison runs only what a distribution ships.
- A NAT between the client and the PBX: the lab network is flat, and
  `scripts/lab.sh nat` covers Sipral alone behind one.
