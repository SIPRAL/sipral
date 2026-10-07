<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is semantic from 1.0.0. The release's version and the C ABI's are
two numbers, each moved by its own rule (`docs/08-ffi.md`, "Versioning").

## [Unreleased]

### Added

- **LiveCommunicationKit on iOS 17.4 and later, as an alternative to CallKit.** `LiveCommunicationBridge` reports incoming and outgoing calls to the system and routes its join, end, mute, pause and tone actions, its audio session and its reset to the bound `Call`, behind `LiveCommunicationProviding`, tested on macOS against a recording provider; `LiveCommunicationAdapter` is the real `ConversationManager` behind it, built for iOS, the simulator and Mac Catalyst. `CallKitBridge` and `CallKitAdapter` are unchanged (`docs/15-mobile.md`, "LiveCommunicationKit"). No C ABI change.
- **DTLS-SRTP proven against OpenSSL, and its state machines fuzzed as a pair.** `scripts/lab.sh dtls-interop`, part of a run that names nothing, runs the handshake against `openssl s_server`/`s_client -dtls1_2 -use_srtp` with no SIP in between: in both roles and on all four profiles the RFC 5764 keying material is identical on both ends, and a certificate the fingerprint does not name, no common profile and DTLS 1.0 are refused either way round (`docs/11-testing.md`, "DTLS-SRTP against OpenSSL"). A new fuzz target, `dtls_connection`, puts the fuzzer on the path between a real client and server; five minutes found nothing.
- **A voice agent with no key, all on one machine.** `sipral_agents.local` (`LocalAgentServer`, `LocalAgent`, `WhisperServer`, `Ollama`, `SystemVoice`, `CommandVoice`, `EnergyVad`) and `integrations/agents/examples/local_agent.py`: whisper.cpp listens, a small Ollama model answers a sentence at a time, the system voice speaks, a turn ends on 700 ms of quiet and the caller talking over the agent cuts it short. On an Apple M2 the caller heard the first sound of an answer 4.3 to 7.1 s after the question; the example places such a call itself (`--ask`, `--barge-in`). No new dependency.
- **The Node.js layer reaches the whole ABI.** SIP over TCP and TLS (`TlsTrust`: the platform's authorities, a private one, only one, or a pinned certificate; the connection made again with back-off), an account's own TCP or TLS connection, a request too large for a datagram moved to a stream, device mode (the engine's packets cross from a worker thread, so the engine never waits on the application's), `Audio`, `LocalConference`, subscriptions with presence, dialogs and a conference's picture, MESSAGE, OAuth 2.0 tokens (`TokenRequired`), the network test, servers located by name through a resolver, STUN and TURN on media sockets, ringing, redirects, real-time text, recording, three-way calls, screening, processors, logs and diagnostics, and every event's whole payload as `fields`; 59 tests on loopback.
- **The resource and `Host` of a WebSocket are the application's to name, and SIP over a secure WebSocket is proven against Asterisk.** `sipral_account_config_t::websocket_host` and `websocket_resource` (ABI 1.2, appended) set what the handshake of an account's own WS or WSS connection asks for, `/ws` and the server's address when left out; `Account::websocket_target` in Rust. Swift, .NET, Kotlin, Python, Dart, React Native and Node take `ws` and `wss` as an account's own connection and the two values beside it; such an account's `Contact` naming an IP address names a `.invalid` host instead (RFC 7118 §5). `scripts/lab.sh wss` registers, calls the echo and hangs up over Asterisk's TLS listener on 8089 (`docs/11-testing.md`).
- **Node.js and TypeScript.** `bindings/node`, the `sipral` npm package (not yet published): `tools/abi-gen` prints its raw layer, `src/sipral_abi.ts`, for koffi 3.3.2 (MIT, prebuilt, no compiler at install), and `Stack`, `Account`, `Call` and `Media` are written over it in TypeScript, events as an `EventEmitter` and an async iterator, each call's PCM in the application's hands. Tested on loopback with a tone each way, DTMF, a transfer refused and one taken, and a registration through a simulated registrar's digest challenge, as a new area of the gate, `scripts/check.sh --only node` (`docs/08-ffi.md`, "Node.js"). No C ABI change.
- **The lab proves FusionPBX, caller identity, diversion, redirection and failover.** `scripts/lab.sh fusionpbx` runs FusionPBX 5.6.5 -- its database, schema, domain, extension and dialplan, and FreeSWITCH on FusionPBX's own configuration and scripts (`interop/fusionpbx`) -- and the harness's registration, call, hold, both transfers, RFC 4733 digit, DTLS-SRTP and compact flows straight at it, then a call to its own echo. `scripts/lab.sh identity` has the Python layer send a `P-Asserted-Identity` Asterisk takes and asserts again to a second account that reads it from a trusted peer, read a `Diversion` on a call Asterisk marked diverted, and follow a 302 on calls placed asking to (`interop/identity/scenarios.py`); `scripts/lab.sh locate` registers and calls through the second of two SRV targets when the first is dead. VitalPBX is not in the lab: it is closed source with no image, and its installer turns a whole Debian 12 machine into the PBX under systemd, with firewalld and fail2ban, then reboots it (`docs/11-testing.md`).

- **SIP over a WebSocket the stack opens (RFC 7118 on RFC 6455).** A TCP connection, or a TLS one the application secured, bound as `Ws` or `Wss` with its far end named becomes a WebSocket the stack runs: the handshake asking for the `sip` subprotocol, every message in a masked frame, fragments reassembled, pings answered and sent, a close answered or sent (`UserAgent::close_websocket`), and a `Via` and `Contact` naming a random `.invalid` host. An account's WebSocket is asked for and reconnected like its TCP or TLS connection (`Account::on_stream`, or `stream_protocol` in the C ABI), and a WebSocket given up on is `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` with the reason. `UserAgent::set_websocket_target` sets the resource and `Host` (`/ws` and the address otherwise). No C ABI change; `docs/04-ua.md`, a fuzz target for the frame reader, and `scripts/lab.sh websocket` registering and calling Asterisk's echo over one.
- **A network test before a call (C ABI 1.2).** `sipral_stack_network_test` asks, without placing a call of its own, whether a STUN server answers and what its answer says about the NAT, whether the TURN server allocates a relay, whether the account's server answers an `OPTIONS` on the account's own transport and how fast (`UserAgent::probe_server`), and, given a call the application placed to an echo service, the loss, jitter, round trip and G.107 R and MOS of what comes back before it hangs the call up; `SIPRAL_EVENT_KIND_NETWORK_TEST` (60) carries every part and a verdict, good, acceptable or poor, by thresholds written down in `docs/25-network-test.md`. Python `Stack.network_test`, Swift `SipralStack.networkTest`, .NET `SipralStack.NetworkTest`, Kotlin and the JVM jar `SipralClient.networkTest` and `networkTestOf`, Dart `SipralStack.networkTest`, React Native `client.networkTest` and the `networkTest` event.
- **Answering-machine detection on the calls a voice agent places.** `sipral_agents.dial` places a call, lets the library decide who answered, and joins the agent for a person; for a machine it hangs up, connects at the beep to leave a message, or connects anyway, as the account's `MachinePolicy` says, with the detector's limits set per policy. The bridge's file carries it as `[accounts.machine]`, and `python -m sipral_agents bridge.toml --dial TARGET --from AOR` places one call (`docs/24-voice-agents.md`, "Calls the agent places"). Tested on loopback with a synthesised person, a greeting that runs on, and a greeting and its beep. No C ABI change.
- **Ringing, header fields and transfer in Python.** `Stack.ring_call` (a 180, or a 183 with `media=True`), `Call.ring`, `Call.ring_media`, `Call.transfer`, `Call.set_headers`, `headers=` on `Stack.place_call` and `Stack.accept_transfer_placed`; .NET gains `SipralStack.AcceptTransferPlaced`. The SIP bridge in `sipral-agents` uses them instead of the C entry points: the caller's context goes on the INVITE to the agent, an outcome on the agent's BYE is read, and a transfer it places itself is reported to the agent's REFER.
- **What a bridge between two calls needs (C ABI 1.2).** A REFER the far end refuses outright, or never answers, is now `SIPRAL_EVENT_KIND_TRANSFER_DONE` with its status instead of silence; `SIPRAL_EVENT_KIND_CALL_ENDED` of a call the far end hung up carries its BYE, so a field on it can be read; and `sipral_call_accept_transfer_placed` (`UserAgent::accept_transfer_placed`) answers a REFER 202 and reports a call the application placed itself in the NOTIFYs (`docs/08-ffi.md`, "What ABI 1.2 added").
- **A phone voice agent in one command.** `python -m sipral_agents.demo` answers calls -- directly from a softphone, or on a PBX extension with `SIPRAL_REGISTRAR_ADDRESS` and the account's settings -- and joins each to OpenAI Realtime when `OPENAI_API_KEY` is set, or with no key to a local echo agent speaking the same WebSocket protocol, so the whole path is heard working without an account. `integrations/agents/README.md`, "A voice agent in five minutes"; `tests/test_demo.py` calls it on loopback and hears its tone back.
- **A ready-to-run bridge from a configuration file.** `python -m sipral_agents bridge.toml` (the `sipral-agents` command) registers every account a TOML file lists and hands each call to the agent named for its account: one of the five WebSocket services, or a SIP address through the SIP bridge, which moves from `bindings/python/examples/agent_bridge.py` into the package as `sipral_agents.sip_bridge`. Keys and passwords come from the environment variables the file names (`api_key_env`, `auth_password_env`) and a secret written in the file is refused; `--check` prints the routes without starting. `integrations/agents/examples/bridge.toml`, `docs/24-voice-agents.md`; tested with a bridge started from a file against a local OpenAI stand-in and a SIP agent on loopback.
- **A call joined to ElevenLabs Agents, Vapi or Deepgram Voice Agent over WebSocket.** `sipral-agents` gains `ElevenLabsAgent` (the conversation WebSocket at the agent's PCM rate, 16 kHz by default, its pings answered and audio from before an interruption dropped), `VapiAgent` (one Vapi call per SIP call, created with `POST /call` and a `vapi.websocket` transport in `pcm_s16le` at 16 kHz, `hangup` sent when the caller leaves) and `DeepgramAgent` (`linear16` at 24 kHz in binary frames, the listen, think and speak providers named by the application). The core gains `Provider.prepare`, `Provider.farewell`, a `Reply` signal and `SessionRefused`, which ends the call with the reason `refused` instead of retrying. Tested against local stand-ins written from each vendor's public protocol documentation, read on 7 October 2026; `docs/24-voice-agents.md` `examples/livekit_bridge.py` puts a call in a LiveKit room as a participant with LiveKit's Python SDK (Apache-2.0, the example's only), run against a local `livekit-server --dev`.
- **A call joined to OpenAI Realtime or Gemini Live, with no framework.** `sipral-agents`, a Python package in `integrations/agents`, answers each call with `serve(account, factory)` (or joins one with `AgentCall`) and connects it to the service's WebSocket API: the call's frames switched to the service's 24 kHz with `Media.set_app_rate`, the agent's audio paced a codec frame at a time with at most 40 ms queued so a barge-in silences it at once (OpenAI's turn truncated to what the caller heard), events for the application, reconnection with exponential backoff (Gemini sessions resumed, `goAway` followed at once), and either side's end ending the other. A `Provider` subclass is all another service needs. Its tests join real calls on loopback to local stand-ins written from each vendor's public protocol documentation, as a new area of the gate, `scripts/check.sh --only agents`; nothing was run against the vendors' services. No C ABI change.
- **OAuth 2.0 sign-in to the PBX (RFC 8898, C ABI 1.2).** A server that challenges with `Bearer` is answered with `Authorization: Bearer <token>` (RFC 6750) from the access token the application supplies; the stack never contacts the authorization server. `SIPRAL_EVENT_KIND_TOKEN_REQUIRED` (`UaEvent::TokenRequired`) names the `authz_server`, the `scope`, the realm and the server's `error` when the account's own server wants a token the account does not have or has had refused (`invalid_token`); `sipral_account_set_access_token` (`UserAgent::set_access_token`) hands it over, and a refused token is never offered to that server again. Offered Digest and Bearer for one realm, the token answers. Swift `Account.setAccessToken`, .NET `Account.SetAccessToken`, Kotlin and the JVM jar `SipralAccount.setAccessToken` and `tokenRequiredOf`, Python `Account.set_access_token`, Dart `SipralAccount.setAccessToken`, React Native `account.setAccessToken` and the `tokenRequired` event (`docs/04-ua.md`, "OAuth 2.0 access tokens"; `docs/08-ffi.md`, "What ABI 1.2 added").
- **A voice agent's first frame and first reply, measured; and a day-long endurance run.** `scripts/soak.sh latency` times three hundred calls through the lab's Asterisk to the headless socket application and its echo agent, both with a new `--timings` flag: 31.5 ms median (31.9 ms p95) from the INVITE to the agent's first audio frame, 20.4 ms (20.6 ms p95) from the agent's first reply to the RTP packet carrying it. `scripts/soak.sh endurance` keeps the pair taking three-minute calls and registering again every two minutes for a day, sampling memory, processor time, descriptors and errors each minute (`docs/19-numbers.md`).
- The gate's `windows` area runs the Python binding's tests on a real Windows x64 machine, against a `sipral_ffi.dll` built there from the tree.

- **The platform's echo cancellation is switched on a running stack (C ABI 1.1).** `sipral_audio_set_system_echo_cancellation(stack, on)` turns the platform's own canceller on or off without a new stack: open devices are reopened at once with or without it (the voice-processing unit on macOS and iOS, the communications stream on Windows, the voice-communication preset on Android), on the devices they were on and with their gain and mute, and a call keeps its media through the short gap; `sipral_audio_info_t` and `sipral_stack_settings_t` report the new state. Application mode is `SIPRAL_STATUS_WRONG_STATE`. Swift `AudioDevices.setSystemEchoCancellation`, .NET `SipralAudioEngine.SetSystemEchoCancellation`, Kotlin and the JVM jar `SipralAudioDevices.setSystemEchoCancellation`, Python `Audio.set_system_echo_cancellation`, Dart `SipralStack.setSystemEchoCancellation`, React Native `client.audio.setSystemEchoCancellation` (`docs/08-ffi.md`, "What ABI 1.1 added").
- **The application chooses the rate of a call's frames (C ABI 1.1).** `sipral_media_set_app_rate(media, hz)` hands out and takes a call's PCM at 8, 16, 24 or 48 kHz whatever the codec negotiated, converted both ways by the library's own resampler, with the frame keeping the call's duration and `sipral_media_info_t` reporting the rate chosen; 0 is the codec's own rate, the default. Any other rate is `SIPRAL_STATUS_INVALID_ARGUMENT`, and device mode `SIPRAL_STATUS_WRONG_STATE`. Every binding carries it on its media object: Swift `Media.setAppRate`, .NET `CallMedia.SetAppRate`, Kotlin and the JVM jar `SipralMedia.setAppRate`, Python `Media.set_app_rate`, Dart `SipralMedia.setAppRate`, React Native `call.audio.setAppRate`. A binding printed at ABI 1.0 still loads; one printed at 1.1 is refused by a 1.0 library (`docs/08-ffi.md`, "What ABI 1.1 added").
- **A bridge from a PBX line to a voice agent that answers SIP itself.** `crates/sipral/examples/agent-bridge.rs` and `sipral_agents.sip_bridge` (in `integrations/agents`) register as an extension, call the agent's SIP address for each caller and join the two calls in a local conference without this end: digits forwarded both ways, either hangup ending the other, the outcome told to the PBX on the BYE or by a REFER, a REFER from the agent passed to the PBX, the caller's number, name and `X-` fields sent to the agent, and a longest duration for the agent's call. `docs/07-headless.md`, "Bridging a call to a voice agent that speaks SIP"; `tests/agent_bridge.rs` and `scripts/lab.sh bridge`. No C ABI change.
- **`docs/24-voice-agents.md`: connecting Sipral to AI voice-agent services.** The three paths -- a SIP bridge that answers a call and joins it to a second call placed to the service, a Pipecat transport (`sipral-pipecat`), and the call's PCM for an application that talks to the service's WebSocket API -- and, for 44 speech-to-speech APIs, hosted agent platforms, frameworks and speech engines, the path that reaches each one, its SIP address, transports, codecs and admission rules or its streaming audio format, with the vendor documentation each fact was read from.
- **A Pipecat pipeline runs on a call.** `sipral-pipecat`, a Python package in `integrations/pipecat`, makes one call in application audio mode a Pipecat transport: the caller's frames become input audio frames at the call's own rate, which Pipecat resamples as its services need; the pipeline's audio goes to the call a codec frame at a time in real time, with never more than 40 ms queued, so an interruption silences it at once; keypad digits cross as Pipecat's DTMF frames both ways; the call's end cancels the pipeline and the pipeline's end hangs up. `serve(account, factory)` answers every call to an account with a pipeline of its own. Its tests run two stacks on loopback with no network and no key, as a new area of the gate, `scripts/check.sh --only pipecat`.
- **.NET: transfer, ringing, screening and a refreshed registration without the raw ABI.** `Call.Transfer(target)` (blind, RFC 3515) and `Call.TransferTo(other)` (attended, RFC 3891), with `Call.WaitForTransferAsync()` returning the `TransferDone` the transfer ends with; `SipralStack.AcceptReferral` and `RejectReferral` take a `TransferRequested` as they take a referral. `SipralStack.RingCall(args)` sends 180 and `SipralStack.RingCallWithMedia(args, ...)` sends 183 with early media and returns the `Call` to answer. `SipralStack.Screen(policy)` installs an INVITE screening policy over `sipral_stack_screen`, each INVITE handed over as a `SipralInvite` with its source, bytes and headers. `Account.RefreshBinding()` sends the REGISTER refresh now. Each is proved on loopback stacks in `Sipral.Tests/CallControlTests.cs`. No C ABI change.
- **A call's own codec order in every binding, placing and answering.** `sipral_call_config_t::codecs` reached Swift and Kotlin already; it now reaches .NET (`SipralCallOptions.Codecs` for `PlaceCall` and `AnswerCall`), Python (`codecs=` on `place_call`, `answer_call` and `Call.answer_with`), Dart (`codecs:` on `placeCall` and `answerCall`), the JVM jar (`SipralJava.placeCall` and `answerCall`) and React Native (`call.answer({codecs})`, beside `placeCall`'s). An answer keeps the offer's order (RFC 3264 §6.1), so an answering list chooses which codecs rather than which comes first. Every binding tests that `PCMA,PCMU` settles on PCMA, placing and answering. No C ABI change.
- **A call answered 3xx can be followed.** A call placed with `OutgoingCall::follow_redirects` (`sipral_call_config_t::follow_redirects`, new in ABI 1.2; `followRedirects`, `follow_redirects` or `SipralCallOptions.FollowRedirects` in the layers) goes again to the 3xx's `Contact` targets, most preferred first, as a new INVITE of the same call -- the same `Call-ID`, `From` and `To`, the next number, the target as Request-URI (RFC 3261 §8.1.3.4) -- and a target that refuses is followed by the next one. A 380, a 6xx, a target already tried and a forked call are not followed, and one call places at most eight redirected INVITEs. Off by default: a 3xx still ends the call with its status and its `Contact` readable, as ABI 1.0 and 1.1 promised; the voice-agent bridge and `scripts/lab.sh identity` turn it on (`docs/04-ua.md`, "Following a call sent somewhere else").

### Changed

- **Dependencies brought up to date.** `rsa` 0.10.0-rc.19; the .NET tests on `xunit` 2.9.3, `xunit.runner.visualstudio` 4.0.0 and `Microsoft.NET.Test.Sdk` 18.10.1; Gradle 9.8.0 for the Kotlin Android build; the Linux build images on `rust:1.99-trixie`, the toolchain the workspace is pinned to. Every other crate, npm, Maven, Android and Dart dependency was already at its latest release.
- **Fixed-size blocks are read as arrays.** The hashes (MD5, SHA-1, SHA-256, SHA-512), the codecs (G.722, G.729, L16), RTP's CSRC and RTCP's BYE lists and the packet checksum split their input with `as_chunks`, so each block has its length in its type and the fallbacks that stood in for a short block are gone; the output is bit for bit what it was.
- **.NET: the stack's, an account's and a call's raw handles are public** (`SipralStack.Handle`, `Account.Handle`, `Call.Handle`), for an entry point of `sipral.h` the classes do not wrap yet, as the Kotlin, Python and Swift layers already allow.
- **Every binding's `unregister` says where an editor shows it what the state does.** It reads unregistered as soon as the call returns, and the registrar's answer is the registration-changed event after it; an application that closes the stack on the state alone cannot answer a challenge to the un-REGISTER (`docs/08-ffi.md` said so already).
- **The gate checks every dependency for known vulnerabilities, in every language.** `scripts/check.sh` runs `osv-scanner` over the Cargo, npm, NuGet, Maven and Python dependencies on each run, `--hygiene-only` included; the advisories that do not apply are set aside in `osv-scanner.toml` with their reasons, and listed in `SECURITY.md`.
- **The .NET assembly names no build path, and the repository asks for a bug report or feature request in a form.** `Sipral.csproj` maps the project directory to `/_/`; GitHub issue forms for bugs and features, with questions sent to Discussions and vulnerabilities to private reporting.

### Fixed

- **The lab's RFC 4733 digit runs through the proxy to FreeSWITCH.** Its 9003 hung up straight after `send_dtmf`, which only queues the digit, so the call ended before the digit was sent back; it now stays up on silence until the caller hangs up, as FusionPBX's does instead of a two-second sleep (`docs/11-testing.md`).
- **Kotlin and the JVM jar read a caller's identity while the stack is polled.** `SipralClient.callerIdentity` and `answering` read each identity text straight from the stack, so a read that met the client's own poll thread failed with `BUSY` instead of waiting it out as every other call does; they now retry the same way.
- **A digit is reported however its packets were played.** RFC 4733 events were read only as the jitter buffer played them, so a key pressed while the buffer skipped a backlog, shortened a pause or found a packet behind its playout point was never reported -- after a receive loop that stalled for a few hundred milliseconds, a press the far end sent was gone for good. They are now read as they arrive, the in-band detector still telling a press heard both ways apart from two. No C ABI change.
- **A voice agent hears the caller from the moment its session is connected.** `sipral_agents` dropped the caller's queued audio when the task sending it to the service started, which on a loaded machine came well after `CONNECTED`: what the caller said first after a connection or a reconnection never reached the service. The audio from before the connection is now dropped before `CONNECTED` is reported, and nothing after it.
- **A far end that hands its media to another sender is heard.** When a re-INVITE moved the far end's media address and a last packet from the old address was read after it -- Asterisk's `direct_media`, handing a call's media from itself to the phone at the other end -- that packet's SSRC became the stream's, and every packet from the new sender was refused as a second source for the rest of the call: no audio either way between two phones Asterisk bridged directly. The stream now starts again under the new sender's SSRC when the latch closes on the new address (`sipral-rtp`). No C ABI change.
- **Python on Windows: a TCP or TLS stack whose connection is down keeps running.** With no socket to watch -- the first connection refused, or one lost and not yet made again -- the poll thread called `select()` on nothing, which Windows refuses with WinError 10022, and the thread ended: no transport-failed event, no reconnection, no REGISTER on the new connection. It now waits out the interval instead, and a SIP datagram the system refuses to send is lost as on the wire rather than ending the thread. The TURN tests' fake server now listens on the address the stacks are bound to, which Windows needs to deliver a datagram to it.
- **The comparison with PJSIP reads Asterisk's own jitter.** `scripts/lab.sh compare` took the jitter under "Receive" in `pjsip show channelstats`, which is the client's RTCP report of Asterisk's audio relayed back; it now reads the "Transmit" one, Asterisk's own measurement. On the mobile profile Asterisk's jitter on the agent's audio, given as 35.0 ms against pjsua's 22.0 (27 to 40 against 14 to 23 over six runs), is 19 to 28 ms against 18 to 21 over three; on a clean link 0 ms for both, not the 5 and then 1 ms the 1.1.0 entry gave. The agent's own jitter stays higher than pjsua's because it counts every packet as RFC 3550 says, where pjsua leaves out those arriving behind a later one (`docs/23-compared-with-pjsip.md`).
- **The gate runs on Linux.** `scripts/check.sh` looked for `libsipral_ffi.dylib` on every system, so on Linux the Python, Pipecat, .NET and Dart areas failed without running; it now looks for `libsipral_ffi.so` there. It sets a UTF-8 locale itself, since under the C locale the language scan read Romanian letters as bytes and flagged two dozen files that hold none. And the Opus fuzz seed is written out rather than encoded on each run: libopus's encoder writes a different packet on x86-64 than on arm64, both valid, so the corpus depended on the machine that checked it.
- **The bridged-conference test in every binding counts what was heard, not an unbroken run of it.** It asked Carol to hear 57 of 60 frames in a row and failed under a loaded gate (47 of 60). Measured with counters on every leg under 48 busy loops of the test's own: no packet was late or dropped on any leg, Carol heard 98 to 100 of Bob's 100 frames in every run, and the gaps were her buffer running dry while all three stacks' threads were held up together and then playing the late frames. The test now asks for 95 of the 100, counting only frames that came through whole, not concealment; a call read by its own thread beside the conference still fails it.
- **The Swift binding builds with Swift 6.4 (Xcode 27).** `SipralStack.setLog` handed the log callback to C through a conditional, which Swift 6.4 no longer turns into a C function pointer; it now makes one call with the callback and one without.
- **The release library links again under Xcode 27.** Rust 1.95 stripped it with an objcopy whose output the Xcode 27 linker refuses ("mis-aligned LINKEDIT string pool"), so nothing on macOS could link `libsipral_ffi.dylib`. The pinned toolchain moves to Rust 1.99.0, which writes a dylib the new linker takes; the minimum supported Rust stays 1.95.
- **.NET: `Account.Remove` waits out a busy stack.** It released the account once and ignored the answer, so a stack busy on another thread kept the account while the layer forgot it; it now retries `SIPRAL_STATUS_BUSY` as every other call in the layer does, raises a refusal, and forgets the account only once the library has let it go.
- **Every REGISTER after a challenge carries a higher `CSeq`.** The REGISTER that answered a registrar's 401 took the next number on the wire, and the account did not count it: its refresh and its un-REGISTER went out again with that number, which RFC 3261 §10.2 forbids. Asterisk let it pass; a stricter registrar refuses it, and an un-REGISTER refused that way leaves the binding on the PBX until it expires.
- **Presence from Asterisk is read again.** Asterisk puts an empty `<dm:person />`, with no `id`, in every presence document it sends, and the stack refused the whole document over it: the NOTIFY was answered 200 and no `PRESENCE_CHANGED` followed, so every busy lamp watching an extension on Asterisk or FreePBX stayed blank. A person with no `id` is now left out and the tuples, their `basic` status and the notes are read as before.

## [1.1.0] - 2026-10-04

The headless agent sends its audio on a steady 20 ms clock and waits on its socket instead of sleeping, Opus rebuilds lost frames from in-band FEC, the in-band DTMF detector costs a fraction of what it did, and the gate holds every published figure to its budget.
The fixes: a forked INVITE rings on both lines of one stack, a waiting de-registration goes as one, the agent echoes every frame, and more below. Still at C ABI 1.0: no surface changed.

### Added

- **The published figures are held by the gate.** A new area, `scripts/check.sh --only numbers`, part of the complete gate, measures what the README, `docs/19-numbers.md`, `docs/23-compared-with-pjsip.md` and the website publish -- the shared library's size, the first and authenticated INVITE of the lab's call with and without ICE, a live call's memory and an idle stack's, counted by the signalling test's allocator, and a frame of the in-band digit detector, timed against a fixed loop on the same thread so that a loaded machine does not read as a regression -- and fails when one passes its budget in `docs/numbers.toml`, naming the figure, what it now measures, the budget and every place it is published. `docs/11-testing.md`, "The published figures", says how each is measured and how to change one on purpose.

### Changed

- **Sytek holds the copyright in Sipral and grants the commercial licence.** Every file's copyright line and the package manifests name it; `AUTHORS` and `LICENSE-COMMERCIAL.md` give its full legal identity.
- **A security report is acknowledged within 7 business days.** `SECURITY.md` promised 3; the triage, fix and disclosure commitments are unchanged.
- **Listening for keypad digits in a call's audio costs a fraction of what it did.** The in-band detector, which runs on every frame of a call that negotiated no telephone event, passes over a window whose samples alone carry too little energy for a digit before any of its filters runs, keeps that window's samples so that the next window's frequency reading still has the one before it, runs its filters beside the window's own power in one pass, and takes the square root and the phase of only the filters it goes on to read. What it hears is unchanged: every reading it takes is the same to the bit, and so is every digit, edge and refusal, on every test in the tree and on three thousand generated cases compared against 1.0. Measured on an Apple M2 (`docs/19-numbers.md`): the load test's frame, which carries silence, from 7.2 to 0.72 µs with two hundred calls; the detector alone on speech from 6.7 to 1.35 µs a frame, and on loud noise, where every window runs the filters, from 7.2 to 2.7 µs.
- **The headless agent waits for SIP instead of sleeping.** Its loop slept 5 ms whenever a turn read nothing, and an answer decided in one turn went out in the next. It now writes what a turn decided before the turn ends, and waits until a SIP datagram arrives or the next thing it has to do falls due: the stack's next timer, the next look at the route, the next instant of its audio grid while it holds calls (below), and a look at standard input every 50 ms while that is open. Every call's own socket is still read on every turn rather than waited on, so a thousand calls with audio waiting cost no extra wake-up. Measured on the Linux lab machine, two runs each, logs kept (`docs/19-numbers.md`): a call set up on loopback, INVITE to 200 at the caller, in a median 1.3 ms where it took 8.9 to 10.0 ms; no measurable processor time idle; and a thousand calls held with the median set-up at 8.0 to 11.0 ms where it was 14.8 to 16.2 ms, at 0.86 of one core where the loop that rested after each turn took 0.78. Against the lab's Asterisk (`docs/23-compared-with-pjsip.md`), it registers in 3.3 to 6.7 ms, places a call in 5.2 to 7.6 ms and answers one in 0.7 to 1.1 ms, where the comparison's run read 7.7, 10.8 and 9.5 ms.
- **The headless agent sends its audio on a steady clock.** On Linux its frames left 16, 24 or 28 ms apart rather than 20, because its loop's waits ended on scheduler ticks, and Asterisk measured 5 ms of jitter on its audio over a clean link. One thread now reads the SIP socket and hands each datagram over a channel, whose waits end on time; while calls have audio the loop turns on a fixed 10 ms grid and sends every frame on it, with no thread per call and no busy wait. Measured in the lab (`docs/19-numbers.md`): the gaps between one call's frames from a standard deviation of 5.7 ms to 0.05 to 0.20 ms, against pjsua's 0.5 to 0.7 ms, and Asterisk's jitter on the agent's audio over a clean link from 5 ms to 0 or 1; a hundred calls on loopback at 13.3 to 13.9 % of a core where the waiting loop cost 11.7 to 12.4 % and 1.0.0 13.7 to 15.0 %. On the mobile profile Asterisk still reads more jitter on the agent's audio than on pjsua's; captured where it leaves the impaired link, the two streams carry the same jitter (`docs/23-compared-with-pjsip.md`).
- **Opus sizes its in-band FEC by the loss the far end reports.** The encoder was told to expect 5 % loss on every call and paid for a copy of each spoken frame whatever the link did. It now starts at 5 % and follows the fraction lost in the far end's reception reports — believed at once when it rises, halfway each report when it falls, at most 30 % — so a clean link stops paying for copies after the first report; the payload stays the size libopus chooses for the rate.

### Fixed

- **Opus rebuilds a lost frame from the copy the next packet carries.** The stack offered `useinbandfec=1`, which says this end decodes Opus's in-band forward error correction (RFC 7587), and concealed every lost frame anyway. When the jitter buffer finds a frame missing and already holds the packet after it, and that packet carries a copy — read from its first header bits with RFC 6716's range decoder, `sipral_media::opus::carries_fec` — the frame is decoded from the copy; `StreamStatistics::fec_recovered` counts them, and the headless agent's last line of a call says `recovered=`. No C ABI change. Measured between two stacks over the lab's `lossy` and `mobile` profiles emulated in process (`docs/19-numbers.md`): 37 % and 39 % of the lost frames rebuilt, the loss left to concealment from 7.6 % to 4.8 % and from 3.9 % to 2.4 %.
- **The headless agent echoes every frame it hears.** It kept only what the latest turn of its loop heard, and its loop turns more than once a frame, so the frame it said back was most often an empty one: 355 of 1 527 packets it sent in a lab capture carried audio. A turn that moves no frame now leaves what was heard for the turn that does.
- **A de-registration that has to wait goes as one.** Asked for while the account waited for its registrar's lookup or for its own connection, it reads `UNREGISTERED` at once, as one sent at once does, and goes as `Expires: 0` when the wait ends; it used to keep the old state and could be sent, or retried, as a REGISTER asking for the binding back.
- **A stack on every interface keeps choosing its own address after a move.** A stack created with no bind address keeps choosing its own address after a network change, in the Swift, Kotlin, .NET and Python layers: its socket stays on every interface and its port, and it advertises the route toward its first account's server again, and each account the route toward its own. It used to take the new address as fixed from then on, so a server reached over a VPN, or a second account's server reached another way, was told an address it could not reach.
- **The examples take their RTP and RTCP ports as a pair.** The examples' media socket holds the RTCP port next to its RTP port from the moment it binds, where it bound RTCP only once the call's plan named it and lost that port to another call in about one call in twenty-five at a thousand at once.
- **The scripts read a listing to its end.** The gate, the lab and the packaging scripts read a whole listing before deciding a line is not in it: `grep -q` stopping at the first match made the writer die of SIGPIPE under `pipefail`, which read a match as none under load — the parallel gate's AAR dry run missing classes it had, a lab call's log missing the packets it counted — and could pass the check that libopus is out of a graph that has it.
- **One INVITE forked to two lines of one stack rings on both.** RFC 3261 §8.2.2.2's merged-request check now compares the Request-URI too: a request with no `To` tag that repeats another's `From` tag, `Call-ID` and `CSeq` is answered 482 only when it reaches the same line (the same Request-URI, or one equivalent by §19.1.4), and a copy a proxy forwards to another contact the stack registered is that line's call. A parallel fork or ring group to two accounts of one stack used to ring one line and refuse the other 482, and a ring group hunting to the next line within five seconds over UDP met the same 482. A branch whose `To` names one line's address of record and whose Request-URI names another line's contact is now the second line's call, where the oldest of the two accounts took it. A STIR-signed call forked this way verifies on both lines. No C ABI change.
- **The Linux packaging runs to the end.** The AAR's POM links the commercial licence at <https://sipral.org/terms/>, as the JVM POM does; the `--with-opus` wheel for x86_64 Linux checks `THIRD-PARTY-LICENSES.txt` against the all-target graph it lists rather than its own target's; and `bindings/c/smoke.c` compiles under gcc's `-Wextra -Werror` at ABI minor 0, which the linux-arm64 wheel's run under qemu builds it with.
- **The NuGet package names only the runtimes it carries.** Its README listed win-arm64, which no release has built yet: Windows on ARM64 needs the MSVC ARM64 build tools, and the package carries win-x64, osx-arm64, osx-x64, linux-x64 and linux-arm64.
- **The npm package carries THIRD-PARTY-NOTICES.md, like every other package, and SECURITY.md says whose business days and clock its deadlines count in** (Monday to Friday outside Romania's public holidays, Romanian time).
- **Packaged natives name no path of the machine that built them.** Source paths read `/cargo/...`, `/rustc/...` and `/sipral/...` instead of the builder's home directory and checkout, the macOS dylib's install name is `@rpath/libsipral_ffi.dylib`, and every packaging script fails a native that still holds such a path.

## [1.0.0] - 2026-10-02

The first release, at C ABI 1.0. What it promises, for every 1.x release:
the C ABI surface frozen at minor 0.33 and carried into ABI 1.0 unchanged —
names, numbers, struct layouts, the behaviour a caller sizes buffers or
retries by, and ownership — stands, a later minor only appends to it, and a
binding built against ABI 1.k loads against every library at 1.m with
m ≥ k (`docs/08-ffi.md`, "The freeze" and "ABI 1.0"). What it
publishes is the C library and the language packages over it: the Swift
package with its XCFramework, NuGet, the Python wheels, the Android AAR and
the JVM jar on Maven as `org.sipral`, the Dart package and the React Native
package. The Rust crates are not part of it, and their API promises
nothing. Security fixes reach the current minor release and the one before
it.

### Added

- **The headless agent raises its ceiling, and its platform can say the network changed.** `headless-agent --max-calls N` holds `N` calls at once where it stopped at the stack's 128, and raises with it the server transactions to three a call and 256 more, since an answered INVITE and a BYE each keep one for 32 seconds over UDP; without `--invite-burst`, the INVITE guard's burst follows it, twice `N` at once and `N` a second after, so two full rounds of calls back to back are let in, which the agent's tests prove at 150 calls, past both defaults. A line `netchange` on its standard input reads the route at once and calls `UserAgent::network_changed` even when the address is where it was, and the stack registers again; `quit` hangs up, gives the registration up and exits; the end of standard input is ignored, for a service manager. A call it cannot open a media socket for is refused 503 and said, where it rang unanswered. Measured on the Linux lab machine with `--max-calls 1000` (`docs/19-numbers.md`): a thousand calls up with audio both ways in 94.8 MB of resident memory, about 88 KB a call, at 0.92 of one core. `maxDialogs` and `maxServerTransactions` are taken at creation by the Dart layer, the React Native client and `SipralJava.open`, as the other layers already took them.
- **The Swift package lives in this repository.** The root `Package.swift` is the package an application adds by this repository's URL and a release's version: the `Sipral` module over a `binaryTarget` whose URL and checksum `scripts/package/xcframework.sh --release` writes from the zip it built, which the release carries as an asset. Every run of the script checks the manifest, and a dry run writes it into a copy from a zip of its own; the React Native podspec asks for the package from this repository at its own version unless `SIPRAL_SWIFT_PACKAGE` names another place.
- **One version for every package, `scripts/version.sh`.** `scripts/version.sh X.Y.Z` writes the workspace's version into the 98 places a copy is kept — the crates' dependencies on each other, the three lockfiles, the .NET project and `SipralInfo.cs`, `pyproject.toml` with the Development Status its major calls for, `__version__`, `pubspec.yaml`, the React Native manifest and its lockfile, the JVM POM — and `--check` holds every copy to it; the gate runs the check in the hygiene area, and every packaging script runs it first.
- **Every package described in full, and a dry run of each.** The NuGet, PyPI, Dart, npm, Maven and AAR metadata carry the description, the licence, the project's home (https://sipral.org), the repository, keywords and the author with no address in them; `scripts/package/pub.sh` and `npm.sh` stage and validate the Dart and React Native packages, the gate runs both in the dart and rn areas, and `docs/11-testing.md`, "Releasing", is the procedure and the order of publication.

- **ABI 0.36: the realms a password answers, a declined challenge said, what a held party is sent, and a PASSporT taken on a second line.** `sipral_account_config_t::realms` names the realms an account's password answers, one per line, for an SBC that challenges calls under a realm the registrar's REGISTERs never meet; without it the realms of every REGISTER challenge join the first one taken, so a registrar that moved realm is followed, and the server is compared in canonical form. `SIPRAL_EVENT_KIND_CHALLENGE_DECLINED` (58) says who asked, for which realms and why. `sipral_stack_config_t::held_audio` sends a held party silence by default in either mode, or the application's own frames on request (`MediaConfig::held_audio` in the facade). STIR's replay check keys a PASSporT by the request and the account too, so a branch of one INVITE reaching a second line of a stack after the first branch's transaction is gone verifies there, and a PASSporT in another request is still refused. Every idiomatic layer carries the three.
- **The lab runs what ABI 0.36 added.** The C harness holds a call with `SIPRAL_HELD_AUDIO_APPLICATION` and reads the application's tone off the wire through the hold (`holdapp`), and its plain hold now checks that what leaves through it is silence; through Kamailio, `realm-elsewhere` is challenged under a second realm, answered by an account that names both (`tworealms`) and declined, with `SIPRAL_EVENT_KIND_CHALLENGE_DECLINED` naming the realm, by one that names none (`realmunnamed`).
- **The lab runs the compact form, a far end's own re-offers on the second SDES line, a foreign realm and a hangup while the devices open.** Every server, and FreeSWITCH behind each proxy, carries a call held and resumed with every request written compact (`compact`). FreeSWITCH's 9010, on a profile of its own that reads the offer once its dialplan has named the one suite it takes (`interop/freeswitch/lab_late_profile.xml`), answers on the second of the two lines offered and then holds, resumes and re-offers the call while it echoes; every answer has to carry that line's key and the echo has to come back after each (`farhold`). Kamailio challenges a call to `realm-elsewhere` for another realm, which the account declines without its password (`foreignrealm`). Against Asterisk's echo, a call handed to the audio engine over fakes that take a second to open is hung up at once, and the attach, the detach and the BYE are each timed (`devicehangup`). The STIR step serves its chains over HTTPS. The matrix has their rows and features.
- **The audio engine's pump runs as audio, and carries a call without allocating.** Its thread asks for the Mach time-constraint policy on macOS and iOS (`sipral_io_coreaudio::run_as_audio`), Pro Audio with the multimedia class scheduler on Windows (`sipral_io_wasapi::pro_audio_thread`) and the urgent-audio priority on Android (`sipral_io_aaudio::urgent_audio_thread`), and the engine says what it got (`Engine::pump_scheduling`) and how many samples the loudspeaker starved for (`Engine::speaker_starved`): none in five seconds on BlackHole with eight threads spinning. Each packet is lent to the transmit function (`sipral_audio::Transmit`) and a session's is copied into one the pump keeps, so carrying a call's microphone makes no allocation where it made one a frame.
- **ABI 0.35 (`docs/08-ffi.md`, "What ABI 0.35 added").** `sipral_account_config_t::stream_protocol`: an account on a TCP or TLS connection of its own to its own server, beside one on the stack's UDP transport, in one stack; the stack asks for the connection with `TRANSPORT_WANTED` and adopts what the application binds (`Account::on_stream`). `sipral_stack_config_t::system_echo_cancellation` turns the platform's canceller off where it can be (voice processing bypassed on macOS and iOS, a raw communications stream on Windows, the voice-recognition preset on Android). `sipral_audio_call_set_gain`, `_gain`, `_set_muted`, `_muted` and `_level`: one call's own mute, gain and meter in the engine's mix. `sipral_stack_settings_t` reads back `srtp_suite_count` (with `sipral_stack_srtp_suite_order`), `pseudonym_salted`, `diagnostic_trace` and `system_echo_cancellation`. Every pin and every 0.34 member's offset is where it was.
- **ABI 0.35 in every layer: Swift, Kotlin, .NET, Python, Dart, React Native and the JVM jar.** An account added with a stream protocol (`streamProtocol`, `stream_protocol`) gets a TCP or TLS connection of its own to its server, beside accounts on the stack's UDP socket: each layer answers the account's `TRANSPORT_WANTED` (nothing outgrown) by opening the protocol it names whatever its stream fallback says, a TLS one held to the account's `tlsPin` or else to the stack's trust and server name, binds it, writes the account's `Contact` with its transport, and opens it again when it closes; Dart, which opened no stream before, now opens these with `Socket` and `SecureSocket`, the pin checked by `checkCertificate`. A call's own gain, mute and meter in each direction (`AudioDevices.setGain(_:for:of:)`, `SipralAudioEngine.SetGain(call, ...)`, `audio.set_gain(..., call=)`, `SipralAudioDevices.setGain(call, ...)`, React Native's `call.audio`); the echo switch at creation (`systemEchoCancellation`); and the settings read back with every default filled in and the SRTP suites in order (`settings()`, `Settings()`, `SipralSettings`). Each layer's tests register an account over TLS and one over UDP with two loopback registrars and place a call through each, reopen an account's TCP connection when its registrar drops it, read the settings back, and set a call's own controls on a device-mode stack whose devices stay closed; `SipralJava.addAccount` takes the protocol, with a Java test.
- **A request over the datagram limit is written compact before it leaves UDP.** RFC 3261 §7.3.3's one-letter names for RFC 3261's own fields, no space after a colon, token lists without spaces, and then no `Allow` when that is not enough; only what is still over goes to a stream, in full. On the first send, the answer to a challenge, inside a dialog and on failover; `DatagramLimit::compaction` (`Compaction::Never`, `WhenOversize` by default, `Always`), recorded as `transport.compacted.size`. An answered best-effort INVITE with four codecs went from 1373 bytes to 1298. `CodecCatalog::with_voip_metrics(false)` leaves `a=rtcp-xr` out of offers and answers.
- **An account's password answers its own server and nobody else.** A challenge to a request that went anywhere but the account's registrar or outbound proxy — the far end of a direct call, a peer challenging a re-INVITE or a BYE — is not answered, nor one for a realm that is not the account's (`Account::realms`, or with none named the realms its server first challenged with, kept). Declined challenges are closed for §22.2's answers ahead of a challenge too, reported as `UaEvent::ChallengeDeclined` with a `ChallengeRefusal`, and recorded as `auth.challenge.declined` (`Endpoint::challenge_origin`, `Endpoint::decline_challenge`).
- **STIR verification refuses a replayed PASSporT, and numbers are read under the deployment's dialling plan.** The agent remembers the PASSporTs it found valid (`StirConfig::remember`, 1024 by default) and refuses one presented again inside its window as stale (RFC 8224 §12.1), 403 "Stale Date" on a strict account; `UserAgent::set_number_plan(NumberPlan)` puts a national number in international form (§8.3) wherever a number is signed or checked.
- **Incoming requests are matched to their account by their flow, and every request to a located server fails over.** Among the accounts the Request-URI or the `To` name, the one on the transport the request arrived on and then the one whose server sent it; with neither URI matching, the Request-URI's user among the accounts on that transport. An INVITE, MESSAGE, SUBSCRIBE or PUBLISH outside a dialog that times out, loses its transport or is answered 503 goes to the next address RFC 3263 found, as itself with a new branch (`Endpoint::unreached`, `Endpoint::send_elsewhere`).
- **The end-of-call record kept, the signalling port kept, and one list of pin forms, in the layers.** Swift's `MediaEventData.statistics` and Dart's `SipralStackEvent.statistics` decode the record `SIPRAL_EVENT_KIND_MEDIA_STATISTICS` carries (Dart also the subscription and the transfer's status code); the call keeps it in Swift's `Call.finalStatistics`, Kotlin's and Dart's `finalStatistics`, .NET's `Call.FinalStatistics` and Python's `Call.final_statistics`, and each layer's media statistics answer with it after the end instead of `WRONG_STATE`. After a network change the Swift, Kotlin, .NET and Python layers bind the UDP signalling socket again on the port chosen at creation, or the one in use, and say through `keptSignallingPort` when another socket held it there. Every layer's certificate pin parser takes bare or colon-separated hexadecimal with colons and spaces ignored, after `sha-256 `, `SHA256=` or `SHA256 Fingerprint=` in any case, and is tested against `bindings/fixtures/pin-forms.txt`; Dart reads `tlsPin` with `sipralPinDigest` and React Native with `pinDigest`. Swift's `AudioDevice` and `Subscription` are `SipralAudioDevice` and `SipralSubscription`, the old names deprecated aliases for one minor release. The .NET SRV and NAPTR client takes only a reply from the server asked with its id and question (RFC 5452 §9.1) and asks again over TCP when one is truncated. Swift, Kotlin, Python and Dart retry `CLOCK_BEHIND` as .NET does.
- **Every event's payload in the Swift, .NET and Python layers.** Subscriptions changed and notified, recovery, a name to resolve (Swift), a call announced or missing (.NET, Python), a MESSAGE received or answered and a message summary, a quality report sent and media unjoined now arrive with their payload read: `subscriptionData`, `recoveryData`, `resolveData` and `messageData` on Swift's `SipralEvent`, `Subscription`, `Recovery`, `Announce` and `MessageInfo` on `SipralEventArgs`, and `fields` in Python. Each layer's test holds every kind the ABI declares to a decoded payload. The Dart layer's `SipralStack.onRawEvent` is handed each event whole, as the printed `SipralEvent`, inside the poll, so every arm is readable there too.
- **A Dart and Flutter binding, `bindings/dart`.** `tools/abi-gen` has a Dart back end: `lib/src/sipral_abi.dart` is printed from the same declarations as the header and the other bindings, a `dart:ffi` `Struct` or `Union` per record with each integer at its exact width, the enumerations as `int` constants, the callbacks as native and Dart function types, and every entry point in `Sipral`, whose `open()` loads the library and refuses one that cannot serve this ABI; a reserved word is printed with a `$` after it, the names go through the same audit as the other back ends, `golden/synthetic.dart` holds its output for the synthetic surface, and `--check` covers the printed file. Over it, by hand, `SipralStack`, `SipralAccount`, `SipralCall` and `SipralMedia`, with the stack's events as a `Stream`, all on the isolate that opened the stack. Its tests hold every record's `dart:ffi` layout to `sipral_abi_struct_size` and place a call between two stacks on loopback against `libsipral_ffi`; `scripts/check.sh` runs `dart analyze`, `dart format` over the hand-written layer and the tests. It asks for Dart 3.7 or later.
- **A documentation site, built with mdBook from `docs/`.** `site/book.toml` and `site/src/SUMMARY.md` make the design documents a book whose pages are symlinks into the tree, so `docs/` stays the only copy of the text; `scripts/site.sh` builds it into `target/site` and fails on an mdbook error or warning, a link that names no page, file or anchor, anything loaded from another host, or an email address on a page, and `scripts/check.sh` runs it. Nothing is published.
- **A JVM server artefact, `sipral-jvm`.** `bindings/jvm` builds the Kotlin binding with Maven for a plain JVM (Java 17 bytecode, Kotlin 2.2 metadata) with `libsipral_ffi.so` and `libsipral_jni.so` for linux-x64 and linux-arm64 inside the jar; `SipralNatives` picks the pair for `os.name` and `os.arch`, checks its ELF machine and loads it by absolute path, so nothing goes on `java.library.path`. `SipralJava` gives Java callers the idiomatic layer: overloads for Kotlin defaults, blocking calls and `CompletableFuture`s for the suspend waits, and a listener for an event flow. A Kotlin and a Java test each place a call between two stacks on loopback in one JVM against the packaged jar, under `-Xcheck:jni`, and the loader's choice is tested on its own. `scripts/package/jvm.sh` builds linux-x64 in manylinux_2_28 and cross-compiles linux-arm64 in the aarch64 cross image, runs the tests again on an arm64 JVM under qemu, and writes the jar, its sources, the flattened POM and the SBOM; `--dry-run` builds only the host's own pair, without Docker. The Docker route reads every native's symbol versions and fails on one that asks for a glibc newer than 2.28. `scripts/check.sh` compiles `bindings/jvm` without Maven and runs, with the JUnit console launcher, the loader's platform and ELF tests and the Java loopback call. The group id is `org.sipral`.
- **A React Native package, `bindings/react-native` (`sipral-react-native`, React Native 0.87.1, New Architecture).** A TurboModule whose codegen spec is `src/NativeSipral.ts`, a typed TypeScript API over it (`Sipral.open`, `SipralClient`, `SipralAccount`, `SipralCall`: registration, calls placed and answered, hold, blind transfer taken or asked for, DTMF, mute and manual audio activation, events on typed emitters, refusals as `SipralError` codes), and two native halves over the idiomatic layers rather than the ABI: Kotlin's `SipralClient` on Android, Swift's `SipralStack` on iOS, both in device mode. Swift's `Call.transfer(to:)` with `TransferEventData`, and Kotlin's `SipralCall.transfer` with `transferOf`, are new for it, each with a three-stack loopback test. `scripts/check.sh` runs the jest suite, the type check and codegen over the spec, both halves' logic over real stacks on loopback, the Android library through Gradle and the iOS module against React Native's headers.
- **ABI 0.34: what device mode on a real PBX and the account work needed from C (`docs/08-ffi.md`, "What ABI 0.34 added").** Appended to `sipral_stack_config_t`: `srtp_suites`, `path_mtu`, `datagram_without_stream_bytes`, `pseudonym_salt`, `diagnostic_trace` (`sipral_stack_diagnostic_trace` while it runs; the path MTU and the UDP limit read back in `sipral_stack_settings_t`); to `sipral_account_config_t`: `keepalive_ms`, `server_uri` with `server_naptr`, `tls_pin_sha256`. `SIPRAL_SRTP_BEST_EFFORT`; `SIPRAL_EVENT_KIND_LOOKUP_WANTED`, `_LOCATED` and `_LOCATE_FAILED` with `sipral_account_looked_up` taking the resolver's records as text; `sipral_account_check_certificate` and `sipral_pinned_certificate_t`; `SIPRAL_STATUS_CERTIFICATE_REFUSED`, `SIPRAL_STATUS_UNREACHABLE_ADDRESS`, `SIPRAL_REGISTRATION_FAILURE_UNREACHABLE_CONTACT` and `sipral_advertised_address`. Every pin and every 0.33 member's offset is where it was on all three layouts.
- **ABI 0.34 in every layer: Swift, Kotlin, .NET, Python, Dart and React Native.** A stack given no bind address listens on every interface and advertises the route toward its first account's server (`sipral_advertised_address`), each account and each call's media socket the route toward its own peer, so an application that names nothing gets audio from a PBX on the network and a loopback peer still works; the layers expose `advertisedAddress`. An account names its server by `serverUri` (with `serverNaptr`), and the layer answers `LOOKUP_WANTED` with the platform's resolver, replaceable by the application's: Apple's DNS service with SRV and NAPTR, JNDI's on a JVM, this package's own UDP SRV and NAPTR query in .NET, addresses only in Python, Dart and on Android, each documented; `LOCATED` points the account at the address found and `LOCATE_FAILED` says why. `keepaliveMs`; a TLS trust that pins one certificate by its SHA-256 fingerprint (`TlsTrust.pinned`, `TLSTrust.pinned`, `SipralTlsTrust.Pinned`) and an account's `tlsPin` with `checkCertificate`; SRTP best effort and the stack's suite list; the path MTU and UDP past the limit for a UDP-only server, with the stack's diagnostic record readable as JSON; the pseudonym salt and the diagnostic trace, at creation and while the stack runs; the new statuses, registration failure and events decoded. The React Native client takes them in `Sipral.open` and `addAccount`, raises `located` and `locateFailed`, and has `setDiagnosticTrace`. Each layer's tests run every one on loopback, against a resolver, a DNS server or a TLS registrar of their own.
- **An account names its registrar or proxy, and RFC 3263 locates it with the application's resolver.** `Account::located`, `Account::unregistered_located` and `Account::locate`; NAPTR when asked for, SRV for the account's transport, A or AAAA, the §4.3 order kept for failover on a timeout, a lost transport or a 503, and the name looked up again when its time-to-live runs out or the recovery ladder asks for an address, in which case the ladder climbs on as soon as the answers are in.
- **An account keeps its registrar flow open at an interval of its own** (`Account::keepalive`, 1 to 120 s) whatever STUN found; **a PBX's self-signed certificate is trusted by its SHA-256 fingerprint** (`Account::tls_pin`, `CertificatePin`); **a loopback address is never advertised to a peer on another machine**, an IPv4-mapped one included (`UaError::UnreachableAddress`, `RegistrationFailure::UnreachableContact`, `sipral::advertised_address`); **a diagnostic trace writes messages whole** with credentials, keys and URI passwords taken out, under **pseudonyms an installation keeps** (`Log::set_diagnostic`, `Log::from_salt`), and a TCP or TLS connection is traced a whole framed message at a time.
- **SRTP best effort, `SrtpPolicy::BestEffort`.** SDES offered on plain `RTP/AVP` (`SrtpSupport::SdesOnAvp`), the "SRTP optional" of desk phones: the call is keyed when the answer takes one of the `a=crypto` lines and plain when it takes none, so a PBX that does no SRTP takes the stream instead of answering 488. Answering, an `RTP/AVP` offer carrying a line this end takes is answered with a key, so two stacks on this policy key their call. The suites offered are the catalogue's or the account's, as for every SDES policy. In the C ABI as `SIPRAL_SRTP_BEST_EFFORT` since 0.34.
- **The lab runs what ABI 0.35 added.** The `tls` step adds two lines in one Python stack (`interop/lines/caller.py`): an account on the stack's UDP socket at Kamailio and one on a pinned TLS connection of its own at Asterisk, both registered at once and a call up on each together, audio both ways. The harness's `callmute` flow, part of the Asterisk run, carries two calls to an echo in the audio engine over its fake devices (`sipral-audio`'s `fake` feature): the first muted with its own per-call mute brings back silence while the second brings back the tone, then unmuted brings the tone back too; `SIPRAL_ECHO_EXTENSION` and `SIPRAL_ECHO_KEY` point it at a PBX's echo test. The matrix has their rows and features.
- **The lab runs what ABI 0.34 added against Asterisk.** `scripts/lab.sh besteffort`: SRTP best effort from an endpoint with no SRTP, which comes up plain, and from one with SDES, which comes up keyed. `scripts/lab.sh locate`: a registrar named by its host name, found by its A record, registered at and called through, and a server named by a domain only an SRV record from the application's resolver locates. The `datagram` step sends the challenged INVITE that cannot be trimmed over UDP anyway when told it may, and the call connects; the `tls` step pins the listener's certificate by its fingerprint and is refused under another's. The datagram caller (`interop/datagram/caller.py`) takes each of these, and names its codecs and sends digits, for the live PBX run too. The matrix has their rows and features.
- **`scripts/lab.sh nway`: three calls in one local conference, through Kamailio.** Three of the harness's stacks register as `conf-a`, `conf-b` and `conf-c`, each on a codec of its own (PCMU, G.722, L16 at 16 kHz), and a fourth calls them through the proxy and mixes them: each has to hear the other two pitches and not its own, and when `conf-c` hangs up the conference has to say so and the two left have to go on hearing each other. The matrix has its row and its feature.
- **A local conference in the four idiomatic layers.** Python's `LocalConference`, .NET's `SipralLocalConference`, Swift's `LocalConference` and Kotlin's `SipralLocalConference` add and remove calls, mute and level each way of a member (this end when no call is named), list the members and the talkers, record the mix and decode `LOCAL_CONFERENCE_CHANGED`; a member's own media thread leaves its frames to the conference while it is in one, and in application mode the conference ticks on a thread of its own with this end's microphone and speaker as a queue and a stream. Each layer's test bridges two calls between three stacks on loopback and checks the far end hears the other steadily.
- **A local conference over the C ABI (0.32).** `sipral_local_conference_create`, `_add`, `_remove`, `_set_muted`, `_set_gain`, `_info`, `_member_at`, `_talker_at`, `_record_start`, `_record_stop` and `_destroy`; in device mode the audio engine carries the conference in place of its members and every packet reaches `audio_transmit_callback` under its member's call handle, and in application mode `sipral_local_conference_tick` and `_poll_transmit` drive it. This end is named by the conference's own handle. `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` (54), `SIPRAL_STATUS_CONFERENCE_REFUSED` (23) for a full conference, a call already in one or joined into a pair, or a codec it cannot mix, and `SIPRAL_FEATURE_LOCAL_CONFERENCE` (`1 << 24`); `sipral_call_join` refuses a conference's member. Status 17 is documented as a permanent hole. The header and the four bindings are regenerated, and `smoke.c` hands the three new structs over at their pinned lengths.
- **A local conference of any number of calls, `sipral::LocalConference`.** `MediaEngine::local_conference` makes one over `sipral_media::nway`: calls join and leave at any time, each on its own codec, rate and frame (8 to 48 kHz, 10 to 60 ms), with or without this end's microphone and speaker as a member, and each hears everybody but itself. Per member, a mute and a gain each way; a member on hold leaves the others talking; a call whose codec moves is seated again at its new rate with its controls; a call that ends leaves by itself. Who joined, who left and why, and who is talking (loudest first) are reported as `ConferenceChange`s, and the whole mix is recorded through the call recorder in WAV or Ogg Opus. `sipral-audio`'s `CallAudio::capture_each` lets one entry the pump carries name each packet after a call of its own.
- **ABI 0.32, security:** `accept_service_provider_codes` in `sipral_stir_config_t` and `recording_in_clear` in `sipral_account_config_t` (64 bits wide, so that it starts past the struct's 0.31 length rather than in its tail padding), both `SipralToggle`s off by default, with `acceptServiceProviderCodes`/`accept_service_provider_codes` on the four layers' `stir` and `recordingInClear`/`recording_in_clear` on their account security. Each layer's tests verify a call signed under a certificate that names only a service provider code (the chain in `bindings/fixtures/stir-provider-709J`, which the C ABI's tests hold equal to `sipral_stir::testing`'s), invalid by default and valid once codes are accepted, and read the recording session's offer for an SDES call: SRTP by default, plain RTP where the account allows it.
- **Conferences, presence, real-time text, RTCP feedback and SIPREC in the .NET and Python layers:** subscriptions (`Account.Subscribe`/`subscribe`) with the conference picture read whole, presence watched and published, a call's text stream sent and read, AVPF asked for, a focus named and a call recorded to a recording server, with L16 proved as a codec.
- **STIR/SHAKEN in calls.** An account given a P-256 key and the URL of its
  certificate signs every call it places (RFC 8224 §6.1, full-form PASSporT
  with RFC 8588's `attest` and `origid`, and the `Date` it is dated by):
  `Account::stir_signing`, or `stir_key` and `stir_certificate_url` in
  `sipral_account_config_t`. An agent given trust anchors
  (`UserAgent::set_stir`, `sipral_stack_stir`) verifies the caller of every
  INVITE for an account that verifies — reporting by default, refusing with
  RFC 8224 §6.2.2's response under `StirVerification::Strict` — before the
  phone rings: the certificate is the application's to fetch when
  `UaEvent::CertificateWanted` / `SIPRAL_EVENT_KIND_CALLER_VERIFICATION` (47)
  asks, and to hand over with `stir_certificate`; the verdict (attestation,
  `verstat`, the reason on failure) is announced just before the call and
  rides on its typed identity (`CallerIdentity::verification`, and
  `verification`, `attestation` and `verification_failure` on every C call
  event). `SIPRAL_FEATURE_STIR` (`1 << 16`). A signer's key is read as the
  bare scalar, SEC1 or PKCS #8, DER or PEM (`Signer::from_key`).
- **An SRTP policy per account.** `MediaEngine::set_account_srtp` /
  `srtp` in `sipral_account_config_t` holds every call of one account to a
  policy of its own, over the stack's; through the C ABI a call may ask for
  more than its account and never for less (`SIPRAL_STATUS_SECURITY_POLICY`,
  18). The suites it runs are the account's to name and order
  (`CodecCatalog::with_srtp_suites`, `srtp_suites`): the SDES lines offered
  and accepted, and the DTLS-SRTP profiles, RFC 7714's GCM ones among them
  only if named. `SIPRAL_FEATURE_SRTP_POLICY` (`1 << 17`), ABI 0.31.
- **DTLS-SRTP falling back to SDES.** `SrtpPolicy::DtlsOrSdes` /
  `SIPRAL_SRTP_DTLS_OR_SDES` offers one `RTP/SAVP` stream with both the
  fingerprint and the crypto lines, so a DTLS-SRTP peer keys the call by the
  handshake and an SDES-only one by a crypto line; a plain offer is refused.
- **The encryption report.** `MediaSession::encryption` /
  `MediaEngine::encryption` and `sipral_media_encryption_at` say, per
  stream, whether it is encrypted, by SDES or DTLS-SRTP, with which suite, and
  whether the exchange authenticated the far end; `sipral_media_event_t`
  carries the same on media started, changed and secured.
- **STIR/SHAKEN, SRTP per account and the encryption report in the four
  idiomatic layers.** Adding an account takes its SRTP policy and suites and
  its STIR verification and signing (`add_account(srtp=..., stir_key=...)`,
  `AccountSecurity` in .NET and Swift, `SipralAccountSecurity` in Kotlin); the
  stack gives the time and the trust anchors (`stir`) and hands over a
  fetched certificate chain (`stir_certificate`); the caller-verification
  event and the caller identity carry the verdict, and the media object's
  `encryption()` the report.
- **Digits in the audio, both ways, on a call.** `MediaConfig::dtmf_detection` (`DtmfDetection::Auto` by default: on the calls that negotiated no `telephone-event`; `Always`; `Off`) listens for Q.23 digits in the far end's audio at any codec rate and reports each as `MediaEvent::DigitReceived` with `DigitSource::InBand` and its length; a press also sent as an RFC 4733 event within `IN_BAND_DIGIT_HOLD` is reported once. `send_dtmf` and `dial` on a call with no telephone event write the tones into the outgoing audio instead of refusing, and `MediaSession::dial_in_band` does so on any call. C ABI 0.31: `sipral_stack_config_t::dtmf_detection`, `sipral_call_dtmf_detection`, `SIPRAL_DTMF_IN_BAND` (4), `SIPRAL_EVENT_KIND_IN_BAND_DIGIT` (48) with `SIPRAL_DIGIT_SOURCE_IN_BAND`, and `SIPRAL_FEATURE_IN_BAND_SIGNALS` (`1 << 18`).
- **Call progress and who answered, per call.** `ProgressDetection` (`MediaConfig::progress`, `MediaEngine::detect_progress`) listens for a network's tones and the special information tone on early media, decides at the 2xx whether a person or a machine answered with configurable limits, and then listens for the machine's beep; each is a `MediaEvent::Progress(CallProgress)`. C ABI 0.31: `sipral_call_detect_progress` with `sipral_progress_config_t`, and `SIPRAL_EVENT_KIND_PROGRESS_DETECTED` (49) carrying `sipral_progress_event_t`.
- **A consent tone while a call is recorded.** `ConsentTone` (`MediaConfig::consent_tone`, `MediaEngine::set_consent_tone`, `MediaSession::set_consent_tone`; C: `sipral_call_consent_tone`) beeps into what goes to the far end, and unless told otherwise into what this end hears, from the moment a recording starts until it stops, and the recording keeps it on this end's side.
- **Recordings as the application asks for them.** `MediaSession::start_recording_with` takes `RecordingOptions`: WAV growing into RF64, or Ogg Opus with the encoder's real pre-skip, a random stream serial and the last page trimmed to the audio; mixed, or stereo with this end on the left and the far end on the right; a rate of the file's own that a codec change no longer ends the recording over; and a checkpoint, five seconds by default, after which a crash leaves a file that plays. A recorder dropped without being stopped finishes its file. C ABI 0.31: `sipral_media_record_start_with` with `sipral_recording_options_t`, `SIPRAL_STATUS_RECORDING_FAILED` (19) for a file that stops taking what is written, and `SIPRAL_FEATURE_RECORDING_FORMATS` (`1 << 19`). `sipral_media::opus::Encoder` gains `stereo`, `lookahead` and `pre_skip`, `formats::wav::Writer` gains `checkpoint`, and the digit and tone generators take any rate (`DtmfGenerator::with_tone_at`, `ToneGenerator::beeps`).
- **The four idiomatic layers carry what a call hears in its audio and how it is recorded (ABI 0.31).** Python, .NET, Kotlin and Swift each set `dtmf_detection` on the stack and per call, send digits in band, report `IN_BAND_DIGIT` on the call's digit stream, listen for call progress and who answered with every limit exposed (`detect_progress` / `DetectProgress` / `detectProgress`), set a consent tone, and record a call's media as WAV or Ogg Opus, mixed or stereo, at a rate of the file's own, with its state readable; each layer has its own loopback test.
- **L16 negotiated as a codec.** `Codec::L16Narrowband` (`L16/8000`) and `Codec::L16Wideband` (`L16/16000`), one channel, offered where a codec order names them and agreed only at the same rate; a frame whose payload would not fit a datagram is refused where it is set. C ABI 0.31: `SIPRAL_CODEC_L16_NARROWBAND` (6) and `SIPRAL_CODEC_L16_WIDEBAND` (7).
- **`scripts/lab.sh inband`: digits, a machine and a recording against Asterisk.** On an endpoint with no telephone event, four digits dialled in the audio are read there by Asterisk and heard back in it; ringback on early media, a recorded greeting and its beep are reported as a machine and its beep; and a call recorded to stereo WAV and Ogg Opus is read back by the harness and by `soxi` and `opusinfo`.

- **Device mode on Android, over AAudio.** From API level 28 the built-in engine runs every call through AAudio voice-communication streams (the platform's echo canceller in the input preset, a ringtone stream for the ringer), lists the phone's devices and moves calls between the earpiece, the loudspeaker and a wired or Bluetooth headset through `AudioManager` once `SipralAndroidAudio.attach(context)` has handed it a context, and reports changes as `AUDIO_DEVICES_CHANGED`; `SIPRAL_FEATURE_AUDIO_DEVICE` is now the phone's answer, and below API level 28 the telecom helper's `AudioRecord` and `AudioTrack` stay the path. `SipralCallAudios` drives the engine through the framework's hold and call focus with `EngineAudioDevice` (`docs/15-mobile.md`).
- **An N-way conference mixer, `sipral_media::nway`.** Participants join
  and leave at any point, each at 8, 16, 32 or 48 kHz with its own frame,
  and each hears everybody but itself, resampled to its own rate. The mix
  is formed on a 20 ms tick at 48 kHz, sans I/O, and allocates nothing
  after a participant has joined. Per participant: gain in and out, mute in
  and out, and listen-only. A soft limiter (1 ms attack, 80 ms release, a
  ceiling at three quarters of full scale) keeps any number of loud legs off
  the rail; an energy detector with hysteresis lists who is talking,
  loudest first; and a tap records the whole mix at a chosen rate.
- **The four idiomatic layers carry the rest of ABI 0.30.** Each stack
  class reads its counters (`counters()` / `Counters()`, the retransmission
  and limit counters among them), replaces its STUN servers while running
  (`set_stun_servers` / `SetStunServers` / `setStunServers`, which also turns
  STUN on or off), and sends its log to the platform's own logging with no
  dependency added: Python's `logging` (`Stack.log_to`, a child logger per
  target, `sipral.TRACE` below `DEBUG`), .NET's `TraceSource`
  (`SipralStack.LogTo`), `java.util.logging` on the JVM and Android
  (`SipralClient.logTo`), and `os.Logger` on Apple platforms
  (`SipralStack.logTo(subsystem:level:)`, a category per target). The state
  snapshot now also names the signalling counters.
- **A stack's limits are set and read over the C ABI (0.30).**
  `sipral_stack_config_t` appends `max_dialogs`, `max_server_transactions`,
  `diagnostic_decisions` and `diagnostic_records`, each zero for its
  default (128, 256, 64, 32), and `sipral_stack_settings_t` reads them back.
  A call placed past `max_dialogs` is `SIPRAL_STATUS_LIMIT_REACHED` (16)
  with nothing sent; one that arrives past it is answered `503` with no
  `Retry-After`. `SIPRAL_FEATURE_LIMITS` (`1 << 15`) says the build has
  them; the four idiomatic layers take the four as constructor arguments.
- **What went out twice is counted.** `Endpoint::retransmissions()` and
  `sipral_counters_t` carry requests and responses sent again and
  transactions that timed out, and the C struct also the requests refused
  `503` at a limit; `Endpoint::transaction_retransmissions` answers for one
  live transaction. A figure that climbs while calls still connect is a
  lossy path, seen before it drops a call.
- **`scripts/bench.sh scale` holds thousands of calls with audio.** Two
  processes of the lab harness on one machine, five and ten thousand calls
  by default, each carrying G.711 both ways for a minute; it reports setup
  rate and times, processor time, memory, packets a second and what each of
  the engine's polls and sweeps costs. `docs/19-numbers.md` has the first
  run.
- **More than one STUN server, with failover.** `stun_fallbacks` beside
  `stun_server` (ABI 0.30; `Mappings::fallbacks` in Rust, `stun_fallbacks` /
  `stunFallbacks` in Python, .NET, Kotlin and Swift) names the servers to
  turn to, in order. A server that does not answer in five and a half
  seconds, or answers without an address, hands every socket asking it to
  the next at once and is passed over for thirty seconds, twice as long each
  time it fails again, up to ten minutes; a signalling socket's refresh finds
  a better server that came back. `SIPRAL_EVENT_KIND_STUN_SERVER` (46) says
  when the server in use moves and when every one has failed, and
  `sipral_stack_stun_servers` replaces the list on a running stack, starts
  STUN on one created without it, or stops it.

- **The engine's log, through a callback, off until asked for.**
  `sipral_stack_log` (Rust: `sipral::Log`, `MediaEngine::set_log`) delivers
  lines at error, warn, info, debug or trace, set and changed at run time:
  registrations, calls and media at info, every event, every diagnostic
  decision and every refused ABI call at debug, every SIP message whole at
  trace. A token bucket and a bounded queue keep a flood from stalling the
  stack, counting what they turn away on the next line; the callback runs
  after the stack is let go, so it may call back into it; and every line is
  redacted — no user part, number, IP address, credential or SDES key.
  `SIPRAL_FEATURE_LOGGING` (bit 14) says a build has it. C ABI 0.30.
- **A snapshot of the stack's state for a crash report.**
  `sipral_stack_state` (Rust: `MediaEngine::state`, `EngineState::render`)
  copies one bounded, redacted text of accounts and registrations, calls and
  their states, transports, media sessions, the last refused calls, the
  queues, the RTP range and the counters. Safe from any thread and never
  waits: a stack busy elsewhere answers with the last snapshot a poll kept,
  and says so.
- **An RTP port range.** `rtp_port_min` and `rtp_port_max` in
  `sipral_stack_config_t` (Rust: `RtpPorts`, `MediaEngine::reserve_rtp_port`)
  hand out even ports with the odd one above kept for RTCP;
  `sipral_stack_rtp_port_reserve` answers `SIPRAL_STATUS_EXHAUSTED` once every
  pair is in use, a call's port comes back when it ends, and a call described
  outside the range is refused. The Swift, .NET, Kotlin and Python stacks bind
  every media socket from the range when given one, and carry the log and the
  state as `setLog`/`SetLog`/`set_log` and `state()`/`State()`.
- **A replayed session exported as one pcapng with both directions.**
  `sipral_diag::export_replayed` (and `sipral::replayed_capture`, redacted)
  replays a `.sipralrec` into a live layer and places every message this end
  writes beside what arrived, each packet marked inbound or outbound in its
  `epb_flags`; `diag-export`'s far-end-only files carry the inbound mark too.
  Read back by `tshark` with every message decoded and its direction shown.
  Redaction now also pseudonymises the user name of an SDP `o=` line, and
  `sipral_diag::redact_text` applies the same rules to free text.
- **A guide for moving off PJSIP** (`docs/21-migrating-from-pjsip.md`),
  written from PJSIP's public documentation alone: the library's lifetime,
  transports, the event pump, accounts, calls, media and the conference
  bridge, the sound device, buddies and presence, messages, logging and
  threads, each with its Sipral equivalent in C and in Python and what works
  differently. Every sample in it was built and run.
- **A TLS recipe per platform** (`docs/22-tls.md`): who checks a
  certificate for SIP and for TURN over TLS, what RFC 5922 asks of a SIP
  domain's certificate beyond an HTTPS check, the trust anchors each
  platform uses by default, how to add a private CA and how to trust one
  authority alone on Linux, Windows, macOS and iOS, and Android, and what an
  application sees when TLS fails. Samples in C with OpenSSL, Python, C#,
  Swift and Kotlin, run against the lab's TLS listener.

- **A public comparison with PJSIP, and the lab flow that makes it.**
  `scripts/lab.sh compare` runs the same scenarios for the headless agent and
  for pjsua from Alpine's own package against the lab's Asterisk --
  registering, a call each way, memory and CPU idle and at 1, 4, 10 and 100
  calls, a call over each netem profile rated from both ends, a move to
  another address mid-call, and the INVITE with ICE -- reading every time off
  a capture; `docs/23-compared-with-pjsip.md` reports a run with its commands
  and raw numbers. The headless agent example gains `--register`,
  `--registrar`, `--pass`, `--call`, `--ice`, `--codecs` and
  `--invite-burst`, follows its own
  address when the route to its registrar changes, says when a request is too
  large for a datagram, and prints what each call measured when it ends.
- **STIR/SHAKEN caller authentication, in its own crate.** `sipral-stir`
  signs a caller's identity into an RFC 8224 Identity header field (a
  PASSporT of RFC 8225 with RFC 8588's `shaken` claims, ES256, full or
  compact form) and verifies one without I/O of its own: it names the
  certificate to fetch, then takes the fetched chain, the trust anchors and
  the time to the attestation level, calling number and origination
  identifier, or to the one reason it fails with the SIP response RFC 8224
  prescribes (403, 428, 436, 437, 438) and the `verstat` value to put on the
  caller's identity. The chain is checked to a trust anchor with the
  TNAuthList of RFC 8226 deciding which numbers it speaks for; freshness is
  sixty seconds unless configured, revocation is left to the application,
  and every input is bounded and fuzzed. Not yet reachable through the C
  ABI or the bindings.
- **Digits, call-progress tones and answering machines are heard in the
  audio itself.** `sipral_media::inband` works on 8 and 16 kHz PCM with no
  new dependency and no platform-specific instructions. `dtmf::DtmfDetector`
  finds the sixteen Q.23 digits to the limits of ITU-T Q.24 Annex A (±1.5 %
  accepted and ±3.5 % refused, twist +4/−8 dB, 40 ms accepted and 23 ms
  refused, a 10 ms interruption bridged), holds off talk-off with a
  signal-to-noise and a second-harmonic test, and reports each digit's
  start and end on the stream's sample clock; `KeyPress::is_same_press`
  matches one against an RFC 4733 event for the same key.
  `generate::DtmfGenerator` and `ToneGenerator` write digits and
  call-progress tones; `progress` tables dial, ringback, busy, congestion
  and call waiting for the CEPT countries, North America and the United
  Kingdom from ITU-T E.180 Supplement 2, and `ProgressDetector` hears them
  and E.180's special information tone on a call's inbound audio.
  `amd::AnsweringMachineDetector` says whether a person or a machine
  answered an outbound call, and why, and `beep::BeepDetector` says when a
  machine's beep has ended. A minute of synthesised speech and of noise
  per rate triggers none of them; all four together run about a thousand
  times faster than real time per core at 8 kHz.
- **Multipart bodies, and the metadata of a recorded call.**
  `sipral_core::msg::Multipart` reads a `multipart/mixed` or
  `multipart/alternative` body (RFC 5621, RFC 2046 §5.1) into parts, each
  with its own `Content-Type`, `Content-Disposition` and `Content-ID`,
  nested multipart included, within bounds on parts, depth, size and
  fields per part; `Multipart::check` returns a required part the receiver
  does not understand as an `Unsupported`, whose status is the 415 of
  RFC 5621 §8.4. `MultipartBuilder` writes one, with a boundary that occurs
  in no part. `sipral_ua::siprec` holds SIPREC recording metadata, the
  RFC 7865 model in RFC 7866's `application/rs-metadata+xml`: written,
  read through the same bounded reader dialog-info bodies use, built for a
  call by `RecordedCall`, and checked against the SDP's `a=label` lines;
  and the pieces of a recording session's INVITE: the SDP and metadata
  body with `Content-Disposition: recording-session`, the `+sip.src`
  feature tag and the `siprec` option tag. A
  `multipart` fuzz target reads any body and requires what it reads to be
  written back the same.
- **Conferences, presence documents and publishing, in `sipral-ua`.**
  `conference` reads RFC 4575's `application/conference-info+xml` and
  `Conference` merges full and partial notifications by §4.6: keyed users,
  endpoints, media and entries merged, `deleted` removed, a stale version
  discarded, and a partial document after a lost one held back with
  `ConferenceUpdate::Resubscribe`, which `UserAgent::request_full_state`
  answers with a refresh. `UserAgent::subscribe_conference` (and
  `Subscribe::conference`) sends `Event: conference`. `presence` reads and
  writes PIDF (RFC 3863) with the RPID activities in common use (RFC 4480).
  `Publication` is an RFC 3903 PUBLISH client driven like every other
  sans-I/O machine here: initial publish, `SIP-ETag` refreshes at the
  registration margin, modify, remove, 412 republished afresh, 423 retried
  with `Min-Expires`, 489 surfaced. Both XML formats go through the
  dialog-info reader and inherit its refusals.
- **The user agent keeps conferences, presence and publications itself.** A `conference` subscription merges every NOTIFY into its own `Conference` (`UserAgent::conference`), raises `UaEvent::ConferenceChanged`, refreshes by itself on a gap and unsubscribes when the conference is deleted; a `presence` subscription reads each PIDF into `UserAgent::presence` and `UaEvent::PresenceChanged`; `UserAgent::publish`, `publish_presence` (one per account), `republish`, `refresh_publication` and `unpublish` drive RFC 3903 over the endpoint, answering challenges with the account's credentials and reporting `UaEvent::Publication`. RFC 4579's `isfocus` is read from the far end's `Contact` (`call_conference`, `subscribe_call_conference`) and written by `OutgoingCall::focus` and `set_focus`; `OutgoingCall::recording_session` places an RFC 7866 recording session (`Require: siprec`, `+sip.src`, the offer and metadata as one `multipart/mixed` body).
- **Call audio as files, and L16 on RTP.** `sipral_media::formats`
  (none of it needs the `opus` feature): `ogg` writes RFC 3533 pages
  (lacing, continued/BOS/EOS flags, granule positions, the CRC with
  generator 0x04c11db7) and reads them back with every checksum,
  sequence and continuation checked; `ogg_opus` writes a `.opus` file
  from packets that are already encoded, RFC 7845's `OpusHead` and
  `OpusTags` (vendor `sipral`), granule positions at 48 kHz, the pre-skip,
  end trimming on the last page, and a page written out at least once a
  second (configurable); `wav` streams sixteen-bit PCM to any
  `Write + Seek`, stereo with the local side left and the remote side
  right, patches the sizes at `finish`, and finishes a file past 4 GiB as
  RF64 (EBU Tech 3306) instead of stopping. `sipral_media::l16` is RFC 3551
  §4.5.11 L16: big-endian samples at any rate and channel count, stereo
  interleaved left first, the static payload types 10 and 11, and the
  `L16/rate[/channels]` rtpmap encoding. Not yet wired into the call
  recording, the codec negotiation or the C ABI.
- **Conformance fixtures for RFC 5118 and RFC 4317.** The twelve IPv6
  torture messages of RFC 5118, unpacked from its Appendix A archive, and
  every offer/answer exchange of RFC 4317, taken from its text, live under
  `fixtures/rfc5118/` and `fixtures/rfc4317/` with SHA-256 manifests, and
  `sipral-core` tests hold the message parser, the answer builder and the
  media planner to each one. The IPv6 reference RFC 3261's grammar allows
  and RFC 4291 does not, `[2001:db8:::192.0.2.1]`, is now read as
  `2001:db8::192.0.2.1`, as RFC 5118 §4.10 asks implementations to
  tolerate it.
- **RTCP feedback for audio: RTP/AVPF and reduced-size RTCP.**
  `sipral_rtp::avpf` builds and reads the Generic NACK (RFC 4585 §6.2.1),
  times feedback by RFC 4585 §3.5 (Early packets rationed by `allow_early`,
  `T_dither_max`, Regular packets thinned by `trr-int` into full, minimal
  or suppressed), sends and accepts reduced-size RTCP once `a=rtcp-rsize`
  is in both offer and answer and a compound packet has gone first
  (RFC 5506), and reads and writes `a=rtcp-fb` (`nack`, `trr-int`; the rest
  ignored) and the `RTP/AVPF` and `RTP/SAVPF` profile names through the
  `sipral_core::sdp` model. New fuzz target `rtcp_fb`.
- **Calls negotiate RTP/AVPF and reduced-size RTCP, and run RFC 4585's RTCP when both ends do.** `CodecCatalog::with_feedback` offers `RTP/AVPF` (`RTP/SAVPF`, `UDP/TLS/RTP/SAVPF` when keyed) with `a=rtcp-fb:* nack` and `a=rtcp-rsize`, and answers an offer on a feedback profile with the lines this stack does; a stream whose offer and answer both name one runs `RtpSession::use_feedback`: AVPF's minimum interval, Early and Regular packets by RFC 4585 §3.5, `trr-int`, Generic NACKs for the packets it finds missing, and reduced-size Early packets once a compound one has gone (RFC 5506). Nothing is retransmitted; `StreamStatistics::feedback` and `feedback_counts` say what was agreed, sent and asked for.
- **The .NET and Python layers carry all of ABI 0.29, device mode first.**
  A stack opens the platform's own devices by default wherever the library
  can (Windows, macOS) and keeps application mode where it cannot or when
  asked; `SipralStack.Audio`/`stack.audio` choose microphone, speaker and
  ringer, gain, mute, the meter, activation and the ring. Calls gain the
  caller's typed identity, Answer-Mode and Alert-Info, `Reason` both ways, a
  3xx redirect, the SRTP suite a handshake settled on, and a move to a new
  network (`MoveTo`/`move_to`, `Readdress`/`readdress`); accounts gain the
  session timer, anonymity and trusted peers. The WPF sample is a softphone
  on the real device list with no audio code of its own, and Python gains
  `examples/softphone.py`.
- **The Swift and Kotlin layers carry ABI 0.29 whole.** A stack opens in
  the library's device mode wherever it has an engine for the platform
  (`AudioMode.platformDefault`, `SipralAudioMode.platformDefault`) and in
  application mode elsewhere, the packets the engine encodes sent from each
  call's own socket or its TURN connection; `SipralStack.audio` and
  `SipralClient.audio` list the devices under ids that survive a refresh,
  choose the microphone, speaker and ringer apart, keep gain and mute per
  direction across a change of device, meter each direction, ring, and open
  and close the devices by hand under manual activation, which
  `CallKitBridge.drive` ties to CallKit's audio session. A call's `Reason` is
  written (`hangup(reason:)`) and read (`endCause`, `endCauseOf`), an
  incoming call's asserted identity behind the account's trust gate, its
  `Privacy`, `Diversion` and `History-Info` are `CallerIdentity`, its
  `Answer-Mode`, `answer-after` and `Alert-Info` are `Answering`, a ringing
  call is redirected with a 3xx, an account takes a session timer, anonymity
  and its trusted peers, a DTLS-SRTP call names its suite, and a network
  change rebinds the signalling socket, points every account at it and
  moves each call's media (`networkChanged`, `moveMedia`). The macOS sample
  has no audio code of its own and shows the devices, the meters and who is
  calling; on Android, `SipralCallAudios` in the telecom helper runs every
  call's `AudioRecord` and `AudioTrack`, and the Compose sample has no audio
  code either.
- **The library opens the audio devices itself, for the stack that asks.**
  `sipral-audio` is the built-in engine: the platform's devices listed with
  their channel counts under handles that survive a refresh and an unplug,
  the microphone, the speaker and the ringer chosen separately, every call
  resampled to the device's rate and summed into the loudspeaker, the
  microphone into every call, a ring tone on the ringer's own output, gain
  and mute per direction kept across a device change, a level meter per
  direction, a device lost reopened on the system's route with the
  selection kept as a preference, a change the engine made told apart from
  one the operating system announced, activation either following the
  calls or left to the application for CallKit and Telecom, and every
  platform call bounded by a timeout so that a stuck driver is a status.
  macOS and iOS run on `sipral-io-coreaudio`'s voice-processing unit,
  Windows on `sipral-io-wasapi` — which now reports each endpoint's channel
  count — and Linux and Android keep pumping from the application. Over the
  C ABI (0.29): `sipral_stack_config_t::audio` (`SIPRAL_AUDIO_DEVICE`, with
  `audio_transmit_callback` for the application's socket, `audio_activation`,
  `audio_probe_ms`, `audio_device_rate_hz`), the fifteen `sipral_audio_*`
  entry points, `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED` (43) with its
  origin, `SIPRAL_STATUS_NO_SUCH_DEVICE` (13), `_DEVICE_UNUSABLE` (14) and
  `_DEVICE_TIMED_OUT` (15), and `SIPRAL_FEATURE_AUDIO_DEVICE` (2048). A
  zeroed configuration is application mode, so nothing changes for a C
  caller that pumps its own frames; the four idiomatic layers default to
  device mode where the platform has an engine (see above). The gate
  refuses a `target-cpu` or `target-feature` anywhere in the tree, so the
  packaged library needs no instruction beyond its target's baseline.
- **Who is calling, how the call asks to be answered, why it ended, and
  where to send it instead.** An incoming call's `IncomingCall` event and
  `call_identity` carry a typed `CallerIdentity`: `P-Asserted-Identity`,
  `Remote-Party-ID` and `verstat` behind a per-account trust gate
  (`Account::trust`, RFC 3325 §8), `Privacy`, `Diversion` (RFC 5806) and
  `History-Info` (RFC 7044, with RFC 4458's `cause` and the escaped
  `Reason`); and `Answering`: `Answer-Mode`/`Priv-Answer-Mode` (RFC 5373,
  `answermode` now understood in `Require`), `answer-after` and
  `info=alert-autoanswer`, and `Alert-Info` with RFC 7462's source URNs.
  `Account::privacy` places an account's calls anonymously (RFC 3323
  §4.1.1.3), asserting its identity only toward a trusted peer; once an
  account names a trust domain, identity fields stay inside it.
  `CallEnded::causes` carries the `Reason` (RFC 3326) of the BYE, the
  CANCEL or the refusal, `hangup_for` writes one on a BYE or a CANCEL
  (held with a CANCEL that waits for a provisional), and the BYE to a
  fork branch that answered too late says `cause=200` "Call completed
  elsewhere". `redirect` answers a call 3xx with a `Contact` list and a
  `Diversion`. Over the C ABI (0.29): the facts on every call event,
  `sipral_call_identity_count`/`_text` for the lists,
  `sipral_call_hangup_for`, `sipral_call_redirect`, `session_timer`,
  `privacy` and `trusted_peers` on `sipral_account_config_t` (the
  per-account session timer C lacked), and `SIPRAL_FEATURE_CALLER_IDENTITY`
  (`1 << 12`).

- **A call in progress moves with the network under it.** A change of
  address used to redo the registration and nothing else, so a call up at
  the time stayed up with the far end's audio going to an address that was
  gone. `UserAgent::network_changed` answering `Recovery::Rebuild` now
  raises `UaEvent::CallAddressWanted` for every call that can be offered a
  new description, and `MediaEngine::readdress` offers it at the media
  socket the application bound on the new network: a re-INVITE with `c=`
  and the port moved and nothing else, carrying the rebound account's
  `Contact` (RFC 3264 §8.3.1). A call running ICE is refused with
  `MediaError::MovesWithIce`. Over the C ABI (0.29):
  `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED` (45),
  `sipral_call_media_readdress` and `SIPRAL_FEATURE_CALL_READDRESS`
  (`1 << 13`). `Link`, `Network` and `Recovery` are re-exported from the
  facade. The lab's new `move` step takes the harness's container off the
  network mid-call and back at another address, and hears Asterisk's echo
  after the re-INVITE.

- **The C ABI names every SRTP suite the stack runs.**
  `sipral_srtp_suite_t` grew `SIPRAL_SRTP_SUITE_AES256_CM80` (4),
  `_AES256_CM32` (5), `_AEAD_AES128_GCM` (6) and `_AEAD_AES256_GCM` (7), so
  `SIPRAL_EVENT_KIND_MEDIA_SECURED` says which of RFC 6188's and RFC 7714's
  suites a call is running rather than `UNKNOWN`; the Swift, Kotlin and .NET
  enums are printed with them, and Python gains `sipral.enums.SrtpSuite`
  (ABI 0.29). The lab's Rust harness names the suite each SDES and
  DTLS-SRTP flow ran under on its result line, and the C harness the one
  each DTLS-SRTP handshake chose.
- **A call's diagnostics can be handed over redacted from Rust.**
  `sipral::redacted_call_record` returns a call's D1 record as JSON with
  every IP literal pseudonymised, and `sipral::redacted_recording` turns a
  D2 recording into a pcapng file with every message redacted, under a
  `Redactor` in `Hash` (keyed HMAC) or `Delete` mode; one redactor over
  both gives an address the same pseudonym in the two, behind the
  `redaction` feature, on by default and left off by the C ABI
  (`docs/14-diagnostics.md`).
- **The lab forks a call to two phones behind a NAT, every end relayed.**
  `scripts/lab.sh turn` (and `ice`) has Kamailio fork a call from a caller
  behind one NAT to two phones behind the other, each end with a relay on
  coturn and the path between the NATs blocked: both branches have to choose
  a path through coturn and carry the tone both ways before the mobile
  answers, the desk is cancelled, and all three relays have to be given back
  (`interop/harness/src/fork_ice.rs`).
- **The lab reaches TURN over TCP and TLS from the Kotlin, .NET and Swift
  agents.** Each agent's direct call reads `SIPRAL_TURN_TRANSPORT`,
  `SIPRAL_TURN_NAME` and `SIPRAL_TURN_CA` as the Python one does, and the
  relay step places the call from behind a NAT that drops every datagram to
  coturn: Kotlin and .NET over TCP and over TLS, trusting only the run's own
  certificate, and Swift over TCP alone, since its TLS is Network.framework's
  and the lab's containers are Linux.
- **A call's audio on Android survives what the platform does to it.**
  `SipralCallAudio` (in the `ConnectionService` helper) keeps one call's
  microphone and speaker through a cellular call answered over it — the
  telecom framework's `onHold` lets the device go at once and the far end
  is held with a re-INVITE, and `onUnhold` takes it back — through the
  framework moving the call focus to another calling application
  (`onConnectionServiceFocusLost`, API 28: the device is stopped before
  `connectionServiceFocusReleased`), through the audio server dying
  (`ERROR_DEAD_OBJECT` from `AudioRecord` or `AudioTrack`: both built again
  until they open, silence sent meanwhile), and through the framework's
  mute (`onMuteStateChanged`, a headset's or a car's button), with route
  changes reported. Every change is an `AudioTransition` on
  `transitions`, and `state` says where the audio stands. The logic is
  `org.sipral.telecom.CallAudio`, over any `AudioDevice`, in the JVM
  library; `AndroidAudioDevice` is its `AudioRecord`/`AudioTrack` device,
  and the Compose sample uses it and shows every transition. Run on an
  Android 16 emulator against the lab's Asterisk: a GSM call answered over
  a live call, the call held and resumed with media both ways, and the
  audio server stopped for 45 seconds mid-call and recovered
  (`docs/15-mobile.md`).
- **A call's audio on iOS survives what the system does to it.**
  `CallAudio` keeps one call's device through `AVAudioSession`
  interruptions (let go when one begins, taken back when it ends with
  `.shouldResume`, and left for the application otherwise), CallKit's
  hold, mute and audio session (`CallKitBridge.attach`: the device starts
  only after `provider(_:didActivate:)` and is let go at
  `didDeactivate`), a media services reset (the device built again from
  nothing) and a device that stops on its own, with route changes and
  their reason reported — each a `CallAudioTransition`.
  `AudioSessionObserver` carries the session's notifications onto it, and
  `VoiceProcessingAudioDevice` is a device over `AVAudioEngine` with the
  system's voice processing, a new engine on every open.
  `CallKitAdapter` configures the session's category on answering, handles
  `CXSetMutedCallAction`, and forwards `didActivate`, `didDeactivate` and
  `providerDidReset`.
- **`sipral-io-coreaudio` on iOS reports a unit the system stopped.**
  `Stream::poll` asks the unit whether it is still running, which is how an
  `AVAudioSession` interruption or a media services reset shows itself to
  the unit, and answers `StreamEvent::DeviceLost`; `Stream::recover` builds
  a new unit, the only thing that works after a reset. It used to answer
  `None` on iOS whatever had happened.
- **TURN through the lab, from Kotlin, .NET and Swift too.**
  `bindings/kotlin/examples/Agent.kt`'s `runDirectCall`,
  `bindings/dotnet/samples/Sipral.Sample.Agent/Program.cs`'s
  `RunDirectCallAsync` and `bindings/swift/Sources/SipralLabAgent/main.swift`'s
  `runDirectCall` each dial a peer straight at its address, no registrar
  between them (`SIPRAL_PEER_HOST`/`_PORT`/`_USER`), with
  `SIPRAL_STUN_SERVER` and `SIPRAL_TURN_SERVER`/`_USER`/`_PASSWORD` turning
  on that binding's own NAT traversal and `SIPRAL_ICE=required` asking ICE
  be required of the call — the same shape the Python binding's own
  `run_direct_call` already proved. `scripts/lab.sh`'s `ice_turn_flow` runs
  each behind the same two-NAT pair the Rust and C harnesses and the Python
  binding already prove TURN through (`NAT_PAIR_CALLER=kotlin`, `=dotnet`,
  `=swift`), without and then with a relay, both ends' allocations given
  back read off coturn's own log the same way every other driver's are.
- **The far end hanging up on its own is proven through the C ABI too.**
  `FLOW_PEER_HANGUP` (key `peerhangup`) is `interop/harness-c`'s own half of
  `Flow::PeerHangup`: it places the call at baresip's dedicated
  `baresip-hangup` account and only waits, never scheduling its own hangup,
  and passes on `end_reason == SIPRAL_CALL_END_REASON_REMOTE_HANGUP` alone —
  the same claim the Rust harness already proved, now proved from both
  drivers on every run of `scripts/lab.sh baresip`.
- **A buffer that ran dry is a count the C ABI and every binding carry.**
  `sipral_stream_stats_t::frames_underrun`, appended at the tail (ABI
  0.28, `MIN_SIZE` unmoved), is `Quality::underruns`: the frames the
  earpiece played as nothing because the jitter buffer had run dry while
  the far end was still sending. It reaches `sipral_media_statistics` and
  the record `SIPRAL_EVENT_KIND_MEDIA_STATISTICS` carries, and every
  binding reads it: `SipralStreamStatistics.FramesUnderrun` in .NET,
  `"frames_underrun"` in both of Python's statistics dicts, and the
  struct's own member in Swift (`frames_underrun`) and Kotlin
  (`framesUnderrun`).
- **A call running ICE says which paths it tried, and why each lost** — D5's
  transport and NAT half. `MediaSession::path_candidates` lists every
  candidate pair the agent's checklist held and every relay it held
  (`PathCandidate`), each with its outcome (`PathOutcome`): selected; valid
  and outranked by the pair selected, or nominated past; never answered;
  refused by the far end, with the STUN code; answered from another address
  (RFC 8445 §7.2.5.2.1); refused by the relay, with the TURN server's
  reason; never checked; and for a relay, held, given back unused (§8.3.1),
  or lost with the server's reason. The agent writes each outcome down as
  the transaction that decides it ends (`IceAgent::pair_report`,
  `IceAgent::relay_report`), so the list outlives the checklist §8.1.2
  prunes at the selection; a restart starts it again. Over the C ABI it is
  `sipral_media_path_candidate_count` and `sipral_media_path_candidate_at`,
  filling a `sipral_path_candidate_t` whose two addresses go into buffers
  the caller brings, with `sipral_path_kind_t`, `sipral_path_outcome_t` and
  `sipral_candidate_kind_t` naming the numbers (ABI 0.28); each binding
  has it as `pathCandidates()` / `path_candidates()` / `PathCandidates()`
  on a call's media.
- **An idle phone behind a NAT stays reachable over UDP.** Behind a NAT
  that filters by address and port (RFC 4787 §5), the registrar's INVITE
  gets in only while the NAT remembers this end sending to it, and the only
  thing sent while idle — the STUN refresh every 25 s — goes to the STUN
  server: in the lab a call 330 s after the REGISTER was dropped at the NAT.
  Every account whose `Contact` a STUN answer moved onto an address that is
  not the socket's own now sends its registrar a double CRLF, alone in a
  datagram, every 20 to 25 s while it holds a binding or is getting one;
  registrars drop it (RFC 3261 §7.5). RFC 5626 §3.5 names STUN for a UDP
  flow's keep-alive, but Asterisk answers none on its SIP port, so the
  double CRLF buys the same and asks the registrar to parse nothing. On by
  default, `UserAgent::keep_registrar_flows_alive` (`None` for off, 1 to 120
  s, `UaError::InvalidKeepalive` otherwise; `sipral_ua::keepalive`), and
  suspended with the stack (`UserAgent::suspending`), since a sleeping phone
  is woken by push. The C ABI's `sipral_stack_config_t` grew
  `registrar_keepalive` and `registrar_keepalive_ms` and
  `sipral_stack_settings_t` `registrar_keepalive_ms`, with
  `registrarKeepalive` in Swift and Kotlin, `registrar_keepalive` in Python
  and `RegistrarKeepalive` in .NET. `scripts/lab.sh nat-idle` places the
  call 330 s after the REGISTER behind the lab's NAT, with the keep-alive on
  and then off. `Endpoint::bound_transport` says what a bound transport
  speaks and where it is bound.
- **A vulnerability handling policy a buyer's security review can read.**
  `SECURITY.md` now says what happens after a report — acknowledgement,
  triage, fix, coordinated disclosure, a GitHub Security Advisory and a
  CVE through GitHub's CNA program, credit — with the maintainer's own
  time commitments (acknowledgement within 3 business days; critical or
  high severity fixed within 30 days of triage; disclosure within 90 days
  of acknowledgement unless extended by written agreement). Reporting
  itself stays through the channel a private repository's invited readers
  already have; GitHub's private vulnerability reporting becomes the
  channel the day this repository turns public. `docs/20-security-model.md`
  now links to it, and `scripts/check.sh` fails when `SECURITY.md` is
  untracked or loses its reporting, handling or supported-versions section.
- **A CycloneDX SBOM beside every packaged artefact.** `scripts/package/
  {wheels,nuget,aar,xcframework}.sh` each now write a `.cdx.json` next to
  the wheel, `.nupkg`, `.aar` or `.xcframework` they build, listing
  `sipral-ffi`'s own normal dependency graph at the features and target
  that artefact was actually built with — name, version, SPDX licence
  expression and a purl per crate — plus libopus itself as its own
  component, with its own version, in a `--with-opus` build: the C library
  `opusic-sys` vendors rather than declares as a dependency of its own.
  The packaged file's SHA-256 goes on the document's own component, when
  one exists to hash (a `--dry-run` `xcframework.sh` builds no zip, so
  that SBOM carries no hash of one). New: `tools/sbom-gen`.
- **A relay over TCP or TLS, for the network that lets no UDP out.** A call
  can now reach its TURN server over TCP, or over TLS on 5349 (RFC 8656
  §3.1), and use the relay exactly as over UDP: allocated before the call,
  offered as its relayed ICE candidate, carrying its checks and its audio,
  refreshed, and given back. The connection is the application's, as a SIP
  stream is: `sipral::Relays::over` names the transport, what is written for
  the server is marked for the connection (`RelayDatagram::transport`,
  `Datagram::transport`, `MediaEngine::poll_turn_stream`), and what the
  connection carries goes back in whatever pieces it arrived in
  (`Relays::receive_stream`, `MediaEngine::receive_stream`,
  `MediaSession::receive_stream`), put back together by
  `TurnClient::push_stream`/`poll_stream` with ChannelData padded to whole
  words on the stream (§12.5). A connection that closes, or stops carrying
  TURN, takes the relay with it (`TurnError::ConnectionLost`). The
  connection's own mapping is never offered as a server-reflexive candidate
  or written in `c=`. The full ICE agent can gather over one too
  (`TurnServer::transport`), and a datagram from the server's address is not
  a relay's over a connection. Over the C ABI: `turn_transport` on
  `sipral_stack_config_t`, `SIPRAL_EVENT_KIND_TURN_STREAM` (42) asking the
  application to open the connection and saying when to close it,
  `sipral_stack_turn_connected`, `sipral_stack_turn_receive` and
  `sipral_stack_turn_closed`, `protocol` on `sipral_media_packet_t`,
  `SIPRAL_STATUS_STREAM_BROKEN` (12) and `SIPRAL_FEATURE_TURN_STREAM`
  (1024). All four bindings open the connection themselves — Swift with
  Network.framework, Kotlin with `SSLSocket`, Python with `ssl`, .NET with
  `SslStream` — checking the server's certificate against a configured name,
  with the platform's trust or with roots the application hands over, so a
  relay over TLS is one option on the stack. The lab proves it from behind a
  NAT that drops every datagram to coturn: over TCP through the C ABI, over
  TLS through the Python bindings.
- **ICE restarts in the full role, from either end.** A peer's re-offer
  that changes both `ice-ufrag` and `ice-pwd` is answered with new
  credentials of this end's own (RFC 8839 §4.4.2.1) instead of the ones the
  running agent held, and `MediaEngine::restart_ice` offers one from this
  end: the call's last description with the ICE lines written as for a
  first offer, the candidates the agent still holds and the role it had.
  Once the exchange is complete the agent restarts (RFC 8445 §9) and checks
  again under both ends' new credentials, while the pair it had selected
  carries the audio until the new session selects one, reported as another
  `MediaEvent::PathChosen`; a restart the far end refuses leaves ICE as it
  was. It is the remedy for `MediaError::IcePathLost`. A call running no
  ICE agent is refused with the new `MediaError::NoIce`. Over the C ABI a
  peer's restart is followed the same way, and `sipral_call_restart_ice`
  starts one from this end (ABI 0.28; `restartIce()` / `restart_ice()` /
  `RestartIce()` on a call in the four bindings).
- **The quality report says what the far end measured.** The RFC 6035
  `vq-rtcpxr` report sent on call end carries a `RemoteMetrics` set from
  the last RTCP XR VoIP Metrics block (RFC 3611 §4.7) the far end sent
  about this end's stream — its jitter buffer, loss, burst and gap
  figures, delays, signal and noise levels and echo return loss where it
  measured them, and its R factor and MOS — and leaves the set out when it
  sent none. `RtpSession::far_voip_metrics` is the block itself, and
  `QualityReportMetrics::remote` (`RemoteQualityMetrics`) what the report is
  written from.
- **A buffer that ran dry is counted where call quality is read.**
  `Quality::underruns` counts the frames played as nothing because the
  jitter buffer had run dry while the far end was still sending, and
  `Quality::loss_rate` takes each of them as it takes a concealed frame, so
  `StreamStatistics::score` and `is_suffering`, and the C ABI's
  `loss_rate`, `score` and `suffering`, fall with it. RTCP-XR stays as RFC
  3611 §4.7.1 defines it, a share of packets lost or discarded, which an
  under-run is neither: a fast earpiece rated R 93 and MOS-LQ 4.4 while its
  tone was cut off 1 774 times in two minutes (`docs/19-numbers.md`).
- **`scripts/lab.sh nat` calls the stack behind the NAT too.** After the
  call placed from behind `interop/nat`, the C harness registers `labuser`
  there again with STUN and Asterisk calls the binding it holds, into a new
  extension (9010) that echoes for eight seconds and hangs up. The INVITE
  has to be recognised as the account's, the 2xx answered through
  `sipral_call_answer_media` has to name the public address in its
  `Contact`, and Asterisk's ACK, its BYE and the echo all have to arrive;
  the harness says which did not. A C ABI unit test pins the same answer
  path without the lab.
- **A REFER from outside any call can be taken — when the application asks.**
  Click-to-dial from a switchboard or a CRM (RFC 3515 §4.1) is a REFER that
  names no dialog. With `UserAgent::allow_referrals(true)` — the C ABI's
  `sipral_stack_config_t::referrals`, and `referrals` in every binding — it
  meets the same screening an INVITE does and reaches the application as
  `UaEvent::ReferralRequested` (`SIPRAL_EVENT_KIND_REFERRAL`, 41) with the
  target, whether it is attended, its `Referred-By`, the account it arrived
  for and the REFER itself; `accept_transfer` / `sipral_call_accept_transfer`
  answers 202, opens the implicit subscription's dialog, sends `100 Trying`
  and places the call exactly as a transfer does, reporting every answer to
  the referrer until the last, and `reject_transfer` refuses it. The
  referral is a call-kind handle that names a request, not a call. One left
  unanswered for 64·T1 is answered 408 and reported as
  `UaEvent::ReferralLapsed` (kind 41 again, with its status). Off by default,
  and refused 403 then: a peer that can make a phone dial is a toll-fraud
  vector. Python `Stack.accept_referral`, Swift `SipralStack.acceptReferral`,
  Kotlin `SipralClient.acceptReferral` and .NET `SipralStack.AcceptReferral`
  open the placed call's media socket and return it; `reject_referral` and its
  siblings refuse.
- **RFC 4488's `Refer-Sub: false` is granted** to every REFER this end takes,
  in a call or out of one: the 202 says so and no subscription, NOTIFY or
  dialog follows. `norefersub` is an option tag this end understands.
- **`SIPRAL_ICE_LITE` (4) crosses the C ABI**, on the stack's `ice` or a
  call's own, for a server reachable at the address it advertises answering
  full ICE peers; `Ice.LITE`, `.lite`, `SipralIce.LITE` and `SipralIce.Lite`
  in the four bindings. The facade's new `ice-lite` feature names
  `IcePolicy::Lite` without `headless`, and `sipral-ffi` turns it on.
- **The C harness listens.** `harness-c listen` answers a call or takes a
  referral through the C ABI, and `scripts/lab.sh referral` and
  `scripts/lab.sh icelite` point the Rust harness at it: a REFER from outside
  any call refused, then taken and placed to Asterisk's echo, and a call that
  requires ICE answered by `SIPRAL_ICE_LITE`.
- **The lab proves TURN and ICE through the Python bindings too, not only
  the two harnesses.** `bindings/python/examples/agent.py` can now dial a
  peer straight at its address, no registrar between them
  (`SIPRAL_PEER_HOST`/`_PORT`/`_USER`), with `SIPRAL_STUN_SERVER` and
  `SIPRAL_TURN_SERVER`/`_USER`/`_PASSWORD` turning on `Stack`'s own NAT
  traversal and `SIPRAL_ICE=required` asking `Ice.REQUIRED` of the call —
  `scripts/lab.sh`'s `ice_turn_flow` runs it behind the same two-NAT pair
  the Rust and C harnesses already prove TURN through, without and then
  with a relay, both ends' allocations given back read off coturn's own
  log exactly as the other two drivers' are.
- **The far end can end a call on its own, and the lab proves it.** A
  fourth baresip peer, `baresip-hangup` (`interop/baresip/config-hangup`),
  loads `ctrl_tcp` — nothing in account or call configuration can make
  baresip hang an already-answered call up by itself, its own
  `call_local_timeout` cancelling the instant one is answered — so
  `scripts/lab.sh`'s `baresip_ctrl_hangup` sends it one command a couple
  of seconds into the call instead, the same code path its own menu
  module's hangup key takes. `Flow::PeerHangup` (key `peerhangup`) is the
  harness's own half: it places the call and only waits, never scheduling
  its own hangup, and passes on `CallEndReason::RemoteHangup` alone.
- **A call's D2 recording exports as pcapng, redacted for GDPR before it
  leaves the organisation.** `diag-export` (`tools/diag-export`, on
  `sipral-diag`) turns a `.sipralrec` file into a pcapng Wireshark and
  `tshark` read as a SIP call — every message the recording holds, as a UDP
  or TCP packet at its recorded address and offset. `--redact
  --key-file <path>` (or `--redact --delete`) rewrites SIP/SDP user parts,
  display names, phone numbers and IP literals into a stable HMAC-SHA256
  pseudonym or a placeholder, and drops `Authorization`/`Proxy-Authorization`
  and SDES keys outright; the redaction is also `sipral_diag::redact::redact_message`,
  a plain Rust function a facade can call without a new C ABI entry point.
- **linux-arm64 packaging, from a host with no arm64 hardware.**
  `scripts/package/wheels.sh --linux-arm64` and `scripts/package/nuget.sh
  collect --rid linux-arm64` cross-compile `sipral-ffi` for
  `aarch64-unknown-linux-gnu` in an unprivileged Docker container
  (`scripts/package/docker/aarch64-cross.Dockerfile`: Debian's own cross
  toolchain, linked against a `manylinux_2_28_aarch64` sysroot taken out
  of that image with `COPY --from`, never executed) and produce a
  `manylinux_2_28`-tagged wheel and a `linux-arm64` NuGet runtime, each in
  the plain and `--with-opus` variant. `scripts/package/qemu-verify.sh`
  proves the result runs without ever giving it privileges: an
  unprivileged container installs `qemu-user` and runs the cross-compiled
  C smoke test and the installed wheel's `bindings/python/tests` through
  `qemu-aarch64` named explicitly on its command line, with no
  `--privileged` and no binfmt registered on the host; the native's own
  glibc symbol versions are checked to confirm none is newer than
  `GLIBC_2.28`. `scripts/check.sh`'s `package --dry-run` step exercises
  both scripts' `linux-arm64` path when Docker is present; without Docker
  it lints `sipral-ffi` for `aarch64-unknown-linux-gnu` and checks the
  cross path's files instead of skipping, and the container build is the
  Linux lab machine's step (`docs/11-testing.md`).
- **SRTP offers and accepts AES-256 and AES-GCM, not only AES-128-CM.**
  `AES_256_CM_HMAC_SHA1_80`/`_32` (RFC 6188) and `AEAD_AES_128_GCM`/
  `AEAD_AES_256_GCM` (RFC 7714) join the three suites SDES already carried;
  the AEAD suites tie confidentiality and integrity into one AES-GCM call
  rather than pairing AES-CM with a separate HMAC. An SDES offer now
  carries two `a=crypto` lines, strongest first — `AEAD_AES_256_GCM`, then
  `AES_CM_128_HMAC_SHA1_80` — each with a master key of its own: four
  pushed the INVITE that answers a digest challenge past RFC 3261
  §18.1.1's 1300 octets, and a phone on UDP alone never placed the call.
  The other five suites are accepted when offered; *answering* one stays
  bound to RFC 4568 §5.1.2's own terms, the offerer's own order, the first
  line this stack can be held to, so a peer's own preference is never
  overridden.
  DTLS-SRTP now negotiates `SRTP_AEAD_AES_128_GCM`/`_256_GCM` (RFC 7714
  §14.2) alongside the original two AES-128-CM profiles and prefers the
  strongest one both ends share — RFC 5764 leaves that choice to the
  server, unlike SDES — so two calls placed with this stack settle on
  `AEAD_AES_256_GCM`; a peer offering only the two AES-128-CM profiles
  still completes on one of those. Every RFC 7714 §16–§17 and RFC 6188 §7
  test vector passes byte for byte.
- **The .NET binding can get a call past a NAT.** `SipralStack`'s
  constructor grew `nat`/`stunServer` and `turnServer`/`turnUsername`/
  `turnPassword` for a relay, alongside the codec/frame/DTMF/SRTP
  options it already took; `ice`, on the stack or on `PlaceCall`, turns
  on ICE, which is what puts a relay to use. `PlaceCall`/`AnswerCall`
  wait out the media socket's own mapping (and, with a TURN server, its
  relay) before the offer or answer is written, so the public address
  is there from the first packet, and `SipralEventArgs.Nat`/`Relay` are
  the idiomatic reading of the ABI's own numbers for both events.
- **The Python binding can get a call past a NAT.** `Stack(nat=Nat.STUN,
  stun_server=...)`, and `turn_server`/`turn_username`/`turn_password`
  for a relay, join the codec/frame/DTMF/SRTP options `Stack.__init__`
  already took; `ice=` on the stack or a call turns on ICE, which is what
  puts a relay to use. `place_call`/`answer_call` wait out the media
  socket's own mapping (and, with a TURN server, its relay) before the
  offer or answer is written, so the public address is there from the
  first packet, and `sipral.enums.Ice`/`Nat`/`NatMapping`/`NatRelay` and
  the matching event fields are the idiomatic reading of the ABI's own
  numbers for all of it.
- **The Swift and Kotlin layers get past a NAT.** `SipralStack` and
  `SipralClient.open` take an ICE policy, a STUN server, a TURN server
  with its credential and the G.729 Annex B setting, all defaulting to
  what they did before. With a STUN server every account's `Contact` and
  every call's SDP name the public address the server reports: each
  call's media socket is mapped before the call is described, read for
  the stack until the call has media, and given back when it carries no
  call. Media and farewells go to the address the stack names, so a call
  can run over the path ICE chose or a TURN relay. The NAT mapping and
  relay events are decoded (`SipralEvent.natData`/`relayData`,
  `natOf`/`relayOf`), and a TURN password stays out of every
  `description` and `toString`.
- **The Swift package runs on the iOS Simulator.** The distribution
  package `xcframework.sh` prints over `CSipral.xcframework` now carries
  the whole `Sipral` module — `SipralStack`, `Call`, `CallKitBridge`,
  `PushKitBridge` and the rest, not only the printed `SipralAbi.swift` —
  and its test suite, which `xcodebuild test` runs on a simulator against
  the XCFramework's simulator slice. A call from the simulator to
  `SipralLabAgent` on the host is an opt-in test (`SIPRAL_PEER`), which
  can also register with a registrar and call through it, or wait there
  for a call and answer it (`SIPRAL_REGISTRAR`), and
  `CallKitAdapter` is tested against CallKit's own action classes on iOS.
  `SipralStack.takeIncomingCall` hands over an incoming call without
  answering it, so that CallKit's Answer is the one answer it gets.
  `docs/15-mobile.md` says what the simulator cannot show: it refuses
  every third-party `CXProvider`, and registers no VoIP push without the
  signing a device needs.

- **G.729's Annex B can be switched off from C.** Rust had
  `CodecCatalog::with_g729_annex_b` and the C ABI had nothing, so a C, Swift,
  .NET, Kotlin or Python application could not stop an offer saying
  `annexb=yes`. `sipral_stack_config_t::g729_annex_b` is that setting as a
  `SipralToggle` — on by default, `SIPRAL_TOGGLE_OFF` for `annexb=no` in
  offers and answers and no SID frames from this end — and
  `sipral_stack_settings_t::g729_annex_b` reads it back, both appended at
  their struct's tail.
- **A call can be relayed through a TURN server.** `sipral::Relays`
  allocates a relay (RFC 8656) on a TURN server for a media socket before
  its call, with the long-term credential the server knows this end by, and
  `CallMedia::relay` hands it to the call: under a full ICE policy it is the
  call's relayed candidate, beside the host and server-reflexive ones, and
  ICE uses it only when nothing cheaper answers. From then on the call's
  agent installs the permissions and binds the channel the media needs,
  keeps the allocation and the NAT binding under it alive, and gives it
  back with a Refresh of lifetime zero when the call ends, when ICE settles
  on another pair, or when the peer answers without ICE. Over the C ABI,
  `turn_server`, `turn_username` and `turn_password` on
  `sipral_stack_config_t` do the same for every socket
  `sipral_stack_nat_map` names, through the calls that already carry its
  STUN request, and `SIPRAL_EVENT_KIND_NAT_RELAY` (40) says what the server
  gave. The password is in no `Debug`, no event and no error text, and is
  overwritten when it is dropped. `scripts/lab.sh turn` proves it: two
  stacks behind two NATs that drop everything between them but SIP fail to
  connect without a relay, and with one the call completes through coturn
  and both allocations are given back — placed from Rust, and from C
  through `sipral_stack_config_t` and nothing else, once with the C end's
  own relay the only path the audio has.
- **A relay is kept, or given back, wherever the call around it goes.** A
  description refused before it left — a call or transfer the user agent
  will not place, a ring or an answer refused — hands its relay back whole
  (`MediaEngine::poll_returned_relay`, `Relays::put_back`) for the next call
  on the socket, where it used to lapse at the server. A call that rings
  longer than the allocation's lifetime less a minute keeps it: what the
  waiting agent sends comes out of `MediaEngine::poll_waiting_transmit`, the
  server's answers go in through `MediaEngine::receive_waiting`, and over
  the C ABI both ride `sipral_stack_poll_stun` and
  `sipral_stack_receive_stun` until the call has a media handle. On a forked
  INVITE the relay moves to the branch that is answered and kept while the
  first still rings. `sipral_stack_nat_unmap` gives back the relay of a
  socket that will carry no call, which until now was kept for as long as
  the stack lived and left to lapse after it was destroyed; one released
  while its Allocate is still unanswered (`Relays::release`) is given back
  when the answer arrives, where it used to be forgotten and left allocated.
- **An hour on a call, and what the jitter buffer did for all of it.**
  `scripts/lab.sh drift` — not part of a run that names nothing, since it
  takes an hour — holds three calls to Asterisk's echo for sixty minutes,
  each with its earpiece's clock set a known number of parts per million
  fast, slow or true, because the lab's two ends read one host's clock and
  would otherwise drift by nothing. Every five minutes it prints each call's
  buffer depth, frames shrunk, stretched, concealed and played as silence
  for want of a packet, and the skew those come to, and it fails if a call
  ends early, a buffer grows past 250 ms, audio stops or stalls, the
  measured skew is more than a quarter of the run's skew from the one
  given, or a buffer runs dry in the middle of the tone. The first full
  hour is in `docs/19-numbers.md`: no buffer ever deeper than its 20 ms
  target, a slow earpiece's drift shrunk out of pauses, and a fast one's
  heard as a 20 ms gap every eighty seconds or so, since at a one-frame
  target the buffer runs dry before it would stretch a pause — which the
  flow now fails on.
- **A hundred calls' worth of signalling, measured and tested.**
  `crates/sipral-ffi/tests/signalling_load.rs` puts two stacks — a user agent
  and a media engine each — on either end of a hundred concurrent calls with
  no network between them: every INVITE challenged and answered again with
  digest credentials the test verifies, a reliable 180 and its PRACK, the 200
  and its ACK, a hold, a resume and a BYE. It fails if any call ends the wrong
  way, if a single message is missing or extra against what the exchange
  makes, or if anything goes out once every transaction's timers have run.
  It prints the wall time each end spends inside the library per call set
  up and per transaction, the messages a second one stack gets through, and
  the memory a live call holds at each end, counted by its own allocator.
  `scripts/bench.sh` runs it at a hundred calls and at a thousand, and
  `docs/19-numbers.md` has the figures.
- **`crates/sipral-aec-webrtc` ships its own licence texts.** It sits outside
  the workspace `tools/license-gen` generates `THIRD-PARTY-LICENSES.txt`
  from, so nothing it links — the three `webrtc-audio-processing` crates,
  the vendored C++ library itself, its two bundled third-party components
  (rnnoise, pffft) and abseil-cpp, its one fetched meson subproject — ever
  reached a shipped notice. `cargo run -p sipral-license-gen -- --aec` now
  generates `crates/sipral-aec-webrtc/THIRD-PARTY-LICENSES.txt` from that
  crate's own `Cargo.lock` and from what its build actually vendors or
  fetches, and `scripts/check.sh` checks it is current once that crate is
  built.
- **A fuzz target for the TURN client against a relay that answers
  anything.** `turn` fuzzed only the framing and ChannelData; the client's
  own state machine — allocation, refresh, permissions, channels, stale
  nonces, the password algorithm a challenge offers — had never been driven
  by a hostile relay. `turn_client` runs it from a program whose answers
  carry the request's own transaction id and can be signed with the
  configured credential's key under either algorithm, so the paths behind
  the integrity check are reached, and asserts that every control message
  parses, every range indexes its datagram and no input raises events
  without end.
- **Full ICE is proven between two stacks behind two NATs, and its start-up
  cost is measured.** `scripts/lab.sh ice` now puts one interop harness behind
  each of two NATs, with coturn between them: both require ICE, neither can
  reach the other's host candidate, and the call has to find its path on the
  server-reflexive candidates STUN gave them, with the tone crossing it both
  ways. The time from the offer, and from the answer, to
  `MediaEvent::PathChosen` is printed on every run, and `docs/06-nat.md`
  records what it measured.

- **A headless agent on a public server can answer as an ICE-lite endpoint.**
  `IcePolicy::Lite`, which exists only in a build with `headless`, writes
  `a=ice-lite`, fresh credentials and one host candidate — the socket's own
  address, or `CallMedia::public_address` behind a one-to-one NAT — answers a
  full peer's connectivity and consent checks under the call's short-term
  credential, and carries the audio on the pair that peer nominates,
  reported as `MediaEvent::PathChosen`. A peer's ICE restart is answered with
  new credentials while the old pair keeps the audio until the new one is
  nominated, and an offer without ICE is now answered without any ICE
  attributes, for every policy. `headless-socket-agent --ice-lite [--public
  ip]` turns it on, and `scripts/lab.sh ice` proves it against the interop
  harness requiring ICE and against Asterisk's own ICE.

- **G.729 Annex B, bit-exact against every Annex B conformance stream and
  input.** `sipral_media::g729::Encoder::with_dtx` makes an encoder with
  Annex B's voice activity detector and discontinuous transmission:
  `encode` now returns `Encoded::Speech`, `Encoded::Sid` or
  `Encoded::Nothing`, and an encoder made with `new` still sends speech
  every time. The decoder gains `decode_sid` and `untransmitted`, turns a
  SID frame into comfort noise with the SID's spectrum and level, carries a
  lost frame in a pause on as the pause (B.4.5), and `decode_into` decodes a
  SID frame at the end of a payload. All four Annex B inputs encode to the
  reference streams — each frame's type and every bit — and all six Annex B
  streams decode to the reference output sample for sample;
  `docs/05-media.md` has the table and the places where the streams and the
  text part ways. The `media_g729` fuzz target now drives SID frames,
  frames not sent and an encoder with DTX.
- **The Kotlin binding carries an event's whole payload, not just its head.**
  The generator now flattens every arm `sipral_event_payload_t` declares
  across JNI, and `SipralEvent.payload` reads them back as one instance of
  each arm's own class -- an RFC 4733 digit, a codec, a media fault's
  reason, registration state details, the NAT mapping and the rest are all
  readable from Kotlin now, the same as from C, Swift and C#. A buffer or a
  whole record behind a pointer is only ever dereferenced for a kind that
  actually wrote that arm (`crates/sipral-ffi/src/event.rs`'s
  `EVENT_KIND_ARMS`, read by the generator); every other kind sees it as
  null, the same as before the library set it, rather than a pointer
  reinterpreted from another arm's own data, which segfaulted the shim
  outright the one way `docs/08-ffi.md`'s existing "reading another arm is
  defined" promise does not cover. `org.sipral.idiomatic` reads
  `payload.media.digit` and `payload.registration.state` directly instead
  of the workarounds this replaces.
- **G.729 in a call, offered only when it is named.** `Codec::G729` is in
  every build and out of the default offer: a codec order that names
  `G729` puts it on payload type 18 (`SIPRAL_CODEC_G729` in the C ABI),
  ten-millisecond frames, two to a packet by default, lost frames concealed
  by the codec's own concealment. Annex B comes with it: an offer says
  `annexb=yes` unless `CodecCatalog::with_g729_annex_b(false)` turns it
  off, an answer follows the offer (RFC 4856 §2.1.9 reads a missing
  `annexb` as yes), and where both descriptions allow it the encoder sends
  a pause as a SID frame and then nothing, marking the next talk spurt's
  first packet. A SID frame received plays as the codec's own comfort
  noise, carried on through the frames the far end does not send, whatever
  was negotiated, and such a pause is not reported as a stalled stream
  while the far end's RTCP keeps arriving. A `media_g729` fuzz target
  covers the decoder, the payload reader and the encoder, and the lab runs
  a G.729-only call through Asterisk's echo extension, untranscoded, and
  hears its own tone come back — from Rust, and from C with the codec
  named in that one call's `sipral_call_config_t::codecs`.
- **A G.729 encoder, bit-exact against every Annex A conformance input.**
  `sipral_media::g729::Encoder` encodes eighty samples into a ten-octet
  frame, or a buffer of several frames into an RTP payload, in Annex A's
  reduced-complexity form: the LP analysis and LSP quantization, the
  open-loop and closed-loop pitch searches, the depth-first search of the
  fixed codebook, and the gain quantizer with its preselection. All seven
  inputs the ITU publishes with Annex A encode to the reference streams bit
  for bit, and one of them encoded and decoded gives the reference output
  sample for sample; `docs/05-media.md` has the table and says which parts
  the streams check and which they never reach.
- **A G.729 decoder, bit-exact against every Annex A conformance stream.**
  `sipral_media::g729::Decoder` decodes a ten-octet frame into eighty
  samples, conceals a lost one, and decodes a payload of several; written
  from the Recommendation's text with Annex A's postfilter, the trained
  tables the text does not print copied mechanically from the software
  annex's table file, and every open point of the fixed-point arithmetic
  settled against the ITU's conformance streams, which are used where they
  were obtained and never committed. All ten streams decode sample for
  sample; `docs/05-media.md` has the table and the places where the streams
  and the text disagree.
- **A `THIRD-PARTY-LICENSES.txt` that actually carries the licence texts a
  binary has to ship.** `THIRD-PARTY-NOTICES.md` named the dependencies and
  their licences but reproduced no licence text and no MIT copyright line, so
  a licensee following it was not meeting the MIT and BSD terms it pointed
  at. The new file, generated by `tools/license-gen` from the normal
  dependency graph of `sipral` and `sipral-ffi` across every shipped target,
  carries each component's name, version, licence expression and full
  licence text as that component's own source ships it; `scripts/check.sh`
  regenerates and compares it so it cannot go stale.
- **A fuzz target for what the headless socket's messages do once decoded.**
  `headless_media` drives one `HeadlessSession` through any order of heard
  audio, queued frames, codec frames filled, barge-ins and codec-rate
  changes, checking that neither queue outgrows its capacity, that every
  frame read for the agent is exactly one frame, and that nothing plays
  after a barge-in until the agent queues something new. Beside it, tests
  run a 440 Hz tone both ways through every pair of the four socket rates
  and the codec rates, at frame sizes that do not divide one another, and
  across a codec change mid-call: real time to the sample, at the right
  pitch. The in-process call test now holds and resumes its call, and
  requires both re-INVITEs to reach the agent as changes and neither as a
  second `answered`.
- **A softphone behind a NAT says where it can really be reached (STUN,
  RFC 8489).** Off by default; on with `SIPRAL_NAT_STUN` and a `stun_server`
  in `sipral_stack_config_t`, or with `sipral::Mappings` from Rust. The stack
  asks the server where its signalling socket appears from, moves every
  account's `Contact` onto that address and registers it, and asks again
  every 25 seconds, which also keeps the NAT's mapping open; a media socket
  named with `sipral_stack_nat_map` is asked once before its call, and the
  call's `c=` and `m=` name what the server saw — and, with ICE on, so does a
  server-reflexive candidate beside the host one. A mapping that moves
  re-registers at once, and a server that never answers leaves every address
  as it would have been without STUN. `SIPRAL_EVENT_KIND_NAT_MAPPING` says
  what each socket learned, and `SIPRAL_FEATURE_STUN` whether the build has
  it. Proven in the lab from behind a NAT, against coturn and Asterisk.
- **Platform packages: an XCFramework, an AAR, a NuGet package and Python
  wheels, each built by its own script under `scripts/package/`.**
  `xcframework.sh` builds and `lipo`s macOS, iOS device and iOS Simulator
  natives into one `CSipral.xcframework`, with a distribution `Package.swift`
  over it. `nuget.sh` assembles `runtimes/<rid>/native/` for `win-x64`,
  `osx-arm64`, `osx-x64` and `linux-x64` from natives collected on whichever
  machine builds each one, over the existing `Sipral.csproj` unchanged.
  `wheels.sh` bundles the native library into the ordinary wheel
  `pyproject.toml`'s own backend builds and retags it for the platform that
  native was built for, closing what `docs/08-ffi.md`'s Python section used
  to list as missing. `aar.sh` builds `arm64-v8a`, `armeabi-v7a` and
  `x86_64` with `cargo-ndk` in a container carrying its own Android NDK, and
  assembles `sipral.aar` by hand, straight to Android's own archive format,
  rather than pulling in Gradle and the Android Gradle Plugin for one
  packaging script. Every script stops before publishing anything, and
  `scripts/check.sh` gained a `package --dry-run` step that runs all four:
  the macOS and iOS natives, the bundled wheel and the `osx-*`/`linux-x64`
  slice of the NuGet package for real on whatever machine runs the gate, and
  the rest structure-checked without a fabricated native standing in for one
  nothing there built.
- **The interop lab can carry a call on a Windows machine's real audio
  devices.** `scripts/lab.sh wasapi up` makes the lab reachable from the
  LAN, and `interop/wasapi/run.ps1` drives a call to the echo extension
  whose microphone and earpiece are VB-CABLE's two WASAPI endpoints, proving
  audio crosses `sipral-io-wasapi` in both directions in a real call — the
  Windows counterpart to the PipeWire flow already in the lab.
- **A hand-written Swift layer over the generated `SipralAbi.swift`:**
  `SipralStack`, `Account` and `Call` as classes, events as an
  `AsyncStream`, errors as `throws`, and `CallKitBridge`/`PushKitBridge`
  running `docs/15-mobile.md`'s wake-up sequence behind small protocols so
  the core module also builds on Linux. Tested against two real stacks on
  loopback (register-less direct calls, hold/resume, DTMF, media, handle
  release with pending events) and, in the lab, as `labuser-agent-swift`, a
  third Asterisk-registered account `scripts/lab.sh` dials, answers and
  carries DTMF over. A skeleton macOS SwiftUI sample
  (`bindings/swift/Sources/SipralSampleMac`) shows registration, a call,
  hold, DTMF and devices wired to the same layer.
- **An idiomatic Kotlin layer, `org.sipral.idiomatic`, over the generated
  `SipralAbi.kt`.** `SipralClient`, `SipralAccount`, `SipralCall` and
  `SipralMedia` wrap the handles as `AutoCloseable` classes, events arrive
  as a `kotlinx.coroutines.Flow`, and placing a call or registering an
  account is a suspend function that completes once the matching event
  does. A hand-written JNI helper beside the generated shim
  (`bindings/kotlin/sipral/src/main/jni/idiomatic_media.c`) builds the two
  structs — `sipral_media_packet_t` and `sipral_transmit_t` — the generator
  cannot yet construct from Kotlin, so the layer can drive real RTP.
  Exercised against the shared library on a JVM: two stacks on loopback
  place a call, answer, exchange RTP while idle, hold, resume, send DTMF,
  hang up, and check that both a media and a stack handle answer
  `SIPRAL_STATUS_STALE_HANDLE` once closed.
- **The .NET binding gets its idiomatic layer.** `bindings/dotnet/Sipral`
  writes `SipralStack`, `Account`, `Call` and `CallMedia` by hand over the
  generated `SipralAbi.cs`, the way the Python binding already writes
  `Stack`/`Account`/`Call` over its own generated file: every handle a
  `SafeHandle` subclass, events as both an ordinary C# `event` on the poll
  thread and an `IAsyncEnumerable<T>` off it, `Task`-returning helpers for
  what the ABI completes through events, and PCM crossing as
  `Span<short>`/`ReadOnlySpan<short>`. Proved against the real ABI on
  loopback the way every binding's own tests prove it, including the
  threading rules — events on the poll thread, `BUSY` surfaced rather than
  blocked on, no use-after-free disposing a stack with events still
  queued. A headless sample agent (`samples/Sipral.Sample.Agent`) answers,
  echoes and hangs up on `"#"`, runs in the interop lab as
  `labuser-agent-csharp`, and doubles as a runnable example; a skeleton WPF
  sample (`samples/Sipral.Sample.Wpf`) covers registration, a call,
  hold/resume and DTMF.
- **Android: a `ConnectionService` helper, a Compose sample, and a real
  AAR.** `org.sipral.telecom.TelecomBridge` carries `docs/15-mobile.md`'s C2
  onto the telecom framework — a push reported first, then announced, and
  the INVITE that follows matched to the screen already up — and maps
  answer, reject, hold, DTMF and disconnect both ways, leaving audio routing
  to the platform; it is tested on a JVM through fakes, one sequence per
  race, and over two real stacks on loopback. `bindings/kotlin/android` puts
  it behind a self-managed `ConnectionService` and adds a Compose skeleton
  (registration, a call, hold, DTMF, audio routes). `scripts/package/android.sh`
  builds `sipral.aar` (both natives for arm64-v8a, armeabi-v7a and x86_64,
  the JNI library now linking the idiomatic layer's own shim too, which it
  had left out, and R8 keep rules), the helper's AAR and the sample's APK inside a
  pinned Android SDK and NDK image, and checks each. The idiomatic layer gains `announce`, `refreshBinding`,
  `forgetAnnouncement` and RFC 8599 push parameters on an account, and
  `SipralCall.waitConfirmed` and `waitEnded` now subscribe before they read
  the call's state, so an event landing between the two is no longer missed
  and waited out to the timeout.
- **`sipral-media`'s DSP stages get their own fuzz targets and property
  tests, and `indexing_slicing` becomes a hard denial.** Resampling, drift
  correction, packet-loss concealment, comfort noise, voice-activity
  detection, G.722 and the mixer each gained a seeded-PRNG property test —
  empty and odd-length frames, `i16::MIN`/`MAX` runs, silence into a burst,
  a sample rate or a mode changed mid-stream — run against the current code
  rather than assumed correct, and eight new `cargo-fuzz` targets
  (`media_resample`, `media_plc`, `media_drift`, `media_comfort_noise`,
  `media_vad`, `media_g722`, `media_mix`, `media_opus`) feed the same
  modules bytes no encoder produced. `indexing_slicing` moves from a warning
  to a workspace-wide denial, in every crate that already set it locally, so
  a slice index that could panic fails the build rather than the call.
- **Linux desktop audio, over PipeWire.** `sipral-io-pipewire` is the third
  device crate, beside CoreAudio and WASAPI and with the same surface:
  `CaptureStream` and `PlaybackStream` over `pw_stream`, mono sixteen-bit at
  the rate asked for with PipeWire's adapter doing the converting, devices
  listed by their stable `node.name` with the session's defaults, hotplug and
  default changes from `DeviceMonitor`, a node that goes reported once as
  `StreamEvent::DeviceLost` rather than silently rerouted, volume, mute and
  the meter, and the render delay an echo canceller needs, read from
  `pw_time`. It links `libpipewire` (MIT) through hand-written bindings;
  ALSA's and PulseAudio's client libraries, both LGPL, stay out. PipeWire's
  own echo canceller is a session module, and `docs/05-media.md` says how it
  is loaded and routed to. `scripts/lab.sh pipewire` checks it against a real
  graph — samples played into a virtual cable come back out identical, and a
  cable pulled from under two streams is reported by both — and then carries
  a call to the lab's Asterisk on PipeWire's devices and hears its tone come
  back.
- **`sipral-headless` linked to real media, behind the facade's own `headless`
  feature.** `sipral::HeadlessSession` pairs one call's `MediaSession` with
  one of that crate's own sans-I/O sessions: PCM frames resampled against
  whatever the negotiation actually settled on rather than a rate picked
  ahead of it, a voice-activity detector run over the caller's own decoded
  audio and reported as a new `VoiceActivity` control message for barge-in,
  DTMF carried both ways, and call state mapped from real signalling events.
  `sipral-headless` itself still names no other crate in this workspace —
  only the facade's manifest grows the edge — and its queues now drop the
  *oldest* frame first when an agent falls behind, each direction counted,
  documented in full in `docs/07-headless.md`'s new "Real media" section.
  `crates/sipral/examples/headless-socket-agent.rs` and
  `crates/sipral-headless/examples/agent.rs` carry a call over that socket
  end to end, and the interop lab gained a second agent account to exercise
  it the same way the Python one already is.
- **Twenty-four CPU-hours of fuzzing on every target.** The eighteen
  original `cargo-fuzz` targets, then the eight media ones, then
  `headless_media`, `media_g729`, `turn_client` and `ice_lite`, each 48
  runs of 30 minutes on one machine, about 61 billion executions in all: no
  crash, no timeout, no run out of memory. `media_g729` decodes and
  re-encodes every input, so its day came to about 0.67 million executions,
  the thinnest of any target. That is the last of phase 1's exit criteria
  but the carrier account.
- **A local conference of two calls.** `MediaEngine::join`/`leave` pair two
  active calls on one facade and `MediaEngine::mix` drives a frame of the
  three-party mix — each far end hears the other far end and this end's own
  microphone, halved and summed the way a call recording already avoids
  clipping, never resampled, so the two calls have to share a sample rate
  and a frame length. A call that ends while joined un-pairs cleanly and
  tells its former partner (`MediaEvent::Unjoined`). Across the C ABI:
  `sipral_call_join`, `sipral_call_leave` and `sipral_media_mix`, the last
  locking its two media handles in a fixed order so two threads mixing the
  same pair cannot deadlock against each other. A new interop flow places
  two calls to Asterisk, joins them and proves one call's tone crosses to
  the other's wire, on both drivers.
- **An audio quality gate on the netem profiles, and a fix to what they had
  actually been testing.** `interop/harness` gained a `quality` module that
  fits the lab's own fixed 350+440 Hz tone (never an echo of what this end
  sent — its own module doc says why one was tried and abandoned) against
  every frame the primary call plays back, once per run of frames this end's
  own ear calls audible, and checks two things a passing packet count never
  could: segmental SNR on the frames that arrived, and no discontinuity at
  either edge of a concealment gap. `scripts/lab.sh netem` now turns it on
  (`SIPRAL_AUDIO_GATE`) and fails a profile whose audio does not hold up.
  Building it surfaced a second, older bug: `tc netem` only ever shaped this
  container's own egress, and with no echo at the far end that never touched
  the audio anything here measured — `lossy`, `mobile` and `satellite` had
  been passing on a link that was bad in name only. `scripts/lab.sh` now
  redirects this container's own ingress through an `ifb` device so the same
  impairment lands both ways, and `blackout.sh`'s own outage check reads the
  ingress side's drop counter rather than the egress one.
- **MESSAGE and message waiting indication, through the C ABI too.**
  `interop/harness-c` gained the two flows `interop/harness` already
  carried: an out-of-dialog MESSAGE sent to the lab's own echo extension
  and read back from `sipral_account_message`'s own events, and a
  `message-summary` subscription (`sipral_account_subscribe`) whose mailbox
  count is read higher after a call announces a message in it. Asterisk
  only, on both drivers now, with the same pass conditions either way.
- **OpenSIPS as a second proxy in the lab.** Kamailio and OpenSIPS share an
  ancestor but have diverged for fifteen years, so a routing rule both of them
  read the same way is a second opinion rather than one implementation's
  private reading of it. Register, call, hold, resume and both transfers now
  run through OpenSIPS too, on both drivers, in `scripts/lab.sh`'s default run
  and selectable alone as `scripts/lab.sh opensips`; it is started only for
  that step and removed right after, so the lab's steady footprint is
  unchanged.
- **A phone-to-phone peer in the lab: baresip, through the proxy.** Every
  flow the lab ran before this ended at a server; none reached another client
  stack. baresip (built from source, pinned by release tag and checksum
  alongside the matching libre release) now registers at the lab's own
  Kamailio as a second user, three accounts for three media policies, and the
  drivers place a call at its AOR the same way they place one at FreeSWITCH's
  or Asterisk's — Kamailio relays the dialog and never joins it, so this is
  the one place in the lab where the media is end to end against a stack this
  repository did not write. Register and call, hold and resume, SRTP and
  DTLS-SRTP all run against it on both drivers, `scripts/lab.sh` starts the
  container for that step alone and removes it straight after, and a peer
  hanging up on its own is left as a next step rather than claimed here.
- **DTLS-SRTP with a peer that certifies with RSA.** FreeSWITCH, left as it
  ships, holds an RSA-4096 certificate, and no call with it could be keyed:
  as a client it withheld its certificate from a request naming ECDSA alone,
  and as a server it could pick no suite offered. A server now asks for either
  kind of client certificate and a client also offers
  `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, holding the server's certificate to
  the kind its suite names; the peer's RSA signatures are verified as
  RSASSA-PKCS1-v1_5 over SHA-256 under a 2048- to 8192-bit key, and this end
  still signs with its own P-256 key alone. The lab's DTLS flow now runs
  against FreeSWITCH as well as Asterisk, on both drivers.
- **Four runnable examples, and a "try it in sixty seconds" README section.**
  `call.rs` dials a public IVR with no account and no configuration, presses a
  digit, and plays or records what comes back; `register-and-call.rs` adds an
  account, a registrar, hold and blind transfer, all from the command line;
  `tls.rs` is the same call over TLS, with `rustls` as that one example's own
  optional dependency behind a Cargo feature reached by nothing else in the
  crate; `headless-agent.rs` is a fifty-line agent with no device anywhere
  near it, that answers and repeats back whatever it hears. `docs/04-ua.md`
  now quotes the examples directly rather than describing them in prose that
  nothing built. The examples find a server by its domain's SRV record (RFC
  3263 §4.2), since `sip2sip.info`'s own address refuses SIP, draw their seeds
  from the operating system rather than from a constant, and record every
  frame of a call, pauses included; both calls, UDP and TLS, have been placed
  to the IVR and heard it answer the digits.
- **A Python binding, over the C ABI.** `tools/abi-gen`'s fifth back end
  prints `bindings/python/sipral/_sipral_cffi.py`: a `cffi` ABI-mode `cdef`
  naming the same types, constants and entry points the header does, and the
  `dlopen` that turns it into `lib` — no C compiler needed to install it.
  `sipral.Stack`, `sipral.Account` and `sipral.Call`, written by hand against
  that raw layer, are the idiomatic surface: a background thread drives
  `sipral_stack_poll` and the transport queues, events land on an
  `asyncio.Queue` per stack and per call, DTMF digits get a queue of their
  own, and a call's audio crosses as `bytes`/`memoryview`, paced by
  `sipral_media_info_t::frame_ms` on a thread of its own once
  `SIPRAL_EVENT_KIND_MEDIA_STARTED` mints the media handle. `bindings/python/tests/test_call.py`
  runs two stacks against each other on loopback, with no registrar between
  them, and answers `SIPRAL_EVENT_KIND_RESOLVE_NEEDED` by treating the host
  as a literal address, which is what a direct call like that one needs and
  nothing more; `bindings/python/tests/test_abi.py` checks the generated
  `cdef` against the header's own numbers and against `bindings/c/abi-sizes.txt`.
  `bindings/python/examples/agent.py` is a complete headless voice agent in
  one file, talking through one `respond(pcm) -> pcm` function
  a real model replaces. It installs from the checkout with
  `pip install -e .`; a wheel with the library bundled in is built by
  `scripts/package/wheels.sh` (see Platform packages, above).
  The interop lab runs that agent as its docstring says to, registered at
  Asterisk and called by it. For that the agent now binds to, and answers
  media on, the address its route to the registrar leaves from: it bound
  signalling to `0.0.0.0` and answered media on `127.0.0.1`, and neither is
  an address a server can send to.
- **SIP MESSAGE (RFC 3428) and message waiting indication (RFC 3842).**
  `UserAgent::message` sends an instant message out of any dialog and
  `UserAgent::message_in_call` sends one inside a call's dialog (§4's MAY);
  both report their outcome as `UaEvent::MessageSent` — 200, a 202 from a
  relay, a refusal, or the 408/503 RFC 3261 §8.1.3.1 gives one that got no
  answer at all. An incoming MESSAGE is answered 200 immediately and delivered
  whole as `UaEvent::MessageReceived`, `text/plain` always taken and any other
  `Content-Type` checked against `Account::accepts_message_type`, answered 415
  with an `Accept` otherwise; a body over this stack's own policy ceiling is
  answered 413 unread. Outbound, a body over RFC 3428 §8's 1300-byte ceiling is
  refused rather than fragmented over UDP unless `Account::transport_protocol`
  says the transport is congestion-controlled, and a second out-of-dialog
  MESSAGE to a target still waiting on its first is refused rather than sent
  (§8's own congestion-safety rule).

  Message waiting indication needs no new subscribe call: `Subscribe::new` already
  takes any event package by name, and `message-summary` is one.
  `application/simple-message-summary` is parsed into RFC 3458 §6.2's per-class
  counts (`UserAgent::message_summary`), and `UaEvent::MessagesWaiting` reports
  the `voice-message` class's new/old counts and urgent counts alongside the
  status line's boolean. An unsolicited `message-summary` NOTIFY — several
  PBXs send one without a subscription — is refused 481, the same answer RFC
  6665 §4.1.3 already gives any other notification nobody asked for.

  `sipral_account_message` is the C entry point, and
  `SIPRAL_EVENT_KIND_MESSAGE_RECEIVED`, `..._MESSAGE_SENT` and
  `..._MESSAGES_WAITING` (34, 35, 36) the new events. The interop lab gained
  two flows against Asterisk: a MESSAGE echoed by the lab's own dialplan, and
  a mailbox whose count is read higher after a call announces a message in
  it.
- **RTCP XR VoIP Metrics and RFC 6035 voice quality reports.** `sipral-rtp`
  builds and parses the RFC 3611 Extended Report packet and its VoIP
  Metrics Report Block: burst and gap loss (Appendix A.2's Gmin
  classification), delay, jitter buffer sizing, and the R factor and MOS
  from a simplified ITU-T G.107 E-model, using the active codec's G.113
  Appendix I `Ie`/`Bpl` pair where one is tabulated and RFC 3611's own
  "unavailable" sentinel where none is. Reporting is negotiated with
  `a=rtcp-xr:voip-metrics` (RFC 3611 §5), on both offer and answer, and
  carried through to `StreamStatistics::voip_metrics` and
  `sipral_stream_stats_t`'s tail either way. An account with
  `quality_report_uri` set gets one RFC 6035 `VQSessionReport: CallTerm`
  published to it (over a PUBLISH, RFC 3903) when each of its calls ends.
- **A live call re-offered on another codec list.** `MediaEngine::change_codecs`
  and `sipral_call_change_codecs` offer a call again on the codecs named, in
  that order (RFC 3264 §8.3.2), and move nothing else: the description this end
  last wrote is carried with only its formats replaced, so the SDES key, the
  DTLS fingerprint, the ICE credentials and the address all stay as they are,
  and nothing is re-keyed or restarted; `a=setup` goes as `actpass`, as RFC
  8842 §5.5 asks of every re-offer. A held call stays held,
  and `resume` takes it off on the new list. Every dynamic payload type keeps
  the codec it has named on the call, from either end — an offer numbered from
  the catalogue alone breaks that the moment a codec leaves the front of the
  list — and a codec new to the call gets a number nothing has had. The list
  becomes the call's own when the far end accepts it; a refusal leaves the
  call where it was. `UserAgent::change_formats` is the signalling half: it
  sends a description whole but writes every stream's direction itself, from
  the hold state.

  Until now there was no way to do this through the facade, and the lab
  proved it: the Rust driver wrote that one re-offer by hand, with no key, no
  fingerprint and payload numbers of its own choosing. It goes through the
  engine now, and so does the C driver's.

- **The C driver runs every flow the Rust one does.** SRTP, DTMF by INFO and
  the hold with a codec change join the six it had, against Asterisk as the
  Rust driver runs them, with the same accounts and extensions. `SIPRAL_FLOWS`
  now matches whole names, as the Rust driver's does: a substring match had
  `hold` select `holdcodec` too, and the RFC 4733 flow's key was not the one
  the Rust driver uses.

- **A DTLS-SRTP call in the lab, from both drivers.** Placed under
  `DtlsRequired` against Asterisk's own DTLS endpoint, heard, held, resumed and
  heard again: the hold and the resume are both re-offers that hand the roles
  back with `actpass`, and audio after them is what says the far end kept the
  association. The Rust driver had never run a handshake — it built the facade
  without DTLS and never sent a handshake record — and a loopback test now keys
  a call between two of its own endpoints over real sockets before the lab is
  asked to.

- **The gate reads the tree's C the way glibc does.** The lab's C driver, the
  smoke test, the Swift package's translation unit and the JNI shim are
  compiled again against glibc's own headers for x86_64 and aarch64 Linux,
  with `zig cc` and warnings fatal. glibc declares nothing beyond ISO C under a
  strict `-std` unless a file asks for POSIX, and the Apple SDK declares it
  regardless, so until now a file could pass here and fail on the machine it
  runs on. `zig` joins the tools the gate needs.

- **Two checks in the gate, both for mistakes it could not see.** A C file
  that includes a header ISO C does not define, or calls one of the POSIX
  extensions an ISO header declares only on request, must ask for POSIX before
  its first `#include`: glibc hides those declarations under a strict `-std`
  and macOS does not, so no compiler on a Mac can find the file that fails on
  Linux. And the printed header cannot change without the ABI version moving
  past the last commit's, which `sipral_abi_check` needs in order to tell two
  surfaces apart at all.

- **The lab, driven a second time through the C ABI.** `interop/harness-c` runs
  the same flows against the same servers with every byte going through
  `sipral.h`: register, a call with audio, hold and resume, both transfers, and
  a digit. It learns what happened from `sipral_event_t` and from nothing else,
  and it matches the Rust driver's command line, output lines and exit code
  exactly, so `scripts/lab.sh` reads both with one parser.

  The Rust driver reaches `MediaEngine` and `UserAgent` as Rust types, which is
  not how anybody outside this repository will ever reach them, so it cannot
  notice a defect that lives in the boundary — a struct whose length the two
  sides disagree about, a handle that goes stale, an entry point that wants a
  clock nobody passes it. Those are what an integrator meets first, and now so
  does the lab. `scripts/check.sh` compiles it on every run and does not run it,
  which is the seventy-seventh check: an ABI change that would stop an
  integrator's program building fails at the moment it is made.

  It is the phase-1 exit criterion and the precondition for freezing the ABI,
  and it passes: `the lab agrees`, both drivers, both servers.

- **ICE in the full role, joined to a call.** The agent in `sipral-nat` — RFC
  8445's gathering, checklists, pacing, nomination, role conflicts, restarts,
  keepalives and RFC 7675's consent — has been written and tested since the
  week before and reached by nothing. It is reached now: `IcePolicy` on
  `CodecCatalog` and `SIPRAL_ICE_OFF` / `_OFFERED` / `_REQUIRED` on
  `sipral_stack_config_t` and `sipral_call_config_t`, off by default in every
  one of them for the reason `docs/06-nat.md` tabulates. An offer under it
  carries `a=ice-ufrag`, `a=ice-pwd`, `a=ice-options`, one host candidate and
  a session-level `a=ice-pacing`; a connectivity check arriving on the media
  socket reaches the agent rather than being read as a broken RTP packet and
  thrown away; and nothing this end builds goes out before the agent has a
  path for it. `MediaEvent::PathChosen` and
  `SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN` (33) say when there is one, and
  `MediaSession::ice_path` answers it at any other moment.

  What the switch turns on is host candidates and nothing else. With no server
  to gather from, gathering finishes before the call that started it returns,
  which is what keeps an offer one pass of work and is why neither the Rust
  API nor the C ABI grew a two-phase description. Server-reflexive candidates
  are the next step and change none of the above. (Since superseded: a stack
  with STUN adds a server-reflexive candidate, and one with a TURN relay a
  relayed candidate; see the STUN and TURN entries above.)

  **A peer that does not do ICE keeps its call.** No ICE attributes, no usable
  candidate, or a description whose own default destinations are missing from
  its candidate lines each drop the agent and leave the stream on `c=`/`m=`
  and symmetric RTP — RFC 8445 §2.6, and without it turning ICE on against an
  Asterisk with `ice_support=no`, which is its default, would turn a call that
  works into a call with no audio. `IcePolicy::Required` is for a deployment
  that would rather have neither and ends the media with
  `MediaError::IceRequired` instead.

- **`sipral_nat::ice::IceAgent::route`**, which answers where application data
  for a component would go without sending any and without counting as traffic
  for the keepalive timer. It exists for a caller whose producer borrows its
  own buffer: one that cannot learn there is nowhere to send by trying, since
  by then it has built a frame it must throw away or taken a handshake record
  out of a flight it cannot put back.

- **`sipral-io-common`**, holding the three parts of an audio device backend
  that are not about any device: the lock-free ring where the thread the
  system will not wait for meets an ordinary one, the gate that says when that
  thread is out of our memory before the memory is freed, and volume, mute and
  the meter. All three were written twice, once in `sipral-io-coreaudio` and
  once in `sipral-io-wasapi`, and identically enough that the second copy's own
  documentation said whose it was — 1,288 lines and 34 tests that existed
  twice and now exist once, on the way to PipeWire and AAudio not being the
  third and fourth copy. The counters stayed behind in each backend, because
  past the four numbers both keep they count different things.

- **A fuzz target for the ICE agent**, `fuzz/fuzz_targets/ice.rs`, the
  seventeenth. It is the one seam open to anybody before a key exists: an ICE
  agent binds the media port and answers connectivity checks on it, so
  `handle_datagram` runs on bytes from an unauthenticated stranger earlier
  than SRTP and earlier than the DTLS handshake. Its seeds carry checks signed
  the way the agent will check them, since an unsigned one dies in the
  authenticator and reaches nothing behind it — the seeds alone reach more of
  the agent than several hundred thousand random runs did.

- **Echo cancellation, gain control and noise suppression are attachable
  from C.** `sipral_call_attach_processor` installs a callback that runs
  `sipral-media`'s existing `Processor` seam over every frame a call plays
  and captures, against the far-end audio lined up by the render delay the
  application already sets; `sipral_call_detach_processor` and
  `sipral_call_reset_processor` complete the surface. All three are
  generated into every binding, including a Kotlin/JNI back end taught to
  marshal a struct with a buffer the listener fills as well as one it only
  reads.
- **A reference echo canceller, `crates/sipral-aec-webrtc`.** A `Processor`
  over `webrtc-audio-processing` (BSD-3-Clause), for an application that
  wants AEC3, gain control and noise suppression attached rather than
  written from scratch. Outside this workspace's default build — the
  bundled C++ library it links needs meson and ninja, which nothing else
  here asks a machine for — with its own build, test, lint and licence
  step in `scripts/check.sh`. Measured against a synthetic echo
  (`crates/sipral-aec-webrtc/examples/erle.rs`): 36.1 dB of echo return
  loss enhancement once AEC3 has adapted, in `docs/05-media.md`.
- **Real-time text, RFC 4103, in `sipral_rtp::rtt`.** T.140 text over RTP,
  sans-I/O like the rest of the crate. `TextSender` gathers typed text into
  one T140block per transmission interval (300 ms by default, never under
  100 ms), sends it inside RFC 2198 redundancy with two generations by
  default on the 1000 Hz clock, keeps sending empty-primary packets only
  while copies of the last text are owed, sets the marker bit after a
  silence, opens with the byte order mark, sends new lines as LINE
  SEPARATOR and holds characters back to the peer's `cps`. `TextReceiver`
  places every block by sequence number, takes whichever copy arrives
  first, waits a bounded time for a late packet, marks what no copy could
  recover with a U+FFFD per block lost (RFC 4103 §5.3), reassembles UTF-8
  split across blocks, bounds what it holds, and hands out erase, new-line, alert and character
  events. `TextFormat` writes the `m=text` section with `t140/1000`,
  `red/1000`, the red `fmtp` and `cps`, and reads the two `fmtp` values
  back. A new fuzz target, `rtt`, drives the receiver with arbitrary
  datagrams.
- **Calls are recorded to a recording server (SIPREC).** `MediaEngine::record_to` places an RFC 7866 recording session for a running call, from its account, with two labelled sendonly streams on the call's codec and RFC 7865 metadata naming both parties; once the server answers, every packet the call sends and every packet it accepts is copied to its stream as an RTP translator would (`MediaSession::poll_recording`, `MediaEngine::poll_recording`), a hold or a codec change is offered to the server with fresh metadata (`UserAgent::update_recording_metadata`), a call that replaces the recorded one takes the recording over, and the recording session is hung up with the call (`stop_recording_to` sooner). `UserAgent::accept_recording_sessions` lets an agent act as the server: `siprec` is understood and the offer is read out of the multipart body.
- **Real-time text in calls.** `CallMedia::text` gives a call a second socket for RFC 4103 text: the offer carries RFC 4103 §7's `m=text` (`red/1000` over `t140/1000`, two generations, `b=RS:0`/`b=RR:0`), an offered text stream is answered on it, each end sends with the other's payload numbers and the far end's `cps`, and `MediaSession::send_text`, `poll_text` (or `MediaEngine::poll_text`) and `receive_text` carry it; `MediaEvent::TextReceived` says what was typed, erasures as U+0008, new lines as U+2028 and a U+FFFD for each block no redundant copy recovered. A call that keys its audio or uses ICE neither offers nor takes text.
- **A text sender takes new numbers mid-call.** `sipral_rtp::rtt::TextSender::reconfigure` sends under another payload numbering, redundancy or `cps` without losing what is queued or restarting its numbering, and a call's text stream follows a re-offer that renumbers `t140` or `red` on either side.
- **Conferences, presence, real-time text, RTCP feedback and SIPREC over the C ABI (0.31).** `SIPRAL_EVENT_KIND_CONFERENCE_CHANGED` (50) with `sipral_subscription_conference`, `_conference_user_at` and `_conference_text` read a conference subscription's picture; `sipral_call_conference_uri`, `sipral_call_subscribe_conference`, `sipral_call_set_focus` and `sipral_call_config_t::focus` cover RFC 4579's focus; `sipral_account_publish_presence` and `_unpublish_presence` publish PIDF with an RPID activity, and `SIPRAL_EVENT_KIND_PRESENCE_CHANGED` (52) reports publications and watched presentities; `sipral_call_config_t::text_address`, `sipral_media_send_text`, `_poll_text`, `_receive_text` and `SIPRAL_EVENT_KIND_TEXT_RECEIVED` (51) carry RFC 4103 text; `sipral_call_config_t::feedback` offers RTP/AVPF, reported in `sipral_media_info_t` and `sipral_stream_stats_t`; `sipral_call_record_to`, `sipral_call_stop_recording_to` and `sipral_media_poll_recording` record a call to a recording server; `sipral_call_answer_with` answers with a call's own configuration. Feature bits 20 to 23, statuses `SIPRAL_STATUS_NOT_NEGOTIATED` (20) and `SIPRAL_STATUS_NOT_A_FOCUS` (21); every binding's generated layer carries it.
- **A transport that fails says why, TLS included (ABI 0.31).** `sipral_stack_transport_failure` takes the transport error, a `SipralTlsFailure` (untrusted, name mismatch, expired, handshake refused) and the TLS library's own sentence; it, `sipral_stack_transport_failed` and `sipral_stack_stream_closed` now raise `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` (53) on the next poll, ahead of the registrations and calls the loss failed. A request asked for while the transport is down is `SIPRAL_STATUS_TRANSPORT_DOWN` (22) instead of `SIPRAL_STATUS_NOT_SENT`.
- **The four idiomatic layers signal over UDP, TCP or TLS.** Python (`Stack(signalling=...)`), .NET (`new SipralStack(signalling: ...)`), Kotlin (`SipralClient.open(signalling = ...)`) and Swift (`SipralStack(signalling:)`, TLS on Apple platforms) keep one connection to the registrar or outbound proxy for every account and call, check the server's certificate against a name with the platform's authorities, a private one beside them or only one, report every failed or lost connection as `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` with the platform's TLS reason mapped to untrusted, name mismatch, expired or handshake refused, and connect again with back-off, registering again once back; each also takes the INVITE rate preset. `docs/22-tls.md` has the mapping per platform.
- **A voice-agent preset for the INVITE rate floor.** The default floor, ten INVITEs from one address at once and then one every two seconds, answered `480`, is published as `SIPRAL_INVITE_LIMIT_BURST` and `SIPRAL_INVITE_LIMIT_EVERY_MS`; `Rate::voice_agent()` and `SIPRAL_INVITE_LIMIT_VOICE_AGENT_*` (128 at once, then twenty a second) let a headless service take a trunk's rush.
- **Swift and Kotlin carry conferences, presence, real-time text, RTCP feedback, L16 and SIPREC.** `placeCall`/`answerCall` take `text`, `feedback`, `focus` and per-call `codecs` (`L16/16000`); `Media.sendText`, `Call.text()` / `SipralCall.text`, `rtcpFeedback()`; `Account.subscribe`, `watchPresence`, `publishPresence` and `unpublishPresence` with a `Subscription` whose `conference()` reads the whole picture; `Call.setFocus`, `conferenceUri()` and `subscribeConference()`; and `Call.record(toServer:destination:)` / `SipralCall.recordTo`, which opens its own TCP connection to the recording server and sends both parties' copies from sockets of their own. The lab agents echo real-time text with `SIPRAL_TEXT=echo`.

- **DTMF by SIP INFO, both ways, owned by the user agent**.
  `UserAgent::send_dtmf_info` builds and sends the INFO in `sipral-ua` now —
  the construction moved out of `sipral-ffi`, which used to build it by hand
  with no transaction ownership and no report of the answer — and reports the
  far end's final status as `UaEvent::DtmfSent`, so a 415 from a switch that
  does not read the `Content-Type` reaches the application with the digit and
  the code rather than vanishing — as does an INFO nobody answered, reported
  as the 408 or 503 RFC 3261 §8.1.3.1 treats a timeout or a transport failure
  as, and one whose challenge nothing could answer, as its 401 or 407.
  `sipral_call_send_dtmf`'s two INFO forms
  hand it their whole string once; its own signature is unchanged. An incoming INFO in
  a dialog, `application/dtmf-relay` or `application/dtmf`, is read by a
  small panic-free parser in `sipral-ua`, answered 200 when it names a digit
  and 400 when it does not (RFC 3261 §21.4.1), and reported as the
  same `DigitReceived` an RFC 4733 event already is — `MediaEvent` and
  `sipral_media_event_t` both gained a `source` member saying which of the
  two carried it, rather than a second event for the same fact. All three
  forms — RFC 4733 sending, INFO sending, INFO receiving — share one
  validation (`sipral_ua::dtmf`) for the sixteen keys a keypad has; both ways
  of sending refuse a tone under 40 ms or over ten seconds identically before
  anything is sent, and receiving holds a peer only to the ceiling; `MediaSession::dial` and `send_dtmf` gained the
  ceiling (`MediaError::DigitTooLong`, `LONGEST_DIGIT`) and INFO the floor
  RFC 4733 already had. Reserved event kind 27 becomes `SIPRAL_EVENT_KIND_DTMF_SENT` in
  place, taking a `digit` member appended to `sipral_call_event_t`; nothing
  else in the ABI moved and no minor version was bumped. A new fuzz target,
  `dtmf_info`, exercises the incoming parser. `interop/harness` gained a
  `DtmfInfo` flow against Asterisk's own `labuser-infodtmf` endpoint
  (`dtmf_mode=info`), so the lab dialplan's echo now exercises this stack's
  receiving half as well as its sending one.

- **The SRTP policy is now chosen from C**. An application
  linking `sipral.h` could not ask for SRTP at all, although the facade
  underneath always could: `sipral_stack_config_t::srtp` sets the stack's
  default and `sipral_call_config_t::srtp` overrides it for one call, both a
  `sipral_srtp_t` — `SIPRAL_SRTP_NOT_OFFERED`, `SIPRAL_SRTP_OFFERED` or
  `SIPRAL_SRTP_REQUIRED` — reaching `sipral::SrtpPolicy` through `catalog_of`
  and `with_srtp` with the same three meanings. Zero keeps today's behaviour:
  unspecified on the stack is this build's own default, and unspecified on a
  call is the stack's own setting. Both members are appended at the tail of
  their structs with the pinned oldest length left where it was, so a caller
  built against an older header still works and gets the default. An
  out-of-range value is refused before anything is built.

- **A call event now names who is on it**. `sipral_call_event_t`
  gained `from_uri`, `from_display`, `to_uri` and `call_id`: the `From` URI,
  the resolved `From` display name, the `To` URI and the `Call-ID` of the
  request that opened the call, read once and the same on every event of that
  call afterwards, including the one that reports its end. An application no
  longer has to parse `sipral_event_t::message` itself, or keep a table of its
  own, to know both parties from any event. Appended at the tail of the
  struct, which grows `sipral_event_t` with it — sixty-four bytes this
  build — but `sipral_event_t` carries no pinned length to begin with, so a
  caller built against an older header is unaffected.

- **Early media when this stack runs the audio**. An incoming
  call could be answered with audio (`sipral_call_answer_media`,
  `MediaEngine::answer`) but not rung with it: `sipral_call_ring` only sent a
  183 with whatever description the application wrote itself.
  `sipral_call_ring_media`/`MediaEngine::ring`/`MediaEngine::ring_with` write
  the answer from this stack's codec order and open the session on it right
  away, so the far end hears whatever the application plays before anybody
  answers. `sipral_call_answer_media`/`MediaEngine::answer` afterwards reuses
  that session and description rather than negotiating a second one — the
  same `o=` id and version — and what the 200 OK carries then follows RFC
  3262 §5 and RFC 6337 §3.1.1 exactly, from whether the 183 went out reliably.
  `sipral_call_ring_media` also takes `sipral_call_config_t::srtp`, closing
  the gap the stack-wide setting left: an answered call could not override
  the stack's SRTP
  policy at all. Ringing with media twice is `SIPRAL_STATUS_WRONG_STATE`;
  ringing with media after a `sipral_call_ring` that sent no description is
  not, and after one that sent the application's own it is, since every
  description in the responses to one INVITE has to be that same one (RFC
  3261 §13.2.1, RFC 6337 §3.1.1). An INVITE that
  carried no offer is not rung with media (`SIPRAL_STATUS_WRONG_STATE`,
  nothing sent): RFC 3261 §13.2.1 and RFC 6337 §3.1.2 leave an offer from
  this end no provisional response this stack can follow up.

- **The DTLS-SRTP handshake, both roles, in a crate no call reaches yet.**
  `sipral-dtls` gains `Connection`, the client and server state machines of
  RFC 6347 for DTLS-SRTP, sans-I/O like the rest of the tree: the server's
  stateless HelloVerifyRequest cookie exchange; a certificate from both ends,
  each checked against the fingerprints the signalling carried and against
  nothing else (RFC 5763 §5, RFC 8122 §5.1); ServerKeyExchange and
  CertificateVerify signatures; the extended master secret and `use_srtp`
  required in both hellos, the profile chosen by the server from the client's
  list; Finished verified over the transcript and accepted only protected.
  Flights go out again on RFC 6347 §4.2.4.1's timer — one second, doubled,
  capped at sixty, six attempts — and a peer's retransmitted flight is answered
  with the last flight rather than processed a second time. A failure sends one
  fatal alert saying why; `close_notify` is answered; renegotiation is refused
  with `no_renegotiation`. The SRTP keys, arranged per direction in the shape
  `sipral-rtp` takes them, and any application data come out only after the
  peer's Finished is verified. `setup::dtls_role` maps `a=setup` to the role.
  Two findings from reading that foundation back against RFC 6347 go with it:
  a hello's extensions
  were checked for a duplicate by searching the list once per extension, a
  hundred million comparisons for one 64 KiB block, and are now sorted once;
  and reassembly kept the first of two fragments that disagree, so one forged
  fragment ahead of a genuine message locked that message out for good, where
  now the later one replaces what was held (`Offered::Replaced`), and a message
  short of room takes it from messages held further ahead, so two forged
  fragments numbered past the flight cannot fill the budget instead. Two fuzz
  targets, `dtls_record` and `dtls_handshake`, seeded from a real handshake.
  The join to a call — the SDP lines, RFC 7983 demultiplexing, `MediaSession`
  — is the next part.

- **Header fields in and out through the C ABI, and a field the stack writes
  refused rather than written twice.** `sipral_header_t` is a name and a value;
  `headers`/`headers_len` sit at the tail of `sipral_call_config_t` for the
  INVITE and of `sipral_account_config_t` for every REGISTER;
  `sipral_call_set_headers` (`UserAgent::respond_with_headers` in Rust) sets the
  fields for the 180/183, 200, refusal, BYE and re-INVITE a call sends at the
  application's request, kept until replaced and never on a CANCEL or on what
  the stack sends by itself; and `sipral_message_header_count` and
  `sipral_message_header`, with their `_element` pair, count and reach a field
  in any message by line or by list value, compact names included, as an offset
  into the caller's bytes. A
  field the stack writes itself (`Via`, `Call-ID`, `Contact`, `Route`,
  `Content-Length` and the rest in `docs/04-ua.md`) is refused on every path, C
  and Rust (`UaError::Header`, and `BuildError::OwnedField` from the core, which
  until now wrote a caller's `Contact` beside its own); so are a value holding a
  line break and a name that is not a token, which the core used to drop without
  a word. `Endpoint::bye_with` sends a BYE of the caller's own. The ABI minor
  moves once, with the rest of this block of surface work.

- **An account can have no registrar.** A trunk that knows this end by its
  address could not be configured: `sipral_account_add` refused an empty
  `registrar`, and `Account` had no way to say there was none.
  `Account::unregistered(aor, contact, transport, outbound_proxy)` makes one,
  and so does a `registrar_len` of zero in C, where `registrar_address` becomes
  the outbound proxy its requests go to. Its state is `NotRegistering`
  (`SIPRAL_REGISTRATION_STATE_NOT_REGISTERING`, 10) for as long as it exists;
  registering it is refused with nothing sent (`UaError::NoRegistrar`,
  `SIPRAL_STATUS_INVALID_ARGUMENT`); no refresh, back-off, recovery rung or push
  pre-warm touches it; and a registration snapshot offered to it is refused
  (`SnapshotError::NotRegistering`). `Account::registrar` now answers
  `Option<&Uri>`.

- **The 200 OK to REGISTER is kept, and what a registrar says in it is used.**
  `UaEvent::Registered` gains `response`, the 2xx whole, and `info`, a
  `RegistrarInfo` with the service route, the GRUUs and the associated
  identities; `UserAgent::registrar_info` reads the same while the binding
  stands, and the C event for a registration that went live carries the 2xx in
  `message` as a refusal always has. The Service-Route (RFC 3608) is preloaded
  on the INVITEs and SUBSCRIBEs an account starts towards its registrar and
  never on the REGISTER; an account with an instance identifier asks for GRUUs
  with `Supported: gruu` and uses the one RFC 5627 §4.4 names as the `Contact`
  of what opens a dialog; P-Associated-URI (RFC 7315) is reported. Every value
  is parsed strictly and bounded, and one that is not is left out and written
  into the REGISTER's diagnostic record under three new codes.

- **ICE in the full role, written and not yet reached from a call.**
  `sipral_nat::ice::IceAgent` gathers host, server-reflexive and relayed
  candidates, forms and paces checklists, resolves role conflicts, nominates,
  restarts, and keeps consent on the pair it selects (RFC 8445, RFC 7675), in
  the sans-I/O shape of the STUN and TURN clients. No trickle, deliberately, and
  RTP and RTCP multiplexed. The SDP side gains `a=ice-pacing`, `a=ice-mismatch`
  and a mismatch check that reads `a=rtcp`; the lite agent now authenticates a
  check through the same code as the full one. Tested over a simulated network
  with the NAT behaviours that decide which pair works, role conflicts from
  both starting roles, a restart, consent lost and revoked, and a lossy path;
  `docs/06-nat.md` says what it does and what it does not do yet.

- **Kotlin can build a stack and hear its events.** The generated binding took
  every struct a caller fills in — `sipral_stack_config_t`,
  `sipral_account_config_t`, `sipral_call_config_t` — as a `Long` holding its
  address, which nothing on the JVM can produce, and had no way to be called
  back. Each of those structs is now a Kotlin class the JNI shim copies into a
  zeroed C struct with its size set, and the event callback is a
  `SipralEventListener`: the listener stays on the Kotlin side under a key, and
  the C function the shim prints for the callback to land in attaches the
  polling thread only when it is not attached, detaches only what it attached,
  and deletes the array it made for each event before the next one arrives.
  `SipralNative` calls `sipral_abi_check` as it loads and throws naming both
  versions. `scripts/check.sh` now links the shim against the shared library
  and runs `BindingCheck.kt` on a JVM under `-Xcheck:jni`, including a poll
  from a thread no JVM made. The event payload union is not carried yet:
  nothing in the declarations says which kind writes which arm. A
  `stackCreate` that throws instead of answering lets its listener go too.

- **The foundation of DTLS-SRTP, in a new crate nothing calls yet.**
  `sipral-dtls` is DTLS 1.2 written from RFC 6347 and RFC 5246 over
  RustCrypto's P-256, AES-GCM, SHA-256 and HMAC: the PRF, the master secret
  and RFC 7627's extended master secret, the RFC 5705 exporter and RFC 5764's
  SRTP key layout, the record layer with AES-128-GCM and the anti-replay
  window, fragmentation and bounded reassembly, every message and extension of
  an `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` handshake with its cookie, and a
  self-signed certificate with its fingerprint. The state machines come next;
  the exporter already refuses a session without the extended master secret,
  as RFC 7627 §5.4 requires.

- **Nine more fuzz targets, and the gate builds all thirteen.**
  `crypto`, `dialoginfo`, `headless`, `replay`, `rtcp`, `rtp_dtmf`,
  `srtp_unprotect`, `stun` and `turn` join the four that existed, one per door
  an attacker's bytes come through that the first four never reached: the
  `a=crypto` policy reader that decodes key material, the recording format a
  person hand-edits, the dialog-info body a SUBSCRIBE gets back, the control
  channel a voice agent connects on, RTCP and its typed accessors, the RFC
  4733 event receiver, SRTP and SRTCP unprotect ahead of the authentication
  check, the STUN parser that shares a port with media, and TURN's framer and
  ChannelData both ways they arrive. `srtp_unprotect` drives a run of
  length-prefixed datagrams through one unprotector per suite rather than one
  packet through a fresh one, because the replay window and the rollover
  estimate are the only state an unprotector keeps between packets and a
  fresh one reaches neither. `scripts/check.sh` now runs `cargo fmt
  --check`, `cargo clippy -D warnings` and `cargo fuzz build` over all
  thirteen under the nightly `fuzz/` pins, so a target cannot rot uncompiled
  or unformatted between releases — `cargo test --workspace`, `cargo fmt
  --all` and the workspace clippy run all stop at the edge of `fuzz/`, which
  is a workspace of its own, and four of the targets had already drifted out
  from under all three. Where the binaries landed is cargo's answer now
  rather than a hard-coded `fuzz/target`, which was the wrong directory on
  any machine that sets `CARGO_TARGET_DIR`. The step says `skip` and names
  what is missing when `cargo-fuzz` or that nightly is not installed, which
  is the one place in this gate a skip is allowed.

- **The fuzz seed corpus is committed, and says where it came from.**
  `fuzz/corpus/<target>/` holds 37 seeds, 10 KB in all, so a clone gets
  thirteen targets with something to start from rather than thirteen runs
  beginning at the empty input. `tools/fuzz-seeds` writes them out of the
  library's own builders and encoders — `RequestBuilder`, `CompoundBuilder`,
  `PacketBuilder`, `MessageBuilder`, `ChannelData::encode`, `Protector` — and
  puts each one through the reader its target puts it through before writing
  it, so a seed that is not what it claims to be fails the generator rather
  than sitting in the corpus doing nothing: the framer seeds through the
  framer, the control-channel seeds through the frame decoder, the protected
  runs through an unprotector holding the target's own key, which is also
  what says the three that authenticate and the one that is refused as a
  replay really do. Twelve of the thirteen families go through that; the
  thirteenth is `builder`, whose input is not a message but the five field
  values its target cuts it into, so what is checked there is the cut. The
  one seed that is not written at all is a copy of
  `fixtures/replay/registration-challenged.sipralrec`, which is this
  project's own. The generator owns the directory besides writing it: what it
  does not write, it removes, so a seed dropped from the generator cannot sit
  in the tree for good behind a check that only counts directories. Nothing
  here is a capture of anybody's traffic, addresses are RFC 5737's and names
  are RFC 2606's, and `fuzz/corpus/README.md` says so. `scripts/check.sh`
  holds the directory to it twice over — its shape, every subdirectory a
  target `fuzz/Cargo.toml` declares, every target one, the README tracked and
  the whole of it under 200 KB; and its content, every byte of every seed
  read for an address somebody could harvest, a forbidden project's name, an
  assistant trace and Romanian, which are the four things the rest of the
  tree is read for and which no scan had ever read here. `scripts/fuzz.sh`
  now writes what a run finds into a scratch corpus under `fuzz/target/`, so
  a run does not push a thousand mutations in beside the seeds.

- **`tools/abi-gen` has tests, and a pass that reads the names back after it
  derives them.** The tool that prints the header and three bindings had none.
  It now has golden files for a small synthetic surface, one per file the
  generator writes — five of them, since the Kotlin back end prints the
  binding and the JNI shim beside it — so a change to an emitter shows up as
  a diff in `tools/abi-gen/golden/` rather than buried in three thousand
  lines of `bindings/`; and it has a pass that
  claims every identifier each back end will print, in the scope it will sit
  in, refusing two declarations that derive one name and naming both. The same
  pass carries a reserved-word list per language. C#, Kotlin and Swift can be
  made to take one of their own keywords — `@event`, backticks — and the back
  ends do; C cannot, and the header is a C++ header too, so a member called
  `class` or `switch` stops the generator instead of reaching a consumer. A
  test asserts the real surface passes all four, so the day a declaration is
  added with a colliding or a reserved name, `cargo test` says so. The
  callback goes through the same walk: it is the one signature that is not an
  entry point, it is printed into the header as a function pointer and into
  the .NET binding as a delegate, and its parameters were the last names in
  the surface that nothing read back. Every refusal now names the declaration
  as well as the identifier, in all four languages rather than in the one
  that happened to report a qualified name. And how wide the golden surface
  is stopped being a claim: a test counts the shapes of the real surface
  against the synthetic one and fails naming each one the golden files do not
  reach, which was twenty of them — the union, the records with no size
  member, a pointer to a record, the callback in a field, samples going both
  ways, a struct crossing in both directions at once, and three of the four
  shapes a documentation link has.

- **`Screen::on_replaces`: the application has the last word on a takeover.**
  A matched `Replaces` is honoured only when the INVITE carrying it arrived
  from the same place the named call's own signalling does, which is right as
  a default and wrong as an absolute — a legitimate attended transfer whose
  transferee reaches this end directly rather than through the line's proxy is
  refused by it, and that is a deployment rather than a corner case. The rule
  is now a defaulted hook on the screening policy: `on_replaces` is handed the
  INVITE and a `Replacing`, which says which of this end's calls would be hung
  up and whether it arrived on that call's own flow, and its default body is
  `Replacing::strict` — the rule as it stands and nothing else. So an agent
  with no policy, and a policy that implements only `on_invite`, including
  every closure, behaves exactly as before. An override can widen the rule for
  the case it recognises and hand the rest back to `Replacing::strict`, and it
  can tighten it: refusing one that *did* arrive on the call's own flow is a
  decision it returns. What it cannot do is see a `Replaces` that matches
  nothing, which is 481 before the hook is reached, or overrule §3 on the
  state of the matched call afterwards. `Incoming` gains `referred_by`, the
  field RFC 3892 §2.2 has a transferee copy from the REFER that asked for the
  transfer, with its rustdoc saying what it is for: it and `From` are plain
  fields on the INVITE being judged, so they are context for recognising a
  transfer that was expected and never authority. The C ABI gains nothing
  here: the screening policy does not cross it yet.

- **Opus is a compile-time feature, and it is on.** `sipral-media` takes
  libopus as an optional dependency behind `opus`, `sipral` and `sipral-ffi`
  carry the feature up, and the default is on so that nothing changes for
  anybody who does not choose. A build with it off offers G.722 and the two
  G.711 laws and does nothing else differently: `Codec::ALL` is three long, a
  codec order naming `opus` is refused where it is set exactly as one naming
  G.729 is, and a negotiation with nothing in common fails on the ordinary
  path. The C ABI gains `SIPRAL_FEATURE_OPUS`, bit 6 of
  `sipral_capabilities_t`'s `features`, clear in such a build, while
  `SIPRAL_CODEC_OPUS` stays 4 in every build: a number that has left the
  header is spent for good. Every C-side answer about the codec — that bit,
  the name `sipral_codec_name` gives 4, the number `named_codec` puts on a
  stream — is read from the catalogue the facade hands down and never from a
  `cfg` in `sipral-ffi`, because a Cargo feature belongs to the crate that
  declares it and features are additive: `sipral-ffi` with its own `opus` off
  over a `sipral` built with it is a configuration anybody can compile, and
  the ABI has to be right in it. `sipral::Capabilities` gains `opus` and
  `sipral::Codec` gains `is_opus` and `sipral::MediaError` gains `is_codec`,
  so the Rust layer answers both questions directly too — and `is_codec` is
  the hinge the C side turns on before either of its tables. The ABI minor goes to 0.7, because the printed surface gained
  a constant and `sipral_abi_check` compares the minor and nothing else while
  the major is 0 — a header that grew without the bump is one no load-time
  check can tell from the one before it. What raises which of the three
  numbers is now written where the ABI is documented, in `docs/08-ffi.md`'s
  Versioning section, with the constant's own rustdoc pointing at it:
  everything the generator prints raises the minor, and not only a function
  or a struct member, which is a project rule rather than something about
  codecs. The reason for all of it is licensing and not size —
  `docs/05-media.md` sets out the licensing position in full, and notes that
  a build without the feature needs no cmake and no C++ toolchain because
  nothing compiles libopus from source, and `docs/10-roadmap.md` now carries
  the half of that decision the packaging owns, so that the pointer lands on
  something: a precompiled artefact is built without the feature, or
  published as two variants labelled clearly enough that nobody ships the
  wrong one without noticing. The `sipral` crate, which is the one that
  publishes, documents the feature in its own rustdoc — what disappears with
  it off, and why — and asks docs.rs for all features, because a published
  crate whose feature removes items from its public API has to say so where
  the API is read. And `scripts/check.sh` now builds, tests and lints both
  configurations, tests the mixed one, and asserts that libopus is out of the
  dependency graph of `sipral` **and** of `sipral-ffi` — the C library
  reaches the codec down an edge of its own, and two
  graphs that agree today can be made to disagree by one edit. That assertion
  captures the tree into a variable first and counts a cargo that did not run
  as a failure: written as a negated pipeline, as it first was, a renamed
  package or an unparseable manifest would have made it print ok having read
  nothing.

- **There is a C library now, and a C program in the gate that links it.**
  `crates/sipral-ffi` declares `crate-type = ["rlib", "cdylib", "staticlib"]`,
  so a release build produces `libsipral_ffi.dylib` and `libsipral_ffi.a`
  beside the rlib the tests and the generator use. Until now the 98 KB header
  described a library nobody could open. `scripts/check.sh` gains the step
  that reads the symbols back out: every entry point `abi.rs` lists is in the
  shared library and in the archive, there are exactly as many exported
  `sipral_` symbols as `SURFACE` has entry points, and nothing else leaves
  unmangled. It reads them with `nm-classic` rather than `nm`, because Apple's
  `nm` is an LLVM 14 tool and refuses the newer bitcode a `lto = "thin"`
  archive carries; it reads the list once and fails when it is empty, because
  an `nm` that resolves and errors prints nothing and every question asked of
  no symbols answers ok. What the archive exports beside the ABI is the other
  690 unmangled C names its dependencies' objects carry — libopus,
  compiler-rt, the LTO symbols — which is not a defect and is now a paragraph
  under "What it does not catch" in `docs/08-ffi.md`, because a consumer that
  static-links has to know before it links.

  And a consumer: `bindings/c/smoke.c`, compiled with `-std=c11 -Wall -Wextra
  -Werror`, linked against the shared library and **run** by the gate. It
  checks the ABI version, builds a stack with a callback and a user pointer of
  its own and proves the pointer arrives, adds an account, places one call and
  has another refused with a status and the sentence that names what was
  wrong with it and no handle, retires the transport with
  `sipral_stack_transport_failed` and has a third call — well formed, over a
  stack with nowhere to write — come back `SIPRAL_STATUS_NOT_SENT`, polls
  once, and destroys the stack from inside its own event callback, once, on
  the first event. That last is the one re-entrant call, which
  `docs/08-ffi.md` now states in its rules list rather than leaving to the
  header, and the one nothing proved from C. It also asks the library the
  length of all fourteen structs that carry their own size and compares each
  with C's `sizeof`, through a new entry point, `sipral_abi_struct_size`, which
  answers for any struct of the ABI by the name the header gives it — and
  asks a second one, `sipral_abi_versioned_count`, how many such structs
  there are, so that the list of fourteen names in `smoke.c` is compared
  against the library's own count and a fifteenth cannot arrive unasked
  about. The ABI minor goes to 0.8 and the four printed files were printed
  again. The rule that turns `SipralStackConfig` into
  `sipral_stack_config` moved out of `tools/abi-gen` and into
  `crates/sipral-ffi/src/abi.rs`, where the declarations are, because the
  library now answers questions about the C names too and a derivation written
  twice can disagree with itself; `abi::Record` carries the size the compiler
  settled on, beside the members it was built from.

- **The gate sees three things nothing compiled.** `RUSTDOCFLAGS="-D
  warnings" cargo doc --workspace --no-deps --all-features` runs in it, so a
  documentation comment is source that has to compile clean, and
  `--all-features` because otherwise the 579 lines of `sipral-ua`'s reference
  loop, which are behind one, are read by no rustdoc at all. Then
  `cargo clippy -p sipral-io-wasapi --target x86_64-pc-windows-msvc
  --all-targets -- -D warnings` and, beside it, the same target under
  `cargo doc`: together they are the only thing in the tree that reads the
  four modules behind `cfg(target_os = "windows")` — 3221 of that crate's
  7782 lines, two fifths of it, and compiled by nobody on the machine the
  gate runs on — and the doc run is what keeps its four links into those
  types honest. And `cargo clippy -p sipral-io-coreaudio --target
  aarch64-apple-ios`, for the three bodies in that crate no installed target
  compiled either. All of them fail rather than skip when the toolchain or
  the target is missing, and so does `gitleaks` from now on: a gate that goes
  green without the scanner has not looked.

- INVITEs refused because the table of watched sources was full are counted
  apart from those refused for calling too fast (`Refusals::by_crowding`).
  Both are one 480 from the far end and two different things to do about it:
  one source over its allowance is a limit set too tight, many addresses at
  once is a flood that wants a firewall.

- **One declaration of the ABI, with the header and three bindings printed from
  it** (B7). The failure this exists for is a C seam declared in three places
  that must agree: add a function, forget one of them, and the build succeeds
  and the field fails, on one platform. The declarations now record themselves
  — the same macros that emit the Rust item emit a descriptor beside it, doc
  comments included — and `tools/abi-gen` prints the C header, the Swift, the
  Kotlin with its JNI shim, and the C#. No Rust source is parsed anywhere.
  `scripts/check.sh` regenerates and compares, so a binding that fell behind is
  a failed gate rather than a surprise.

  What the gate cannot do is stated with it, because a gate believed to catch
  more than it does is worse than a smaller one: **nothing compiles the
  generated Swift, Kotlin or C#**, there being no toolchains in the gate, and
  the JNI shim in particular has never been compiled. The descriptor records
  the spelling rather than the layout, so a wrong `usize`-to-`size_t` rule
  would be wrong in all five outputs at once and compare clean.

  It also closed a coupling of exactly the shape B7 describes, inside the
  workspace itself: `UaEvent::IncomingCall` was destructured field by field
  in the FFI, so adding a field to it broke the build, and a feature in
  progress had already had to be redesigned around that.

- **SRTP is reachable from a call** (SDES, RFC 4568). It was written in full,
  proved against RFC 3711's own test vectors, and joined to nothing: no offer
  named `RTP/SAVP`, no answer was read for keys, and no session was ever opened
  protected. `Capabilities` said `srtp: true` regardless, which is the D8
  failure exactly — a capability that cannot drift from the build is the whole
  point of deriving it, and this one was a constant.

  Offering is off by default and on per call, because the key travels in the
  body (§7) and this layer cannot tell whether the signalling protects it.
  **Answering is on by default**, which is a different decision made
  differently: the peer has already asked for encryption, and refusing there
  turns a call that would have worked into a silent one. "Offer" and "require"
  are two settings and they differ in one place — an offer arriving *without*
  keys, which `Required` refuses before anything goes on the wire, because that
  is the only place a downgrade would be invisible.

  Proved on the bytes rather than on the SDP: the same call is placed twice
  from the same seeds, and the protected datagram is ten octets longer, shares
  its first twelve with the plain one, and does not contain the plaintext
  payload anywhere in it.

  DTLS-SRTP is reported absent rather than pretended: there is no handshake in
  this tree, and `Capabilities` now lists which keying a call can actually
  reach instead of answering a bare yes.

- **A session can be recorded and replayed deterministically** (D2). The
  hardest failures happen on one PBX, on one carrier, behind one NAT, and do
  not reproduce in a lab; they are fixed today by reasoning about a capture,
  shipping a guess and waiting. A recording holds the inbound messages, their
  timing and the seed the run was drawn from, and a replay feeds them back — so
  the bytes out, the events and the whole diagnostic record come back identical,
  which is asserted rather than claimed. The sans-I/O core is what makes this
  nearly free: everything enters through one shape and time was already a
  parameter.

  **It never contains audio, and that is structural rather than careful.** The
  format has no binary spelling at all — no escape for an arbitrary byte, no
  base64, no length prefix — and the only constructor for a payload validates
  against that alphabet. The honest cost is stated with it: a message with a
  binary body cannot be recorded either, and the recorder spoils the whole
  recording rather than dropping the body, because a recording holds every byte
  the stack was fed or it does not exist.

  One limit is worth knowing before relying on it: what the application does on
  its own — register, place a call, answer — arrives from nowhere, so it cannot
  be captured. A recording names those moments instead, and a replay hands the
  names back at the same offsets. There is a test showing that a replay which
  ignores them drives a stack that sends nothing.

- **The engine says why the codecs that lost, lost** (D5), and **a call carries
  its own catalogue** (D6, A2). "PCMU was chosen" is a fact; "Opus was offered
  and the answer never named it, G.722 was offered and the far end's own order
  put PCMU first" is a diagnosis, and it is what makes a wrong configuration
  visible instead of inferred from a capture. Every codec the call's catalogue
  could have offered now carries exactly one outcome, worked out at the moment
  the plan is settled rather than reconstructed afterwards — a reconstruction
  can be wrong in precisely the case somebody is debugging.

  The catalogue, the media configuration and the device are properties of a
  call now, not of the process. Two calls up is not hypothetical in a stack
  that has attended transfer, and every global mutable value in an engine is a
  race waiting for the second call. The process-wide default stays, because one
  codec order per site is the ordinary case; what is new is that a call can be
  placed with its own and keep it.

  Two things were checked before being built and turned out to need nothing:
  the transport half of D5 is already covered by the diagnostic record, and the
  NAT half has no decision to report because nothing in the tree reaches
  `sipral-nat` yet — which is `docs/06-nat.md`'s own admission, now confirmed
  from the other side.

- **Every call carries the story of what the stack decided** (D1). An ordered,
  bounded record per `Call-ID`: a stable reason code, the wire event that caused
  it with its size on the wire, a monotonic offset, and the addresses and limits
  involved — serialising to JSON that can be attached to a bug report unchanged.
  Eighteen codes to start with, and the rule that a code's wire form never
  changes and is never reused is written next to the type rather than hoped for.

  The bound is the part that is easy to get wrong twice. A record that overflows
  says how much it lost instead of quietly becoming a lie, records are evicted
  by least-recently-written so an hour-long call survives churn, and a request
  refused for want of room goes to the endpoint's own record — otherwise a
  scanner dialling extensions all night would evict every live call.

- **A stack that knows the device sleeps** (C2, C3). An application woken by a
  push tells the stack a call is expected on this account from this caller; the
  stack pre-warms the transport and refreshes the binding on the fastest path
  it has, matches the INVITE that follows to that announcement so the call
  screen already on the screen is the one that gets the call, and reports an
  announced call that never arrived as its own diagnosis rather than as an
  error. The INVITE that beats its own push, the call cancelled before the
  device woke, and two calls in quick succession are all tested rather than
  hoped for.

  A push carries no `Call-ID` and cannot be made to, so the match is on the
  account plus the user and host of the `From`. Full §19.1.4 equivalence is
  wrong in both directions here: it fails on a proxy that adds `;user=phone`,
  and failing to match sounds safe but produces a second call screen for a call
  the person is already looking at.

  Registration can also be frozen and thawed across a cold start, with a
  versioned format that refuses a snapshot from a later version rather than
  misreading it, and a restored binding says it is restored rather than
  claiming to be proved. Time-to-ready is measured and reported, because it is
  what decides how long a queue rings a sleeping phone before skipping it. RFC
  8599's `pn-provider`, `pn-prid` and `pn-param` go on the REGISTER contact and
  nowhere else — and a de-registration leaves the push identifier out.

- **A lifecycle for a machine that suspends** (D4, A7, C5), and the state that
  was missing from it. `suspending`, `resumed`, `network_changed(from, to)`,
  `interface_lost` and `name_resolution_lost`, each with a written recovery
  ladder and each tested under the conditions that actually break it rather
  than only the path where everything works.

  The idea the rest hangs off: **a monotonic clock cannot tell you that you
  slept.** It does not advance during suspend, so a stack that slept eight
  hours comes back believing eight milliseconds passed, with every deadline
  still in the future and every binding still valid, and nothing it can measure
  contradicts that. Hence `Unverified` — a binding a registrar really granted,
  over a transport since suspended or lost, that nothing has proved since.
  Neither registered nor failed, and the direct answer to a cached registration
  that read as valid while name resolution had gone.

  `suspending` sends nothing at all. A graceful unregister cannot be observed
  to have left, and if it does leave, a de-registered device cannot be woken by
  a push.

- **Health counters and an honest answer about what this build can do** (D3,
  D8). Registrations attempted, succeeded and failed **by reason**; calls by
  disposition; media gaps; jitter-buffer events; transport promotions; and one
  gauge for calls in progress. A snapshot differences against an earlier one,
  so a deployment's health is a subtraction rather than a search through text.
  Capabilities are derived from the build — the codec catalogue, the transports
  and features actually compiled in — never hand-maintained, because a
  capability list that can drift from the build is worse than none: it is
  believed.

- **The device crates report the delay the canceller needs.** WASAPI had it in
  one property; CoreAudio has four per direction across two kinds of object,
  and a rate to convert them by, so `sipral-io-coreaudio` assembles it and both
  crates now answer the same question in the same shape. On a laptop's own
  speakers and microphone, with a stream open, that comes to a little over a
  hundred milliseconds. It is what the devices report, not an estimate, and
  `docs/05-media.md` gives the readings and the conditions they were taken
  under.

  On Windows the stream is now opened as a communications stream, which is what
  puts the operating system's own capture-side processing in the path. What it
  cannot do is confirm that anything is cancelling: Windows offers no
  per-stream way to report it, so the crate says what was asked and accepted
  and stops there rather than implying more.

- **A call can be dialled into, and hears what is dialled at it** (RFC 4733).
  The packet and everything §2.1 does to the sequence number and the timestamp
  were already written and had no schedule to run on, because the layer that
  writes them never sees a frame boundary. The facade does: one packet per
  captured frame, which §2.5.1.2 calls the natural interval, and the digit
  replaces the audio for as long as it lasts because §2.1 leaves no way for
  both to be on the wire at once.

  Keys queue rather than being refused — somebody entering an extension presses
  four of them faster than four can be sent — and the 40 ms floor RFC 4733
  §2.5.2.1 takes from ITU-T Q.24 is enforced where the digit is asked for
  rather than discovered by a far end that heard nothing. A dial string with a
  character no keypad has queues nothing at all: half an extension is worse
  than none, because it reaches somebody. A call whose negotiation settled on
  no telephone-event payload type says so instead of swallowing the key.

  The other direction was missing outright: events arrived, were correctly
  ignored by the earpiece, and were never reported to anybody. One keypress is
  now one event, collapsed on the timestamp that identifies it — reporting per
  packet would have turned one 7 into five.

- **The echo-cancellation seam is reachable from a live call.** `Processor` has
  been in `sipral-media` since the audio pipeline was written and nothing
  called it, which made it a shape rather than a seam. A call now takes one,
  and — the part that is actually work — keeps the recent past of its own
  loudspeaker so the processor is handed the frame that was playing while the
  microphone was open, at a distance the platform reports with
  `set_render_delay`. Handing a canceller the wrong frame is not weaker
  cancellation but none at all: an adaptive filter given an uncorrelated
  reference diverges, and the call ends up worse than with nothing attached.

  Nothing is allocated until a processor is attached, so a headless build —
  which has no loudspeaker and therefore no echo — pays nothing. Two decisions
  that follow are worth knowing about: silence suppression and the recording
  tap both see the processed audio rather than the raw microphone, and the
  application's own capture buffer is never written to. A delay above half a
  second is refused where it is set, because nothing between a loudspeaker and
  a microphone in one room takes that long and the number would only ever be a
  platform reporting something else.

- **Subscriptions, and the busy-lamp field on top of them** (RFC 6665, RFC 4235)
  — the largest piece of protocol the stack was missing, and the one a desktop
  client cannot ship without. Establish, refresh, expire, re-subscribe after
  failure, and report every state change including the termination and its
  reason, which is the half that tells an application whether to try again.

  The dialog is established by the first notification and not by the 2xx,
  because §4.4.1 says so and because the notification really does arrive first
  in the field. Writing that turned up something sharper: on a reliable
  transport the server transaction is gone the instant its final response is
  sent, and the request and the flow the dialog is built from live on that
  transaction — so the dialog has to be opened before the 200, not after. Found
  by a test that passed on UDP and failed on TCP.

  A subscription that ends takes its dialog with it, since there is no BYE for
  one. Without that a phone watching thirty extensions leaks a dialog per lamp
  per refresh.

  The `dialog-info+xml` reader is deliberately not an XML parser and must not
  become one. No DOCTYPE, so there is no entity to expand and the billion-laughs
  shape cannot be written; no CDATA; the five predefined entities and numeric
  references only; and depth, element count, attribute count and value length
  all bounded before the first byte is read. Above it sits §4.3's coherence
  table and §3.7.2's state machine, which is what a lamp actually shows.

  Notifications are divided with the transfer handler by their event package,
  and the general machine runs last: a transfer owns `refer` inside a call it is
  driving, and only once everyone holding a subscription has had a turn can
  anything say a notification belongs to nobody — which is answered 481, as
  §4.1.3 requires. Two silent `?` in the transfer path that swallowed a REFER or
  a NOTIFY arriving on a dialog that is not a call are now reachable, because
  subscriptions have dialogs too.

  Not built, with the seams named: no notifier role, so an incoming SUBSCRIBE
  still reaches the application unclaimed; `Allow-Events` is read but not yet
  advertised; and the REFER subscription stays as it is rather than being
  half-converted — it opens with a REFER, its dialog already belongs to a call,
  and this end is the notifier there, which is three real differences and a
  rewrite that needs the notifier role first.

- **A call can be placed through the C ABI.** It could not: `sipral_stack_poll`
  counted what the stack wanted written and threw it away, and nothing could
  hand it bytes that had arrived. The only thing that ever read an outgoing
  message was a test helper. So the ABI could carry a call's audio and not its
  INVITE, which blocked the phase whose exit criterion is a desktop client
  running on this engine.

  Six entry points now: take the next message out, put a datagram or a run of
  stream bytes in, and tell the stack that a transport is bound, has failed, or
  has closed. A message that will not fit the caller's buffer is **kept**, not
  dropped — the difference between this and the media path is that a media
  packet is refused before it is built while a SIP message already exists by the
  time it reaches the boundary, and throwing away something the stack has
  committed to sending is not a refusal, it is a lost call. The needed length
  comes back so the caller can ask, then fetch.

  What travels with a message is all of it, including the address it must leave
  *from*: RFC 3581 §4 makes a response go out from the address its request
  arrived on, and a caller on a wildcard socket cannot work that out. Addresses
  cross as `host:port` text, which is the convention every other address in this
  ABI already uses.

  One transport, its number published rather than hard-coded out of sight, and
  every other number refused with a message naming the one that exists — so the
  day a second one arrives it is more valid numbers rather than a second set of
  functions.

  Two older tests asserted that one message had been discarded, as a stand-in
  for "something went out". They now take that message through the ABI and
  assert what it is, which makes their names true for the first time.

- **The C ABI carries media.** It depended on signalling and stopped there, so a
  client on the other side of it parsed its own SDP, ran its own RTP and owned
  its own audio — which is why most of `docs/13-client-requirements.md` was
  waiting on one crate. It now drives the facade's engine, and fourteen entry
  points came with it: the codecs this build contains and the order they are
  offered in, without needing a stack to ask; what a live call agreed, with its
  wire payload type, clocks and keying; recording started and stopped mid-call;
  statistics live and complete at the end; media stopping and coming back; and
  the audio path itself, without which the rest is decoration.

  A call is described one way or the other and never both: give it a media
  address and the stack writes the offer and owns the audio, give it raw SDP and
  it behaves as it always did. Both is refused. A managed call answers its own
  re-offers, so the application is told the media changed rather than asked what
  to do about it.

  The recording's ownership is the part that had to be got right: the file
  belongs to the media session and C never sees a handle, and the WAVE header's
  lengths are patched on all three exits — an explicit stop, the call ending,
  and the stack being destroyed, including when it is destroyed from inside the
  event callback. A file that is never closed is a file that will not play.

  Two of the reserved event numbers were taken in place, which is what they were
  reserved for. Taking them meant letting live and reserved lines interleave in
  one run rather than forcing the live ones into a prefix, since otherwise
  reaching a number meant also spending the ones before it on features that do
  not exist.

  **What this does not yet do, said plainly: a call still cannot be placed
  through this ABI.** There is no transport entry point — `sipral_stack_poll`
  counts what the stack wants to send and discards it — so media I/O is now
  ahead of signalling I/O. That gap predates this change and is next.

- A default profile for the equipment this stack is actually deployed against —
  a softphone behind consumer NAT talking to an Asterisk-family PBX — with what
  each optional mechanism costs on the wire beside it. **Declaring ICE adds 143
  bytes per candidate**, measured and pinned by a test rather than estimated
  into a document that would stop being true, and that is the floor: a laptop
  with Wi-Fi, Ethernet and a VPN writes nine such lines, and an offer carrying
  them no longer fits the 1300-byte datagram floor of RFC 3261 §18.1.1. Which is
  not hypothetical — NAT attributes were four hundred of the bytes in the
  request that fragmented in the field and died in silence, sent to a peer that
  did not speak the protocol at all.
  The document also says the uncomfortable part plainly: ICE is off today
  because nothing links `sipral-nat`, which is the right behaviour reached the
  wrong way. A default that holds only because nobody wired the alternative is
  one that changes the first time somebody does.

- Gain, mute and a level meter on both device crates, and the device that goes
  away mid-call reported rather than turning into silence.

  The gain is applied to the frames here rather than through the platform,
  because none of the platform's volumes belongs to a call: the device volume
  is shared with everything on the machine, the process volume is one setting
  for the whole application, and both outlive the call. Turning a call down
  must not turn a film down. It is applied at the device end of the ring rather
  than the caller's, because the ring holds sixteen frames and a mute heard a
  third of a second after the button is not a mute.

  Both ends of the range are defined: the ratio clamps, the samples saturate
  instead of wrapping, and every sample that lands at the end is counted — so a
  gain set too high is a number beside the slider rather than a mystery
  distortion. A muted direction keeps frames moving, so unmuting does not play
  a backlog.

  The meter is the loudest sample over a tenth of a second, held between one
  window and two. Peak-since-last-poll was rejected because it makes the number
  depend on how often it is read; polling now mutates nothing, so any number of
  callers at any rate see the same answer. It costs one compare per sample,
  folded into the pass the gain already makes.

  A device that disappears mid-call is reported — read from the platform rather
  than inferred from silence — and the stream stops rather than quietly
  producing nothing, so an application that ignores the event finds a stream
  that has plainly stopped. Recovery is one call, carrying the gain and the
  mute across, and is deliberately not automatic: whether to move to the laptop
  speaker, wait, or end the call is not this layer's decision. A saved
  selection is held as the identity that survives a replug, and the
  documentation is explicit that a crate cannot stop the operating system
  changing the default — reopening is what re-applies it.

- An INVITE nobody asked for can be refused before anything sees it. Scanners
  dial common extension numbers at every hour, and a client on a public port
  either filters them or wakes its user at three in the morning. The policy hook
  sits between registration and calls in the event chain, which is the last
  place before the one site that mints a call handle and pushes
  `IncomingCall` — "before any user-visible effect" is the requirement's own
  sentence and it is where the ordering comes from.

  Beneath it, a token bucket per source address — per address rather than per
  socket, since a port costs an attacker nothing to change — in a table bounded
  at sixty-four entries. At the bound a source whose bucket has refilled is
  evicted, holding nothing a new entry would not; if every seat is still
  spending, a stranger is refused rather than admitted untracked, because
  admitting what cannot be limited is a hole exactly when it matters. The
  limiter runs before the hook: calling arbitrary application code at flood rate
  is the second attack.

  Refusals are counted, cumulatively, and are deliberately not an event. An
  event queue anybody on the internet can fill is the same attack one layer up.

  The answer is 480 for every reason. §21.4.18 covers a callee "in a state that
  precludes communication", which is what a screened number is and also what a
  switched-off phone says, so one answer gives a scanner no way to tell a
  guarded extension from an unattended one. 404 was rejected as an enumeration
  oracle, 503 because §21.5.4 has a proxy stop forwarding to this agent
  altogether, and 6xx because it speaks for the person rather than the device
  and would silence the desk phone they are also registered on.

- **The `sipral` crate is the facade it was always described as.** It was eleven
  lines — a name reserved for crates.io, not yet uploaded — while
  `docs/01-architecture.md` said it was
  where signalling and media meet. Nothing joined them, so `MediaPlan` and
  `MediaCapabilities` were a vocabulary nobody spoke, and an application that
  wanted a call with audio in it wrote the join itself.

  It now carries: a codec catalogue that says what this build actually contains,
  in the order it offers them, and what one live call settled on — a name the
  build has no encoder for is refused where the order is set rather than dropped
  where it would have been used; a media session that owns one call's audio,
  taking the negotiated description, driving the codec and the jitter buffer and
  comfort noise, allocating nothing per packet and reading no clock; the engine
  that attaches a session when a call confirms, follows it through hold, resume,
  a peer that moved and a codec change, and releases it with the call's
  statistics; call recording, both directions mixed into one WAVE file the crate
  never opens itself; stream statistics that travel, live and at the end; and a
  watchdog that says when inbound audio stops and when it comes back, silent
  while this end is not meant to be receiving, because an alarm that cries wolf
  during hold is an alarm an application learns to ignore.

  The rule it exists to keep is unchanged: `sipral-ua` still reaches into no
  media crate and no media crate reaches into it. The join lives here because
  here is the only place the architecture allows it.

  Deliberately not yet: ICE, SRTP keying and DTMF sending, each with its seam
  named in the code rather than left to be found. And the C ABI still points at
  signalling alone, which is the next thing to close.

- One declaration for the ABI's event numbers, and disagreeing with it is a
  build failure. The kinds, their names and their numbers are generated from a
  single list, with an assertion that the list runs `1, 2, 3, …` with nothing
  repeated, moved or missing. The hole it closes is the one the requirements
  describe from the other side: two features written in two branches each take
  the number after the last kind, both compile, and the one that lands second
  has silently renumbered an event a shipped binding already knows. The numbers
  of the six features already committed to are spent now, as reserved lines
  naming what each belongs to, so taking one means reading a number rather than
  choosing it.

- The shapes of bad network a call is measured over, as fixtures in
  `interop/impairment/` rather than as arguments somebody types. A threshold
  measured against a profile that lives in a shell history is a threshold
  nobody can reproduce. Four of them: bursty loss with jitter and reordering; a
  mobile leg losing two per cent in bursts on a link whose delay moves; a
  geostationary carrier, where the interesting failure is arithmetic rather
  than audio, because a retransmission schedule tuned on a fast path gives up
  before a satellite answers; and a link that disappears for eight seconds in
  the middle of the call.
  That last one is the one worth having, and the one an easy simulator does not
  produce: loss and delay held constant for a whole call are a bad line, not an
  interruption. It does not ask whether audio survived, since eight seconds of
  nothing cannot be concealed, but whether the stack is still there afterwards
  — the dialog kept, no timer having fired into the gap, and a buffer that
  returns to the target it had rather than staying where the gap left it. Each
  profile declares what must appear in the qdisc once it is applied, and the
  runner reads it back, because `tc` accepts settings the kernel then discards
  in silence and a run whose impairment never happened is byte for byte a clean
  one.

- `scripts/lab.sh` and `scripts/fuzz.sh`, and no CI configuration at all.
  Nothing runs on hardware that is not ours: a runner that builds, signs or
  publishes needs credentials on somebody else's machine, and for Apple
  signing there is no way to give it one — a runner has no keychain. So the
  three jobs that were hosted are three scripts. `scripts/check.sh` was already
  the gate and is unchanged; `lab.sh` brings the three-container lab up, runs
  the flows against each server and repeats one over a link made bad with
  `tc netem`; `fuzz.sh` runs every target for as long as it is given.
  `.github/workflows/` is gone and gitignored.
- G.722 wired into the interop harness, and the trap that goes with it closed.
  What used to be a single `Law` field is a codec, because G.711's samples,
  octets and timestamp ticks for a twenty-millisecond frame are all 160 and
  G.722's are 320, 160 and 160 — one constant served all three, and anything
  written against that shape encodes half a frame and calls it a packet. The
  session now accepts payload type 9, the tone keeps its pitch when the rate
  doubles, and `SIPRAL_CODEC=g722` puts the wideband codec first in the offer
  so the same ten flows run against real software with it. Not the default:
  every lab server takes G.722, so offering it unasked would quietly change
  what those flows have been proving.
- G.722 in `sipral-media`, written from ITU-T Recommendation G.722 (09/2012).
  The twenty-four-tap filter pair that splits sixteen kilohertz into two bands
  of eight and puts them back together, six-bit ADPCM on the lower band and
  two-bit on the higher, the logarithmic scale factor and its adaptation, the
  sixth-order zero section and second-order pole section, and all three
  decoder modes. Every arithmetic operation is §6.2's, including its
  definition of multiplication as a shift and its saturating addition, because
  a wrapping add here decodes to noise only on loud passages.
  The roadmap used to say this would be linked. There is nothing to link: the
  usual library is spandsp's, which the clean-room rule forbids by name, and
  the Rust crate that looks free of it carries spandsp's comments word for
  word. A Recommendation is a specification, and this is implemented from it.
  Every table was read off the document twice, independently, and compared;
  the one cell the two readings disagreed on was settled against the closed
  form the table follows. Two of the document's own slips are handled and
  written down: Table 19 prints six characters for a five-bit codeword, and
  Table 14 prints two of its columns two rows lower than the address they are
  addressed by.
  G.722's RTP clock rate is 8000 although it samples at 16000 (RFC 3551
  §4.5.2), so `SAMPLE_RATE` and `CLOCK_RATE` are separate constants and
  `frame_samples`, `frame_octets` and `frame_ticks` are three different
  numbers for the same frame.
- SRTP and SRTCP in `sipral-rtp`, written from RFC 3711. Counter mode and f8
  keystreams, HMAC-SHA-1 tags, the key derivation of §4.3 with erratum 3712
  applied to the SRTCP index, the implicit packet index of §3.3.1 with
  Appendix A's estimator, and a replay window twice the size §3.3.2 requires.
  The three suites RFC 4568 defines, the `UNENCRYPTED_*` and
  `UNAUTHENTICATED_SRTP` session parameters, an optional master key
  identifier, and the packet counts §9.2 caps at 2^48 and 2^31.
  Protecting and unprotecting happen in the caller's own buffer, so a
  protected packet costs no allocation. Every test vector in the RFC's
  Appendix B is in the suite, as are RFC 3174's for SHA-1 and RFC 2202's for
  HMAC.
  The block cipher comes from the `aes` crate, the first thing `sipral-rtp`
  depends on, because a table-driven AES leaks its key through the cache;
  everything above it is in-tree. Linking libsrtp2, which the roadmap used to
  name, was dropped: it is C, and this crate denies `unsafe`.
- `RtpSession::protected`, which puts SRTP under an ordinary RTP stream. What
  it builds goes out protected and what arrives is verified before any of it
  is believed, so the order RFC 3711 §3.3 sets out is not something an
  integrator can get wrong. `RtpSession::receive` and `rtcp_receive` now take
  the caller's buffer mutably, because a receiver decrypts in place.
- The `a=crypto` line read as values in `sipral-core`: the suite, the master
  key and salt out of the `inline:` parameter, the lifetime in both forms, the
  master key identifier, and the session parameters that say whether to
  encrypt and whether to authenticate. Every rule RFC 4568 states as making
  the attribute invalid refuses it. A peer that sends back a key we offered is
  refused too — §7.1.2 requires the keys to differ, and one key protecting
  both directions is the failure the transform cannot survive.
- Hold and resume in `sipral-ua`, and the offers that come after them. Hold is
  RFC 3264 §8.4's: the description already negotiated, with a stream that was
  `sendrecv` marked `sendonly` and one that was `recvonly` marked `inactive`,
  and the `o=` version moved on. The stack writes it, so the application says
  hold rather than `a=sendonly`, and resume puts back the direction each stream
  started with rather than assuming `sendrecv`. `Hold` has a flag per
  direction, because §8.4 holds each one separately; the far end holding us is
  read off `sendonly`, `inactive`, or the `0.0.0.0` address RFC 2543 used, and
  reported as `SessionChanged`.
  Which request carries the change is the dialog's decision first: a confirmed
  call uses a re-INVITE, which RFC 3311 §5.1 recommends outright, and an early
  one uses UPDATE, because §14.1 forbids a second INVITE while the first is
  running — and only when the far end listed UPDATE in an `Allow` (§4), which
  this end now advertises on its INVITE, on a provisional carrying a
  description, and on the 2xx.
  An offer arriving from the far end is answered here when it keeps the streams
  and the formats that were negotiated, because the answer is then this end's
  own ports with the direction §6.1 leaves. One that changes the codecs or the
  stream list arrives as `Reoffer` with the transaction still open, for
  `accept_reoffer` or `reject_reoffer`; a body that claims to be a session
  description and is not gets a 488 with the `Warning` §14.2 asks for.
  Glare is handled from both sides: a 491 carries the wait §14.1 draws and the
  change goes out again once, and an offer that crosses one of ours is answered
  491 while one that arrives on top of an unanswered offer of theirs is
  answered 500 with a drawn `Retry-After` (RFC 3311 §5.2, generalised to both
  requests).
- `StatusCode::NOT_ACCEPTABLE_HERE`, the refusal that is about the session
  description rather than about the request that carried it.
- A 2xx that is never acknowledged now ends the dialog with a BYE, which
  §13.3.1.4 asks for and §14.2 repeats for a re-INVITE. RFC 6026's timer L was
  ending the transaction in silence, so the layer above could not tell an ACK
  that arrived from one that never did; it now reports
  `TerminationReason::TimedOut`, and `sipral-ua` sends the BYE and reports the
  call as unreachable. Without it a far end that stops answering leaves a line
  busy for as long as the process runs.
- `OutgoingResponse::status`, to read back what a response was built with.
- Session timers (RFC 4028) in `sipral-ua`. `Supported: timer` on every request,
  an interval asked for per account and thirty minutes by default, the
  refresher left to the negotiation on the first INVITE and carried afterwards.
  The refresher refreshes at half the interval (§7.2) and the other end hangs up
  shortly before expiry (§10), reporting `CallEndReason::Expired`. The refresh
  is an UPDATE where the peer takes one and a re-INVITE where it does not,
  repeating the description already agreed unchanged, which is how §7.4 and
  RFC 3264 §8 together say nothing has moved. A 422 sends the INVITE again on
  the same `Call-ID` with the demanded floor, once; an incoming interval below
  §5's ninety seconds is answered 422 before the application sees it.
- `StatusCode::SESSION_INTERVAL_TOO_SMALL`.
- `sipral-rtp`, phase one's share of it: the fixed header read and written
  (RFC 3550 §5.1), the validity checks a receiver makes before it believes a
  source (Appendix A.1) including the probation state machine and sequence
  wraparound, the marker-bit rule the audio profile adds (RFC 3551 §4.1),
  symmetric RTP with latching onto the first valid packet's source, and a
  fixed-depth de-jitter buffer that takes reordering as normal, drops
  duplicates by sequence number and never grows past its depth. Sans-I/O, with
  no dependency on `sipral-core`. RTCP, the adaptive buffer, loss concealment,
  DTMF and SRTP are later phases and are not stubbed here.
- `sipral-media`, phase one's share: G.711 mu-law and A-law, encode and decode,
  written from the companding law, with the frame arithmetic a caller needs and
  the two payload types RFC 3551 fixes. Every one of the 512 code points is
  round-tripped in the tests, which is the strongest property the code has.
- The interop lab under `interop/`: Kamailio, FreeSWITCH and Asterisk on
  default settings in Compose, a capture beside them, and a harness that drives
  `sipral-ua` through register, call, and hold and resume, judging each flow
  against conditions written before the run. It runs as its own CI job on
  Linux. Every other test in this workspace runs the stack against a peer we
  wrote; this is the first that does not.
- Reliable provisional responses on the answering side (RFC 3262). `ring` sends
  reliably exactly when the INVITE asked — §3 leaves no choice either way — and
  the PRACK is answered 2xx here, with an answer to any offer it carried. A
  reliable response that carried a description holds the 2xx to the INVITE until
  it is acknowledged (§5), so an application that answers early has its 200 kept
  and sent on the PRACK rather than putting two unanswered offers on the wire.
  In the other direction an offer arriving in a reliable provisional is reported
  by `answer_wanted` on `CallProgress` and answered with
  `UserAgent::answer_early`, which puts it in the PRACK where §5 wants it.
- A `Require` naming an extension that is not implemented is answered 420 with
  the token in `Unsupported` (§8.2.2.3), before the application sees the call.
- Transfer, both kinds (RFC 3515, RFC 3891). `transfer` sends a REFER and
  reports what the transferee says in its `message/sipfrag` NOTIFYs as
  `TransferProgress` and `TransferDone`; the call is given up only when the
  transfer has actually succeeded, because hanging up when the REFER goes turns
  a failure into a call that vanished. `transfer_to` sends the other call's
  remote target with an escaped `Replaces` naming its dialog, which is the only
  difference between an attended transfer and a blind one.
  A REFER that arrives is `TransferRequested`, taken with `accept_transfer` —
  202, the opening NOTIFY, and the call it asked for — or refused with
  `reject_transfer`; anything but exactly one `Refer-To` is answered 400.
  `Replaces` on an incoming INVITE is matched before the application sees it,
  with §3's status code for each way it can fail: 481 for no match or several,
  603 for a dialog that has ended, 486 for `early-only` against a confirmed
  one. A match is replaced when the new call is answered, and reported as
  `CallReplaced`.
- The reference loop, behind the `reference-loop` feature and off by default.
  `Runtime::bind` gives a `UserAgent` with a datagram socket under it, a thread
  per socket doing the blocking reads, and a `Handler` with two methods. It
  answers `ResolveNeeded` with an A lookup and `TransportWanted` by opening the
  TCP connection §18.1.1 asks for; it does not do SRV, does not link TLS, and
  binds to a named address rather than a wildcard, because `std::net` cannot
  say which local address a datagram arrived on and RFC 3581 §4 needs that.
  With it comes the first test in this workspace where two stacks talk to each
  other over real sockets rather than to a peer written in the same file: an
  INVITE, a 180, a 200, the ACK, a hold and a BYE, on loopback.

- Glare, both ways (§14.2, RFC 3311 §5.2). An INVITE that crosses one of ours
  inside a dialog is answered 491, a second one that arrives before we answered
  the first is answered 500 with a drawn `Retry-After`, and so is a second
  UPDATE; none of them reaches the caller, because none is a decision. The end
  that receives a 491 gets `Event::ReinviteGlare` with how long to wait, drawn
  from the range §14.1 gives it — which differs by who generated the `Call-ID`,
  so that two ends backing off do not collide again.
- `SendError::InviteInProgress` and `SendError::WrongMethod`: §14.1 forbids a
  second INVITE transaction in a dialog while one is running in either
  direction, and an INVITE handed to `request_in_dialog` would have run on a
  transaction machine that cannot acknowledge it.

- The mark, and the rules for drawing it. `assets/` carries the mark and the
  horizontal lockup as SVG and PNG, light and dark, with `assets/BRAND.md` for
  the geometry, the three colours and the one red cell. The README shows the
  lockup, every crate carries `html_logo_url` and `html_favicon_url` for
  docs.rs, and the NuGet package carries an icon. The lockup SVG keeps the
  wordmark as live text, so anywhere Archivo is not installed the PNG is the
  one to use — which `BRAND.md` says.
- `scripts/check.sh` fails on embedded provenance metadata. Artwork arrives with
  a signed C2PA manifest naming the tool that made it, in a PNG `caBX` chunk or
  an SVG `<metadata>` element; it is base64 inside a binary, so the existing
  text scan never saw it, and this repository is public. The files in `assets/`
  were stripped before being committed — PNG down to `IHDR`, `PLTE`, `tRNS`,
  `IDAT`, `IEND` and `sRGB`, SVG without `<metadata>` — which changes no pixel.

- Workspace skeleton: the eight crates from `docs/01-architecture.md`, each with
  its scope documented and nothing implemented.
- Design documents for phase 0: architecture, clean-room rules, signalling
  core, user agent, media, NAT, headless endpoint, FFI, RFC index, roadmap,
  testing.
- Licensing set: AGPL-3.0-only alongside a commercial arm, with `LICENSING.md`,
  `LICENSE-COMMERCIAL.md`, `TRADEMARK.md`, `AUTHORS`, `THIRD-PARTY-NOTICES.md`,
  and SPDX headers on every source file.
- `deny.toml` with a permissive-only allow-list, enforced by the check script.
- `scripts/check.sh`: licence headers, provenance, published-tree language,
  internal files and captures, build, lints, tests, dependency licences,
  secrets.
- CI on Linux, macOS and Windows, plus separate licence and hygiene jobs.
- `sipral-core::msg`: the message layer's foundation. `Span`, `HeaderSlot` and
  a reusable `ParseScratch`; `Method` and `StatusCode`; `RawMessage` as a view
  over the caller's buffer; and a parser that locates the start line, the
  header fields and the body without copying any of them. Folded values are one
  slot with their interior CRLF intact, repeated headers are one slot each in
  wire order, and `Content-Length` frames the body so trailing octets in a
  datagram are ignored. Bounded by a `Limits` struct so a hostile peer cannot
  make it do unbounded work, and written so that no input reaches a panic.
  37 tests, several of them RFC 4475 cases the corpus will assert in full later.
- `sipral-core::msg::HeaderName`: the 38 header fields the stack knows, matched
  whatever their case and in either form. Fifteen compact forms, each read out
  of the RFC that defines it rather than from memory. `RawMessage` gains
  `header`, `header_values`, `header_count` and `header_names`, so asking for
  `Via` finds a `v:` line and asking for an extension is case-insensitive too.
- `sipral-core::msg::UriRef`: SIP URIs in parts, borrowed from the buffer.
  An enum rather than a struct, because only `sip:` and `sips:` have a
  hostport: a `tel:` URI and an unknown scheme are kept whole instead of being
  forced into a shape they do not have. The userinfo boundary is settled before
  parameters or headers are looked for, since `user` may contain `;` and `?`
  unescaped. Parameters and headers are walked on demand, and `unescape`
  handles `%` escapes including `%00`, leaving a stray `%` alone because the
  corpus has one in a message that is valid.
- `sipral-core::msg::lex`: the lexical rules every header value obeys, in one
  place instead of once per field. Unfolding, comma-separated values, and
  `;name=value` parameters, all of which stop at a quoted string or a `<...>`
  URI. `Contact: "Smith, John" <sip:j@x>` is one value; `qop="auth=1,auth-int"`
  is one parameter.
- `sipral-core::msg::OwnedMessage`: the same bytes and header index behind two
  `Arc`s, so a message the stack keeps costs one copy and a clone costs none.
  Bytes past the body are left behind, so a second request sharing a datagram
  is not carried along.
- `sipral-core::msg::scalar`: the fields that carry a number, and `CSeq`, which
  carries one and a method. The separator inside `CSeq` and `RAck` is `LWS`, so
  a fold between the digits and the method still reads. Overflow is two rules,
  not one: a `CSeq` that does not fit in 32 bits is refused, while an `Expires`
  parses and reports that it did not fit, because the RFC lets an element fall
  back to its default there. Nothing is truncated, so a hundred-digit `Expires`
  cannot become a plausible small number.
- `sipral-core::msg::ViaRef`: the field that decides where a response goes.
  `SLASH` and `COLON` absorb surrounding whitespace, so the two slashes are
  located before anything else; `received` carries an IPv6 address without
  brackets, unlike everywhere else, and accepts them anyway because they are
  sent; `ttl` is `1*3DIGIT`, so `;ttl=1234` is not a ttl at all; `rport` has
  three states and `;rport=` is none of them. A `Via` with no branch is an RFC
  2543 peer to be matched per §17.2.3, not a malformed header.
- `sipral-core::msg::NameAddrRef`: `From`, `To` and `Contact`. The angle
  brackets decide who owns the parameters — inside them `;transport=tcp` is on
  the URI, outside them it is on the header field — and RFC 4475 `cparam01` and
  `cparam02` are one address written both ways to catch a stack that cannot
  tell. Whitespace lives outside the brackets, so `< sip:a@b >` is refused; a
  display name is a token run or a quoted string and nothing else, so
  `Bell, Alexander <sip:...>` is refused while `caller<sip:...>` is accepted as
  the documented grammar defect it is; an unterminated quoted string is refused
  rather than guessed at. `Contact: *` is the whole field or nothing.
  `RawMessage` gains `from`, `to`, `contact` and `field_values`, the last
  walking a comma-separated field across its lines and its commas alike.
- `sipral-core::msg::RouteRef`: `Route` and `Record-Route`. A route entry is a
  `name-addr` with no bracket-less alternative, so `Route: sip:p1;lr` is
  refused rather than guessed at — without the `>` there is nothing to say
  where the URI ends. `is_loose_route()` reads `;lr` on the URI and not on the
  header field, because `<sip:p1>;lr` is a strict router carrying a parameter
  that happens to be spelled the same, and getting that backwards sends the
  request to a strict router with a Request-URI it cannot use. Entries come
  back in wire order, never sorted or deduplicated.
- `sipral-core::msg::ChallengeRef` and `CredentialsRef`: digest challenges and
  credentials, as two types rather than one, because `qop` is a quoted comma
  list in a challenge and a bare token in credentials and the RFC's own worked
  example writes both. `realm`, `nonce`, `cnonce`, `username` and `opaque` come
  back unescaped; `uri` and `response` come back exactly as written, since
  neither is a `quoted-string` and a Request-URI is no place to resolve
  backslashes. `response` has no fixed length, per RFC 8760. Each header line
  is one value: RFC 3261 §20.7 and §20.28 exempt these fields from
  comma-joining, and several challenges are several lines in preference order.
- `sipral-core::msg::TokenIter` and `MediaTypeRef`: `Require`, `Proxy-Require`,
  `Supported`, `Unsupported`, `Content-Encoding`, `Accept`, `Allow` and
  `Content-Type`. Option tags are matched without case; methods are not,
  because the six RFC 3261 verbs are fixed-case literals in the grammar and
  `Allow: invite` is an extension method that happens to be spelled like one
  of them.
- `sipral-core::msg::RequestBuilder` and `ResponseBuilder`: writing a message
  out. Deterministic — same inputs, same bytes, whatever order the setters were
  called in — because a retransmission has to be the identical datagram and a
  byte-comparing test is worth nothing otherwise. `Via` goes first, then the
  routing and dialog fields, then whatever else the caller added, then the
  body's two fields; `Content-Length` is always written, since a stream
  transport has no other way to find the end of a message. A response copies
  what RFC 3261 §8.2.6.2 says must be equal, adds a `To` tag only when the
  request carried none, and copies `Record-Route` only when asked, because
  §12.1.1 requires that of a response establishing a dialog and only the
  caller knows whether this is one. No value may hold CR or LF: a header value
  goes out on one line, and a caller's data with a line break in it would
  otherwise write headers of its own.
- `sipral-core::msg::StreamFramer`: reassembling TCP and TLS into messages, and
  the one place in the receive path that copies. A message without
  `Content-Length` is refused rather than read to the end of the buffer, since
  RFC 3261 §18.3 makes the field mandatory on a stream and guessing would
  swallow whatever followed. Keep-alives (RFC 5626 §4.4.1) are skipped between
  messages and counted, so the connection's owner can send the single CRLF a
  double CRLF is owed. Work is bounded per byte received rather than per call:
  a peer feeding one byte at a time cannot make reassembly quadratic.
- `RawMessage::validate`: the question a UAS asks before answering — is this a
  message the stack can act on, or one that draws a 400? A message can be
  framed correctly and still carry a `From` whose display name is not one, a
  `CSeq` naming a different method than the start line, or a `Date` in a zone
  nobody can read. The parser has no business refusing those, since it does not
  know which fields the caller will read, so the question is asked once, here,
  by whoever is about to answer.
- `SipDate` and `RawMessage::date`: RFC 3261 §20.17, which narrows RFC 1123 to
  GMT and says outright that the names are case-sensitive. `EST` is not a zone
  this reads, and neither is `UT`, `UTC` or `gmt`.
- `sipral-core::transaction`: the handles the transaction layer is addressed
  by. Typed by machine, so answering a PRACK with an INVITE server transaction
  handle is a compile error rather than a runtime one, and the guarantee
  survives into C as one struct per kind. Generational, so a handle issued
  before a transaction died never answers to whoever took its slot — which is
  what a late retransmission is holding. The four state enums carry RFC 6026's
  `Accepted` on both INVITE machines.
- The INVITE client transaction (RFC 3261 §17.1.1, RFC 6026 §7.2), and the ACK
  a client transaction builds for a final response that is not a 2xx. A 2xx
  does not end the transaction: the machine moves to `Accepted` and stays there
  for timer M, so a retransmitted 2xx or one from another fork is passed up
  rather than dropped as a stray. A provisional response stops both timer A and
  timer B, because how long to wait for a ringing phone is the user's decision.
  A retransmitted final response re-sends the ACK and is not reported twice.
  On UDP the request goes out seven times in 64·T1, which is what the RFC says
  that number is for.
- The non-INVITE client transaction (RFC 3261 §17.1.2), which is what REGISTER,
  OPTIONS, BYE and MESSAGE run on. Retransmissions cap at T2 rather than
  doubling forever, and a provisional response does not stop them — it moves
  the machine to `Proceeding`, where the interval is T2 flat and timer F still
  ends the transaction. Only an INVITE gets to ring indefinitely.
- The two server transactions (RFC 3261 §17.2, RFC 6026 §8.1). The INVITE one
  sends a 100 Trying at once — the transaction layer never knows whether the
  user will answer within 200 ms, and a redundant 100 costs one datagram while
  a missing one costs six retransmitted INVITEs. A 2xx puts it in `Accepted`,
  where retransmitted INVITEs are absorbed rather than answered again and an
  arriving ACK is passed up rather than swallowed, because after a 2xx the ACK
  belongs to the dialog. A non-2xx final response is retransmitted by timer G,
  but only on an unreliable transport. The non-INVITE one sends nothing until
  the user says so: in `Trying` a retransmitted request is discarded, since
  inventing a response the user never wrote is worse than silence.
- Message matching (RFC 3261 §17.1.3 and §17.2.3). A response finds its client
  transaction by branch and `CSeq` method — the method matters because a CANCEL
  borrows the branch of the request it cancels while being a transaction of its
  own. A request finds its server transaction by branch, the `Via`'s sent-by
  and the method, with an ACK keyed as the INVITE it answers. A peer without
  the magic cookie is matched the pre-3261 way instead, on the Request-URI,
  From tag, `Call-ID`, `CSeq` number and top `Via`.
- CANCEL (RFC 3261 §9.1): built to look exactly like the INVITE it cancels so
  the two can be paired, with `Route` copied for stateless proxies and
  `Require`/`Proxy-Require` deliberately dropped. Asking to cancel is always
  accepted while the transaction is open: a CANCEL may not be sent before a
  provisional response has arrived — the server could otherwise receive it
  before the INVITE and have nothing to cancel — so one asked for too early is
  held and released at the first provisional rather than refused.
- Dialogs (RFC 3261 §12): route set, remote target, the two sequence spaces,
  the `secure` flag and both ways of opening one — from the response to a
  request we sent, and from a request we are answering. The route set is
  reversed for the caller and kept in order for the callee, because the two
  ends face opposite ways down the same path, and it is built from the bytes as
  they arrived so that every URI parameter survives. Requests come out through
  §12.2.1.1, including the strict-router rewrite for proxies that predate loose
  routing: the request is addressed to the first hop and the real target is
  pushed to the end of the `Route`, where a loose router lifts it back. ACK and
  CANCEL are refused there — their number belongs to the request they answer.
  The remote target moves only for a re-INVITE or an UPDATE (RFC 3311 §5.1),
  never for an ACK; a request whose `CSeq` runs backwards is answered 500 and
  changes nothing.
- Digest authentication (RFC 3261 §22, RFC 8760): MD5, MD5-sess, SHA-256,
  SHA-256-sess, SHA-512-256 and SHA-512-256-sess, with `qop=auth` and the
  counter that makes a captured response useless a second time. The three hash
  functions are written out here, because the crate has no dependencies, and
  each is checked against published digests — including the SHA-256 of the
  empty string that RFC 8760 §2.6 prints — before anything is built on it.
  `AuthCache` keeps a challenge per protection domain so a later request can
  carry credentials without a round trip, answers the topmost challenge it
  understands per realm, keeps the 401 and 407 spaces apart, and refuses to
  answer the same nonce twice after a refusal: §22.1 forbids re-attempting
  credentials that were just rejected, and repeating them only locks the
  account. A `-sess` algorithm without `qop` is treated as unanswerable rather
  than guessed at, which is what §22.4 rule 8 leaves. The password lives in a
  `Secret` with no `Debug` and no way out of its module, overwritten on drop as
  far as safe Rust can promise.
- SDP (RFC 4566) and offer/answer (RFC 3264). A description that is read and
  written back comes out as it went in, down to the lines the stack has no use
  for — an SDP body travels through a call inside messages that get forwarded,
  so quietly dropping what is not understood breaks the next extension somebody
  adds. Ordering is enforced the way §5 fixes it, and a type letter that is not
  one of the fourteen refuses the whole description rather than the line, which
  is what §5 asks for. `answer()` builds the answer from the offer: the same
  number of streams in the same order, the same `t=` line, the payload mappings
  the offer defined, and a direction narrowed to what the offer allows — an
  offer of `sendonly` can only be answered `recvonly` or `inactive`. Which
  codecs to keep and which streams to take arrive as arguments; there is no
  policy here. The RFC 3264 §10.1 exchange is a test, byte for byte, and a
  fourth fuzz target asserts that writing a description out and reading it back
  yields the same description.
- Forking and the ACK for a 2xx (RFC 3261 §13.2.2). One INVITE can produce
  several dialogs — a proxy rings the desk phone, the mobile and the voicemail,
  and each branch that answers is told apart by its `To` tag. `DialogSet` keeps
  them all and chooses between none of them: which fork to keep is policy, and
  policy does not live in the core. A non-2xx final ends every dialog still
  early and leaves an already confirmed one alone; a 2xx arriving after that is
  still taken, because dropping it would leave a call standing at the far end
  with nobody able to hang it up. The 2xx confirming an early dialog recomputes
  its route set, which RFC 2543 compatibility requires and which nothing else
  in a dialog's life does. The ACK for a 2xx belongs to the dialog rather than
  the transaction: the caller builds it once, since only the caller knows
  whether there is an answer to put in it, and every retransmitted 2xx after
  that is answered from the stored bytes.
- `sipral-core::endpoint`: what a transport is to a stack that never opens one.
  `TransportProtocol` derives from the protocol alone everything the RFCs make
  conditional on the transport — reliability, which is what RFC 3261 §17 sets
  timers D, I, J and K to zero on; framing, which is why TCP and TLS need
  `Content-Length` and WebSocket does not, since RFC 7118 §4.2 puts one SIP
  message in each WebSocket message; and the default ports of §18.1.1.
  `Input` and `Transmit` are the two directions of the whole surface, with the
  payload refcounted because a retransmission has to be the identical datagram.
  `DatagramLimit` is §18.1.1's size rule as two numbers, both settable because
  the RFC's 1300 assumes a 1500-byte Ethernet MTU that plenty of access
  networks do not have.
- `sipral-core::endpoint::Endpoint`: the five calls the whole stack is driven
  through, and the first place the layers are bound together. Bytes and time
  in, bytes and events out; nothing opens a socket, reads a clock or draws a
  random number. The branch, the sent-by, the tags, the `Call-ID` and the
  sequence numbers are the endpoint's, derived from thirty-two bytes of
  caller-supplied entropy, because a caller that writes its own branch writes
  one that repeats. Registrations, calls, forking, CANCEL racing a 200, the
  ACK for a 2xx and its retransmissions, incoming calls and the dialogs they
  open, BYE in both directions, the §18.1.1 switch to a stream transport, the
  §18.2.2 and RFC 3581 rules for where a response goes, the §18.1.2 check that
  discards a response addressed to somebody else, and RFC 5626 keep-alives on
  a jittered interval. Two things happen without asking, because the RFC
  leaves no choice: a CANCEL that matches gets its 200 and its INVITE gets a
  487 (§9.2), and an in-dialog request whose `CSeq` runs backwards gets a 500
  (§12.2.2). Everything else is reported and left to the layer above.
  36 tests, each a scripted exchange on a fake clock.
- Reliable provisional responses (RFC 3262), both ways round. A 180 is a
  datagram like any other and can be lost, which matters because an offer or an
  answer can travel in a 1xx and offer/answer has no recovery from a lost
  message — and because a carrier that puts `100rel` in `Require` will not
  complete a call without one. The end that sends one numbers it, retransmits
  it doubling from T1 with no cap, and refuses to send a second until the first
  is acknowledged; 64·T1 without a PRACK refuses the call with a 500, which is
  what §3 asks for. The end that receives one keeps the highest number it has
  seen in order and silently drops a retransmission or a gap, so a PRACK is
  never sent twice for one response. A PRACK that matches nothing is answered
  481 without being handed up, and one that matches stops the retransmissions
  before the caller sees it. `Supported: 100rel` goes on every outgoing INVITE,
  merged with whatever the caller listed rather than written as a second line
  of the same field. The received numbering is kept per dialog rather than per
  request, because a forked INVITE is answered by several user agents that each
  number from their own transaction; the reasoning is in `docs/03`.
- Answering a challenge (RFC 3261 §22, RFC 8760). A registrar refuses the first
  REGISTER it ever sees and a proxy refuses the first INVITE; that is the
  handshake, not a failure. The endpoint reads the challenge, reports it, and
  waits — the password is the one thing this layer must not hold, and answering
  with the wrong one is how an account gets locked. `retry_with_credentials`
  sends the original request again header for header, body included, with a new
  branch, the next `CSeq` (§22.2, taken from the dialog when it had one so the
  numbering does not collide), and the credentials. The nonce count moves by one
  and never skips, since a skipped number reads to a server as a replay; the
  same nonce coming back without `stale` is a refusal rather than a fresh
  challenge, because §22.1 does not re-try credentials that were just rejected;
  and a challenge nothing here understands is ignored rather than reported, per
  RFC 8760 §2.4. A challenge outlives the transaction that earned it, and the
  set of them is capped so a peer that refuses everything cannot grow it.
- Where a dialog's requests go (RFC 3261 §8.1.2, §12.2.1.1, RFC 3263). A dialog
  keeps the flow its first message travelled on — the address the INVITE went
  to and the answer came back from — which §8.1.2 explicitly allows as "an
  alternate address" and which is the only thing that survives the NAT nearly
  every softphone sits behind. When the next hop the route set or the target
  names is not that address, the endpoint says so rather than resolving it:
  `Event::ResolveNeeded` carries the host, the port if the URI gave one, and
  the transport if the URI or the scheme named one, and `resolved` retargets
  the dialog. Ignoring it is a legitimate choice and the common one. There is
  no `ResolveId`: the only thing the core ever needs resolved is a dialog's next
  hop, so the dialog is both the question and the handle.
- `Uri`, a URI that outlives the buffer it arrived in: the text held once in an
  `Arc<str>` with the parts as offsets into it, so borrowing the parsed form
  back is free and a clone shares the bytes. It carries RFC 3261 §19.1.4
  comparison as `equivalent()` rather than `PartialEq`, because §19.1.4
  equivalence is not transitive and the RFC says so itself. `Tag` and `CallId`
  compare the way the RFC compares them, which is not the same way: byte for
  byte for a `Call-ID` (§20.8), without case for a tag, which is a token
  (§7.3.1).
- `TimerConfig` and the timer schedule: T1, T2 and T4 from RFC 3261 Table 4,
  with every other timer derived from them, and a schedule that answers "when
  do I have to come back" through a shared reference. Nothing reads a clock —
  the caller says what time it is — so a timer diagram from §17 is an ordinary
  test that runs in microseconds. The absorbing timers are zero on a reliable
  transport, because nothing retransmits there.
- Fuzzing under `fuzz/`: three libFuzzer targets over the parser and every
  typed accessor, the stream framer fed at arbitrary read sizes, and the
  builder fed arbitrary bytes as header values to prove a caller's data cannot
  become structure. Outside the workspace with its own lockfile and nightly
  pin, and covered by `cargo deny` too.
- The RFC 4475 corpus is now a test, and it passes: all 49 messages behave as
  `fixtures/rfc4475/manifest.toml` says, and every valid one round trips byte
  for byte. Three messages moved from `semantic` to `reject` — `insuf`,
  `multi01` and `mcl01` sit in the application group but their RFC sections ask
  for a 400 outright — so the split is 13 parse, 22 reject, 14 semantic.
- `StatusCode::reason`: the reason phrases RFC 3261 §21 registers, plus 422
  from RFC 4028, so nobody has to invent one.
- `RawMessage::transaction_lookup_method`: the key §17 matches on. An ACK
  answers INVITE, since the INVITE server transaction absorbs the ACK to a
  non-2xx and an ACK to a 2xx finds nothing under that key and belongs to the
  dialog; a response answers with its `CSeq` method, having none of its own.
- `crates/sipral`: the facade crate, for now a name reserved for crates.io
  that exports a version constant. The only crate with `publish = true`.
- `bindings/dotnet/Sipral`: the .NET package, for now a name reservation
  published to NuGet as `Sipral` 0.0.1.
- `docs/12-core-api.md`: the public surface of `sipral-core` as signatures,
  with register, call, CANCEL-race and fork walkthroughs, a fake-clock test,
  the C projection, and a record of what was rejected and why. Adds the RFC
  6026 `Accepted` state to both INVITE machines, which every draft of the
  surface had missed on the client side.
- RFC 4475 torture corpus under `fixtures/rfc4475/`: the 49 messages decoded
  byte for byte from the archive in Appendix A, laid out by RFC section, with
  a manifest carrying section, title, expected outcome and SHA-256 per file.
  `scripts/check.sh` verifies the hashes so line-ending normalisation cannot
  silently alter a test.
- `SECURITY.md`, pointing at GitHub private vulnerability reporting, and an
  issue template for commercial licence enquiries. No email address appears
  anywhere in the repository, by design: `scripts/check.sh` fails on one, in a
  file or in commit metadata.

### Changed

- **The commercial licence is linked where its terms are published.** The Maven POM and the NuGet description point to <https://sipral.org/terms/>, `LICENSING.md` links the terms and the contact page, and `LICENSE-COMMERCIAL.md` states that outside code is taken only under a contributor licence agreement.
- **A call past `max_dialogs` is answered 503 with `Retry-After: 2`.** RFC 3261 §21.5.4 has a client that gets a 503 with no `Retry-After` act as if it got a 500, which said broken where the stack is full, and room comes back the moment any call ends; two seconds is the time between call endings at the default ceiling, rounded up, so a proxy that honours it sends callers elsewhere only briefly. The 503 for want of server transactions, the ceiling a flood meets, still carries none.
- **`docs/23-compared-with-pjsip.md` read again on 2 October.** The authenticated INVITE with ICE and every default codec is 1236 bytes and goes over UDP whole, where the 29 September run had 1333 bytes and a stream asked for; the move to another address is also read from the cut, 220 to 240 ms until the agent's audio is heard again against pjsua's 360 to 400 ms when told; and the agent met the stack's 128-call ceiling with two hundred offered.
- **The C ABI is 1.0, and older applications keep working through 1.x.** ABI 1.0 is 0.36's surface under the first frozen major: nothing added, removed or reshaped, every pin and offset where 0.36 had it. `sipral_abi_check` takes a binding built against any minor of the library's major up to the library's own, so a binding built against 1.k loads against a library at 1.m for every m ≥ k; a later minor, another major and every 0.x binding are refused at load with both versions named. The header and every binding are printed at 1.0, and each binding's tests hold the rule: the minor it was printed at and every earlier one served, a later minor, the next major and 0.36 refused (`docs/08-ffi.md`, "ABI 1.0").
- **The documentation describes the release.** The README's status is 1.0.0 at ABI 1.0 and what that promises, every line of it held to what the tree does; `docs/08-ffi.md` says the library's version and the ABI's are two numbers, and that within a major a binding loads against the minor it was printed at and every later one; `docs/10-roadmap.md` says where 1.0 falls and what it does not wait for; `docs/12-core-api.md` no longer promises compatibility for `sipral-ua`, and lists what ABI 0.36 added in Rust; `docs/19-numbers.md` has the release's own measurements, and the per-frame cost the in-band digit detector adds on a call that negotiated no telephone event.
- **The Maven group id is `org.sipral`**, one property in `bindings/jvm/pom.xml` that the AAR's POM reads as well, where it was a placeholder.
- **`scripts/package/crate.sh` refuses, and says why**: the Rust crates are not part of the release, and the `sipral` name on crates.io stays the 0.0.1 reservation. `--crates-io` runs the checks a publication there would need.
- **The README is one page on what Sipral is and what sets it apart**, with a call placed from Python (run against a loopback server before it went in), the platforms, languages and audio modes in one table, the status and the planned work marked as planned. The design documents are brought up to ABI 0.34: the freeze section no longer calls minor 33 the last one, `docs/09-rfc-index.md` gains RFC 3263's location procedure, PUBLISH beyond quality reports, the conference package and focus, SIPREC, multipart bodies, STIR/SHAKEN, RFC 5922, RTCP feedback and real-time text; `docs/01-architecture.md` places `sipral-audio`, `sipral-stir` and `sipral-diag`; `docs/06-nat.md` says which address this end advertises; `docs/10-roadmap.md` records device mode, the freeze and ICE restarts from C as done; the testing and security documents count thirty-four fuzz targets; and `docs/08-ffi.md` no longer says macOS cannot choose its microphone. This changelog's Unreleased section is one list per kind.
- **ABI 0.33, the surface 1.0 freezes (`docs/08-ffi.md`, "The freeze").** Every pin is the member the struct's 0.33 version ends with, derived per target, so a 32-bit build no longer refuses 27 structs at the size its own header gives them; no struct ends in padding on any of the three layouts (fourteen gained a `reserved` member, `dtmf_detection` moved), checked by the `record!` macro on every target, by `tools/abi-gen`, and by `bindings/c/abi-layout.c` compiled for six targets, with every binding's size test holding its own layout to the same table, and the gate holding every member's offset on every layout to the last commit's, so a member slipped into a hole between two others is refused like one in tail padding. Renamed: `SIPRAL_STATUS_NOT_A_FOCUS`, `sipral_media_{attach,detach,reset}_processor`, `sipral_stack_transport_failed_with`, `sipral_stack_state_text`; `sipral_call_identity_text` takes `index` before `which`. Text out is one convention (`out_needed`, nullable, NUL written and counted, `sipral_audio_device_at` included), `SIPRAL_STATUS_CLOCK_BEHIND` (24) is its own status, an empty optional address or `sdp` is absent (and a member `sipral_call_ring_media` or `sipral_call_accept_transfer` does not read counts as set by its length alone), a packet longer than its buffer is refused, a media handle from inside any frame and a stack destroyed from the transmit callback are `BUSY`, and a poll no longer waits for the audio engine. Every parameter and member that holds an enumeration's number is declared with its `typedef` (`sipral_call_state_t *out_state`, not `uint32_t *`), and the header names no Rust module, macro or type. The .NET, Python and Dart layers no longer end every error message in a NUL; the generated .NET layer passes every callback as a function pointer and finds an unpackaged library even when its own class is the first thing used, the Swift one takes a null listener and keeps the number of a status it has no name for rather than calling it `.panic`, and Kotlin reaches `sipral_media_mix`.
- **A service provider code in a STIR certificate covers no number unless the application says so.** `sipral_stir::Config::accept_service_provider_codes` is off by default, and `StirConfig::accept_service_provider_codes(true)` turns it on for an agent: a certificate whose TNAuthList names only a code (RFC 8226 §9) vouched for every number there is.
- **A call that cannot meet a required SRTP policy is refused by the stack.**
  An INVITE whose offer a `Required`, `DtlsRequired` or `DtlsOrSdes` call
  will not carry audio on is answered 488 by `MediaEngine::answer` and
  `ring`, which still return `MediaError::SrtpRequired`
  (`SIPRAL_STATUS_SECURITY_POLICY` in C), instead of being left ringing for
  the application to refuse; a call this end placed and the far end answered
  in the clear is hung up with `Reason: SIP;cause=488`.
  `SIPRAL_MEDIA_FAULT_SECURITY_POLICY` (10) names the media failure.

- **A call recording's WAVE header is the 80-octet one of `sipral_media::formats::wav`**, with a `JUNK` chunk held for RF64: the data length is at offset 76, not 40. `MediaError::CodecChanged` and `MediaError::NoDtmf` are gone, since a codec change no longer ends a recording and a call with no telephone event takes its digits in the audio; `Codec` prints and is named in a codec order by `Codec::name`, which is the encoding name for every codec but L16's two.
- **On Android from API level 28 a client opens in device mode by default.** `SIPRAL_FEATURE_AUDIO_DEVICE` is now set there, so `SipralAudioMode.platformDefault` is `Device` with automatic activation and the engine, not the application, opens the microphone and the loudspeaker as a call's media starts; an application that reads `SipralMedia.frames` and runs its own audio opens its client with `SipralAudioMode.Application`, and one under the telecom framework with `Device(SipralAudioActivation.MANUAL)`, as the sample does.
- **`max_dialogs` holds the calls this end places too.** A call counts
  from its INVITE on, and one placed at the ceiling is
  `SendError::LimitReached` before anything goes out; a refusal or timer B
  gives the room back at once. A dialler that places more than 128 calls at
  once raises the limit, as a server that answers them already did.
- **`MediaEngine::poll_event` costs the sessions that have an event, not
  every session.** A session puts its call on the engine's ready list when
  it queues an event, and a poll takes from that list, so a stack holding
  ten thousand calls pays nothing for the ones with nothing to say.
- **A drain of `MediaEngine::poll_rtcp` looks at each session once.** Each
  call picks up after the call the last report came from, where it used to
  start from the first session every time: draining the reports due among
  ten thousand calls cost 8.3 ms of the signalling thread every sweep on
  the lab machine, more than the sweep interval.
- **`AudioRoute` is `org.sipral.telecom.AudioRoute`.** It moved out of the
  Android helper into the JVM library beside `CallAudio`, which reports
  route changes with it; `SipralConnection.routes`, `route` and
  `requestRoute` take the same type under its new name. The Android
  sample's own `AudioPump` is gone, replaced by `SipralCallAudio`.
- **What a pause keeps in hand for the earpiece's pace is bounded at
  100 ms.** Every clock a device runs at needs a frame or two: measured, a
  laptop's loudspeaker ran 3 ppm off its machine's crystal, and the widest
  a device may run and meet its bus's specification is USB full speed's
  2500 ppm (USB 2.0 §7.1.11). The budget carries 2500 ppm through a
  twenty-second spurt, and no frame runs dry up to ±10 000 ppm in the
  crate's simulations of `scripts/lab.sh drift`, either callback length.
  Past that the skew is a stream played at the wrong rate, and the buffer
  no longer chases it with delay — 340 ms at 500 000 ppm, past what ITU-T
  G.114 finds acceptable for conversation — but keeps the budget, runs dry
  for the rest and counts every frame (`Quality::underruns`,
  `frames_underrun`), so the loss rate, `is_suffering` and the score say
  so. At 500 000 ppm in the lab the fast earpiece now holds 80 ms at most and
  is scored 0 and suffering at every report (`docs/05-media.md`,
  `docs/19-numbers.md`).
- **`scripts/lab.sh drift` proves a two-frame earpiece, and judges a skew
  no device runs at on what the product does with it.** The flow places
  six calls: slow, true and fast, each taking one frame and two at a
  callback, as a 40 ms device period on 20 ms packets does. Up to 5000 ppm
  it fails, as before, on any cut in the tone and on a buffer past 250 ms;
  past it on a buffer deeper than its own ring, on one deeper than 250 ms
  that the stack still scores at half or more, and on a call that ran dry
  on a twentieth of its frames that the stack never called suffering.
  Every run now fails where the frames the earpiece played as silence and
  the stack's own under-run count differ by more than a run in progress.
  The step runs on the Compose project's own network, so a copy of the lab
  under a `COMPOSE_PROJECT_NAME` of its own runs it against its own
  Asterisk.
- **ABI 0.28.** `sipral_stack_config_t` grew `registrar_keepalive` and
  `registrar_keepalive_ms` at the tail, and `sipral_stack_settings_t`
  `registrar_keepalive_ms`; `sipral_call_accept_session` refuses a null
  `sdp`. A binding built against 0.27 is refused by this library, and the
  Kotlin agent's jar has to be rebuilt.
- **`UserAgent::accept_reoffer` takes the answer, not an `Option` of one.**
  Every `UaEvent::Reoffer` carries an offer — a re-INVITE without one is
  answered with this end's own offer before anything is handed up — and
  RFC 3264 §5 has an offer answered, so `None` sent a 2xx with no body that
  answered nothing. The signature is now `sdp: &[u8]`, and the C ABI's
  `sipral_call_accept_session` refuses a null or empty `sdp` with
  `SIPRAL_STATUS_INVALID_ARGUMENT`, the request still waiting to be answered
  or refused.
- **A re-INVITE or UPDATE whose only body is of a type the agent does not
  read, marked `handling=optional`, no longer reaches the application.** It
  used to arrive as a `UaEvent::Reoffer` carrying no offer; RFC 3204 §6,
  which defines the parameter RFC 3261 §20.11 points to, has "the UAS MUST
  ignore the message body" when it is optional, so the request is answered
  as the one it would be without it: a re-INVITE with this end's own offer
  (§14.1), an UPDATE as a target refresh. A body without that marking is
  refused 415, as above.
- **ABI 0.29.** `sipral_stack_config_t` grew `turn_transport` and
  `sipral_media_packet_t` grew `protocol`, both at the tail with `MIN_SIZE`
  unmoved, after `registrar_keepalive_ms`; event kind 42, status 12 and
  feature bit 1024 are spent, and a binding built against 0.28 is refused
  (the Kotlin agent's jar is rebuilt). The same minor carries the built-in
  audio engine and the caller-identity and moving-call surface: after
  `turn_transport`, `sipral_stack_config_t` grew the `audio*` members;
  `sipral_account_config_t` grew `session_timer`,
  `session_interval_seconds`, `privacy` and `trusted_peers`, and
  `sipral_call_event_t` the identity, cause and answer-mode members, all at
  their tails; event kinds 43 (audio devices changed) and 45 (call address
  wanted), statuses 13 to 15 and feature bits 2048, 4096 and 8192 are spent,
  and 44 is held and spent unused. In Rust, `sipral_nat::ice::Transmit`,
  `Route` and `TurnServer`, `sipral::Datagram`, `RelayDatagram` and
  `MixOutcome` each grew a field saying what a message goes over, and
  `TurnError` a variant; a caller that builds one by its fields names the
  new one.
- **The `sipral` crate's own description of its bindings names all four.**
  `crates/sipral/README.md`, its `Cargo.toml` description and
  `bindings/dotnet/Sipral/README.md` said "Swift, .NET and Kotlin bindings,"
  leaving out Python though the crate has had one as long as the other three.
  No behaviour changed.
- **ABI 0.27.** `sipral_stack_config_t` and `sipral_stack_settings_t` grew
  `referrals` at the tail, `SIPRAL_EVENT_KIND_REFERRAL` (41) and
  `sipral_referral_event_t` are new, `SIPRAL_ICE_LITE` is 4, and
  `sipral_call_reject_transfer` refuses a code under 300. A binding built
  against 0.26 is refused by this library, and the Kotlin agent's jar has to
  be rebuilt.
- **Every Swift event stream now reaches every reader.**
  `SipralStack.events`, `Call.events`, `Call.dtmf` and `Media.frames` were
  each one `AsyncStream`, which hands every item to one reader only: a call
  bound to `CallKitBridge`, which reads the call's events itself, lost
  events to the application's own loop over the same call, and the other
  way round. They are now methods — `events()`, `dtmf()`,
  `frames(bufferingNewest:)` — and every call returns a stream of its own
  that gets every item from then on, in order. Nothing raised before a
  stream is taken reaches it, except a call's `CALL_ENDED`: a call's
  streams finish right after it, and one taken later gets that event and
  finishes at once, so a call that ended before `CallKitBridge.bind` is
  still reported ended. A media's streams finish when it ends, a stack's
  when it closes. A reader that falls behind drops its own oldest items —
  past 4096 events or digits, past 50 frames unless it asks for another
  number — and never slows the others. `CallKitBridge` also covers the one
  case where a call's stream finishes without ever handing over
  `CALL_ENDED` — the application hanging up and closing a bound call
  without reading its own `events()` first — by still reporting the call
  ended and forgetting it.
- **The packaged artefacts leave libopus out unless asked for it.** The
  XCFramework, wheel, NuGet and AAR scripts build the C ABI without the
  `opus` feature by default, with every other default feature kept;
  `--with-opus` builds the variant that carries it, under a name that says
  so (`CSipral-opus.xcframework.zip`, `sipral-opus`, `Sipral.Opus`,
  `sipral-opus.aar`). The gate checks the packaged XCFramework for libopus
  symbols.
- **`CallMedia` is no longer `Clone` or `PartialEq`.** It can carry a relay
  on a TURN server, which is an allocation one call holds, not a value two
  calls can share or be compared by; build one per call with
  `CallMedia::new`.
- **One header field's value may be 16 KiB, up from 4 KiB.**
  `msg::Limits::DEFAULT.max_header_value_bytes` was tight for real traffic:
  a full RFC 8224 `Identity` with rich call data, a long `History-Info`, or a
  caller's display name of a few kilobytes all refused the request that
  carried them. The message bound (64 KiB) and the header count (128) are
  unchanged, and a value is a span into the message, so the new bound costs
  no memory of its own. `StreamFramer::next_message` now returns `Framed`,
  which is either the message or the head of one it refused and passed over.
- **The licence documents say what they mean.** `LICENSE-COMMERCIAL.md` is
  now plainly a description that grants nothing on its own, with the licensor
  named by the signed agreement rather than by `AUTHORS`. It gains the rights a
  licensee's customers, stores and contractors need, a patent clause that
  grants nothing and names the Opus pool, a first year of maintenance inside
  the one-time fee, a liability cap that does not fall to zero and keeps what
  the law does not allow to be limited, and a termination clause that protects
  copies already delivered. `LICENSING.md` describes the AGPL arm as the AGPL
  actually reads and explains `LicenseRef-Sipral-Commercial`; `TRADEMARK.md`
  attaches the AGPL section 7 additional terms; `AUTHORS` promises a
  contributor licence rather than an assignment; the Opus pool facts in
  `THIRD-PARTY-NOTICES.md` are corrected; `SECURITY.md` lists the one advisory
  a scanner will report and why it does not apply.
- **Every re-offer hands the DTLS roles back, and a far end that moves them
  is refused by name.** RFC 8842 §5.5 asks each subsequent offer for
  `a=setup:actpass`; the hold, the resume and the codec change now write it
  whichever role the call has, where a call this end had answered used to
  carry the role it answered with. Each re-offer this end answers takes the
  role the running association gives it (§5.3) — to `actpass`, a fresh answer
  said `active` every time, which from a DTLS server is asking to become the
  client. A far end that takes the other role anyway is asking for a new
  association, which this stack does not start: its answer is not adopted and
  is reported as the new `MediaError::DtlsRoleChanged`, and a re-offer that
  leaves this end only the other role is answered 488 under the same name. A
  re-offer naming another certificate is answered 488 too, as
  `MediaError::DtlsFingerprintChanged`, where it used to be accepted and then
  not followed.

- **Every re-offer on a secured call is answered by the facade.** `sipral-ua`
  hands them up, holds and refreshes included, because their answers need a
  key, or a certificate and a role, that only the layer holding them can
  write; see Fixed. An application that describes its own secured calls now
  hears the far end's hold as `SIPRAL_EVENT_KIND_SESSION_OFFERED`, as it hears
  a codec change. An SDES answer repeats the key this end already sends under
  rather than drawing one, which RFC 4568 §7.1.4 warns leaves the far end
  unable to read this end until the answer arrives.

- **The ABI is at 0.26.** Each minor since 0.20 is noted with the entry that
  caused it.
- **ABI 0.20.** It covers two changes to the printed header: ICE's own
  (`SipralIce`, `SIPRAL_FEATURE_ICE`, event 33, the `ice` member on both
  config structs, and `now_ms` on `sipral_media_capture`), which went out
  without the minor moving, and `sipral_call_change_codecs`. The gate now
  refuses the first kind.
- **ABI 0.21.** `sipral_call_join`, `sipral_call_leave` and
  `sipral_media_mix`, for a two-call conference held on this stack, and
  what had landed since 0.20 without the minor moving: `sipral_account_message`
  and events 34 to 37 (MESSAGE received and sent, message waiting, and the
  quality report sent).
- **ABI 0.22.** `SIPRAL_EVENT_KIND_MEDIA_UNJOINED` (38), the survivor notice
  a joined call's partner gets when the call it was joined to ends.
- **ABI 0.23.** STUN from the stack (`sipral_stack_nat_map`,
  `sipral_stack_poll_stun`, `sipral_stack_receive_stun`, the `nat` and
  `stun_server` fields of `sipral_stack_config_t`, `SIPRAL_FEATURE_STUN` and
  event 39, `SIPRAL_EVENT_KIND_NAT_MAPPING`) and the audio processor
  attached from C (`sipral_call_attach_processor` and its detach and reset,
  `sipral_processor_frame_t`, `sipral_processor_callback_t`).
- **ABI 0.24.** `SIPRAL_CODEC_G729`.
- **ABI 0.25.** TURN in the stack configuration (`turn_server`,
  `turn_username`, `turn_password`), its relay event and records
  (`SIPRAL_EVENT_KIND_NAT_RELAY`, event 40), and the G.729 Annex B toggle
  (`g729_annex_b` on `sipral_stack_config_t` and `sipral_stack_settings_t`).
- **ABI 0.26.** `sipral_stack_nat_unmap`.

- **`sipral_media_capture` takes `now_ms`**, in the position its three
  siblings put it and read exactly as they read theirs. ICE has to be told
  that traffic went out on the pair it chose — RFC 8445 §11 is what lets it
  stop sending keepalives — and the capture path was the one producer with no
  clock at all. `MediaSession::capture` and `MediaSession::poll_transmit` take
  one for the same reason. The ABI's major is 0 and `docs/08-ffi.md` says in
  plain words that it is not frozen; this is the kind of change that is free
  now and impossible later.

- **An answer the user agent writes itself no longer withdraws ICE from a call
  that had it.** `sipral-ua` answers a hold, a resume and a peer moving its
  address without handing the description up, and it carried forward
  `rtcp-mux`, `ptime` and `maxptime` and nothing else. RFC 8839 §4.4 wants the
  username fragment, the password and the candidates on every description of a
  session, so an answer without them reads as ICE being withdrawn mid-call —
  which takes a checked path away from a call that had one, silently, from a
  layer that has never read a candidate. Exactly the failure the function's own
  documentation already described for multiplexing.

- **`sipral_nat::ice::Received::Data` and `sipral_nat::turn::Input::Data` now
  answer with a position rather than a borrow**, and both types have lost
  their lifetime parameter. A borrow holds the caller's datagram shared for as
  long as it holds the answer, and what a caller does next with a relayed
  packet is unprotect it in place — so the type that said "here it is" was the
  type that stopped it. The position comes from the layers that already knew
  it: `stun::Attribute::range` and `turn::ChannelData::range` are new and
  public for it.

- **A peer's `a=ice-pacing` no longer outlives the session it was proposed
  for.** RFC 8445 §14.2 makes Ta the larger of the two agents' values, and a
  restart is a new session; `IceAgent::restart` now goes back to this agent's
  own proposal. Carried forward, one peer asking for the ten seconds RFC 8839
  §5.5 allows slowed every check, every gathering transaction and every
  retransmission of that agent for the rest of its life — including across the
  restart a network change causes, which is when pacing matters most.

- **An ICE checklist with nothing left to check is now waited on, then
  failed** (RFC 8863), where before it stayed `Running` for the life of the
  call. Two situations reach it and neither is rare: a peer whose candidates
  were all unusable leaves a checklist with no pairs at all, and a checklist
  whose pairs have all failed is the same thing one round trip later. Both
  used to leave `IceAgent::deadline()` answering `None`, so a caller that
  slept until the agent next had something to do slept for ever, on a call
  that was never going to carry a packet. The wait is `IceConfig::patience`,
  one whole STUN transaction by default, and it is a window rather than a
  delay: a check arriving inside it still forms a peer-reflexive pair and
  connects the call.

- **`SipralClient.events`, `SipralCall.events` and `digits` document what
  their buffer actually guarantees.** A stale comment in `IdiomaticCheck.kt`
  called them "unbounded Kotlin channels"; they are a `SharedFlow` with
  `extraBufferCapacity = 4096` and `onBufferOverflow = DROP_OLDEST`, which
  is bounded, not unbounded, and does not mean a slow collector sees
  everything -- past 4096 events of lag, its oldest unread ones are
  silently dropped to make room, with no exception and no signal. The KDoc
  on both flows and `bindings/kotlin/README.md` now say so directly, found
  while reproducing the ordering bug above and checking, as its own review
  asked, whether a live collector under a burst load could still lose
  events: a slow one can, once it falls behind by more than the buffer
  holds. No behaviour changed.

- **A zeroed field no longer means "send the digits in the media".**
  `SIPRAL_DTMF_RTP` was zero, which is what a caller who filled nothing in
  leaves behind, and the way a digit travels is the one setting here a peer can
  ignore in silence: a call that meant INFO and sent nothing at all looks, from
  this end, exactly like one that sent it. The three forms are 1, 2 and 3 now,
  and zero is refused by name. The ABI minor goes to 10.

- **A compound RTCP report is held to a bound of its own on the way in.**
  `sipral_media_receive` refused anything over `SIPRAL_MEDIA_PACKET_BYTES`,
  which is the bound this stack builds against — but what arrives is the
  peer's arithmetic, and RFC 3550's compound report grows with the number of
  sources it describes. A datagram RFC 5761 §4 says is control is now held to
  `SIPRAL_MEDIA_RTCP_BYTES` (8 KB) instead, so a report larger than this end
  would have built is read and judged for what it is rather than refused as a
  caller's mistake. Media is unchanged, and so is sending.

- **The Swift binding checks the ABI before the first call into it, rather
  than asking the application to remember**. C# and Kotlin
  already checked at load; Swift has no load hook, so the generator now
  prints a `static let` whose initialiser runs once, before the first read of
  it returns, on whichever thread gets there first — and every generated
  entry point reads it first. A mismatch is a thrown `SipralError` naming
  both versions, not a printed warning. The three name lookups
  (`statusName`, `codecName`, `eventKindName`) became `throws` with the
  rest, because an entry point that skips the check is a gap rather than a
  convenience. Written in `tools/abi-gen`, not by hand in the binding.

- **The gate reads the artefact for libopus, not only the dependency graph**.
  `cargo tree` says what the build was told to link; it does
  not say what came out. The step that proves a build without the feature
  carries no Opus now rebuilds `sipral-ffi`'s shared library with
  `--no-default-features` and inspects it — `otool -L` for a dynamic
  dependency, and `nm` for the statically linked symbols, which is where they
  actually are, since the Opus crate vendors and builds libopus with hidden
  visibility. The mirror half asserts the default build does carry them, so
  an empty default feature set cannot pass quietly. The inspection is of a
  debug artefact on purpose: the release profile strips local symbols, which
  would make the two builds look identical.

- **`docs/13-client-requirements.md` says which requirements a C caller can
  reach today**. A new section sorts all of them three ways:
  answerable from `sipral.h` alone, built in Rust with no C entry point yet,
  and not built anywhere. It is written against the header and the FFI crate
  rather than against a plan for them, and it is the list 8.4 shortens.
  Two documents were also brought back to the truth: `docs/08-ffi.md` said no
  Swift, Kotlin or .NET toolchain ran in the gate, which stopped being true
  when that step was added, and `docs/04-ua.md` said neither form of DTMF had
  been run against a real server, which stopped being true when the lab ran
  both. Both forms pass against Asterisk; RFC 4733 does not yet pass through
  the lab's proxy to FreeSWITCH, and the document now says so rather than
  reporting a pass on one server's word.

- **The Kotlin step finds its own standard library on a wrapped
  installation**. `kotlinc` from a package manager is often a
  one-line wrapper that execs the real compiler a directory further in, so
  reading the jars off the command landed beside the wrapper and the step
  failed on a machine where Kotlin was installed correctly. Both layouts are
  tried now. With that, and with a Kotlin compiler present, the gate runs
  with no skipped step for the first time.

- **Event kinds 28 and 29 are held for two events the C ABI does not raise
  yet**: the stack recovering from a suspension or a network change, and the
  application being asked to resolve a destination. `sipral.h` lists them
  with the other reserved numbers, so the branches that add them cannot
  collide. 27 was held the same way, for a DTMF digit sent by SIP INFO being
  answered, and the work that brought DTMF by SIP INFO turned it into a kind
  in place.

- **A transfer taken from C places its call the way `sipral_call_place`
  does**. `sipral_call_accept_transfer` used to place an
  offerless INVITE with no SRTP policy and no application headers on it,
  because it had no configuration to read one from; it now takes a
  `sipral_call_config_t`, the same struct and the same versioned reader
  `sipral_call_place` uses, meaning the same thing on every member but
  `target` — the REFER already named where this goes, so a `target` of the
  caller's own is `SIPRAL_STATUS_INVALID_ARGUMENT` naming it, and nothing is
  placed. `media_address` writes the offer from this stack's codecs and runs
  the audio, exactly as it does on a placed call, and `MediaEngine` gained
  `accept_transfer`/`accept_transfer_with` to do it: the new call is managed
  the same way one `place` placed, so its session opens once the 2xx is
  acknowledged and `MEDIA_STARTED` follows. `sdp` carries the application's
  own description and this stack runs no audio for it, as before. Giving
  neither is now refused rather than placing an offerless INVITE — the
  same rule `sipral_call_place` already keeps, and for the same reason: the
  answer would have to travel in the ACK, which this ABI has no way to hand
  back. In `sipral-ua`, `UserAgent::accept_transfer` takes an `OutgoingExtras`
  bundling a destination, a fork policy and header fields — the pieces
  `OutgoingCall` carries beside the target this call has no legitimate value
  for, since the REFER supplies it instead. The REFER supplies `Replaces` and
  `Referred-By` as well, so either among those header fields is refused
  (`SIPRAL_STATUS_INVALID_ARGUMENT` from C) — RFC 3891 §3 has an INVITE with
  more than one `Replaces` refused with a 400 — and every field is checked
  before the REFER is touched, so a refusal leaves the transfer still there to
  take. The signature is not additive:
  nothing outside this tree calls it yet, so it changed outright rather than
  carrying a parameter nobody could ever set.

- **The lab now drives calls through the facade an application links**.
  `sipral-interop` carried its own RTP session, its own codec pair and
  its own DTMF sender — a second media join, written for the lab and used
  nowhere else, which is a phase 1 exit criterion this stack had not met:
  "a phase whose proof runs on a path no customer uses has not exited"
  (`docs/10-roadmap.md`). It now depends on `sipral` and drives every flow
  through `MediaEngine`/`MediaSession` — RTP, codecs, DTMF and SRTP alike —
  and `interop/harness/src/media.rs` is gone; `crate::audio` is what is left,
  a socket and a tone, which is what any application still has to write for
  itself. The five existing flows judge exactly what they judged before, with
  their numbers now read off what `capture`/`receive`/`playback` actually did
  on the wire rather than a hand-rolled `RtpSession`. Three flows join them:
  DTMF as an RFC 4733 named telephone event, confirmed by the lab's own
  dialplan reading a digit however it arrived and naming it straight back
  (`interop/asterisk/extensions.conf`'s 9003, `interop/freeswitch/lab.xml`'s
  9003); SRTP against a new SDES endpoint of Asterisk's own
  (`interop/asterisk/pjsip.conf`'s `labuser-srtp`, extension 9004); and a
  hold whose resume re-offers a narrower codec list than the call held on
  (the case a codec change makes), against Asterisk, by a re-offer the harness
  writes
  itself — `sipral::MediaEngine` has no public way yet to re-offer a live
  call on a catalogue of its own choosing, which `interop/harness/src/main.rs`
  (`reoffer_onto`) says in full. DTMF by SIP INFO is not among them:
  nothing in `sipral-ua` sends one yet, so there is no path through the
  facade to drive rather than a lab limitation to work around. The lessons
  the old media join encoded by hand are now tests of `sipral::MediaSession`
  itself (`crates/sipral/src/tests.rs`): a peer that answers with one G.711
  law and sends the other used to be dropped as an unnegotiated payload
  type, and is now decoded with the law it actually names — `accepted` and
  `fill` in `crates/sipral/src/session.rs` both changed for it, watched red
  before the fix by sending A-law on a call negotiated for mu-law.

- **A call's audio no longer waits on the stack, and the event callback runs
  with nothing held.** `sipral_stack_poll` holds the stack only while it works
  and delivers afterwards, from a queue the stack owns, so the callback may call
  back into the library and events still arrive in order and on one thread at
  a time. Every per-call media entry point takes a media handle from the new
  `sipral_call_media` instead of the stack and the call, is renamed
  `sipral_media_…` to match, and never takes the stack's lock; the handle is
  freed with `sipral_media_release`, answers `SIPRAL_STATUS_WRONG_STATE` once
  its call or stack is gone, and `SIPRAL_STATUS_BUSY` only when a thread
  re-enters its own session — which a processor calling into its call's stack
  is told as well. `sipral_media_poll_rtcp` asks one call rather than
  the stack. Underneath, each `MediaSession` has a lock of its own,
  `Processor` requires `Send`, `MediaEngine::session` hands out a guard,
  `MediaEngine::share` a `SessionShare`, and `MediaEngine::poll_rtcp` returns
  the octets rather than a borrow.

- **The derived constant names in two bindings were nonsense, and are not any
  more.** `SIPRAL_FEATURE_OPUS` — the one symbol an application reads to know
  whether this build has Opus — reached Swift as `fEATUREOPUS` and C# as `FEATUREOPUS`,
  beside `fEATURESUBSCRIPTIONS` and `MEDIAPACKETBYTES` and seventeen others.
  The camel-case derivation looked for an underscore or a capital to start a
  word at, and a name already in capitals has neither, so it lower-cased the
  first letter and left the rest. It now finds word boundaries the way
  `abi::snake` does, which is the rule the library itself answers with, and
  the twenty constants are `featureOpus` in Swift, `FeatureOpus` in C#,
  `FEATURE_OPUS` in Kotlin and `SIPRAL_FEATURE_OPUS` in C. Nothing else in any
  of the four files moved. The ABI is not frozen and nothing depends on the
  old spellings, which is why this is a rename rather than an alias.

- **The roadmap carries what an outside reading of the tree found, and what
  was decided about it.** Phase 1 gains two exit criteria: the lab's flows run
  through the join an application links and then through `sipral.h`, and no
  request leaves as an oversized datagram inside a dialog either. Phase 2
  gains re-negotiation that keeps stream identity and never reuses an SRTP
  index, RTCP-XR with an E-model MOS, SIP MESSAGE and message waiting, a local
  three-way conference, STUN reached from a call, early media on the answering
  side, the REGISTER 200 OK kept, and a written decision on DTLS-SRTP. Phase 3
  now lists what is built in Rust and unreachable from C, and does not freeze
  the ABI before that list is empty and every printed binding compiles in the
  gate; it adds the idiomatic Swift, C# and Kotlin layers, the platform
  artefacts, a Linux device crate over PipeWire and a common device crate.
  Phase 5 starts by joining the headless crate to the engine, and adds Python,
  a sixty-second example with no account, measured numbers, a public
  interoperability matrix and a security model. G.729 joins phase 2, written
  from the Recommendation with the patent position confirmed before it ships;
  ICE in the full role joins phase 4, off by default on a desktop. DTLS-SRTP
  is written in-tree as the last item of phase 2, the state machine from the
  RFC and the primitives from the crate family that already supplies AES.
  Video waits for 1.0 and is phase 6 after it, with its contents named.

- Documents corrected against the tree after an outside reading of the README.
  RFC 3263 is split in the index between what the core owns and what the caller
  does, with RFC 2782 named next to it; RFC 3327 and RFC 8599 added; iLBC and
  AMR given their exclusion rows. `a=ice-lite` is now conditioned on a public
  address, which RFC 8445 Appendix A requires and which separates the headless
  build from the softphone. SDES is stated to need a secured signalling channel
  (RFC 4568 §7). The layer diagram says outright that signalling and media do
  not depend on each other, and `MediaPlan` and `MediaCapabilities` name what
  crosses between them. The README names the codecs, the fuzzing and the parser
  bounds, and no longer refers to a transport crate that does not exist.
- The project's home is `sipral.org`. `Cargo.toml`, both package READMEs and the
  NuGet `PackageProjectUrl` say so; the published NuGet 0.0.1 still carries the
  previous domain and is corrected at the next version.

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

### Fixed

- **Every request on a datagram goes compact under `Compaction::Always`, the ACK of a refusal and a CANCEL included.** Both are written out of an INVITE already sent, the ACK by the INVITE's own transaction (RFC 3261 §17.1.1.3), and went with their fields' long names; the lab's compact call against Asterisk, which challenges the INVITE, counted 11 of its 12 requests compact.
- **A deactivate right after the last call ended waits for its devices.** The engine stops the devices itself, without waiting, when the last call's media ends; `Engine::deactivate` (`sipral_audio_deactivate`) then found nothing running and came back at once while the voice unit was still being let go of, so an application that deactivated its audio session next could find it still running. It now waits for that teardown at most the probe wait, as it does when it stops the pump itself.
- **A call being recorded allocates nothing per frame.** The recorder copied the frame waiting for its opposite direction into a new buffer at every frame; it keeps one buffer for the recording's life, and a test counting the thread's allocations holds a hundred frames of both directions, a direction that skipped a frame and a frame on hold to none.
- **An account that was asked to leave never registers again on a retry.** A de-registration that timed out, lost its transport or was answered 5xx cleared the account's leaving mark and scheduled an ordinary retry, so the next attempt was a REGISTER asking for the binding back. It is retried as a de-registration (`Expires: 0`), and the account stays `Unregistered` while it waits.
- **An account's own connection that could not be opened reaches the application with its reason.** `sipral_stack_transport_failed_with` for the connection a stream account asked for, never bound, was refused as an unknown transport, so no `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` was raised and the TLS reason every layer passes (a pin or certificate refused) was lost; it is raised now, and the account waits on for its connection as before.
- **Dart holds an account's TLS connection to the pin by its leaf.** The pinned connection took the verdict of `onBadCertificate`, which Dart calls with the certificate of the chain that failed, the top one: a server that sent the pinned certificate above a leaf of its own, under its own key, was taken for the pinned server. The callback now lets the handshake through and the leaf the handshake was signed with is checked against the pin before anything is sent.
- **A call the audio engine stops carrying reads silence on its own meter.** A call moved into a local conference kept, in `sipral_audio_call_level`, the last peak it had before it went, frozen there as if it were live.
- **A call's own mute, gain and meter act inside a local conference.** In device mode a call that joined one left its own controls behind: muted with `sipral_audio_call_set_muted`, it was still heard there and its far end still heard this end. The controls now go with it (`LocalConference::filter`, `MemberFilter`, `sipral_audio::CallControls`): the input direction acts on what the conference sends the call, the output direction on what the call says into it, and the meters read both.
- **A move to an address this machine lacks keeps the signalling socket.** Keeping the signalling port across a network change let the old socket go before the new address was known to be one the machine has, so in the Swift, Kotlin, .NET and Python layers a move to a vanished address failed with no socket left and the next move lost the port; the old socket is now let go of only once the new address takes a bind.
- **An account on a connection of its own keeps it when it is pointed at the stack's UDP socket.** `sipral_account_rebind` with `SIPRAL_TRANSPORT_MAIN`, which every layer sends after a network change (and Kotlin, .NET and Swift when a located server is reached at a new route), moved a TCP or TLS account onto UDP, so its next call went in the clear to a server it reached over TLS; such an account now keeps a connection of its protocol to its server, or names none, and asks for one, until one is bound.
- **A new stack's audio device list is complete on its first read**, without a refresh; **SRTP best effort** ends a call whose `a=crypto` lines give no key, and refuses such an offer with 488, rather than running it plain; **a certificate pin** is read in the forms `openssl x509 -fingerprint -sha256` prints, `sha256 Fingerprint=` and `SHA256 Fingerprint=` included; **the ICE password** is taken out of both trace modes, and the diagnostic trace no longer lets a credential past a bare CR or a control byte before a field's colon; **`scripts/check.sh`** keeps every `cargo test` run's output in `target/check-logs/` and names the tests that failed.
- **What the WASAPI loudspeaker has queued is the ring's own count.** The engine's playback stream said it held the depth it asked for less the room left, short by however far the ring rounded that depth up to a power of two; it now reads the ring's fill, as the Core Audio stream does. Also fixed in the layers: a stream or TURN receive that met `CLOCK_BEHIND` in Swift, Kotlin or Python closed the connection as lost framing; the React Native Android core held a call whose end came before it was stored, for the life of the core, and threw after `invalidate()`; and the gate passed `SipralNativesTest`'s staged-pair check with nothing staged, and a Dart run that never said it passed.
- **Ending a call in device mode no longer waits for the voice unit, nor for the main thread.** The last call's media ending stopped the engine inside `sipral_stack_poll` and joined its thread while it took the devices down, so the BYE the hangup queued left only after the teardown; an application that hung up and unregistered on its main thread and then waited there sent neither when the teardown needed that thread. The engine now hands back what the next call needs and lets its devices go on its own thread after the poll returns, every open waits a bounded time for that teardown, and `sipral_audio_deactivate` waits for it at most `audio_probe_ms`. Devices an open had already handed over when the last call ended, before a poll put them to work, are let go of on a thread of their own too, not on the thread that ended the call. What `sipral_account_registration_state` reads between `sipral_account_unregister` and the registrar's answer — `UNREGISTERED`, at once — is pinned by a test and documented.
- **A device that is slow to open no longer holds the poll that starts a call.** Opening a USB headset under the voice unit takes about a second and a half, and it was done inside `sipral_stack_poll` under the stack's lock, so signalling on every other thread waited and the far end's packets reached the call in one burst. The engine starts at once on no device — silence out, the far end's audio drained at its own pace, both counted (`Engine::frames_without_device`) — opens the devices on a thread of its own and puts them under the call from a later poll, which it asks for within twenty milliseconds; a device lost or a default moved is reopened the same way.
- **A recording keeps this end as silence while the call is on hold.** The recorder took the microphone's frame whatever the call's direction, so a call held from either end was recorded with what was said beside the phone; it now writes this end's frames as silence while the stream is not two-way, each in its place on the call's timeline, as it already did for a muted microphone.
- **A jitter buffer no longer keeps a backlog as delay for the rest of the call.** Packets that piled up while nothing pulled — the receive loop held up while device mode opened the devices, or early media nobody was playing yet — were all played, and given back only in the far end's pauses; a far end that never paused, or a detector that never found the pause, kept them: an incoming PCMA call ended 1.56 s behind a 100 ms target. More than 200 ms over the top of its dead band, the buffer now skips to the top of the band on the next pull, in speech or not, and counts the skipped packets in `discarded_overflow`.
- **The macOS device list is the same during a call as outside one.** With a voice-processing unit open, the hardware layer lists the unit's private aggregate device (`VPAUAggregateAudioDevice-…`) and gives every output device an extra input stream, the reference its echo canceller listens for, so a loudspeaker showed six input channels and a headset's output half two, and a list of microphones showed each device twice. `devices()` now leaves out an aggregate whose composition says it is private and does not count the reference stream (`kAudioDevicePropertyReferenceStreamEnabled`) among a device's inputs; an aggregate a person made is still listed.
- **macOS device mode no longer opens a new voice-processing unit for every activation.** Opened after an earlier one had been taken down, a new unit was seen under Guard Malloc to read freed memory on the framework's property-listener thread at the second or a later activation, whatever the order of stop, uninitialise and dispose; the process now keeps the one unit it makes, stopped and uninitialised between streams, and configures it again. A unit whose device was lost, that would not uninitialise, or that `Stream::recover` replaces is still disposed of. `SipralDeviceCheck` takes `SIPRAL_CHECK_RESELECT` to move the microphone to the system default and back in every round.
- **An SDES call whose far end took the second offered crypto line survives the far end's hold, resume or session refresh.** The answer to a far-end re-offer repeated the key of the first line this end had offered (`AEAD_AES_256_GCM`, 44 octets) under the `AES_CM_128_HMAC_SHA1_80` tag the far end had taken, which no end can read, and both ends lost the call's media. The answer now repeats the key of the line agreed, read off the running plan, draws a fresh key of the right width when the re-offer moves to another suite, and refuses the stream rather than write a key whose width does not match its suite (RFC 4568 §5.1.2, §6.1, §7.1.4).
- **macOS device mode no longer loses a third of the microphone, nor starves the loudspeaker, on a device that takes a long slice.** Under the voice-processing unit a narrowband headset at 8 kHz hands a 48 kHz stream 24,576 samples in one callback, and both rings held 16,384: a third of every slice was dropped on the way in, and the loudspeaker, which the engine kept two frames ahead, played silence for most of each one it took (any device asking more than two frames at once did, `BlackHole 2ch` at 48 kHz included). The rings now hold a whole slice of the slowest device at the stream's rate beside two frames, the stream says the most its device has taken at once (`Playback::burst`) and what is queued (`Playback::queued`, rather than a count worked out from a frame depth the ring no longer has), and the engine keeps that slice queued on top of its two frames, rebuilding it a frame a tick so the call is still pulled at the pace the far end sends. On `BlackHole 2ch` at 8, 16, 44.1 and 48 kHz nothing was dropped and only the first callback, before the slice is known, was short.
- **A signalling connection the stack let go of is made again.** Over TCP or TLS, the stack retires the main connection itself when a flow that answered keep-alive pings leaves one unanswered for ten seconds (RFC 5626 §4.4.1), and says so with `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` while the socket is still open in the layer; the Swift, .NET, Kotlin and Python layers kept that socket and never connected again, so every registration on it lapsed. Each now closes it after the poll that said so and connects again with the back-off it uses for a lost connection, registering again every account that was registering.
- **A Swift stack past 960 recordings still reaches its streams.** Connections to recording servers were numbered from 64 and the ones opened for a request too large for a datagram from 1024, so the 961st recording took an id a stream could already hold. Every connection the layer opens now takes its id from one count, past any id a connection still holds.
- **A test that opens this machine's audio devices plays through `BlackHole 2ch` when the machine has it.** The CoreAudio stream tests, the engine's real-device tests, and the device-opening tests of the Swift, .NET, Python and Kotlin layers put every role on the virtual loopback device, so a gate run never sounds through a laptop's loudspeaker; without it they run on the system's route as before.
- **The React Native package names the statuses of ABI 0.33.** `notAFocus` (was `notAfocus`) and `clockBehind` reach JavaScript as the library's own codes rather than as `platform`, and the iOS half no longer calls a status `Optional(...)` now that the Swift layer keeps the number of one it has no name for.
- **A server that takes SIP over UDP alone can be sent a request past 1300 bytes, when the deployment says so.** An authenticated INVITE of 1,444 bytes to a PBX with no TCP listener ended as a 513 once the stream fallback failed. `DatagramLimit::without_stream_bytes` (off by default, a deliberate deviation from RFC 3261 §18.1.1, whose line is about an unknown path MTU; `DatagramLimit::path_mtu` remains the way to state a known one) lets such a request go over the datagram up to that size once the application says no stream is coming, or the wait for one runs out: `Endpoint::no_stream_coming` marks the addresses a stream was asked for, the user agent sends what it was holding again, each one is recorded as `transport.kept.datagram` with its size and the limit, and a stream bound later is preferred again. In the four idiomatic layers, the transport failure told for a fallback connection that could not be made now carries a detail naming where it was going and whether it was refused, timed out or not tried.
- **Named events are offered on every clock the offer's codecs run on.** An offer of Opus, G.722, PCMU and PCMA named `telephone-event/48000` alone, on the first codec's clock, so a PBX that settled on PCMU and answered `telephone-event/8000` agreed no events and the digits went in-band. `MediaCapabilities::dtmf_payloads` now gives one payload type per clock rate among the codecs (G.722's RTP clock is 8 kHz, RFC 3551 §4.5.2), each with `a=fmtp:<pt> 0-15`, and the plan takes the events on the agreed codec's clock (RFC 4733 §2.5.1.2), falling back to the first common one. The default INVITE grew by 53 bytes; `docs/06-nat.md` quotes the new sizes.
- **macOS device mode no longer overruns a buffer in the capture callback, and the microphone and the ringer can be chosen.** The voice-processing unit converts the device's slice to the stream's rate before the input callback is told of it, so a 48 kHz stream on a microphone running 4,096-frame slices at 44.1 kHz was asked for 4,458 frames; the callback rendered 4,096 of them into a 4,096-sample buffer and the unit copied past the end of its own buffers (a fault under the guard allocator at the first activation, heap corruption later). The callback now renders exactly the frames it is told of into a buffer sized for a whole slice of the slowest device at the stream's rate, and refuses and counts (`Counters::capture_oversized`) a slice that still does not fit. `sipral-io-coreaudio` refuses a second voice-processing unit in a process (`Error::Busy`, `voice_units_open`), a ringer on a device of its own plays through a plain output unit (`StreamKind::Playback`) beside the call's, and the microphone is named on the unit's input element apart from the loudspeaker's (`StreamConfig::capture_device`) without moving the system default; the engine opens a call's two halves in one `Backend::open_duplex` and, on a reopen, waits for the pump to confirm the old unit is gone. On macOS `select` now takes the microphone and the ringer; iOS still answers `NotSupported` for them. `SipralDeviceCheck` (in `bindings/`) runs the device-mode sequence by hand, under the guard allocator.
- **A TCP connection to a server that answers no keep-alive is no longer called dead.** Every stream flow was held to RFC 5626 §4.4.1's ten seconds for a pong, and Asterisk answers none, so a call it carried over TCP lost its connection about thirty seconds in and could not be held, resumed or hung up. §4.4 lets a UA without an outbound registration expect a pong only on an explicit indication; the ten seconds now apply once the flow has answered a ping, and each ping closes the framer's CRLF run, so a server that answers every ping is no longer read as pinging back on its second answer. A flow the stack does call dead is raised as `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` (`SIPRAL_TRANSPORT_ERROR_TIMED_OUT`) instead of not at all, and the four idiomatic layers close their connection when they hear it.
- **A MESSAGE or PUBLISH whose answer to a challenge outgrows a datagram waits for the stream.** It was reported refused with the 401 or 407 the moment the stream was asked for; it now goes on the connection once one is bound, and without one a MESSAGE is reported with a 513 and a PUBLISH fails as unreachable with a 513.
- **A challenged request that outgrows a datagram no longer hangs.** An SDES call offering two suites answered a PBX's challenge with an INVITE past RFC 3261 §18.1.1's 1300 bytes, the stack asked for a stream transport and nothing ever ended the call. The four idiomatic layers now answer `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` themselves over UDP (`stream_fallback`/`streamFallback`, on by default; `stream_server`/`streamServer` for a PBX that takes TCP on another port): they open a TCP connection, the held retry goes on it with a TCP `Via`, and the call or registration carries on. A connection that cannot be opened is told with `sipral_stack_transport_failed` on the number it would have been bound at, and the stack stops waiting at once; an application that says nothing gets `sipral_ua::STREAM_WAIT`, ten seconds. A call's INVITE then goes again over the datagram with one SDES suite per stream when that fits — `AES_CM_128_HMAC_SHA1_80`, SRTP's mandatory-to-implement suite, where it was offered, since Asterisk refuses an offer of `AEAD_AES_256_GCM` alone with a 488 (`Endpoint::reshape_challenged_body`), and otherwise ends as unreachable with a 513 whose text names the size and the limit; a REGISTER fails as unreachable with a 513, a re-INVITE or UPDATE fails and leaves the call as it was. `scripts/lab.sh datagram` runs it against Asterisk with TCP and with UDP alone.
- **A Kotlin client past a thousand recordings still reaches its recording servers.** Transport ids at 1024 and above were taken for the connections the datagram fallback opens, and what the stack sent under one went there; a recording server's connection is numbered from the same count and reached that range after 960 recordings, and its messages were dropped. Every connection the layer opens now takes its id from one count, and what is sent goes by the connection that holds the id.
- **The .NET layer's frame clock keeps a schedule too.** `CallMedia`'s application-mode thread slept a frame after its work, which Windows' 15.6 ms timer rounds to about thirty-one frames a second; it now waits for a due time a frame after the last, as the other three layers do.
- **A recording's SRTP never reuses keystream.** A stream the recording server moved to another `a=crypto` line and back was given a fresh protector with its rollover counter at zero, so past a sequence wrap it could protect an index its key had already covered (RFC 3711 §9.1); every line's protector is now kept for the life of the recording.
- **One late packet from the far end no longer ends an encrypted recording.** Its copy was protected behind the one before it, which the sender's rollover counter reads as a wrap, so the recording server failed that copy and every one after it; a repeated one would have gone under the same index. On an SRTP recording session a copy behind the last is now left out, and a far end that starts a new source is carried on from where the copies got to.
- **A recording is offered no suite weaker than the call it records** (RFC 7866 §12.2): only the account's suites whose key and tag are at least as long as the recorded call's, or the call's own suite alone.
- **A call's own frame clock in the Swift, Python and Kotlin layers keeps time.** In application mode each call's thread slept a frame's length after its work, so every late wake-up was lost and the call sent and played fewer than fifty frames a second; bridged in a local conference, whose clock keeps a schedule, a far end heard 48 to 53 of 60 frames and silence in the gaps. The thread now keeps a schedule too. The .NET layer's own thread did not fall behind on the machine it was measured on, and is unchanged.
- **The Swift layer waits for a connection to name its local address.** A connection could be ready before its path named the local end, and the stack was then created on, or a recording server's connection bound by, an empty address (`bind_address` or `local` "is required and was not given"). It now waits for the address within the connection's patience, and refuses the connection if none comes.
- **An encrypted call is recorded to a recording server encrypted.** The copies SIPREC sends of a call keyed with SRTP went out as plain RTP; the recording session now offers both streams as `RTP/SAVP` with SDES keys of their own (RFC 7866 §12.2, RFC 4568), each copy goes out under this end's key for the line the server took, and a stream the server will not take as SRTP gets nothing. Plain RTP only where the account allows it: `AccountSrtp::recording_in_clear`, `recording_in_clear` in `sipral_account_config_t` (ABI 0.32). Copies that move to a call that replaced the recorded one, or to a stream the server took back, carry their numbering on, so no SRTP index goes out twice under one key. A recording that began in the clear copies nothing of an encrypted call that replaces the recorded one, unless the account allows it.
- **An RTCP sender report pairs the wall clock with the media clock.** Its RTP timestamp was the next packet's, not the one standing for the instant of its NTP timestamp (RFC 3550 §6.4.1); it is now carried on at the clock rate from the last frame's sampling instant. The headless and register-and-call examples read the system clock instead of dating their reports from 1970, the Kotlin layer passes `media_clock_unix_seconds`, `MediaEngine::set_wall_clock` gives running calls a clock learned late, and a C ABI stack created without a media clock takes the one `sipral_stack_stir` pairs with `now_ms`.
- **A dynamic codec or named events an answer renumbered are found in common, and each end sends and receives on the right number.** The SDP planner matched formats by number, so an answer that listed iLBC as 99 to an offer of 97 (RFC 4317 §2.3, allowed by RFC 3264 §6.1) had no codec at all; a dynamic type is now matched by encoding, clock rate and channels, `MediaPlan` carries the number to send with (`codec`, `dtmf`) and the one that arrives (`codec_in`, `dtmf_in`), and a call takes in its audio and keys, and copies them to a recording server, on its own numbers.
- **A PASSporT holds only for the called party it was signed for, whatever the request names it with.** The verifier compared `dest` with the request only when `To` was a number, so a PASSporT signed for `sip:alice@example.com` vouched for a request to anyone else; now the number or SIP URI in `To` or the Request-URI is held against `dest.tn` and `dest.uri` in every case, both canonical (RFC 8224 §8.3, §8.5), and `DestMismatch`'s `detail` names what was signed and what was asked for. The signer writes `dest.uri` in §8.5's canonical form (`sip:user@host`, lower case, no port, parameters or headers), and `sipral_stir::canonical_uri`, `Dest::uri`, `Dest::names_number` and `Dest::names_uri` do the same for any caller.
- **The Kotlin binding loads with every 0.31 event arm.** Each payload arm's numbers now cross JNI in one `long[]`, so the event's `deliver` stays inside the JVM's 255 parameter slots; `SipralEvent.payload` reads the same.
- **The Swift binding hands an empty list over as a null pointer.** `Sipral.callAnswerWith` with no header fields was refused `headers is not read here`, because an empty Swift array still carried a buffer; every printed wrapper that takes a list now passes null and zero for an empty one, as the .NET and Kotlin layers already did.
- **The interop matrix reads the newer steps of a lab run.** The SRTP policy per account against Asterisk and through the proxy, STIR/SHAKEN between two C ABI stacks (whose flows start after the seed and end at `every STIR call passed`) and SIP over TCP and TLS through the four layers (one row per agent, a stray FAIL a row of its own) each have rows and a feature in `interop/features.toml`, so the recorded run passes the generator's own check again; `docs/11-testing.md` is regenerated from it.
- **Every result a lab run prints has a row in the interop matrix.**
  `scripts/interop-matrix.py` knew section headers only from its own list, so
  a step it was not told about was read as the tail of the step above it: the
  field failures, the NAT pair with its first STUN server dead, the call whose
  address moves and the call placed 330 s after registering all went
  unreported, and a FAIL in any of them could have turned the TURN relay's
  rows into failures. Every header lab.sh prints now ends a section, those
  four steps have rows and features, and an `ok`/`FAIL` line in a step that
  produced no row stops the generator, in both modes, naming the line.
  `--self-test` runs the generator's own tests. In the same batch,
  `scripts/bench.sh scale` counts each call it asks for once: a call never
  answered is no longer counted again as never ended, and a call that fails
  early no longer stops the placing short of the calls asked for.
- **A 2xx lost on UDP is sent again until its ACK arrives.** RFC 3261
  §13.3.1.4 has the answering end repeat its 2xx, T1 doubling up to T2, and
  nothing did: the INVITE's retransmissions stop at the first provisional,
  so a lost 200 left the caller ringing until it gave up and the answering
  end holding a call nobody heard; ten thousand calls on one machine lost
  243 of them this way. The INVITE server transaction now repeats
  it on timer G's schedule until the ACK or timer L.
- **An answered call's ACK is no longer recorded as missing.** The ACK to a
  2xx arrives under a branch of its own and never reached the INVITE's
  server transaction, so when RFC 6026's timer L ended it 32 seconds later
  every answered call's D1 record said `transaction.unacknowledged`. The
  dialog that takes the ACK now tells the transaction.
- **A registration that stops being evidence is said at once.** When names
  stop resolving, the machine wakes, or the network changes, each binding
  that becomes unverified raises `UaEvent::Unverified` —
  `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED` with
  `SIPRAL_REGISTRATION_STATE_UNVERIFIED` across the C ABI — instead of
  changing state in silence until a refresh failed minutes later.
- **The reference loop no longer drops a name its resolver cannot answer.**
  `sipral_ua::Runtime` hands the `ResolveNeeded` event to the application,
  where it used to leave the dialog's question unanswered without a word,
  and tells the agent names stopped resolving when a registrar's own name
  fails too, so one `Contact` naming nowhere does not put every binding into
  recovery.
- **The C ABI's documentation of a request too large for a datagram says
  what happens.** The call that asked for it is refused with
  `SIPRAL_STATUS_NOT_SENT` beside `SIPRAL_EVENT_KIND_TRANSPORT_WANTED`, and
  asking again once the stream is bound sends it; it said the stack sent it
  again by itself, which it never did.
- **The examples keep RTCP on its own port when the call says so.** A peer
  that does not multiplex RTCP with RTP (RFC 5761), Asterisk among them,
  sends its reports to the port after the RTP one and reads ours as coming
  from there (RFC 3550 §11); the examples' media socket listened on the RTP
  port alone and sent every report from it, so neither end of such a call
  ever measured a round trip. The socket now binds that port once the
  call's plan names it, reads it, and sends reports and goodbyes from it.
- **A DTLS-SRTP profile order names each profile once.** `sipral-dtls`'s
  `Config::srtp_profiles` is the client's `use_srtp` list "in descending
  order of preference" (RFC 5764 §4.1.1) and the server's own order of
  choice; a list naming a profile twice is now refused by
  `Connection::new` with `IllegalValue`, and `Config::new`'s documentation
  names the four profiles it really defaults to, RFC 7714 §14.2's
  `SRTP_AEAD_AES_256_GCM` and `_128_GCM` first. New tests negotiate from
  both sides against a peer offering only AES-CM, only GCM, and nothing in
  common; check each profile's exported key and salt widths against the
  `sipral-rtp` suite that consumes them (twelve-octet salt for both GCM
  profiles, RFC 7714 §12); carry one GCM-protected RTP packet each way
  under the keys a full in-process handshake exported; and refuse
  malformed `use_srtp` data and an unoffered server MKI in either hello
  without panicking.
- **A packet still on its way from where the far end was does not take a
  moved call back there.** After a re-INVITE moved the far end's media, the
  first packet read closed the stream's latch wherever it came from; one
  the far end had sent from its old address just before it moved, read
  after the re-INVITE, held the stream on an address nobody listened at
  and refused every packet from the new one, for the rest of the call. Such
  a packet is still played but leaves the latch open, until half a second
  of them says the far end is sending from there still.
- **SRTP under AES-GCM interoperates.** RFC 7714's two suites derive their
  session keys with RFC 3711's PRF, over a salt two octets narrower than
  the one it is defined for; `sipral-rtp` put the twelve-octet salt at the
  right of the PRF's block, the SRTP stacks a call meets put it at the left
  with two zero octets after it, and every packet either end protected
  failed the other's tag check. The salt now goes at the left, which
  changes nothing for the fourteen-octet suites.
- **A forked call's relay over TCP or TLS reaches every branch.** The
  branches of a forked call hold the one allocation, and a relay reached
  over a connection has one connection for all of them; everything read off
  it went to the first branch's session, so the other branch's checks and
  audio never reached it and the fork found no path. `MediaEngine::
  receive_stream` now puts the bytes back together once and hands each whole
  message to the branch it is for, as a datagram from the server already
  was; `IceAgent::next_stream_frame` and `take_stream_frame` are the two
  halves of `poll_stream` that let it.
- **The volume flow no longer blames this end for a call the far end never
  answered.** `scripts/lab.sh volume` through Kamailio to FreeSWITCH at a
  100 ms stagger reported two or three of a hundred calls as "the stream
  stalled", reproducibly. The capture shows those calls get a `183` that
  promises early media, which opens a session this end counts as up, and then
  no RTP at all before the far end is cancelled 15 s later — FreeSWITCH
  shedding load at the edge of its own session-rate throttle, never answering
  them. The stall watchdog fired correctly on the early media that never came,
  but the flow counted an unanswered call among those that came up and called
  the miss a stalled stream. It now counts a call as up only once the far end
  answers it, reports the ones left in early media apart as the server
  declining under the offered rate, and fails only on a stall of a call that
  was answered — the real media defect the watchdog is there to catch,
  including a call answered while its early media was still silent that stays
  silent, which the watchdog, firing once per silence, does not report twice.
  A call refused with a `5xx` before it was answered, which FreeSWITCH sends
  at a 50 ms stagger, is reported apart the same way; a `4xx` or `6xx` still
  fails the run, since it says the request was wrong, not that the server was
  busy.
- **The Swift package's tests build and run on Linux.** `NatTests` masked
  the interface flags as `Int32`, which Glibc imports as `Int`, and the
  macOS SwiftUI sample was declared on every platform, so `swift test`
  failed to compile under Swift 6.1 on Linux before any test ran. The
  sample is now declared on macOS only; the NAT suite passes in a
  `swift:6.1` container.
- **A lite ICE end that started controlling yields to a full peer.** Two
  lite ends make the offerer controlling (RFC 8445 §6.1.1), so a lite end
  told the peer was lite too started controlling; when the peer was in fact
  full, its checks arrived with ICE-CONTROLLING and the §7.3.1.1 tiebreaker
  kept the lite end in charge about half the time, answering 487 while
  never sending a check of its own, and the call found no path. The first
  such request now moves it to controlled, and its nomination is taken.
- **A change offered in an UPDATE or a PRACK that the application never
  answers no longer blocks the call for good.** The endpoint answers such a
  request 408 after 64·T1, but the offer went on counting as unanswered, so
  every later UPDATE on the call was refused 500 until Timer J ran out, and
  every later offer of any kind for the rest of the call; for a PRACK, the
  2xx to the INVITE held behind the reliable provisional response never
  went. The 408 now ends the offer at both layers, the call takes the next
  one, and the held 2xx goes.
- **A hung agent in the lab no longer holds the lab lock.** Every agent and
  harness `scripts/lab.sh` runs in a container of its own gets a wall-clock
  derived from the calls it places and what starting it takes; past it, only
  that container is removed and the step fails by name. The relay step also
  counts the relays coturn has to have given back as its steps run, so a
  binding skipped before another no longer throws the later counts off.
- **Silence played for a packet lost on the way is counted, apart from the
  under-runs.** A packet lost with nothing behind it yet to conceal it from
  left the buffer empty, and the earpiece played a frame of silence that no
  counter held: `Quality::underruns` is the earpiece asking before the next
  packet arrived, and the lost packet itself was only in `Quality::lost`,
  beside the concealed ones. `Quality::silenced` now counts those frames, so
  the two together are every frame of silence heard while the far end was
  sending. The drift flow's check, which failed under `lossy` with 12 frames
  of silence played against 3 under-runs counted, sets the silence against
  both. The C ABI's `frames_underrun` is unchanged.
- **A Python call closed the moment it ends still gives its relay back.**
  `Stack` sent a call's farewells — its RTCP BYE and the TURN Refresh with a
  lifetime of zero — only after the poll that ended the call had delivered
  all its events, so an application that closed the call as soon as it saw
  `Call.ended` could forget it first, and the relay lapsed on its server; the
  lab's TURN step counted one allocation fewer given back than made, now and
  then. They now leave before `SIPRAL_EVENT_KIND_CALL_ENDED` reaches the call.
- **A hold from Android's telecom framework says held at once.**
  `TelecomBridge.hold` sent the re-INVITE and left the connection active
  until the far end answered it, but `Connection.onHold` documents that a
  connection not in `STATE_HOLDING` within two seconds is disconnected: a
  slow far end, or one that refused the re-INVITE, cost the call when a
  cellular call was answered over it. Hold and unhold now reach the
  connection before the re-INVITE goes, and what the framework asked for
  stands until the dialog agrees with it — a refused re-INVITE no longer
  takes the call off hold under the call that has the microphone.
- **CallKit's mute and reset reach the call.** `CallKitAdapter` did not
  handle `CXSetMutedCallAction`, so muting from the system's call screen, a
  headset or CarPlay did nothing, and its `providerDidReset` was empty, so a
  call the system's call service forgot kept running with no call screen.
  Mute now sends the far end silence, and a reset hangs every call up.
- **A call this end answered hears what the far end measured of its
  audio.** The answer never carried `a=rtcp-xr:voip-metrics`, and the
  offer's own line asks only the answerer to send (RFC 3611 §5.2), so the
  caller sent no VoIP Metrics block and the callee's RFC 6035 quality
  report never had a `RemoteMetrics` set. The answer now asks for the block
  whenever the catalogue's capabilities do, as the offer always has; two
  sessions exchanging reports now each carry the other's block, figure for
  figure, as their `RemoteMetrics`.
- **The far end's checks under a restart's new credentials are kept until
  the restart is taken up, not refused.** Once this end has offered or
  answered an ICE restart, the far end checks under the new credentials as
  soon as it has answered, and those checks often arrive before its answer
  does. They were answered with an unsigned 401 (RFC 8489 §9.1.3), which
  the far end discards and retransmits after, costing the new session up to
  one RTO. The agent now keeps them — the newest thirty-two, in the full
  role (`IceAgent::expect_restart`) and the lite one alike — and answers and
  checks back on them the moment the restart is taken up; a restart refused
  drops them, and so does waiting past the far end's 39.5-second
  transaction.
- **A request inside a dialog that nothing claims is answered, not left to
  time out.** A SUBSCRIBE or PUBLISH inside a call reached the application
  as `UaEvent::Unclaimed`, which neither the facade nor the C ABI can
  answer, so the peer retransmitted it until its own timer gave up — and
  RFC 3261 §12.2.1.2 then has it end the dialog, the call with it. Each is
  now answered by the usage RFC 5057 §5.3 matches it to: 405 with `Allow`
  for a method this agent recognises and does not take there, 501 for one
  it does not recognise, 481 for an UPDATE, INFO, PRACK or re-INVITE in a
  dialog that holds no call, 403 for a REFER there, 200 for a PRACK that
  matches a provisional of a call already gone (RFC 3262 §3). An OPTIONS
  inside a dialog is answered as one outside it (§11.2). An INFO in a call
  that is not DTMF — RFC 5168's media control, a vendor Info Package, one
  with no body — is answered by RFC 6086 §4.2.2: 469 with an empty
  `Recv-Info` for an Info Package, 415 with `Accept:
  application/dtmf-relay, application/dtmf` for a body this agent cannot
  read, 200 for none. A Rust application that answers those itself calls
  the new `UserAgent::hand_over_info(true)` and receives them as before.
- **A PRACK is asked its `Require`, and a refused PRACK acknowledges
  nothing.** RFC 3262 §3 has a PRACK processed by RFC 3261 §8.2 like any
  request, and §8.2.2.3 was never asked of one: a PRACK demanding an
  extension this agent lacks is now answered 420 naming it. A PRACK refused
  for any reason — 420, 415 for its body, 488, 491 or 500 for its offer —
  goes through the new `Endpoint::refuse_prack`, which answers it and puts
  its provisional back on the list of unacknowledged ones, retransmitting
  it again until the INVITE has its final response: the PRACK the far end
  sends again (§8.1.3.5) is matched on the same `RAck` rather than answered
  481, which ends the dialog, and a 2xx held behind the provisional waits
  for it instead of going for a PRACK that acknowledged nothing.
- **An offer in a PRACK is answered, and an answer in one is taken.** An
  offer the agent could not answer itself got a 2xx with no body and was
  never reported, although RFC 3262 §5 puts its answer in that 2xx. It now
  goes the way a re-offer does: a hold, a resume or a moved address is
  answered in the PRACK's 2xx, and anything else — another codec, a secure
  profile — arrives as `UaEvent::Reoffer` with the PRACK held open, for
  `accept_reoffer` (whose 2xx carries the answer alone) or `reject_reoffer`
  (which leaves the provisional unacknowledged, as above); a managed call's
  engine answers it itself. And when the reliable provisional carried this
  end's own offer — an INVITE that came without one — the description in
  the PRACK is the answer, and becomes the call's far end instead of being
  read as a new offer and dropped.
- **An in-dialog REFER nobody answered in time frees the call for the
  next one.** Left unanswered for 64·T1, it was answered 408 by the
  endpoint but kept as a transfer still being decided, so every later REFER
  on the call got 491; the end of its transaction now lets it go, and
  `accept_transfer` or `reject_transfer` on it is `UaError::WrongState`.
- **The Python example agent gives back a relay it hung up on.**
  `bindings/python/examples/agent.py` closed a call the moment it saw it
  end, when the same end had hung up after its dwell, so the TURN Refresh
  queued a poll later found the call gone and was dropped: the relay lapsed
  at coturn instead, and the lab's count of allocations given back came up
  one short. The short wait for that farewell now runs on every way a call
  ends.
- **A body the agent cannot read is refused 415 on every request that
  carries an offer, not only on the INVITE that opens a call.** A
  re-INVITE, UPDATE or PRACK whose body is not `application/sdp`, or is
  content-coded, is answered 415 with `Accept: application/sdp` or
  `Accept-Encoding: identity` before anything acts on it (RFC 3261 §8.2.3),
  so it no longer arrives as `UaEvent::Reoffer` for the application — or
  the facade's 488 — to answer, and it refreshes no session timer. One its
  sender marked `handling=optional` is ignored: a re-INVITE carrying only
  that asks for an offer, an UPDATE only refreshes the target. A PRACK
  refused this way acknowledges nothing, and a 2xx held behind its
  provisional waits for the PRACK sent again.
- **A media-type parameter in `Accept` counts toward the most specific
  range.** The 406 decision ranked `application/sdp`, `application/*` and
  `*/*` and stopped there, so `application/sdp;level=1;q=0,
  application/sdp` took SDP; RFC 2616 §14.1, which RFC 3261 §20.1 keeps,
  puts a range with parameters above the same range without, and the
  parameterised one now decides. Parameters after `q` are accept-extensions
  and are not counted.
- **The INVITE rate limit counts a stream the application bound without
  naming its far end.** It only bucketed INVITEs it could attribute to a
  source address, so every INVITE on such a connection went straight to
  the policy and the application however fast it came. The connection is
  now the caller: one bucket per stream, dropped when the stream closes.
- **A 2xx that arrives after the call it would have joined is over is
  acknowledged and hung up under `ForkPolicy::KeepAll` too.** Once the
  call placed had ended, a later branch's 2xx inside the answer window
  was dropped with no ACK and no BYE, leaving a dialog up at a far end
  that answered (RFC 3261 §13.2.2.4). A sibling still up now takes the
  INVITE over, so a late branch is minted beside it; with none left, the
  2xx is acknowledged and hung up, as `KeepFirst` already did.
- **A 2xx after a refusal is passed up and hung up instead of being
  answered with the refusal's ACK.** The INVITE client transaction
  re-sent the ACK it built for a 486 or 603 to any final response in
  `Completed`, including another branch's 2xx that a proxy forwards
  regardless (RFC 3261 §16.7); RFC 6026 §8.4 re-sends that ACK only for a
  retransmitted 300-699. The 2xx now reaches the dialog layer, which
  acknowledges it, and the user agent ends it with a BYE, since the call
  was already reported `Refused`.
- **The 200 to a CANCEL carries the `To` tag of the INVITE it cancels.**
  It was given a tag of its own, so a lab capture showed the 180, the 487
  and the 200 to the CANCEL naming two different dialogs; RFC 3261 §9.2
  has them share one.
- **An offer that overtakes the ACK carrying the answer to ours is refused
  491.** After answering a re-INVITE that carried no description with an
  offer in the 2xx, the agent answered a second one that arrived before the
  ACK with another offer — which RFC 3264 §4 forbids before the first is
  answered — and would have taken an UPDATE's offer the ACK's answer then
  landed on. The offer in a 2xx now counts as outstanding until its ACK,
  as RFC 3311 §5.2 has it.
- **Every branch of a forked call runs ICE over the one relay its offer
  named.** A forked INVITE's one offer named one relayed candidate, and one
  allocation stands behind it — a second from the same socket is refused by
  the server (RFC 8656 §3.2) — so the branch kept after early media on
  another, or the second leg of `ForkPolicy::KeepAll`, ran without it, and a
  call only a relay could carry had a path on one branch at most. Now every
  branch holds the one allocation with an agent of its own
  (`sipral_nat::ice::SharedRelay`, `IceAgent::add_shared_relay`), from the
  moment `UaEvent::CallForked` reports it: each asks the relay to let its own
  phone through, runs its own checklist under the offer's credentials (RFC
  8839 §7), and hears only its own phone's checks and media —
  `IceAgent::claims` says whose a datagram on the shared socket is, by the
  peer fragment in a check's USERNAME, the check an answer answers, or the
  peer address, relayed or not, and `MediaEngine::receive_early` hands each
  one to the branch that claims it. An agent handed another branch's check
  no longer answers it. A branch that ends lets go of the relay, and stops
  renewing the permissions only its phone needed (`TurnClient::withdraw`);
  the last to let go gives it back with a Refresh of lifetime zero (RFC 8445
  §8.3.1).
- **A relay handed to the answer of a call already rung with media comes
  back whole.** `MediaEngine::answer_with` on a call `ring_with` described
  reads no relay, since the 200 OK carries the 183's description, and it
  used to delete the allocation it was given with a Refresh of lifetime
  zero. It now hands it back through `MediaEngine::poll_returned_relay`,
  still live on its server, for `Relays::put_back` to keep for the next
  call on its socket, as every refused description already did.
- **An earpiece that takes two frames a callback, or slips more than one
  in a talk spurt, no longer runs dry in the middle of a word.** A device
  callback two frames long pulls twice at one instant, and the second pull
  could never stretch a pause, since the evidence it waited for was an
  arrival since the last pull; the buffer now counts the arrivals its
  pulls have not caught up with, and widens the pause's dead band by the
  frames taken at once, which it reads off the pulls between arrivals. And
  a pause kept one frame in hand whatever the earpiece's pace: the buffer
  now measures that pace against the far end's clock and the length of
  its recent spurts, and keeps in hand what the next spurt will slip. In
  the crate's own simulation of the lab's tone, two minutes at 2000 ppm
  with a two-frame callback cut it 10 times before and none after; in
  `scripts/lab.sh drift` at 500 000 ppm the fast earpiece's tone was cut
  1 774 times in two minutes before and not once after, at the cost of up
  to 340 ms held in hand; a buffer that runs dry mid-spurt now starts
  again at once rather than waiting out a pause's frames in hand
  (`docs/19-numbers.md`, `docs/05-media.md`).
- **The lab's Asterisk calls a phone behind a NAT from the port the phone
  registered to.** `scripts/lab.sh wasapi up` published Asterisk's internal
  5060 as 5062, so an INVITE Asterisk started itself left the lab machine
  from 5062 only while the machine's connection tracking still held the
  phone's REGISTER, and from 5060 after that; a NAT that filters by address
  and port dropped it, and the phone never rang. Asterisk's own socket is
  now moved to 5062 and published one to one, and `wasapi up` fails unless
  Asterisk reports it there. On the Android emulator with STUN and the plain
  `labuser` account, an incoming call now rings and carries audio both ways
  (`docs/15-mobile.md`); the earlier report of that call answered with a
  private `Contact` did not reproduce, on the emulator or in the lab.
- **A REFER that names no dialog is refused 403, not 481.** 481 said it named
  a dialog this end lacks, which RFC 3515 §4.1's own REFER never does; one
  whose `To` does carry a tag is still 481. A SUBSCRIBE for the `refer`
  package that names no subscription is 403 too, as §2.4.4 requires, rather
  than 405.
- **The subscription a taken REFER opens says how long it runs, and ends.**
  Every `active` NOTIFY carries the `expires` RFC 6665 §4.2.2 makes
  compulsory (an hour, since the INVITE placed carries none); the referrer may
  refresh it or end it with a SUBSCRIBE of its own, answered with a NOTIFY of
  the whole state, and one nobody refreshed ends `terminated;reason=timeout`
  without touching the call. A call a taken REFER could not even send ends the
  subscription with §2.4.5's 503 instead of leaving the referrer on a 100 and
  the call unable to take another REFER.
- **A full ICE peer that gets the roles backwards can no longer strand a
  lite end without a path.** RFC 8445 §6.1.1 makes a full peer's role
  against a lite one controlling, unconditionally — never controlled — but
  `LiteAgent`'s role-conflict handling ran the general §7.3.1.1 tiebreaker
  arithmetic anyway, so a Binding request carrying ICE-CONTROLLED (a full
  peer, honestly confused about 3PCC-style role determination or an
  attacker forging one) moved the lite end to the controlling role roughly
  half the time — a role it can never act on, since it gathers no
  candidate beyond host, leaving the call unable to complete ICE. A Binding
  request only ever reaches a lite agent's answering side from a full peer
  in the first place (§8.2: two lite agents exchange no connectivity
  checks at all), so an ICE-CONTROLLED request naming the lite end's
  controlled role is never a genuine ambiguity for the tiebreaker to
  settle; it is now always answered 487 with the role kept.
- **A TURN 401 to an already-authenticated request no longer gets a
  pointless retry.** `TurnClient::answerable` answered a 401 once per
  transaction regardless of whether the request already carried
  MESSAGE-INTEGRITY, so a Refresh — or anything else sent once the
  allocation was authenticated — whose credentials the server rejected,
  most commonly because ephemeral credentials had expired, sent one more
  copy of the same USERNAME/REALM/password before giving up, which RFC
  8489 §9.2.5 forbids ("the client MUST NOT perform this retry if it is
  not changing the USERNAME, USERHASH, REALM, or its associated password
  from the previous attempt"). A 401 naming the realm already in use now
  ends the transaction with `TurnError::Unauthenticated` at once; one
  naming a different realm, a genuine change, still gets its one retry.
- **Apple artefacts are built for the releases they claim.** The macOS
  wheel was tagged with the building Mac's own version (`macosx_26_0`), so
  pip refused it on every older macOS the library runs on; and in every
  `--with-opus` variant cmake built libopus for the Mac's own SDK (macOS or
  iOS 26.5) while the XCFramework's `Package.swift` promised iOS 15 and
  macOS 12. `scripts/package/apple.sh` now sets macOS 12.0 and iOS 15.0
  once for the wheel, the NuGet macOS natives and the XCFramework, each
  built in a target directory of its own (cargo does not rebuild a C
  dependency when only the deployment target changes), and each script
  reads every object in the static archive and fails on one built for a
  newer release.
- **The Python and .NET layers now give a TURN relay back to the server,
  not to the last address media came from.** `Stack._drain_farewells`
  (Python) and `SipralStack.DrainFarewells` (.NET) read
  `sipral_stack_poll_farewell`'s own `destination` -- what
  `docs/08-ffi.md` already asked of them -- the way the Swift and Kotlin
  layers already did; before, both asked for no destination at all and
  routed every farewell, the Refresh with a lifetime of zero among them,
  to `call.media.remote_address`. Under ICE or with a peer that never
  sent any media, that address is the far end or nothing at all, so the
  Refresh either went to the wrong peer or was silently dropped and the
  relay was left to lapse on its own ten minutes later. Each layer's own
  NAT tests gained a case with a real (if fake) TURN server that asserts
  the Refresh actually reaches it when the call ends.
- **A PipeWire node removed between the crate naming it and `pw_stream_connect`
  reaching the daemon is reported, instead of leaving a silently unlinked
  stream.** `target.object` is a property the daemon never validates, and
  `node.dont-fallback` leaves a target it cannot find unlinked rather than
  rerouted to the default — no state change at all, so the state-based
  detection `docs/05-media.md` already described never saw it, and nothing
  said the stream was dead until an unrelated `recover` quietly opened a
  working one in its place. `sipral-io-pipewire`'s `Session::connect` now
  looks the target up again itself the moment the stream reports itself
  connected, and reports `StreamEvent::DeviceLost` right there.
- **`SipralSampleMac` builds under Swift 6 strict concurrency with no
  warnings.** `AudioBridge.swift`'s two `AVAudioConverter` input callbacks
  captured an `AVAudioPCMBuffer` — not `Sendable` — in a block the compiler
  treats as `@Sendable` because it crosses an Objective-C boundary, though
  AVFoundation's own overlay is not itself audited for Swift 6 concurrency
  and the block runs synchronously, on the calling thread, within
  `convert(to:error:withInputFrom:)`'s own call. `@preconcurrency import
  AVFoundation` takes the framework's own (missing) Sendable annotations as
  given instead of imposing stricter ones on code that predates them.
- **Kamailio's own forwarded requests no longer carry `Via: SIP/2.0/UDP
  0.0.0.0`.** Its `listen` directive named the bare wildcard with no
  `advertise`, so every request it relayed wrote the unreachable address
  it is bound to, rather than its own name, into the `Via` it added —
  visible first on a CANCEL, whose 487 had nowhere to come back to, so
  Kamailio retransmitted the CANCEL and relayed the same 487 more than
  once. `interop/kamailio/kamailio.cfg`'s `listen` now advertises
  `kamailio:5060`, the name every peer in the lab already resolves it by.
- **The lab's own "inbound, narrowed" flow could register but never
  receive anything.** `interop/harness/src/pair.rs`'s two roles never
  called `Endpoint::read_sip`, so a datagram arriving on either one's SIP
  socket — the wide INVITE this flow exists to narrow, among everything
  else — sat there unread until the flow's own patience ran out. Both
  roles' `turn` reads the socket now, the same way `main`'s own `drive`
  does.
- **A TURN 401 to an already-authenticated request no longer gets a
  pointless retry.** `TurnClient::answerable` answered a 401 once per
  transaction regardless of whether the request already carried
  MESSAGE-INTEGRITY, so a Refresh — or anything else sent once the
  allocation was authenticated — whose credentials the server rejected,
  most commonly because ephemeral credentials had expired, sent one more
  copy of the same USERNAME/REALM/password before giving up, which RFC
  8489 §9.2.5 forbids ("the client MUST NOT perform this retry if it is
  not changing the USERNAME, USERHASH, REALM, or its associated password
  from the previous attempt"). A 401 naming the realm already in use now
  ends the transaction with `TurnError::Unauthenticated` at once; one
  naming a different realm, a genuine change, still gets its one retry.
- **An incoming call the caller gave up on before it was taken no longer
  leaves a call that can never end.** `SipralStack.takeIncomingCall` (and
  `answerCall`, which calls it) minted and registered a `Call` for a
  handle whose `CALL_ENDED` had already been raised to nobody — no `Call`
  existed yet to receive it — so its event and DTMF streams never
  finished, `ended` stayed false, and a `CallKitBridge` bound to it never
  reported the call ended. It now reads the handle's state right after
  registering it and closes and throws on a stale one, instead of handing
  back a call nothing can ever end. `SipralSampleMac`'s `AppModel.answer`
  no longer leaves that call as the current one when `answer()` then
  throws: it detaches and closes it, rather than leaving hangup, hold and
  DTMF doing nothing, silently, against a ghost call.
- **The published interop matrix no longer shows a failed lab run as
  passing.** `scripts/interop-matrix.py` read only the calling harness's own
  pass/FAIL line for the full-ICE and TURN-relay rows in `docs/11-testing.md`,
  never the callee's (a separate container, on the other side of the pair of
  NATs) or `scripts/lab.sh`'s own closing line for the step — so a callee
  that failed, or a step `nat_pair_call` never got off the ground, still
  rendered "pass". Both are read now, and the row fails if either did.
  Separately, the two "blocked without TURN" rows — negative controls that
  are supposed to fail to place a call — were read like every other flow, so
  the block holding read "fail" in the table and the block breaking, a real
  regression, read "pass"; both are inverted now, with the reason given when
  the block breaks.
- **A pinned `SIPRAL_HARNESS_SEED` now actually pins a containerized lab
  run.** `scripts/lab.sh` never forwarded it into any of its `docker run`
  invocations of `/harness` or `/harness-c`, so setting it on the host to
  repeat a failing run drew a fresh seed inside the container instead, with
  different Call-IDs, tags and branches every time.
- **`interop/harness-c/main.c` builds again on the interop lab's own host.**
  It read its run seed through `getentropy`, unconditionally including
  `<sys/random.h>` for it — glibc 2.25 and newer only, older than the lab
  host's own glibc — so the host-side `cc` build that `scripts/lab.sh` falls
  back to when no prebuilt C harness is given failed to compile there. It
  reads `/dev/urandom` directly now, the same fallback the file already had
  for a `getentropy` call that failed at run time.
- **The interop harnesses no longer send the same Call-ID and tags on two
  runs of the same flow.** Both drivers seeded every flow's stack from a
  fixed pattern, one constant per flow, with no platform entropy — enough
  to keep two flows of *one* run from colliding, not enough to keep two
  *runs* apart, since a fresh process always drew the same pattern again.
  A server that still held the previous run's transaction or dialog read
  the new one as the same request arrived twice and answered 482 Request
  Merged, reproduced running two of the Rust harness's own `call` flow at
  once against the lab's Kamailio. Both harnesses now draw a fresh
  thirty-two-byte seed from the operating system once per run and fold it
  into the per-flow pattern — and into the constants the Rust harness's
  fork, join, pair, drift, ICE, PipeWire and WASAPI steps bind with — so
  flows of one run still differ from each
  other and two runs never mint the same branch; `SIPRAL_HARNESS_SEED` (64
  hex digits) pins it so a failing run can be repeated exactly, printed at
  the start of every run either way.
- **A loss right after a long one, or after the jitter buffer ran dry, no
  longer clicks on G.711.** The
  concealer kept the audio from before a hole in the stream — frames it
  concealed, silence played while the jitter buffer ran dry and
  refilled, or comfort noise the far end sent — and joined the next frame that arrived straight onto it, as if
  nothing had been missed. A history joined that way can look periodic
  where the signal is not: after four missing frames of a tone whose period
  is five, the frame after the hole matched the one before it exactly, and
  a loss one frame later repeated it as a one-frame period, opening on its
  first sample instead of continuing from its last. On the lab's lossy
  links that was a jump of 6 396 and of 7 992 on a tone whose steepest step
  is about 3 000. The history now starts again at the frame after any hole,
  concealed or silent, so a pitch is only ever estimated over audio that is
  contiguous in time.
- **G.711 at 10 ms frames conceals a loss one frame after another at the
  voice's own pitch.** Once the history started again after a gap, a
  single 10 ms frame was all there was, and the search halved it into a
  window and a range of lags that reached only 200 to 400 Hz: every voice
  below that was repeated at a pitch it never had, -1 to -5 dB against
  what was really said. The pitch measured before the first gap now
  carries across it while the new audio is too short to measure one, and
  a short history gives up window length before lag range; the same loss
  pattern now scores 9 to 22 dB for voices from 110 to 178 Hz, and 20 ms
  frames gain 1 to 3 dB on average. A frame the jitter buffer plays to
  stretch a pause no longer starts the history again either, since nothing
  the far end sent is missing, and the frame after a gap is remembered as
  it arrived rather than with the cross-fade into it.
- **A call through a registrar reached at another address than its
  `Contact` names is hung up where the registrar is.** The Swift, Python
  and .NET packages answered `SIPRAL_EVENT_KIND_RESOLVE_NEEDED` themselves
  with the far end's `Contact` taken as a literal address, which moved the
  rest of the dialog off the path its INVITE took: behind a port mapping or
  a NAT the ACK still reached the server and the BYE went to an address
  nothing answered on, so the server kept the call up. The event is now
  delivered and left unanswered, as `sipral_ua::Runtime` already leaves it
  for a literal address. Found calling through the lab's Asterisk from the
  iOS Simulator (`docs/15-mobile.md`).
- **The example agents no longer cut a call short, or print -1 packets, when
  the far end hangs up.** `bindings/kotlin/examples/Agent.kt` hung every call
  up 60 seconds after answering — `waitEnded(60_000)` timing out and
  `close()` sending its own BYE over a phone's own hang-up — for no reason
  `scripts/lab.sh` needs; the cap is gone, matching `agent.py` and the .NET
  sample, which never had one. Separately, all three read the call's final
  statistics only once the far end had already ended it, racing the moment
  `sipral_media_statistics` starts answering `WRONG_STATE` (its own numbers
  arrive with `SIPRAL_EVENT_KIND_MEDIA_STATISTICS` instead) — printing -1 in
  Kotlin and .NET, an empty record in Python, zeros in the Swift
  `SipralLabAgent`. All four now poll the numbers every 200 ms while the call
  is up, so what `ended` prints is real either way, not a race against
  teardown. Removing the cap left `Agent.kt`'s own wait for the end hand-rolled
  as `if (!call.ended) call.events.first { CALL_ENDED }`, a check-then-subscribe
  race against the delivery thread: a `CALL_ENDED` landing between the read and
  the subscribe was missed outright, and with no cap left the call's handler then
  hung forever. It calls `waitEnded(Long.MAX_VALUE)` instead, which subscribes
  before it reads `ended`.
- **The Android sample's screen no longer sits under the status bar.** An
  application targeting Android 15 is drawn edge to edge, and the sample's
  first field and heading were under the clock, with the status bar's white
  icons over a light screen. It now keeps its content clear of the system
  bars and the keyboard, and the icons are dark. Found running the APK on an
  Android 16 emulator, where it also placed, held, resumed and hung up a
  call through the telecom framework (`docs/15-mobile.md`). The no-argument
  `enableEdgeToEdge()` this drew on picks icon colour from the *system's*
  dark-mode setting, not from the sample's own screen, which is
  unconditionally light — so the icons stayed dark only as long as the
  device itself was in light mode, and turned white, invisible over the
  same light screen, in system dark mode. Both bars now ask for `light`
  style explicitly, regardless of the system setting.
- **A call answered twice is no longer broken by the second answer.** The
  INVITE's server transaction stays for 32 seconds after its 200 OK (RFC
  6026), and an answer through it in that time — an application answering
  from its own code and from the system call screen — sent a second 200
  and put a call that was up back to waiting for its ACK; hanging it up
  then sent no BYE. `UserAgent::answer` now refuses a call already
  answered, and `sipral_call_answer`/`sipral_call_answer_media` answer it
  `SIPRAL_STATUS_WRONG_STATE`.
- **An ICE call hears the far end before a pair is chosen.** Until the
  controlling end nominates — up to `nomination_wait`, a second, after its
  first valid pair — the far end sends on whichever pair its own checks
  proved first and moves to a better one as they prove it (RFC 8445 §12.1).
  The session's RTP latch closed on the first address and refused every
  packet from the next as foreign until the selection reopened it: the
  lab's relayed call through the C ABI lost about fifty packets of the
  callee's tone that way on every run, the first few through the caller's
  own relay and the rest straight from the callee's. Until the selection
  the latch now follows the far end, moved only by a packet the stream took
  — past SRTP, the source, the sequence and the buffer — so a stranger's
  packet under a wrong SSRC, or a copy of one already heard, leaves it where
  it is (`RtpSession::set_following`), and holds again from the selection
  on.
- **The far end's first connectivity checks reach the call's agent over the
  C ABI.** A loop with no media handle for a call's socket hands what
  arrives there to `sipral_stack_receive_stun`, as `docs/08-ffi.md` says,
  and that refused everything but a server's answer — so a check that
  arrived before the 200 was read, or between `MEDIA_STARTED` and
  `sipral_call_media`, was lost, and the pair waited half a second or more
  for the far end to check again. The stack now hands what arrives there to
  the call (`MediaEngine::receive_early`): to its session once it is open,
  and before that, a check signed with the password the call's own
  description gave out is kept — the newest sixteen per socket, a
  retransmission in the place of the copy it repeats — and answered by the
  agent as the session opens (RFC 8445 §7.3), unless it has waited longer
  than the far end's transaction for it lasts, 39.5 seconds, or its call
  ended first.
- **A forked call answered first by a second phone is kept, not hung up.**
  `ForkPolicy::KeepFirst` kept only the call placed and sent a BYE to any
  sibling that answered, even when the call placed had not: a proxy ringing
  a desk phone and a mobile in parallel forwards the mobile's 2xx and cancels
  the desk, so the one phone that answered was hung up and the call was
  lost. The first branch to answer is now the one kept, whichever it is; the
  branches still ringing end at once as `ForkLost`, after the kept one's
  `CallConfirmed`, and a 2xx from any other branch afterwards is acknowledged
  and hung up without an event. A sibling kept carries on as the call: its
  own session and dialog, the same `Call-ID` and parties, and the transfer it
  was placed for or the consultation it is. A TURN relay the offer named
  moves to it before the branch it waited with ends. A 2xx that crosses the
  CANCEL of a call the user put down is no longer also reported up and
  acknowledged a second time. Proven through Kamailio forking one user to
  two registered stacks (`scripts/lab.sh kamailio`).
- **A second branch answering a call that is already over is still hung up.**
  Once the call an INVITE placed had ended, whether it was put down before
  anybody answered or its CANCEL lost the race, a 2xx from another branch of
  the fork arriving inside the answer window was dropped: neither
  acknowledged nor hung up, so that phone stayed off-hook until it gave up
  by itself. It is now acknowledged and hung up, without an event, as a late
  branch of a call that was kept already is.
- **An earpiece whose clock runs fast no longer hears the drift as gaps.**
  On a clean path the jitter buffer aims at one frame, and a buffer at one
  frame has nothing below its target to fall to but empty: every frame the
  earpiece's clock gained on the far end's was played as 20 ms of silence
  wherever it fell, a word included, one every eighty seconds at 250 ppm.
  A pause now never leaves fewer than two packets queued, so a fast
  earpiece's slip takes the frame in hand and the next pause stretches it
  back. A clean path pays one frame of delay for it, bought in a pause. A
  talk spurt from a far end that sends nothing in its pauses waits for its
  second packet rather than being stretched as it starts, which would have
  played a frame concealed from the end of the spurt before.
- **The R factor and MOS-LQ count what the jitter buffer threw out.**
  They were rated from the loss rate alone, so a call whose buffer
  discarded most of what arrived still rated R 93 and MOS-LQ 4.4. RFC 3611
  §4.7.1 gives loss and discard "equal effect on the quality of the voice
  stream", and the E-model's packet loss is now the two together. What the
  buffer throws out on a restart of the far end's stream or a change of
  codec is now in the discard rate as well, and the RFC 3611 figures
  outlive a change of codec as the buffer's own counters do.
- **RTCP XR's loss and discard rates count every packet once, as RFC 3611
  defines them.** A packet that turned up after its turn stayed counted as
  lost, where §4.7.1 has late arrival among a discard's causes; within 512
  sequence numbers of the playout point it is now a discard. An empty slot
  skipped in a pause was left out of the loss rate, and a frame given up in
  a pause out of the packets expected. And the rates of a stream that took
  on a new source carried what the old source lost and had thrown out,
  though the block names the new one: they start again with it, as the RFC
  3550 reception statistics do.
- **A flood of ICE checks can no longer grow a call's memory without bound.**
  Both ICE roles answer every Binding request that reaches the media port, a
  stranger's unsigned one included, and queued the answers for as long as
  the application left them there. What waits to be sent is now held to
  `sipral_nat::ice::TRANSMIT_CEILING`, 256 datagrams, in the full agent and
  in the lite end alike; past it the datagram being queued is dropped, which
  a STUN transaction treats as a lost one and retransmits, and the drop is
  counted in `IceAgent::transmits_dropped` and
  `MediaSession::ice_transmits_dropped`. Refusals of checks that failed
  authentication stop at half of it, `REFUSAL_CEILING`, so a flood cannot
  crowd out the answers to the peer's own checks and consent requests.
- **A request outside a dialog that nothing here takes is answered at
  once.** A SUBSCRIBE, a PUBLISH, a stray BYE or a method nobody defined
  reached the application as `UaEvent::Unclaimed`, and through the C ABI
  nothing answered it until the endpoint's 408 thirty-two seconds later.
  The user agent now answers it after every handler has passed it over, as
  RFC 3261 §8.2.1 asks: 405 with `Allow` for SUBSCRIBE and PUBLISH, 501
  for a method it does not recognise, and 481 for one whose `To` names a
  dialog it does not have or whose method it takes only inside one (BYE,
  UPDATE, REFER, INFO, PRACK). OPTIONS, MESSAGE and the NOTIFYs of its own
  subscriptions are handled as before.
- **A request missing `From`, `To` or `Call-ID` is answered 400, not
  dropped.** RFC 4475's `insuf` has none of the three and "ideally" gets a
  400; the endpoint wrote nothing, because a response copies those fields
  and the builder refused to write one without them. A refusal now needs
  only the top `Via` that routes it: the 400 copies the `Via` and whichever
  of `From`, `To`, `Call-ID` and `CSeq` the request carried, and invents
  nothing for the rest (`ResponseBuilder::build_refusal`). The same holds
  for a request the parser refuses, which used to be dropped unless all
  five fields could be read. Only a request with no readable `Via` is
  still dropped.
- **`scripts/bench.sh` reads the load test's peak memory, not cargo's.** The
  timer was around `cargo test`, and reported cargo's own peak whatever the
  test did; it now runs the test binary cargo built, and a call's resident
  memory reads about 79 KB rather than 1.4 KB. The times the benchmarks
  print are called wall time, which is what they are.
- **A request the parser refuses is answered, not dropped without a trace.**
  An INVITE with a 6,000-byte display name got nothing back at all: one
  field past the parser's bound on a single value, and the whole request was
  discarded while the caller retransmitted into silence. A request past a
  bound, or not well formed enough to parse, is now answered statelessly
  from the `Via`, `From`, `To`, `Call-ID` and `CSeq` that can still be read
  (RFC 3261 §8.2.6.2) — 513 when it is longer than the message bound, 400
  otherwise, with a reason phrase naming the bound or the fault, such as
  `From Too Long (limit 16384 bytes)` — including when the field past the
  bound is one of those five, which goes back whole. What cannot be answered
  (a response, an ACK, a request whose top `Via` cannot be read, or
  one whose top `Via` is itself past the bound, since that `Via` would say
  where the answer goes) is counted by `Endpoint::unreadable` and, like
  every refusal, recorded in the endpoint's diagnostic record as
  `request.refused.unreadable` or `message.dropped.unreadable`. On TCP and
  TLS a refused message no longer costs the connection when its
  `Content-Length` still says where it ends: it is answered and the stream
  reads on, and one whose body is past the bound is answered 513 as soon as
  its head is in, the body passed over unheld. The examples print each
  datagram the parser refused.
- **The reference headless agent reads audio frames of any length the
  session agreed.** It bounded every frame by the control message limit, so
  48 kHz frames longer than 85 ms ended its connection as malformed; it now
  raises the bound to the session's own frame size once `SessionOpen` names
  it (`payload_bound`, `FrameDecoder::set_max_payload`), and answers a control
  message it cannot take with an error message instead of only logging it.
- **A `SessionOpen` naming a frame duration no session can have is refused
  where it is read.** Zero milliseconds, or a frame too long for the 16-bit
  length at its rate, decoded without complaint and failed later in whatever
  first tried to fill a frame; both are now `ControlError::FrameDuration`,
  on decode and on encode alike, and `AudioConfig::with_frame_duration_ms`
  refuses zero as `AudioError::EmptyFrame`.
- **`headless-socket-agent` no longer leaves a call it cannot take
  ringing.** A call it could not bind an RTP socket for, open a session for,
  or answer was left neither answered nor refused. It is now refused at
  once — 503 with `Retry-After` when no RTP port was to be had, 488 for an
  offer that cannot be answered, 500 otherwise — and the agent is told why on
  the error channel.
- **Nothing appended after a STUN message's SHA-256 integrity is read any
  more, even when a SHA-1 integrity follows it.** The parser drew the line
  after which attributes are ignored at MESSAGE-INTEGRITY whenever the
  message had one, including when MESSAGE-INTEGRITY-SHA256 came first. So a
  message signed with SHA-256, with an attribute and any MESSAGE-INTEGRITY
  appended by someone on the path, passed its SHA-256 check and then had the
  appended attribute believed — a nomination, a role, an address the sender
  never wrote. After MESSAGE-INTEGRITY-SHA256 only FINGERPRINT counts now
  (RFC 8489 §14.6); after MESSAGE-INTEGRITY, MESSAGE-INTEGRITY-SHA256 and
  FINGERPRINT still do (§14.5).
- **An unsigned error no longer fails an ICE check, and an unsigned 400 no
  longer ends a STUN or TURN transaction run under long-term credentials.**
  The full ICE agent believed a 400, a 401, a 420 or any error other than
  487 and 403 without a MESSAGE-INTEGRITY, so anyone who saw a check could
  fail its pair from the peer's address without the password; RFC 8489
  §9.1.4 discards every response that does not check out, and now so does
  the agent, whose check retransmits until a signed answer or its timeout.
  `BindingClient` and `TurnClient` configured with credentials ended their
  first, unauthenticated request on an unsigned 400; §9.2.5 has it discarded
  and the request retransmitted, which is what happens now. Without
  credentials — the STUN mappings of `sipral::Mappings` among them — a 400
  still ends the request at once, as §6.3.4 has it.
- **A long-term STUN or TURN key is wiped when it goes, and a broken TURN
  stream stops buffering.** The key derived from the username, realm and
  password signs requests in that realm as well as the password does, and
  was left in memory by every copy dropped, one per response checked; it is
  now overwritten on drop with the same best effort as the password.
  `StreamFraming` kept appending whatever arrived after the stream broke,
  for as long as the caller kept reading; it now holds nothing after the
  break.
- **Behind a NAT, the private `Contact` a REGISTER sent before the STUN
  answer is removed from the registrar, not left there for an hour.** The
  REGISTER that moves an account onto its public address, or onto a mapping
  that moved, now carries the `Contact` it replaces with `expires=0`, and
  every REGISTER after it does until the registrar answers one with a 2xx;
  before, the registrar kept forking calls to the dead address until that
  binding expired. A mapping that moves back never asks for the address it is
  on to go. The `Contact` being removed goes as its URI alone, without
  `+sip.instance`: Kamailio matches a removal by instance, and given both
  under the same tag it drops the new binding with the old one.
- **`TurnClient::deadline` is no longer in the past while a permission or a
  channel binding waits for its answer.** The renewal time of each
  permission and channel counted towards the deadline even after its
  CreatePermission or ChannelBind had gone out, so from the first `permit`
  or `bind_channel`, and again at every renewal, a caller that sleeps until
  the deadline woke at once, over and over, until the relay answered — up to
  39.5 seconds of a busy loop when it did not. The full ICE agent, which
  folds the TURN deadline into its own, spun with it. A renewal in flight is
  now due at its retransmission, and the lapse of a permission or a channel
  is a deadline of its own.
- **`SIPRAL_EVENT_KIND_NAT_MAPPING` no longer says `accounts=0` when the
  accounts did move.** `UserAgent::readdress` answered an error, and the
  event zero, whenever one REGISTER could not leave, although every
  account's `Contact` had already been rewritten. It now answers the count
  (`usize` rather than `Result`), and a REGISTER that could not leave is
  retried on the back-off with `RegistrationFailed { Unreachable }`, the way
  a refresh that could not leave already was.
- **A media socket's STUN answer no longer grows old while it waits for its
  call.** A socket mapped long before its call — the next call's socket,
  mapped as the last call ends — was described with whatever the server said
  then, although a NAT lets an idle mapping go in minutes. `sipral::Mappings`
  now asks again every refresh interval (25 s) until the socket is forgotten,
  an answer that differs is `MappingEvent::Moved` (`SIPRAL_NAT_MAPPING_MOVED`
  with `signalling` zero), and `sipral_stack_poll_stun` never holds more than
  one request per socket for an application that leaves it alone.
- **A request from a peer that predates RFC 3261 is matched rather than
  dropped, or confused with the next one.** A request whose `From` carried
  no tag -- legal in RFC 2543, and one RFC 3261 §12.1.1 says a UAS "MUST be
  prepared to receive" -- could not be keyed to a transaction and was
  dropped without any answer, so RFC 4475's `inv2543` was never heard. It is
  now matched as a tag of null, and so is the dialog it opens. A `Via`
  branch that is the magic cookie and nothing else (RFC 4475 §3.2.1) was
  taken as a unique identifier, which made every such request from one
  sender the same transaction and answered the second from the first; it
  now takes the RFC 2543 rule instead. An INVITE that names no `Contact`
  (RFC 3261 §8.1.1.8) is answered `400 Missing Contact` rather than handed up,
  rung and answered into a dialog that could never be reached.
- **A stale nonce that comes back unchanged no longer gets a replayed nonce
  count.** The count started again at `00000001` whenever a challenge said
  `stale=true`, even when the nonce was the same one, so the retry carried
  the nonce, cnonce and `nc` of a request already sent -- a replay to the
  server. The count now starts again only for a new nonce value (RFC 7616
  §3.4).
- **A user agent answers what RFC 3261 §8.2 says a UAS answers, before the
  application is asked.** A REGISTER was handed to the application, and
  through the C ABI nothing ever answered it until the endpoint's own 408 at
  32 seconds; it is now answered 405 with `Allow`. A Request-URI scheme other
  than `sip`, `sips` or `tel` was answered like any other (an OPTIONS got a
  200); it is now 416. An INVITE whose body is not `application/sdp` (and not
  marked `handling=optional`), or is content-coded, rang like any other; it
  is now 415 with `Accept` or `Accept-Encoding`. An INVITE whose `Accept`
  rules out `application/sdp` is now 406, since its answer would have to
  carry one; as in HTTP, the most specific range decides, so
  `application/sdp;q=0, */*` rules it out and `*/*;q=0, application/sdp`
  does not. Every message of RFC 4475 §3.2 to §3.4 is now fed to a user agent
  in the test suite and held to what the RFC says goes back on the wire.
- **An answered call that was addressed to no account names a `Contact`.**
  The 180 and the 200 for an INVITE that matched no account carried an
  empty `Contact` field, which is not a SIP message at all; they now name the
  address and transport the INVITE arrived on.
- **`SipralAccount.registerAndWait` no longer risks hanging on, or wrongly
  matching, a later, unrelated registration change.** It sent the REGISTER
  and only then subscribed to `SipralClient.events`, so a terminal
  `REGISTRATION_CHANGED` for that account arriving in the gap -- and it
  can, within microseconds of the request going out -- was missed outright,
  leaving the wait to catch whatever that account's *next* registration
  change happened to be: a periodic refresh, a retry. It now subscribes
  before sending. The Kotlin idiomatic layer's `SharedFlow`-backed event
  streams (`SipralClient.events`, `SipralCall.events`, and `digits`) never
  replay a value to a subscriber that starts late, buffered or not, so the
  fix is ordering, not buffering; the same ordering bug in
  `IdiomaticCheck.kt`'s own untargeted wait for an incoming call is fixed
  the same way, through a new `SharedFlow<SipralEvent>.awaitNext` that
  subscribes before running the action that is expected to cause the event.
- **A resume asked for while the hold was still on its way is no longer
  accepted and lost.** `hold` and `resume` compared the request against the
  hold state last agreed, which a hold whose re-INVITE had not been answered
  yet had not moved, so a resume in that window answered `Ok`, sent nothing,
  and left the call held with nothing said. Both are now measured against
  where the call is headed and, while another session change is running in
  either direction — including an offer of ours whose answer the ACK has
  still to bring (RFC 3264 §4) — wait and go once it is over, as RFC 3261
  §14.1 requires. `reoffer` and `change_formats` still answer
  `ChangeInProgress` in that window, and an ACK without the answer it owed
  no longer leaves the call waiting for one.
- **Two re-offers that cross now both go through, and a refused offer no
  longer skips an `o=` version.** The end waiting out a 491 refused the far
  end's retry with a 491 of its own, although its INVITE was no longer in
  progress (RFC 3261 §14.2), so when both ends pressed hold at once only one
  hold ever arrived. That retry is now answered, and this end's own retry
  waits for a far-end change still being answered. A hold or resume retried
  after the far end's change is written again from the session that change
  left, one version past the answer, instead of offering the old codec back;
  an application's description is not sent over it and is reported as
  `SessionChangeFailed`. A session-timer refresh told to wait goes again as a
  refresh, with its `Session-Expires`, instead of as a plain re-INVITE that
  asked for no timer and was reported as a session change. `reoffer`,
  `change_formats` and `hold` refused before sending (a change in progress, a
  call that cannot carry one) no longer use up a version, so the next offer
  is one past the last one sent (RFC 3264 §8).
- **The .NET binding no longer crashes the whole process over an
  exception thrown from an application's own `EventReceived` or
  `FrameDecoded` handler.** Both ran synchronously on the library's own
  worker threads with nothing catching what they threw, so a bug in one
  subscriber's handler unwound back into the native call the thread was
  inside of and took every stack and call in the process down with it.
  Now caught at the point each is invoked, the same "the callback does
  not unwind" contract already documented for the Kotlin binding.
- **The Android helper no longer leaves a call up that has ended, and
  `sipral.aar` compiles in an ordinary Android project.** A connection
  declined with a reason or a text reply (`onReject(int)`,
  `onReject(String)`) now declines the call instead of ringing on; a
  confirmation that lands after a hang-up no longer shows the call active
  again; a connection the framework creates after its call ended is told why
  it ended rather than that something failed; and `TelecomBridge.endAll`,
  which the sample now calls before closing its client, ends every call so
  that none outlives the client. `sipral.aar`'s classes are compiled for
  Kotlin 2.2, which the Android Gradle Plugin 9's own compiler reads; for
  Kotlin 2.4 they were refused. The build image pins command-line tools
  22.0, because 23.0's `sdkmanager` downloads an unpinned tool at build time
  and uploads usage metrics from it, and `android.sh` now runs the helper's
  unit tests and checks the licence of every artefact Gradle resolves for
  the helper, the sample and those tests.
- **`sipral_headless::encode_control` no longer writes a control frame the
  far end will refuse.** It wrote up to the sixteen bits of the length
  field, while every `Decoder` refuses a control frame past
  `MAX_CONTROL_PAYLOAD` (8192 bytes) as final and drops the connection.
  `IncomingCall` carries the caller's address and display name straight off
  an INVITE, so a stranger could make one that long. The encoder now
  refuses what no decoder would read, with nothing written.
- **`DecodeError::is_final` says which decode errors end a connection.**
  Only a length past the bound does; an audio frame of the wrong size or a
  control message that does not decode was still a whole frame, and the
  decoder reads on past it, which nothing said before.
- **`HeadlessSession::speak` puts a frame out on every tick, silence
  included.** It skipped `MediaSession::capture` whenever the agent had
  nothing queued, so the RTP timestamp stopped while the call went on, a
  digit asked for with `DtmfSend` by an agent that was not talking never left,
  and a listening agent's far end got no RTP at all.
- **A barge-in drops the agent's audio already resampled for the codec.**
  Up to a frame of the interrupted sentence played ahead of whatever the
  agent said next; `Session::barge_ins` now counts every barge-in and
  `HeadlessSession` discards its own share the next time it fills a frame.
- **A codec change mid-call no longer ends speech early or drops the
  caller's audio.** `HeadlessSession::set_codec_rate` rebuilt everything on
  every call — a hold or a resume with the same codec included — restarting
  the voice-activity detector, whose lost hangover reported the next quiet
  frame of a word as `speaking: false`, and discarding caller audio already
  at the socket's rate. It is now a no-op at the same rate, the detector
  reads the socket's fixed rate, and only what is at the old codec rate
  goes. An empty frame no longer reports `speaking: true`.
- **The socket-framed agent survives a hostile caller and a misbehaving
  agent, keeps real time, and acts on `BargeIn`.** In the lab, against
  `crates/sipral/examples/headless-socket-agent.rs`: one 3.4 KB INVITE whose
  display name was escaped control characters made an `IncomingCall` the
  reference agent refused, and the application exited — the caller's address
  and display name are now cut to fit; one control frame that was not JSON
  also made it exit — it now answers on the error channel; its media tick
  replayed every tick since start-up once a call was answered, 188 RTP
  packets a second instead of 50 for a call taken 40 seconds in — it now
  restarts from now when it falls behind; and a write to an agent that
  stopped reading blocked the whole loop, so the call's BYE was never
  answered — the socket is now written from its own thread, what it has no
  room for held in order and the oldest audio dropped past a second, never a
  control message. It also ignored `BargeIn`, never reported the bridged
  call's `ringing`, and left the protocol session's state at ringing for the
  whole call.
- **`org.sipral.idiomatic.SipralCall.close()` no longer races
  `SIPRAL_EVENT_KIND_MEDIA_STARTED`.** Closing a call the instant it is
  placed, or the instant its far end hangs up, could land between the poll
  thread minting a `sipral_call_media` handle and this call handing it to
  the application: the raw socket `close()` had already released was then
  handed to that mint's own `SipralMedia`, whose constructor threw
  uncaught out of the event-delivery path, and, when the mint itself won
  the race instead, its handle was minted and reachable from nowhere. Both
  sides of that race are now serialized, and a `SIPRAL_STATUS_BUSY` from
  the mint colliding with a concurrent signalling call is retried the same
  way every other call in this layer already retries it.
- **The local conference's `MediaEvent::Unjoined` now reaches the C ABI.** A
  call ending while its partner is still joined told the facade, but the
  translation to `sipral_event_t` dropped it silently; an application driving
  the pair through `sipral_media_mix` alone learned only from a later
  `SIPRAL_STATUS_WRONG_STATE`. It now arrives as
  `SIPRAL_EVENT_KIND_MEDIA_UNJOINED`, naming the surviving call.
- **.NET trusts a certificate its one pinned authority signed.** `turnTrustedCertificates` built its chain with revocation checked online, which a private authority's certificates never pass, having no revocation list; revocation is now left unchecked, as `SslStream` itself leaves it.
- **An INVITE retried with credentials is held to `max_dialogs`.** A proxy's `407` gives the call's room back, and the authenticated retry went out without looking, so a call placed in between took the stack one past its ceiling; the retry is now refused like a call placed afresh, the challenge kept for when there is room.

- **A pause at the start of a DTLS-SRTP call no longer costs half a second of
  delay.** FreeSWITCH sent two packets, paused while it keyed, and resumed
  with a timestamp that had not moved, so the jitter buffer read the pause as
  path delay and sat at its 500 ms ceiling for over a minute; the first packet
  of a talk spurt that looks later than the target allows for now starts the
  delay measurement again. Asterisk resumed fifty-one sequence numbers further
  on, and playout started on the gap, concealed a second of nothing and kept
  it as delay; a buffer that has run dry now starts at the first packet it
  holds and counts the gap as loss. After a resume, when Asterisk's first
  packet under its new keys was refused and its second sat alone, too few to
  start on, playout started on that packet and concealed the second behind
  it; a packet stranded in front of a gap longer than the target is now
  dropped unplayed, and packets held together are still all played.
- **The lab's mailbox count goes up once per call.** `MinivmMWI()` publishes
  a count rather than adding to one, and the lab's hangup handler published
  1 every time, so the first driver's flow left the count where the second
  driver's flow needed to see it climb from; the handler now keeps a count of
  its own.
- **A request challenged with a nonce another request already answered is
  answered too.** A server that draws its nonce from the clock, as Asterisk
  does, challenges a SUBSCRIBE sent in the same second as a REGISTER with the
  nonce the REGISTER answered, and the digest cache read that as the
  password refused and sent nothing more, so the subscription ended refused.
  RFC 3261 §22.1 forbids re-sending credentials "that have just been
  rejected", and a request that carried none had nothing rejected: the nonce
  is now answered again, its `nc` counting on, and a refusal still stands
  once a request that carried the answer is refused with the same nonce.
- **A DTLS-SRTP call survives a far end that starts its handshake over.**
  Asterisk begins a new association on every re-negotiation — a fresh
  ClientHello on a hold, `a=connection:new` on the resume — and the running
  connection took the ClientHello and ignored it, so the call went silent from
  the first re-offer on. The lab's new DTLS flow found it. RFC 6347 §4.2.8 is
  followed now: the new handshake runs beside the old one, the old keys carry
  the call until it finishes, and each direction then moves to its new key the
  way a re-key does. One that never finishes is dropped silently.

- **Seven defects an adversarial review of DTLS-SRTP found, all of them
  availability or interoperability; none let media be read, forged or
  replayed.**
  - Without ICE, the handshake's latch closed on the first datagram whose first
    octet was 22, from anywhere: one packet from a stranger kept a call from
    ever keying. Only the host the signalling named may close it now.
  - This end's flights went to the signalled port whatever port the far end's
    records came from, since RTP cannot latch before there are keys. They go to
    the latched address now.
  - The latch stayed where it was when ICE selected another pair or a
    re-negotiation moved the far end, and dropped its records as a stranger's.
  - A certificate renewed between a call's offer and its answer was the one its
    handshake presented, not the one its offer named, so the far end refused
    it. A call keeps the certificate it first described itself with.
  - A re-negotiation that changed a running stream's kind of keying — clear,
    SDES, DTLS — was adopted, leaving SRTP sent to a far end expecting RTP or
    the reverse, and the plan later certificates were compared against empty.
    It is refused as the new `MediaError::KeyingChanged`: 488 to a re-offer,
    not adopted from an answer.
  - A forged epoch-0 retransmission kept `sipral_dtls::Connection` from ever
    giving up on a handshake: answering one postponed the deadline without
    spending an attempt. It is answered and the deadline stays.

- **A hold on a secured call reaches the end that asked for it.** The far
  end's answer to it came from the user agent, which wrote the stream without
  its `a=crypto` line under SDES and without `a=fingerprint` and `a=setup`
  under DTLS-SRTP. The end that held the call then failed its own
  negotiation — `CryptoMissing` — and its media never went on hold, while on
  the wire the answer had withdrawn the key or the certificate. This was the
  gap `docs/05-media.md` named for SDES; under DTLS-SRTP it caught every hold.

- **A call held here stays held through the far end's re-offer.** The facade
  answers every re-offer it is handed `sendrecv`, narrowed only by the offer,
  so a codec change or a session refresh from the far end took a held call
  off hold on the wire — and this end's stream started sending into a call its
  user believed was on hold, while `hold_state` still said "held here".
  `UserAgent::accept_reoffer` now narrows any answer to the hold this end asked
  for, and leaves one with nothing held here byte for byte.

- **A call the application describes is left to the application.** The
  engine keeps a record of every incoming call, and on one the application
  had answered with a description of its own it refused every re-offer
  handed up with 488 before the application saw it — the application's own
  `accept_reoffer` then failed for want of a request to answer — and after a
  plain hold it opened a media stream of its own on the call, with its own
  SSRC and RTCP, beside the one the application was running. It acts only on
  calls it describes now.

- **A certificate written differently is not a new certificate.** The check
  that refuses a moved DTLS certificate compared the `a=fingerprint` lines in
  order and as written, so a far end repeating the same certificate with its
  lines in another order, in lower case or with one twice had the
  renegotiation refused. They are compared as the set they name.

- **`UserAgent::accept_reoffer` answers a refresh with its timer, and survives
  a bad answer.** The 200 carried no `Session-Expires` (RFC 4028 §9), which
  every answer the user agent writes itself does. And an answer that did not
  parse had already consumed the pending request, so it could no longer be
  answered or refused, and the re-INVITE ran on unanswered until it ended the
  call.

- **A resume written by hand no longer leaves the call reading as held.**
  `UserAgent::reoffer` kept the hold flag it had before the re-offer instead
  of reading it back out of what it sent, so a description that resumed a held
  call left `hold_state` saying "held here" — and the next `hold` found the
  call held already, sent nothing, and returned success.

- **A re-offer naming no codec this call holds is refused, not accepted.** The
  engine answered one with its stream refused, which RFC 3264 §6 allows and
  which left the call without audio for the rest of its life over a codec the
  far end had merely proposed. It is answered 488 now (RFC 3261 §14.2) and the
  session stands; an offer that took the stream away itself is still answered.

- **The peer's ICE password no longer reaches a log.** `a=ice-pwd` is
  redacted in `Attribute`'s `Debug` beside the `a=crypto` master key, and
  `sipral_nat::ice::RemoteIce` — the parsed form of the same value — writes
  its own `Debug` instead of deriving one. ICE signs every connectivity check
  with it (RFC 8445 §7.1.2.3), so a reader who has it can answer checks as
  either end and steer the media to itself. Both are now named in the gate
  that asserts a type holding key material never derives `Debug`, which
  previously listed four types and now lists six.

- `Capabilities::srtp_keying`, `crates/sipral-ffi/src/event.rs` and
  `THIRD-PARTY-NOTICES.md` each still described the tree as it was before
  DTLS-SRTP was wired in: a documented claim that DTLS is absent from the
  keying list, a doc comment cut in half by an item inserted into the middle
  of it, and a notice saying nothing that ships depends on `sipral-dtls`.

- **DTLS-SRTP keys a call.** Twelve thousand lines of handshake had been
  written, tested and depended on by nothing; this is the joint. A catalogue
  set to `SrtpPolicy::DtlsOffered` or `DtlsRequired` writes
  `UDP/TLS/RTP/SAVP` with `a=fingerprint` and `a=setup`, the handshake of RFC
  5764 runs on the call's own media socket, and the keys it exports open the
  same SRTP contexts an `a=crypto` line would have. Which transform it opens
  is the handshake's to choose rather than the signalling's, so the new
  `MediaEvent::Secured` carries it. In C: `SIPRAL_SRTP_DTLS` and
  `SIPRAL_SRTP_DTLS_REQUIRED`, `SIPRAL_FEATURE_DTLS_SRTP`,
  `SIPRAL_EVENT_KIND_MEDIA_SECURED`, and a fifth media call,
  `sipral_media_poll_transmit`, which **must** be drained or the handshake
  never leaves.

  What is new under it is a third state for a stream. SDES keys a stream
  before its session opens; DTLS-SRTP agrees in the signalling that a stream
  is protected and produces the keys a round trip later, so `RtpSession` now
  has `awaiting` between "in the clear" and "keyed". Nothing goes out and
  nothing arriving is believed while it holds — `BuildError::NotKeyed` and
  `Discard::NotKeyed` — and the refusal is decided before the packet is
  written rather than after, so a refused frame never sits in the caller's
  buffer in the clear. `MediaSession::is_encrypted` reads that state rather
  than the plan, so for the length of a handshake it says no, because for the
  length of a handshake nothing has been encrypted.

  Four failures that would otherwise have been silent are refused by name. Two
  `a=setup` values RFC 4145 §4.1 has no row for, because two ends that both
  believe they are the server wait for each other until the handshake gives
  up. A call that agreed DTLS-SRTP and not `a=rtcp-mux`, because RFC 5764 §4.2
  would put a second association on the RTCP port. A DTLS server, which has no
  flight to retransmit and would therefore never time out at all — every
  handshake now gets the budget the client's own schedule spends. And a fatal
  alert from an address the call has not heard a handshake record from: an
  alert arriving before the keys exist cannot be authenticated, so without
  that latch one forged datagram would have ended any encrypted call this
  stack placed.

  A re-negotiation that names a different certificate is refused by name
  (`MediaError::DtlsFingerprintChanged`) rather than ignored. RFC 5763 §6.6
  asks for a new DTLS association there and this does not start one; refusing
  keeps the session on keys both ends still agree on and tells the
  application, where carrying on would have left the media flowing as though a
  certificate nobody checked had been checked.

- **The demux of RFC 7983 §7 tells DTLS from the media beside it.**
  `sipral_nat::Demux` classified two protocols on the first two bits and put a
  DTLS record in `Other` with the rest of the noise. It now reads the first
  octet as the RFC's own table does — 0 to 3 STUN, 20 to 63 DTLS, 128 to 191
  RTP or RTCP — which also tightens STUN from sixty-four values to the four it
  actually uses.

- **Every `a=fingerprint` of a description is carried, not the first.** RFC
  8122 §5 lets a description name one per hash function so that a peer which
  knows only one of them can still check it, and `Keying::Dtls` had room for
  one: a call could die over which hash the other end happened to write first.

- **A destination the application is asked to resolve, and the answer that
  moves it.** Nothing below this boundary owns a resolver, for the same reason
  nothing below it owns a socket, so a dialog whose route set and remote target
  name a next hop that is not where its requests are going now says so:
  `SIPRAL_EVENT_KIND_RESOLVE_NEEDED` — number 29, held for exactly this since
  before it was written — carries the host as the URI spells it, the port the
  URI gave or zero, the transport it named or zero, and a handle for the dialog
  itself. `sipral_stack_resolved` is the answer, and it takes a **list** in RFC
  3263 §4.3 priority order rather than one address: the first one this stack
  can already reach is taken and the rest are kept for it to try in turn when
  that one fails, which is what makes failover possible at all.

  A protocol is found, never opened. An address on one nothing has bound is
  passed over, and answering again after `sipral_stack_transport_bind` is how
  it gets another chance — so an answer that moves nothing is
  `SIPRAL_STATUS_OK`, not a failure, and so is one for a dialog that has ended.
  Nothing times out: ignoring the request leaves the dialog on the flow its
  first message travelled, which RFC 3261 §8.1.2 allows as an alternate address
  and which is the only thing that survives a NAT, so there is no second event
  saying the first went unanswered.

  `sipral_account_retarget` is the same question one layer up, and was the
  other half of the ABI that had been specified and never built: it points an
  account's next REGISTER at another address for a registrar named by a record
  with more than one target, keeping the binding's `Call-ID`, its sequence and
  its credentials, so the registrar reads it as the same device continuing
  rather than a second one arriving.

  The dialog handle is the seventh kind of handle and the only one the library
  mints rather than the application asking for: it is named rather than
  inserted, so a dialog asking again on every target refresh keeps the handle
  it was first given, and it is forgotten with the call it belonged to.

- **A registration that survives the process, through C.**
  `sipral_account_freeze` writes an account's binding into a buffer the caller
  sizes by asking — a null buffer and a capacity of zero get
  `SIPRAL_STATUS_BUFFER_TOO_SMALL` with the length, which is the question and
  not a failure — and `sipral_account_thaw` reads it back on a process that was
  not there when it was written. The account comes up
  `SIPRAL_REGISTRATION_STATE_RESTORED` rather than registered, because a
  binding nobody has confirmed since the machine slept is a belief and not
  evidence, and the refresh it books is what turns one into the other. How long
  the snapshot sat unused is the caller's to say: nothing here reads a wall
  clock and a monotonic instant does not survive the process that minted it.

  The bytes are opaque across this boundary and their layout is not part of the
  ABI — the version rule only stays enforceable while the library is the only
  reader. The three ways a thaw is refused are three statuses, so a caller can
  tell them apart without reading the sentence: a snapshot a newer build wrote,
  an account that does not register at all, and bytes that are damaged or are
  another account's. The account is left exactly as it was in all three.

  `sipral_stack_cold_start` and `sipral_account_time_to_ready` ship with them,
  because neither is any use alone: without a declared launch there is nothing
  to measure from, and the reader could only ever answer "nothing". The number
  is a product requirement rather than a curiosity — how long a queue rings each
  agent before skipping to the next has to be longer than it, or a phone that
  was asleep is skipped every time and its owner is told the queue was quiet.

- **The codec order is a property of the call, not of the process.**
  `sipral_call_config_t::codecs` overrides `sipral_stack_config_t::codecs` for
  one call, the same comma-separated list of names, refused the same way for a
  stray comma, a name given twice, or a name this build has no encoder for.
  Two accounts on two codec policies no longer need two stacks. The override
  is derived from the stack's catalogue rather than from a fresh one, so the
  frame length, named events, multiplexing and SRTP policy the call said
  nothing about are the ones the stack was configured with, and nothing shared
  is mutated: a second call off the same stack still offers what the stack was
  configured with. It composes with `::srtp`, and it is read on every entry
  point that takes the struct and describes a session — `sipral_call_place`,
  `sipral_call_ring_media` and `sipral_call_accept_transfer` — while
  `sipral_call_consult`, which has no catalogue to apply it to, still refuses
  a name this build has no encoder for rather than accepting what its siblings
  would refuse.

- **Why each codec lost, through C.** `sipral_media_codec_candidate_count` and
  `sipral_media_codec_candidate_at` walk a call's own codec order and say what
  became of every entry: it won, the far end never named it, or the far end
  named it and something this end preferred won — with
  `sipral_codec_candidate_t::outranked_by` naming what. Exactly one candidate
  is the one that won, and it names the same codec as
  `sipral_media_info_t::codec`, which is what makes the list an explanation of
  that number rather than a second opinion about it. The list is what the
  negotiation recorded when it recorded it, never recomputed: a second run
  against a description that has since been renegotiated would disagree with
  the first in exactly the case somebody is debugging.

- **A call announced by a push notification reaches C (RFC 8599).** On a phone
  the ringing screen exists before the call does: the operating system delivers
  a notification, the process gets one run loop to raise a screen, and the
  INVITE arrives some time afterwards, or never.
  `sipral_account_announce` is what an application calls the moment it is
  woken. It refreshes the binding at once, which §4.1.3 makes a MUST for a
  woken agent, and writes back either the announcement — when nothing has
  arrived yet — or the call, when the INVITE beat the notification, which is a
  race the application cannot control. `SIPRAL_EVENT_KIND_CALL_ANNOUNCED` says
  which announcement an INVITE answers and is queued immediately before the
  incoming-call event for it, so the screen is named before the call is;
  `SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING` says one never came, which is a
  diagnosis rather than an error — a wake-up chain has a notification service,
  a proxy, a bucket timer and a radio in it, and this is the only place that
  says which end gave up.

  `sipral_account_config_t` carries the four push members it takes to ask for
  any of that: `push_provider`, `push_prid`, `push_param` and
  `push_wakes_itself`, appended at the tail with the pinned minimum unmoved.
  They go on the REGISTER's `Contact` and on no other request, because §4.1
  says a `pn-prid` in the `Contact` of an INVITE hands the far end a token that
  wakes the device whenever it likes. `sipral_account_push_echo` reads §8.2's
  `Feature-Caps` answer back: a phone that suspends itself believing the
  network will wake it, when the network never said so, is a phone that stops
  ringing.

- **Subscriptions and the busy lamp field reach C.** Everything RFC 6665 needs
  was already written and tested — the transaction, the dialog, timer N, the
  refresh at a fraction of what the notifier granted, the fork that turns one
  SUBSCRIBE into two subscriptions, the retry with a fresh `Call-ID` — and none
  of it could be reached from an application. `sipral_account_subscribe` mints
  a subscription, which is a handle of its own because a desk phone holds
  thirty of them on one account, and `sipral_subscription_end` gives one up.
  Two events report what becomes of it: `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED`
  for the state, which is what a lamp goes grey on, and
  `SIPRAL_EVENT_KIND_NOTIFIED` for a notification arriving, which is what it
  changes colour on — with the NOTIFY whole, for every package this ABI has no
  reader for.

  For `dialog`, it does have one: `sipral_subscription_lamp` is RFC 4235
  §3.7.2's virtual state machine over every dialog of the watched extension, in
  one call and one number, and `sipral_subscription_dialog_count`, `_at` and
  `_text` are for showing who is on the call as well. Text is copied into the
  caller's buffer rather than pointed at, because a pointer into this library's
  memory is one a caller could outlive. `sipral_capabilities` sets
  `SIPRAL_FEATURE_SUBSCRIPTIONS` now that all of it is reachable — the bit was
  deliberately clear for two phases while the feature existed underneath and
  the ABI could not reach it.

- **An INVITE can be refused before it has had any effect, from C.**
  `sipral_stack_screen` installs a policy that is asked about every INVITE
  before ringing, before `SIPRAL_EVENT_KIND_INCOMING_CALL`, and before a call
  handle exists for anyone to answer or reject; what it refuses is answered
  with the status it named and forgotten, and what it takes arrives exactly as
  it would with no policy at all. The answer is a SIP status code rather than a
  flag, and acceptance is `SIPRAL_SCREEN_ACCEPT` — 200 — so that zero, which is
  what a binding hands back when the application's listener threw and what a
  caller who filled nothing in leaves behind, refuses rather than admits.
  `sipral_stack_invite_limit` sets the token bucket underneath it, asked before
  the policy is, and four `screened_*` counters say how many INVITEs each floor
  refused. A refusal is a failure status and nothing else: a 1xx would leave
  the caller ringing at a call this end had already forgotten, with a server
  transaction and an early dialog nothing could ever reach, so a policy that
  names one has not made a decision this ABI can carry out and is answered the
  way an answer that never arrived is. The policy runs with the stack's own lock held, which is the
  opposite of the event callback and is why it must not call back into the
  stack it was given — a call that tries is answered `SIPRAL_STATUS_BUSY`
  rather than allowed to deadlock.

- **The generator can print a callback taken as a parameter of its own.** A
  callback followed by a `*mut c_void` was one listener when it was a member of
  a struct going in; it is one listener as a pair of parameters now too, which
  is the sixth and last of the conventions `tools/abi-gen/src/model.rs` reads
  off a declaration. C, Swift and C# hand the pair through as it comes; Kotlin,
  whose listener never leaves the JVM, takes a listener and hands over the key
  it is kept under, and the shim makes the function pointer and the user
  pointer out of that key. A listener installed this way is handed to the
  handle it was installed on, so installing a second policy releases the first,
  installing none releases what was there, a call that failed or threw leaves
  the handle what it had, and destroying the handle releases whatever is left.
  The wrapper holds the keeper's monitor across the call, so that two threads
  installing at once cannot record their keys in an order the library did not
  install them in.
  A callback declared without the pointer after it is refused by name rather
  than printed as a listener nothing could ever reach again.

- **A stack can hold more than one transport, and an account or a call can say
  which.** `StackState` kept exactly one, and the header said so: the constant
  for it was documented as "for now always". `sipral_stack_transport_bind`
  takes a protocol and hands back the id it bound, `sipral_account_config_t`
  and `sipral_call_config_t` gained a `transport` where zero still means the
  main one, and two accounts can now live on two transports in one stack —
  which is the test that proves it, each account's REGISTER leaving on its own.
  With it, reserved event 18 becomes `SIPRAL_EVENT_KIND_TRANSPORT_WANTED`: a
  request too large for a datagram (RFC 3261 §18.1.1) is not sent and the
  event names where it was going and over what protocol, the application binds
  one, and the same request leaves on it. A call's `transport` is read only
  together with its own `destination`, because a call that names neither is
  already the account's to route, and a value that is silently read for
  nothing is worse than one that is refused.

- **A resolved answer can name the protocol, and the addresses after the first
  are kept.** `Endpoint::resolved` took addresses and nothing else, so an
  answer that came from an SRV record naming TCP could not say so and the
  dialog kept sending the way it already was. It takes the protocol now, takes
  the first address there is a bound transport for, and keeps the rest: a
  transport failure or a timeout on the current one moves to the next without
  a second round trip. A refusal at the SIP layer does not — a 404 from the
  right server is not a reason to try a different server.

- **`UserAgent::retarget`**: an account's registrar address can move — a
  second SRV target, a failover, an operator's migration — without losing the
  binding, the credentials or the handle, and without restarting the Call-ID
  or the sequence number. An attempt already in flight is superseded rather
  than left to time out, so the new address is tried now instead of after the
  back-off; the superseded transaction's late answer is reported as unclaimed
  rather than misread as this attempt's.

- **The binding generator can print a callback that answers.** A callback was
  modelled as arguments and no result, which was true while the only one was
  the event callback and is not true in general: a policy callback is the
  library asking the application a question it must answer before going on.
  The declaration can name what a callback answers with now, and all four
  languages print it — including the JNI shim, where the listener's answer is
  read back across the boundary, and where a listener that threw has its
  exception cleared and the declared fail-closed value returned in its place.
  Every existing declaration prints byte for byte as it did.

- **The lifecycle a phone actually lives is reachable from C.** A stack could
  be suspended, woken, moved between networks and told its interface or its
  resolver was gone — in Rust. From C none of it existed, which meant
  `SIPRAL_REGISTRATION_STATE_UNVERIFIED` and `_RESTORED` were states a C
  application could read and never cause: it could be told a binding was no
  longer evidence, but had no way to say the machine had slept.
  `sipral_stack_suspending`, `sipral_stack_resumed`,
  `sipral_stack_network_changed`, `sipral_stack_interface_lost`,
  `sipral_stack_name_resolution_lost` and `sipral_account_rebind` are those
  words, and `sipral_stack_suspending` hands back what the stack found when it
  was told — how many bindings stopped being evidence, how many subscriptions
  and calls were open. Reserved event 28 becomes
  `SIPRAL_EVENT_KIND_RECOVERY`, raised when the ladder settles: a registrar
  proved the path again, or every rung was climbed and none worked.

- **A call's own story, and the whole diagnostic document, can be read from
  C.** `sipral_call_record_json` and `sipral_stack_diagnostics_json` hand back
  the JSON `docs/14-diagnostics.md` describes, in the buffer convention the
  rest of this header already uses: call once to learn the length, once to
  take it. And the signalling can be recorded for replay —
  `sipral_stack_recording_start` and `sipral_stack_recording_stop` — with the
  guarantee `docs/18-replay.md` makes held where it matters: a recording is
  only ever offered what arrived, never what this end sent, so the key this
  end negotiated is not in its own recording. A test places a real encrypted
  call from C and reads the finished recording back to show it.

- **`docs/20-security-model.md`**: what a hostile peer, a rewriting proxy, a
  flood and a replay can each do, what refuses them and where that lives, what
  the keys are and are not protected by, what this stack deliberately does not
  do — no sockets, no clock, no thread, no signalling TLS of its own — and,
  named plainly, what has had no security reading yet.

- **A request that cannot be read is answered 400, and named.** RFC 3261
  §8.2.x has a UAS that detects a syntax error answer 400 with a phrase
  identifying the problem. `RawMessage::validate` has always been able to find
  those faults, and its own documentation said the question is asked "once, by
  whoever is about to answer" — but nothing on the live path asked it. A
  framed message with, say, a `CSeq` naming a different method than its start
  line went straight to the handlers, each of which read the field it needed,
  failed, and dropped the message without a word; the peer retransmitted into
  silence. It is asked now, before a transaction is matched to the request,
  and the answer names the field: `400 Bad CSeq`. An ACK is dropped rather
  than answered, because nothing answers an ACK, and a request whose own `Via`
  cannot be read is dropped too, because there is nowhere to send an answer.
  Responses are unchanged: §18.1.2 already discards one whose `Via` is not
  ours, and each reader of a response handles the field it reads.

- **A network change that changed nothing no longer announces a recovery.**
  A stack told about the same network twice decided, correctly, that there was
  nothing to do — and then raised the event that says a recovery settled,
  because the no-op and the real thing pushed the same lifecycle state. An
  empty ladder says so only when the state moved now. A device that reports
  its network on every wake would otherwise have announced a recovery it never
  made.

- **An expired subscription no longer claims it is worth retrying**.
  `SubscriptionEnd::is_worth_retrying` answered true for `Expired`
  while the timer path ended such a subscription for good, and the two never
  met because that path called `end_subscription` directly rather than going
  through the one function that asks. The lapse goes through it now, so the
  enum is the single answer for every reason there is, and `Expired` sits
  with the refusals: a granted lifetime that ran out is this end's own doing,
  and what follows it is a fresh SUBSCRIBE rather than a resumed one.

- **A REFER's transfer seat is freed on every way it can end**. A REFER that
  timed out or whose transport failed left the
  call unable to transfer again for good: the core raises
  `TransactionTerminated` before `RequestFailed` on both paths, so the
  release that ran on the answer no longer found the transaction it keyed
  on. The seat is released as the transaction itself retires unanswered now,
  before the answer that never carried a status is even looked for. A NOTIFY
  that terminates the subscription frees it too when its body is a 100 or
  unreadable, as RFC 3515 §2.4.4 lets the first NOTIFY be.

- **The 415 branch `on_dtmf_event` could no longer reach is gone**.
  `names_a_dtmf_body` already turns back every `Content-Type`
  but the two this stack reads before a body is parsed, so the `Accept`
  header a 415 used to add named a case that could not happen any more;
  removed along with the constant it built.

- **A queued digit whose own INFO could not be sent is reported**.
  `request_in_dialog` refusing a digit behind the one just
  answered used to vanish silently; it is `UaEvent::DtmfSent` with 503 now —
  the status RFC 3261 §8.1.3.1 already stands for a request that never went
  out — and the digits still waiting are discarded the same as for any other
  failure mid-sequence.

- **`Duration=0` and no duration at all read apart again, at the facade**.
  `MediaEvent::DigitReceived::held` is
  `Option<Duration>`: `None` for the INFO body that never carries one,
  `Some(Duration::ZERO)` for a peer that said `Duration=0` on the other. No
  ABI change — `sipral_media_event_t::held_ms` still reads zero for both, and
  its documentation now says so.

- **A call's SIP INFO digit queue is bounded at sixty-four** — the digit in
  flight and everything waiting behind it. A
  string that would carry a call past that many is refused whole, before
  anything of it is sent, with the same error an invalid digit already gets.

- **Four follow-ups of DTMF by SIP INFO**. An INFO whose
  `Content-Type` is not `application/dtmf-relay` or `application/dtmf` — RFC
  5168's media control, a vendor Info-Package, one with no body at all —
  reaches the application unanswered again, the way it did before this stack
  began claiming every INFO in a call's dialog by method alone.
  `UserAgent::send_dtmf_info` takes a whole string now, validated as a whole
  before anything is sent, and sends it one digit at a time — each INFO only
  after the one ahead of it has a final answer, so a refusal, a timeout or a
  transport failure discards the digits still waiting instead of racing them
  out of order over UDP, and a string handed over while a digit is still
  unanswered queues behind it; `sipral_call_send_dtmf` hands the string over
  once rather than looping over it. A received `Duration=0` is reported as
  `held_ms: Some(0)` rather than the sending default, because reading how
  long a peer already held a key checks only the ceiling sending also
  refuses, not its floor. And that default is now one constant, a hundred
  milliseconds, `sipral_ua::dtmf::DEFAULT_DTMF_MS`, that RTP, both INFO
  bodies and the C ABI's own `duration_ms` all read, in place of INFO's own
  160.

- **`MediaEngine::ring_with` no longer reports a change that never
  happened.** `settle` re-evaluated the negotiation on every event that
  could plausibly touch it, including the ACK that confirms a call answered
  after early media — which carries no body of its own, since RFC 6337
  §3.1.1 already forbids repeating a description sent reliably — and read
  the absence of anything new as a change anyway. A call rung with media,
  then answered, now reports `MediaEvent::Started` once and no
  `MediaEvent::Changed` for it; a hold, a resume, a moved address or a real
  re-negotiation afterward is still reported, because `settle` now compares
  the plan already running against the one it just worked out rather than
  assuming the second call always differs from the first. The same
  comparison reaches C beyond `ring_with`: a re-offer the stack answers on a
  managed call's behalf used to raise `SIPRAL_EVENT_KIND_MEDIA_CHANGED` every
  time, and now raises it only when the codec, the address or the direction
  actually moved.

- **A BYE is exempt from the per-dialog non-INVITE transaction budget.**
  Sixteen non-INVITE server transactions open on a dialog
  used to get a BYE the same 503 as a seventeenth INFO would, but RFC 3261
  §15.1.1 has the caller consider the session over the moment it sends one,
  whatever answer comes back — so the refusal only left the far end holding
  a dialog this end had already been told was abandoned. A BYE in order now
  reaches the dialog regardless of how many other transactions are open on
  it; one whose `CSeq` runs backwards ends nothing (§12.2.2 answers it 500)
  and, like every other non-INVITE request, is still held to the same
  ceiling of sixteen.

- **Documentation for the per-dialog 503.**
  `docs/09-rfc-index.md` gains the row for RFC 5057, the source for reading
  that 503 as ending only the transaction it answers rather than the dialog
  underneath it. `docs/03-core-signalling.md` says why the refusal carries
  `Retry-After: 1`: the budget behind it frees again as soon as any one of
  the sixteen open transactions retires, which is immediate on a reliable
  transport once it is answered and `64 · T1` after its answer over UDP,
  when Timer J lets it go — at most `128 · T1` for one this end never
  answers itself, since the endpoint's own 408 goes at `64 · T1` and Timer J
  runs after that. Room can reappear at any moment up to that bound, so a
  longer wait would idle an otherwise healthy call for room that may already
  be there.

- **`StackState::farewells` is bounded.** An application that
  never called `sipral_stack_poll_farewell` — a binding built against a
  header from before that entry point existed, among others — kept every
  ended call's RTCP goodbye queued for as long as the stack lived, about a
  hundred bytes per call. The queue now holds at most 256; past that the
  oldest queued goodbye is dropped to make room for the one that just
  arrived, because a stale goodbye is worth less than a recent one, and each
  drop is counted in `sipral_counters_t::farewells_dropped`, appended at the
  struct's tail with `MIN_SIZE` unchanged.

- **Six follow-ups from reading the transaction and dialog layers back
  against RFC 3261.** A
  request inside a dialog was wholly exempt from `max_server_transactions`,
  so a peer already inside a live call could open non-INVITE server
  transactions without limit; each dialog now has a ceiling of its own —
  sixteen at once — past which the request is answered 503 with a
  `Retry-After`, RFC 5057 leaving the dialog itself untouched. A non-INVITE
  server transaction an application never answered held its slot forever,
  because §17.2.2 gives `Trying`/`Proceeding` no timer; the endpoint now
  answers 408 on the application's behalf 64·T1 after the request arrived,
  the same point its own Timer F would have given the client up. The RFC
  2543 fallback key (§17.2.3, a peer with no magic cookie) compared every
  method without the `To` tag the INVITE and every other method are matched
  on, leaving only the ACK's documented exception; it now follows the
  section as written. An ACK for a 2xx was accepted onto a confirmed dialog
  on tags alone; it is now also matched by `CSeq` against the INVITE whose 2xx
  this end sent last, and reported once, so a stale ACK for an earlier
  re-INVITE or a repeat of one already reported is absorbed, while the ACK of
  a call whose PRACK or UPDATE came first is still the one that confirms it. A 2xx a fork had no room left
  for was silently neither reported nor acknowledged; that drop now leaves a
  `dialog.fork.dropped` diagnostic entry. And a merged request (RFC 3261
  §8.2.2.2) — a request with no `To` tag reaching this end a second time by
  another path, almost always a fork — is now answered 482 on a transaction
  of its own rather than handed up again, as a second call for an INVITE or
  a second request for any other method. `EndpointConfig::timers` built with
  `t1` or `t2` at zero, or a `keepalive_interval` of zero, either of which
  would make a timer re-arm at the instant it fired and hang `handle_timeout`
  forever, is refused at `Endpoint::new` rather than accepted and left to
  hang.

- **A stack handle could reach a call, an account or a call's media through
  `sipral_call_hangup`, `sipral_account_remove`, `sipral_media_release` and
  every other entry point that names one of those, because the first stack of
  a process, its first account and its first call were tag 0, slot 0,
  generation 1 alike.** Every table numbered its own slots and its own
  generations from the same start, and the tag alone told two stacks apart, not
  two kinds of thing on the same stack. A handle now carries a four-bit kind —
  a stack, an account, a call, or a call's media — set once by the one function
  in `crates/sipral-ffi/src/handle.rs` that assembles every handle, and every
  lookup refuses a handle of another kind with `SIPRAL_STATUS_INVALID_HANDLE`
  before it looks at a slot, naming the kind it actually got. The generation
  gave up four of its thirty-two bits to make room and is retired rather than
  wrapped when it runs out, the same as before, in a stack's account and call
  tables as in the process-wide ones. What a stack's tables mint with holds a
  share of that stack's lease on its tag, so the tag is never given to another
  stack while anything that could still mint with it exists.

- **A media entry point's declared struct size was checked after the handle
  it was named through had already been resolved**, in `sipral_media_info` and
  `sipral_media_statistics`, and the same was true of the stack handle in
  `sipral_stack_settings`, `sipral_stack_counters` and `sipral_stack_poll`'s
  `result`, although each one's own comment said the size came first. A caller
  whose handle was stale or simply invalid never reached the size check at
  all, so a struct one version behind this build's — the case the size exists
  to answer — was reported as a bad handle instead of
  `SIPRAL_STATUS_UNSUPPORTED_VERSION`. The size is now checked before any
  handle in the same call is looked up, in all five.

- **A signalling call that failed for a reason that had nothing to do with
  time still moved the stack's clock**, because `now_ms` was written down
  before the rest of the call was validated. A refusal for a stale handle or a
  bad argument now leaves the clock exactly where it was: validating `now_ms`
  and committing it to the stack are two separate steps, and the second only
  runs once the call it was read for has actually gone through. Signalling
  also now tolerates a `now_ms` up to fifty milliseconds behind the last one a
  stack saw rather than refusing any backward step at all — it may be called
  from any thread, and two of them reading the same clock a moment apart is
  not the caller losing track of time — while a media entry point, which never
  checked against the stack's clock in the first place, is unaffected.

- **A call kept naming a GRUU after the registration that issued it had
  lapsed.** The `Contact` of a re-INVITE, a session-timer `UPDATE`, a REFER and
  a NOTIFY was the one the dialog opened with, fixed for the life of the call;
  RFC 5627 §4.4 forbids using a GRUU once its registration is gone. Every
  request and response a call builds now reads the account's registration
  state at that moment — the public GRUU while registered and issued, the
  temporary GRUU on an anonymous call, the plain contact otherwise — the way a
  subscription already did. `Supported: gruu` now goes on every INVITE and
  SUBSCRIBE this end sends, a re-INVITE included, and on the 18x and 2xx it
  sends to an INVITE or a re-INVITE, and an incoming `Require: gruu` is honoured rather than answered 420
  once the account has asked its own registrar for one. A REFER's
  `Referred-By` is now the call's own `From`, which RFC 3892 wants for
  identifying the referrer, rather than its `Contact`, which could name a
  temporary GRUU an anonymous call had no reason to hand out.

- **A call's RTCP BYE was built and then dropped, and a slow callback could
  hold every thread on a stack open for as long as other threads kept posting
  behind it.** `MediaEngine::poll_farewell` had nothing in
  `sipral-ffi` or `interop/harness` calling it, so the goodbye RFC 3550 §6.3.7
  owes a call's far end was built at the moment the call ended and then
  discarded with the session it came from; `sipral_stack_poll_farewell` is
  the new stack-level entry point that hands it over, addressed to the far
  end's RTCP socket and named to the call it belonged to, and the harness now
  sends one from its own media socket on every call it ends. And the queue
  behind `sipral_stack_poll`'s event callback grew without bound while a slow
  callback ran and other threads kept posting: it is now capped at 4096
  waiting deliveries, with the excess dropped and counted in the new
  `sipral_counters_t::events_dropped` rather than queued or blocking the
  poster, and one delivery pass now hands over only what was already waiting
  when it began, leaving anything posted during it for the next pass instead
  of holding the delivering thread open to chase it — and a poll whose pass
  left something waiting answers a deadline already due, so a caller that
  sleeps until input or the deadline does not strand it.

- **On Windows, a saved device choice now falls back when the headset is
  unplugged, not only when the machine has never seen it.**
  `DeviceChoice::Preferred` fell back only when `GetDevice` said the identifier
  was unknown, but Windows keeps unplugged, disabled and absent endpoints in its
  registry, so recovering from a pulled headset failed at `Activate` instead of
  landing on the system's route; it now asks `IMMDevice::GetState`. Three more
  corrections in `sipral-io-wasapi`, whose tests now run on Windows:
  `Start`, `Stop` and `Reset` answering `AUDCLNT_E_DEVICE_INVALIDATED` now
  report `StreamEvent::DeviceLost` and end the audio thread, so a headset
  pulled while the stream was stopped is reported at the next start, and a
  start or stop asked once a loss is written down answers `Error::NoDevice` at
  once instead of waiting two seconds on a loop already left; a
  `start`/`stop` now takes only the answer sent under its own ticket, so the
  late answer to a command that timed out is not reported as its own; and a
  device format whose extension is longer than `WAVEFORMATEXTENSIBLE`'s is
  copied with `cbSize` cut to the 22 octets actually copied, rather than
  telling `IAudioClient::Initialize` to read past a stack value.

- **A CoreAudio stream took its render-to-capture delay and its device-loss
  check off one device object, while the voice-processing unit plays to one and
  captures from another.** The capture half was read off the speaker's absent
  input side at the speaker's rate, and an unplugged microphone went
  unreported. Each half is now asked of the device the unit reports for it
  (`Stream::capture_device` is new), losing either is `DeviceLost`, the silence
  flag goes only on buffers that were zeroed, and a ragged
  `kAudioDevicePropertyStreams` size is no longer cut short.

- **The SDP fuzz target could report a crash that was not one.** It wrote a
  parsed description back out and asserted the result read back in under the
  same `sdp::Limits::DEFAULT` it started from, but `to_bytes` always closes a
  line with CRLF while `parse` tolerates a bare LF — so a description close
  to the 16 KiB body limit and built with bare LF grows by one octet per line
  once every line gets its `\r` back, and the re-parse failed with
  `BodyTooLarge` on an input the real parser had already accepted. The
  target now re-parses under a body limit doubled plus one, which is always
  enough for that growth since it cannot exceed the input's own length, and
  every other bound is left at the default: the property under test is that
  writing a description does not change what it means, not that its
  canonical form obeys the size cap a wire policy puts on a stranger's bytes.
  The answer the target builds to that offer was read back under the default
  limits too, and it is not a copy of the offer: it repeats the offer's `t=`
  and `r=` lines, media types, transports and kept formats, adds an origin, a
  connection and a direction line of its own, and writes a four-digit port
  where the offer's `m=` line may have had one digit. So an offer within the
  limits could be answered past the body limit or past the line limit, CRLF
  or not. The answer is now read back under three times the body limit and
  four octets more per line, each shown enough in the target, with every
  count left at the default.
  `crypto` and `replay` round-trip the same way but enforce no size limit of
  their own, so neither is exposed to this; `builder` re-parses the exact
  bytes its own `build()` already checked, so there is nothing left to grow.
  Three regression seeds are committed to `fuzz/corpus/sdp/`: a bare-LF
  offer at the body limit, and two offers whose answers cross the body and
  the line limit.

- **A repeated RTCP BYE could pull the group below the local participant, and
  the first RTCP report was never actually randomised.** (a) `RtpSession`'s
  BYE handling called `IntervalTimer::remove_member` and `remove_sender`
  again for a source it had already removed, because nothing recorded that
  it had left; a peer repeating its BYE — a retransmission, or a duplicate
  the network made — drove `members` to zero, and reverse reconsideration
  (RFC 3550 §6.3.4) pulled the next report to the instant the repeat arrived.
  `Inbound::departed` now marks a source gone on its first BYE, so a repeat
  is still reported as `Arrival::Goodbye` but removes nothing a second time,
  and `IntervalTimer::remove_member` never counts below the local participant,
  which also covers a far end's BYE crossing the one `send_bye` sent.
  (b) `MediaSession::open` built every stream's `RtpSession` with a fixed
  `unit_interval` of `0.5`, so the first deadline always sat at the midpoint
  of the `[0.5, 1.5)` scaling RFC 3550 §6.2 asks to be drawn at random, and
  the first report could only land in [2.05 s, 3.08 s] rather than across
  [1.03 s, 3.08 s]. It now draws that factor
  from the call's own seeded generator before the session exists — the same
  generator every later report already drew from.

- **A far end that came back under a new SSRC after saying goodbye was never
  counted again, and a peer heard only through RTCP could say goodbye and
  never be removed.** (a) `RtpSession::follow` and `resync` left
  `member_known`, `sender_known` and `departed` set the way the abandoned
  source had left them, so a re-INVITE or an ICE restart that brought the far
  end back under a fresh SSRC found this session already claiming to count it
  and never added it again (RFC 3550 §6.3.3: counting has to follow whichever
  source is actually being received). Both methods now reset all three, along
  with the new `rtcp_source` below. (b) `rtcp_receive`'s BYE handling matched
  a departure only against `Inbound::source`, which only RTP ever sets, even
  though the same method already counts a source as a member the moment its
  first RTCP report arrives — so a recvonly peer, or a call on hold, could
  never have its BYE recognized. A BYE is now matched against
  `Inbound::rtcp_source` too, the SSRC an SR or RR names itself with. (c)
  `send_bye` called `IntervalTimer::leaving` — §6.3.7 bullet one's reset to a
  single member — regardless of group size, although the RFC lets a session
  at or below fifty members send its BYE immediately without resetting
  anything (bullet three, "MAY send a BYE packet immediately"); that branch
  is now `IntervalTimer::sent_bye`, which leaves `members` and `senders`
  alone, and `leaving` is reserved for a session actually past
  `bye_should_back_off`'s fifty-member threshold. Either branch now marks the
  session as departing, because §6.3.4's rule for a *received* BYE excludes
  "the case when an RTCP BYE is to be transmitted" without conditioning that
  on group size: once this session has sent its own goodbye, a BYE from the
  far end no longer removes it — §6.3.7 bullet two counts it up instead
  (`IntervalTimer::note_bye_while_departing`).

- **A master key identifier whose value does not fit the width its line gives
  it is refused rather than truncated.** `Mki::new` checked only the width, so
  `|1066:1` built an identifier that went out as the single octet `0x2a` and
  was compared on arrival with 1066, which no octet equals: every packet of the
  call was refused as `UnknownKey`. The facade answered such a line, because
  `keying::usable` kept a copy of the width check of its own. `Mki::new` now
  also refuses a value its width cannot carry, and `usable` asks `Mki::new`
  rather than repeating the rule, so the line is refused where it is read.

- **`Protector::protect_rtcp` no longer overflows on a length past the end of
  its buffer.** It added the SRTCP overhead to the length before comparing the
  sum with the buffer, and a length near `usize::MAX` wrapped: a panic in a
  debug build, and in a release build a call that went on, spent an SRTCP
  index and, under `UNENCRYPTED_SRTCP`, wrote the tag over the packet's own
  header and reported success. Such a length is now refused as `TooShort`
  before anything is added to it, as `protect_rtp` already refused it.

- **A field written in a compact form registered after RFC 3261 was not the
  field it abbreviates.** `HeaderName` knew fifteen compact forms and not the
  other four: `y` for `Identity` (RFC 8224 §13.1), and `a`, `j` and `d` for
  `Accept-Contact`, `Reject-Contact` and `Request-Disposition` (RFC 3841 §12).
  A `y:` line was an extension named `y`, so `sipral_message_header_count`
  asked for `Identity` counted none. All four are known fields now, in both
  forms.

- **An attended transfer names its own dialog whatever the target's `Contact`
  carried.** `transfer_to` appended `?Replaces=` to the target's `Contact` URI
  as it came, so one that already held URI headers turned ours into part of
  its last header value, and the transferee read the Replaces the target had
  written instead. The target now goes into `Refer-To` as a Request-URI, with
  no URI headers and no `method` (RFC 3261 Table 1 allows neither in a
  dialog's `Contact`).

- **A URI whose headers name one field twice is equivalent to itself again.**
  `Uri::equivalent` held every URI header against the first of that name in
  the other URI, so `?Route=a&Route=b` failed against itself, and `?Route=a`
  matched `?Route=a&Route=a`. The n-th field of a name is now held against the
  n-th of that name, in order (RFC 3261 §7.3.1).

- **An attended transfer names its own dialog whatever the target's `Contact`
  carried.** `transfer_to` appended `?Replaces=` to the target's `Contact` URI
  as it came, so one that already held URI headers turned ours into part of
  its last header value, and the transferee read the Replaces the target had
  written instead. The target now goes into `Refer-To` as a Request-URI, with
  no URI headers and no `method` (RFC 3261 Table 1 allows neither in a
  dialog's `Contact`).

- **A URI whose headers name one field twice is equivalent to itself again.**
  `Uri::equivalent` held every URI header against the first of that name in
  the other URI, so `?Route=a&Route=b` failed against itself, and `?Route=a`
  matched `?Route=a&Route=a`. The n-th field of a name is now held against the
  n-th of that name, in order (RFC 3261 §7.3.1).

- **Calls given up on at the same instant for want of a PRACK no longer cost
  the square of their number.** Ending a dialog, matching a PRACK and
  refusing a call whose reliable provisional response went unacknowledged
  each found the responses they were about by visiting every one the endpoint
  had held, so ten thousand calls ringing reliably and refused together cost
  a hundred million visits. They are now found through the dialog and the
  INVITE they belong to.

- **Quieting a reliable provisional response after a refusal had no test
  proving it does not cost the square of the calls refused.** `on_invite`,
  the third of the three lookups `of_invite` was added for, could regress to
  the full scan it replaced and every test in the suite would still pass —
  the other two (ending a dialog, refusing on timeout) were already held to
  ten thousand by a counted sweep. A third such test now holds `on_invite` to
  the same bound.

- **A reliable provisional response stops being retransmitted once a CANCEL
  has refused its call.** The 487 went out and the 180 kept going out after
  it until 64*T1, where RFC 3262 §3 says it "SHOULD NOT"; the 487 now quiets
  it, as a refusal the application sends already did.

- **A CANCEL that matches no transaction is answered 481, not 200.** The 200
  went to every CANCEL, telling its sender that something had been cancelled
  when nothing had; RFC 3261 §9.2 keeps the 200 for a CANCEL that matched an
  existing transaction, whatever that transaction's method, and answers the
  rest 481.

- **`ServerKey::is_cancelled_by`'s legacy branch (§17.2.3's fallback for a
  peer with no magic cookie) had no test at all.** Only the RFC 3261 branch,
  matched by branch and sent-by, was exercised; dropping the Request-URI,
  From tag or `CSeq` number from the legacy comparison passed every test in
  the suite. A unit test now checks a legacy CANCEL against the transaction
  it cancels, and against one sharing its branch but not its `Call-ID` or
  `CSeq` number — which a legacy peer's branch, being untrustworthy, can do.

- **`ServerKey::is_cancelled_by` had no test for the one case its two
  field-by-field branches cannot check: a CANCEL keyed the other way than
  the transaction it names.** The fall-through arm carries that whole
  answer on its own, and flipping it from `false` to `true` — an RFC
  3261-keyed transaction "cancelled" by a legacy CANCEL naming the same
  call, or the reverse — passed every test in the suite. A CANCEL forged
  without the magic cookie its INVITE carried, or with one its INVITE never
  had, is exactly what that arm exists to refuse. A unit test now checks
  both directions never match.

- **A CANCEL that crosses the answer to a call no longer reports the call as
  cancelled.** It got its 200, the INVITE's 487 was rightly not sent, and
  `IncomingCancel` went up anyway, so the layer above ended a call that was up
  and left its dialog confirmed with nobody to hang it up. RFC 3261 §9.2 gives
  such a CANCEL no effect on any session state; nothing is reported for it.

- **Calls whose timer M fires at the same instant no longer cost the square of
  their number.** Retiring an INVITE transaction found the dialogs of its fork
  by walking every dialog the endpoint held, so ten thousand answered calls
  ending their transactions together cost a hundred million slot visits. It
  now reads them off the fork's own branches, and a test holds the timers to
  their bound by counting visits: one per transaction slot to find the next
  deadline, and at most two sweeps per `handle_timeout`.

- **Asking to cancel a call twice puts one CANCEL on the wire.**
  `Endpoint::cancel` sent a second CANCEL with the first one's branch and
  method, the key RFC 3261 §17.1.3 finds a response's transaction by, so two
  transactions stood under one name: the 200 reached the second, and the first
  retransmitted until timer F reported an answered CANCEL as failed. A CANCEL
  already running is now left to finish.

- **A session timer that could not be refreshed yet stayed due at the instant
  that had already fired, forever.** `send_refresh` returned without moving
  `due` when the call had no dialog to send a refresh in, and when it was not
  up yet: the timer this end arms for the retry after a 422 while that retry
  is still ringing, and the one armed with a 2xx this end sent whose ACK has
  not arrived. `poll_timeout` kept handing back the past deadline, so the
  event loop never slept. Both returns now wait a quarter of the interval, as
  the refresh already did when a request could not go. The timer is kept, not
  dropped: it holds the mark that makes a second 422 end the call instead of
  asking again (RFC 4028 §10), and on an answered call nothing re-arms it when
  the ACK arrives, while §7.2 still wants the refresh before the session
  expires.

- **A call or account handle no longer names a call on another stack.** Every
  stack numbered its handles from the same first slot, so the first call on one
  stack and the first call on a second were the same number, and a hang-up
  passed to the wrong stack ended that stack's call and answered
  `SIPRAL_STATUS_OK`. A handle now carries the tag of the stack that minted it —
  generation (32 bits), stack tag (8), slot (24) — and one used with another
  stack is `SIPRAL_STATUS_INVALID_HANDLE`, "minted by another stack". A tag is
  reused once its stack is gone, and the stack that takes it mints above every
  generation the last one handed out, so a handle kept from a destroyed stack is
  refused the same way. A process holds 256 live stacks; the next
  `sipral_stack_create` is `SIPRAL_STATUS_EXHAUSTED`.

- **A request inside a dialog could leave as a datagram it did not fit in.**
  RFC 3261 §18.1.1 was applied to the first send and the challenge retry but
  not to the path every re-INVITE, UPDATE, PRACK, INFO, REFER, NOTIFY, BYE and
  2xx-ACK is built on, so a re-INVITE whose body pushed it past the datagram
  limit still went out over UDP, to be fragmented or dropped on the way. That
  path now promotes such a request onto a stream open to the same address or
  refuses it with `SendError::NeedsStreamTransport` and
  `Event::TransportWanted`, written down as the first send is; the ACKs carry
  the refusal in `AckError::Build`, a refused BYE leaves the dialog up, and a
  retransmitted 2xx is answered on the stream its ACK went on while that
  stream is open. `sipral-ua` returns the refusal from what the application
  asked for — `answer_early` no longer turns it into `WrongState` and loses
  the answer it owed — and holds what it sends by itself until a transport is
  bound.

- **No binding called `sipral_abi_check` on its own, so a caller compiled
  against an older header found out at whichever entry point happened to
  run first, unnamed, rather than up front.** The pinned lengths landed;
  the load-time check did not. .NET's `Sipral` now has a static
  constructor, printed by `tools/abi-gen`'s C# back end rather than
  written by hand, so it exists for exactly as long as the class it
  guards and runs before that class's first use; a mismatch stops the
  class before anything else in it runs, as a `TypeInitializationException`
  whose inner exception is the `SipralException` naming both versions —
  the runtime wraps what a static constructor throws, and every later use
  of the class throws the same wrapper again. The call in it, and the one
  Swift's documentation gives, are spelled from the declarations of
  `sipral_abi_check` and the two version constants, and a surface that
  lacks them is refused rather than printed calling names it does not
  have. Swift has no load hook a library can hang a check on — no module
  initializer, nothing a namespace `enum` runs before first use — so
  `SipralAbi.swift` now says so on `Sipral` itself, with the exact call and
  when: once, before the application creates a stack or touches anything
  else in the module. `bindings/c/smoke.c` gained the test that was still
  owed: every struct a caller declares is handed to an entry point that
  takes one, at the oldest length `bindings/c/abi-sizes.txt` pins and at
  one byte short of it, and the first is accepted while the second is
  refused with `SIPRAL_STATUS_UNSUPPORTED_VERSION`. The pins are read from
  that file, not asked of `sipral_abi_struct_size`, which answers with the
  length a struct has now — the number the pin replaced, and the one that
  parts company with it the day a member is appended. The file is held to
  the library before any number in it is used: its current lengths are the
  ones the library reports, it lists as many structs as
  `sipral_abi_versioned_count` counts, and a pinned struct with no entry
  point in the test, or an entry point with no pin, fails by name.
  Kotlin's binding calls it as its native object initialises.

- **A stream whose ICE checklist had Failed could still carry data and select
  a pair.** `IceAgent::send` kept routing data on a Failed stream — on a
  component selected before another component's nomination failed, on a pair
  kept from before a restart, or on the best valid pair — although RFC 8445
  §12.1 forbids sending on any component of a stream that cannot produce a
  selected pair for all of them. A success arriving afterwards, for a check
  cancelled when the checklist failed, still selected a pair and started
  consent checks on it. A Failed stream now refuses to send with `NoRoute`, and
  a late success selects nothing.

- **The ICE pair limit could discard the pair a nomination needed.** When
  `IceAgent::set_remote` was called again with the same credentials and a
  better candidate while the checklist set was at `max_pairs`, the lowest
  pairs were discarded whatever their state. A pair whose check had already
  succeeded went with them, and so did the only way to repeat that check with
  USE-CANDIDATE: the controlling agent skipped the valid pair on every pass and
  never nominated, which RFC 8445 §8.1.1 requires it eventually to do. The
  limit now discards only pairs no check has touched; a pair that is
  In-Progress, has finished, is queued for a triggered check or carries a
  nomination stays.

- **An ICE agent configured below the default Ta kept it against a peer that
  proposed none.** RFC 8445 §14.2 has both agents use the higher of the two
  proposed values, and counts an agent that proposes nothing as proposing the
  default 50 ms. `IceAgent::set_remote` raised Ta only when the peer wrote
  `a=ice-pacing`, so an agent set to 20 ms paced its checks at 20 ms against
  every lite peer, which never writes one, and against any full peer that
  left it out. A peer without `a=ice-pacing` now counts as 50 ms.

- **A controlled ICE agent accepted nominations it then dropped.** When the
  source of a USE-CANDIDATE check did not fit under `max_remote_candidates`, or
  its pair did not fit under `max_pairs`, `IceAgent` still answered with a
  success and then did nothing with the nomination: the controlling side
  completed and the controlled side stayed Running with nothing selected. RFC
  8445 §7.3.1.5 requires a nomination the controlled agent does not accept to
  be refused with an error, so it now gets a signed 400, which fails the
  nominating check on the other side as §7.2.5.3.4 prescribes. A nomination
  that arrives before the answer and finds the queue of early checks full is
  refused the same way, and so is one on a stream whose checklist has Failed,
  one naming a peer fragment the stream does not hold, and one on a component
  the stream was reduced away from: each was also answered and then dropped.

- **A DTLS handshake fragment could be cut larger than a record may carry.**
  `record_payload_budget` in `sipral-dtls` returned whatever the datagram
  left — 65494 octets on a loopback path — and `fragment_message` cut to
  whatever it was given, while RFC 5246 §6.2.1 holds a record's fragment to
  2^14 and `encode_plaintext` refuses anything longer, so a flight on a wide
  path could not be sent at all. Both now stop at 2^14. Nothing calls the
  crate yet.

- **A stateless DTLS server could not reassemble anything after its cookie
  exchange.** `Reassembler` only ever started at message 0, but a server that
  answers the first ClientHello with a HelloVerifyRequest keeps nothing until
  the second, which RFC 6347 §4.2.2 numbers 1, so that ClientHello and every
  message after it would have waited for a message 0 the server never kept.
  `Reassembler::expecting` starts where the server's state does.

- **Three `sipral-dtls` tests stayed green with the guarantee they named
  removed.** Two DER length bounds (`wire::bounded`'s upper end, `wire::block`'s)
  passed their own unit test with the bound deleted, because the one case each
  test tried also tripped a width overflow; both now include a length inside
  the field's width but over the caller's narrower bound. A P-256 signature
  check that ignores the message it was asked to verify passed the test named
  for exactly that, because every case in it already expected a refusal; it
  now asserts the correct pairing verifies first. The certificate reader's
  panic-fuzz test bit-flipped each octet through four fixed masks, which a
  length or count field is rarely one of, so it missed a missing empty-content
  guard entirely; it now tries every octet value at every position. Two pieces
  of the foundation had no test at all — `Role::peer` and `Error`'s `Display`
  — and now do.

- **The lab's outage profile could pass without the outage touching the
  call.** `interop/impairment/blackout.sh` cut the link five seconds after its
  container started and then checked only that the qdisc said `loss`. On a
  host where the call took longer than that to begin sending, the eight seconds
  fell on the REGISTER and the INVITE, whose retransmissions outlasted them, and
  the call ran clean from start to finish — a run on a 6.12 kernel reported
  "audio survived it" with no packet of the call lost. The outage now waits
  until audio is visibly leaving through the qdisc, and afterwards netem's own
  drop counter has to show that it took at least four seconds of the call's
  packets; a run where it did not is reported as proving nothing, never as a
  pass. Checked both ways: the profile passes with the outage landing in the
  call, and a copy cut before the call starts is refused. `lab.sh`'s note for a
  run that proves nothing no longer blames the kernel for every cause.

- **The mechanism that makes appending a struct member safe did the opposite
  of what it promised.** `Versioned::MIN_SIZE`'s own contract says it is the
  length of the **oldest published** version of a struct, and `declared_size`
  refuses anything below it. All thirteen implementations wrote
  `size_of::<Self>()` — the length of the **current** build. So the first
  member appended to any config struct would have moved the floor with it and
  turned away every caller compiled against yesterday's header, from a change
  whose entire point was to be additive, and nothing in the diff that caused
  it would have looked wrong. The thirteen lengths are now pinned as literals,
  three tests driven off the ABI declaration say the table is complete, names
  nothing that has gone, and pins nothing longer than the struct is now, and
  `bindings/c/abi-sizes.txt` is printed beside the header and the four
  bindings so that moving a pin is a line somebody has to sign.
  `sipral_event_t` is named as the one exception and why: the library fills it
  in, so no caller ever declares one and there is nothing to refuse.

- **A registration restored from a snapshot, or one whose REGISTER answer
  arrived just before a suspend, could come back from a wake with nothing
  that would ever register it again.** `distrust()` — the first rung of
  every recovery ladder, and the only thing `suspending` does — left
  `Restored` out of the states it promotes to `Unverified`, so `reregister()`
  never saw a thawed binding: the ladder climbed straight to `GiveUp` with
  the account still `Restored` and no REGISTER ever sent. The same loop left
  `reg.transaction` untouched, so a REGISTER whose 200 arrived a moment
  before the sleep still read as in flight after the wake, and
  `refresh_binding` (RFC 8599 §4.1.3's pre-warm) treats anything in flight as
  reason enough to send nothing — so a push landed on a binding that never
  got its refresh. `distrust()` now promotes `Restored` the same as
  `Registering`/`Registered`/`Refreshing`/`Retrying`, and clears
  `reg.transaction` for every registration it touches, so a stale in-flight
  id from before the sleep is never mistaken for a real one.

- **A wake left a busy lamp field's subscriptions either retrying against a
  schedule the sleep had already made stale, or not retrying at all.**
  `distrust()` demoted a live subscription's state to `Retrying` but never
  touched its `due`, `lapses_at` or `forks_until` — deadlines that an
  `Instant` frozen across a real suspend still reads as ahead of `now`, so a
  suspended stack still had a deadline `poll_timeout()` would report, and
  once that stale deadline eventually fired nothing had re-armed the
  subscription for it: a refresh went out against a schedule from before the
  sleep, or a lapse ended the subscription outright.
  `Subscription::stop_timers` now clears all three alongside the state
  change, and the `Reregister` rung of every recovery ladder calls a new
  `UserAgent::resubscribe`, sending a fresh out-of-dialog SUBSCRIBE for every
  subscription `distrust` demoted — on the same rung, and the same 64·T1
  bound, as the registrations recovering beside it. Each of those goes out
  under a fresh `Call-ID` and `From` tag: RFC 6665 §4.1.2.4 identifies a
  subscription by the dialog those name, and re-using them would offer the
  notifier a second subscription under a name it already holds one for, then
  leave it to guess which of the two the next NOTIFY belongs to. And every
  subscription is demoted, not only the live ones — one waiting on its first
  NOTIFY has a Timer N scheduled and one already retrying has a retry
  scheduled, both measured against the clock that stopped.

- **A transfer that was refused, or never answered at all, now closes the
  subscription it opened.** RFC 3515 §2.4.7 makes a NOTIFY marked
  `terminated;reason=noresource` the last word on a REFER's subscription, but
  that NOTIFY was only ever sent on success — a call the far end refused, or
  never answered before this end gave up, left the transferor holding a
  subscription that could never close. The call's own ending now reports the
  refusal's status, or a synthesized 408 when the call never got one at all
  (a `408 Request Timeout` is what the transaction's own giving-up would have
  carried, RFC 3261 §21.4.9), before the record of who to tell is forgotten.

- **A call could not be transferred a second time until the first transfer's
  REFER got its 202, even though the first was still going.** RFC 3515
  §2.4.2 has a 2xx oblige the far end to open a subscription and report on
  it — it is not the last word, the closing NOTIFY is (§2.4.7) — but the seat
  a REFER takes on its call was freed as soon as that 2xx arrived, before any
  NOTIFY could possibly have been. A second transfer offered while the first
  was still being tried would open a second implicit subscription in the same
  dialog with no way to tell a report on one from a report on the other. The
  seat is now freed only when the REFER is refused (which opens no
  subscription at all) or when the closing NOTIFY says the first is over.
  Outgoing NOTIFYs about an accepted REFER now also carry the `id` parameter
  §2.4.6 names — the accepted REFER's own `CSeq` — so a report is never
  ambiguous about which REFER it belongs to. A second REFER arriving on a
  call whose first has not finished is answered `491 Request Pending` rather
  than taken: this end keeps one transfer per call, and taking the second
  would throw away the first's transaction, the call it placed and the `id`
  its own NOTIFYs are tagged with.

- **Taking a transfer placed the new call with no media at all.**
  `accept_transfer` built the outgoing INVITE itself and never gave it
  anything to offer, so an application taking a transfer got a call it could
  place but never hear or be heard on. It now takes the same session
  description a call or a consultation would, and places an offerless INVITE
  only when none is given — the answer then travels in the 2xx, exactly as it
  does for either of those.

- **The reference loop stopped running timers on a socket that was never
  quiet.** `Runtime::wait` called `UserAgent::handle_timeout` only when a turn
  found nothing waiting on the inbox; a peer that always has a datagram in
  flight — any UDP port reachable from the open internet — kept `wait`
  in its other branch forever, so a deadline already due (a retransmit, timer
  B giving up on a call, a registration's refresh) never fired as long as
  packets kept arriving. `wait` now checks `poll_timeout()` against the clock
  after handling an arrival too, not only when the inbox came back empty.

- **A datagram one destination refused could end the whole reference loop.**
  `Runtime::flush` used `?` on `send_to`, so one `EPERM` or `ENETUNREACH` on
  one transmit propagated out of `flush`, out of `turn`, and out of `run` as
  an `io::Error` — freezing every other call, registration and subscription
  behind it, and losing the transmit that failed along with them. A single
  UDP socket in this loop carries every destination an application talks to,
  so a failure on one of them is not grounds to retire it the way a broken
  transport is elsewhere in this stack; `flush` now lets a refused datagram
  go unsent and relies on the transaction layer's own §17 timeout to notice,
  the same way it already does for a transport that has gone away entirely.
  A stream write that fails is a different case — one connection serves one
  peer — so it still closes the connection, through the same
  `Input::StreamClosed` path a read finding nothing already used.

- **A non-INVITE request a server refused left no trace in the call's
  record.** `Endpoint::note_failure_for(_, FailureReason::Refused)` ran for
  every INVITE a dialog set gave up on, but `on_non_invite_response` never
  called it, so a REGISTER answered 403 or an OPTIONS answered 503 went out,
  came back, and the diagnostics record showed nothing past the initial send
  — even though `docs/14-diagnostics.md` already documented `failure.refused`
  as covering a request as well as a call. A final response of 300 or above
  is now recorded the same way for both, except for a 401 or 407: those stay
  the sole business of the challenge/answer bookkeeping right below it, which
  already says what happened to them.

- **Resuming a call that was held for a while no longer reports the stream as
  stalled.** The watchdog measures from the last packet that arrived, and
  during a hold none do. A resume keeps the media address — only the direction
  attribute moves — so nothing reset that mark, and the first timer tick after
  resuming read the entire length of the hold as silence and raised
  `MediaEvent::Stalled` before the far end's first resumed packet could
  possibly have arrived. Reception starting up now resets the watchdog, which
  is the mirror of the guard that already silenced it going in.

- **A call that ends now says goodbye.** RFC 3550 §6.6 has a participant that
  leaves send an RTCP BYE, and this stack could not: `MediaEngine` takes the
  session out in the same breath as the event reporting the end, so by the
  time an application heard about the call it had no way to reach the session
  that would have produced the packet, and the engine never produced one
  itself. The far end was left to wait out its own timeout on every call.
  `MediaEngine::poll_farewell` hands over the goodbye of a call that has
  ended, drained like every other poll.

- **A target refresh inside a dialog is now reported.** §12.2.1.2 and §12.2.2
  both replace the dialog's remote target on a target refresh — a re-INVITE's
  2xx, or an incoming one — but nothing compared the new target to the flow
  those requests actually go out on, since `Dialog::on_response`/`on_request`
  are pure, sans-I/O mutations with no access to it. `Endpoint::ack_reinvite`
  built the ACK's Request-URI from the new target while still sending it to
  the flow from before the move: one host named, another dialled, and no
  event. The endpoint now compares the remote target before and after each
  call into the dialog and pushes `Event::ResolveNeeded` when it moved. The
  flow itself deliberately stands, literal address or not, until the caller
  answers with `resolved`: a far end behind a NAT writes its own private
  address into `Contact`, which is the ordinary case, and following it would
  take the call off the only address that reaches it.

- **A reliable provisional to a re-INVITE can now be acknowledged.** This
  endpoint answers a re-INVITE with a 1xx sent reliably the same as it
  answers an initial INVITE — RFC 3262 §3 carves out no exception for a
  request already inside a dialog — but on the receiving end such a response
  reached the caller as a bare `ReinviteProgress` with no handle to PRACK it
  by, while the far end retransmits it until it gives up on the call
  entirely. `Event::ReinviteProgress` now carries the same
  `ProvisionalResponseId` a fresh `Endpoint::prack` call needs, exactly like
  `ReliableProvisional` does for an initial INVITE.

- **A 2xx to a re-INVITE retransmitted before the ACK went out was reported
  to the caller twice.** The dedup that answers a retransmission from the
  cached ACK only applies once that ACK exists; before the caller has built
  it — which can take longer than one retransmit interval, since the ACK may
  carry the answer — a retransmitted 2xx fell through to the same branch that
  handles the first one and pushed a second, indistinguishable
  `Event::ReinviteAnswered`. The branch now checks whether this re-INVITE's
  answer has already been reported and returns without pushing again.

- **A recording could not tell two sessions apart that sent their requests to
  different addresses.** `Endpoint::resolved` is a third way into a sans-I/O
  core, beside `receive` and `handle_timeout`, and the replay format had no
  frame for it — a call whose dialog was re-resolved and one that never was
  wrote byte-identical text, so replaying either sent every later request to
  the address the dialog opened with rather than the one it was told to use.
  `Step::Resolved` gives the answer a frame of its own, `Recorder::resolved`
  records it beside the call, and a replay applies it itself rather than
  asking the caller to redo it, the way a cue would. The recording format
  moves to version 2 for it; a version 1 file still reads.

- **An `a=crypto` tag with a leading zero was accepted and silently
  renumbered.** RFC 4568 §4's "leading zeroes MUST NOT be used" already
  covered the MKI, the lifetime and the key identifier in this parser;
  `Crypto::parse` checked only that the tag was all digits, so `"01 ..."`
  parsed to tag `1` instead of being refused. `Crypto::parse` now shares the
  same check the other three fields use.

- **A codec change no longer restarts the stream, or the SRTP keystream under
  it.** A re-INVITE onto another codec opened a new media session and dropped
  the running one, and the new one was built from the identity the *call*
  opened with — so the outgoing sequence number rewound to where it had
  started while the master key stayed exactly as it was. The SRTP packet index
  is `2^16 · ROC + SEQ`, so every packet after such a change re-used a
  keystream already spent, which is the two-time pad RFC 3711 §9.1 calls
  catastrophic; the SRTCP index, which §3.4 says is never reset, went back to
  zero with it. Nothing about it was audible and nothing about it showed in a
  capture. Separately, RFC 3550 §5.1 has a source that resets its counters
  read as a different source. The session is now re-formatted rather than
  replaced: `RtpSession::reformat` keeps the stream and both SRTP contexts and
  rebuilds only what is measured in the old codec's units, and
  `JitterBuffer::reformat` keeps the cumulative counters across that rebuild.
  Everything else the running session held is carried with it — the octet and
  packet totals, the RTCP timeline and CNAME, the stall watchdog, the render
  delay and device the application set at run time, the events it had not
  collected, the digits still owed (rescaled into the new clock's ticks), the
  processor it attached, and the recording. A recording whose sample rate or
  frame length moves under it cannot follow a WAVE header written once at the
  front of the file, so it is now closed properly and reported with the new
  `MediaError::CodecChanged` rather than dropped with the session, which left
  a file with zeroes where its two lengths should be.

- **A re-negotiation that moves the SRTP keys now reaches the running
  stream.** `MediaSession::adopt` looked at the media address and nothing
  else, so a re-offer or an answer carrying a fresh `a=crypto` updated the
  plan — `is_encrypted` went on saying yes — while the contexts kept the keys
  the call opened with. From the first packet after such a re-key the far end
  heard silence, reported as `Discard::Insecure`, and RFC 4568 §7.1.4 makes a
  re-offer exactly the place both ends expect to re-key. Each direction is now
  compared against the one it is running and only what moved is replaced.
  `Security` and `RtpSession` gain `rekey_local` and `rekey_remote`, and the
  new `Rekeyed` says which of two things a negotiation did, because the two
  must not be confused: a master key that has never been used starts the
  packet index again, while the same key under different terms — the same
  `inline:` with `AES_CM_128_HMAC_SHA1_80` giving way to `_32` — keeps it,
  since §4.3.1 derives the session keys from the key, the salt and the index
  alone and restarting there would spend one keystream twice. The receive
  context a re-key replaces keeps opening packets for 250 more, because the
  answer naming a key and the first packet under it cross on the wire;
  `Protector::retune` and `Unprotector::retune` are the same-key half.
  `adopt` is fallible from here on.

- **A challenge no longer dies when the answer to it outgrows a datagram.**
  Credentials are the one addition certain to make a request bigger, and a
  retry that crossed RFC 3261 §18.1.1's line was refused with "open a stream
  and send it again" — while the endpoint, the only holder of the challenge,
  had already thrown it away. The caller opened the connection it was asked
  for and got `NoChallenge`. The challenge now stays put on that one error,
  and the same handle works once the transport is bound. `SendError::
  NeedsStreamTransport`'s contract says which side holds the request on which
  door, because the two differ.

- **A connection to one place no longer hides every connection to another.**
  Choosing a stream transport for §18.1.1 picked the lowest-numbered one
  speaking TCP and only then measured it against the destination, so a single
  connection to a registrar made every promotion to any other address report
  that nothing spoke TCP — however many connections were open, and however
  many times the caller opened the one being asked for. The destination is
  now part of the question rather than a filter on the answer. This was
  reachable on the ordinary first send, not only on a retry.

- **A nonce count is spent by the request that leaves, not the one that is
  built.** Working out an answer no longer moves the counter; committing the
  bytes to a transaction does. A request refused for size took its number
  into the bin, and whoever asked next either repeated it, which a server
  reads as a replay, or stepped over it. Both doors are covered: the retry
  after a challenge and §22.2's pre-emptive answer.

- **A server that rotates its nonce can no longer run one wrong password per
  round trip.** §22.1's guard — the same nonce back without `stale` means the
  password was rejected — turns on the nonce being the same, and a registrar
  that draws a fresh one every refusal walks straight past it. The count that
  closes that hole existed on the REGISTER path only; it now lives in the
  endpoint and covers calls, in-dialog requests, re-INVITE and UPDATE, and
  SUBSCRIBE. One request is answered three times, and the fourth challenge on
  it is a refusal whatever nonce it carries. The credentials for that
  protection domain are marked refused with it, so the pre-emptive answer
  stops offering a password three refusals old on every later request — and
  only that domain, because one destination can hold a registrar's realm and
  a proxy's at once with only one of the two passwords wrong.

- **A retry waiting for a connection is no longer reported as a wrong
  password.** Every path that answers a challenge used to drop the "open a
  stream" error on the floor, and the pass that decides whether a parked
  refusal became a retry then ran in the same breath — so the application was
  told its credentials were bad at the same moment it was asked for a socket
  nobody had been given time to open. A parked retry is now left where it is
  and sent when the transport is bound, on all five paths: registration, the
  INVITE, a request inside a dialog, a re-INVITE or UPDATE, and SUBSCRIBE.

- **A REFER that is never authenticated gives the transfer seat back.** The
  seat a call holds while a REFER is outstanding was released on every final
  answer except a challenge, on the grounds that a retry would follow. When
  no retry can follow, the seat stayed taken for the life of the call and
  every later transfer on it was refused here before anything was sent. The
  application is now told the transfer did not happen, and the call can be
  transferred again.

- **`+sip.instance` went out without the angle brackets RFC 5626 §4.1
  requires around the URN.** `Account::contact_with` wrote
  `+sip.instance="urn:..."` on every REGISTER, INVITE and response carrying
  the parameter, instead of the `+sip.instance="<urn:...>"` the grammar
  (`DQUOTE "<" instance-val ">" DQUOTE`) and RFC 3840 §9's case-sensitive
  comparison both need; a strict registrar could refuse the registration or
  never grant a GRUU. The reader that matches a registrar's echoed value
  against this instance already tolerated both forms and needed no change.

- **Two entry points took a `call` and an `out_call`, and three printed
  bindings could not survive it.** `sipral_call_consult` and
  `sipral_call_accept_transfer` both had a parameter named `call` and one
  named `out_call`; every binding that derives a name off `out_` collapsed the
  two into one. C# declared two parameters called `call` and would not
  compile. The JNI shim declared two called `call` and would not compile
  either. Swift did compile, and was wrong: it wrote `var call` beside the
  parameter `call`, so the handle it passed the library was a zeroed one and
  the caller's was never used. The out parameters are now `out_consultation`
  and `out_placed`. Likewise the three `sipral_call_reject*` entry points took
  a SIP response code in a parameter named `status`, which the JNI shim
  shadowed with its own result local — `sipral_status_t status = f(...,
  status, ...)`, a variable read inside its own initialiser. It is `code` now,
  which is also what it is. Only parameter names changed: no symbol, no type
  and no number moved, and nothing about the ABI is different.

- **The Swift back end read the spelling of a return type instead of the
  type.** It compared `function.returns` against the string `*const c_char`
  where the other three back ends go through `Type::read`, so
  `sipral_event_kind_name`, whose declaration sits inside a macro and reaches
  `stringify!` as `* const c_char` with a space in it, was printed as a call
  returning a status: `let status = sipral_event_kind_name(kind)` handed a
  `char` pointer to the status check. It is printed as the string-returning
  call it is.

- **A NOTIFY of the `refer` package drove a transfer nobody here asked for.**
  A notification of that package arriving in any dialog this layer maps to a
  call was acted on without anything checking that this end had ever sent a
  REFER: the far end of an ordinary established call could report progress on
  a transfer that did not exist, and the last one of those — a 2xx marked
  `terminated` — hung the call up, because that is what a transfer that
  succeeded means. Nothing could have checked it, either: the seat the call
  holds while a REFER is in flight is given back when the REFER is answered,
  which is before any notification can arrive. A call now records the implicit
  subscription its REFER opened (RFC 3515 §2, §2.4.4) when the REFER is
  written rather than when the 202 comes back — §2.4.4 warns the agent to be
  ready for a NOTIFY before the transaction completes — and drops it when the
  REFER is refused, since §2.4.2 makes a 2xx the answer that obliges the far
  end to create a subscription at all, or when the last NOTIFY says
  `terminated` (§2.4.7). A notification matching none of that reaches the
  subscription machine, which answers it 481 as RFC 6665 §4.1.3 requires, and
  nothing acts on it. The record carries the `CSeq` of its REFER, which is the
  `id` §2.4.6 puts on the `Event` of a NOTIFY, so one naming a REFER this end
  did not send is not this subscription's news either; putting that `id` on
  the wire is still to come and belongs to the same record rather than to a
  second one.

- **The INVITE an accepted transfer places carried no `Referred-By`.** RFC
  3892 §2.2 is a MUST — "A UA accepting a REFER request (a referee) to a SIP
  URI ... MUST copy any Referred-By header field" — and it was not
  implemented. Demoting the field from authorisation, which the previous
  release did on purpose, does not remove the obligation to pass it on: the
  far end may have a policy that reads it, and dropping it silently decides on
  that end's behalf. `accept_transfer` now copies it whole, parameters
  included. It still means nothing on the way *in*: §3's signed token is not
  implemented here, so an incoming one is context and never authority. A REFER
  carrying two of them, which §2.1 forbids, has neither copied — which of two
  to pass on is not ours to guess — and the transfer is not refused over it.

- **The hand-written digests left the password in buffers nobody wiped.** A1
  lives in a `Secret` that overwrites itself, and then went one level deeper:
  `md5`, `sha256` and `sha512_256` copy the last part-block of their input
  into a stack buffer and read that block back as words, and both were left as
  they were on return — for an A1, which is shorter than one block, that is
  the whole password. Each digest now works in a named buffer it overwrites
  before it returns, with the same `fill(0)` plus `compiler_fence` the
  `Secret` uses and the same honest limit: only a volatile write survives an
  optimiser for certain, and that needs `unsafe`, which the crate denies. MD5
  no longer copies whole blocks into a buffer of its own on the way past and
  SHA-512 no longer rebuilds each word through one, so there are two fewer
  copies to wipe rather than two more wipes. The known-answer vectors are
  unchanged and are the guard. HA1 is still a `String` that is not wiped;
  that is a scope decision, and `docs/12-core-api.md` now says so where the
  rest of the rule is written down.

- **The password spent a moment in a buffer that was never wiped.** `A1` -
  `username:realm:password` — was built in a plain `Vec` inside
  `Challenge::respond` and freed as it was, so the whole of it, password
  included, was left in freed memory on every answered challenge. It is built
  now in the existing `Secret`, which overwrites itself on drop, and in one
  exact allocation rather than a buffer grown a part at a time: growing it
  leaves every intermediate copy behind, which is the thing the type exists
  to prevent. The response bytes are unchanged — the three RFC vectors in the
  module are the guard — and `sipral-core` gains no dependency, which its own
  no-dependency rule and the record in `docs/12-core-api.md` both require.
  `HA1` itself is still a `String` that is not wiped; that is a scope
  decision and the code says so where it is made.

- **A `Replaces` could take over a live call from any address that could reach
  the port.** An INVITE naming one of this end's calls by `Call-ID` and both
  tags was matched on those three strings and on nothing else, then handed to
  the application as an ordinary incoming call: answering it hung up the call
  it named. The three strings are on every packet of the call they name, so
  knowing them is not being the far end. A matched `Replaces` is now honoured
  only when the INVITE carrying it arrived from the same place the named
  call's own signalling does, and anything else is 403 with the named call
  left exactly as it was (RFC 3891 §3 and §8). `From` and `Referred-By` are
  deliberately not consulted: both are written by whoever sent the INVITE, and
  RFC 3892's signed token is not implemented here. Two `Replaces` fields on
  one request are 400, which §3 always asked for and which keeps the field the
  check reads the same one the far end acted on. `refusals()` gains
  `by_replaces`. Two limits are written out in `docs/04-ua.md`: behind an
  outbound proxy every caller shares one source address, and a byte stream
  bound without naming its far end has no source address to compare at all.

- **Rebinding a transport left the old connection's deadlines armed.** Binding
  a `TransportId` that was already bound replaced the entry and dropped its
  keep-alive and pong timer handles without cancelling them, so the ping sent
  on a connection that no longer existed failed the flow that replaced it ten
  seconds later — an `Event::FlowFailed` against a healthy connection, and one
  extra keep-alive on the schedule for every rebind. `Transports::bind` now
  hands the replaced entry back and the driver cancels its two deadlines
  before arming the new ones. RFC 5626 §4.4.1 is about a flow, not about a
  name. The move that trips it is the ordinary one: a caller whose connection
  broke reconnects and reuses the identifier so that the registration it was
  carrying stays where it was.

- **Seventeen rustdoc warnings across eight crates.** A public documentation
  comment linking a private item renders as text and sends the reader
  nowhere, and `cargo doc` was the one compiler the gate never ran. They fall
  in `sipral-rtp` (4), `sipral-io-wasapi` (4), `sipral-core` (3),
  `sipral-ffi` (2), and one each in `sipral-ua`, `sipral-nat`, `sipral` and
  `sipral-headless`. Each is fixed at the link: where the private item is a
  number, the prose names the window and the constants keep the numbers
  (`sipral-rtp`'s RTCP multiplexing span, `sipral-ua`'s announcement window);
  where it is a concept, the link goes to the public thing that is it
  (`sipral-nat`'s `classify`, `sipral`'s `Capabilities::srtp_keying`,
  `sipral-rtp`'s `RtpSession::rtcp_due` and `build_report`,
  `sipral-headless`'s `ErrorCode`); and where the item is private and stays
  private because nothing a caller names is in it, the reference is a code
  span (`sipral-ffi`'s `versioned` and its `entry!` macro). Two quotations
  from RFC 4566 lost their angle brackets to an HTML parser and are code
  spans now, and one link in `sipral-core` never named the module its type
  lives in. The four in `sipral-io-wasapi` stay links: they point at types
  that exist only on Windows, which is the target the gate now runs rustdoc
  against, and off Windows that crate allows the lint rather than pretending
  in a code span that the reader has nowhere to go.

- **The README and five design documents say what the tree does.** The status
  banner said nothing interoperates while the roadmap recorded three servers
  passing; the crate table called G.722 linked (it is written in-tree), WASAPI
  future (7 800 lines), the facade empty (it is what the C ABI exposes) and the
  reference loop unshipped. `docs/04` said DTMF over INFO is received — it is
  not, and now says so; `docs/08` said the transport is already a member of the
  account configuration — it is not yet; `docs/12` omitted `RetryAfter` and
  described a command enum that was never built; `docs/09`'s legend said
  nothing was done; `docs/14` was a byte off. Two intra-doc links to a private
  constant made `cargo doc` fail with warnings denied. Found by reading the
  tree the way a stranger would.

- **The provenance gate matches the policy it enforces.** `scripts/check.sh`
  looked for eight of the nine projects `docs/02-clean-room.md` forbids, and
  case-sensitively, so `Janus` and any capitalised spelling of the others went
  through. Nine now, in any case.

- **A registrar that draws a new nonce for every refusal can no longer walk a
  wrong password into a locked account.** §22.1's guard — the same nonce coming
  back means the password was wrong — turns on the nonce being *the same*, and
  a registrar that draws a fresh one every time and never says `stale` goes
  straight past it. Measured before the fix: forty attempts and still going,
  one per round trip, for as long as the process lives. Nothing on the wire
  distinguishes that from a server ageing its nonces honestly, so the only
  defence left is to stop counting: three answers per registration attempt, and
  then the same refusal the other guard produces. A correct exchange needs one
  and a nonce that aged out mid-flight needs two; a fresh attempt gets the
  allowance again, because a password can be corrected while a process runs.

- **An `a=crypto` line carrying a parameter this build does not know is now
  refused rather than accepted without it.** RFC 4568 §6.3.7 inverts the usual
  extension rule — "New SRTP session parameters are by default mandatory ... If
  an SDP crypto attribute is received with an unknown session parameter that is
  not prefixed with a '-' character, that crypto attribute MUST be considered
  invalid" — and the code had been written to the usual rule, with a comment
  citing that section for the opposite of what it says. A peer that asked for
  something and was silently not given it is the failure mode the whole section
  exists to prevent. Parameters written with a leading dash are still ignored,
  which is the half that keeps the rule usable.

- **A registration refresh no longer pays for a 401 it has already answered.**
  Every request this stack sent went out bare and waited to be challenged, the
  refreshes included: REGISTER, 401, REGISTER with `Authorization`, 200 — and
  then the same four an hour later, for the life of the process. §22.2 says
  otherwise ("UAs SHOULD cache the credentials for a given value of the To
  header field and 'realm' and attempt to re-use these values on the next
  request for that destination"), and time to ready from cold is a product
  requirement, not a nicety: it decides how long a call queue rings a sleeping
  phone before skipping it.

  What the endpoint remembers is now kept per destination rather than per
  transaction — the nonce, the client nonce and the count, and never the
  password, which is borrowed for the length of one call. The count keeps one
  owner whichever way the credentials leave, because `nc` must differ on every
  request that carries a nonce and two places counting would repeat one. A
  proxy's challenge travels only as far as §22.3 allows it to, which is the
  `Call-ID` it was made in; a registrar's or a callee's own goes on any request
  to that destination. §22.1's guard against a rejected password being offered
  twice now covers credentials that went out ahead of the refusal as well as
  ones that answered it, so a refresh with a wrong password still costs the
  account one attempt and not two, and a nonce the server has aged out is told
  from a password it has rejected by `stale`, as RFC 7616 §3.3 defines it.
  `Endpoint::request_with_credentials` and `Endpoint::invite_with_credentials`
  are how a caller hands the password over for one send.

- **A call refused over TCP or TLS now tells the application why.** The same
  486 that reported `Failed` over UDP reported only `TransactionTerminated`
  over a reliable transport, so on the transport most carriers use nothing
  above the core ever learned that the callee was busy — only that a
  transaction had ended. Timer D is zero on a reliable transport (§17.1.1.2)
  and so is timer K (§17.1.2.2), so the final response ends the client
  transaction in the same call that delivers it, and the endpoint was retiring
  the transaction before handing the response up: by the time the dialog set
  was asked what the refusal meant, the entry that names it had been dropped.
  The response is reported first now and the transaction retired after, which
  is what §17.1.1.2 and §17.1.2.2 make a MUST in both cases.

  The same ordering had taken four more things with it, all of them only on a
  reliable transport: an early dialog a refusal ended was reported as abandoned
  rather than refused; a 487 that answered a CANCEL was not reported as a
  cancellation; a repeated `nonce` was not recognised as one, so a rejected
  password could be offered again and again (§22.1 says not to); and a
  challenged request inside a call took its `CSeq` from the message rather than
  from the dialog, which then handed the same number out twice.

- **A rate limit that admits nothing is refused where it is set.**
  `Rate::new` read a `burst` of zero as one and an interval of zero as "no
  limit" instead of answering. B2 leaves three answers for a setting — applied,
  rejected with a reason, unsupported — and no fourth for one that took effect
  as something else. It returns `Result<Rate, RateError>` now, `Rate::unlimited`
  is how a deployment asks for no floor on purpose, and `Rate::burst`,
  `Rate::every` and `UserAgent::invite_limit` read back what took effect.

- **A refresh that could not leave no longer kills the account for the life of
  the process.** A scheduled registration refresh whose REGISTER failed to
  reach a transport was treated as a registrar that had refused: the state went
  to `Failed` with no retry, and nothing would ever try again. That is not what
  happened — nothing on the wire said anything — and the shape it happens in is
  the ordinary one on a machine that slept: the deadline falls due before the
  socket has been rebuilt. It backs off and tries again now, which is what the
  same failure gets when it happens on the wire.

- A request too large for the path now says how large, and the check now covers
  the request that made the trouble. `Event::TransportWanted` carries the size
  of the request that did not fit and the size that would have, so
  "request 1785 bytes, limit 1299" is a line an application can log instead of
  a packet capture nobody took; the reference loop passes the event up as well
  as answering it, which it did not. The limit comes from one place, so the
  number reported and the number the decision was taken on cannot drift.

  Two real faults came out of writing it. The switch to a stream took the first
  TCP transport in the table whatever it was connected to, so a large request
  to one server left over an open connection to another; it now takes only a
  connection to the destination asked for, which is what §18.1.1 recommends and
  the only one that would deliver it. And the check was on the first send only,
  while the request that fragmented in the field was the one carrying
  `Authorization` — three hundred bytes larger than the attempt that had fitted,
  and built by the retry. The retry checks now too.

- A configuration value cannot be accepted and ignored. `SIPRAL_STATUS_NOT_SUPPORTED`
  is the third answer a setter may give, distinct from a value that is wrong
  and from a struct this build cannot read, and reading every setter against
  the transport it applies to found the failure it was written for:
  `timer_t2_ms` and `timer_t4_ms` were
  taken without complaint on TCP, TLS and WebSocket transports, where neither
  is ever armed — a setting disabled by a neighbouring one, which is the shape
  the requirement describes. Both are refused where they are set now, naming
  the setting and the transport, as is a T2 below the T1 it caps, which makes
  T1 the value that disappears. An expiry too large for the header it goes in
  is refused at the account rather than by the registrar. `sipral_stack_settings`
  reads back what a stack is actually running on, since a zero in the config
  means "the default" and the effective figure is otherwise unknowable.

- A `Require` this agent cannot honour is refused on every request, not only on
  the INVITE that opens a call. §8.2.2.3 says a UAS, not an INVITE: a re-INVITE,
  an UPDATE, an OPTIONS or a NOTIFY demanding an extension that is not
  implemented cannot be honoured as sent, and answering it as though it could is
  worse than declining — a peer that asked for something and got a 200 believes
  it got it. Writing the test found that the OPTIONS handler answered 200 to
  anything it was handed, including this, because it sat first in the event
  chain; it now runs after the check. Only the tags that are actually unknown
  come back in `Unsupported`, which the section asks for by name.

- A challenge to any request inside a call is now answered, not given up on.
  Only REGISTER and the INVITE that opened a call were retried with
  credentials; a 401 or 407 on a BYE, CANCEL, PRACK, REFER, re-INVITE or
  UPDATE fell through to the application as an unclaimed event, and §22.2 does
  not stop at the first request of a dialog. The one with teeth is the BYE: a
  carrier that challenges it is told nothing more, and keeps a call open that
  this end has hung up. Three things had to be settled underneath. A BYE ends
  its dialog as it goes, so by the time the challenge arrives there is no
  dialog to take a `CSeq` from — it now comes from the request that was
  refused, which is right precisely because nothing will ever ask that dialog
  for another number. The account behind a request is kept beside the call
  rather than inside it, since a BYE outlives the call it ended. And a REFER
  that is refused now gives back the seat it took, without which the first
  refusal was the last transfer that call could ever attempt.

- The reference loop could end without writing what it had been given. A
  handler that hangs up and stops in the same breath is the ordinary shape of
  an application, and the BYE was still in the queue when the loop came out —
  so the far end kept the call. Found by the loopback test on its first run,
  which is what that test is for.
- A re-INVITE with no session description could start a second offer/answer
  exchange on top of an unfinished one. §14.1 has such a request ask *this* end
  to offer, so it is the same exchange starting over, and it now meets the same
  491 or 500 that one carrying an offer does.
- A request the far end was still waiting on was abandoned when the call ended.
  §15.1.2: "The UAS MUST still respond to any pending requests received for
  that dialog. It is RECOMMENDED that a 487 (Request Terminated) response be
  generated to those pending requests." Left alone it was retransmitted at the
  far end until it gave up.
- An offer written by the application is given an `o=` version that has moved.
  RFC 3264 §8 makes an unchanged version a promise that the bytes are
  unchanged, and that is not a promise to leave a caller free to break.

- Calls in `sipral-ua`: place, answer, refuse, hang up, and forks handled
  rather than hidden. A `CallHandle` names one dialog, so an INVITE a proxy
  forked to three phones becomes three calls under one attempt, each reported
  as it appears; `ForkPolicy` says what happens to the ones that are not kept,
  and every 2xx among them is acknowledged either way, because §13.2.2.4 does
  not make that conditional. The ACK is sent by the stack rather than offered
  to the application — the exception being a call placed without an offer,
  where the answer travels in the ACK and only the application has one.
  Hanging up is one call that means a CANCEL, a BYE or a refusal depending on
  where the call is. An incoming INVITE is matched to the account it was
  addressed to, and one that matches none is still reported.
- `sipral-ua`, the first crate above the core, and registration in it. An
  account is a registrar, an identity and a password; `UserAgent` keeps its
  binding alive without being asked again. It has the endpoint's five calls,
  so the same event loop drives either and a year of refreshes is a test that
  finishes in a millisecond.
  The policy the core refuses to have lives here: the refresh at 0.85 of what
  the registrar granted and never later than thirty seconds before it lapses;
  the granted expiry winning over the requested one, read off the `Contact`
  the registrar echoed back by §19.1.4 equivalence; one `Call-ID` per boot
  cycle (§10.2.4); a challenge answered from the account, and the same
  challenge coming back a second time stopping rather than locking the
  account; a 423 obeyed once (§10.2.8); and RFC 5626 §4.5's back-off, with the
  wait drawn between half the bound and the bound so that a thousand phones
  that lost one server do not come back in the same second. What cannot be
  fixed by trying again — a 403, a refused password, a redirect — stops and
  says so, with the response whole.
- `Endpoint::token`, so the layer above draws its `Call-ID`s and its intervals
  from the stream the branches come from rather than asking the caller for a
  second seed.

- A refused re-INVITE held its dialog shut. §14.1 lets a new INVITE go once the
  old transaction is "completed or terminated", and a refusal completes it at
  once — the ACK for a non-2xx belongs to the transaction, not to the dialog —
  but the endpoint waited for an ACK it would never build, so nothing could be
  offered again for the thirty-two seconds of timer D. §14.1 asks for a change
  refused with 491 to be offered again after two to four.
- A response to a non-INVITE request `sipral-ua` did not send was dropped
  instead of being passed through. Anything the application starts through
  `UserAgent::endpoint` is its own news, and `UaEvent::Unclaimed` promises that
  nothing is lost on the way through.
- A re-INVITE could not finish. Its responses were offered to the dialog set
  that follows a forked INVITE, which a re-INVITE has none of, so every answer
  to one — 200, 488, 491 — was dropped in silence and the call could never be
  put on hold. RFC 3261 §14.1 is explicit that a re-INVITE never forks, so it
  now has a path of its own: the response feeds the dialog it was sent in, the
  remote target is refreshed from the 2xx (§12.2.1.2), and the ACK is built
  from the re-INVITE so that it carries the right `CSeq`. `Endpoint::reinvite`
  takes an `OutgoingInDialogRequest` and requires the `Contact` §8.1.1.8 makes
  mandatory; the 2xx is acknowledged with the new `Endpoint::ack_reinvite`,
  which keeps the ACK and answers retransmissions with it.
- `Event::Failed` carries the response. A status code alone cannot say what a
  3xx names or what a `Retry-After` asked for, and the bytes were being thrown
  away for every non-2xx final.
- `Event::ResolveNeeded` named the wrong host for a URI with a `maddr`.
  RFC 3263 §4 makes the target the `maddr` when there is one — the response
  path already did this, so the two halves of one rule disagreed.

### Security

- **A party this end holds hears silence, not the microphone.** A hold leaves this end's stream `sendonly` (RFC 3264 §8.4), and `MediaSession::capture` went on encoding the microphone into it, so whoever was put on hold heard the room. From the moment the hold is in force until the resume the frame goes out as silence, with digits and the consent beep still written into it (`MediaSession::is_holding`).
- **The media engine's key stream is forward secure.** Every SDES key, ICE password and DTLS seed came from `SHA-256(media_seed || counter)` with the seed held unchanged, so one read of the engine's memory gave away the keys of every call it had placed (RFC 4086 §6.2). The engine now draws from `KeySource::forward_secure`, which replaces its seed with a one-way step at every block; the endpoint's stream, which replay recordings reproduce, is unchanged.

- **A key's declared lifetime is held to.** An `a=crypto` line's `|2^n` lifetime was parsed and then dropped, so a peer's key opened packets past the count its owner declared (RFC 4568 §6.1). `sipral_rtp::srtp::Policy` has a `lifetime`, which the facade fills from the line, and a `Protector` or `Unprotector` under it protects or opens fewer than that many SRTP and SRTCP packets each, refusing the next with `SrtpError::KeyExhausted`.

- **SDES keys follow RFC 4568 §7.1.4 and RFC 3711 §8.1 on a live call, and are compared and decoded as secrets.** `MediaEngine::readdress` offers a new master key with the new address instead of repeating the old one. A re-offer, from either end, that keeps a key but moves it to a suite running AES in another mode (counter, f8, GCM) is refused, with 488 to a far end's (`MediaError::UnusableKeying`), rather than adopted as new terms. `KeySalt` equality reads every octet, and a decoded `inline:` key is held in a buffer sized once and wiped when it is dropped, a key of the wrong width included.

- **A forked SDES call is re-keyed once a branch answers.** The master key in a forked INVITE reached every branch, and went on protecting what this end sent for the life of the call (RFC 4568 §7.3, RFC 3711 §9.1). A call seen to fork now sends, once confirmed, a re-INVITE with one crypto line under the agreed tag and suite and a freshly drawn key; the answer keys the sending context anew, and the INVITE's key opens nothing sent after it.

- **An SDES key sent or taken over signalling that is not encrypted is said, or refused.** Keys in `a=crypto` went over UDP or TCP with nothing telling the application (RFC 4568 §8.3). `MediaEngine::keys_in_clear` now reads `Some(true)` for a call, or a recording session, whose keys went that way, and the engine's log warns once; `CodecCatalog::with_sdes_signalling(SdesSignalling::SecureOnly)`, or `AccountSrtp::sdes_signalling` per account, refuses such a call, answer or recording with `MediaError::KeysWouldTravelInClear` before anything is sent. `UserAgent::call_signalling_secure` and `UserAgent::placing_securely` say what a call's signalling travels over. The default takes the call, as before.

- **A `sips:` request never leaves on a transport that is not TLS.** A call, registration, subscription or any other request outside a dialog whose Request-URI, first `Route` or `Contact` was `sips:`, or a REGISTER for a `sips:` address of record, went out over UDP or TCP in clear, SDES keys included. The endpoint now refuses it before anything is drawn or written with `SendError::SipsNeedsTls` (RFC 3261 §26.2.2); the same request on TLS or secure WebSocket goes as before.

- **A replay recording carries a seed of its own, and predicts nothing drawn after it.** `UserAgent::start_recording` (and `sipral_stack_recording_start`) wrote the seed the stack was built with into the file, so whoever was handed a recording could work out every later `Call-ID`, tag, branch, SSRC and initial sequence number of that stack. Starting a recording now moves the endpoint onto a fresh seed drawn from a stream derived one way from the stack's own (`Endpoint::reseed`), the recording carries that one, and stopping moves the endpoint on again; a replay built with the recording's seed still draws exactly what the stack drew while it recorded. The seed is no longer a field of `UserAgent`, so a `{:?}` of one prints nothing of it.

- **The log's pseudonym key is derived from the media seed, not made of it, and every copy is wiped; a refused password is not described.** A stack given no pseudonym salt keyed its log and state pseudonyms with its `media_seed` followed by a label, the seed every SRTP master key is drawn from, kept in three plain copies for the stack's life; the key is now `sipral::derived_pseudonym_key`, HMAC-SHA256 keyed with the seed over a label of its own, and the stack, the `Log` and the redactor's `Mode::Hash` hold it in buffers wiped when they go (`sipral::PseudonymKey`), as the two seeds the C ABI reads are once the stack is made. `auth_password` with a control byte or invalid UTF-8 is refused without its offset in the last error.

- **A SHA-2 digest challenge without `qop` is no longer answered RFC 2069-style, and HA1 is wiped.** A challenge naming no `qop` was answered without a client nonce or counter whatever its algorithm; that legacy shape is now kept for `MD5` alone, and a `SHA-256` or `SHA-512-256` challenge without `qop` is ignored as one this stack does not understand (RFC 8760 §2.4, which follows RFC 7616 in making `qop` part of every exchange). `HA1`, the `H(A1)` a `-sess` HA1 is made from, and the inputs hashed from them are now built in `Secret` buffers that are overwritten on drop rather than in plain `String`s.

- **A STIR verifier holds the request's Date to the freshness window, can refuse a replayed PASSporT, and fetches certificates over `https` only.** A full-form PASSporT was judged by its `iat` alone; `Pending::dated` now holds the request's Date to the same window and `iat` to the Date (RFC 8224 §6.2 Step 4), and the agent passes the Date of every INVITE it verifies. `ReplayCache` with `Pending::verify_once` refuses a PASSporT already verified inside its window (§12.1), as `Failure::Stale` with `Staleness::Replayed`; `Failure::Stale` says which time was wrong in its new `what`. An `info` URI under any scheme but `https` is refused with `InfoProblem::Scheme` unless `Config::info_schemes` names it. `Tn::canonical_with` takes the deployment's dialling plan for numbers written without `+` (§8.3). A signer key's PEM body and the block decoded from it are wiped, and a base64 decode that fails part way wipes what it had decoded.

- **An SRTP context no longer trusts its caller with the index or the key width.** `Protector::protect_rtp` counted any sequence number below the last as a rollover and sent a repeated one under the index it repeated, the same keystream (or GCM nonce) twice; it now refuses either with `SrtpError::IndexNotAdvancing` and moves nothing (RFC 3711 §9.1). A master key or salt not the width the suite calls for was padded or cut, a short key becoming an AES key that was mostly zeros; such a context now derives nothing and refuses every packet with `SrtpError::KeyLength`, and `Master::fits` says so before. `Security::rekey_local` and `rekey_remote` given the key in use as a new one keep the SRTP and SRTCP indices and the replay lists, as new terms do (§3.4). A source pushed out of the eight-source table leaves its highest index behind, so a recording of it is refused when it comes back and its rollover counter carries on; with a key derivation rate, a packet's derivation replaces the cached session keys only after its tag verifies. The authentication key, the session salt, the HMAC pads and SHA-1 state, and the GCM key's staging copy are wiped, and a test now holds that a packet which does not open is left as it arrived, which the retired context's second try relies on.

- **A forged epoch-0 handshake message can no longer stall or end a DTLS handshake once only the peer's Finished is left.** A client that had sent flight 5, or a server that had verified CertificateVerify, still read unprotected handshake fragments: a forged HelloRequest under the number the server's Finished would carry moved the client past it, so the genuine Finished was dropped as a retransmission and the handshake waited two minutes for nothing; any other message under that number ended either end's handshake as out of place. Both ends now discard every epoch-0 fragment at or past the Finished's number at that point (RFC 6347 §4.1.2.7), and a HelloRequest is discarded before reassembly at any point of a handshake, so it never takes a number (RFC 5246 §7.4.1.1). A server that has finished answers a retransmitted last flight only when its Finished authenticates, rather than any epoch-0 fragment numbered below it for the life of the connection, and refuses to start its epoch 0 at a ClientHello record number above 2^47 (`illegal_parameter`). Fingerprints under `sha-384` and `sha-512` are read and checked, the longest hash a peer offered preferred (RFC 8122 §5.1), and the random octets a DTLS identity and handshake are drawn from are wiped as they are handed out and when their source goes.

- **The SRTP master key and salt are built in a buffer that wipes itself**.
  `draw_key` drew one block of `SHA-256(media seed || counter)`
  into a plain array, copied the key and the salt out of it into two more,
  and cleared only the block, by hand, with a compiler fence behind it — so
  the two buffers that actually held the key outlived the function on the
  stack. All three are `zeroize::Zeroizing` now, wiped in their own `Drop`,
  which the next edit to that function cannot quietly stop doing. The two
  halves are copied out a byte at a time rather than sliced, and an assertion
  beside the function holds both lengths to the block: this is the one place
  in the tree where reading past the end must not be recoverable, because a
  key of zeros protects nothing while every message still looks right.
  `zeroize` was already in the tree at the same pinned version for
  `sipral-rtp` and `sipral-dtls`; `sipral` now names it directly, and
  `THIRD-PARTY-NOTICES.md` says why.

- **A recorded call is shown, not assumed, to carry no key**.
  The separation of the media seed from the endpoint's own was already built;
  what was missing was a demonstration of it. A test now negotiates a
  real SRTP call between two stacks, records the caller's inbound half with
  the replay recorder, and asserts the caller's own negotiated key appears
  nowhere in the finished recording — and a second test places two calls from
  two agents that share one endpoint seed and differ only in their media
  seed, and asserts the keys they offer differ. The first test was watched to
  fail with the key written in on purpose before it was left passing.

- **No binding reads past the header fields it was handed.** The Swift and .NET
  wrappers printed for `sipral_call_set_headers` took a single `sipral_header_t`
  and the caller's `headers_len`, so any length above one read the memory after
  it, and the Kotlin binding could not be printed at all once `headers` joined
  the call and account configurations. `tools/abi-gen` now reads an array of
  records going in off the declarations — a `const` pointer to a record and the
  `_len` named for it, as parameters or as struct members — and every binding
  takes a list whose own count is what C sees: `[SipralHeader]` in Swift, copied
  into one buffer for the length of the call; `(string Name, string Value)[]` in
  .NET, copied and pinned until the call returns or throws; `List<SipralHeader>`
  in Kotlin, packed, with the JNI shim checking every length against the bytes
  before it points into them. A pointer to records beside a length that is not
  that shape — the `_len` of a writable pointer, or any length beside a record
  with no `size` — and a call answering with text that takes a list are refused
  by name in Swift, .NET and Kotlin rather than printed as one struct.

- **A CR that neither ends a line nor begins a fold makes a message malformed,
  in both parse modes.** It has no reading in RFC 3261 §25.1, and it could never
  be written back: `From: <sip:bob@example.com>;x=a\rb;tag=1` on an INVITE made a
  call that could not be answered, refused or hung up, whose server transaction
  waited for good, and the same byte in a REFER's `Referred-By` got a 202 for a
  transfer that then placed nothing. The parser now answers
  `ParseError::BadHeaderLine`, or `BadStartLine` on the first line.

- **A request whose copied fields arrived folded can be answered.** Every
  response copies `Via`, `From`, `To`, `Call-ID` and `CSeq` from the request,
  and the builder refused the line break a fold leaves in them (RFC 3261
  §7.3.1), so no response to such a request could be written: an INVITE got no
  100, could not be answered, refused or hung up, and its server transaction
  waited for good. A fold now goes out as the one space it stands for; any other
  CR or LF is still refused.

- **A REFER whose `Replaces` unescapes to a control byte draws a 400.** The
  `Replaces` in a `Refer-To` is unescaped to go onto the INVITE sent to the
  transfer target, so `?Replaces=call%00x...` put a NUL into that header, and
  `%0D%0AContact:%20...` a line break the builder refused only after the REFER
  had been accepted with a 202, leaving a transfer that could never be placed.
  The Refer-To is now refused up front (RFC 3515 §2.4.2).

- **A `From` or `To` whose tag is not a token is a malformed field.** The tag
  was unquoted and kept as it came, and a dialog writes it back after `;tag=`
  on every request: `tag="alice1;maddr=198.51.100.66"` put a `maddr` the peer
  chose into the `To` of the BYE, and `tag=bob1, <sip:mallory@example.net>`
  put a second address into it. `RawMessage::from` and `RawMessage::to` now
  refuse such a tag (RFC 3261 §25.1 `tag-param`); a quoted token still reads.

- **A URI holding an unescaped space, control byte, `"`, `<` or `>` is refused
  (`UriError::IllegalByte`).** Kept from a peer and written into the next
  message, each one broke out of where it was put: a REFER whose
  `Refer-To: <sip:carol>;tag=abc@example.com>` made the transferee's INVITE
  carry a `To` tag the referrer chose, and an unbracketed
  `From: sip:a"b@example.com;tag=alice1` left the dialog with no remote tag and
  every BYE addressed `To: <sip:a"b@example.com;tag=alice1>`.

- **`Uri::equivalent` no longer matches a URI whose `maddr` is spelled with an
  escape.** Parameter and URI header names were compared as written, so
  `;%6Daddr=198.51.100.66` was an unknown parameter and ignored, and the URI
  compared equal to the same address without it (RFC 3261 §19.1.4 makes
  `%6D` the letter `m`).

- **`Uri::equivalent` no longer reads a lone `%` as the start of the escape
  after it.** `sip:a%%33B@example.com` decoded `%33` to `3`, the lone `%`
  joined it, and the user compared equal to `sip:a%3B@example.com`, whose
  user holds a semicolon. A `%` that starts no escape is now the octet `%25`.

- **`Uri::equivalent` compares URI header values with their case.**
  `?to=sip:Bob%40example.com` matched `?to=sip:bob%40example.com` and
  `?Call-ID=abc` matched `?Call-ID=ABC`, although RFC 3261 §20 compares both
  with case; header names still ignore it.

- **A fork opens no more dialogs than `max_dialogs` has room for.** Every
  distinct `To` tag answering one INVITE of ours opened a dialog, with no
  bound at all, and each one was looked up by a linear scan of the INVITE's
  branches, so whoever could answer the INVITE decided how much the endpoint
  held and how long each response took. The first dialog of an INVITE, and
  the first 2xx to it, still always open, since a forking proxy can ring one
  phone and have another answer; each further branch opens only while there
  is room, and one
  that finds none is reported without a dialog, or, as a 2xx, is not
  acknowledged here.

- **`max_dialogs` holds for calls that arrive faster than they are answered.**
  The ceiling was measured against the dialogs that existed when an INVITE
  arrived, and an incoming call's dialog is made later, by this end's own 180
  or 2xx; every INVITE that came in ahead of the first answer was let in, and
  answering them all took the store past the ceiling by up to
  `max_server_transactions`. A call now counts from the moment it is let in.

- **An incoming call that rang and was then refused no longer leaves its early
  dialog behind.** The 487 to a CANCEL, a refusal the application sent, and
  the 500 after an unacknowledged reliable 180 all left the dialog the 180 had
  opened standing for the life of the process, so a peer repeating INVITE and
  CANCEL filled `max_dialogs` and had every later call refused with a 503. The
  refusal now ends it with `DialogTerminated { Refused }` (RFC 3261 §12.3),
  including for an INVITE that carried a `To` tag naming no dialog. While a
  reliable provisional response is still unacknowledged the dialog ends with
  the INVITE transaction instead, so that a PRACK crossing the refusal is still
  answered (RFC 3262 §3).

- **An ACK no longer confirms a dialog that no 2xx has confirmed.** An ACK
  naming the tag of a 180 moved the early dialog to confirmed and was reported
  as `IncomingAck`, so anyone who saw the ringing could make a call nobody had
  answered read as up; it is now dropped (RFC 3261 §13.3.1.4).

- **`sdp::parse` had no bound on a session description's size, `m=` count or
  attribute lists — the message parser has had one since it was written, this
  did not.** A body arrives inside a message a proxy may have grown on the
  way, and every line of it becomes an allocation; nothing stopped a hostile
  peer from writing thousands of `m=` blocks, an attribute flood, or a single
  line long enough to be the whole body by itself. `sdp::Limits` now bounds
  body size, line length, `m=` blocks, attributes per section and in total,
  and formats on one `m=` line, mirroring `msg::Limits`'s shape; exceeding one
  is a typed `SdpError`, and every default is sized and documented against
  what a real call plus ICE and SRTP actually carry. `EndpointConfig` gains
  `sdp_limits`, and every place `sipral-ua` reads a session description off
  the wire now parses against it instead of an implicit default.

- **A replay recording no longer carries the means to decrypt what it
  recorded.** SRTP master keys were drawn from the same seeded stream as the
  branches, tags and `Call-ID`s — and that seed is written into every
  recording, in clear, under a document promising the file held only what a
  capture would have held. Anyone handed a recording taken to diagnose
  something else could derive every key the stack had offered and every key it
  ever would. The media engine now has a seed of its own, supplied by the
  application, written nowhere. `MediaEngine::new` takes it as a fourth
  argument; `sipral_stack_config_t` gains `media_seed` and `media_seed_len`,
  and `sipral_stack_create` **refuses** the two seeds being equal, because
  that call is the only place in the library that can see both. The ABI minor
  moves 8 → 9, so a caller built against the older header is turned away at
  create rather than running with one generator for both. A key is now one
  block of `SHA-256(media seed || counter)` rather than two hex tokens, and
  the block is wiped before it leaves the stack.

- **A debug print of a live stack no longer carries the keys.** `{:?}` on a
  user agent printed every `a=crypto` line of every call with its master key
  on it, and every RFC 8599 push token every account held — the one that wakes
  the device, which §4.1 keeps off every request but REGISTER for exactly that
  reason. RFC 4568 §9.2 says the SDP "MUST be protected"; a log file is a worse
  place for a key than an INVITE is, because it is kept. The engine redacted
  its own copy, but that was a rule every other holder had to remember, and
  they did not. The redaction now sits on the four types that carry the
  material — `Attribute` (which keeps the tag and the suite and drops the key),
  the deprecated `k=` line, `KeySalt`, and the push token — so every holder
  above them may derive `Debug` freely and none of them can get it wrong.
  `scripts/check.sh` refuses a build in which one of the four grows a derive
  or loses its own implementation. The `k=` value is now `sdp::KeyLine` rather
  than `String`.

- **A mid-call downgrade is no longer answered by a layer that holds no
  policy.** `SrtpPolicy::Required` promises that a plain re-offer inside a
  live call is refused rather than accepted, and it was — as long as the
  re-offer also changed a codec. A re-offer that kept every format the first
  negotiation settled and moved only the transport profile, or only dropped
  the `a=crypto` line, read as "the same media" to `sipral-ua`, which answered
  it itself: 200 OK, from a layer that has never read a crypto line and knows
  nothing about the account's policy. That is what a B2BUA which has lost its
  own SRTP sends, and what an attacker in the signalling path would send. The
  comparison now takes in the transport profile and whether a key is there at
  all, so both go up to the facade and both are refused with 488 under
  *required*. The `a=crypto` **value** is deliberately not compared: RFC 4568
  §7.1.4 makes a re-offer an opportunity to re-key, and a re-key reaches the
  media session by its own path.

- **An SRTP receiver no longer forgets one source the moment another one
  speaks.** `Unprotector` kept the rollover counter and the replay list of a
  single SSRC, and an authenticated packet from any other SSRC under the same
  master key replaced both. RFC 3711 §3.2.3 names a context by its SSRC and
  RFC 4568 §6.4.2 lets every source a peer sends share one key, so nothing had
  to be forged: once a peer had changed its SSRC, a recording of either source
  was accepted again, and a single packet from a second source cost the running
  one its rollover counter, so everything it sent after its first wrap was
  refused as forged. SRTP and SRTCP now keep that state per source, for up to
  eight sources held in place, and the one heard from least recently is the one
  that gives way.

- **A copy of a secured packet sent from another address no longer costs the
  genuine packet its place.** `RtpSession::receive` ran SRTP before the address
  latch, so a datagram the latch was about to refuse had already had its index
  recorded in the replay list, and the genuine packet arriving from the peer
  afterwards was dropped as a replay. Anyone who could see the stream and get a
  datagram in ahead of it could silence a call packet by packet without holding
  a key. A stream that has latched now refuses a foreign address before SRTP
  looks at the datagram. `RtpSession::rtcp_receive` had the same order for
  SRTCP, so a copied report, a goodbye included, cost the genuine one its
  index in the same way; a secured stream now refuses a report from a host
  its origin check would refuse before SRTCP looks at it.

- **A re-offer that writes a lifetime or an identifier beside an unchanged key
  no longer re-opens the replay window.** The facade decided whether a
  direction had been re-keyed by comparing the whole `inline:` parameter,
  lifetime and MKI included, so the same thirty octets with `|2^31` added read
  as a new master key: the receive context was replaced, its fresh replay list
  accepted packets the stream had already taken, and a peer whose rollover
  counter had moved past zero was refused once the 250-packet grace ran out.
  Only the key and salt are compared now, which are all RFC 3711 §4.3.1 derives
  the session keys from.
