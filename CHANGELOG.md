<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is semantic once 1.0 exists; before that, minor versions may break.

## [Unreleased]

### Changed

- **A transfer taken from C places its call the way `sipral_call_place`
  does** (task 8.4.4). `sipral_call_accept_transfer` used to place an
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

### Added

- **The SRTP policy is now chosen from C** (task 8.4.6). An application
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

- **A call event now names who is on it** (task 8.4.7). `sipral_call_event_t`
  gained `from_uri`, `from_display`, `to_uri` and `call_id`: the `From` URI,
  the resolved `From` display name, the `To` URI and the `Call-ID` of the
  request that opened the call, read once and the same on every event of that
  call afterwards, including the one that reports its end. An application no
  longer has to parse `sipral_event_t::message` itself, or keep a table of its
  own, to know both parties from any event. Appended at the tail of the
  struct, which grows `sipral_event_t` with it — sixty-four bytes this
  build — but `sipral_event_t` carries no pinned length to begin with, so a
  caller built against an older header is unaffected.

- **Early media when this stack runs the audio** (task 8.4.9). An incoming
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
  the gap 8.4.6 left: an answered call could not override the stack's SRTP
  policy at all. Ringing with media twice is `SIPRAL_STATUS_WRONG_STATE`;
  ringing with media after a `sipral_call_ring` that sent no description is
  not, and after one that sent the application's own it is, since every
  description in the responses to one INVITE has to be that same one (RFC
  3261 §13.2.1, RFC 6337 §3.1.1). An INVITE that
  carried no offer is not rung with media (`SIPRAL_STATUS_WRONG_STATE`,
  nothing sent): RFC 3261 §13.2.1 and RFC 6337 §3.1.2 leave an offer from
  this end no provisional response this stack can follow up.

### Fixed

- **Six follow-ups from the transaction and dialog audit (task 8.7.4).** A
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

### Security

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

### Fixed

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

### Added

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
  Two findings of the foundation's review go with it: a hello's extensions
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
  `docs/05-media.md` says which customer needs it out and why, and notes that
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
  dependency graph of `sipral` **and** of `sipral-ffi` — the C library a
  hardware customer ships reaches the codec down an edge of its own, and two
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

### Changed

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
  more.** `SIPRAL_FEATURE_OPUS` — the one symbol a hardware customer is told
  to check for — reached Swift as `fEATUREOPUS` and C# as `FEATUREOPUS`,
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

### Fixed

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
  and from a struct this build cannot read, and the audit that came with it
  found the failure it was written for: `timer_t2_ms` and `timer_t4_ms` were
  taken without complaint on TCP, TLS and WebSocket transports, where neither
  is ever armed — a setting disabled by a neighbouring one, which is the shape
  the requirement describes. Both are refused where they are set now, naming
  the setting and the transport, as is a T2 below the T1 it caps, which makes
  T1 the value that disappears. An expiry too large for the header it goes in
  is refused at the account rather than by the registrar. `sipral_stack_settings`
  reads back what a stack is actually running on, since a zero in the config
  means "the default" and the effective figure is otherwise unknowable.

### Added

- INVITEs refused because the table of watched sources was full are counted
  apart from those refused for calling too fast (`Refusals::by_crowding`).
  Both are one 480 from the far end and two different things to do about it:
  one source over its allowance is a limit set too tight, many addresses at
  once is a flood that wants a firewall.

### Fixed

- A `Require` this agent cannot honour is refused on every request, not only on
  the INVITE that opens a call. §8.2.2.3 says a UAS, not an INVITE: a re-INVITE,
  an UPDATE, an OPTIONS or a NOTIFY demanding an extension that is not
  implemented cannot be honoured as sent, and answering it as though it could is
  worse than declining — a peer that asked for something and got a 200 believes
  it got it. Writing the test found that the OPTIONS handler answered 200 to
  anything it was handed, including this, because it sat first in the event
  chain; it now runs after the check. Only the tags that are actually unknown
  come back in `Unsupported`, which the section asks for by name.

### Added

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

  It also closed a coupling of exactly the shape B7 describes, found inside the
  workspace this morning: `UaEvent::IncomingCall` was destructured field by
  field in the FFI, so adding a field to it broke the build — one agent had
  already had to redesign a feature around it.

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

### Fixed

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

### Added

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

### Fixed

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

### Fixed

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

### Added

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

### Changed

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

### Added

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
