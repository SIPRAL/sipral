<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# sipral-ffi and the language bindings

Codes such as B7, D5 or D6 are requirements in
[`docs/13-client-requirements.md`](13-client-requirements.md).

## The shape

One narrow C ABI, and one idiomatic wrapper per language written on top of it.
The C layer is not meant to be pleasant. It is meant to be stable and small.

Rules for the ABI:

- **Opaque handles only.** No Rust type crosses the boundary. Structs that do
  cross are `#[repr(C)]`, POD, and versioned by a `size` field as the first
  member.
- **Explicit ownership.** Every allocation the library returns has exactly one
  matching free function. Strings are UTF-8, length-delimited, never assumed
  null-terminated on input. No text crosses the boundary in either direction
  without its length beside it, and the only text handed out without one —
  the static names `sipral_status_name`, `sipral_event_kind_name` and
  `sipral_codec_name` return — is NUL-terminated, which a test walking the
  whole declared surface holds
  (`docs/11-testing.md`, "What a field failure is answered by").
- **No panics across the boundary.** Every entry point catches unwinding and
  turns it into an error code. A panic that reaches an `extern "C"` boundary
  uncaught aborts the whole host process (defined behaviour since Rust 1.24, but
  not something the caller can recover from), and a SIP stack sees malformed
  input for a living. This is why the release profile keeps `panic = "unwind"`:
  with `panic = "abort"` there is nothing to catch, and Cargo does not allow a
  per-crate override of that setting.

  Held up by two things rather than by care. The `entry!` macro is the only way
  to declare an entry point, and each of its three shapes reaches for a
  wrapper that catches; a test panics inside one of each shape and asserts the
  status that comes back instead. And `scripts/check.sh` fails if any file
  outside the macro's own module exports a symbol, so an entry point written by
  hand does not reach a release.
- **Errors are integer codes** plus a thread-local last-error string. No
  errno-style globals shared between handles.
- **Events arrive on one callback**, registered per stack handle, carrying a
  tagged union. It is called from inside `sipral_stack_poll`, on the thread
  that polled, and never on two threads at once for one stack, so the language
  side never has to reason about which thread it is on.
- **Nothing is held while the callback runs, so the library may be re-entered
  from inside it.** A poll does the stack's work under the stack's lock, takes
  what the stack has to say out into a queue that owns every byte the events
  point at, and lets the lock go before the first event is delivered.
  Answering an event with a request — hanging up, minting a media handle,
  polling again — is an ordinary call rather than `SIPRAL_STATUS_BUSY`, and a
  device thread that asks for the frame that is due while the callback runs is
  not refused either. `sipral_stack_destroy` works from inside the callback as
  it always has: the poll that is delivering holds its share of the stack until
  it returns, so the rest of that poll's pass still arrives and nothing is
  freed underneath it. What was posted while that pass ran is freed with the
  stack instead of delivered, since no poll can follow a destroy to deliver
  it.

  The queue belongs to the stack, not to one poll. A poll made from inside the
  callback, or from a second thread while another poll is delivering, still
  does the stack's work, and leaves what it raised to the delivery already
  under way — so events arrive in the order they were raised and one at a time,
  and such a poll returns before its own events have been heard. The other
  price is that the stack may have moved past an event by the time it is read:
  a call whose media started and ended inside one poll is already gone when its
  first event arrives, and asking about it then answers
  `SIPRAL_STATUS_STALE_HANDLE`.

  One pass of that queue hands over only what was already waiting when it
  began. What is posted while it runs — from another thread, or
  from the callback it is in the middle of calling — is still in the queue
  when the pass returns, and the very next poll on this stack, even one that
  raised nothing of its own, is what notices and delivers it. The poll whose
  pass left something behind says so in its result, with `has_deadline` set
  and `next_poll_in_ms` zero, so a caller that sleeps until input arrives or
  the deadline passes polls again at once rather than leaving those events
  until something else wakes it. Nothing here
  loops for as long as other threads keep posting behind it, which is what
  used to let one slow callback hold every thread on the stack open
  indefinitely. And the queue itself holds at most `OUTBOX_CEILING` — four
  thousand and ninety-six — events at once: a poll that finds it already full
  drops what it would have added rather than growing the queue or waiting for
  room, since signalling must never block on the application's callback, and
  counts what it dropped in `sipral_counters_t::events_dropped`, appended at
  that struct's tail.
- **Signalling on one stack is one thread at a time, and a second thread is
  told so rather than made to wait.** Every entry point that names a stack
  takes its lock without blocking; one that finds it taken answers
  `SIPRAL_STATUS_BUSY` and does nothing. The lock is held for the work of the
  call that took it and no longer — never across the callback and never for a
  frame of audio — so Busy means two threads that really did arrive together,
  or a frame calling out into its own stack, as the next rule says. The
  `sipral_audio_*` calls are the one family that waits, and on the audio
  engine rather than the stack: asking the platform about its devices holds
  the engine for up to `audio_probe_ms`. A poll only tries the engine's
  lock, leaves the engine's news for the next poll when another thread holds
  it, and asks for that poll twenty milliseconds on, so a slow platform never
  holds the stack's lock with it.
  The reasoning is the module documentation of
  `crates/sipral-ffi/src/stack.rs`, and the generated header puts the rules in
  a few sentences at the top, so a binding author meets them wherever they
  start.
- **A call's media has a handle of its own, and never takes the stack's
  lock.** `sipral_call_media(stack, call, out_media)` mints one once the
  negotiation has settled — `SIPRAL_EVENT_KIND_MEDIA_STARTED` is the moment,
  and minting from inside that event's callback is allowed — and every entry
  point that works on one call's media takes it in place of the stack and the
  call: `sipral_media_receive`, `sipral_media_playback`,
  `sipral_media_capture`, `sipral_media_mix`, `sipral_media_poll_rtcp`,
  `sipral_media_poll_transmit`, `sipral_media_info`, `sipral_media_statistics`,
  `sipral_media_dialling`, `sipral_media_stop_dialling`,
  `sipral_media_record_start`, `sipral_media_record_stop`,
  `sipral_media_record_state`, `sipral_media_codec_candidate_count`/
  `..._at` and `sipral_media_path_candidate_count`/`..._at`. A handle costs
  the stack's lock once, when it is minted, and
  never on the path that runs fifty times a second. `sipral_media_release`
  frees the handle.

  Each session has a lock of its own, and that lock waits. Two threads on one
  call's media — a render thread and a capture thread, or the poll thread
  applying a re-negotiation while a frame is being encoded — wait for each
  other for the length of one frame's work, and that work waits for nothing
  else; a recording adds its write to the frame of the call being recorded and
  to no other. No call waits on another call's media, and none waits on
  signalling or on the callback — with one exception, named because it is
  one: `sipral_media_mix` takes two media handles and holds both sessions'
  locks for the length of one mixed frame, in a fixed order (by handle value,
  never by which one was named first) so that two threads mixing the same
  pair cannot deadlock against each other. So `SIPRAL_STATUS_BUSY` from a
  media entry point means one thing: the thread is already inside a frame of
  a call's media further down its own stack — which only code run during a
  frame, a processor or a local conference's tick, can arrange — and
  answering it is how re-entry stays a status rather than a deadlock. It is
  refused for every media handle, not only the frame's own call: a
  processor on one call reaching into a second call's media while that
  call's processor, on another thread, reached into the first would have
  each thread waiting for the other's frame. The same code calling into the
  call's stack instead — hanging up, polling, destroying it — is answered
  `SIPRAL_STATUS_BUSY` by that entry point too, even with no other thread
  inside: the stack's work can need the very session the frame is holding.

  A media handle outlives its call, and says so. Once the call has ended, or
  its stack has been destroyed, every media entry point answers
  `SIPRAL_STATUS_WRONG_STATE`, and the session behind the handle has already
  been let go, with its recording closed. A hold, a resume or a change of codec
  keeps the handle. `sipral_media_release` is its one matching free, whether or
  not the call and the stack are still there, and a released handle is
  `SIPRAL_STATUS_STALE_HANDLE`; minting twice gives two handles, each released
  once.

  `now_ms` means what it means everywhere else — the caller's milliseconds from
  the stack's origin — but a media entry point neither moves the stack's clock
  nor is checked against it. It runs on a thread that reads the clock apart
  from the one that polls, and a reading a millisecond behind the last poll is
  not a caller bug.

  Signalling makes a smaller version of the same allowance rather than none at
  all. It *is* checked against the stack's own clock — `sipral_stack_poll` and
  every other signalling entry point that takes `now_ms` still refuse a caller
  whose reading has gone backwards; the media entry points above, and
  `sipral_account_freeze`, which only stamps a snapshot, read it unchecked —
  but signalling may be called from any thread,
  and two threads reading the same clock a moment apart do not agree to the
  millisecond any more than a media thread and the poll thread do. So a
  `now_ms` up to fifty milliseconds behind the last one this stack saw is
  honoured rather than refused, and only a jump further back than that is
  `SIPRAL_STATUS_CLOCK_BEHIND`. Honouring one never moves the clock
  backward to it: the stack's high-water mark only ever advances, so a
  fifty-millisecond straggler from one thread cannot make a second thread's
  later, larger reading look like a jump forward it was not. And the clock
  moves only once the call it was read for has actually gone through — a
  refusal for an unrelated reason, a stale handle or a bad argument, leaves the
  clock exactly where it was, because validating `now_ms` and committing it are
  two separate steps in `crates/sipral-ffi/src/stack.rs`.

  **Why a handle, and not a lock per session found through the stack.**
  Finding the session through `stack` and `call` means taking the stack's lock
  on every frame, however briefly, and a frame that can meet the stack's lock
  can meet whatever is holding it. The handle is the one shape in which a frame
  never does. What it costs is a second handle a binding keeps beside its call,
  fetched when media starts rather than when the call is placed.

  **Why `Processor` is `Send`.** A session is now reached from the threads that
  carry its audio as well as from the one that polls, and an echo canceller
  attached to it goes where it goes. The alternative was the library declaring
  in an `unsafe` block that an object it did not write may cross threads — a
  promise about somebody else's code that nothing here can keep. Every serious
  audio API already asks a processing object to move from the thread that
  builds it to the one that runs it.

  **What is still shared.** Media handles live in one table for the process,
  and resolving one takes that table's own lock for an index and a reference
  count — never for a frame, and never while waiting for anything else. That is
  the whole of what hundreds of calls in one process have in common on the
  media path; if it ever shows up in a measurement, the table can be split
  without a signature changing.
- **Nothing is added to a released ABI except at the end of a struct**, guarded
  by the `size` field, or as a new function. Nothing is removed or reordered.
  Ever. `sipral_abi_struct_size` answers what this build compiled a named struct to,
  so a caller can find out that its header and the library disagree in one call
  at load rather than in whichever member happened to move, and
  `sipral_abi_versioned_count` says how many structs there are to ask about,
  so the list a caller walks cannot quietly fall behind the ABI.
- **A numbered space has one declaration, and disagreeing with it is a build
  failure.** The event kinds are declared once, by the `event_kinds!` macro in
  `crates/sipral-ffi/src/event.rs`. The enum, the name a kind prints in a log
  line, and the number that indexes both are generated from that single list, so
  a kind cannot be added to one of them and missed in another. A number is spent
  by appearing in the list, and a generated assertion says the list runs
  `1, 2, 3, …` with nothing repeated, nothing moved, and no hole.

  The hole is what this exists to close. Two features written in two branches
  each take the number after the last kind, each builds, and the one that lands
  second has quietly renumbered an event that a shipped binding already knows —
  B7's failure, one layer down, and permanent because the number is the ABI. So
  the numbers of the features already committed to are spent now, as `reserved`
  lines naming the requirement each belongs to. Taking one means turning that
  line into a kind in place: the number is read rather than chosen, and two
  features cannot read the same one.

  Live and reserved lines interleave, in number order, in one run. That is what
  makes "in place" literal, and it is not cosmetic: a list that made every live
  kind come first would force a feature that wants the sixth reserved number to
  also take the five in front of it, and a number taken by a feature that does
  not exist is exactly the lie the reservation was meant to prevent. The media
  surface took 17 and 19 this way and left 15, 16, 18 and 20 where they were.
  18 has since turned into `SIPRAL_EVENT_KIND_TRANSPORT_WANTED`, in place,
  and so have 15 (`..._SUBSCRIPTION_CHANGED`) and 20
  (`..._ANNOUNCED_CALL_MISSING`); 16 is still reserved.
  27, 28 and 29 were held the same way for three events no requirement numbers
  but the C ABI already planned: a DTMF digit sent by SIP INFO being answered,
  the stack recovering from a suspension or a network change, and a
  destination the application is asked to resolve. All three have since been
  taken where they stood — `SIPRAL_EVENT_KIND_DTMF_SENT` at 27,
  `..._RECOVERY` at 28 and `..._RESOLVE_NEEDED` at 29 — and 16, for audio
  devices, is the one number still held. `..._MEDIA_SECURED` took 32 and
  `..._MEDIA_PATH_CHOSEN` took 33, both of which were nobody's and are the
  ordinary way a number is spent: at the end of the run, because no
  reservation named it. 34, 35 and 36 went the same way to
  `..._MESSAGE_RECEIVED`, `..._MESSAGE_SENT` and `..._MESSAGES_WAITING`
  (RFC 3428, RFC 3842), 37 to `..._QUALITY_REPORT_SENT` for the RTCP-XR
  quality reports, and 38 to `..._MEDIA_UNJOINED` for the local conference's
  own survivor notice. 39 and 40 went to `..._NAT_MAPPING` and `..._NAT_RELAY`,
  and 41 to `..._REFERRAL`, a REFER outside any dialog. 42, 43, 45 and 46 went
  to `..._TURN_STREAM`, `..._AUDIO_DEVICES_CHANGED`, `..._CALL_ADDRESS_WANTED`
  and `..._STUN_SERVER`, with 44 held for audio devices. ABI 0.31 was written
  in four branches at once, so its numbers were handed out before any of them
  was: 47 is `..._CALLER_VERIFICATION`, 48 and 49 are `..._IN_BAND_DIGIT`
  and `..._PROGRESS_DETECTED`, 50, 51 and 52 are `..._CONFERENCE_CHANGED`,
  `..._TEXT_RECEIVED` and `..._PRESENCE_CHANGED`, and 53 is
  `..._TRANSPORT_FAILED`. ABI 0.32 took 54, at the end of the run, for
  `..._LOCAL_CONFERENCE_CHANGED`. The next free number is 55.

  Where a number cannot be generated — `SipralStatus`, which C switches on and
  whose zero is load-bearing — the equivalent is a test that writes out every
  value rather than deriving it, so a declaration that moved would disagree with
  a test that did not.

  `SipralStatus` has one hole, and it is permanent: 17 was passed over when
  ABI 0.31 numbered its statuses, and it stays reserved and never used — no
  build returns it, `sipral_status_name` has no name for it, and the
  enumeration's own documentation says so in every printed binding. 23,
  `SIPRAL_STATUS_CONFERENCE_REFUSED`, came at ABI 0.32.

## Handles

A handle is sixty-four bits naming one thing the library owns: a stack, an
account, a call, a call's media, a subscription, an announced call, a
message send, or a dialog waiting to be resolved. A caller reads nothing out
of it. The layout is written down for the person reading a log line or a
crash dump, and for
whoever adds a table.

- **The layout.** The low twenty-four bits are the slot, the eight above them
  are the tag of the stack the handle belongs to, the four above that are the
  kind of thing it names, and the top twenty-eight are the slot's generation.
  Zero is never a generation, so zero is never a handle, and a handle that lost
  its top half in a 32-bit variable is refused before a slot is read — rather
  than working for the first call on the first stack and failing for every
  other.
- **A handle names something only on the stack that minted it.** Every stack
  numbers its accounts and its calls from the same first slot, so before the tag
  the first call on one stack and the first call on a second were the same
  number, and a hang-up passed to the wrong stack ended that stack's call and
  answered `SIPRAL_STATUS_OK`. An account or call handle used with any other
  stack is now `SIPRAL_STATUS_INVALID_HANDLE`, and the last error says it was
  minted by another stack. The tag is checked where a stack's tables look a
  handle up, `crates/sipral-ffi/src/names.rs`.
- **A handle names something of the kind it was asked for.** The tag alone was
  not the whole of the collision: every table starts its own slots at zero and
  its own generation at one, so on the first stack of a process the stack
  itself, its first account and its first call were *also* the same
  number — tag 0, slot 0, generation 1 — and `sipral_call_hangup(stack, stack,
  now)` reached whichever of the three sat in that slot, most often the account
  or the call, and answered `SIPRAL_STATUS_OK` for a hang-up that named no call
  at all. The four bits of kind are what a handle now carries to say which
  table it came from — a stack, an account, a call, a call's media, a
  subscription, an announced call, a message send, a dialog, or a local
  conference — and
  every lookup refuses a handle of another kind with
  `SIPRAL_STATUS_INVALID_HANDLE` before it looks at a slot, naming the kind it
  actually got. Every handle of every kind, tag included, is put together by one
  function in `crates/sipral-ffi/src/handle.rs` that takes both, so a table
  added later cannot mint without either. Eight of the nine kinds are handed
  out by a call the application made; the ninth, a dialog waiting to be
  resolved, is minted by the library when it raises the event that carries it,
  and is named rather than inserted so a dialog asking again keeps the handle
  it was first given.
- **The widths.** Twenty-four bits of slot is sixteen million live objects on
  one stack. Eight bits of tag is 256 stacks alive in one process, and that is
  the limit: the next `sipral_stack_create` is `SIPRAL_STATUS_EXHAUSTED` and
  writes no handle. Four bits of kind is sixteen values for the nine this
  library mints; a tenth kind is still seven away. What is left for the
  generation is twenty-eight bits rather than the thirty-two a handle with no
  kind could give it: ten calls a second through one slot ran for about
  thirteen and a half years on thirty-two bits and runs about three hundred and
  ten days on twenty-eight. A generation that reaches the limit is retired rather
  than wrapped: nothing here recycles it, because the only two values a wrap
  could land on are zero, which is not a generation, and the first generation
  the slot ever had, which would make its very first handle look live again.
  Retiring the slot instead of wrapping it is what makes a spilled generation
  merely wasteful rather than a handle answering to the wrong kind of thing —
  `join` refuses one at or past the limit outright, so it can never reach into
  the kind above it in the first place.
- **A tag is given back when the stack is gone, not when it is destroyed.** A
  stack takes the lowest free tag when it is created. It gives it back when the
  last share of it goes: inside `sipral_stack_destroy` for a stack nothing is
  polling, and when the poll returns for a stack destroyed from its own
  callback. That poll is still delivering and can still name an incoming call,
  so a tag handed on at the destroy would belong to two stacks that are both
  minting.
- **A tag that comes back brings no old handle back with it.** Given back, a tag
  remembers the highest generation its stack put in any handle, and the next
  stack to take it starts every slot of every table above that. A handle kept
  from the destroyed stack carries the new stack's tag and a generation below
  anything the new stack mints, so it is refused the same way, in the same
  words, as a handle from a stack that is alive. A tag whose generations the
  stacks holding it have used up between them — the limit above, reused between
  them — is not offered again, and the limit is one stack lower from then on.
- A stack's own handle lives in one table for the whole process, whose
  generations never start over, so the handle of a destroyed stack is
  `SIPRAL_STATUS_STALE_HANDLE` even once another stack carries its tag.
- **A mint cannot outlive the tag it mints with.** What puts a tag, a kind and
  the generation high mark together for one table is `Mint`, and it holds a
  share of its stack's lease on the tag rather than a copy of the tag's byte.
  The tag is given back only when the last share goes — the stack's own and
  every mint taken from it — so a mint kept somewhere that outlives its stack
  keeps the tag from going to another stack for as long as it could still mint
  with it, and no handle is ever minted under a tag another stack holds. Every
  mint in the library today lives inside the stack whose tag it shares and goes
  with it, so the tag is given back at the same moment as before.

## Signalling across the boundary

The ABI could describe a call, negotiate its audio, record it and report what it
cost before it could place one. `sipral_stack_poll` counted the bytes the stack
wanted written and threw them away, and there was no way to hand back what
arrived — media I/O was ahead of signalling I/O, so the boundary carried a call's
audio and not its INVITE. `crates/sipral-ffi/src/transport.rs` is the other half.

**A call event names both parties.** `sipral_call_event_t::from_uri`,
`from_display`, `to_uri` and `call_id` are the `From` URI, the `From` display
name, the `To` URI and the `Call-ID` of the request that opened the call — the
INVITE this end sent, or the one it answered — read once, when the call is
placed or arrives, and the same on every event of that call afterwards,
including the one that reports its end. A branch a fork produced answers with
its parent's, since one INVITE is what opened every early dialog among them.
An application that wants to show who is calling, or who a call it placed is
to, reads these off any event and never has to keep a table of its own or
parse `sipral_event_t::message` itself. The URIs are as written in the header,
without the angle brackets and without header parameters such as `tag`; the
display name has its quotes removed and its backslash escapes resolved
(RFC 3261 §25.1), and is null and zero, not merely empty, when the header
named none — the same convention `local_sdp` and `remote_sdp` use for a
description that is not there. **Their pointers are valid for the duration of
the callback that carries them and no longer**, the same rule every pointer in
`sipral_event_t` follows: the queued delivery (or, if the call has since ended
and its own record forgotten, nothing but that delivery) owns the bytes, so a
binding that wants them past the callback copies them the way it already
copies `local_sdp` and `message`.

Appending these four members to `sipral_call_event_t` grows the union they sit
in and, with it, `sipral_event_t` itself — sixty-four bytes longer this build.
That is not the growth the versioning rules below call out, because
`sipral_event_t` carries no pinned length to begin with: it is the one struct
the library alone fills in, handed to a callback as a `const` pointer that a
caller reads no further into than the `size` member says, so a binding
generated against last month's header still reads every member it knew about
and never reaches for the four it did not.

**Six calls, and no socket among them.** `sipral_stack_poll_transmit` takes what
the stack wants written; `sipral_stack_receive_datagram` and
`sipral_stack_receive_stream` hand bytes back; and
`sipral_stack_transport_failed`, `sipral_stack_stream_closed` and
`sipral_stack_transport_bind` are the other three members of `endpoint::Input`,
which is the whole of what the core will hear. The loop is poll, drain, read,
repeat, and it is written out in C in that module's documentation.

**What the stack produced waits until it is taken.** A poll no longer empties the
queue on its way past, because the messages a poll produces are the ones the
caller is about to write; a queue drained by the thing that fills it cannot be
read. `sipral_poll_result_t::transmits_discarded` stays where it is and reads
zero — a released member is never removed, and a build that has to drop a message
again has somewhere to say so.

**A message that does not fit is kept, not dropped.** Outgoing bytes go into a
buffer the caller brings, as in the media path, but with one difference that
matters: a media packet is refused before it is built, and a SIP message has
already been built by the time it reaches here. So a buffer too small answers
`SIPRAL_STATUS_BUFFER_TOO_SMALL` with the length needed in `len` and holds the
message back for the next call — including for a caller that deliberately brings
no buffer in order to ask the length first, which is the same
ask-then-fetch sequence `sipral_last_error_message` uses. The two address buffers
*are* checked up front, because their bound is fixed, so the address side is
never the reason a message is held.

**Addresses are text**, `host:port`, as they are everywhere else in this ABI:
`bind_address`, `registrar_address`, `media_address` and the destination of a
media packet. A `sockaddr` in a `#[repr(C)]` struct would be a second convention
and a portability problem, and a `getaddrinfo` per message is a rounding error
next to the message. `sipral_transmit_t` carries the source address as well,
empty for everything this stack originates: RFC 3581 §4 makes a response go out
from the address its request arrived on, which a caller on a wildcard socket
cannot work out for itself.

**An account with no registrar never registers.** A `registrar_len` of zero in
`sipral_account_config_t` is a trunk that knows this end by the address its
requests come from. `registrar_address` is still required, and is then the
outbound proxy every request the account places is sent to — the same member a
registering account's calls already default to, so placing a call does not
change. The account reads `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING` from the
moment it is added and never moves; `sipral_account_register` and
`sipral_account_unregister` answer `SIPRAL_STATUS_INVALID_ARGUMENT` for it and
send nothing. It is a registration state rather than a status because it is a
fact about the account for as long as the account exists, not about one
request.

**A table of transports, and the main one still published.**
`SIPRAL_TRANSPORT_MAIN` is the transport a stack is created with, and every
call still names it by default — a caller that never binds a second one sees
exactly the surface this crate always had. `sipral_stack_transport_bind` may
now bind more: the number beyond the main one is the caller's own to choose,
the same way `TransportId` one crate down already documents itself as "named
by the caller" and never interpreted, and `out_transport_id` hands the same
number back so a caller always has one place to read the id it is about to
put in `sipral_account_config_t::transport` or `sipral_call_config_t::transport`
— the two new members that say which transport an account's REGISTER, or a
call's INVITE, goes out on, with zero meaning `SIPRAL_TRANSPORT_MAIN` in both,
so a caller that fills neither in gets exactly what it always got. A call's
own `transport` is read only together with an explicit `destination`: with
neither given the call already goes where its account does, over the
account's own transport, and there is nothing to combine a bare `transport`
with. This is also where the §18.1.1 promotion onto a stream now lands,
described two paragraphs on: it spends event number 18, previously reserved.

**A transport that failed is retired, not forgotten.** Both the failure and an
orderly close fail every transaction on the transport and unbind it, which is
§17's "inform the TU and terminate" arriving where an application can see it.
Nothing goes out on it afterwards until `sipral_stack_transport_bind` brings it
back — which is also how a socket re-opened on another address after the
network moved says what goes in the `Via` from now on, how a stream names the
far end it reached, and how a further transport enters the table the first
time. An account whose transport is retired this way is untouched by it: it is
a fact about the transport, and the account starts sending again the moment
the same id is bound.

**The stream path is carried, and the promotion onto it is now too.**
TCP and TLS work end to end: bytes go in as fragments, the layer
below frames them on `Content-Length` (§18.3), and a connection that closes
retires its transport. A WebSocket frame goes in as a datagram, because RFC
7118 §4.2 puts one message in each. §18.1.1 — a request that outgrew a
datagram going out on a stream instead — arrives as
`SIPRAL_EVENT_KIND_TRANSPORT_WANTED`, naming the protocol and the destination
in `sipral_transport_wanted_event_t`, and the call that asked for the request
is refused with `SIPRAL_STATUS_NOT_SENT`, nothing on the wire; the application
answers it with `sipral_stack_transport_bind`, and once that returns
`SIPRAL_STATUS_OK` it asks again — places the call, registers — and the
request leaves on that stream. There is no separate "it went" event.
A request the stack itself sends again — the answer to a challenge, which is
where a request most often outgrows a datagram, its `Authorization` added to
an INVITE offering two SDES suites — is not asked for again: the stack holds
it and sends it the moment the bind succeeds, and the call, registration or
session change behind it carries on over the stream. An application that
cannot open the stream says so with `sipral_stack_transport_failed` (or
`_failure`) naming the transport number it would have bound it at: a failure
told of a transport that is not up while the stack waits for a stream is a
connection that could not be opened, and everything waiting stops at once. A
call's INVITE goes again over the datagram with one SDES suite per stream
when that fits; otherwise the call ends with
`SIPRAL_CALL_END_REASON_UNREACHABLE`, `status_code` and `cause_sip` 513 and
a `cause_text` naming the size and the limit, and a registration fails as
unreachable with a 513. An application that says nothing gets the same ten
seconds after the event. The four idiomatic layers answer the event
themselves (`stream_fallback`, on by default, and `stream_server` for a
server that takes TCP on another port than UDP). The stream stays open for
the rest of the dialog and is pinged like any other (RFC 5626 §4.4.1), but
held to the ten-second pong only once it has answered one: Asterisk answers
none, and a call over its TCP would otherwise lose its connection half a
minute in. A stream the stack does call dead is raised as
`SIPRAL_EVENT_KIND_TRANSPORT_FAILED` with `SIPRAL_TRANSPORT_ERROR_TIMED_OUT`:
the stack has let it go, the socket is the application's to close, and the
four layers close theirs, so that the next `TRANSPORT_WANTED` to the same
place opens a new one.
`sipral_transmit_t::protocol` is still the seam that made this possible
without a second `sipral_stack_poll_transmit`: it says what the message went
out over rather than what the socket is, which is what lets one account's
REGISTER and another's leave on two different transports through the one
queue.

**Header fields go in as an array and come out as offsets.** An application
that labels a call, asserts an identity or reads a carrier's `Diversion` needs
fields this ABI has no member for, and a binding that writes its own SIP parser
to reach them is exactly what the library exists to spare it. `sipral_header_t`
is a name and a value. `headers` and `headers_len` sit at the tail of
`sipral_call_config_t`, for the INVITE, and of `sipral_account_config_t`, for
every REGISTER. `sipral_call_set_headers` sets the fields for what a call sends
afterwards at the application's request: the 180 or 183, the 200, a refusal,
the BYE a hangup turns into, and the re-INVITE or UPDATE of a hold or a resume.
Those are kept until they are set again rather than spent on the first message,
because a field spent on a provisional response that left first is missing from
the 200 that mattered; and they never go on a CANCEL, which a proxy answers and
replaces with its own, or on anything the stack sends by itself.
`sipral_header_t` is the one struct here without a `size`: it is an array
element, strided by its own length, so it cannot grow — and a field is a name
and a value and has nothing to grow into.

Every field is checked before anything is built, and refused with
`SIPRAL_STATUS_INVALID_ARGUMENT` naming the element: a name that is not a token,
a value that is not one line of UTF-8 text, or a field the stack writes itself on
those messages. That list, and the reason for each name on it, is in
`docs/04-ua.md`; the C side adds `User-Agent` when
`sipral_stack_config_t::user_agent` is set. A second `Contact` or `Via` is not a
detail the far end sorts out, it is a message two implementations read two ways,
so refusing it is the one answer that does not leave the choice to whichever hop
reads it first. An account with no registrar refuses `headers` outright, since it
sends no REGISTER to put them on.

Out of a message, four accessors run the parser the stack already runs, over
bytes the caller holds — the message an event carries, or any other.
`sipral_message_header_count` says how many lines a field is on and
`sipral_message_header` reaches one of them by index;
`sipral_message_header_element_count` and `sipral_message_header_element` do the
same for the values of a list field across its lines and its commas, which
RFC 3261 §7.3.1 makes the same message and a proxy may convert between. A field
that is absent is a count of zero rather than a failure, so no status was added
for it, and an index past the count is `SIPRAL_STATUS_INVALID_ARGUMENT`. What
comes back is an offset and a length into the caller's bytes rather than a
pointer: a binding that copied the bytes across the boundary holds its own copy,
and an offset means the same thing in both. Counting and reaching are two calls
rather than one with three values written back because no binding generator here
has a shape for a third. Names match the way the parser matches them, without
regard to case, and a compact form is the field it abbreviates (§7.3.3).

**A binding takes a list of header fields, and C is handed the list's own
count.** A pointer and a length taken separately from the caller are a length
nothing checked against the pointer: the first Swift and .NET wrappers printed
for `sipral_call_set_headers` took one `sipral_header_t` and the caller's
`headers_len`, so any length above one read the memory after it. The generator
reads the shape off the declarations instead — a `const` pointer to a record,
followed by the `usize` named for it with `_len`, is an array of records going
in, whether the two are parameters or members of a struct going in — and each
binding builds the array itself:

- **Swift** takes `[SipralHeader]`, a struct it prints with a `name` and a
  `value`. `SipralHeader.withUnsafeArray` copies every name and value into one
  buffer, points an array of `sipral_header_t` into it and hands that array's
  `baseAddress` and `count` to C inside a closure, so nothing it points at
  outlives the call.
- **.NET** takes `(string Name, string Value)[]`. `SipralHeaderArray` encodes
  and copies the text into one buffer before it pins anything, pins that buffer
  and the records, and is declared with `using`, so both pins go as the call
  returns or throws. `NativeMethods` takes the records as an `IntPtr`, the one
  pointer it does not let the runtime pin, because what the records point at
  has to stay pinned as well.
- **Kotlin** takes `List<SipralHeader>`, a class it prints. `SipralHeader.packed`
  turns the list into one `ByteArray` of UTF-8 and a `LongArray` with the length
  of every piece, and the JNI shim pins the bytes, reads each length once,
  checks it against what is left of them before it makes a pointer, and
  releases the pin whatever the library answered. A negative length, one past
  the bytes, a count that is not a whole number of elements and bytes no length
  accounts for are each an `IllegalArgumentException` before the library is
  called. A list crosses packed rather than as objects the shim walks, because
  walking one makes a local reference per string, which a long list turns into
  more than a native call is promised.

Where the list is a member of `sipral_call_config_t` or
`sipral_account_config_t`, Kotlin's class has a `headers` field, and Swift and
.NET take the list as an argument beside the struct — `configHeaders` — and set
`headers` and `headers_len` from it inside the call, over whatever the caller
left in them. An empty name or value crosses as a null pointer with a length of
zero, which the library reads as empty. A record the generator cannot build an
element out of — one with a `size`, a union, a member that is not text, or, in
.NET, a single member or a name a tuple element may not take — stops it with
the declaration named. So does a pointer to a record with a length after it
that is not that shape, since printed as one struct it would hand C the address
of a single element and a length the caller chose: the `_len` behind a writable
pointer, which is an array coming back that no binding builds, and any length
beside a record with no `size`, which only an array is made of. So does a call
that answers with text and takes a list, directly or in a struct, because such
a call is printed with its parameters handed through as they came.

### Who is calling, why a call ended, and where to send it

ABI 0.29 appends to `sipral_call_event_t`, after `digit`, what the INVITE of a
call that came in said beyond its `From`, read once as it arrived and repeated
on every event of the call, and why the far end ended it:

| Member | What it carries |
|---|---|
| `cause_sip`, `cause_q850`, `cause_text` | on `SIPRAL_EVENT_KIND_CALL_ENDED`: the `Reason` (RFC 3326) of the BYE or the CANCEL that ended the call, or of the refusal (RFC 6432). `cause_sip` 200 on a CANCEL is a forking proxy saying another phone answered — not a missed call |
| `identity_trusted` | whether the INVITE came from a peer in the account's `trusted_peers` |
| `asserted_uri`, `asserted_display` | the first `P-Asserted-Identity`, or a calling `Remote-Party-ID` — only from a trusted peer (RFC 3325 §8) |
| `verstat` | a `sipral_verstat_t`: what the network concluded about the caller's number, trusted peers only |
| `privacy` | the `SIPRAL_PRIVACY_*` bits the caller's `Privacy` asked for |
| `diverted_from`, `diversion_reason`, `diversion_count`, `history_count` | the top-most `Diversion` (RFC 5806) and how many there were; how many `History-Info` entries (RFC 7044) |
| `answer_mode`, `answer_mode_required`, `priv_answer_mode`, `priv_answer_mode_required` | RFC 5373, as `sipral_answer_mode_t` and whether `;require` was said |
| `has_answer_after`, `answer_after_ms` | whether, and after how long, the call asked to be answered without the user — `Answer-Mode: Auto`, `answer-after`, or `info=alert-autoanswer` |
| `ring_source`, `alert_info` | a `sipral_ring_source_t` from RFC 7462's URNs or the `info=` word, and the first `Alert-Info` URI |

Every pointer follows the rule every other one in the event does: valid for
the callback, owned by the delivery. The lists behind the first entries —
every asserted party, every `Diversion` with its reason, every `History-Info`
target and index, every `Alert-Info` URI and `info=` word — are read with
`sipral_call_identity_count(stack, call, which, &count)` and
`sipral_call_identity_text(stack, call, which, index, buffer, capacity,
&needed)`, `which` a `sipral_identity_text_t`, the text copied out with its NUL
the way `sipral_subscription_dialog_text` copies. Whether to answer by itself
is the application's policy: RFC 5373 §4.2 forbids a stack deciding it.

`sipral_call_hangup_for(stack, call, sip_cause, q850_cause, text, text_len,
now_ms)` ends a call with a `Reason` on the BYE or the CANCEL, and only the
Q.850 value on the refusal of an unanswered call. `sipral_call_redirect(stack,
call, status_code, targets, targets_len, reason, reason_len, now_ms)` answers
an incoming call 3xx with the comma-separated `targets` in `Contact` and, when
`reason` is given, a `Diversion` naming the address that was called.

`sipral_account_config_t` grows at its tail too: `session_timer` (a
`sipral_session_timer_t`: default, off, or `session_interval_seconds`, at
least 90) — the per-account session timer the Rust `Account` always had and
C did not; `privacy`, the `SIPRAL_PRIVACY_*` bits every call the account
places asks for, anonymous in `From`; and `trusted_peers`, the comma-separated
addresses whose asserted identities the account believes and toward which
alone it asserts its own. `SIPRAL_FEATURE_CALLER_IDENTITY` (`1 << 12`) says
the build has all of this. SRTP per account came at 0.31, below.

### Who is calling, as a signature says (STIR/SHAKEN)

ABI 0.31, behind `SIPRAL_FEATURE_STIR` (`1 << 16`), the Rust side of which is
`docs/04-ua.md`'s STIR/SHAKEN section. `sipral_account_config_t` appends, after
`srtp_suites` below:

| Member | What it says |
|---|---|
| `stir_verification` | a `sipral_stir_verification_t`: zero or `REPORT` verifies and reports once the stack has trust anchors, `STRICT` refuses what does not verify with RFC 8224 §6.2.2's response, `OFF` verifies nothing |
| `stir_key`, `stir_certificate_url` | the P-256 key every call the account places is signed with — the bare scalar, or an `EC PRIVATE KEY` or `PRIVATE KEY` in DER or PEM — and where its certificate chain is published; both or neither |
| `stir_orig` | the number it signs as, or null for the one in `aor` |
| `stir_origid`, `stir_attestation` | RFC 8588's `origid` (null draws one for the account) and `attest` (zero is `A`) |

A signing account needs the wall clock, which `sipral_stack_stir` gives the
stack as `unix_seconds` paired with its `now_ms` — the one pairing only the
application can make, since `now_ms` counts from wherever the application's
clock does; without it `sipral_account_add` answers
`SIPRAL_STATUS_WRONG_STATE`. A stack that only signs makes that call with no
anchors. `media_clock_unix_seconds` is not taken for it: it goes with no
`now_ms`.

`sipral_stack_stir(stack, &config, now_ms)` takes a `sipral_stir_config_t`:
the trust anchors (PEM or DER, one after another), `freshness_seconds` (zero
for sixty), `certificate_wait_ms` (zero for four seconds) and `unix_seconds`,
and from ABI 0.32 `accept_service_provider_codes`, a `SipralToggle` off by
default: a certificate has authority over the numbers and ranges its
TNAuthList names, and one that names a service provider code instead — what a
SHAKEN certificate carries — covers every number only once this is on, the
decision about the certified providers being the deployment's. A stack
created with `media_clock_unix_seconds` zero dates its RTCP sender reports by
the `unix_seconds` this call pairs with `now_ms`, from then on (RFC 3550
§6.4.1). The called party is compared with the PASSporT's `dest` in every
case — the number or SIP URI in `To` or the Request-URI, each canonical (RFC
8224 §8.3, §8.5) — and a mismatch is `SIPRAL_VERIFICATION_FAILURE_DEST_MISMATCH`
with `detail` naming what was signed and what the request names.
The verification service then works in two halves of
`SIPRAL_EVENT_KIND_CALLER_VERIFICATION` (47), whose `payload.verification`
says which by `stage`:

- `SIPRAL_VERIFICATION_STAGE_CERTIFICATE_WANTED`: fetch `certificate_url`,
  from a cache or over HTTPS, and hand the chain to
  `sipral_call_stir_certificate(stack, call, chain, len, now_ms)` — null and
  zero for one that could not be had. The call waits, and has not been
  announced: `call` names it all the same. The event callback runs with
  nothing held, so the answer may be handed over from inside it, or later
  from wherever the fetch finishes.
- `SIPRAL_VERIFICATION_STAGE_VERIFIED`: the verdict — `outcome`, `failure`,
  `attestation`, `verstat`, `orig`, `origid`, `certificate_url`, `detail`,
  and `response_code`, the response §6.2.2 prescribes. It arrives just before
  `SIPRAL_EVENT_KIND_INCOMING_CALL`, whose call events then carry
  `verification`, `attestation` and `verification_failure` (appended to
  `sipral_call_event_t`); with `refused` set, the account was strict, that
  response went out, and `SIPRAL_EVENT_KIND_CALL_ENDED` follows instead.
  `sipral_call_identity_text` reads `SIPRAL_IDENTITY_TEXT_VERIFIED_ORIG`,
  `_VERIFIED_ORIGID`, `_VERIFICATION_CERTIFICATE` and `_VERIFICATION_DETAIL`
  for the rest of the call.

### SRTP per account, and the encryption report

ABI 0.31, `SIPRAL_FEATURE_SRTP_POLICY` (`1 << 17`). `sipral_account_config_t`
appends `srtp`, a `sipral_srtp_t` for every call of the account over the
stack's own (zero keeps the stack's), and `srtp_suites`, the suites those
calls run, most preferred first, by their RFC 4568 §6.2 and RFC 7714 §14.2
names separated by commas — the SDES lines offered and accepted and the
DTLS-SRTP profiles offered and chosen (`docs/05-media.md`). `sipral_srtp_t`
gains `SIPRAL_SRTP_DTLS_OR_SDES` (6): DTLS-SRTP, falling back to SDES, never
unencrypted.

`SIPRAL_STATUS_SECURITY_POLICY` (18) is what a call refused by its security
policy answers: `sipral_call_answer_media` or `sipral_call_ring_media` on an
INVITE whose offer the call's policy will not carry audio on, which has been
answered 488 by then; and `sipral_call_place`, `sipral_call_ring_media` or
`sipral_call_accept_transfer` naming a `srtp` looser than the one its account
set, before anything is built. A call this end placed that the far end
answered in the clear under a required policy is hung up with a `Reason` of
488, after `SIPRAL_EVENT_KIND_MEDIA_FAILED` with
`SIPRAL_MEDIA_FAULT_SECURITY_POLICY` (10).

The encryption report is `sipral_media_encryption_count(media, &count)` and
`sipral_media_encryption_at(media, index, &stream)`, a
`sipral_stream_encryption_t` per stream: `media`, `encrypted`,
`key_exchange` (a `sipral_key_exchange_t`), `suite`, `authenticated` — set
for a DTLS-SRTP stream once its handshake checked the far end's certificate
against the signalled fingerprint, never for SDES — and `awaiting_keys`.
`sipral_media_event_t` appends `key_exchange`, `encrypted` and
`authenticated`, filled with `suite` on `SIPRAL_EVENT_KIND_MEDIA_STARTED`,
`_MEDIA_CHANGED` and `_MEDIA_SECURED`.

### A call that moves with the network

`sipral_stack_network_changed` answering `SIPRAL_RECOVERY_REBUILD` also
raises `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED` (45, ABI 0.29) for every call
that can still be offered a new description — up, or early in a dialog that
allows UPDATE — with `call` naming it and `payload.call` filled like every
other call event. Its media was described at an address the network no longer
has, and the far end is still sending there. The application binds the SIP
transport at the new address (`sipral_stack_transport_bind`), answers the
ladder with `sipral_account_rebind`, binds a media socket on the new network,
and hands its address to `sipral_call_media_readdress(stack, call,
media_address, public_address, now_ms)`: a re-INVITE with the call's last
description, only `c=` and the port on `m=` moved, and the account's
`Contact` as it is then. The answer arrives as
`SIPRAL_EVENT_KIND_SESSION_CHANGED`, a refusal as
`SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`, and the new socket is the call's
either way. `SIPRAL_STATUS_WRONG_STATE` for a call whose description is the
application's, one whose session runs ICE (`sipral_call_restart_ice` moves
that), or one with a change already on its way. `SIPRAL_FEATURE_CALL_READDRESS`
(`1 << 13`) says the build has both. `docs/16-lifecycle.md` has the reasoning.

### Behind a NAT

**`nat` and `stun_server` on `sipral_stack_config_t`** (appended at
the tail; `MIN_SIZE` unmoved) turn on STUN: `SIPRAL_NAT_STUN` and a server as
`host:port`. Either without the other is `SIPRAL_STATUS_INVALID_ARGUMENT`, and
a build without `SIPRAL_FEATURE_STUN` answers `SIPRAL_STATUS_NOT_SUPPORTED`.
`docs/06-nat.md` has the decisions; this is the order an application meets
them in.

**`stun_fallbacks` on `sipral_stack_config_t`** (appended at the tail in
0.30) names the servers to turn to, in order, when `stun_server` does not
answer: `host:port` addresses separated by commas, refused without a
`stun_server` in front of them. Every socket moves on by itself, and
`SIPRAL_EVENT_KIND_STUN_SERVER` (46) says when the server in use changed or
every one failed (`payload.stun_server`: the state, the server, the one
before it). **`sipral_stack_stun_servers(stack, list, len, now_ms)`** replaces
the list on a running stack, starts STUN on one created without it, and with
an empty list stops it; `docs/06-nat.md`, "More than one server".

The **signalling socket** asks for nothing new. Its Binding request is the
first thing `sipral_stack_poll_transmit` hands out, on the transport it is
about, and the answer goes back in through `sipral_stack_receive_datagram`,
where it is taken before the parser sees it. Every UDP transport
`sipral_stack_transport_bind` binds is kept mapped the same way, and binding
one again at the same address asks again at once. What was learned arrives as
`SIPRAL_EVENT_KIND_NAT_MAPPING` (39), with `payload.nat` saying which socket,
what it maps to, and how many accounts' `Contact` moved onto it — the ones
already holding a binding have registered it by the time the event arrives. An
application that registers only after that event registers the public
`Contact` the first time, which is what the lab's own flow does.

**The registrar's flow is kept open too, with nothing asked of the
application.** Every account whose `Contact` an answer moved onto an address
that is not the socket's own is behind a NAT, and on a UDP transport it sends
its registrar a double CRLF, alone in a datagram, every 20 to 25 seconds while
it holds a binding or is getting one. It leaves through
`sipral_stack_poll_transmit` like everything else on that transport, addressed
to the registrar; the registrar drops it, and a NAT that filters by address
and port has seen this end send to the registrar, which is what keeps the
INVITE's way in open (`docs/06-nat.md`). **`registrar_keepalive` and
`registrar_keepalive_ms` on `sipral_stack_config_t`** (appended at the tail in
0.28; `MIN_SIZE` unmoved) are a `sipral_toggle_t`, on by default, and the
interval in milliseconds, zero for 25 000, from 1 000 to 120 000; anything
else, or an interval with the toggle off, is
`SIPRAL_STATUS_INVALID_ARGUMENT`. `sipral_stack_settings_t::registrar_keepalive_ms`
reads back the interval in force, zero when off. Nothing goes while the stack
is suspended: `sipral_stack_suspending` stops it, and the REGISTER after
`sipral_stack_resumed` starts it again.

A **media socket** is named before its call, because it is the application's
and exists before the call does: `sipral_stack_nat_map(stack, local, len,
now_ms)`, then send what `sipral_stack_poll_stun` hands out — a
`sipral_transmit_t` like `sipral_stack_poll_transmit`'s, whose `source` is the
socket to send from and whose `transport` is zero — and hand what arrives on
that socket to `sipral_stack_receive_stun`. The event for it arrives within
five and a half seconds whatever the server does. A call placed, rung or
answered with that `media_address` before then is `SIPRAL_STATUS_WRONG_STATE`;
after it, the description names the public address. Until that call the socket
is asked again every twenty-five seconds, since nothing else holds its NAT
binding open and an answer minutes old may name a mapping that is gone, so the
loop keeps sending and handing in for it; an answer that differs arrives as
`SIPRAL_NAT_MAPPING_MOVED`, and the queue never holds more than one request per
socket. `sipral_stack_receive_stun` answers `SIPRAL_STATUS_INVALID_ARGUMENT`
for anything that is neither the configured server's answer to a request this
stack sent nor, once a call is described on the socket, the call's (below),
which costs that datagram and nothing more. The answer is spent by the call it
describes.

**Until the call's media handle exists, everything arriving on its socket
still goes to `sipral_stack_receive_stun`,** and the call takes what is its
own. The far end starts its ICE connectivity checks the moment it sends its
answer, so on a call using ICE the first of them can reach the socket before
the 200 is read, or in the poll between `SIPRAL_EVENT_KIND_MEDIA_STARTED` and
the `sipral_call_media` after it. Refused, they would be lost: the far end
checks again no sooner than half a second later (RFC 8445 §14.3). So a check
signed with the password the call's own description gave out, for the call
described on that socket, is kept — the newest sixteen for the socket, a
retransmission in the place of the copy it repeats — and handed to the call's
agent when its session opens, which answers it and checks back on the same
pair as RFC 8445 §7.3 asks of a check that arrives before the peer's
candidates; once the session is open, the datagram goes to it exactly as
through `sipral_media_receive`. Both are `SIPRAL_STATUS_OK`, and a datagram
the session drops is `SIPRAL_STATUS_INVALID_ARGUMENT`. A check kept longer
than the far end's transaction for it lasts, 39.5 seconds, is dropped when the
session opens rather than answered, and everything kept for a call goes with
it when the call ends before its session opens; a check for a call that has
ended is refused. A check nobody can authenticate — unsigned, signed with any
other password, or naming another fragment — is refused like any other
stranger's datagram. From the media
handle on, the socket's datagrams go to `sipral_media_receive` and nowhere
else. A loop that does not read the socket at all until the media handle
exists loses nothing either — what arrives waits in the socket — but it cannot
do that on a socket with a relay, whose refresh is answered here.

**A socket the branches of a forked call share keeps coming here.** A call
placed with `keep_all_forks` that a proxy forks has one media handle per
branch kept, and one offer described them all on the one socket, so what
arrives there says which branch it is for only by what it is: a check names
the phone's ICE fragment, an answer answers one branch's own check, and
media comes from an address among one phone's candidates (RFC 8839 §7.3).
`sipral_stack_receive_stun` hands each datagram to the branch that claims it,
media handles or not — on a stack that asks no server too, which refuses
only what no call takes — and the relay the offer named serves every branch at
once — each branch's agent holds it, lets its own phone through, and lets go
when its branch ends, and the last to let go gives it back
(`docs/06-nat.md`). A loop with one socket per call and one handle per
socket loses nothing by going on as before.

Three entry points rather than a second use of the two signalling ones,
because a media socket is not a transport: a STUN request for it that came out
of `sipral_stack_poll_transmit` would be sent from the SIP socket by every loop
that ignores `source` on a request — every one written so far — and would
learn the SIP socket's mapping instead, silently.

**`turn_server`, `turn_username` and `turn_password`** (appended
at the tail after `stun_server`; `MIN_SIZE` unmoved) add a TURN server
(RFC 8656) to the same path: with them, every media socket
`sipral_stack_nat_map` names is also given a relay on that server, and the
call placed, rung or answered on the socket offers it as its relayed ICE
candidate. They need `SIPRAL_NAT_STUN` — the relay rides on the media-socket
calls above, and the server may be the same address as `stun_server`, as one
coturn usually is — and all three together; anything else is
`SIPRAL_STATUS_INVALID_ARGUMENT`, and a build without `SIPRAL_FEATURE_ICE`,
the only thing that can use a relay, answers `SIPRAL_STATUS_NOT_SUPPORTED`.
The password is copied into memory overwritten when the stack is destroyed,
and it is in no event and no error text.

A relay is used only by a call that runs ICE, and ICE is off by default. Set
`sipral_stack_config_t::ice`, or `sipral_call_config_t::ice` for one call, to
`SIPRAL_ICE_OFFERED`. With the default `SIPRAL_ICE_OFF`, the relay is given
back as soon as the call is described. `docs/06-nat.md` has the policy
values.

**`SIPRAL_ICE_LITE` (4) is the server's value, never the phone's.** It makes
the call an ICE-lite endpoint (RFC 8445 §2.5): the description carries
`a=ice-lite`, its credentials and one host candidate — the media socket, or the
public address `sipral_stack_nat_map` learned for it — and the stack answers
the full peer's checks and puts the call on the pair the peer nominates,
reporting it as `SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN` the way a full agent
does. The answers to the checks leave through `sipral_media_poll_transmit`, as
a full agent's own checks do; a lite end sends no check of its own. It is right
only for a host reachable at the address it advertises — a voice agent in a
data centre on a public address, or behind a one-to-one NAT — answering a
WebRTC gateway or any other full-ICE peer; RFC 8445 Appendix A says ICE "will
not function when a lite implementation is placed behind a NAT", and a peer
told this end is lite stops looking for another path, so a softphone never
names it. A relay is no use to a lite call, which offers a host candidate and
nothing else. `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
`SIPRAL_FEATURE_ICE`, as the other two ICE values are. The Rust facade names it
only with its `ice-lite` feature (or `headless` beside `ice`), which this crate
turns on; nothing of `sipral-headless` comes with it.

Nothing new to call. The Allocate and its authenticated second attempt come
out of `sipral_stack_poll_stun` after the Binding request, and the answers go
back through `sipral_stack_receive_stun`, which hands each to the transaction
it answers even when one server answers both. What the server said arrives as
`SIPRAL_EVENT_KIND_NAT_RELAY` (40), with `payload.relay` naming the socket,
the relayed address and the mapped one for `SIPRAL_NAT_RELAY_ALLOCATED`, or
the server's error code (401, 486, 508; zero for no answer) and a reason for
`SIPRAL_NAT_RELAY_FAILED`. A call on the socket before that event is
`SIPRAL_STATUS_WRONG_STATE`, as it is before the mapping; after a failure it
goes without a relay. Until its call the socket keeps its allocation alive
through the same queue. From the call on the relay is the call's. Until the
call's media handle exists — a caller waiting for the 200, a callee ringing —
what its agent sends still comes out of `sipral_stack_poll_stun`, from the
same socket: the Binding indications that keep the NAT binding towards the
server open, and the refresh that keeps the allocation past its lifetime less
a minute, nine minutes into a ring with coturn's default. The server's answers
go back through `sipral_stack_receive_stun`, which is where a loop that has no
media handle for the socket sends what arrives on it anyway. From the media
handle on, its permissions, channel and refreshes go out through
`sipral_media_poll_transmit` with the rest of the media path, and the
Refresh with a lifetime of zero that gives it back when the call ends comes
out of `sipral_stack_poll_farewell` with the call's other farewells, to be
sent from the call's own socket. A call that does not use ICE — its policy is
`SIPRAL_ICE_OFF`, or the peer answered without it — gives the relay back the
same way as soon as that is known. A call that is refused — for its
configuration before the stack is reached, or by the user agent after the
relay has gone into its description, a `Replaces` among the headers of an
accepted transfer, say, or a second `sipral_call_ring_media` on one call —
sent nothing that named the relay, and leaves it on its socket for the next
call there. A relay nobody takes is given back when the socket is spent by a
call that did not take it.

**`turn_transport`** (appended after `registrar_keepalive_ms`, ABI 0.29;
`MIN_SIZE` unmoved) is how every media socket reaches `turn_server` (RFC 8656
§3.1): zero or
`SIPRAL_TRANSPORT_UDP` as above, `SIPRAL_TRANSPORT_TCP` for the network that
lets no UDP out, `SIPRAL_TRANSPORT_TLS` for the one that lets one port out —
5349, TURN's own — or for the application that wants the server checked. The
relay speaks UDP to the peer whichever it is, and a call uses it exactly as
over UDP; only the carriage changes, the way SIP's does over a stream. The
application owns the connection, one per media socket since the server knows
an allocation by the 5-tuple it was made on:

- `sipral_stack_nat_map` raises `SIPRAL_EVENT_KIND_TURN_STREAM` (42) with
  `payload.turn_stream.state` `SIPRAL_TURN_STREAM_OPEN`, the socket as
  `local`, the server and the `protocol`. The application opens the
  connection — for TLS with the platform's own stack, checking the server's
  certificate against the name it configured, as it does for SIP over TLS —
  and says so with **`sipral_stack_turn_connected(stack, local, len,
  now_ms)`**; the Allocate is in `sipral_stack_poll_stun` when that returns.
  A connection that cannot be opened is `sipral_stack_turn_closed`, and the
  socket's `SIPRAL_EVENT_KIND_NAT_RELAY` is then `SIPRAL_NAT_RELAY_FAILED`. A
  call on the socket before either is `SIPRAL_STATUS_WRONG_STATE`, as before
  the relay's event over UDP.
- What goes on the connection comes out of the queues a datagram for the
  server would: `sipral_stack_poll_stun`, `sipral_media_poll_transmit`,
  `sipral_media_capture`, `sipral_media_poll_rtcp` and
  `sipral_stack_poll_farewell`, with `protocol` — `sipral_transmit_t`'s, and
  `sipral_media_packet_t`'s own, appended — `SIPRAL_TRANSPORT_TCP` or `_TLS`
  rather than `_UDP`, `destination` the server, and the socket the one the
  record names or the call's own. Written as they are and in order: they
  are whole messages already framed, a ChannelData message padded as RFC 8656
  §12.5 asks on a stream. A binding that sends every packet as a datagram
  sends these as datagrams too, to a server that is not listening for them,
  which is why the member is read before the address.
- Everything the connection delivers goes to **`sipral_stack_turn_receive(stack,
  local, len, data, len, now_ms)`**, in whatever pieces it arrived in, for as
  long as it is open: before the call, while the call waits for its session,
  and once its media handle exists alike — the stack puts the messages back
  together and hands each to wherever the socket's relay is, a call's audio
  included, so the media loop reads the socket and nothing more. It is one
  stream: a byte skipped is a stream that never finds its place again, so
  `SIPRAL_STATUS_BUSY` is waited out rather than dropped, and
  **`SIPRAL_STATUS_STREAM_BROKEN`** (12) says the connection carried
  something no TURN message starts with — close it; its relay is lost with
  it, and no close event follows.
- **`sipral_stack_turn_closed(stack, local, len, now_ms)`** says the
  connection went: the relay goes with it (§3.2) — `SIPRAL_NAT_RELAY_FAILED`
  for one still waiting for its call, and for a call that had it, the pair
  through it losing consent while the pairs that need no relay go on.
- `SIPRAL_TURN_STREAM_CLOSE` says nothing more will be written for the
  connection: the relay went back or was lost before a call took it, the
  socket was unmapped, or no call is described on the socket any more — every
  branch of a fork counted, since a branch left may inherit the relay. Write
  what the queues still hold for it, the Refresh that gives the relay back
  among them, and close it.

`SIPRAL_FEATURE_TURN_STREAM` (1024) is set where `SIPRAL_FEATURE_ICE` is; a
build without it answers the three calls `SIPRAL_STATUS_NOT_SUPPORTED`.

**`sipral_stack_nat_unmap(stack, local, len, now_ms)`** is how a
socket named with `sipral_stack_nat_map` that will carry no call after all
says so: it is no longer asked about every twenty-five seconds, a request for
it still queued is dropped, and its relay goes back to the server — a Refresh
with a lifetime of zero, waiting in `sipral_stack_poll_stun` when the call
returns. A socket whose Allocate was sent and not yet answered asks nothing
more, but the server may have allocated all the same: its answer, handed in
through `sipral_stack_receive_stun` as before, is still taken for the forty
seconds the request would have waited, and an allocation it reports is given
back the same way. Without it the stack keeps the allocation refreshed for as
long as it lives. A socket a call was described on was spent by that call already, and a
socket never named is nothing to give back; both are `SIPRAL_STATUS_OK` with
nothing done. `SIPRAL_STATUS_WRONG_STATE` on a stack without
`SIPRAL_NAT_STUN`, `SIPRAL_STATUS_INVALID_ARGUMENT` for a signalling socket.

`sipral_stack_destroy` sends nothing, relays included: the stack owns no
socket, and a relay is given back only by a Refresh this end sends. One still
held when the stack is destroyed stays allocated on the server until its
lifetime runs out, up to ten minutes later, holding a port and a share of the
account's quota. An application that must leave none behind hangs up its calls
and sends their farewells, calls `sipral_stack_nat_unmap` for every socket
still named and sends what `sipral_stack_poll_stun` hands out, and destroys
the stack after that.

All four idiomatic layers -- Swift, Kotlin, .NET and Python -- run all of
this for the application: given a STUN server they name each call's media
socket before describing the call, wait for the mapping (and the relay),
read the socket for the stack until the call's media handle exists, send
every request from the socket `sipral_stack_poll_stun` names to the address
it names, send each farewell to the destination `sipral_stack_poll_farewell`
gives rather than to the last address media came from, and give back every
socket still named when a call ends before its media or the stack closes.
`NatTests.swift`, `NatCheck.kt` and `scripts/lab.sh`'s own `ice_turn_flow`
(driving each binding's idiomatic layer directly, through
`NAT_PAIR_CALLER=python`, `=kotlin`, `=dotnet` or `=swift`) hold them to it
on the wire. All four also open the TURN connection themselves when the
server is reached over TCP or TLS — Swift with Network.framework's
`NWConnection`, Kotlin with an `SSLSocket`, Python with `ssl`, .NET with an
`SslStream` — read it into `sipral_stack_turn_receive`, write on it whatever
is marked for it, and close it when told; `TurnStreamTests.swift`,
`NatCheck.kt`, `test_turn_stream.py` and `TurnStreamTests.cs` prove each
against a TURN server on TCP and on TLS, trusted and not.

### Limits, and what went out twice

ABI 0.30 hands the application the ceilings every endpoint underneath already
had, and the counters that say how close to them a stack runs.
`SIPRAL_FEATURE_LIMITS` (`1 << 15`) is set in every build.

`sipral_stack_config_t` has four members after `audio_device_rate_hz` for
them. Each is zero for its default, and `sipral_stack_settings_t` has the
same four, read back with the default filled in:

| Member | Default | Past it |
|---|---|---|
| `max_dialogs` | 128 | An INVITE that arrives is answered `503 Service Unavailable` before it rings. A call placed with `sipral_call_place` is `SIPRAL_STATUS_LIMIT_REACHED` (16), and nothing goes out. |
| `max_server_transactions` | 256 | A request from another end that would start one more server transaction is answered `503` statelessly. A request inside a call is held to that call's own share instead, and a BYE never is. |
| `diagnostic_decisions` | 64 | The oldest decision of that call's D1 record goes, and the record counts it. Nothing is refused. |
| `diagnostic_records` | 32 | The record written longest ago goes, and the stack counts it. Nothing is refused. |

A call counts against `max_dialogs` from its INVITE on, in both directions:
one that arrives from the moment it is let in, one placed here from the
moment it is sent, until it ends. A refusal from the far end gives the room
back at once, and so does timer B on a call nothing answered, even while the
INVITE's transaction still stands to absorb a repeated response. The first
dialog of a call this end placed always opens, however full the stack has
become since: the application asked for that call while there was room.
A call a proxy challenged (`401`, `407`) is the one exception to "from its
INVITE on": the refusal gives its room back, so the INVITE sent again with
credentials is held to the ceiling like a call placed afresh. When another
call has taken the room in between, the retry is not sent and the call ends
as the refusal that challenged it; the stack never holds one call past
`max_dialogs`.

Neither `503` carries a `Retry-After`. RFC 3261 §21.5.4 has the client try
another server either way; what the header would add is a proxy that sends
this stack nothing at all for that long (the same section's "SHOULD NOT
forward any other requests to that server for the duration"), so one call
too many would shut out every call behind it. A deployment that wants a
proxy to back off for a while says so at the proxy. Every `503` either limit
sends is counted in `sipral_counters_t::requests_refused_at_limit`.

`sipral_counters_t` appends four totals, each only ever growing:

- `requests_retransmitted`: requests sent again because nothing answered in
  time (RFC 3261 timers A and E), and ACKs sent again because the 2xx they
  acknowledge arrived again (§13.2.2.4);
- `responses_retransmitted`: timer G, a reliable provisional response's own
  timer (RFC 3262 §3), and the last response of a server transaction sent
  again because its request arrived again — which is what the far end does
  when that response did not reach it;
- `transactions_timed_out`: transactions that ended because the far end never
  answered or never acknowledged — timers B, F, H and L — and a reliable
  provisional response never PRACKed within 64·T1;
- `requests_refused_at_limit`, above.

Over TCP and TLS nothing retransmits at the transaction layer, so there the
first two stay at zero and only a timeout moves. Over UDP the first two
climbing while calls still connect is a path losing packets before it loses
calls: sampled twice a minute, the difference is the loss an application can
show before anyone complains about it. The same figures are
`Endpoint::retransmissions()` in Rust, where
`Endpoint::transaction_retransmissions(id)` also answers for one live
transaction.

**How fast one address may ring this stack.** Beside the two ceilings, every
stack starts with a floor on INVITEs per source address: ten at once, then
one more every two seconds (`SIPRAL_INVITE_LIMIT_BURST`,
`SIPRAL_INVITE_LIMIT_EVERY_MS`). An INVITE past it is answered
`480 Temporarily Unavailable` before any policy sees it, and counted in
`sipral_counters_t::screened_refused_by_rate`; nothing is raised for it,
because an event queue anybody on the internet can fill is the same attack
one layer up. It is loose on purpose, since a phone's calls all arrive from
the one proxy it registered with. A voice agent or a headless answering
service is the case it does not fit: every call comes from one trunk, dozens
at once when a campaign starts, and the twelfth caller would be answered
`480`. `sipral_stack_invite_limit(stack, SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS,
SIPRAL_INVITE_LIMIT_VOICE_AGENT_BURST)` is the preset for it — a hundred and
twenty-eight at once, the default `max_dialogs`, so that a rush meets the
ceiling's `503` before the rate's `480`, then twenty a second. `Rate::voice_agent()`
is the same preset in Rust, and each idiomatic layer takes it as a
constructor argument (`invite_limit` / `inviteLimit`).

### When a transport fails, and why

Sipral opens no socket and links no TLS library (`22-tls.md`), so a TLS
connection that is refused is refused in the application's code, and until
ABI 0.31 the stack heard only that its transport failed. Every layer on top
then reported "the connection to the server closed" whether the server was
down, its certificate was self-signed, it named another host or it had
expired.

`sipral_stack_transport_failed_with(stack, &failure, now_ms)` is
`sipral_stack_transport_failed` with the reason carried along. The caller fills
in `sipral_transport_failure_t`: the transport, a `SipralTransportError`, a
`SipralTlsFailure` — `UNTRUSTED` (1), `NAME_MISMATCH` (2), `EXPIRED` (3) or
`HANDSHAKE_REFUSED` (4), `NONE` (0) for anything that was not TLS saying no —
and, optionally, the TLS library's own sentence in `detail` (at most
`SIPRAL_TRANSPORT_DETAIL_BYTES`, one line of UTF-8). A server that never
answered is `SIPRAL_TRANSPORT_ERROR_CONNECTION_REFUSED` with the TLS reason at
none. A TLS reason on a transport that speaks neither TLS nor WSS is
`SIPRAL_STATUS_INVALID_ARGUMENT`, and nothing is retired.

Whichever of the three calls retired it — or `sipral_stack_receive_stream`,
for a stream that carried bytes no message starts with — the next poll raises
`SIPRAL_EVENT_KIND_TRANSPORT_FAILED` (53) with `payload.transport_failed`: the
transport, what it spoke, the error (`SIPRAL_TRANSPORT_ERROR_CLOSED` after
`sipral_stack_stream_closed`), the TLS reason and the detail. It comes before
the registration and call events the loss caused, so an application that
shows "registration failed" can say why in the same breath. A connection the
application could not open at all is told the same way, which retires a
transport that carried nothing yet; the bind after the reconnect undoes that.

While a transport is down, a request that would leave on it — registering,
placing a call, a MESSAGE — is `SIPRAL_STATUS_TRANSPORT_DOWN` (22), with nothing
sent, rather than the `SIPRAL_STATUS_NOT_SENT` a request that could not be
built gets: the one says reconnect and ask again, the other says the request
is wrong. A registration already running is not lost meanwhile: it goes to
`SIPRAL_REGISTRATION_STATE_RETRYING` and its back-off carries on, so a
REGISTER due while the connection is being made again waits for the next
rung, and one asked for after `sipral_stack_transport_bind` goes at once.

Event 53 came in the same minor as events 47 to 52, which belong to other
features of it.

### The log, the state snapshot and the RTP port range

Three things an application wants once a deployment is in the field, each
behind `SIPRAL_FEATURE_LOGGING` (bit 14) or the stack's configuration; what
they carry and why is `docs/17-observability.md`.

```c
typedef void (*sipral_log_callback_t)(const sipral_log_record_t *record, void *user_data);
sipral_status_t sipral_stack_log(sipral_handle_t stack, uint32_t level,
                                 sipral_log_callback_t callback, void *user_data);
sipral_status_t sipral_stack_state_text(sipral_handle_t stack, char *buffer,
                                   size_t capacity, size_t *out_len);
sipral_status_t sipral_stack_rtp_port_reserve(sipral_handle_t stack, uint32_t *out_port);
sipral_status_t sipral_stack_rtp_port_release(sipral_handle_t stack, uint32_t port);
```

**The log.** A stack's log is off until `sipral_stack_log` names a level —
`SIPRAL_LOG_LEVEL_ERROR` (1) to `SIPRAL_LOG_LEVEL_TRACE` (5) — and a callback;
the same call again changes either, and `SIPRAL_LOG_LEVEL_OFF` or a null
callback turns it off. A level past trace is `SIPRAL_STATUS_INVALID_ARGUMENT`.
Each line arrives as a `sipral_log_record_t` the library fills (read `size`
first): the stack, the level, a `target` word and the `message`, both UTF-8
with a length and no NUL, and `suppressed`, how many lines the rate limit
turned away before this one. The record and its strings live for the call
alone. **The callback is called at the end of an entry point, on the thread
that made the call, after the stack has been let go** — so, like the event
callback, it may call back into the library, this stack included, and never
answers `SIPRAL_STATUS_BUSY` to itself. One delivery runs at a time. Every
line is already redacted; every refused call into the stack is a debug line
under the target `api` with the status and the sentence
`sipral_last_error_message` would give.

**The state.** `sipral_stack_state_text` copies a text snapshot for a crash report
into `buffer`: accounts and registrations, calls and their states,
transports, media sessions, the last refused calls, the queues, the RTP range
and the counters, redacted. It is never longer than `SIPRAL_STATE_TEXT_MAX`
with its NUL; a smaller buffer is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with the
length needed. It is the one entry point that neither waits for nor refuses a
stack another thread holds: it answers with the snapshot the last poll kept,
and says so on its first line.

**The RTP port range.** `sipral_stack_config_t::rtp_port_min` and
`rtp_port_max`, both zero for none, appended at the struct's tail with the
pin unmoved, and read back in `sipral_stack_settings_t`. A range needs both
ends, at most 65535, the lower not above the upper, and at least one even
port whose odd partner is inside it; anything else is
`SIPRAL_STATUS_INVALID_ARGUMENT` at `sipral_stack_create`.
`sipral_stack_rtp_port_reserve` writes a free even port, with the odd one
above kept for RTCP; the application binds it and describes the call there
with `media_address`. `SIPRAL_STATUS_EXHAUSTED` when every pair is reserved
or described by a call the stack holds, and `SIPRAL_STATUS_WRONG_STATE` on a
stack without a range. A port a call took comes back when the call ends or
moves; one no call took goes back with `sipral_stack_rtp_port_release`. With a
range set, every entry point that takes a `media_address` for the stack to
run the media of — `sipral_call_place`, `sipral_call_ring_media`,
`sipral_call_answer_media`, `sipral_call_accept_transfer` and
`sipral_call_media_readdress` — refuses one whose port the range does not hand
out; a call whose SDP the application writes itself is its own business.

The four bindings carry all three on their stack class: Swift's
`SipralStack.setLog(level:handler:)`, `state()`, and `rtpPortMin`/`rtpPortMax`
with `openMediaSocket(host:port:)`; .NET's `SetLog`, `State()`,
`rtpPortMin`/`rtpPortMax` and `OpenMediaSocket`; Kotlin's
`SipralClient.setLog`, `state()`, `open(rtpPortMin, rtpPortMax)` and
`openMediaSocket`; Python's `Stack.set_log`, `state()`,
`rtp_port_min`/`rtp_port_max` and `open_media_socket`. A stack given a range
binds every media socket it opens without an explicit port from it —
reserving, binding, and on a port another process holds giving it back and
trying the next — so a call placed, answered or moved through the idiomatic
layer lands inside the range with no further code. `LoggingTests.swift`,
`LoggingTests.cs`, `LoggingCheck.kt` and `test_logging.py` prove each: a
refused call logged with nobody in it and silent once off, a state text with
the account and not the person, two stacks on loopback whose call is carried
on even ports from each one's range, and a one-pair range that says
`EXHAUSTED` on the second socket.

Each binding also hands the log to the platform's own logging, with nothing
added to its dependencies: Python's `Stack.log_to` to the `logging` module (a
child logger per target, `sipral.TRACE` = 5 below `DEBUG`), .NET's
`SipralStack.LogTo` to a `TraceSource`, Kotlin's `SipralClient.logTo` to
`java.util.logging`, and Swift's `SipralStack.logTo(subsystem:level:)` to
`os.Logger`, a category per target. The same stack classes read
`sipral_stack_counters` (`counters()`, `Counters()`) and call
`sipral_stack_stun_servers` (`set_stun_servers`, `SetStunServers`,
`setStunServers`), after which a stack created without STUN maps its media
sockets as one created with it would.

### Conferences, presence, real-time text, feedback and recording

ABI 0.31 carries five protocols the facade runs (`docs/04-ua.md`,
`docs/05-media.md`), each behind a feature bit set in every build:
`SIPRAL_FEATURE_SIPREC` (`1 << 20`), `SIPRAL_FEATURE_CONFERENCE` (`1 << 21`,
the conference package, `isfocus`, presence and PUBLISH together),
`SIPRAL_FEATURE_REALTIME_TEXT` (`1 << 22`) and `SIPRAL_FEATURE_RTCP_FEEDBACK`
(`1 << 23`). Two statuses are new: `SIPRAL_STATUS_NOT_NEGOTIATED` (20), for
something the call never agreed, and `SIPRAL_STATUS_NOT_A_FOCUS` (21).

**Conferences (RFC 4575, RFC 4579).** A subscription to the `conference`
package — `sipral_account_subscribe` naming it, or
`sipral_call_subscribe_conference` for the conference a call's focus runs —
keeps a picture of the conference by §4.6's rules, and every document merged
into it is `SIPRAL_EVENT_KIND_CONFERENCE_CHANGED` (50) with
`payload.conference`: the subscription, `SIPRAL_CONFERENCE_UPDATE_APPLIED` or
`..._ENDED`, the version and how many users. A document that follows a lost
one makes the stack ask for full state by itself; a deleted conference ends
the subscription. The picture is read with `sipral_subscription_conference`
(version, users, the focus's `user-count`, `active` and `locked`),
`sipral_subscription_conference_user_at` (one user: its endpoints, where the
first is as a `SIPRAL_ENDPOINT_STATUS_*`, how many media streams) and
`sipral_subscription_conference_text`, which copies the entity, subject,
display text or a user's entity, display text or device the way
`sipral_subscription_dialog_text` copies. A subscription to another package
holds none, and says `SIPRAL_STATUS_NOT_SUPPORTED`. `sipral_call_conference_uri`
copies the conference a call belongs to when its far end's `Contact` said
`isfocus`, and is `SIPRAL_STATUS_NOT_A_FOCUS` otherwise. The other way round,
`sipral_call_set_focus` puts `isfocus` on this end's `Contact` from the next
message a call sends, and `sipral_call_config_t::focus` places or answers a call
that way from its first.

**Presence (RFC 3903, RFC 3856, RFC 3863, RFC 4480).**
`sipral_account_publish_presence` takes a `sipral_presence_t` — open or closed
(`SIPRAL_BASIC_*`), one RPID activity (`SIPRAL_ACTIVITY_*`, none for a
document with no person) and a note — and publishes a PIDF document for the
account's address of record. The first call publishes it and every later one
modifies the same publication; the stack refreshes it, answers the
compositor's challenges, starts afresh after a 412 and meets a 423's
`Min-Expires`. `sipral_account_unpublish_presence` takes it away, and is
`SIPRAL_STATUS_WRONG_STATE` for an account that published none.
`SIPRAL_EVENT_KIND_PRESENCE_CHANGED` (52) says what became of it, with
`payload.presence.kind` `SIPRAL_PRESENCE_KIND_PUBLICATION`, `account` naming
the account, and the state (`SIPRAL_PUBLICATION_STATE_*`), the failure and SIP
status when one was refused, the lifetime granted and when it is refreshed.
The same event with `SIPRAL_PRESENCE_KIND_WATCHED` is a `presence`
subscription's NOTIFY read: open or closed, the first activity, the first note
and the entity, pointing into the event.

**Real-time text (RFC 4103).** `sipral_call_config_t::text_address` names a
second socket the application bound for a call's text, read with
`media_address` on `sipral_call_place`, `sipral_call_ring_media`,
`sipral_call_accept_transfer` and `sipral_call_answer_with`; set without
`media_address` it is `SIPRAL_STATUS_INVALID_ARGUMENT`. The offer carries the
`m=text` stream, an offered one is taken, and once both ends agree
`sipral_media_info_t::has_text` is set. `sipral_media_send_text` queues typed
UTF-8 (`SIPRAL_STATUS_NOT_NEGOTIATED` on a call with no text,
`SIPRAL_STATUS_EXHAUSTED` when more is unsent than a stream holds),
`sipral_media_poll_text` hands out the datagram due for the text socket, and
`sipral_media_receive_text` takes one that arrived on it and says whether it
was this call's. What the far end typed is `SIPRAL_EVENT_KIND_TEXT_RECEIVED`
(51) with `payload.text`: the text, and how many lost blocks it marks with
U+FFFD.

**RTCP feedback (RFC 4585, RFC 5506).** `sipral_call_config_t::feedback`, a
`SipralToggle`, makes a call offer RTP/AVPF with Generic NACKs and
reduced-size RTCP; zero leaves it off, as the facade does, and an offer that
asks for it is answered in kind either way. `sipral_media_info_t` appends
`feedback`, `generic_nack` and `reduced_size`, what the two descriptions
agreed, and `sipral_stream_stats_t` appends `feedback`, `trr_interval_ms` and
the counts: NACKs sent and received, the packets each asked for, Early and
reduced-size packets sent, and feedback the bandwidth held back.

**Recording to a recording server (RFC 7866).** `sipral_call_record_to` takes
a `sipral_record_config_t` — the server's URI, where to send the INVITE and
over which transport (a stream one: the INVITE carries the metadata beside the
offer and is too large for UDP), and the two sockets the copies go from,
`this_end` and `far_end` — and writes the recording session's handle, a call
like any other from then on. It needs a call this stack runs the audio of,
started, and one not already recorded (`SIPRAL_STATUS_WRONG_STATE`
otherwise). `sipral_media_poll_recording`, on the recorded call's media
handle, hands out each copy with the server's address and `out_far_end`, zero
for `this_end`'s socket and one for `far_end`'s; collect them with every
frame. `sipral_call_stop_recording_to` stops the copies and hangs the
recording session up, which the recorded call's end, and the server's hanging
up, do by themselves.

**An encrypted call is recorded encrypted (ABI 0.32).** The copies of a call
keyed with SRTP go to the server as SRTP, offered with SDES keys of their own
in the recording session's INVITE (RFC 7866 §12.2), and a stream the server
will not take that way gets nothing. `sipral_account_config_t` appends
`recording_in_clear`, a `SipralToggle` off by default: on, the account's
encrypted calls are recorded as plain RTP, as an unencrypted call always is.
It is 64 bits wide, unlike every other toggle, because the struct's 0.31
length of 384 bytes ended in four bytes of padding after `stir_attestation`:
a 32-bit member would have sat in them, read from bytes a 0.31 caller may
never have written, and declared the same length. A member appended to a
released struct starts at or past the struct's released length, never in its
tail padding. The keys ride in the recording session's signalling, which is one more reason
to send it over TLS.

`sipral_call_answer_with` is the answer `sipral_call_ring_media` always had
the configuration for: `sipral_call_answer_media` with the call's own
`srtp`, `codecs`, `ice`, `text_address`, `feedback` and `focus`.

`sipral_call_config_t`, `sipral_media_info_t` and `sipral_stream_stats_t`
carry the members above at their tails. The generated layers carry every
entry point, struct and name above.

## Media across the boundary

The ABI is built over `crates/sipral`, the facade that joins signalling to
media, and not over `sipral-ua` alone. Until it was, a client on the other side
of this boundary had to parse its own descriptions, run its own RTP and own its
own audio — which is to say it had to bring a second stack in order to use this
one.

**A call is described one way or the other, never both.** Set `media_address` in
`sipral_call_config_t` and the offer is written from this stack's codec order,
the answer is read, and the call gets a media session; answer an incoming one
with `sipral_call_answer_media` for the same. Set `sdp` instead and the
application describes its own session and runs its own audio, exactly as before.
Setting both is `SIPRAL_STATUS_INVALID_ARGUMENT`: two descriptions of one
session is one too many.

**A managed call answers its own re-offers.** The engine writes the answer, from
the same codec order, inside the poll that saw the request — so
`SIPRAL_EVENT_KIND_SESSION_OFFERED` never arrives for one, and
`sipral_call_accept_session` on it is `SIPRAL_STATUS_WRONG_STATE`. The
application hears the outcome as `SIPRAL_EVENT_KIND_MEDIA_CHANGED` when the
re-offer actually moves the session it is running — a different codec, a
different address, a different direction. One that adds nothing this stack's
catalogue would pick, or otherwise repeats what is already running, reports
nothing: the codec order was answered from and the media itself never moved,
and an event for a change that was not one would be the same false signal
`ring`/`ring_with` learned not to send on the ACK that merely confirms a call
already settled.

A call the application describes hears as `SIPRAL_EVENT_KIND_SESSION_OFFERED`
every re-offer this stack cannot answer for it: a codec change, a stream
added or dropped, and anything at all on a secure profile — a hold included,
because its answer has to carry the application's own SDES key, or its
fingerprint and the DTLS role the call already has, and those are the
application's. `sipral_call_accept_session` keeps a hold this end asked for in
whatever answer it is given, so answering `sendrecv` to the far end's change
does not take a call off hold behind its user's back.

**And asks for its own codec changes.** `sipral_call_change_codecs(stack,
call, codecs, codecs_len, now_ms)` re-offers a managed call on another list,
named the way `sipral_call_config_t::codecs` names one. Only the codecs
change — `docs/05-media.md` says what is carried unchanged and why, and how
each payload type number keeps its codec — and a held call stays held, so
`sipral_call_resume` afterwards takes it off hold on the new list. The outcome
is `SIPRAL_EVENT_KIND_MEDIA_CHANGED` naming the codec the answer settled on,
or `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED` with the call left on the list it
had. A call placed or answered with `sdp` is the application's to re-offer,
and is `SIPRAL_STATUS_WRONG_STATE` here.

**And restarts its own ICE.** `sipral_call_restart_ice(stack, call, now_ms)`
re-offers a managed call running ICE with new credentials of this end's own —
both `ice-ufrag` and `ice-pwd` changed, which is how RFC 8839 §4.4.1.1.1
signals a restart — and the candidates its agent still holds, and nothing
else of the description moved. Nothing reaches the running agent until the
far end accepts (§4.4); then it checks again under both ends' new
credentials while the pair it had goes on carrying the audio, and the new
selection arrives as another `SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN`. The far
end's checks that beat its answer back are kept and answered when it comes.
A refusal is `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`, with ICE as it was.
It is the remedy for `SIPRAL_MEDIA_FAULT_ICE` after consent was lost, and for
a network change this end sees first. `SIPRAL_STATUS_WRONG_STATE` for a call
placed or answered with `sdp`, a call running no ICE agent, or while another
change is on its way; `SIPRAL_STATUS_NOT_SUPPORTED` from a build without
`SIPRAL_FEATURE_ICE`.

One session change runs in a call at a time (RFC 3261 §14.1). A
`sipral_call_hold` or `sipral_call_resume` asked for while another is running
— one of this end's not yet answered, or one of the far end's not yet answered
here — succeeds and waits, and goes when that change is over; the last one
asked for is the one that goes, and one still waiting when the call ends goes
with it, unsent. `sipral_call_change_codecs` is refused with
`SIPRAL_STATUS_WRONG_STATE` instead, because the offer it writes is built from
a session the running change is about to move. For the same reason a codec
change told to wait by a 491 is not offered again if the far end's own change
was answered in that wait: it ends in `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`
with the call on the list the far end's change left, and can be asked for
again. A hold or a resume in the same position goes again, written over the
session as it now stands.

**Two calls can be joined into a local conference of three.**
`sipral_call_join(stack, call_a, call_b)` pairs two calls this stack already
has media on, so that each far end hears the other's far end and this end's
own microphone, mixed — `docs/05-media.md` has the arithmetic and the reasons
behind it. Nothing like a SIP conference server: neither far end's own
signalling ever names the other. `sipral_call_leave(stack, call)` un-pairs
both calls, whichever one `call` names, and a call that ends while it is
still joined takes the pairing down with it the same way, unasked — the
survivor is told with `SIPRAL_EVENT_KIND_MEDIA_UNJOINED`, its `call` naming
that survivor, rather than being left to find out only when a later
`sipral_media_mix` on the pair answers `SIPRAL_STATUS_WRONG_STATE`. Both
`join` and `leave` take the
stack's lock, like `sipral_call_change_codecs`, because pairing two calls is
a fact about the stack, and both are `SIPRAL_STATUS_WRONG_STATE` for a call
this stack writes no description for, one with no session yet, or — `join`
only — one already in a pair, or two calls whose sessions would decode at
different rates or cut audio into frames of different lengths (nothing here
resamples).

Driving a frame of the pair is a different entry point, and does not take
the stack: `sipral_media_mix(media_a, media_b, ...)` takes two *media*
handles, the same kind `sipral_media_playback`/`sipral_media_capture` do,
decodes both, mixes what each of the three parties is owed, and sends the
two frames the far ends are owed. It does not check that `sipral_call_join`
was ever called on the pair it is handed — that would mean taking the
stack's lock on every frame, which is exactly what a media handle exists to
avoid — so it trusts the caller the same way every other media entry point
already does. What it does check, because two sessions have to be locked
together rather than one, is the order it locks them in: by handle value,
never by which one the caller named first, so that two threads mixing the
same pair with the arguments swapped wait for each other instead of
deadlocking.

**Any number of calls can be mixed in a local conference (ABI 0.32).** The
pair above needs two calls at one rate; a local conference takes any number,
each on its own codec, rate and frame — 8 to 48 kHz, 10 to 60 ms — with or
without this end, and every member hears everybody but itself.
`sipral_local_conference_create(stack, config, &conference)` makes one:
`sipral_local_conference_config_t` says how many members it holds (this end
included), whether this end takes part, and the rate of this end's frames.
`sipral_local_conference_add` and `sipral_local_conference_remove` take a
call in and out; a call already in a conference or joined into a pair, a
full conference and a codec it cannot mix are all
`SIPRAL_STATUS_CONFERENCE_REFUSED` (23), and `sipral_call_join` refuses a
member the same way it refuses a call already paired. Where a member is
named — a mute or a gain each way (`sipral_local_conference_set_muted`,
`_set_gain`, in the audio engine's steps), `sipral_local_conference_member_at`,
`sipral_local_conference_talker_at` and the event — a call is named by its
call handle and this end by the conference's own handle. The whole mix is
recorded with `sipral_local_conference_record_start`, one channel, in any of
the call recorder's formats.

Who drives it depends on the stack's mode. In device mode the audio engine
carries the conference as one more entry: it lets go of each call as the
call is added and takes it up again as it leaves, the microphone is this
end's voice and the loudspeaker plays this end's share, and every packet a
member owes its far end reaches `audio_transmit_callback` under that
member's own call handle. In application mode the application ticks it every
twenty milliseconds, from the thread that carries its audio:
`sipral_local_conference_tick` takes this end's microphone frame and fills
its loudspeaker frame, and `sipral_local_conference_poll_transmit` hands out
the packets, each with the call whose socket sends it. Neither takes the
stack's lock; a member's own `sipral_media_playback` and
`sipral_media_capture` belong to the conference while it is in it, and its
`sipral_media_receive`, RTCP and DTLS stay where they were. Who joined, who
left and why (removed, its media ended, or a codec change the conference
cannot follow), who is talking — loudest first, with hysteresis — and a
recording that stopped by itself arrive as
`SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` (54) from the stack's poll.
`sipral_local_conference_destroy` hands every member back. The feature bit is
`SIPRAL_FEATURE_LOCAL_CONFERENCE` (`1 << 24`), and `docs/05-media.md` has
the mixer underneath.

**A processor attached with `sipral_media_attach_processor` runs on the media
path, not on the poll thread.** Unlike `sipral_event_callback_t`, which is
called from inside `sipral_stack_poll` with nothing held, `process` is
called from inside `sipral_media_playback` and `sipral_media_capture`, on
whichever thread the application called those from, with the phone call's
media locked for the duration of that one entry point — the same footing
`sipral_screen_callback_t` stands on, and the opposite of every other
callback in this ABI. Two consequences follow directly from that lock:
`process` must not call back into the media handle it was attached through,
on this thread or on any other, because every media entry point takes its
session's lock without waiting and answers `SIPRAL_STATUS_BUSY` rather than
block — so the call would not deadlock, it would just be refused, but it is
refused outright rather than a caller being invited to rely on it. And
`process` must not unwind past this boundary, the same rule every callback
here is held to: a panic that reached C uncaught would abort the host
process rather than fail one call. A *different* call's media, and this
stack's own entry points reached through `sipral_stack_config_t`, are both
unaffected — the lock is the one session's, not the stack's.
`sipral_media_reset_processor` calls `process` the same way, from whichever
thread called it, with `sipral_processor_frame_t::reset` set instead of a
frame to run.

**SRTP is a policy, chosen from C, for a call this stack describes.**
`sipral_stack_config_t::srtp` is the stack's default and `sipral_call_config_t::srtp`
overrides it for one call; both are a `sipral_srtp_t` — `SIPRAL_SRTP_NOT_OFFERED`,
`SIPRAL_SRTP_OFFERED` or `SIPRAL_SRTP_REQUIRED` — or zero, which is not a fourth
value but means "unspecified" and resolves differently on the two structs: on the
stack it is this build's own built-in default, `SrtpPolicy::default()`
(`crates/sipral`), which is `SIPRAL_SRTP_NOT_OFFERED` — nothing here offers
encryption until it is asked to, for the reason `SrtpPolicy::NotOffered`'s own
documentation gives; on a call it is the stack's own setting, whatever that came
to. Any other value is `SIPRAL_STATUS_INVALID_ARGUMENT` before anything is
built, and `srtp` is read for no call but one this stack describes the media
of — a call placed with `sdp` instead is a session the application wrote, and
what goes on its own `m=` line is the application's to decide. The three named
values mean exactly what the three `sipral::SrtpPolicy` variants mean: what
`SIPRAL_SRTP_REQUIRED` and `SIPRAL_SRTP_OFFERED` write to the offer is the
same secure profile with one key, and the two differ only in what each does
with a plain re-offer or a plain answer, which is `docs/05-media.md`'s to
explain and not this ABI's to duplicate. `sipral_media_info_t::secured`
already reports the outcome a session actually reached; `srtp` is only ever
the request. `SIPRAL_FEATURE_SRTP` in `sipral_capabilities_t::features`
answers whether this path exists in the build at all, from the same
`sipral::Capabilities::srtp` this crate has always read it from — true in
every build, because SDES keying is compiled in unconditionally and not behind
a Cargo feature.

The choice between SDES and DTLS-SRTP grew into the same member, as that
paragraph said it could: `SIPRAL_SRTP_DTLS` and `SIPRAL_SRTP_DTLS_REQUIRED`
are two more values of `srtp` rather than a second member, and
`SIPRAL_FEATURE_DTLS_SRTP` says whether this build has a handshake behind
them. Both numbers are in every header — a value that has left it is spent for
good — and a build without the feature answers `SIPRAL_STATUS_NOT_SUPPORTED`
rather than placing the unencrypted call the policy was chosen to prevent.

**A DTLS-SRTP call has one obligation no other call has**, and an application
that does not meet it gets a call that rings, answers and carries nothing:
`sipral_media_poll_transmit` must be drained to empty, after every
`sipral_media_receive` that answered `SIPRAL_ARRIVAL_HANDSHAKE` and at every
deadline `sipral_stack_poll` names. It is the fifth media call, beside
receive, capture, playback and `poll_rtcp`, and it exists because the key
exchange runs on the media socket rather than in the signalling: a record that
never leaves is a ClientHello that never goes out, and DTLS takes two minutes
to notice. Between the answer and `SIPRAL_EVENT_KIND_MEDIA_SECURED` the call
is up and silent by design — `sipral_media_capture` answers a `len` of zero
and every arrival is `SIPRAL_ARRIVAL_NOT_KEYED` — because a stream that agreed
to be encrypted and sent one packet in the clear has leaked exactly what it
was asked to protect. `SIPRAL_EVENT_KIND_MEDIA_SECURED` carries
`payload.media.suite`, the transform the handshake chose, which the signalling
never named: `SIPRAL_SRTP_SUITE_AEAD_AES256_GCM` between two ends of this
stack, and one of RFC 5764's two AES-CM profiles with a peer that offers only
those. Every suite the stack runs has its own `sipral_srtp_suite_t` since
ABI 0.29, RFC 6188's `AES256_CM80`/`_CM32` (4, 5) and RFC 7714's
`AEAD_AES128_GCM`/`AEAD_AES256_GCM` (6, 7) included; `UNKNOWN` is left for an
event that is not about a transform.

`srtp` sits at the tail of both structs, and zero means "unspecified" —
exactly what leaving it alone does.

**The codec order is a property of the call, not of the process** (D6).
`sipral_stack_config_t::codecs` is the stack's order and
`sipral_call_config_t::codecs` overrides it for one call — the same
comma-separated list of names, refused the same way for a stray comma, a name
given twice, or a name this build has no encoder for. Two accounts on two
codec policies no longer need two stacks, and the override is derived from the
stack's catalogue rather than from a fresh one, so everything the call said
nothing about — frame length, named events, multiplexing, and SRTP where the
call's own `srtp` does not override it — is what the stack was configured
with. Nothing shared is mutated: the call gets a catalogue of its own, which
is what keeps a second call off the same stack offering what the stack was
configured with. `codecs` is read for no call but one this stack describes the
media of, for the same reason `srtp` is, and the names are still checked
wherever the struct is read, so a caller with one wrong learns it from the
entry point it called rather than from a call that behaved as though it had
not been set.

**G.729's Annex B is a stack setting, appended at the tail of
`sipral_stack_config_t`** as `g729_annex_b`, a `SipralToggle` like the other
switches there: zero is this build's default, which is on — a `G729` line
with no parameter allows Annex B (RFC 4856 §2.1.9), so an offer says
`annexb=yes` — and `SIPRAL_TOGGLE_OFF` makes both offers and answers say
`annexb=no` and keeps this end's encoder from sending SID frames. It is the
catalogue's `CodecCatalog::with_g729_annex_b`, and it crosses the way
`offer_dtmf` and `offer_rtcp_mux` do: a call's own `codecs` keeps it, since
the override is derived from the stack's catalogue, and
`sipral_stack_settings_t::g729_annex_b`, appended at that struct's tail,
reads back what it came to. It is taken whatever `codecs` names, because a
call's own order can name G.729 when the stack's does not; anything but the
three toggle values is `SIPRAL_STATUS_INVALID_ARGUMENT` and builds nothing.
`docs/05-media.md` says what Annex B does on the wire.

**Why each codec lost** (D5) is the reporting half.
`sipral_media_codec_candidate_count` and `sipral_media_codec_candidate_at`
walk this call's own order and say what became of each entry: it won
(`SIPRAL_CODEC_OUTCOME_CHOSEN`, exactly one, naming the same codec as
`sipral_media_info_t::codec`), the far end never named it
(`..._NOT_NAMED`), or the far end named it and something this end preferred
won (`..._OUTRANKED`, with `outranked_by` naming what). The list is what the
negotiation itself recorded, kept from the moment it recorded it, not worked
out again when it is asked for: a second run against a description that has
since been renegotiated would disagree with the first in exactly the case
somebody is debugging. Both take a media handle, like `sipral_media_info`, so
neither reaches a stack and neither can wait on one. A count of zero is an
answer — a call negotiated from a description with no media line in it had
nothing in the running at all.

**Why each path lost** is D5's other half, for a call running ICE.
`sipral_media_path_candidate_count` and `sipral_media_path_candidate_at`
walk every candidate pair the call's agent formed, in the order its checklist
took them in, then every relay it held, and fill a `sipral_path_candidate_t`
(88 bytes): `kind` (`SIPRAL_PATH_KIND_PAIR` or `..._RELAY`), `outcome` and,
beside it, `code`, the pair's `priority` (RFC 8445 §6.1.2.3), what kind of
candidate each end is (`SIPRAL_CANDIDATE_KIND_HOST`, `..._SERVER_REFLEXIVE`,
`..._PEER_REFLEXIVE`, `..._RELAYED`), and the two addresses as `host:port`,
written into two buffers the caller brings the way `sipral_media_packet_t`
brings its destination — `local`/`local_capacity` and `remote`/
`remote_capacity`, each at least `SIPRAL_ADDRESS_BYTES` or null for an
address not wanted, `SIPRAL_STATUS_BUFFER_TOO_SMALL` before anything is
written otherwise. For a pair, `local` is the candidate its checks left from
(a reflexive candidate is paired as its base, RFC 8445 §6.1.2.4) and
`remote` the far end's; for a relay, the relayed address and the TURN
server. The outcomes: `SELECTED` — the pair the media takes, or the relay it
runs through; `VALID` and `WAITING` while nothing has decided; `OUTRANKED`,
a pair that worked and lost to one of higher priority; `NOMINATED_ELSEWHERE`,
one another was nominated ahead of (§8.1.2 takes the unfinished pairs off the
checklist at the selection); `TIMED_OUT`; `REFUSED`, with the far end's STUN
error in `code`; `NOT_SYMMETRIC`, an answer from an address other than the
one the check went to (§7.2.5.2.1) — a NAT between rewriting it;
`UNUSABLE`; `RELAY_REFUSED`, with the TURN server's error in `code`, for a
relayed pair whose peer the relay would not let through; `NOT_CHECKED`, a pair
the pair limit discarded or its checklist ended before; and for a relay,
`HELD`, `RELEASED` — given back unused (§8.3.1), or let go of by the branch
of a forked call that ended — and `LOST`, with the server's code. Like the
codec list, it is what the agent wrote down as each transaction ended, not
worked out again; a restart (RFC 8445 §9) starts it again. A call not using
ICE has none, and a count of zero.

**`sipral_call_ring_media` rings an incoming call with this stack running the
audio:** the answer to the offer the INVITE carried is written
from this stack's codec order against `config.media_address`, and the session
opens on it there and then, before anybody answers — the far end hears
whatever the application plays on it, `SIPRAL_EVENT_KIND_MEDIA_STARTED`
follows, and the 183 goes reliably exactly when `sipral_call_ring` would send
one reliably (RFC 3262 §3, decided from the INVITE's own `Require` or
`Supported`, not from anything this entry point reads). `config.srtp`
overrides the stack's own SRTP policy for the call, applied through the
facade the same way `sipral_call_place` applies it — the one way an incoming
call can choose its own SRTP policy at all, since `sipral_call_answer_media`
takes no configuration of its own and so could not before this. `config.codecs`
overrides the stack's codec order for the same call over the same window, and
what `sipral_call_ring_media` settles is what `sipral_call_answer_media`
keeps. Every other
member of `config` names something a call to place needs — `target`, `sdp`,
`destination`, `keep_all_forks`, `headers` — and this call already exists, so
each is `SIPRAL_STATUS_INVALID_ARGUMENT` by name if set, the same struct read
through the same versioned reader and `MIN_SIZE` as `sipral_call_place`. An
INVITE that carried no offer is `SIPRAL_STATUS_WRONG_STATE`, with nothing
sent: the offer this end would make instead does not belong in a
provisional response this stack can follow up (`docs/05-media.md`).

`sipral_call_answer_media` after `sipral_call_ring_media` reuses the session
and the description rather than negotiating a second one: no second `o=` id
or version, and `media_address` is not used a second time — it must still be
an address and a port, the same check any call to it gets, but the one given
to `sipral_call_ring_media` is the one the session keeps. What the 200 OK it
sends then carries is RFC 3262 §5 and RFC 6337 §3.1.1's rule, from whether
the 183 went out reliably — nothing, when it did, since RFC 6337 forbids
repeating an answer already sent reliably; the same description again,
unchanged, when it did not, since an early answer sent unreliably is only a
preview and the 200 OK is where the exchange actually completes. Ringing
with media twice on one call is `SIPRAL_STATUS_WRONG_STATE`, and so is
ringing with media after a `sipral_call_ring` that sent a description of the
application's own, since every description in the responses to one INVITE
has to be that same one; after a `sipral_call_ring` that sent none it is
not — see `docs/05-media.md`, "Ringing with media", for the reasoning in
full.

**`sipral_call_accept_transfer` takes a `sipral_call_config_t` now**,
and places the call a REFER asked for the way `sipral_call_place`
places one: `media_address` for an offer this stack writes and runs the
audio of, `sdp` for a description the application wrote and runs its own,
`srtp` overriding the stack's policy for the former the same way it does on
`sipral_call_place`, and `headers`, `destination` and `keep_all_forks` for
the INVITE this places — read through the same versioned reader and
`MIN_SIZE`. `Replaces` and `Referred-By` among `headers` are
`SIPRAL_STATUS_INVALID_ARGUMENT`, nothing sent and the transfer still there
to take: that INVITE takes both from the REFER. Giving neither `sdp` nor `media_address` is
`SIPRAL_STATUS_INVALID_ARGUMENT`, the same refusal `sipral_call_place` gives
for the same reason: the answer to an offerless INVITE belongs in the ACK,
and this ABI has no way to hand one back from there. `target` is the one
member this call does not read: the far end already said where the transfer
goes, and a target of the caller's own would be a second one contradicting
it, so a non-empty `target` is `SIPRAL_STATUS_INVALID_ARGUMENT` naming it —
nothing sent. The signature changed outright rather than growing a
`sipral_call_config_t *` beside the old parameters, because nothing outside
this tree calls it yet and a fifth parameter nobody could set would be a
promise this ABI cannot keep before the offer this task exists to carry.
`sipral_call_reject_transfer` takes a refusal, 300 to 699: a 1xx or 2xx would
tell the far end the REFER was taken, and is `SIPRAL_STATUS_INVALID_ARGUMENT`
with nothing sent.

**A REFER outside any dialog is a referral, and it is off by default.**
`referrals` on `sipral_stack_config_t` (appended at the tail; `MIN_SIZE`
unmoved), a `sipral_toggle_t`, and `sipral_stack_settings_t::referrals` says
what it came to. Left at the default every such REFER — click-to-dial from a
switchboard, RFC 3515 §4.1 — is refused 403 before anything reads it, because
a peer that can make a phone dial can make it dial a premium-rate number and
this stack authenticates no peer to tell the two apart. On, each one is
screened as an INVITE is (the rate limit, `sipral_stack_screen`'s policy) and
then raised as **`SIPRAL_EVENT_KIND_REFERRAL` (41)**: `call` is the referral's
handle, `account` the line it arrived for, `message` the REFER, and
`payload.referral` its `target`, whether it is `attended` (its `Refer-To`
carried a `Replaces`) and its `referred_by`, which is what the sender wrote
and never proof of who it is. The handle is of the call kind — one table, one
number space, so it never collides with a call — and it names a request, not a
call: `sipral_call_state` on it is `SIPRAL_STATUS_WRONG_STATE`. It is answered
with the two calls a transfer already is: `sipral_call_accept_transfer`, which
answers 202, opens the subscription's dialog, sends the 100 NOTIFY, places the
call exactly as for a transfer — from the event's account, with the REFER's own
target, `Replaces` and `Referred-By` — writes the placed call's handle and
reports every answer that call gets as a NOTIFY until the last; or
`sipral_call_reject_transfer` with the application's refusal. Either spends the
referral's handle; one refused before anything was sent — a header, a
`target` — is still there to take. The application answers neither before the
REFER's transaction runs out, 64·T1 on, and the stack has answered 408 for it:
kind 41 is raised again for the same handle with `payload.referral.status_code`
set and nothing else, and the handle is stale after that poll. Nothing about
the referral's own subscription reaches the application: the far end's
refreshes and unsubscription, `Refer-Sub: false` (RFC 4488) and the dialog's
end are the stack's. `docs/04-ua.md`, "A REFER from outside any call", has the
refusals and why.

**Four calls carry the packets**, each on a call's media handle, and none of
them opens a socket or touches a device: `sipral_media_receive` for a datagram
that arrived, `sipral_media_playback` for the frame due for the earpiece,
`sipral_media_capture` for one from the microphone, and
`sipral_media_poll_rtcp` for the control traffic RFC 3550 §6.3 schedules.
Three of the four take `now_ms`, read as every other entry point reads it and
moving nothing: `playback` is the exception, because a frame for the earpiece
is due when it is asked for. `capture` takes one because ICE has to be told
that traffic went out on the pair it chose — RFC 8445 §11 is what lets it stop
sending keepalives — and because a call whose checks have not chosen a path
yet answers a `len` of zero rather than sending to the address the signalling
named. The
last asks one call rather than the stack, so the thread that sends a call's
audio sends its reports too: it is called after every captured frame, and
whenever `sipral_stack_poll` reports a deadline for a call that is not
capturing. Samples are 16-bit mono at `sipral_media_info_t::sample_rate`, a
frame is exactly `frame_samples` of them, and outgoing packets are written into
buffers the caller brings — checked before anything is built, so a frame is
never encoded and then dropped for want of somewhere to put it.

**A call that ends owes the far end an RTCP BYE, and by then its media handle
is already gone.** `MediaEngine::release` builds the goodbye at
the moment the call ends, but every `sipral_media_` entry point on that call's
handle already answers `SIPRAL_STATUS_WRONG_STATE` by the time an application
could ask for it, so `sipral_stack_poll_farewell(stack, out_call, out_packet)`
is a stack-level call instead — the one place still able to say the goodbye
belonged to that call. `out_call` carries the handle of the call it ended
with, given only so the application knows which media socket to send the
datagram from, since it owns that socket and this ABI never did; `out_packet`
is the same shape `sipral_media_poll_rtcp` already fills. Call it after
every `sipral_stack_poll` that delivered `SIPRAL_EVENT_KIND_CALL_ENDED` for a
call this stack was running media on, and keep calling until it answers a
`len` of zero — a goodbye that is never polled is a far end left to wait out
its own timeout. A call whose media never ran leaves nothing here.

**The queue behind it has a ceiling, the same shape `events_dropped` already
has for the outbox.** An application that never calls
`sipral_stack_poll_farewell` — including one built against a header from
before this entry point existed — would otherwise keep every ended call's
goodbye in memory for as long as the stack lives. Past
`FAREWELL_CEILING` (256, `crates/sipral-ffi/src/stack.rs`) the oldest queued
goodbye is dropped to make room for the one that just arrived, because a
stale goodbye is worth less than a recent one — the far end it was owed to
has almost always timed the dialog out on its own by the time a queue that
deep would be reached — and each drop is counted in
`sipral_counters_t::farewells_dropped`, appended at the struct's tail the
same way `events_dropped` was.

**A buffer that ran dry is a count a C caller reads, not only a score that
fell.** `sipral_stream_stats_t::frames_underrun`, appended at the tail at
minor 28 (`MIN_SIZE` unmoved), is `Quality::underruns`: frames the earpiece
played as nothing because the jitter buffer had run dry while the far end was
still sending — an earpiece whose clock runs faster than the far end's, or
audio held up on the way. `loss_rate`, `score` and `suffering` already fell
with them; none of the `voip_*` figures does, since RFC 3611 §4.7.1 counts
packets lost or discarded and an under-run is neither (`docs/05-media.md`).
The same struct reaches `SIPRAL_EVENT_KIND_MEDIA_STATISTICS`, so the count
is in a call's last word as well. Every binding carries it:
`SipralStreamStatistics.FramesUnderrun` in .NET, `"frames_underrun"` in
Python's two dicts, and the struct's own member in Swift and Kotlin
(`frames_underrun`, `framesUnderrun`).

**Recording is where a path becomes a file**, and the file belongs to the media
session from then on. C never sees the file handle, so it cannot leak it or
close it underneath the stack. The one thing that had to be arranged rather than
inherited is the WAVE header: it carries two lengths that are not known until
the recording stops, so every way a recording can end closes it properly —
`sipral_media_record_stop`, the call ending, and the stack being destroyed,
including from inside its own event callback. Destroying a stack mid-recording
leaves a playable file, not a repair job.

`sipral_media_record_start_with` (ABI 0.31) takes a
`sipral_recording_options_t`, every member zero for the plain recording:
`format` (`SIPRAL_RECORDING_FORMAT_WAV`, or `_OGG_OPUS` where
`SIPRAL_FEATURE_OPUS` is set and `SIPRAL_STATUS_NOT_SUPPORTED` where it is
not), `layout` (`_MIXED`, or `_STEREO` with this end on the left and the far
end on the right), `sample_rate` (the file's own, which a codec change no
longer ends the recording over), `bitrate` for Ogg Opus, and
`checkpoint_ms`, how often the file is made to survive a crash — five
seconds unless set; `docs/05-media.md` says what a crash leaves. Options no
file can be written with are refused before the file is made. A file that
stops taking what is written — a full disk — is
`SIPRAL_STATUS_RECORDING_FAILED` (19) from `sipral_media_record_stop` and at
start, and `SIPRAL_EVENT_KIND_RECORDING_STOPPED` part-way; a path the file
system refuses stays `SIPRAL_STATUS_INVALID_ARGUMENT`.
`SIPRAL_FEATURE_RECORDING_FORMATS` (`1 << 19`) says the build has all of
this, and L16 among its codecs (`SIPRAL_CODEC_L16_NARROWBAND` 6,
`_L16_WIDEBAND` 7, named `L16/8000` and `L16/16000` in a codec order).

**What a call carries in its audio (ABI 0.31).** Three per-call settings,
each reachable from `sipral_call_place` on — before the call has media — and
each `SIPRAL_STATUS_WRONG_STATE` on a call whose media is not this stack's:
`sipral_call_dtmf_detection` (a `sipral_dtmf_detection_t`, whose default,
`AUTO`, is also `sipral_stack_config_t::dtmf_detection`'s zero: listen on the
calls that negotiated no telephone event), `sipral_call_detect_progress`
(a `sipral_progress_config_t`: the network's tones, the answering-machine
limits and the beep, every member zero for its default and `listen` off to
stop) and `sipral_call_consent_tone` (a `sipral_consent_tone_t`, `enabled`
off for none). A digit heard in the audio is
`SIPRAL_EVENT_KIND_IN_BAND_DIGIT` (48) in `payload.media`, with `source`
`SIPRAL_DIGIT_SOURCE_IN_BAND`; what the progress detection heard is
`SIPRAL_EVENT_KIND_PROGRESS_DETECTED` (49) in `payload.progress`, a
`sipral_progress_event_t` whose `what` says which members mean anything.
`SIPRAL_DTMF_IN_BAND` (4) sends digits as tones on any call, and
`SIPRAL_DTMF_RTP` does so by itself on a call that negotiated no telephone
event, where it used to be `SIPRAL_STATUS_NOT_SUPPORTED`.
`SIPRAL_FEATURE_IN_BAND_SIGNALS` (`1 << 18`) says the build has all three.
Event 47, in the same minor, is the caller-identity verdict.

**Configuration is answered, never absorbed.** A codec name this build has no
encoder for is `SIPRAL_STATUS_NOT_SUPPORTED` where the order is set, with the
names it does have in the last error; a stall threshold set while the watchdog
is off is `SIPRAL_STATUS_INVALID_ARGUMENT`, the same shape as a retransmission
timer set on a transport that retransmits nothing. Every boolean media setting
is a three-valued `sipral_toggle_t` — default, on, off — because a zeroed struct
cannot otherwise tell "off" from "nothing was said", and
`sipral_stack_settings_t` reads back what each of them came to.

### The built-in audio engine (device mode)

Everything above pumps frames: the application takes them from whatever
device it opened and hands them to `sipral_media_capture`, and takes what
`sipral_media_playback` gives it to the device. That stays, unchanged, as
**application mode** — what a zeroed `sipral_stack_config_t` says, and what
every caller compiled against an earlier header therefore keeps. **Device
mode** is the other answer to `sipral_stack_config_t::audio` (appended after
`turn_transport`, ABI 0.29, `MIN_SIZE` unmoved): `SIPRAL_AUDIO_DEVICE` has
the library open the platform's own devices — `sipral-io-coreaudio`'s
voice-processing unit on macOS and iOS, `sipral-io-wasapi`'s communications
streams on Windows, through the `sipral-audio` crate that sits beside the
facade rather than under it — and pump every managed call itself, from the
moment its media starts to the moment it ends. The socket is still the
application's: each packet the engine encodes reaches
**`audio_transmit_callback`** as a `sipral_audio_transmit_t` — the call, the
`destination`, the `protocol` the way `sipral_media_packet_t` marks it, the
octets — on the engine's own thread, to be sent and returned from; received
packets go in through `sipral_media_receive` as before. The callback is
required with `SIPRAL_AUDIO_DEVICE`, and a platform this build has no backend
for answers `SIPRAL_STATUS_NOT_SUPPORTED`, which
`SIPRAL_FEATURE_AUDIO_DEVICE` (2048) says before a stack is created: set on
macOS, iOS and Windows, and on Android from API level 28, where the answer
is the phone's and not the build's (AAudio, `docs/15-mobile.md`); clear on
Linux, where `sipral-io-pipewire` would link a library the packaged wheel
must not require, and on an older Android phone, whose calls the Kotlin
layer's own `CallAudio` carries over `AudioRecord` and `AudioTrack`.

The engine keeps ten rules a softphone on another stack has been bitten by,
each tested against a platform made of fakes (`crates/sipral-audio/src/tests.rs`)
and again through this ABI (`crates/sipral-ffi/src/audio.rs`):

- **A device's id is the engine's, never reused, and survives a refresh.**
  `sipral_audio_refresh` asks the platform again; a device seen before keeps
  its `sipral_audio_device_t::id`, one that has gone keeps its row with
  `present` zero, and a new one gets the next number. A role running on a
  device is not reopened by a refresh. `sipral_audio_device_count` and
  `sipral_audio_device_at(stack, index, &device, buffer, capacity, &needed)`
  read the list, the name UTF-8 into the caller's buffer.
- **Channel counts are listed and refused.** `input_channels` and
  `output_channels` say what a device can do; `sipral_audio_select` on a
  device with none in the role's direction is `SIPRAL_STATUS_DEVICE_UNUSABLE`
  (14), as is one that is not plugged in, and an id the list never held is
  `SIPRAL_STATUS_NO_SUCH_DEVICE` (13) — all three before any platform call.
- **Microphone, speaker and ringer are chosen separately**, as
  `sipral_audio_role_t`, with `sipral_audio_select(stack, role, id)` and zero
  for the system's route; `sipral_audio_selection` reads back both what was
  asked for and what the role is running on, which differ while a chosen
  device is unplugged: the selection is kept as a preference, the role runs
  on the system's route meanwhile, and goes back when the device returns. On
  macOS the microphone and the loudspeaker are the two halves of one unit, so
  choosing the microphone or a ringer of its own is
  `SIPRAL_STATUS_NOT_SUPPORTED` there and the ring goes through the
  loudspeaker; Windows opens a stream per endpoint and takes all three.
- **A change the engine made and one the operating system made are told
  apart.** `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED` (43) carries
  `payload.audio.origin`: `SIPRAL_AUDIO_ORIGIN_SYSTEM` for a device arriving
  or leaving or the default moving, `SIPRAL_AUDIO_ORIGIN_ENGINE` for a
  selection applied or a role reopened on its fallback. A role the
  application put on a device does not follow the default when the system
  moves it, and an application that ignores engine-origin events cannot
  re-apply its own choice in a loop.
- **Gain and mute belong to the direction, not the stream.**
  `sipral_audio_set_gain(stack, direction, gain)` — 256 is unity, the input
  direction is the microphone gain — and `sipral_audio_set_muted` are kept
  by the engine and applied to whatever device the direction is on, so a
  headset unplugged mid-call comes back at the volume the person set.
  `sipral_audio_level` is the meter, per direction, cheap enough for a
  window's timer.
- **The ring has an output of its own.** `sipral_audio_ring(stack, samples,
  count, rate, looped)` plays the application's tone on the ringer's device
  until `sipral_audio_stop_ringing`, whatever the speaker is on.
- **Activation is decoupled from the calls** with
  `sipral_stack_config_t::audio_activation`: automatic opens the devices with
  the first call's media or the first ring and closes them with the last;
  manual opens them only between `sipral_audio_activate` and
  `sipral_audio_deactivate`, which is what CallKit's `didActivate` and the
  telecom framework's audio-route callbacks are for.
- **A stuck driver is a status, not a hang.** Every platform call is made
  from a thread the engine can walk away from, bounded by
  `audio_probe_ms` (default three seconds):
  `SIPRAL_STATUS_DEVICE_TIMED_OUT` (15), and the entry point returns.
- **No instruction beyond the baseline.** The resampler and the mixer are
  plain integer arithmetic; `scripts/check.sh` refuses a `target-cpu` or
  `target-feature` in any build configuration in the tree, so a packaged
  library runs on the oldest machine its target names.
- **Echo cancellation is reported, not assumed.** `sipral_audio_info` says
  whether the platform's own processing sits behind the microphone
  (`system_echo_cancellation`: the voice-processing unit on Apple's
  platforms, which cancels; a communications stream Windows accepted, which
  applies whatever processing the endpoint has — a virtual cable has none,
  and the lab's measurement through VB-CABLE reads 0 dB of echo return loss
  with the flag set) and what the devices report as `render_delay_ms`; the
  application that wants the echo gone regardless attaches a canceller to
  each call through `sipral_media_attach_processor` as before, and the engine
  tells every managed call that delay itself, again after every device
  change.

All four idiomatic layers choose device mode by default wherever
`SIPRAL_FEATURE_AUDIO_DEVICE` is set and application mode elsewhere, and
keep application mode for the caller that asks for it. The .NET and Python
sections below say how each carries the rest. The Swift and Kotlin layers
name that default `AudioMode.platformDefault` and
`SipralAudioMode.platformDefault`, with the engine behind
`SipralStack.audio` and `SipralClient.audio` and the transmit callback
sending from each call's own socket; on Android, whose devices the library
does not open, the Kotlin telecom helper's `SipralCallAudios` runs every
call's `AudioRecord`/`AudioTrack` instead.

## One declaration, and every printed file (the header, the four bindings and the JNI shim)

B7's failure is a C seam declared in several places that have to agree: a
function added to the Rust and forgotten in one binding produced a build that
compiled and failed at run time, on one platform, in the field. The answer here
is that the header and the four bindings are not declarations at all. They are
printed, by `tools/abi-gen`, from what `crates/sipral-ffi` declares, and they
are committed — a consumer of a released library must not have to run a
generator — and `scripts/check.sh` prints them again and fails when what is
committed is not what came out.

```sh
cargo run -p sipral-abi-gen             # write them
cargo run -p sipral-abi-gen -- --check  # what the gate runs
```

**The declaration writes itself down.** Every macro that declares something
crossing the boundary emits the Rust item exactly as it would have been written
by hand and, beside it, a `const` saying what it emitted: the name, the members,
their types and the documentation, all built out of the very tokens the
declaration is made of. `entry!` already wrapped every entry point, so it gained
the recording without a single invocation changing; `record!` and `codes!` do
the same for the structs and the enumerations, `constants!` and `alias!` for
what is left, and `event_kinds!` hands over its reserved numbers along with its
kinds. `crates/sipral-ffi/src/abi.rs` is where those macros and the descriptors
live, and `abi::SURFACE` is what the generator reads. Nothing reads Rust source.
A parameter or a member that holds an enumeration's number is declared
`Number<SipralCodec>` rather than `u32`: the alias is the enumeration's own
integer, which `codes!` names through the `Enumerated` trait it implements, so
the Rust reads a number exactly as before, and the spelling carries the name
the header prints the `typedef` from.

**Two other designs, and why not.** A generator that parses the Rust would be
a second compiler with a worse front end: the first `cfg`, the first type alias,
the first macro that declares an item, and it is either wrong or it is rustc.
This one cannot be wrong about what was declared, because the compiler is what
read it. Declaring the surface in a data file that the Rust is checked against
is the other real option, and it fails on documentation rather than on
correctness — the header's audience is an application developer, the prose is
most of what they read, and a data file means writing every paragraph twice and
watching the two drift. Carrying the documentation from the declaration is the
whole reason the descriptor is built by the macro rather than beside it.

A `cbindgen.toml` used to sit in `crates/sipral-ffi`, configuring a generator
nothing ever ran and that would have printed the header alone. It is gone. Two
generators configured for one header is the drift this arrangement exists to
remove, and the second of them was the one no gate would have noticed going
stale.

**The failure mode this choice has, because every one has one.** A macro cannot
enumerate its own invocations, so something has to list them: `abi::SURFACE` is
one line per item, written by hand, and that line is the thing a person can
forget. Three things close it and none of them is the list itself. The
descriptor beside an unlisted item is dead code, and this workspace builds with
`-D warnings`, so forgetting the line fails the build before it fails anything
else. `scripts/check.sh` compares the entry points and the types the modules
declare against the lines in `abi.rs` and names the difference in both
directions. And the generator refuses to print a surface in which one type is
reachable from another that is not listed.

The hole left under those is a declaration made where the macros never see it —
a `#[repr(C)]` or a `pub const SIPRAL_…` written out by hand. That is covered by
two more scans in `scripts/check.sh`, and they are text scans looking for a
declaration at the left margin, which is the weakest link in the arrangement: a
type declared inside a `mod` block, indented, would slip past them. It would
still have to reach C somehow, and the only way to do that is `entry!`, which
`scripts/check.sh` already insists is the only thing that may export a symbol.

**What the descriptor records is the spelling, not the layout.** `usize` becomes
`size_t` by a rule in the generator, `*const c_char` becomes `const char *`, and
a rule that is wrong is wrong in the header and all four bindings at once — the
gate would compare wrong output against wrong output and pass. That is the
price of one source of truth, and it is the right price: a mistake that is
everywhere is a mistake somebody finds, where a mistake in one binding of four
is the failure B7 exists for.

**The names are read back after they are derived.** Each back end makes names
of its own: `out_state` becomes `state` in C# and in Kotlin, a struct the
library fills in becomes a `long[]` beside the locals the JNI shim writes
around it, and a constant becomes `featureOpus`, `FeatureOpus`,
`FEATURE_OPUS` or `SIPRAL_FEATURE_OPUS` depending on who is reading. Two
declarations whose derived names land on the same word produce a file that
does not compile, or — worse, and this happened — one that does: Swift
printed `var call` beside a parameter called `call` and passed a zeroed handle
where the caller's was meant to go. So every identifier each back end will
print is claimed first, in the scope it will sit in, and a second claim on the
same word stops the generator with both declarations named. The same pass
carries a reserved-word list per language. Three of the four can be made to
take one of their own keywords — `@event` in C#, backticks in Swift and in
Kotlin — and they do; C cannot, and the header is also a C++ header, so a
member called `class` or `switch` stops the generator rather than reaching a
consumer. The callback goes through the same walk as everything else: it is
the one signature that is not an entry point, it is printed into the header
as a function pointer and into the .NET binding as a delegate, and its
parameters were the last names in the surface nothing read back.
`tools/abi-gen/src/names.rs` is the pass, and `tools/abi-gen/golden/` holds a
small synthetic surface printed as the seven files the generator writes — the
header, the Swift binding, the .NET binding, the Kotlin binding with the
JNI shim beside it, the Python binding and the Dart binding — so a change to an emitter shows up there rather than
buried in `bindings/`. "Small" and "reaches every emitter path" pull against
each other, so the second one is counted rather than claimed: a test takes
the shapes of the real surface and the shapes of the synthetic one and fails
naming each shape the golden files do not reach.

**The conventions are load-bearing now.** The generator reads the ABI's own
shapes off the parameter lists: a pointer followed by a length is one buffer
going in, a `const` pointer to a record followed by the `_len` named for it is
an array of records going in, a pointer followed by `capacity` is a buffer the
library fills, a writable pointer named `out_…` is one value coming back, a
pointer to a versioned struct is a struct going in, coming back, or both,
according to which way it points and whether the struct holds buffers of the
caller's, and a callback followed by a `*mut c_void` is one listener — the
same pair a struct going in has always meant by those two members, read the
same way when they are parameters of their own. So a new parameter called
`blob` beside `blob_size` rather than `blob_len` is not a naming preference:
it is a binding that hands over a raw pointer instead of a string, and a
callback taken without the pointer after it is refused by name rather than
printed as a listener nothing could reach again.
`tools/abi-gen/src/model.rs` is where those six rules are written down.

**A callback may answer, and the answer is a plain integer or nothing.**
`SipralEventCallback` only ever reports — the poll hands it an event and moves
on — but a policy callback, one the library asks a question it must wait for
the answer to before it goes on, has to return a value. `alias!` takes that
return type straight off the declaration: `pub type X = fn(a: A, b: B) ->
u32;` is a callback that answers a `u32`, and leaving the `-> …` off, as every
callback declared today does, is a callback that answers nothing. Both are
printed in all four languages — `void` becomes the answer's C type, its C#
delegate return, and a return on the Kotlin listener's method — from the one
declaration, the same way everything else here is. An answer that is not a
plain integer, or a return type this generator has no rule to print in one of
the four languages, is refused by name: `tools/abi-gen/src/model.rs` reads it
off the declaration once, rather than leaving each back end to find out on
its own that it cannot spell what a listener would have to return.

Zero is the answer that fails closed, for every answering callback this ABI
declares, by the declaration's own choice rather than a rule the generator
imposes: a policy callback is declared so that zero means refuse, matching
`SipralToggle::Off` and every other yes/no answer in this ABI. It matters
because it is also what a listener that throws instead of answering is read
as — Kotlin's, and no other language here builds a listener of its own to
throw from. See "Kotlin" below for what that costs.

### What the gate catches

A function, a struct, a union, an enumeration, a constant or an alias added,
removed or renamed on the Rust side and not reaching the header or any of the
four bindings. A member appended to a struct, a value added to an enumeration,
a parameter added to a function, a type changed. The number an event kind
spends, which travels into every printed file (the header, the four
bindings and the JNI shim). Every one of those is a difference
between what is committed under `bindings/` and what the declarations produce,
and the gate prints which file and says what to run.

Two declarations that derive one name in one of the four languages, and a
name one of them will not take — a parameter of the callback as much as a
parameter of an entry point or a member of a struct. Those stop the
generator, so they fail the gate step above and `cargo test -p sipral-abi-gen`
alike, each naming the language, the declaration and the identifier.

And, because the artefacts exist to be linked rather than read: every entry
point `abi.rs` lists present in `libsipral_ffi.dylib` and in
`libsipral_ffi.a`, as many exported `sipral_` symbols as `SURFACE` has entry
points and no more, and nothing else leaving the shared library under a name a
C linker could collide with.

### What it does not catch

**A missing toolchain is a named skip, not silence.** `scripts/check.sh` has a
step, `the bindings compile`, that builds every one of the three generated
bindings: `dotnet build -c Release` on `bindings/dotnet/Sipral`; `kotlinc` over
every `.kt` file it finds under `bindings/kotlin` except the Android-only
`bindings/kotlin/android`, which needs the Android SDK and is built by
`scripts/package/android.sh` instead; and `xcrun --toolchain
default swift build` on `bindings/`. Kotlin goes further than a compile: once
`kotlinc` and a JDK carrying `include/jni.h` are both there, `cc -fsyntax-only
-Wall -Wextra -Werror` checks `sipral_jni.c` against that JDK's own headers,
the shim and a small test helper are then linked against the shared library
built earlier in the gate, and `BindingCheckKt` runs against the two on a JVM
under `-Xcheck:jni`, so a native crash or a JNI warning fails the step and not
only a compiler would have. `xcrun --toolchain default` on the Swift line is
not decoration: a bare `swift build` resolves to whatever toolchain answers to
`swift` on `PATH` — a version manager such as swiftly, where one is installed,
rather than the toolchain the Xcode Command Line Tools ship — and a mismatched
one can fail on the package's declared `tools-version` instead of building it;
`xcrun --toolchain default` names the Command Line Tools' own toolchain, so
the gate builds with that one regardless of what else answers to `swift`.
None of the three is assumed present: a machine with no .NET SDK, no
`kotlinc`, no JDK carrying `include/jni.h`, or Command Line Tools with no
`PackageDescription` module for `swift package dump-package` to read first,
prints `skip` naming exactly what is missing, rather than staying quiet about
that language. The header remains the one binding compiled unconditionally
rather than skippably: `bindings/c/smoke.c` includes it, compiles under
`-std=c11 -Wall -Wextra -Werror`, links the shared library and runs, in the
gate; `bindings/c/sipral.c` compiles it a second time as the Swift package's
own translation unit.

**It says nothing about meaning.** A member that keeps its name and its type and
starts meaning something else travels into every printed file intact. So does a
function whose behaviour changed under a signature that did not.

**The built library is checked on this platform and no other.** The gate reads
the symbols out of the `.dylib` and the `.a` it just built, so a symbol dropped
on a target nobody here builds is still between `entry!` and that linker.

**A Rust-to-Rust coupling is outside it entirely.** `crates/sipral-ffi/src/event.rs`
destructures `sipral_ua::UaEvent` variant by variant, and a variant destructured
without a `..` rest pattern makes adding a field to it a build failure over
here. That is loud rather than silent, so it is not B7's failure — but it is a
coupling this gate has no view of, and it has already cost one feature its
shape. The arms use `..`.

**The static archive carries its dependencies, and their names.** An archive
is the objects that went into it, so `libsipral_ffi.a` holds libopus and
compiler-rt as well as this library, and exports around seven hundred
unmangled C names that are not the ABI's — `opus_decode`, `celt_fatal`,
`alg_quant`, the `__udivti3` family, the LTO symbols. The gate counts the
names leaving the shared library and not those, because they belong to the
projects they came from and their number moves with a dependency version. It
is not a defect and nothing here will remove them: a consumer that links this
archive into a program that also links libopus of its own has two definitions
of each of those names for its linker to settle, and has to know that before
it gets there. Link the `.dylib`, or link the archive knowing what is in it.

**The packaging is written by hand.** `Package.swift`, the `.csproj`,
`bindings/python/pyproject.toml`, the readmes, `bindings/c/sipral.c` and
`bindings/c/smoke.c` are not printed and not compared. What they build is.

## Swift

A Swift Package whose C target is the generated header, and whose Swift target
is `SipralAbi.swift`, printed beside it. A status is a thrown `SipralError`
carrying the last message, the number, and its name when this binding has
one; a pointer and a length are a `String` or an array
held alive across the call; an array of records going in is an array of a
struct the binding prints, made into the C array inside the call; a buffer the
caller brings is an `inout` array; a struct the library fills in whole is what
the call returns, with an extension per struct that hands over a zeroed one
with its `size` already set. Nothing in
the printed surface is a raw pointer except the three structs a caller
part-fills with its own buffers, which are `inout` and typed.

What is not printed is the platform work, and it is what the binding earns its
place for: `SipralStack`, `Account` and `Call` (`swift/Sources/Sipral/`), one
POSIX socket per stack and per call's media (`UDPSocket.swift`, `Darwin` or
`Glibc` directly rather than `Network.framework`, so the module also builds
and runs on Linux) — or, for SIP over TCP or TLS, one connection to the
server (`Signalling.swift`: Network.framework on Apple platforms, where TLS
is; a plain TCP socket on Linux, where it is not) — and the event callback
bridged into `AsyncStream`s —
decoded synchronously, on the poll thread, into a `Sendable` `SipralEvent`
before it crosses, the same rule `bindings/python/sipral/events.py` follows
for the same reason (`sipral_event_t`'s pointers outlive nothing past the
callback that carries them). `SipralStack.events()`, `Call.events()`,
`Call.dtmf()` and `Media.frames()` each hand every caller a stream of its
own, fed every item from then on (`Broadcast.swift`): one `AsyncStream`
read from two places splits its items between them, and a call bound to
`CallKitBridge` is read by the bridge and the application at once. Nothing
raised before a stream is taken reaches it, apart from a call's
`CALL_ENDED`, handed to a stream taken after the call ended; a call's
streams finish right after that event, a media's when it ends, a stack's
when it closes. `CallKitBridge` and `PushKitBridge` run
`docs/15-mobile.md`'s "C2" sequence — push, report to CallKit, announce,
refresh the binding, match the INVITE, answer — behind `CallKitProviding`, a
protocol small enough to fake in a test with no device and no `CallKit`
framework at all; `CallKitAdapter.swift`/`PushKitAdapter.swift` are the real
`CXProvider`/`PKPushRegistry` behind it, compiled in only where those
frameworks actually work (`canImport(CallKit) && os(iOS)` — the module is
importable on plain macOS too, but every type in it is marked
`API_UNAVAILABLE(macos)`, so `canImport` alone is not enough to keep this
module building there). The devices are the library's: `SipralStack(audio:)`
is in device mode wherever the library has an engine for the platform, the
layer sends from each call's socket what `audio_transmit_callback` hands it,
and `stack.audio` lists, chooses and meters the devices; `CallKitBridge.drive`
opens and closes them with CallKit's audio session under manual activation.
The macOS sample has no audio code of its own. `SipralStack`'s initialiser takes `ice`, `stunServer`, `turn` and
`g729AnnexB`, and with a STUN server it runs the media-socket loop "Behind a
NAT" describes on its own poll thread; `SipralEvent.natData` and `relayData`
carry the two events that loop waits for. It takes `referrals` too, off by
default: `SipralEvent.referralData` carries `SipralEventKind.referral`, and
`acceptReferral` opens the placed call's media socket the way `placeCall`
does, takes the referral and returns that call as a `Call`, while
`rejectReferral` refuses it.

An empty string passed where the library reads an optional address — `to`
on `sipral_stack_receive_datagram`, `remote` on
`sipral_stack_transport_bind` — is left out, like every optional text in the
ABI: a length of zero is absent whatever the pointer, since
`Array("".utf8).withUnsafeBufferPointer`'s `baseAddress` for an empty array
is not a null pointer. Up to minor 32 such an empty `to` was refused.
`SipralStack.run()` passes its own `bindAddress` explicitly all the same.
The generated wrappers that install a listener take an optional callback
and an optional `userData`, so `stackLog` and `stackScreen` with `nil`
remove what was installed.

## .NET

`SipralAbi.cs`, printed, in two layers. `NativeMethods` is the ABI as P/Invoke
declares it, with every pointer written as an array or as `in`, `ref` or `out`,
so the package compiles without an unsafe block and the runtime does the
pinning — except for an array of records, an `IntPtr` to records the wrapper
pins itself; `Sipral` is the layer above, where a status becomes a
`SipralException`, a byte pointer and its length become a `string`, an array of
records becomes an array of tuples, and everything written back becomes what
the call returns.

What is not printed: the native assets for `osx-arm64`, `osx-x64`, `win-x64`,
`win-arm64` and `linux-x64` (`linux-arm64` is: `scripts/package/nuget.sh
collect --rid linux-arm64` cross-compiles it, no arm64 hardware needed), the
`Task`-based surface, `IAsyncEnumerable` for event streams, and the
`SafeHandle` that makes a missed `Dispose` a leak rather than a crash.

`SipralStack`, `Account`, `Call` and `CallMedia`, in `bindings/dotnet/Sipral/`,
are written against `NativeMethods`/`Sipral` by hand, the way
`sipral.stack.Stack` is the base the Python package is written against.
Every handle a call or an application holds is a `SafeHandle` subclass
(`bindings/dotnet/Sipral/Handles.cs`), so a missed `Dispose` releases on a
finalizer rather than leaking, and a double `Dispose` is the no-op
`SafeHandle`'s own reference count already makes it. A `SipralStack` owns
one UDP socket — or, for SIP over TCP or TLS, one connection to the server
and a reader for it (`SipralSignalling.cs`) — and one background poll
thread — the same drain-receive,
poll, drain-transmit, drain-farewell loop `bindings/python/sipral/stack.py`
runs, kept alive as a GC root by the thread's own closure over it rather
than a separate keep-alive list — and delivers events two ways: an ordinary
C# `event` fired synchronously on the poll thread for a handler that wants
to run there, and an unbounded `Channel<T>`-backed `IAsyncEnumerable<T>`
(`SipralStack.Events`, `Call.Events`, `Call.Dtmf`, `CallMedia.Frames`) for
an `await foreach` consumer, matching `docs/08-ffi.md`'s own "Events arrive
on one callback" for the first and staying off that thread entirely for the
second. `SipralErrors.Call` retries an ordinary `SIPRAL_STATUS_BUSY` for up
to half a second, the same allowance `sipral.errors.call` gives it, and
also retries `SIPRAL_STATUS_CLOCK_BEHIND`, the signalling clock's own "more
than the ABI's slack behind this stack's last reading" — by its status,
where up to minor 32 it had to read the English of an
`SIPRAL_STATUS_INVALID_ARGUMENT` for it. This layer
always reads `now_ms` fresh right before the call, so what beat it there is
the OS scheduler on the calling thread, not a stale value, and the stack's
high-water mark only ever advances, so a retry with a later reading is
never refused for the same reason twice. `Call.WaitForConfirmedAsync` and
`Call.WaitForMediaAsync` are the `Task`-based surface the ABI completes
through events rather than a return value. `PlaybackOnce`, `Capture` and
`SendAudio` cross PCM as `Span<short>`/`ReadOnlySpan<short>`, never a
managed array copy the caller did not already own.
`bindings/dotnet/Sipral.Tests` is what `scripts/check.sh`'s `the dotnet
bindings` step runs: two stacks on loopback proving the same shape
`bindings/python/tests/test_call.py` proves, plus the threading rules
`docs/08-ffi.md` states for every binding — events on the poll thread and
not the caller's, `BUSY` surfaced rather than blocked on, and no
use-after-free disposing a stack while events are still queued behind it.
What an application's own `EventReceived`/`FrameDecoded` handler throws is
caught at the point it is invoked and never allowed to unwind back into
the native frame that thread is inside of — the same "the callback does
not unwind" contract this section states by name for the Kotlin listener,
and for the same reason: a reverse P/Invoke that unwinds is undefined
behaviour, and in practice the CLR's own fatal-exception handling for one,
which would take the whole process down over one subscriber's bug rather
than only the thread it ran on.

`SipralStack`'s constructor grew `ice`, `nat`, `stunServer`, `turnServer`,
`turnUsername`, `turnPassword` and `g729AnnexB`, all defaulting to
today's behaviour, and `PlaceCall` grew `ice`, the same additions
`bindings/python/sipral/stack.py`'s own `Stack.__init__`/`place_call`
made, kept to the same option names in each language's own idiom.
`SipralEventArgs` grew `Nat`/`Relay`, decoding
`SipralEventKind.NatMapping`/`NatRelay`'s payloads the same way every
other kind already there does. It grew `Referral` the same way, and the
constructor `referrals` (off by default), with `AcceptReferral` — a media
socket opened and the referral taken, the placed call returned as a `Call` —
and `RejectReferral` beside `AnswerCall` and `RejectCall`. A media socket is the harder half, since
it is the application's own and exists before its call: `SipralStack`
tracks every one `sipral_stack_nat_map` names — from `PlaceCall` or
`AnswerCall`, once built with `nat: SipralNat.Stun` — in a
`Dictionary<string, Socket>` the poll thread's own loop folds into the
`Socket.Select` it already runs its main socket through each pass,
reading what arrives on one into `sipral_stack_receive_stun` and sending
what `sipral_stack_poll_stun` hands out for it from that socket and no
other. `PlaceCall`/`AnswerCall` block the *calling* thread — never the
poll thread, which keeps polling throughout — until the socket's own
`SipralEventKind.NatMapping` arrives (and, with `turnServer` set, its
`SipralEventKind.NatRelay` too), the wait `sipral_stack_nat_map`'s own
doc comment requires before a call may be described on it. Once
`SipralEventKind.MediaStarted` mints `Call.Media`, the socket is
`CallMedia`'s to read from then on; a call that never reaches it gives
the mapping back through `sipral_stack_nat_unmap` when it closes, and so
does `SipralStack.Dispose` for a socket mapped and never spent by a call
at all. `bindings/dotnet/Sipral.Tests/NatTests.cs` proves it against a
STUN responder that test project runs itself, and runs two stacks with
`ice: SipralIce.Required` against each other for the ICE half, with no
server at all.

ABI 0.29's surface reaches .NET the same way. `SipralStack`'s `audio` is
nullable and resolves, when left out, to `SipralAudio.Device` where
`sipral_capabilities` has `SIPRAL_FEATURE_AUDIO_DEVICE` and to
`SipralAudio.Application` elsewhere (`SipralStack.AudioMode` says which): a
Windows or macOS application gets the platform's devices with no audio code,
and a Linux one keeps pumping its own frames. In device mode the stack
registers its own `audio_transmit_callback`, kept alive beside the event
callback, which looks the call up by handle and sends the packet from that
call's media socket (or writes it on the socket's TURN connection, a broken
one told to the stack from the poll thread, never from the engine's); it
calls nothing in the library, since an entry point reached from the engine's
thread could wait on the engine. `CallMedia.Pumped` is then true: its thread
still reads the socket into `sipral_media_receive` and sends what RTCP and
DTMF owe, and never plays or captures a frame. `SipralStack.Audio`
(`SipralAudioEngine`) wraps the fifteen `sipral_audio_*` entry points, gain
as a ratio over the ABI's 256 steps. `SipralCallEventInfo` grew `Identity`,
`Answering` and `Cause`, `SipralEventArgs` grew `Audio`, and the call kinds
grew `CallAddressWanted`; `Call.Readdress`, `Call.HangupFor`,
`Call.Identity`, `Call.SrtpSuite`, `SipralStack.RedirectCall`,
`SipralStack.CallIdentity`, `SipralStack.MoveTo` (the signalling socket
bound again, `sipral_stack_transport_bind`, `sipral_stack_network_changed`,
and `sipral_account_rebind` for every account with a default `Contact`) and
`Account.Rebind` are the rest, with `AddAccount`'s `sessionTimer`,
`sessionIntervalSeconds`, `privacy` and `trustedPeers`.
`Sipral.Tests/AudioEngineTests.cs`, `IdentityTests.cs` and `MoveTests.cs`
prove them; the one test that opens real devices runs only with
`SIPRAL_AUDIO_DEVICES=1`, and passed on the Windows lab machine's virtual
cable. Windows routes no datagram between a socket bound to loopback and
one bound to the machine's own LAN address, so the move from one to the
other is proved on macOS and Linux only.

## Kotlin

Two printed files, because Android has no way to call C but JNI:
`SipralAbi.kt`, one `external fun` per entry point plus the enumerations, the
constants, the exception, the classes a caller builds, the listener, and a
layer that turns a status into a throw; and `sipral_jni.c`, the C that
implements them. They are printed from the same walk over the same
declarations, which is the only reason it is safe for them to be two files.

**No struct's layout crosses.** A struct the library fills in whole comes back
a member at a time in a `long[]` the shim writes, with a float carried as its
own bits, so nothing on the Kotlin side has to know a field offset — which it
could not, since Android builds for two pointer widths. A struct the caller
fills in and the library only reads — `sipral_stack_config_t`,
`sipral_account_config_t`, `sipral_call_config_t` — is a Kotlin class with one
field per member, every field defaulting to the zero the C struct would hold:
a pointer and its `_len` are one `String` or array, or a `List` of a class the
binding prints when the pointer is to records, and the callback with the user
pointer after it is one listener. The wrapper hands the fields over one
argument each, and the shim copies them into a zeroed struct whose `size` it
sets from its own header. A member those conventions do not cover — a pointer
with no `_len` after it, a struct or a union held by value — stops the
generator, rather than crossing as an address nobody on the Kotlin side has a
way to make.

**A struct the library hands to a listener can carry a buffer the listener is
expected to fill, as well as ones it only reads** — `sipral_processor_frame_t`
is the one declaration that does, `near_end` and `far_end` read, `out` filled.
A `const` pointer and its `_len` cross in as an array copied from the native
side before the call, the same as a struct going in; a writable one crosses as
a fresh array the size the native side says, left zeroed rather than copied
in, because there is nothing on that side yet for the native side to say. Once
the listener has had its chance to write into it, the landing function copies
it back into the native buffer it stands for — before that array's own local
reference is deleted, and whether or not the listener threw, since `New*Array`
already zeroed it and a listener that threw partway through a frame is meant
to hand back silence rather than whatever the last frame happened to leave in
a scratch buffer nobody re-zeroed for it.

**The listener never leaves the JVM.** `SipralEventListeners` keeps each
listener under a key, and the key is all C sees, as `event_user_data`, beside a
C function the shim prints for the callback to land in. That function attaches
the polling thread to the JVM for the length of the call when it is not
attached already, and detaches only a thread it attached: a thread that called
`stackPoll` from Kotlin is attached, and detaching it would pull it out from
under its caller. It hands over the event and deletes the array it made for the
message before the next event arrives, because a poll delivers all its events
inside one native call and a local reference lives until that call returns. The
class and method it calls are looked up in `JNI_OnLoad`, because a thread
attached later looks classes up through the system class loader, which on
Android cannot see the application's. The listener is let go of by
`stackDestroy`, whatever that answers — a handle destroy refuses names no stack
that could still call back — so an event from a poll still running when its
stack went away finds no listener rather than a freed one. The cost is that a
Kotlin listener, unlike a C callback, hears nothing from its stack after the
destroy. A `stackCreate` that makes no stack lets its listener go as well, and
that includes one that throws rather than answers — a native library that did
not load, or one that serves another ABI — because the listener is kept as the
last thing before the call and settled in a `finally` around it.

**A listener installed on a handle the caller already had** — `stackScreen`,
which takes the policy rather than receiving it inside a config struct — goes
the same way with one difference: there is no handle being made for it to be
tied to, so it is handed to the handle it was installed on, and what that
handle held before is let go of in the same step. Installing a second policy
therefore releases the first, and installing none — Kotlin's `null`, C's
`NULL` — releases what was there and installs nothing. A call that failed, or
threw rather than answered, leaves the handle exactly what it had and lets go
of the listener that never arrived. `stackDestroy` releases whatever is left,
the same way it releases the one a config struct carried. On the C side the
key is all that crosses, in the callback's own user pointer, as it does for
every other listener here: a Kotlin caller never sees a function pointer and
has no way to hand one over.

Such a wrapper holds the keeper's own monitor for the whole of the call, which
is the one place in this binding where a lock spans a native call. It has to:
registering the listener, installing it and recording which one is now
installed are three steps, and two threads installing at once would otherwise
each record their own key after the other's call had already replaced it —
leaving the library asking about a listener this side had just let go of, and
every INVITE after that refused by a policy nobody wrote. Holding the monitor
makes the two orders one. Nothing waits behind it for long, because every
entry point takes the library's own lock without waiting: a call made while a
policy is running answers `SIPRAL_STATUS_BUSY` rather than blocking.

What a listener throws goes to the uncaught exception handler of the thread it
was called on, and the poll carries on once that handler returns. Android's
default handler never does: it ends the process, as it would for a throw
anywhere else in the application. The C contract is that the callback does not
unwind; a throw carried out through the poll instead would leave a Java
exception pending across every JNI call the shim makes on the way out.

**A callback that answers is handled differently, because forwarding to the
thread's own handler is the wrong answer for it.** `deliver` does not catch
for one of these: what a listener throws is left to propagate out of the call
and across the JNI boundary, rather than sent to a handler that could end the
process over a question the library only needs a yes or a no from. The
landing function reads it there instead — the same `ExceptionCheck` it already
made for a call that only reports, which used to see nothing but a JVM
failure such as an array it could not make. Whatever is pending, from either
cause, is cleared, described to `stderr` for whoever is watching, and the
answer is set to zero: the library gets the refusal every answering callback
here is declared to mean by zero, never a value read off a call that did not
finish making one. **An application author reading this is owed one
sentence, so here it is: a listener that throws is a listener that refused,
not a listener that crashed anything, and the library goes on as if it had.**

**A listener that answers returns a `Long` rather than nothing** — `Long`
because every integer crosses this boundary as one, the same rule
`SipralNative`'s parameters already follow — and the shim reads the call's
result with `CallStaticLongMethod` in place of `CallStaticVoidMethod`, cast
down to whatever C type the declaration answers with. Nothing else about the
listener changes: it is still kept under a key, tied to the handle its call
made, and let go of when that handle is destroyed, exactly as
`SipralEventListener` is.

**A listener is handed the head of the event, and every arm of the payload
union beside it.** Nothing in the declarations says which kind writes which
arm, so a generated reader that picked one would be guessing; instead every
arm crosses, flattened a member at a time the same way a struct handed over
directly already does, and `SipralEvent.payload` is a computed property that
reads them back as one instance of each arm's own class —
`SipralRegistrationEvent`, `SipralCallEvent`, `SipralMediaEvent`, and the rest,
one per member `sipral_event_payload_t` declares. Reading a plain number out
of an arm `kind` does not name is defined the same as it is in C, Swift and
C# — it reads bytes the library wrote for a different arm — and never a
crash, only not meaningful. A buffer or a whole record behind a pointer is
not: a kind's own write into the union is real data reinterpreted as every
other arm's layout, and a pointer read out of it, whichever arm's bytes it
came from, is not an address anything owns. So the shim never dereferences
one unless `crates/sipral-ffi/src/event.rs`'s `EVENT_KIND_ARMS` says `kind`
is one of the ones that actually wrote that arm — every other kind sees that
member as if the library had never set it, null and zero, the same as it
reads before the event's `size` reaches it at all. `SipralMediaEvent.statistics`,
the one arm member that itself points at another record, is guarded the same
way, and crosses the way `sipral_media_statistics` already hands one back: a
`long[]` of its own members, made fresh for the event rather than filled into
an array the caller brought, and read back through `SipralStreamStats.of`.

**The binding checks the ABI as it loads.** `SipralNative`'s initialiser calls
`sipral_abi_check` with the version the file was printed from, and throws a
`SipralException` naming both versions when the library disagrees, which the
first touch of the binding surfaces as the cause of an
`ExceptionInInitializerError`.

**What still crosses as an address.** `sipral_media_packet_t` and
`sipral_transmit_t`, and `sipral_path_candidate_t` beside them, the structs a
caller part-fills with buffers the library writes into, cross as a `Long`, so
`mediaCapture`, `mediaMix`, `mediaPollRtcp`, `mediaPollTransmit`,
`mediaPollText`, `mediaPollRecording`, `stackPollTransmit`, `stackPollStun`,
`stackPollFarewell`, `localConferencePollTransmit` and
`mediaPathCandidateAt` cannot be called from Kotlin alone through the
generated shim; `org.sipral.idiomatic` reaches all of them through a second,
hand-written one (`idiomatic_media.c`) linked into the same library, and
`SipralClient.open` takes `ice`, `stunServer`, `turn` and `g729AnnexB` and runs
the media-socket loop "Behind a NAT" describes. It takes `referrals` as well,
off by default; `referralOf` reads `SIPRAL_EVENT_KIND_REFERRAL`'s payload, and
`acceptReferral`/`rejectReferral` take or refuse it, the first returning the
placed call as a `SipralCall` with its own media socket. `sipral.aar`, built by
`scripts/package/aar.sh`, carries a `proguard.txt` with the keep rules R8
needs for the three listener keepers' `deliver`, which nothing but native code
calls, and for every `external fun`. Coroutines and `Flow` for events are
`org.sipral.idiomatic`, and the `ConnectionService` helper is
`org.sipral.telecom` over it with `bindings/kotlin/android` on top
(`bindings/kotlin/README.md`). A foreground service for the call's lifetime is
still ahead.

`bindings/kotlin/sipral/src/test/kotlin/org/sipral/BindingCheck.kt` is what
holds the rest to account. `scripts/check.sh` links the printed shim against
the shared library and runs it on a JVM with `-Xcheck:jni`: a stack built from
a class, its first event heard on a native thread the shim attached and let go
of, a poll's worth of messages none of which the shim still holds when the next
event arrives, two header fields in a list found in the INVITE a call went out
in and two more in the 486 a refused call went out on, a second element refused
by name, every malformed packing thrown before the library is called, a
listener that throws, and one that destroys its own stack.

## Python

The fifth back end, and the only one that needs no compiler to install:
`tools/abi-gen/src/python.rs` prints `bindings/python/sipral/_sipral_cffi.py`,
a `cffi` ABI-mode `cdef` — a restricted C grammar `cffi` reads and lays out
for itself — naming the same aliases, constants, forward declarations,
enumerations, callbacks, structures and function prototypes the header
does, built out of the same printers `crate::c` already has rather than a
second walk that could disagree with them. What it prints of its own is
the published constants as `#define NAME NUMBER`, since ABI mode's own
preprocessor takes a bare literal and refuses the cast the header's own
`#define` wraps one in, and the load-and-check boilerplate around the
`cdef`: `_library_name` and `_candidates` for where the shared library
might be (`SIPRAL_LIBRARY`, then beside the package, then a checkout's own
`target/release` and `target/debug`), `ffi.dlopen`, and a call to
`sipral_abi_check` against the major and minor this file was printed from,
raising `OSError` on a mismatch the same way every other binding's load
check does — see "Checked at load is a promise four runtimes keep four
different ways" below.

`sipral.stack.Stack`, `sipral.account.Account` and `sipral.call.Call`, in
`bindings/python/sipral/`, are written against `ffi`/`lib` by hand, the way
`SipralAbi.swift` is the base the Swift package is written against. A
`Stack` owns one UDP socket — or, with `signalling` TCP or TLS, one
connection to the server (`sipral/signalling.py`) — and one background
thread: the thread drains
`sipral_stack_receive_datagram`, `sipral_stack_poll` and
`sipral_stack_poll_transmit` in a loop, the same one `interop/harness-c/main.c`
writes in C, and delivers events by decoding `sipral_event_t` whole,
inside the C callback, into a plain `sipral.events.Event` dataclass — never a
`cffi` pointer past the callback that carries it, which is exactly the rule
`docs/08-ffi.md`'s own "Signalling across the boundary" section states for
every language here. Decoded events land on an `asyncio.Queue`, per stack
and per call, reached with `loop.call_soon_threadsafe` from the poll
thread; an event naming a call updates that `Call`'s own state — minting
`Call.media` on `SIPRAL_EVENT_KIND_MEDIA_STARTED`, marking it ended on
`SIPRAL_EVENT_KIND_CALL_ENDED` — before it is ever queued, so a coroutine
woken by the queue never reads state the poll thread has not finished
writing yet. `sipral.enums` builds `EventKind`, `Status`, `CallState` and
the rest as Python `IntEnum`s by reading `lib`'s own attribute names at
import time rather than copying the header's numbers into a second
declaration, which is what lets an event kind or a status a later task
spends, from a number `docs/08-ffi.md`'s own "A numbered space has one
declaration" already reserved for it, come through as a plain,
unrecognised `int` before this file is regenerated against it, rather
than raising on the way into an enum with no member for it yet.

`sipral.media.Media` is a call's audio, on a thread of its own, the same
shape signalling has: `sipral_media_receive`, `sipral_media_playback`,
`sipral_media_capture` and `sipral_media_poll_rtcp` run in a loop paced by
`sipral_media_info_t::frame_ms`, and audio crosses as `bytes`/`memoryview`
— `Media.send_audio` queues 16-bit mono PCM of any length, cut to one
frame at a time as it is sent, and `Media.frames` is the far end's own
audio, one frame per item, decoded the moment `sipral_media_playback`
answers it. `SIPRAL_EVENT_KIND_RESOLVE_NEEDED` is delivered and not
answered: this package wires no DNS resolver of its own, and the dialog
stays on the flow its INVITE took, as `docs/12-core-api.md` says the
endpoint keeps it — the same choice the Swift and .NET packages make, and
the one `sipral_ua::Runtime` makes for a literal address. Answering with
the far end's `Contact` as a literal would move the rest of the call onto
it, and behind a registrar reached through a port mapping or a NAT the BYE
would then go where nothing answers. `sipral_stack_poll_farewell`'s own
goodbye is drained on the same poll thread and sent through the ending
call's own media socket, to the last address that socket actually heard
from, since nothing in this ABI hands an address back for it any other way
(`docs/08-ffi.md`, "A call that ends owes the far end an RTCP BYE").

An ordinary `SIPRAL_STATUS_BUSY` — another thread calling `Call.answer` or
`Account.register` while the poll thread is between two polls, both told
apart from a real failure by `docs/08-ffi.md`'s own "Signalling on one
stack is one thread at a time" — is retried for up to half a second by
`sipral.errors.call` before it ever reaches an application as
`sipral.SipralError`, and the poll thread's own draining never raises on
one at all: a `SipralError` that reached the top of that thread would end
it for good, and this stack would never poll again.

`bindings/python/tests/test_abi.py` is what holds the generated `cdef` to
account: every `#define` and enumerator the header declares, read back off
`lib` and compared against the number the header itself gives it, and
`ffi.sizeof` for every record in `RECORD_LAYOUTS`, compared against the
length tools/abi-gen worked out for the layout the process runs on and
against `sipral_abi_struct_size` — the one check nothing else
here can stand in for, since `cffi`'s ABI mode lays a struct out for
itself from the `cdef` text alone rather than linking against a compiled
definition of it. `bindings/python/tests/test_call.py` is what
`scripts/check.sh`'s `the python bindings` step runs: two stacks on
loopback, with no registrar, placing a call, answering it, exchanging
audio and DTMF, and reading back what it cost.

What is not here: a real resolver for `SIPRAL_EVENT_KIND_RESOLVE_NEEDED`.
`sipral.events._decode_payload` reads the payload of every event kind this
ABI declares, and `bindings/python/tests/test_events.py` holds it to
`EVENT_KIND_ARMS` in `crates/sipral-ffi/src/event.rs`; a kind from a newer
library it has no case for is still a whole `Event`, with `kind`,
`kind_name` and `message`, and an empty `fields`, never an exception. The
Swift, .NET and Kotlin layers read every arm too (`SipralEvent`'s typed
views, `SipralEventArgs`'s, and the flattened `SipralEvent` respectively).

A platform wheel with the native library bundled in — the one thing this
list used to name as missing — is `scripts/package/wheels.sh`: it builds
`sipral-ffi`, places the shared library beside this package the same way
`_candidates` already looks for one there, and retags the ordinary wheel
`pyproject.toml`'s own `hatchling` backend built. Nothing above changes to
make that true; a wheel built this way loads exactly the `cdef` and the
load-and-check boilerplate this section describes. On macOS the library is
built for macOS 12.0 and later — the minimum every Apple artefact shares,
set once in `scripts/package/apple.sh` — and the platform tag is read back
from the library's own load command rather than from the machine that built
it, so a wheel built on the newest macOS still installs on every release the
library runs on.

`Stack.__init__`'s `ice`, `nat`, `stun_server`, `turn_server`,
`turn_username`, `turn_password`, `g729_annex_b` and `referrals` set the
matching `sipral_stack_config_t` fields, all defaulting to today's behaviour
(everything off). `Stack.accept_referral` and `Stack.reject_referral` take and
refuse the `SIPRAL_EVENT_KIND_REFERRAL` that last one lets through, the first
opening the placed call's media socket the way `place_call` does. `sipral.enums.Ice`/`Nat`/`NatMapping`/`NatRelay` are
built the same reflective way every other enum here is, and
`sipral.events._decode_payload` grew the two cases `sipral_nat_event_t`
and `sipral_nat_relay_event_t` need. The harder half is a *media* socket:
it is the application's own and exists before its call, so `Stack`
tracks every one `sipral_stack_nat_map` names — from `place_call` or
`answer_call`, when the stack was built with `nat=Nat.STUN` — in the poll
thread's own selector alongside the signalling socket, reading what
arrives on it into `sipral_stack_receive_stun` and sending what
`sipral_stack_poll_stun` hands out for it from that socket and no other,
exactly as "Three entry points rather than a second use of the two
signalling ones" above requires. `place_call`/`answer_call` themselves
block the *calling* thread — never the poll thread, which keeps polling
throughout — until the socket's own `SIPRAL_EVENT_KIND_NAT_MAPPING`
arrives (and, with `turn_server` set, its `SIPRAL_EVENT_KIND_NAT_RELAY`
too), the wait `sipral_stack_nat_map`'s own doc comment requires before a
call may be described on it. Once `SIPRAL_EVENT_KIND_MEDIA_STARTED`
mints `Call.media`, the socket is `sipral.media.Media`'s to read from
then on, the same handoff this ABI itself describes; a call that never
reaches it — refused, or hung up while still ringing — gives the mapping
back through `sipral_stack_nat_unmap` when its `Call` closes, and so does
`Stack.close` for any socket mapped and never spent by a call at all.
`bindings/python/tests/test_nat.py` proves it against a STUN responder
this test suite runs itself, and runs two stacks with `ice=Ice.REQUIRED`
against each other for the ICE half, with no server at all.

ABI 0.29 reaches Python as it reaches .NET. `Stack(audio=None)` resolves to
`AudioMode.DEVICE` where `sipral.features()` has `Feature.AUDIO_DEVICE` and
to `AudioMode.APPLICATION` elsewhere (`stack.audio_mode`); in device mode the
stack hands the library a cffi `audio_transmit_callback`, kept on the
instance like the event callback, that sends each packet from its call's
media socket and calls nothing in the library, and `Media.pumped` keeps the
media thread to the socket, RTCP and DTMF. `sipral.audio.Audio`
(`stack.audio`) carries the `sipral_audio_*` entry points with gain as a
ratio; `Event` grew the typed views `identity`, `answering`, `cause` and
`audio` over the fields `_decode_payload` now copies; and `Call.readdress`,
`Call.hangup_for`, `Call.identity`, `Call.srtp_suite`,
`Stack.redirect_call`, `Stack.call_identity`, `Stack.move_to`,
`Account.rebind` and `add_account`'s `session_timer`,
`session_interval_seconds`, `privacy` and `trusted_peers` are the rest.
`sipral.enums` reads the new spaces off `lib` like every other one, with
`Feature` and `Privacy` as `IntFlag`s. `tests/test_audio.py`,
`tests/test_identity.py` and `tests/test_move.py` prove them without opening a
microphone: device mode is only ever activated manually there, and the
transmit callback is handed a record the test builds.

## Dart

The sixth back end: `tools/abi-gen/src/dart.rs` prints
`bindings/dart/lib/src/sipral_abi.dart` for `dart:ffi`. Each record is a
`Struct` or `Union` whose integers carry their exact width, each enumeration
is a set of `int` constants, each callback a native and a Dart function
type, and every entry point is a method of `Sipral`, looked up in the library
`Sipral.open()` opened and refused, like every other binding, when
`sipral_abi_check` says the library cannot serve the ABI the file was printed
from. A name that is a reserved word in Dart is printed with a `$` after it.
`Sipral.recordSizes()` lists every record with its `dart:ffi` length, which
`bindings/dart/test/abi_test.dart` holds to what `sipral_abi_struct_size`
reports.

`SipralStack`, `SipralAccount`, `SipralCall` and `SipralMedia`, in
`bindings/dart/lib/src/`, are written by hand against it. Everything runs on
the isolate that opened the stack: the sockets are `RawDatagramSocket`s, the
poll and each call's frame clock are timers, and the event callback is a
`NativeCallable.isolateLocal` the library calls from inside
`sipral_stack_poll`, on that same thread; the events reach the application
as a `Stream`, and `SipralStack.onRawEvent` is handed each one whole, as the
printed `SipralEvent`, while it is still the library's, for any payload arm
the typed copy does not carry. The application carries each call's audio,
as in application mode everywhere. Signalling is UDP only: unlike the four layers above, this
one does not answer `SIPRAL_EVENT_KIND_TRANSPORT_WANTED`, so a request too
large for a datagram gets the ten seconds an application that says nothing
gets. `bindings/dart/test/loopback_test.dart` places a call between
two stacks on loopback, and `scripts/check.sh`'s `the dart bindings` step
runs both test files against the library it built.

## React Native

`bindings/react-native` is not a back end: nothing in it is printed,
and none of it calls the ABI. It is a TurboModule whose native halves are
written over the Kotlin layer on Android (`SipralClient`, `SipralAccount`,
`SipralCall`) and the Swift layer on iOS (`SipralStack`, `Account`, `Call`),
so it speaks whatever ABI those two speak and moves when they do.

What crosses to JavaScript is the codegen spec, `src/NativeSipral.ts`: a
client, its accounts and calls named by their handles as decimal strings (a
handle is 64 bits and a JavaScript number carries 53 exactly), and one event
type, flattened, whose kind and states are the library's names in lower
camel case (`SIPRAL_CALL_STATE_EARLY_MEDIA` is `earlyMedia`). The typed API
above it keeps each call's state from those events and refuses what the
state does not allow before crossing, with the status the library would
answer. Audio is device mode on both phones, never application mode: nothing
in JavaScript could carry a call's frames. Each half's logic is a class with
nothing of React Native in it (`SipralReactCore`, in Kotlin and in Swift),
which `scripts/check.sh` runs over real stacks on loopback; the TurboModule
around it only moves arguments and promises. `bindings/react-native/README.md`
has the API and what is tested where.

## Versioning

The C ABI carries its own version, independent of the crate version. It is
reported by a function, `sipral_abi_check`, and a mismatch is a hard failure
with a legible message naming both versions, rather than a crash at whichever
call happens to hit the difference first.

Which number moves is a rule about the printed surface and not about the Rust
behind it. `SIPRAL_ABI_VERSION_MAJOR`, `_MINOR` and `_PATCH` in
`crates/sipral-ffi/src/version.rs` are where they are written down, and this
is what they mean:

- **major**, when a declaration that was published changes meaning, changes
  shape or goes away. Nothing built against one major works against another.
  While it is 0 the ABI is not frozen and no minor promises anything about
  another, so `sipral_abi_check` takes an exact match; from 1.0 a binding
  built against an earlier minor of the same major keeps working.
- **minor**, for anything the header gains: a function, a struct member, an
  enumerator, a published constant, a type alias — everything the generator
  prints, and not only the function and the struct member the rule used to
  name. `sipral_abi_check` compares the major and the minor, and does not ask about the patch, so a
  surface that grew without the bump is a surface no load-time check can tell
  from the one before it: a binding generated against the grown header loads
  happily against a library built before the addition, and finds the symbol
  or the member missing at the first call that wants it.
- **patch**, for a fix that changes no declaration, once a release has been
  published; before the first release it stays 0. It is not asked for at
  load, because it cannot make two builds disagree.

A member appended to a config struct is the ordinary case of that, and what
decides whether it costs the caller anything is the **pinned length**.
`declared_size` refuses anything below `Versioned::MIN_SIZE`, and that is
where the oldest version of the struct the frozen ABI publishes ended. It is
written as the member that version ended with — `pin!(SipralAbiVersion,
reserved)` — and the number is where the compiler puts the end of that member
on the target being built, so it stands still while the struct grows and is
right on a 32-bit target as well as a 64-bit one. Pinned that way, an
appended member is genuinely additive: the old caller's smaller `sizeof` is
still at or above the pin, so it is still accepted, and the members it never
sent come back zero.

There are two ways to get this wrong, and the crate has made both. Written
as `size_of::<Self>()`, the pin tracks the current build, and the first
appended member turns away every caller compiled against yesterday's header.
Written as a literal read off a 64-bit build, which is what every pin was up
to minor 32, it is one number on every target while the length it describes
is not: on 32-bit ARM `sipral_abi_version_t` is 20 bytes and the literal said
24, so the library refused every caller doing exactly what its own header
said — 27 structs on every 32-bit target. A const assertion beside every pin
now refuses, when the crate is compiled for any target, a pin longer than
the struct it pins.

**No struct ends in padding, on any target.** Padding after the last member
is where the next appended member would start on that target, and a caller
compiled against the shorter header declares a length that includes it and
never wrote those bytes: the library would read whatever its stack held
there as a value the caller set. Up to minor 32 seven members were appended
that way, and fifteen structs ended in padding on 64-bit targets, on 32-bit
ARM or on both. At minor 33 fourteen of them carry an explicit `reserved`
member and the fifteenth had a member moved, and three checks keep it so: the
`record!` macro asserts, when
the crate is compiled, that a struct with a size ends where its last member
does on that target; `tools/abi-gen` refuses to print a surface in which one
ends in padding on any of the three layouts below; and `scripts/check.sh`
compiles `bindings/c/abi-layout.c` for six targets.

`bindings/c/abi-sizes.txt` is printed beside the header and the bindings,
and the gate diffs it like the rest: per struct, the pinned member, then for
each layout the pin and the current length. Three layouts cover every target
the ABI ships for: `p64` (64-bit pointers), `p32a4` (32-bit pointers, a
64-bit integer aligned to four inside a struct: i386 System V) and `p32a8`
(32-bit pointers, a 64-bit integer aligned to eight: ARM EABI and 32-bit
Windows). `tools/abi-gen` works each out from the declarations rather than
reading them off the build it runs on; `bindings/c/abi-layout.c` states every
length, offset and pin as `_Static_assert`s over the header, and the gate
compiles it with `clang -target` for x86-64, i386, ARM64 and ARMv7 Linux and
for 64-bit and 32-bit Windows. Every generated binding carries the same table
and its own size test holds its own layout of each record, and the library's
answer from `sipral_abi_struct_size`, to the number for the layout it runs
on. The gate also holds the pins to the last commit: a pin that moved or went
away within one major fails it. And it holds every member's offset, on every
layout, to the last commit's `abi-layout.c`: a member that moved or went away
fails it, and so does a new member that starts inside the length the struct
had there. That is the one fault the three checks above cannot see — a member
slipped into a hole between two others changes no length and no pin, and the
assertions are printed again with it — and it is the tail-padding fault over
again: a caller built against the header before it never wrote those bytes.

Turning a caller away is still the right answer when the member is one the
call cannot proceed without: `media_seed` is one of those, and
`sipral_stack_create` says `SIPRAL_STATUS_INVALID_ARGUMENT` rather than
running with one key generator where there should be two.

Growing the surface is a minor bump in the same change as the addition, next
to the regenerated `bindings/`. The gate forces the regeneration — committed
output against what the declarations print — and nothing but a reader forces
the bump, which is why the rule is written here rather than left to be
inferred from the constant. Within one block of surface work the bump is
taken **once, at the end**: nothing is published, so no build in the world is
on an intermediate minor, and a bump per task costs a full gate run and a
regenerated binding set for a version nobody can have.

**Checked at load is a promise four runtimes keep four different ways, not
one mechanism.** .NET's `Sipral` gets a static constructor, printed by
`tools/abi-gen`'s C# back end rather than written into `SipralAbi.cs` by
hand — the CLR guarantees it runs before the class's first use, which is the
nearest a managed assembly has to "at load" without asking every caller to
remember it. It calls `AbiCheck(AbiVersionMajor, AbiVersionMinor)`, and a
mismatch stops the class before anything else in it runs — but not as a
`SipralException` a caller can catch by that name. The runtime wraps whatever
a static constructor throws, so the first use of `Sipral` throws
`TypeInitializationException`, whose `InnerException` is the `SipralException`
with both versions in its message, and every later use throws that same
`TypeInitializationException` again without running the check a second time.
An application that wants the sentence reads the inner exception. Kotlin's
`SipralNative.init {}` block keeps the same promise the JVM's own way: the JVM
guarantees a singleton `object`'s initialiser runs once, before its first
member is read, and that block calls `agree(major, minor)` there, which
throws `SipralException` on a mismatch — wrapped, on the first touch, as the
cause of an `ExceptionInInitializerError`, and rethrown as
`NoClassDefFoundError` on every touch after, without the check running again.

Swift has neither a module initialiser nor a singleton object to hang one on:
nothing the language guarantees to run before a namespace `enum`'s first use,
the way a static constructor does for a class or `init {}` does for a Kotlin
`object`. What Swift does guarantee, and what `SipralAbi.swift` uses instead,
is narrower and just as usable: a static stored property's initialiser runs
at most once, finishing before the first read of it returns, on whichever
thread reaches it first — the same promise `dispatch_once` made in
Objective-C. `Sipral.abiMismatch` is that property. It calls
`sipral_abi_check` once, against the version this file was printed from, and
every call in the `enum` reads it first, through `ensureAbi()`, before it does
anything else. So the check runs the first time the application calls
anything at all in the module, on whichever thread makes that call — not at
import, which Swift gives no hook for — and a mismatch is what that first
call throws: a `SipralError`, not a separate call the application has to
remember to make and not a warning that is easy to miss.

Python's own module, of the four, needs no trick to hang the check on: a
module's top-level code runs exactly once, the first time anything imports
it, which is already "at load" with nothing further to ask of the
language. `sipral/_sipral_cffi.py` calls `sipral_abi_check` there, right
after `ffi.dlopen`, and raises a plain `OSError` naming both versions on a
mismatch — the same statement that loaded `lib` is the one that checked
it, so there is no later call, no wrapped exception type, and no second
touch that skips the check the way .NET's and Kotlin's both do.

Skipping it is not safe on any binding, and on Swift it is not something a
caller can do at all: there is no call into `Sipral` that reaches C without
going through `ensureAbi()` first. The `size` every versioned struct carries
settles how long a struct is, not what is in it: a header and a library that
disagree about the order or the meaning of members can still agree about the
length, and then every size rule passes while the library reads a pointer out
of whatever the caller put in its place. No entry point can catch that,
because whether a pointer is readable for the length beside it is the
caller's promise in every Safety section, not something the library can
check. The version check is the one call that finds the disagreement before
anything is read.

## The freeze (ABI 0.33)

Minor 33 is the last minor before 1.0, and the surface it prints is the one
1.0 promises. From 1.0 on, for the life of major 1:

- **Names stand.** Every entry point, struct, member, parameter, enumeration,
  enumerator, constant and callback keeps the name it has at 0.33, and every
  parameter keeps its place.
- **Numbers stand.** An enumerator, a status, a feature bit and a constant keep
  their values; new ones are only added. Status 17 stays a hole.
- **Layouts only grow at the end.** A struct that carries `size` gains members
  only after its last one, and never ends in padding on any of the three
  layouts; its pin — `bindings/c/abi-sizes.txt` — never moves. `sipral_header_t`
  and the event payload arms never change shape.
- **Behaviour a caller sizes buffers or retries by stands**: which calls
  write a NUL and count it, which accept a null out-pointer, which status a
  failure is. The conventions block at the top of `sipral.h` is the list,
  in one place, and every entry point follows it or says why not in its own
  comment.
- **Ownership stands.** The library hands out no memory a caller frees, every
  pointer a callback is handed is valid for that call, and the table of
  callbacks at the top of the header says on which thread each runs, what is
  held while it does, what it may call, and how long its `user_data` must
  live.

A header from before 0.33 is refused at load by the exact-minor rule, and a
struct as long as a pre-0.33 header declared it is refused by its pin: the
oldest version of every struct the frozen ABI serves is minor 33's. The
sections above that tell how a member was appended "with the pin unmoved"
describe how the ABI grew before the freeze.

What changed at 0.33, against the audit of 30 September 2026:

- The pins are members, not literals (see Versioning), and hold on 32-bit
  targets; fourteen structs gained a `reserved` member and
  `sipral_stack_config_t::dtmf_detection` moved before `stun_fallbacks`, so
  no struct ends in padding anywhere.
- `SIPRAL_STATUS_NOT_AFOCUS` is `SIPRAL_STATUS_NOT_A_FOCUS`, the name every
  sentence already used; the rule that turns a Rust name into a C one now
  starts a word at a capital that a lower-case letter follows.
- `sipral_call_attach_processor`, `_detach_processor` and `_reset_processor`
  take a media handle and are `sipral_media_attach_processor`,
  `sipral_media_detach_processor` and `sipral_media_reset_processor`; the
  callback parameter is `callback`, as it is everywhere else.
- `sipral_call_identity_text` takes `index` before `which`, as
  `sipral_subscription_dialog_text` and `sipral_subscription_conference_text`
  do: the entry first, then the piece of it.
- `sipral_stack_transport_failure` is `sipral_stack_transport_failed_with`,
  the richer form of `sipral_stack_transport_failed` in the `_with` pattern
  `sipral_call_answer_with` and `sipral_media_record_start_with` set.
  `sipral_stack_state` is `sipral_stack_state_text`: it copies text, where
  every other `_state` returns an enumerator.
- Text out is one family: `out_needed` everywhere (it was `out_len` on five
  calls), null accepted everywhere (four calls refused it), the NUL written
  and counted everywhere — `sipral_audio_device_at` wrote neither, and wrote
  its struct even when it answered `SIPRAL_STATUS_BUFFER_TOO_SMALL`; it now
  writes nothing then. The .NET, Python and Dart layers each read one byte too
  many of the last error and handed the NUL on in every exception message.
- `SIPRAL_STATUS_CLOCK_BEHIND` (24) is what a `now_ms` more than fifty
  milliseconds behind the stack's last reading answers; it was
  `SIPRAL_STATUS_INVALID_ARGUMENT`, which a binding could only tell apart by
  reading the English. `SIPRAL_STATUS_EXHAUSTED` is documented as what it
  already was: no room, in a table, a port range or a queue.
- An optional address (`to` on `sipral_stack_receive_datagram`, `remote`
  on `sipral_stack_transport_bind`) and
  the `sdp` beside a `media_address` are absent when their length is zero,
  whatever the pointer, like every other optional text: a binding that hands
  every string over as a buffer had no way to leave one out. The members
  `sipral_call_ring_media` and `sipral_call_accept_transfer` refuse as "not
  read here" count as set by the same rule, their length, and not by their
  pointer.
- Every callback crosses the generated .NET binding as a function pointer
  (`IntPtr`), in a struct and as a parameter, so no struct holds a delegate;
  the generated Swift wrappers take an optional callback and an optional
  `user_data`, so a log or a screening policy can be removed through them;
  the Kotlin layer reaches `sipral_media_mix` through its own shim.
- Safety: a datagram longer than the caller's packet buffer is refused rather
  than copied past it; `sipral_media_mix` builds no slice over a null
  pointer; every media entry point called from inside a frame of any call's
  media is `SIPRAL_STATUS_BUSY`, which rules out two processors each waiting
  on the other's call; a poll never waits for the audio engine; and
  `sipral_stack_destroy` from the audio transmit callback is
  `SIPRAL_STATUS_BUSY` rather than a thread waiting for itself to end.
- `stdbool.h` is no longer included: nothing in the surface is a `bool`.
- Every parameter and member that holds an enumeration's number is declared
  with that enumeration's `typedef` — `sipral_call_state(..., sipral_call_state_t
  *out_state)`, `sipral_codec_info_t::codec` as a `sipral_codec_t` — where it
  was a `uint32_t` with the enumeration named only in its comment. The
  declaration in `crates/sipral-ffi` says it with `Number<E>`, which is `E`'s
  integer and nothing else, so a number no enumerator has is still read as a
  number and refused where it is used; a test fails the build for a `u32`
  member whose documentation names an enumeration. The typedef is the same
  width, so nothing a caller or a binding hands over changed; the generated
  Swift, .NET, Kotlin and Dart wrappers keep the plain integer, and the name
  travels in the generator's model for a binding that wants to type it.
- The header speaks C: a link's path into the crate is taken off, a type
  named in code quotes is spelled the C way (`sipral_toggle_t`, not
  `SipralToggle`), and `tools/abi-gen` refuses to print a header that still
  names a module, a macro or a crate below this one.
- The generated Swift `SipralError` carries the number it was thrown with,
  `code`, and a `status` that is nil for a number a newer library returned
  and this binding has no name for; it used to call every such status
  `.panic`.

## What ABI 0.34 added

The first minor after the freeze, grown the way the freeze allows and no
other: every member is appended after the last one its struct had at 0.33,
every number is the next free one, and the gate held every pin and every
member's offset on all three layouts to the 0.33 tree. A 0.33 header is
refused at load by the exact-minor rule, as any header of another minor is;
a struct declared at its 0.33 length is still taken, its new members read as
zero.

**Stack configuration** (`sipral_stack_config_t`, after `rtp_port_max`):

- `srtp_suites` — the SRTP suites every call of the stack offers and accepts
  unless its account names its own, in the account's comma-separated form.
- `path_mtu` — the path MTU toward the server when the deployment knows it,
  zero for unknown; under 576 is refused. RFC 3261 §18.1.1 moves a request
  to a stream within 200 bytes of it rather than past 1300 bytes.
- `datagram_without_stream_bytes` — a deliberate deviation from §18.1.1 for
  a server that takes SIP over UDP alone: once the application says the
  stream `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` asked for is not coming
  (`sipral_stack_transport_failed` on the number it would have bound) or the
  wait runs out, what was waiting goes over UDP up to this size. Zero is off;
  past 65 507 is refused. `sipral_stack_settings_t` reads both figures back.
- `pseudonym_salt` — at least 16 bytes an installation keeps, keying the
  pseudonyms of the log and the state text so that two runs compare line by
  line; without it they are keyed from `media_seed` and differ every run.
- `diagnostic_trace` — a `sipral_toggle_t`: the trace writes SIP messages
  whole, with the peer, credentials and keys taken out;
  `sipral_stack_diagnostic_trace` turns it on and off while the stack runs.
- `reserved`, so that the struct ends where its last member does.

`SIPRAL_SRTP_BEST_EFFORT` (7) offers SDES on plain `RTP/AVP`: keyed when the
answer takes a line, plain when it takes none, for a PBX that answers an
`RTP/SAVP` offer with 488 (`docs/05-media.md`).

The signal that a request went over UDP past the line is not an event. No
event this ABI has carries a reason a transport choice could be written in —
`SIPRAL_EVENT_KIND_TRANSPORT_WANTED` asks the application for a stream, and
`SIPRAL_EVENT_KIND_TRANSPORT_FAILED` says one was lost — and reusing either
would have an application open a connection or mourn one that nothing
lost. It is the decision `transport.kept.datagram`, with the request's size
and the limit, in the call's diagnostic record
(`sipral_call_record_json`, `sipral_stack_diagnostics_json`).

**Account configuration** (`sipral_account_config_t`, after
`recording_in_clear`):

- `keepalive_ms` — the account keeps its flow to its registrar, or to its
  outbound proxy, open at this interval whatever STUN found: a double CRLF
  on UDP, a ping on a stream (RFC 5626 §4.4.1). 1 000 to 120 000; zero is
  off.
- `server_uri` — the server the account's requests go to, as a URI whose
  host RFC 3263 locates, in place of `registrar_address`; exactly one of
  the two is given. `server_naptr` asks NAPTR before SRV.
- `tls_pin_sha256` — the SHA-256 fingerprint of the one TLS certificate the
  account trusts, in the forms `openssl` and RFC 8122 print.
- `reserved`.

**Locating a server.** The lookups are the application's resolver's, one at
a time. `SIPRAL_EVENT_KIND_LOOKUP_WANTED` (55) names a query in
`payload.locate` — `name`, and `record`, a `sipral_dns_record_type_t` —
and `sipral_account_looked_up` hands the answer back: a
`sipral_dns_answer_t` and, with `SIPRAL_DNS_ANSWER_RECORDS`, the records as
text, comma-separated, each its time-to-live and then its data as a zone file
writes it (`300 10 60 5060 sip1.example.com` for SRV). Text rather than an
array of structs, because it is what a platform resolver prints and what
every binding hands over as it is, and because an array element can never
grow. `SIPRAL_EVENT_KIND_LOCATED` (56) gives every address found, first the
one in use; `SIPRAL_EVENT_KIND_LOCATE_FAILED` (57) gives why, as a
`sipral_locate_failure_t`, and when the name is asked again. Until the first
answer a call with no `destination` of its own is
`SIPRAL_STATUS_WRONG_STATE`. When the recovery ladder climbs to
`WantAddress` (`docs/16-lifecycle.md`), every account whose server is a name
is looked up again, and the ladder climbs on at once when the answers are in,
as it does when the application answers with `sipral_account_rebind`.

**A pinned certificate.** `sipral_account_check_certificate` takes the DER
bytes of the leaf a TLS server presented, from inside the application's
certificate verifier, and answers `SIPRAL_STATUS_CERTIFICATE_REFUSED` (25)
when the account pins another, or `SIPRAL_STATUS_OK` with
`sipral_pinned_certificate_t::pinned` set and the certificate's dates, an
expired one included; `pinned` zero means the account pins nothing and the
platform decides (`docs/22-tls.md`). `sipral_pinned_certificate_t` is the
one new versioned struct, pinned at its `reserved`.

**An address a peer can reach.** A loopback address advertised to a peer
that is not on this machine, in a `Contact` or a session description, or the
unspecified address in a `Contact`, is refused with nothing sent:
`SIPRAL_STATUS_UNREACHABLE_ADDRESS` (26) from the call that would have sent
it, and `SIPRAL_REGISTRATION_FAILURE_UNREACHABLE_CONTACT` (5) for a REGISTER
the stack sends on its own. `sipral_advertised_address` gives the address to
advertise for a socket bound at `bound` toward `peer` — the route's address
for a wildcard bind — as text out; it names no stack and may be called from
anywhere.

**The trace of a stream.** A connection's reads are not messages. With the
log at `SIPRAL_LOG_LEVEL_TRACE`, every message the endpoint frames off a
TCP or TLS connection is traced whole, one line per message, with the far
end the connection was bound to, or "on a connection" for one bound without
it; the byte count of each read is no longer written.
