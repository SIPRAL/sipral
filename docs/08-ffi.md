<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# sipral-ffi and the language bindings

## The shape

One narrow C ABI, and one idiomatic wrapper per language written on top of it.
The C layer is not meant to be pleasant. It is meant to be stable and small.

Rules for the ABI:

- **Opaque handles only.** No Rust type crosses the boundary. Structs that do
  cross are `#[repr(C)]`, POD, and versioned by a `size` field as the first
  member.
- **Explicit ownership.** Every allocation the library returns has exactly one
  matching free function. Strings are UTF-8, length-delimited, never assumed
  null-terminated on input.
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
  tagged union. The callback may be invoked from the caller's own polling
  thread only, so the language side never has to reason about which thread it
  is on.
- **The library is not re-entered from inside that callback, except to destroy
  the stack.** Every call naming the stack being polled returns
  `SIPRAL_STATUS_BUSY` while its callback is running, so a binding can neither
  deadlock itself by answering an event with a request nor see a stack halfway
  through delivering one; what it does with an event is copy what it needs and
  act after poll returns. `sipral_stack_destroy` is the exception and always
  will be — it takes nothing but the handle table, and what the poll is
  holding stays alive until that poll returns — so a binding whose event
  handler is where its object gets disposed needs no queue of deferred frees
  to be correct. The reasoning behind both is the module documentation of
  `crates/sipral-ffi/src/stack.rs`, and the generated header puts the rule in
  two sentences at the top, so a binding author meets it wherever they start.
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

  Where a number cannot be generated — `SipralStatus`, which C switches on and
  whose zero is load-bearing — the equivalent is a test that writes out every
  value rather than deriving it, so a declaration that moved would disagree with
  a test that did not.

## Handles

A handle is sixty-four bits naming one thing the library owns: a stack, an
account, a call. A caller reads nothing out of it. The layout is written down
for the person reading a log line or a crash dump, and for whoever adds a table.

- **The layout.** The low twenty-four bits are the slot, the eight above them
  are the tag of the stack the handle belongs to, and the top thirty-two are the
  slot's generation. Zero is never a generation, so zero is never a handle, and
  a handle that lost its top half in a 32-bit variable is refused before a slot
  is read — rather than working for the first call on the first stack and
  failing for every other.
- **A handle names something only on the stack that minted it.** Every stack
  numbers its accounts and its calls from the same first slot, so before the tag
  the first call on one stack and the first call on a second were the same
  number, and a hang-up passed to the wrong stack ended that stack's call and
  answered `SIPRAL_STATUS_OK`. An account or call handle used with any other
  stack is now `SIPRAL_STATUS_INVALID_HANDLE`, and the last error says it was
  minted by another stack. The tag is checked where a stack's tables look a
  handle up, `crates/sipral-ffi/src/names.rs`, and every handle of every kind is
  put together by one function in `crates/sipral-ffi/src/handle.rs` that takes
  it, so a table added later cannot mint without one.
- **The widths.** The generation keeps all thirty-two bits because a slot that is
  reused runs out of them: ten calls a second through one slot last about
  thirteen and a half years on thirty-two bits, and nineteen days on
  twenty-four. Twenty-four bits of slot is sixteen million live objects on one
  stack. Eight bits of tag is 256 stacks alive in one process, and that is the
  limit: the next `sipral_stack_create` is `SIPRAL_STATUS_EXHAUSTED` and writes
  no handle.
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
  stacks holding it have used up between them — four billion reuses of one slot
  — is not offered again, and the limit is one stack lower from then on.
- A stack's own handle lives in one table for the whole process, whose
  generations never start over, so the handle of a destroyed stack is
  `SIPRAL_STATUS_STALE_HANDLE` even once another stack carries its tag.

## Signalling across the boundary

The ABI could describe a call, negotiate its audio, record it and report what it
cost before it could place one. `sipral_stack_poll` counted the bytes the stack
wanted written and threw them away, and there was no way to hand back what
arrived — media I/O was ahead of signalling I/O, so the boundary carried a call's
audio and not its INVITE. `crates/sipral-ffi/src/transport.rs` is the other half.

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

**One transport, and its number is published.** `SIPRAL_TRANSPORT_MAIN` is the
transport a stack is created with and the only one this build binds; every other
number is `SIPRAL_STATUS_INVALID_ARGUMENT`. Every call names it anyway. A second
transport is not an I/O question — an account carries the transport its REGISTER
goes out on and a call carries the one its INVITE does — so when it arrives it
is a member of `sipral_account_config_t` (today that struct has no such member),
and it belongs with the §18.1.1 promotion onto a stream that spends event
number 18. Naming the transport now makes that growth
more valid numbers rather than a second set of functions taking an argument the
first set lacks.

**A transport that failed is retired.** Both the failure and an orderly close
fail every transaction on the transport and unbind it, which is §17's "inform the
TU and terminate" arriving where an application can see it. Nothing goes out
afterwards until `sipral_stack_transport_bind` brings a transport back — which is
also how a socket re-opened on another address after the network moved says what
goes in the `Via` from now on, and how a stream names the far end it reached.

**The stream path is carried, and the promotion onto it is not.** TCP and TLS
work end to end: bytes go in as fragments, the layer below frames them on
`Content-Length` (§18.3), and a connection that closes retires its transport. A
WebSocket frame goes in as a datagram, because RFC 7118 §4.2 puts one message in
each. What is deferred is §18.1.1 — a request that outgrew a datagram going out
on a stream instead — which needs a second transport and the event number already
reserved for it. `sipral_transmit_t::protocol` is the seam: it says what the
message is going out over rather than what the socket is, and it is the member
that would start disagreeing with `sipral_stack_settings_t::transport` on the day
that lands.

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
application hears the outcome as `SIPRAL_EVENT_KIND_MEDIA_CHANGED`.

**Four calls carry the packets**, and none of them opens a socket or touches a
device: `sipral_call_media_receive` for a datagram that arrived,
`sipral_call_playback` for the frame due for the earpiece, `sipral_call_capture`
for one from the microphone, and `sipral_stack_poll_rtcp` for the control
traffic RFC 3550 §6.3 schedules. Samples are 16-bit mono at
`sipral_media_info_t::sample_rate`, a frame is exactly `frame_samples` of them,
and outgoing packets are written into buffers the caller brings — checked before
anything is built, so a frame is never encoded and then dropped for want of
somewhere to put it.

**Recording is where a path becomes a file**, and the file belongs to the media
session from then on. C never sees the handle, so it cannot leak it or close it
underneath the stack. The one thing that had to be arranged rather than
inherited is the WAVE header: it carries two lengths that are not known until
the recording stops, so every way a recording can end closes it properly —
`sipral_call_record_stop`, the call ending, and the stack being destroyed,
including from inside its own event callback. Destroying a stack mid-recording
leaves a playable file, not a repair job.

**Configuration is answered, never absorbed.** A codec name this build has no
encoder for is `SIPRAL_STATUS_NOT_SUPPORTED` where the order is set, with the
names it does have in the last error; a stall threshold set while the watchdog
is off is `SIPRAL_STATUS_INVALID_ARGUMENT`, the same shape as a retransmission
timer set on a transport that retransmits nothing. Every boolean media setting
is a three-valued `sipral_toggle_t` — default, on, off — because a zeroed struct
cannot otherwise tell "off" from "nothing was said", and
`sipral_stack_settings_t` reads back what each of them came to.

## One declaration, and four files printed from it

B7's failure is a C seam declared in several places that have to agree: a
function added to the Rust and forgotten in one binding produced a build that
compiled and failed at run time, on one platform, in the field. The answer here
is that the header and the three bindings are not declarations at all. They are
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
a rule that is wrong is wrong in the header and all three bindings at once — the
gate would compare wrong output against wrong output and pass. That is the
price of one source of truth, and it is the right price: a mistake that is
everywhere is a mistake somebody finds, where a mistake in one binding of three
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
small synthetic surface printed as the five files the generator writes — the
header, the Swift binding, the .NET binding, and the Kotlin binding with the
JNI shim beside it — so a change to an emitter shows up there rather than
buried in `bindings/`. "Small" and "reaches every emitter path" pull against
each other, so the second one is counted rather than claimed: a test takes
the shapes of the real surface and the shapes of the synthetic one and fails
naming each shape the golden files do not reach.

**The conventions are load-bearing now.** The generator reads the ABI's own
shapes off the parameter lists: a pointer followed by a length is one buffer
going in, a pointer followed by `capacity` is a buffer the library fills, a
writable pointer named `out_…` is one value coming back, and a pointer to a
versioned struct is a struct going in, coming back, or both, according to which
way it points and whether the struct holds buffers of the caller's. So a new
parameter called `blob` beside `blob_size` rather than `blob_len` is not a
naming preference: it is a binding that hands over a raw pointer instead of a
string. `tools/abi-gen/src/model.rs` is where those four rules are written down.

### What the gate catches

A function, a struct, a union, an enumeration, a constant or an alias added,
removed or renamed on the Rust side and not reaching the header or any of the
three bindings. A member appended to a struct, a value added to an enumeration,
a parameter added to a function, a type changed. The number an event kind
spends, which travels into all four files. Every one of those is a difference
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

**Nothing compiles the output but the C.** There is no Swift, Kotlin or .NET
toolchain in `scripts/check.sh`, so a generated file in one of those three that
will not compile passes the gate. The JNI shim is never compiled by anything
here, which is why it is printed as casts and array handling and nothing
cleverer. The header is the exception, and no longer only just:
`bindings/c/smoke.c` includes it, compiles under `-std=c11 -Wall -Wextra
-Werror`, links the shared library and runs, in the gate; `bindings/c/sipral.c`
compiles it a second time as the Swift package's own translation unit.

**It says nothing about meaning.** A member that keeps its name and its type and
starts meaning something else travels into all four files intact. So does a
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

**The packaging is written by hand.** `Package.swift`, the `.csproj`, the two
readmes, `bindings/c/sipral.c` and `bindings/c/smoke.c` are not printed and not
compared. What they build is.

## Swift

A Swift Package whose C target is the generated header, and whose Swift target
is `SipralAbi.swift`, printed beside it. A status is a thrown `SipralError`
carrying the last message; a pointer and a length are a `String` or an array
held alive across the call; a buffer the caller brings is an `inout` array; a
struct the library fills in whole is what the call returns, with an extension
per struct that hands over a zeroed one with its `size` already set. Nothing in
the printed surface is a raw pointer except the two structs a caller part-fills
with its own buffers, which are `inout` and typed.

What is not printed is the platform work, and it is what the binding will
actually earn its place for: `CallKit` for call UI and audio session priority,
`PushKit` for waking on an incoming call, and `AVAudioSession` category and
interruption handling. An iOS softphone that gets these wrong does not work,
regardless of how good the stack is. `async`/`await` over the event callback
belongs there too.

## .NET

`SipralAbi.cs`, printed, in two layers. `NativeMethods` is the ABI as P/Invoke
declares it, with every pointer written as an array or as `in`, `ref` or `out`,
so the package compiles without an unsafe block and the runtime does the
pinning; `Sipral` is the layer above, where a status becomes a
`SipralException`, a byte pointer and its length become a `string`, and
everything written back becomes what the call returns.

What is not printed: the native assets for `osx-arm64`, `osx-x64`, `win-x64`,
`win-arm64` and `linux-x64`, the `Task`-based surface, `IAsyncEnumerable` for
event streams, and the `SafeHandle` that makes a missed `Dispose` a leak rather
than a crash.

## Kotlin

Two printed files, because Android has no way to call C but JNI:
`SipralAbi.kt`, one `external fun` per entry point plus the enumerations, the
constants, the exception and a layer that turns a status into a throw; and
`sipral_jni.c`, the C that implements them. They are printed from the same walk
over the same declarations, which is the only reason it is safe for them to be
two files.

Structs are what JNI makes awkward, and the way out is not to let one cross. A
struct the library fills in whole comes back a member at a time in a `long[]`
the shim writes, with a float carried as its own bits, so nothing on the Kotlin
side has to know a field offset — which it could not, since Android builds for
two pointer widths. What is left over is a struct the caller part-fills, and it
crosses as an address.

Two things are therefore missing from the Kotlin binding and are not missing
from the other two: a way to build a `sipral_stack_config_t` without an address,
and the event callback, which needs a C function that attaches the calling
thread to the JVM and builds a Java object out of the event struct. Until those
are printed as well, Kotlin has every declaration and not every ergonomic — the
gate binds on the first and says nothing about the second. The AAR, coroutines
and `Flow` for events, `ConnectionService` for the system dialer and the
foreground service for the call lifetime are all still ahead.

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
- **patch**, for a fix that changes no declaration. It is not asked for at
  load, because it cannot make two builds disagree.

A member appended to a config struct is the ordinary case of that, and what
decides whether it costs the caller anything is the **pinned length**.
`declared_size` refuses anything below `Versioned::MIN_SIZE`, and that
constant is the length the struct had in the **first published header** —
written once as a literal in `crates/sipral-ffi`, never recomputed. Pinned
that way, an appended member is genuinely additive: the old caller's smaller
`sizeof` is still at or above the pin, so it is still accepted, and the
members it never sent come back zero.

Written as `size_of::<Self>()` instead, which is what every one of these
constants was until the pinning landed, the arrangement inverts: the pin
tracks the current build, and the first appended member turns away every
caller compiled against yesterday's header — from a change whose whole point
was that it would not. That is the one way to get this wrong, and it is not
visible in the diff that causes it.

Turning a caller away is still the right answer when the member is one the
call cannot proceed without: `media_seed`, added at minor 9, deliberately
moved its pin, and `sipral_stack_create` says
`SIPRAL_STATUS_UNSUPPORTED_VERSION` rather than running with one key
generator where there should be two. That is a decision per member, taken
once, not a consequence of how the constant happens to be written.

`bindings/c/abi-sizes.txt` is printed from the pins beside the header and the
four bindings, and the gate diffs it like the rest: the first number per
struct is the pin, the second is what this build compiled to. Moving a pin is
therefore a line in a committed file that somebody has to sign, rather than a
constant nobody re-reads.

Growing the surface is a minor bump in the same change as the addition, next
to the regenerated `bindings/`. The gate forces the regeneration — committed
output against what the declarations print — and nothing but a reader forces
the bump, which is why the rule is written here rather than left to be
inferred from the constant. Within one block of surface work the bump is
taken **once, at the end**: nothing is published, so no build in the world is
on an intermediate minor, and a bump per task costs a full gate run and a
regenerated binding set for a version nobody can have.

**Checked at load is a promise three runtimes keep three different ways, not
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
An application that wants the sentence reads the inner exception.
Kotlin's `SipralNative.init {}` block is where the same call belongs, and it
is not there yet: today that block loads the JNI shim and checks nothing.

Swift has neither a module initializer nor anything else the language
guarantees to run before a namespace `enum`'s first use, so it has no load
hook to print one into. `SipralAbi.swift` says so directly, on `Sipral`
itself, and the application calls the check itself, once, before it creates a
stack or calls anything else in the module:

```swift
try Sipral.abiCheck(major: Sipral.abiVersionMajor, minor: Sipral.abiVersionMinor)
```

Skipping it is not safe on any binding. The `size` every versioned struct
carries settles how long a struct is, not what is in it: a header and a
library that disagree about the order or the meaning of members can still
agree about the length, and then every size rule passes while the library
reads a pointer out of whatever the caller put in its place. No entry point
can catch that, because whether a pointer is readable for the length beside
it is the caller's promise in every Safety section, not something the library
can check. The version check is the one call that finds the disagreement
before anything is read.
