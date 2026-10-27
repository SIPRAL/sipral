<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# Sipral from C++

`bindings/cpp/include/sipral.hpp` is the C ABI as C++17 classes, one header
and nothing to build: include it beside `sipral.h` and link `libsipral_ffi`
as a C program does.

```sh
c++ -std=c++17 -I bindings/c/include -I bindings/cpp/include app.cpp -lsipral_ffi
```

It adds what a C program writes by hand around every call, and nothing that
would make it a second API to learn:

- **Lifetimes.** `sipral::Stack` destroys its stack when it goes, after
  stopping the networking component if it was started and taking its message
  hook away; `sipral::Account` removes its account. Both move and neither
  copies. A `sipral::Call` holds two handles and nothing to free: the library
  forgets a call after `SIPRAL_EVENT_KIND_CALL_ENDED`, and `hangup()` is how
  one is ended.
- **Errors.** Every entry point that answers a status other than
  `SIPRAL_STATUS_OK` throws `sipral::Error`, carrying the status (`status()`)
  and the library's own sentence about it, behind the name of the call that
  failed (`what()`).
- **Handlers.** Events reach a `std::function<void(const sipral::Event &)>`
  given in `StackOptions::on_event`, on the thread inside `poll()` or `run()`;
  the message hook is a `std::function<sipral::Verdict(const sipral::Hooked &)>`
  (`03-core-signalling.md`, "A message hook"). An exception either throws is
  never let into the library: the event is skipped, the message kept as it
  was, and the first exception comes out of the next `poll()` or `run()`.
- **Time and seeds.** Every `now_ms` the C ABI asks for is read from
  `std::chrono::steady_clock`; a stack's two seeds come from
  `std::random_device`.

What the classes do not cover is still there: each object's `handle()` is the
C handle, and `Event::raw()` the whole `sipral_event_t`, payload included, so
any `sipral_*` function can be called next to them.

## The classes

| | |
|---|---|
| `Stack(StackOptions)` | `sipral_stack_create`: bind address, transport, the event handler, ICE, and a STUN and a TURN server with how the TURN server is reached. `poll()`, `set_message_hook()`, `add_account()`, `call(handle)` for a call an event names |
| `Stack::start_network(NetworkOptions)`, `run(wait_ms)` | the networking component (`26-network.md`): trust, a client certificate, name servers, the name a SIP server is held to and how it is read, and the TURN server's own trust, name and client certificate; `run` is one turn of its loop. `open_media()`, `attach_media()`, `capture()` and `close_media()` carry a call's audio through it, with its STUN and TURN |
| `Account` | `start_registration()`, `stop_registration()`, `place_call(target, media_address)` |
| `Call` | `answer()`, `reject(code)`, `hangup()`, `hold()`, `resume()`, `send_dtmf()`, `media()` |
| `locate()`, `advertised_address()`, `has_network()` | where RFC 3263 finds a server, the local address toward it, and whether this library carries the networking component |
| `frame_samples()`, `playback()` | a call's frame size, and the next frame to play with whether it came from the far end |

`interop/network/register-and-hold.cpp` is a whole program with them: it finds
Asterisk by NAPTR and SRV, registers over TLS, calls, hears the far end, holds,
resumes and hangs up with no networking code and no handle freed by hand, and
`scripts/lab.sh network` runs it after its C twin.

## How it is held

`bindings/cpp/smoke.cpp` is compiled by `scripts/check.sh`'s `abi` area with
`-std=c++17 -Wall -Wextra -Wpedantic -Werror` and run against the release
library: a refused stack is an `Error` with its status, an account goes with
its object, an INVITE carries the header a hook added, a hook that throws
keeps the message and its exception comes out of `poll()`, and a library
without the networking component answers `start_network` with
`SIPRAL_STATUS_NOT_SUPPORTED`. The lab program is compiled there too, and run
by the lab.
