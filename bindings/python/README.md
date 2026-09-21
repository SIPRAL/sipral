<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# The Python binding

Two layers, the way every binding here is two layers:

- `sipral/_sipral_cffi.py` — printed by `tools/abi-gen`'s Python back end
  from `sipral_ffi::abi::SURFACE`, the same declarations the header and the
  Swift, .NET and Kotlin bindings are printed from. `ffi` and `lib`: a
  `cffi` ABI-mode `cdef` naming the same types, constants and entry points
  `bindings/c/include/sipral.h` does, and the `dlopen` that turns it into
  `lib`. ABI mode needs no C compiler at install time — cffi lays every
  struct out for itself from the `cdef` text, so the `cdef` has to be
  exact; `tests/test_abi.py` checks it against `bindings/c/abi-sizes.txt`
  and against the header's own numbers.
- `sipral/stack.py`, `sipral/account.py`, `sipral/call.py`,
  `sipral/media.py`, `sipral/events.py`, `sipral/enums.py`, `sipral/errors.py`
  — written by hand against `ffi`/`lib` directly, the way `SipralAbi.swift`
  is the base the Swift package is written against. `Stack`, `Account` and
  `Call` are what an application reaches for.

## Install

```sh
cd bindings/python
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

`cffi` is the only dependency. The native library is found through
`SIPRAL_LIBRARY` (a path to the file itself, or to the directory holding
it), then beside this package, then the repository's own `target/release`
and `target/debug` — build it first with `cargo build --release -p
sipral-ffi`, or point `SIPRAL_LIBRARY` at a checkout's `target/debug`
while developing against one.

## Use

```python
import asyncio
from sipral import Stack

async def main():
    loop = asyncio.get_running_loop()
    with Stack(loop=loop) as stack:
        account = stack.add_account(
            "sip:alice@example.invalid",
            registrar_address="203.0.113.10:5060",
        )
        account.register()

        call = stack.place_call(account, "sip:bob@example.invalid")
        while call.media is None:
            event = await call.events.get()
            print(event.kind_name)

        call.media.send_audio(pcm_bytes)      # 16-bit mono, one call at a time
        frame = await call.media.frames.get()  # the far end's own audio back

asyncio.run(main())
```

An incoming call has no `Call` until the application decides what to do
with it: read `SIPRAL_EVENT_KIND_INCOMING_CALL` off `stack.events` and
call `stack.answer_call(event)` or `stack.reject_call(event)`. `call.dtmf`
is an `asyncio.Queue` of the digits the far end sent; `call.media.statistics()`
is `sipral_media_statistics`, as a `dict`. See `examples/agent.py` for a
complete voice agent that answers, talks and hears DTMF.

Every idiomatic method raises `sipral.SipralError` on anything but
`SIPRAL_STATUS_OK`, except an ordinary `SIPRAL_STATUS_BUSY` from another
thread racing the stack's own poll loop, which is retried for up to half a
second before it is raised as anything else
(`docs/08-ffi.md`, "Signalling on one stack is one thread at a time").

## Test

```sh
python3 -m unittest discover -s tests
```

Standard library `unittest` only, no `pytest`. `tests/test_abi.py` needs
`bindings/c/include/sipral.h` and `bindings/c/abi-sizes.txt` from this
checkout; `tests/test_call.py` runs two stacks against each other on
`127.0.0.1`, with no registrar and no network beyond loopback.

## What is not here

Wheels with the native library bundled in (a later task); `numpy` support
for `call.media` (accepted wherever `bytes`/`memoryview` is, but never
required — `array.array('h', ...)` or a `numpy` array's `.tobytes()` work
today); a DNS resolver for `SIPRAL_EVENT_KIND_RESOLVE_NEEDED` beyond
treating the host as a literal address, which is what two stacks with no
registrar between them, or a target already given as `host:port`, need
and nothing more (see `Stack._resolve`).
