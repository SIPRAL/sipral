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
- **Errors are integer codes** plus a thread-local last-error string. No
  errno-style globals shared between handles.
- **Events arrive on one callback**, registered per stack handle, carrying a
  tagged union. The callback may be invoked from the caller's own polling
  thread only, so the language side never has to reason about which thread it
  is on.
- **Nothing is added to a released ABI except at the end of a struct**, guarded
  by the `size` field, or as a new function. Nothing is removed or reordered.
  Ever.

The header is generated from the Rust source in the build, so it cannot drift.

## Swift

A Swift Package wrapping the C target. `async`/`await` over the event callback,
`Sendable` types, errors as a Swift `Error`, and no exposed pointers.

The platform work is what the binding actually earns its place for: `CallKit`
for call UI and audio session priority, `PushKit` for waking on an incoming call,
and `AVAudioSession` category and interruption handling. An iOS softphone that
gets these wrong does not work, regardless of how good the stack is.

## .NET

A NuGet package with native assets for `osx-arm64`, `osx-x64`, `win-x64`,
`win-arm64` and `linux-x64`. `Task`-based API, `IAsyncEnumerable` for event
streams, `IDisposable` mapped to the handle free functions, and a `SafeHandle`
so a missed `Dispose` leaks rather than crashes.

## Kotlin

An AAR over JNI, coroutines and `Flow` for events. `ConnectionService` for
integration with the system dialer, and a foreground service for the call
lifetime, because Android will otherwise stop the process mid-call.

## Versioning

The C ABI carries its own version, independent of the crate version. It is
reported by a function, checked by every binding at load, and a mismatch is a
hard failure with a legible message rather than a crash later.
