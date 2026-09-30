<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# The bindings

Only the files in the table below are printed. Everything else here is written
by hand. The header and every binding are printed from the declarations in
`crates/sipral-ffi` by
`tools/abi-gen`, and `scripts/check.sh` prints them again and fails if what is
committed is not what came out. A function added on the Rust side and missing
from a binding is therefore a failed check rather than a crash on one platform.

```sh
cargo run -p sipral-abi-gen           # write them
cargo run -p sipral-abi-gen -- --check # say whether they are current
```

| Printed file | What it is |
|---|---|
| `c/include/sipral.h` | The C header, and the interface the other four are written against |
| `swift/Sources/Sipral/SipralAbi.swift` | The Swift binding, over the C target |
| `dotnet/Sipral/SipralAbi.cs` | The .NET binding: P/Invoke and the layer above it |
| `kotlin/sipral/src/main/kotlin/org/sipral/SipralAbi.kt` | The Kotlin binding |
| `kotlin/sipral/src/main/jni/sipral_jni.c` | The JNI that implements it |
| `python/sipral/_sipral_cffi.py` | The raw `cffi` ABI-mode surface: `ffi` and `lib` |
| `dart/lib/src/sipral_abi.dart` | The raw `dart:ffi` surface |
| `c/abi-sizes.txt` | Each sized struct's pinned member, and on each of the three layouts the length it pins and the length the struct is now |
| `c/abi-layout.c` | Every length, offset and pin on the three layouts, as assertions a C compiler checks against the header for six targets |

Written by hand: `Package.swift`, `c/sipral.c`, `c/smoke.c`,
`dotnet/Sipral/Sipral.csproj`, `dotnet/Sipral/SipralInfo.cs` and the rest of
`dotnet/Sipral/*.cs` other than `SipralAbi.cs`, `dotnet/Sipral.Tests/`,
`dotnet/samples/`,
`kotlin/sipral/src/main/kotlin/org/sipral/{idiomatic,telecom}/`,
`kotlin/sipral/src/main/jni/idiomatic_media.c`, `kotlin/sipral/src/test/`,
`kotlin/android/`, `kotlin/examples/`,
`python/pyproject.toml`, `python/sipral/{stack,account,call,media,events,enums,errors}.py`
(the idiomatic layer `_sipral_cffi.py` is written against), `python/tests/`,
`python/examples/agent.py`,
`swift/Sources/Sipral/{SipralStack,Account,Call,Media,SipralEvent,Broadcast,UDPSocket,CStrings,CallKitBridge,PushKitBridge,CallKitAdapter,PushKitAdapter}.swift`
(the idiomatic layer `SipralAbi.swift` is written against, the same way
the Python files above are written against `_sipral_cffi.py`),
`swift/Tests/SipralTests/`, `swift/Sources/SipralLabAgent/`,
`swift/Sources/SipralSampleMac/`, and the readmes. Everything the packages
build from declarations rather than write themselves is generated.

`c/sipral.c` is the Swift package's one translation unit, and exists so that
a header that will not compile is found by building the package. `c/smoke.c`
is a program: it links the built library and exercises the ABI the way an
integrator would, and `scripts/check.sh` compiles and runs it.

What each binding covers, and what it does not, is in `docs/08-ffi.md`.
