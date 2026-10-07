<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
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
| `c/include/sipral.h` | The C header, and the interface the others are written against |
| `swift/Sources/Sipral/SipralAbi.swift` | The Swift binding, over the C target |
| `dotnet/Sipral/SipralAbi.cs` | The .NET binding: P/Invoke and the layer above it |
| `kotlin/sipral/src/main/kotlin/org/sipral/SipralAbi.kt` | The Kotlin binding |
| `kotlin/sipral/src/main/jni/sipral_jni.c` | The JNI that implements it |
| `python/sipral/_sipral_cffi.py` | The raw `cffi` ABI-mode surface: `ffi` and `lib` |
| `dart/lib/src/sipral_abi.dart` | The raw `dart:ffi` surface |
| `node/src/sipral_abi.ts` | The raw koffi surface for Node.js, with TypeScript types |
| `c/abi-sizes.txt` | Each sized struct's pinned member, and on each of the three layouts the length it pins and the length the struct is now |
| `c/abi-layout.c` | Every length, offset and pin on the three layouts, as assertions a C compiler checks against the header for six targets |

Everything else under `bindings/` is written by hand: `Package.swift`,
`c/sipral.c` and `c/smoke.c`; every other source file of each package — the
idiomatic layer each language's application uses, written against its
printed file (`swift/Sources/Sipral/`, `dotnet/Sipral/`,
`kotlin/sipral/src/main/kotlin/org/sipral/{idiomatic,telecom}/` with the JNI
shims `idiomatic_media.c` and `audio_routes.c`, `python/sipral/`,
`dart/lib/src/`, `node/src/`), with its tests, samples and examples; `kotlin/android/`
(the AAR's Gradle build, the telecom helper and the Compose sample); `jvm/`
(the Maven build of the Kotlin binding for a server JVM, with its Java face);
`fixtures/` (the STIR certificate chain the bindings' tests share); `react-native/`
(the React Native package, over the Swift and Kotlin layers rather than the
ABI); and the readmes. Everything the packages build from declarations rather
than write themselves is generated.

| Binding | Readme | Where it runs | Audio |
|---|---|---|---|
| C | `c/include/sipral.h` | anywhere the library builds | device or application mode |
| Swift | [`swift/README.md`](swift/README.md) | macOS, iOS | device or application mode; CallKit and PushKit helpers |
| Kotlin and Java | [`kotlin/README.md`](kotlin/README.md), [`jvm/README.md`](jvm/README.md) | Android (AAR), a JVM (jar for linux-x64 and linux-arm64) | device mode on Android from API level 28, application mode anywhere; a `ConnectionService` helper |
| .NET | [`dotnet/README.md`](dotnet/README.md) | Windows, macOS, Linux | device or application mode |
| Python | [`python/README.md`](python/README.md) | macOS, Windows, Linux | device or application mode |
| Dart and Flutter | [`dart/README.md`](dart/README.md) | wherever `dart:ffi` loads the library | application mode, signalling over UDP with an account's own TCP or TLS connection beside it |
| Node.js and TypeScript | [`node/README.md`](node/README.md) | wherever Node.js 20 or later and koffi load the library | application mode, signalling over UDP |
| React Native | [`react-native/README.md`](react-native/README.md) | iOS, Android | device mode, over the Swift and Kotlin layers |

Device mode is wherever the library has an audio backend: CoreAudio on macOS
and iOS, WASAPI on Windows, AAudio on Android.

`c/sipral.c` is the Swift package's one translation unit, and exists so that
a header that will not compile is found by building the package. `c/smoke.c`
is a program: it links the built library and exercises the ABI the way an
integrator would, and `scripts/check.sh` compiles and runs it.

What each binding covers, and what it does not, is in `docs/08-ffi.md`.
