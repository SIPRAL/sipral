<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# The bindings

Nothing in here is written by hand except the packaging. The header and every
binding are printed from the declarations in `crates/sipral-ffi` by
`tools/abi-gen`, and `scripts/check.sh` prints them again and fails if what is
committed is not what came out. A function added on the Rust side and missing
from a binding is therefore a failed check rather than a crash on one platform.

```sh
cargo run -p sipral-abi-gen           # write them
cargo run -p sipral-abi-gen -- --check # say whether they are current
```

| Printed file | What it is |
|---|---|
| `c/include/sipral.h` | The C header, and the interface the other three are written against |
| `swift/Sources/Sipral/SipralAbi.swift` | The Swift binding, over the C target |
| `dotnet/Sipral/SipralAbi.cs` | The .NET binding: P/Invoke and the layer above it |
| `kotlin/sipral/src/main/kotlin/org/sipral/SipralAbi.kt` | The Kotlin binding |
| `kotlin/sipral/src/main/jni/sipral_jni.c` | The JNI that implements it |

Written by hand: `Package.swift`, `c/sipral.c`, `c/smoke.c`,
`dotnet/Sipral/Sipral.csproj`, `dotnet/Sipral/SipralInfo.cs`, and the two
readmes. Everything the packages build is generated.

`c/sipral.c` is the Swift package's one translation unit, and exists so that
a header that will not compile is found by building the package. `c/smoke.c`
is a program: it links the built library and exercises the ABI the way an
integrator would, and `scripts/check.sh` compiles and runs it.

What each binding covers, and what it does not, is in `docs/08-ffi.md`.
