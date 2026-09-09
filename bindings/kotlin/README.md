<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# The Kotlin binding

Two printed files that have to agree with each other as well as with the ABI:

- `sipral/src/main/kotlin/org/sipral/SipralAbi.kt` — one `external fun` per
  entry point in `SipralNative`, the enumerations, the constants, the
  exception, and the layer above them where a status becomes a throw.
- `sipral/src/main/jni/sipral_jni.c` — the C that implements them. It is casts
  and array handling and nothing else, and it is printed from the same walk
  over the same declarations, which is the only reason it is safe for the two
  to be separate files.

Build it against `sipral.h` from `bindings/c/include` and link it to the
`sipral` static library; the Kotlin side loads it as `sipral_jni`.

The Gradle and AAR packaging is not in the tree yet, and neither is the event
callback: a C function that calls back into the JVM has to attach the calling
thread and build a Java object out of the event struct, which is not something
this generator prints today. `docs/08-ffi.md` says what that means for the
gate — the declarations are covered, the ergonomics around them are not yet.
