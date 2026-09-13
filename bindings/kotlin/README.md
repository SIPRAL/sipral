<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# The Kotlin binding

Two printed files that have to agree with each other as well as with the ABI:

- `sipral/src/main/kotlin/org/sipral/SipralAbi.kt` — one `external fun` per
  entry point in `SipralNative`, the enumerations, the constants, the
  exception, a class for each struct a caller builds and for each record
  handed over in a list, the listener the event callback reaches, and the layer
  above them where a status becomes a throw.
- `sipral/src/main/jni/sipral_jni.c` — the C that implements them: the casts
  and the array handling, each struct built out of the fields its class crossed
  as, each list made into the C array it stands for, and the function the event
  callback lands in. It is printed from the same walk over the same
  declarations, which is the only reason it is safe for the two to be separate
  files.

Build the shim against `sipral.h` from `bindings/c/include` and link it to the
shared library, `libsipral_ffi.dylib` or `libsipral_ffi.so`, which is what a
JVM can load; the Kotlin side loads it as `sipral_jni` and checks the ABI
version as it does.

```kotlin
val stack = Sipral.stackCreate(
    SipralStackConfig(
        eventListener = SipralEventListener { event -> println(event.kind) },
        transport = SipralTransport.UDP.value.toLong(),
        bindAddress = "192.0.2.10:5060",
        entropy = entropy,      // 32 bytes from SecureRandom
        mediaSeed = mediaSeed,  // 32 more, a second draw
    ),
)
Sipral.stackPoll(stack, nowMs)  // the listener is called from in here
```

`sipral/src/test` is what `scripts/check.sh` runs: `BindingCheck.kt`, and a
small C helper that polls from a thread no JVM made, so that the half of the
shim that attaches a thread is run too, and reads back what a stack sends, so
that header fields handed over in a list can be found in the message they went
out in. The gate links both against the shared library and runs them on a JVM
under `-Xcheck:jni`.

The Gradle and AAR packaging is not in the tree yet. `docs/08-ffi.md` says what
else the binding does not carry: the event payload union, and the two structs a
caller part-fills with buffers, which still cross as addresses.
