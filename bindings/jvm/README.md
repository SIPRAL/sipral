<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Sipral for a server JVM

One jar, `sipral-jvm-<version>.jar`, for a JVM on Linux: the Kotlin binding
in `bindings/kotlin` compiled for a plain JVM (Java 17 bytecode, Kotlin 2.2
metadata), with `libsipral_ffi.so` and `libsipral_jni.so` for linux-x64 and
linux-arm64 inside it. Its dependencies are `kotlin-stdlib` and
`kotlinx-coroutines-core-jvm`, which the POM names.

```sh
scripts/package/jvm.sh --out /tmp/sipral-jvm            # both platforms, via Docker
scripts/package/jvm.sh --out /tmp/sipral-jvm --dry-run  # the host's own pair only
```

`scripts/package/jvm.sh` says what each mode builds and checks. The Maven
project here builds nothing native itself: it takes the pairs staged under
`-Dsipral.natives=DIR` as `org/sipral/jvm/native/<platform>/`.

## Where the classes come from

The Maven build copies `bindings/kotlin/sipral/src/main/kotlin` into
`target/generated-sources` unchanged but for one line: each
`System.loadLibrary("sipral_jni")` becomes `org.sipral.jvm.SipralNatives.load()`.
`System.loadLibrary` searches only `java.library.path`, which a jar cannot add
to. The build fails if a `System.loadLibrary(` is left over, or if it found
none to replace.

## Loading

`SipralNatives.load()` runs as the first class with native methods is
initialised, so an application never has to call it. It picks
`linux-x64` or `linux-arm64` from `os.name` and `os.arch`, checks that both
libraries' ELF headers name that machine, writes them to a directory only the
JVM's user can read, loads them by absolute path (the shim finds the ABI
beside itself through its `$ORIGIN` run path) and deletes the files again.
Anywhere else it throws `UnsatisfiedLinkError` naming the platform; on a
glibc older than 2.28 the `UnsatisfiedLinkError` is the dynamic linker's. `-Dsipral.native.dir=DIR` loads
the pair from `DIR` instead, for a library built locally. Calling
`SipralNatives.load()` at start-up makes a server fail at once rather than at
its first call. From Java 24 the JVM warns when a jar on the class path calls
`System.load`, and says a later release will refuse it; start the server with
`--enable-native-access=ALL-UNNAMED` (or the name of the module the jar is
on), as `scripts/check.sh` runs these tests.

## From Java

`org.sipral.idiomatic` is plain classes, and most of it Java calls as it is:
`hangup`, `hold`, `resume`, `close`, `getState`, `getMedia`, `statistics`.
`org.sipral.jvm.SipralJava` covers what Java cannot reach directly: factories
whose optional arguments are Kotlin defaults, `suspend` waits (blocking, or a
`CompletableFuture`), and event flows (a `Consumer` until closed).

```java
try (SipralClient client = SipralJava.open("192.0.2.10")) {
    SipralAccount account = SipralJava.addAccount(client, "sip:agent@example.com", "203.0.113.5:5060",
        "sip:example.com", "agent", secret);
    SipralJava.registerAndWait(account, 10_000);
    SipralCall call = SipralJava.placeCall(client, account, "sip:bob@example.com", "192.0.2.10");
    SipralJava.waitConfirmed(call, 30_000);
    try (AutoCloseable digits = SipralJava.subscribe(call.getDigits(),
            event -> System.out.println(SipralJava.digitOf(event)))) {
        SipralJava.sendDtmf(call, "123#");
        call.hangup();
        SipralJava.waitEnded(call, 30_000);
    }
}
```

A client opened here runs in application mode: a server has no sound card,
and `SipralMedia` carries each call's PCM. `SipralJava.addAccount` takes a
`SipralTransport.TCP` or `TLS` (and a certificate pin) after the
credentials, for an account on a connection of its own beside the client's
UDP socket; `client.settings()` is a plain method.
`SipralJava.open(host, port, userAgent, maxDialogs, maxServerTransactions)`
raises the ceilings a server meets first: 128 calls at once, past which a
call that arrives is answered 503 with `Retry-After: 2`, and 256 requests
from other ends worked on at once; a server holding `N` calls gives the
second three a call and 256 more (`docs/08-ffi.md`, "Limits, and what went
out twice").


## Tests

- `SipralNativesTest`: the platform each `os.name` and `os.arch` gets, the
  ELF check, that each staged pair is for its own machine, and that the
  running JVM loads its own pair once.
- `LoopbackCallKotlinIT` and `LoopbackCallJavaIT`: two stacks on loopback in
  one JVM, one calling the other, RTP both ways, three digits, a hang-up;
  and, from Java, an account on a TCP connection of its own registering;
  run by failsafe against the packaged jar under `-Xcheck:jni`.
  `jvm.sh` without `--dry-run` runs all three again on an arm64 JVM under
  qemu.

## Publishing

Nothing here publishes. The POM carries what Maven Central asks for (name,
description, URL, licences, developer, SCM, a sources jar) but no
`distributionManagement`, no signing and no javadoc jar. The group id is
`org.sipral`, the property `sipral.groupId`, which the AAR's POM reads too
(`-Dsipral.groupId=...`, or `SIPRAL_GROUP_ID` for `jvm.sh`, names another
for one build); the artefact is `org.sipral:sipral-jvm`. Maven warns that
a group id is an expression, and the POM `jvm.sh` writes beside the jar is
the flattened one, with the group id and version written out.
