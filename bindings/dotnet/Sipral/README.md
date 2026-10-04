# Sipral

Session Initiation Protocol Rust Audio Layer.

A SIP client stack in Rust -- signalling, media, encryption and NAT traversal
behind one C ABI -- and this package is its .NET binding: `SipralStack`,
`Account`, `Call` and `CallMedia` over the native library, which the package
carries for win-x64, osx-arm64, osx-x64, linux-x64 and linux-arm64.

```sh
dotnet add package Sipral
```

`Sipral` is built without libopus; `Sipral.Opus` is the same binding with it.

The binding's documentation:
https://github.com/SIPRAL/sipral/blob/main/bindings/dotnet/README.md

Licensing: AGPL-3.0-only, or a commercial licence for closed-source and
app-store distribution --
https://github.com/SIPRAL/sipral/blob/main/LICENSING.md

https://sipral.org
