# Sipral for .NET MAUI

Session Initiation Protocol Rust Audio Layer.

A SIP client stack in Rust -- signalling, media, encryption and NAT traversal
behind one C ABI -- and this package is its .NET binding for .NET MAUI on iOS
and Android: the same `SipralStack`, `Account`, `Call` and `CallMedia` as the
`Sipral` package, with the native library for iOS (device and simulator,
linked into the application) and Android (arm64-v8a, armeabi-v7a, x86_64)
inside, plus `SipralMicrophone` for the microphone permission and
`SipralAppLifecycle` for the move to the background and back.

```csharp
builder.UseMauiApp<App>().UseSipral(out var lifecycle);
// later, once there is a stack and an account
lifecycle.Stack = stack;
if (!await lifecycle.RestoreAsync(account, "work")) account.Register();
```

An iOS application's `Info.plist` must carry `NSMicrophoneUsageDescription`.
The package is built without libopus.

The binding's documentation:
https://github.com/SIPRAL/sipral/blob/main/bindings/dotnet/README.md

Licensing: AGPL-3.0-only, or a commercial licence for closed-source and
app-store distribution --
https://github.com/SIPRAL/sipral/blob/main/LICENSING.md

https://sipral.org
