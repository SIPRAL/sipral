# sipral

Session Initiation Protocol Rust Audio Layer.

A SIP + RTP client stack written in Rust, with Swift, .NET, Kotlin and Python bindings. This crate is the facade: it joins the signalling half of the stack to the media half, so an application depends on one crate and gets a softphone rather than a set of parts to wire together. It writes the offer from the codecs the build contains, reads the answer, and gives a call that is answered an RTP session, a codec, packet loss concealment, recording and stream statistics.

It opens no socket and no audio device, and it reads no clock. The application owns all three, which is what lets the same stack run under Tokio, Swift structured concurrency, a .NET task or a bare event loop.

This Rust API is not part of a Sipral 1.x release and makes no compatibility promise: what 1.x promises is the C ABI and the language packages over it. The `sipral` name on crates.io is a reservation at 0.0.1; no release publishes this crate. Dual-licensed AGPL-3.0 / commercial.

https://sipral.org
