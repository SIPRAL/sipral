# sipral

Session Initiation Protocol Rust Audio Layer.

A SIP + RTP client stack written in Rust, with Swift, .NET and Kotlin bindings. This crate is the facade: it joins the signalling half of the stack to the media half, so an application depends on one crate and gets a softphone rather than a set of parts to wire together. It writes the offer from the codecs the build contains, reads the answer, and gives a call that is answered an RTP session, a codec, packet loss concealment, recording and stream statistics.

It opens no socket and no audio device, and it reads no clock. The application owns all three, which is what lets the same stack run under Tokio, Swift structured concurrency, a .NET task or a bare event loop.

Pre-release: the C ABI is not frozen and neither is this API. Dual-licensed AGPL-3.0 / commercial.

https://sipral.org
