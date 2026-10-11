# sipral

Session Initiation Protocol Rust Audio Layer.

A SIP + RTP client stack written in Rust, with Swift, .NET, Kotlin and Python bindings. This crate is the facade: it joins the signalling half of the stack to the media half, so an application depends on one crate and gets a softphone rather than a set of parts to wire together. It writes the offer from the codecs the build contains, reads the answer, and gives a call that is answered an RTP session, a codec, packet loss concealment, recording and stream statistics.

It opens no socket and no audio device, and it reads no clock. The application owns all three, which is what lets the same stack run under Tokio, Swift structured concurrency, a .NET task or a bare event loop.

From 1.2.0 this crate's API is promised like the C ABI's: a program that builds against `sipral` 1.k builds against every later 1.x. The whole user agent is `sipral::ua`, the session descriptions `sipral::sdp`, and STIR/SHAKEN `sipral::stir`; the other `sipral-*` crates on crates.io are its parts and promise nothing of their own. Dual-licensed AGPL-3.0 / commercial.

https://sipral.org
