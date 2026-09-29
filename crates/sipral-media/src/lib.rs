// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Audio for a SIP call.
//!
//! What is here is G.711 — the two companding laws every carrier still
//! accepts, in both directions, with the arithmetic a caller needs to cut a
//! frame — the concealment that fills the frames the network loses on the way,
//! and the pipeline that sits between a codec and whatever produces or
//! consumes samples: [`resample`] between the device rate and the codec rate,
//! [`drift`] to keep two clocks that disagree from emptying a buffer over the
//! length of a call, and [`mix`] for a conference leg or a local tone.
//!
#![cfg_attr(
    feature = "opus",
    doc = "[`opus`] is the exception to all of that: the wideband codec worth
defaulting to, linked rather than written, wrapped here so that libopus stops
at this crate's edge. It brings its own concealment and its own forward error
correction, which are better than [`plc`]'s and are used instead of it on an
Opus stream. It is behind the `opus` feature, which is on unless somebody
turned it off — `docs/05-media.md` says who does and why.\n"
)]
#![cfg_attr(
    not(feature = "opus"),
    doc = "Opus is the exception to all of that, and this build does not have
it: the `opus` feature is off, nothing links libopus, and what is here is
G.711 and G.722 with [`plc`] concealing for both. `docs/05-media.md` says who
builds it this way and why.\n"
)]
//!
//! [`vad`] decides whether a frame is speech or a pause, which the jitter
//! buffer's adjustment schedule and [`comfort_noise`]'s silence suppression
//! both need. [`comfort_noise`] is RFC 3389: the payload a carrier expects
//! during a suppressed silence, and the noise generated from it on receive.
//! [`processor`] is the seam echo cancellation, gain control and noise
//! suppression attach at — not implemented in this crate, and the module
//! docs say why.
//!
//! Nothing here opens a device or a socket, and nothing allocates once it has
//! been built. Samples arrive in a slice and leave in one, so the whole crate
//! is testable without either.

#![doc(
    html_logo_url = "https://sipral.org/brand/sipral-mark-256.png",
    html_favicon_url = "https://sipral.org/brand/favicon.svg"
)]
// tests say what they mean; the no-panic discipline is for the library
#![cfg_attr(
    test,
    allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )
)]

pub mod comfort_noise;
pub mod drift;
pub mod formats;
pub mod g711;
pub mod g722;
pub mod g729;
pub mod mix;
#[cfg(feature = "opus")]
pub mod opus;
pub mod plc;
pub mod processor;
pub mod resample;
pub mod vad;

pub use formats::l16;
