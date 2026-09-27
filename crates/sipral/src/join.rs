// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A local conference of two calls and this end.
//!
//! `sipral-media::mix` has always had the arithmetic for this — summing two
//! sources into one, clamped rather than wrapped — and until now nothing in
//! the tree called it against two live calls.
//! [`MediaEngine::join`](crate::MediaEngine::join) is the part that decides
//! which two calls are in a pair, kept in the engine's own bookkeeping and
//! nowhere near a session; [`mix_two`] is the part that decides what one
//! frame of it sounds like, kept here and touching nothing but the two
//! sessions it is handed. [`MediaEngine::mix`](crate::MediaEngine::mix) is
//! the two joined together: it finds the pair `join` recorded, locks both
//! sessions, and calls [`mix_two`] on them.
//!
//! The split matters past this crate's own boundary. `sipral-ffi`'s media
//! handles reach a session without ever taking the engine's lock — each has
//! its own, so the thread that carries one call's audio is never held up by
//! another call being busy — and a mixed pair needs exactly the same thing
//! for two sessions at once, which is what [`mix_two`] gives it: a function
//! that asks nothing of the engine, so `sipral_media_mix` can call it having
//! locked two media handles' sessions and touched no stack at all.
//!
//! # What "joined" means here
//!
//! Nothing like a SIP conference server. No third dialog is created, no
//! `Refer-To` is sent, and neither far end is ever told about the other by
//! name — from either one's own signalling, this still looks like an
//! ordinary two-party call. What changes is only what this end puts on the
//! wire and what it decodes off it:
//! [`MediaEngine::mix`](crate::MediaEngine::mix), called once a frame for
//! the pair, decodes both far ends, mixes what each of the three parties —
//! the two far ends and this end's own microphone — is owed, and sends the
//! two frames that leaves owed.
//!
//! # Why the two calls have to match
//!
//! [`MediaEngine::join`](crate::MediaEngine::join) refuses a pair whose
//! sessions do not share a sample rate and a frame length. Nothing here
//! resamples: the samples [`mix_two`]
//! decodes out of one session line up, index for index, with the ones it
//! decodes out of the other only when the two codecs cut a frame the same
//! way, and a mismatch would either mix at the wrong pitch or read past the
//! shorter buffer's own idea of a frame. Checking once, when the pair is
//! made, is what every other fact a call cannot change mid-stream is checked
//! against in this crate — a re-negotiation that would move the rate under
//! a running recording is refused the same way, in `MediaSession::adopt`.
//!
//! # Levels
//!
//! Every sum [`mix_two`] forms is two sources at half scale apiece, the same
//! reasoning this crate's own call recorder already carries for the same
//! problem: two full-scale sources summed at unity is a sum that does not
//! fit in the sixteen bits a sample has, and a mixer that let it clip could
//! never undo the clip afterwards. Halved first, the loudest two sources can
//! ever sum to is full scale, never past it — at the cost of six decibels
//! nobody notices on a phone call, and no state that has to be carried
//! between one frame and the next to get there.
//!
//! # Recording
//!
//! [`mix_two`] sends each far end `mic` mixed with the *other* far end's
//! decoded frame, through [`MediaSession::capture`] — the same call that
//! feeds a running recording's captured half. So a call recorded while it is
//! joined keeps a recording of the conference it was actually in, three
//! parties and all, rather than of the two legs it would have carried alone.

use std::net::SocketAddr;
use std::time::Instant;

use sipral_media::mix::{Gain, sum_scaled_into};

use crate::error::MediaError;
use crate::session::MediaSession;

/// What one frame of a joined pair produced for each far end.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MixOutcome {
    /// What is now owed to the far end of the session passed first to
    /// [`mix_two`] — `call` on [`MediaEngine::mix`](crate::MediaEngine::mix).
    /// `None` for a frame deliberately not sent: the same three reasons
    /// [`MediaSession::capture`] itself ever answers `None` for — this end
    /// holding that far end, silence suppression, or a stream still waiting
    /// on its keys.
    pub to_a: Option<(SocketAddr, Vec<u8>)>,
    /// The same, for the far end of the session passed second.
    pub to_b: Option<(SocketAddr, Vec<u8>)>,
    /// How `to_a` leaves, as [`Datagram::transport`](crate::Datagram::transport)
    /// says: a datagram, or bytes for the relay's connection to its TURN
    /// server.
    #[cfg(feature = "ice")]
    pub via_a: crate::TurnTransport,
    /// The same, for `to_b`.
    #[cfg(feature = "ice")]
    pub via_b: crate::TurnTransport,
}

/// One frame of a local conference of two calls and this end.
///
/// `a` and `b` are the two calls' sessions, in either order —
/// [`MediaEngine::join`](crate::MediaEngine::join) does not distinguish
/// which is which, and neither does this. `mic` is this end's own frame;
/// `local_out` is filled with what this end's own loudspeaker is owed. Both
/// sessions are decoded exactly once, here, the way a solo call's own
/// [`MediaSession::playback`] always is — voice activity, concealment, the
/// recorder's `played` half, all run exactly as they always do for either
/// call alone — and what changes is only what goes out: each far end is
/// sent `mic` mixed with the *other* far end's frame, through
/// [`MediaSession::capture`], rather than `mic` alone.
///
/// Buffers shorter than a session's own [`MediaSession::frame_samples`] are
/// read as silence past their end and buffers longer are read only that
/// far, the same rule [`sipral_media::mix::sum_scaled_into`] always keeps: a
/// caller that gets `mic` or `local_out` the wrong length loses samples
/// rather than panics.
///
/// # Errors
/// Whatever [`MediaSession::capture`] refuses on either leg — a codec that
/// will not cut the mixed frame it was given, chiefly, which for a frame
/// built here means exactly what it would for a solo call's own microphone.
pub fn mix_two(
    a: &mut MediaSession,
    b: &mut MediaSession,
    mic: &[i16],
    local_out: &mut [i16],
    now: Instant,
) -> Result<MixOutcome, MediaError> {
    let half = Gain::ratio(1, 2);

    let mut from_a = vec![0_i16; a.frame_samples()];
    let mut from_b = vec![0_i16; b.frame_samples()];
    a.playback(&mut from_a);
    b.playback(&mut from_b);

    sum_scaled_into(local_out, &[&from_a, &from_b], &[half, half]);

    let mut to_a = vec![0_i16; a.frame_samples()];
    sum_scaled_into(&mut to_a, &[mic, &from_b], &[half, half]);
    #[cfg(feature = "ice")]
    let mut via_a = crate::TurnTransport::Udp;
    let sent_a = a.capture(&to_a, now)?.map(|datagram| {
        #[cfg(feature = "ice")]
        {
            via_a = datagram.transport;
        }
        (datagram.destination, datagram.payload.to_vec())
    });

    let mut to_b = vec![0_i16; b.frame_samples()];
    sum_scaled_into(&mut to_b, &[mic, &from_a], &[half, half]);
    #[cfg(feature = "ice")]
    let mut via_b = crate::TurnTransport::Udp;
    let sent_b = b.capture(&to_b, now)?.map(|datagram| {
        #[cfg(feature = "ice")]
        {
            via_b = datagram.transport;
        }
        (datagram.destination, datagram.payload.to_vec())
    });

    Ok(MixOutcome {
        to_a: sent_a,
        to_b: sent_b,
        #[cfg(feature = "ice")]
        via_a,
        #[cfg(feature = "ice")]
        via_b,
    })
}
