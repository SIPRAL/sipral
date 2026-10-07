// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A local conference of two calls and this end.
//!
//! [`MediaEngine::join`](crate::MediaEngine::join) records which two calls form a pair, in the
//! engine's bookkeeping; [`mix_two`] computes one frame, touching only the two sessions it is
//! given; [`MediaEngine::mix`](crate::MediaEngine::mix) finds the pair, locks both sessions and
//! calls [`mix_two`]. The arithmetic is `sipral-media::mix` (clamped sums).
//!
//! The split matters for `sipral-ffi`: its media handles reach sessions without the engine lock, so
//! `sipral_media_mix` can lock two handles' sessions and call [`mix_two`] without touching the
//! stack.
//!
//! # What "joined" means
//!
//! Not a conference server. No third dialog, no `Refer-To`, and neither far end is told about the
//! other; each still sees an ordinary two-party call. Only the media changes: once per frame,
//! [`MediaEngine::mix`](crate::MediaEngine::mix) decodes both far ends, mixes what each of the
//! three parties should hear, and sends the two far-end frames.
//!
//! # Why the calls must match
//!
//! [`MediaEngine::join`](crate::MediaEngine::join) refuses sessions with different sample rates or
//! frame lengths. Nothing resamples, so samples only line up when both codecs cut frames alike;
//! otherwise the mix would be at the wrong pitch or read past a frame. It is checked once at join
//! time, as `MediaSession::adopt` refuses a rate change under a running recording.
//!
//! # Levels
//!
//! Each sum is two sources at half scale, as in the call recorder: full-scale sources summed at
//! unity would clip irreversibly. Halving keeps the maximum at full scale for 6 dB nobody notices
//! on a phone, with no state between frames.
//!
//! # Recording
//!
//! Each far end is sent `mic` mixed with the other far end through [`MediaSession::capture`], which
//! also feeds a running recording, so a joined call's recording holds the whole three-party
//! conference.

use std::net::SocketAddr;
use std::time::Instant;

use sipral_media::mix::{Gain, sum_scaled_into};

use crate::error::MediaError;
use crate::session::MediaSession;

/// What one frame of a joined pair produced for each far end.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MixOutcome {
    /// What is owed to the far end of the first session passed to [`mix_two`] (`call` on
    /// [`MediaEngine::mix`](crate::MediaEngine::mix)). `None` for a frame deliberately not sent,
    /// for the same reasons [`MediaSession::capture`] returns `None`: holding that far end, silence
    /// suppression, or keys not ready.
    pub to_a: Option<(SocketAddr, Vec<u8>)>,
    /// The same, for the far end of the session passed second.
    pub to_b: Option<(SocketAddr, Vec<u8>)>,
    /// How `to_a` leaves, as in [`Datagram::transport`](crate::Datagram::transport): a datagram, or
    /// bytes on the relay's TURN connection.
    #[cfg(feature = "ice")]
    pub via_a: crate::TurnTransport,
    /// The same, for `to_b`.
    #[cfg(feature = "ice")]
    pub via_b: crate::TurnTransport,
}

/// One frame of a local conference of two calls and this end.
///
/// `a` and `b` are the two sessions in either order. `mic` is this end's frame; `local_out`
/// receives what this end's loudspeaker should play. Each session is decoded once, as
/// [`MediaSession::playback`] does for a solo call (voice activity, concealment, the recorder's
/// `played` half all run as usual); only the output changes: each far end gets `mic` mixed with the
/// other far end, through [`MediaSession::capture`].
///
/// Buffers shorter than a session's [`MediaSession::frame_samples`] read as silence past their end,
/// and longer ones are read only that far, as [`sipral_media::mix::sum_scaled_into`] does: a wrong
/// length loses samples instead of panicking.
///
/// # Errors
///
/// Whatever [`MediaSession::capture`] refuses on either leg, mainly a codec refusing the frame,
/// exactly as for a solo call.
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
