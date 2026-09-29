// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What the pump needs from a call, and the facade's session as one.

use core::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{SessionShare, SessionUnavailable};

/// The engine's name for one call: whatever the layer above uses, carried
/// through unread.
pub type CallId = u64;

/// How a datagram the pump captured leaves the media socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// A datagram from the socket.
    Udp,
    /// Bytes written, in order, on the socket's TCP connection to its TURN
    /// server.
    Tcp,
    /// The same, on its TLS connection.
    Tls,
}

/// One packet the pump produced from a microphone frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    /// Where it goes.
    pub destination: SocketAddr,
    /// The octets.
    pub payload: Vec<u8>,
    /// How it leaves.
    pub transport: Transport,
}

/// Why a call could not take a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallGone {
    /// The call's media has ended; the pump lets go of it.
    Ended,
}

impl fmt::Display for CallGone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the call's media has ended")
    }
}

/// One call's audio, as the pump drives it: a frame in from the microphone,
/// a frame out to the loudspeaker, at the call's own rate.
///
/// Every method is called from the pump's thread, once per frame, with
/// nothing else held. The facade's [`SessionShare`] is one; a test's fake is
/// another.
pub trait CallAudio: Send {
    /// The rate the call hears at, which is the codec's and not the RTP
    /// clock's.
    ///
    /// # Errors
    /// [`CallGone::Ended`] once the call's media is over.
    fn sample_rate(&self) -> Result<u32, CallGone>;
    /// Samples in one frame at that rate.
    ///
    /// # Errors
    /// [`CallGone::Ended`] once the call's media is over.
    fn frame_samples(&self) -> Result<usize, CallGone>;
    /// Encode one microphone frame; the packet to send, when one is due.
    ///
    /// # Errors
    /// [`CallGone::Ended`] once the call's media is over.
    fn capture(&mut self, frame: &[i16], now: Instant) -> Result<Option<Outgoing>, CallGone>;
    /// Fill one frame for the loudspeaker: what the far end sent, concealed
    /// or silent when it sent nothing.
    ///
    /// # Errors
    /// [`CallGone::Ended`] once the call's media is over.
    fn playback(&mut self, out: &mut [i16]) -> Result<(), CallGone>;
    /// The loudspeaker-to-microphone delay of the devices the call is on,
    /// told once when the call is attached and again whenever a device
    /// changes under it: the reference a canceller attached to the call
    /// looks back by. A call with nothing to do with it does nothing.
    fn set_render_delay(&mut self, _delay: Duration) {}
}

impl CallAudio for SessionShare {
    fn sample_rate(&self) -> Result<u32, CallGone> {
        self.with(|session| session.sample_rate()).map_err(gone)
    }

    fn frame_samples(&self) -> Result<usize, CallGone> {
        self.with(|session| session.frame_samples()).map_err(gone)
    }

    fn capture(&mut self, frame: &[i16], now: Instant) -> Result<Option<Outgoing>, CallGone> {
        let captured = self
            .with(|session| {
                session
                    .capture(frame, now)
                    .ok()
                    .flatten()
                    .map(|datagram| Outgoing {
                        destination: datagram.destination,
                        payload: datagram.payload.to_vec(),
                        transport: transport_of(&datagram),
                    })
            })
            .map_err(gone)?;
        Ok(captured)
    }

    fn playback(&mut self, out: &mut [i16]) -> Result<(), CallGone> {
        self.with(|session| {
            session.playback(out);
        })
        .map_err(gone)
    }

    fn set_render_delay(&mut self, delay: Duration) {
        // a delay past what the session keeps history for is refused by it,
        // and a session with no processor keeps the number for the one
        // attached later; neither is anything the pump can act on
        let _ = self.with(|session| session.set_render_delay(delay));
    }
}

fn gone(_: SessionUnavailable) -> CallGone {
    // `Reentered` cannot happen from the pump's own thread, which is inside
    // no session of its own; and a session that is gone is gone
    CallGone::Ended
}

#[cfg(feature = "ice")]
fn transport_of(datagram: &sipral::Datagram<'_>) -> Transport {
    match datagram.transport {
        sipral::TurnTransport::Udp => Transport::Udp,
        sipral::TurnTransport::Tcp => Transport::Tcp,
        sipral::TurnTransport::Tls => Transport::Tls,
    }
}

#[cfg(not(feature = "ice"))]
fn transport_of(_: &sipral::Datagram<'_>) -> Transport {
    Transport::Udp
}
