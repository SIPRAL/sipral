// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What the pump needs from a call, and the facade's session as one.

use core::cell::RefCell;
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

/// Where the pump hands every packet it produced, on its own thread: send
/// it and return. The packet is lent for the length of the call, so that a
/// call's capture can be copied into one the pump's thread keeps rather
/// than into a new one every frame.
pub type Transmit = Box<dyn FnMut(CallId, &Outgoing) + Send>;

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
    /// Encode one microphone frame and hand every packet it produced to
    /// `send`, each with the call it belongs to. This is what the pump calls.
    ///
    /// A call is one stream, and the default is [`CallAudio::capture`] with
    /// its packet named `own`, the name the pump carries it under. A local
    /// conference carried as one entry is several streams, each of a call
    /// of its own, and names each packet after the call it belongs to.
    ///
    /// # Errors
    /// [`CallGone::Ended`] once the media is over.
    fn capture_each(
        &mut self,
        own: CallId,
        frame: &[i16],
        now: Instant,
        send: &mut dyn FnMut(CallId, &Outgoing),
    ) -> Result<(), CallGone> {
        if let Some(packet) = self.capture(frame, now)? {
            send(own, &packet);
        }
        Ok(())
    }
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

    /// The packet copied out of the session's lock into one the pump's
    /// thread keeps from frame to frame, and handed over by reference: once
    /// it has grown to a packet's size, carrying a call's microphone to the
    /// far end allocates nothing.
    fn capture_each(
        &mut self,
        own: CallId,
        frame: &[i16],
        now: Instant,
        send: &mut dyn FnMut(CallId, &Outgoing),
    ) -> Result<(), CallGone> {
        PACKET.with_borrow_mut(|kept| {
            let captured = self
                .with(|session| {
                    let Some(datagram) = session.capture(frame, now).ok().flatten() else {
                        return false;
                    };
                    let packet = kept.get_or_insert_with(|| Outgoing {
                        destination: datagram.destination,
                        payload: Vec::with_capacity(PACKET_ROOM),
                        transport: Transport::Udp,
                    });
                    packet.destination = datagram.destination;
                    packet.transport = transport_of(&datagram);
                    packet.payload.clear();
                    packet.payload.extend_from_slice(datagram.payload);
                    true
                })
                .map_err(gone)?;
            // handed over outside the session's lock, as every packet is
            if captured && let Some(packet) = kept.as_ref() {
                send(own, packet);
            }
            Ok(())
        })
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

/// Room for one packet: what a datagram on a path of the usual size holds.
const PACKET_ROOM: usize = 1_500;

thread_local! {
    /// The packet a call's capture is copied into, on the thread that
    /// carries the call: the pump's.
    static PACKET: RefCell<Option<Outgoing>> = const { RefCell::new(None) };
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
