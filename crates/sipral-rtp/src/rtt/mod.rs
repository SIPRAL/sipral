// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Real-time text: RFC 4103, ITU-T T.140 text conversation over RTP, with
//! the RFC 2198 redundancy RFC 4103 §4 recommends.
//!
//! Text travels as it is typed, a character at a time from the user's point
//! of view, erasures and all. On the wire it is UTF-8 in T140blocks, one per
//! transmission interval, on a 1000 Hz timestamp clock (§3). Since a lost
//! packet would lose what was typed rather than a few milliseconds of sound,
//! each packet normally carries the blocks of the two before it as well.
//!
//! - [`TextSender`] gathers typed text into blocks, paces them, wraps them
//!   in redundancy and sets the marker bit after a silence (§4, §5).
//! - [`TextReceiver`] puts the blocks back in order from whichever copy
//!   arrives first, drops the rest, waits a bounded time for a late one and
//!   marks what could not be recovered (§5), and hands out
//!   [`TextEvent`]s.
//! - [`RedPayload`] and [`write_red`] are the RFC 2198 payload itself.
//! - [`TextFormat`] writes and reads the SDP that negotiates all this (§6
//!   and the SDP examples of §7).
//!
//! Sans-I/O, like the rest of the crate: time is a [`Duration`] the caller
//! supplies, packets come in and go out as values.
//!
//! Written from RFC 4103, RFC 2198 and ITU-T T.140.

mod receiver;
mod red;
mod sdp;
mod sender;
mod t140;

use core::fmt;
use core::time::Duration;

pub use receiver::{
    Arrival, DEFAULT_MAX_EVENTS, DEFAULT_MAX_PENDING, DEFAULT_REORDER_WAIT, ReceiverConfig,
    TextReceiver,
};
pub use red::{
    MAX_BLOCK_LEN, MAX_TIMESTAMP_OFFSET, RedError, RedPayload, RedundantBlock, write_red,
};
pub use sdp::{TextFormat, parse_cps, parse_red_fmtp};
pub use sender::{BufferFull, DEFAULT_MAX_BUFFERED, SenderConfig, TextPacket, TextSender};
pub use t140::TextEvent;

/// The RTP timestamp clock of `t140` and of `red` carrying it (RFC 4103
/// §3): milliseconds.
pub const CLOCK_RATE: u32 = 1000;

/// The transmission interval RFC 4103 §5.1 recommends.
pub const DEFAULT_INTERVAL: Duration = Duration::from_millis(300);

/// The shortest transmission interval this sender takes. RFC 4103 sets no
/// floor of its own; §5.1 bounds the buffering from above, at T.140's
/// 500 ms, and §9 lets a congested sender stretch it up to five seconds.
pub const MIN_INTERVAL: Duration = Duration::from_millis(100);

/// Redundant generations RFC 4103 §4 recommends: each block is sent three
/// times, once as the primary and twice more.
pub const DEFAULT_GENERATIONS: u8 = 2;

/// Characters a second a receiver takes when its SDP names no `cps` (RFC
/// 4103 §6).
pub const DEFAULT_CPS: u32 = 30;

/// BYTE ORDER MARK, U+FEFF, which T.140 has a sender open the conversation
/// with.
pub const BOM: char = '\u{FEFF}';

/// BACKSPACE, U+0008: in T.140, erase the last character.
pub const BACKSPACE: char = '\u{8}';

/// LINE SEPARATOR, U+2028: in T.140, a new line.
pub const LINE_SEPARATOR: char = '\u{2028}';

/// REPLACEMENT CHARACTER, U+FFFD, the marker RFC 4103 §5 puts where text
/// was lost.
pub const MISSING_TEXT: char = '\u{FFFD}';

/// The largest payload type the RTP header has room for.
const MAX_PAYLOAD_TYPE: u8 = 0x7F;

/// Sending inside RFC 2198 redundancy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Redundancy {
    /// The payload type negotiated for `red/1000`.
    pub payload_type: u8,
    /// Copies of earlier blocks each packet carries besides its own.
    pub generations: u8,
}

/// A text sender or receiver asked for something the RFCs do not allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// A payload type wider than seven bits.
    PayloadType(u8),
    /// `t140` and `red` given the same payload type.
    SamePayloadType(u8),
    /// A transmission interval under [`MIN_INTERVAL`].
    IntervalTooShort(Duration),
    /// So many generations at this interval that the oldest copy lies
    /// further back than a fourteen-bit timestamp offset reaches.
    RedundancyReach(u8),
    /// A `cps` of zero, which would never let a character through.
    ZeroCps,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::PayloadType(pt) => write!(f, "payload type {pt} does not fit seven bits"),
            Self::SamePayloadType(pt) => write!(f, "t140 and red both on payload type {pt}"),
            Self::IntervalTooShort(interval) => write!(
                f,
                "a {} ms interval is under the {} ms minimum",
                interval.as_millis(),
                MIN_INTERVAL.as_millis()
            ),
            Self::RedundancyReach(generations) => write!(
                f,
                "{generations} generations reach past a {MAX_TIMESTAMP_OFFSET} ms offset"
            ),
            Self::ZeroCps => f.write_str("cps of zero"),
        }
    }
}

impl core::error::Error for ConfigError {}

fn check_payload_types(t140: u8, red: Option<Redundancy>) -> Result<(), ConfigError> {
    if t140 > MAX_PAYLOAD_TYPE {
        return Err(ConfigError::PayloadType(t140));
    }
    if let Some(red) = red {
        if red.payload_type > MAX_PAYLOAD_TYPE {
            return Err(ConfigError::PayloadType(red.payload_type));
        }
        if red.payload_type == t140 {
            return Err(ConfigError::SamePayloadType(t140));
        }
    }
    Ok(())
}
