// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The range a deployment's RTP ports come from.
//!
//! The application owns every socket, so this range opens nothing: it is
//! the rule [`crate::MediaEngine::reserve_rtp_port`] hands ports out by, and
//! the one a firewall is configured to. The rule is RFC 3550's, as this stack
//! uses it:
//!
//! - **RTP on an even port** (§11: "RTP data SHOULD be carried on an even UDP
//!   port number").
//! - **RTCP on the odd port above it** (§11, and `sipral_rtp::rtcp::paired_rtcp_port`,
//!   which is where the stack sends and expects it unless the far end said
//!   otherwise with `a=rtcp`). The pair is reserved whole even when this end
//!   offers RFC 5761 multiplexing, because the far end may decline it and the
//!   odd port is then needed after all.
//! - So a range holds as many calls as it holds even ports whose odd partner
//!   is still inside it, and not one more.

use std::fmt;

/// An RTP port range: `min..=max`, with every call taking an even port and
/// the odd one above it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RtpPorts {
    min: u16,
    max: u16,
}

/// Why a range was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RtpPortsError {
    /// Zero is not a port: nothing can be bound to it on purpose.
    Zero,
    /// The lower bound is above the upper one.
    Reversed {
        /// The lower bound given.
        min: u16,
        /// The upper bound given.
        max: u16,
    },
    /// No even port in the range has its odd partner in it too, so the range
    /// holds no call at all.
    NoPair {
        /// The lower bound given.
        min: u16,
        /// The upper bound given.
        max: u16,
    },
}

impl fmt::Display for RtpPortsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Zero => f.write_str("an RTP port range cannot start at port 0"),
            Self::Reversed { min, max } => {
                write!(f, "the RTP port range {min}..{max} ends before it starts")
            }
            Self::NoPair { min, max } => write!(
                f,
                "the RTP port range {min}..{max} holds no even port with the odd port above it \
                 for RTCP, so it holds no call"
            ),
        }
    }
}

impl core::error::Error for RtpPortsError {}

/// Every pair in a range is in use: the call that wanted one cannot have it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortsExhausted {
    /// The range that ran out.
    pub range: RtpPorts,
}

impl fmt::Display for PortsExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "every one of the {} RTP port pairs in {}..{} is in use",
            self.range.pairs(),
            self.range.min,
            self.range.max
        )
    }
}

impl core::error::Error for PortsExhausted {}

impl RtpPorts {
    /// The range `min..=max`, or why it holds no call.
    ///
    /// # Errors
    /// [`RtpPortsError`] for a range starting at zero, a reversed one, and
    /// one with no even port whose odd partner is inside it.
    pub const fn new(min: u16, max: u16) -> Result<Self, RtpPortsError> {
        if min == 0 {
            return Err(RtpPortsError::Zero);
        }
        if min > max {
            return Err(RtpPortsError::Reversed { min, max });
        }
        let range = Self { min, max };
        if range.pairs() == 0 {
            return Err(RtpPortsError::NoPair { min, max });
        }
        Ok(range)
    }

    /// The lower bound, as given.
    #[must_use]
    pub const fn min(self) -> u16 {
        self.min
    }

    /// The upper bound, as given.
    #[must_use]
    pub const fn max(self) -> u16 {
        self.max
    }

    /// The first even port, where the first pair starts.
    const fn first(self) -> u32 {
        let min = self.min as u32;
        min + min % 2
    }

    /// How many RTP/RTCP pairs fit: how many calls the range holds.
    #[must_use]
    pub const fn pairs(self) -> u16 {
        let first = self.first();
        let max = self.max as u32;
        if first + 1 > max {
            return 0;
        }
        // (max - first + 1) / 2 is at most 32767, so it fits
        #[allow(clippy::cast_possible_truncation)]
        let pairs = (max - first).div_ceil(2) as u16;
        pairs
    }

    /// The RTP port of the `index`th pair, counting from zero.
    pub(crate) fn pair(self, index: u16) -> u16 {
        u16::try_from(self.first() + 2 * u32::from(index)).unwrap_or(u16::MAX)
    }

    /// Whether `port` is one this range hands out for RTP: even, and with its
    /// RTCP partner inside the range too.
    #[must_use]
    pub const fn holds(self, port: u16) -> bool {
        let port = port as u32;
        port.is_multiple_of(2) && port >= self.first() && port < self.max as u32
    }
}

#[cfg(test)]
mod tests {
    use super::{RtpPorts, RtpPortsError};

    #[test]
    fn a_range_holds_its_even_ports_with_their_odd_partners() {
        let range = RtpPorts::new(10000, 10009).unwrap();
        assert_eq!(range.pairs(), 5);
        assert_eq!(range.pair(0), 10000);
        assert_eq!(range.pair(4), 10008);
        assert!(range.holds(10008));
        assert!(!range.holds(10001), "odd ports are RTCP's");
        assert!(!range.holds(10010), "outside");
    }

    #[test]
    fn an_odd_lower_bound_starts_at_the_even_port_above_it_and_an_even_upper_bound_loses_its_last_port()
     {
        let range = RtpPorts::new(10001, 10006).unwrap();
        assert_eq!(range.pair(0), 10002);
        assert_eq!(
            range.pairs(),
            2,
            "10002/10003 and 10004/10005; 10006 has no partner"
        );
        assert!(!range.holds(10006));
    }

    #[test]
    fn a_range_that_holds_no_call_is_refused() {
        assert_eq!(RtpPorts::new(0, 10), Err(RtpPortsError::Zero));
        assert_eq!(
            RtpPorts::new(20, 10),
            Err(RtpPortsError::Reversed { min: 20, max: 10 })
        );
        assert_eq!(
            RtpPorts::new(10001, 10002),
            Err(RtpPortsError::NoPair {
                min: 10001,
                max: 10002
            })
        );
        assert_eq!(
            RtpPorts::new(10000, 10000),
            Err(RtpPortsError::NoPair {
                min: 10000,
                max: 10000
            })
        );
        assert_eq!(RtpPorts::new(65534, 65535).unwrap().pairs(), 1);
    }
}
