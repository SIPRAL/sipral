// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The cause indicators parameter (Q.763 §3.12), coded as ITU-T Q.850 has
//! it:
//!
//! ```text
//!             8     7  6        5      4  3  2  1
//! octet 1     ext   coding std  spare  location
//! octet 1a    ext   recommendation           (only when octet 1's ext is 0)
//! octet 2     ext   cause value
//! octet 3...  diagnostics, if any
//! ```
//!
//! The cause value is seven bits, read as one number, 1 to 127: 16 normal
//! call clearing, 17 user busy. RFC 3326's `Reason: Q.850;cause=` carries
//! the same number.

/// The coding standard of a cause (Q.850 §2.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CodingStandard {
    /// `00`: ITU-T, the values Q.850 lists.
    Itu,
    /// `01`: ISO/IEC.
    Iso,
    /// `10`: national.
    National,
    /// `11`: specific to the location.
    Location,
}

impl CodingStandard {
    const fn of(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::Itu,
            1 => Self::Iso,
            2 => Self::National,
            _ => Self::Location,
        }
    }

    /// The two-bit value.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Itu => 0,
            Self::Iso => 1,
            Self::National => 2,
            Self::Location => 3,
        }
    }
}

/// Where in the connection the cause arose (Q.850 Table 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Location {
    /// `0000`: the user.
    User,
    /// `0001`: a private network serving the local user.
    PrivateLocal,
    /// `0010`: the public network serving the local user.
    PublicLocal,
    /// `0011`: a transit network.
    Transit,
    /// `0100`: the public network serving the remote user.
    PublicRemote,
    /// `0101`: a private network serving the remote user.
    PrivateRemote,
    /// `0111`: an international network.
    International,
    /// `1010`: a network beyond the interworking point.
    BeyondInterworking,
    /// Any other value.
    Other(u8),
}

impl Location {
    const fn of(bits: u8) -> Self {
        match bits & 0x0f {
            0 => Self::User,
            1 => Self::PrivateLocal,
            2 => Self::PublicLocal,
            3 => Self::Transit,
            4 => Self::PublicRemote,
            5 => Self::PrivateRemote,
            7 => Self::International,
            10 => Self::BeyondInterworking,
            other => Self::Other(other),
        }
    }

    /// The four-bit value.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::User => 0,
            Self::PrivateLocal => 1,
            Self::PublicLocal => 2,
            Self::Transit => 3,
            Self::PublicRemote => 4,
            Self::PrivateRemote => 5,
            Self::International => 7,
            Self::BeyondInterworking => 10,
            Self::Other(value) => value & 0x0f,
        }
    }
}

/// A cause: why a call is released, or did not progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Cause {
    /// The cause value, 0 to 127.
    pub value: u8,
    /// Where it arose.
    pub location: Location,
    /// Whose list `value` is from.
    pub coding: CodingStandard,
}

impl Cause {
    /// An ITU-T cause value at a location.
    #[must_use]
    pub const fn new(value: u8, location: Location) -> Self {
        Self {
            value: value & 0x7f,
            location,
            coding: CodingStandard::Itu,
        }
    }

    pub(super) fn of(content: &[u8]) -> Option<Self> {
        let (&first, mut rest) = content.split_first()?;
        if first & 0x80 == 0 {
            // octet 1a, the recommendation, is there
            rest = rest.get(1..)?;
        }
        let &value = rest.first()?;
        Some(Self {
            value: value & 0x7f,
            location: Location::of(first),
            coding: CodingStandard::of(first >> 5),
        })
    }

    /// The cause's class, its top three bits (Q.850 §2.2.5): 0 and 1 normal
    /// events, 2 resource unavailable, 3 service or option not available,
    /// 4 service or option not implemented, 5 invalid message, 6 protocol
    /// error, 7 interworking.
    #[must_use]
    pub const fn class(self) -> u8 {
        self.value >> 4
    }

    /// Q.850's name for the value, when the coding standard is ITU-T's and
    /// Q.850 lists it.
    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        match self.coding {
            CodingStandard::Itu => cause_name(self.value),
            _ => None,
        }
    }

    /// The content of a cause indicators parameter, without diagnostics.
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        vec![
            0x80 | self.coding.code() << 5 | self.location.code(),
            0x80 | (self.value & 0x7f),
        ]
    }
}

/// The name Q.850 §2.2.7 gives a cause value of the ITU-T standard; `None`
/// for one it does not list.
#[must_use]
pub fn cause_name(value: u8) -> Option<&'static str> {
    Some(match value {
        1 => "Unallocated (unassigned) number",
        2 => "No route to specified transit network",
        3 => "No route to destination",
        4 => "Send special information tone",
        5 => "Misdialled trunk prefix",
        6 => "Channel unacceptable",
        7 => "Call awarded and being delivered in an established channel",
        8 => "Preemption",
        9 => "Preemption, circuit reserved for reuse",
        16 => "Normal call clearing",
        17 => "User busy",
        18 => "No user responding",
        19 => "No answer from user (user alerted)",
        20 => "Subscriber absent",
        21 => "Call rejected",
        22 => "Number changed",
        23 => "Redirection to new destination",
        25 => "Exchange routing error",
        26 => "Non-selected user clearing",
        27 => "Destination out of order",
        28 => "Invalid number format (address incomplete)",
        29 => "Facility rejected",
        30 => "Response to STATUS ENQUIRY",
        31 => "Normal, unspecified",
        34 => "No circuit/channel available",
        38 => "Network out of order",
        41 => "Temporary failure",
        42 => "Switching equipment congestion",
        43 => "Access information discarded",
        44 => "Requested circuit/channel not available",
        46 => "Precedence call blocked",
        47 => "Resource unavailable, unspecified",
        49 => "Quality of service not available",
        50 => "Requested facility not subscribed",
        53 => "Outgoing calls barred within CUG",
        55 => "Incoming calls barred within CUG",
        57 => "Bearer capability not authorized",
        58 => "Bearer capability not presently available",
        62 => "Inconsistency in designated outgoing access information and subscriber class",
        63 => "Service or option not available, unspecified",
        65 => "Bearer capability not implemented",
        66 => "Channel type not implemented",
        69 => "Requested facility not implemented",
        70 => "Only restricted digital information bearer capability is available",
        79 => "Service or option not implemented, unspecified",
        81 => "Invalid call reference value",
        82 => "Identified channel does not exist",
        83 => "A suspended call exists, but this call identity does not",
        84 => "Call identity in use",
        85 => "No call suspended",
        86 => "Call having the requested call identity has been cleared",
        87 => "User not member of CUG",
        88 => "Incompatible destination",
        90 => "Non-existent CUG",
        91 => "Invalid transit network selection",
        95 => "Invalid message, unspecified",
        96 => "Mandatory information element is missing",
        97 => "Message type non-existent or not implemented",
        98 => {
            "Message not compatible with call state or message type non-existent or not implemented"
        }
        99 => "Information element/parameter non-existent or not implemented",
        100 => "Invalid information element contents",
        101 => "Message not compatible with call state",
        102 => "Recovery on timer expiry",
        103 => "Parameter non-existent or not implemented, passed on",
        110 => "Message with unrecognized parameter, discarded",
        111 => "Protocol error, unspecified",
        127 => "Interworking, unspecified",
        _ => return None,
    })
}
