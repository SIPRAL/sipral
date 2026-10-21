// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The ISDN User Part message a carrier gateway carries inside SIP.
//!
//! SIP-T (RFC 3372) and SIP-I (ITU-T Q.1912.5) put the ISUP message of the
//! call beside the session description, as an `application/ISUP` body
//! (RFC 3204 §3.1): the message from its message type code on, without the
//! routing label and the circuit identification code. This module reads that
//! message in the format ITU-T Q.763 gives it, and writes one.
//!
//! # The format (Q.763 §1.4 to §1.8, §2.3)
//!
//! ```text
//! message type code                       1 octet
//! mandatory fixed part                    the octets the message type names
//! pointers to the mandatory variable part one octet each, then one to the
//!                                         optional part when the message
//!                                         type allows one
//! mandatory variable part                 length, content; per parameter
//! optional part                           name, length, content; per
//!                                         parameter, then a zero octet
//! ```
//!
//! A pointer counts the octets from itself, itself included, to the first
//! octet of what it points at; a pointer to the optional part of zero says
//! there is none.
//!
//! # What is read
//!
//! The messages an endpoint sees on a call — IAM, ACM, CPG, ANM, CON, REL,
//! RLC — are read into their parts, and their parameters through typed
//! accessors: the calling, called, original called, redirecting, connected
//! and generic numbers ([`Number`]), redirection information
//! ([`Redirection`]), cause indicators ([`Cause`], the Q.850 cause and its
//! location), the nature of connection, forward and backward call
//! indicators, and the call progress event. Every other message type is
//! recognised by its code ([`MessageType::name`]) and kept as bytes, its
//! parameters not interpreted.
//!
//! Reading is bounded by the input and never panics: every pointer and
//! every length is checked against what is there, and a parameter that does
//! not fit refuses the message ([`IsupError`]). Two leniencies, both on
//! what is missing at the very end: a message that stops where its pointer
//! to the optional part would be has none, and an optional part that runs to
//! the end of the input without its closing zero octet ends there.
//!
//! # What this end sends
//!
//! Nothing, on its own. RFC 3372 §4.1 makes encapsulating ISUP the work of
//! the gateway that has it, and "not the responsibility of an IP endpoint
//! like a SIP phone"; the gateway at the far end writes the ISUP for the
//! network from the SIP it receives (§4.2, RFC 3398). [`IsupBuilder`] writes a
//! message for an application that is a gateway, and for this crate's tests
//! and the lab's.

mod body;
mod build;
mod cause;
mod indicators;
mod number;
#[cfg(test)]
mod tests;

use core::fmt;

pub use body::{IsupBody, Variant};
pub use build::IsupBuilder;
pub use cause::{Cause, CodingStandard, Location, cause_name};
pub use indicators::{
    BackwardCall, CallEvent, CalledStatus, EventKind, ForwardCall, NatureOfConnection,
    RedirectReason, RedirectingIndicator, Redirection,
};
pub use number::{
    GenericNumber, Nature, Number, NumberQualifier, NumberingPlan, Presentation, Screening,
};

/// Parameter name codes (Q.763 Table 5) of the parameters this module reads
/// or writes.
pub mod code {
    /// End of optional parameters (§3.20).
    pub const END_OF_OPTIONAL: u8 = 0x00;
    /// Called party number (§3.9).
    pub const CALLED_PARTY_NUMBER: u8 = 0x04;
    /// Nature of connection indicators (§3.35).
    pub const NATURE_OF_CONNECTION: u8 = 0x06;
    /// Forward call indicators (§3.23).
    pub const FORWARD_CALL: u8 = 0x07;
    /// Calling party's category (§3.11).
    pub const CALLING_CATEGORY: u8 = 0x09;
    /// Calling party number (§3.10).
    pub const CALLING_PARTY_NUMBER: u8 = 0x0a;
    /// Redirecting number (§3.44).
    pub const REDIRECTING_NUMBER: u8 = 0x0b;
    /// Redirection number (§3.46).
    pub const REDIRECTION_NUMBER: u8 = 0x0c;
    /// Backward call indicators (§3.5).
    pub const BACKWARD_CALL: u8 = 0x11;
    /// Cause indicators (§3.12).
    pub const CAUSE: u8 = 0x12;
    /// Redirection information (§3.45).
    pub const REDIRECTION_INFORMATION: u8 = 0x13;
    /// Connected number (§3.16).
    pub const CONNECTED_NUMBER: u8 = 0x21;
    /// Event information (§3.21).
    pub const EVENT_INFORMATION: u8 = 0x24;
    /// Original called number (§3.39).
    pub const ORIGINAL_CALLED_NUMBER: u8 = 0x28;
    /// Generic number (§3.26). May be repeated.
    pub const GENERIC_NUMBER: u8 = 0xc0;
}

/// An ISUP message type (Q.763 Table 4). The seven an endpoint sees on a
/// call are named; every other code is [`MessageType::Other`], which
/// [`MessageType::name`] still names when Table 4 does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MessageType {
    /// Initial address (IAM), `0000 0001`.
    InitialAddress,
    /// Address complete (ACM), `0000 0110`.
    AddressComplete,
    /// Call progress (CPG), `0010 1100`.
    CallProgress,
    /// Answer (ANM), `0000 1001`.
    Answer,
    /// Connect (CON), `0000 0111`.
    Connect,
    /// Release (REL), `0000 1100`.
    Release,
    /// Release complete (RLC), `0001 0000`.
    ReleaseComplete,
    /// Any other code.
    Other(u8),
}

/// Table 4's other message types, by code, for [`MessageType::name`].
const OTHER_NAMES: &[(u8, &str)] = &[
    (0x02, "Subsequent address"),
    (0x03, "Information request"),
    (0x04, "Information"),
    (0x05, "Continuity"),
    (0x08, "Forward transfer"),
    (0x0d, "Suspend"),
    (0x0e, "Resume"),
    (0x11, "Continuity check request"),
    (0x12, "Reset circuit"),
    (0x13, "Blocking"),
    (0x14, "Unblocking"),
    (0x15, "Blocking acknowledgement"),
    (0x16, "Unblocking acknowledgement"),
    (0x17, "Circuit group reset"),
    (0x18, "Circuit group blocking"),
    (0x19, "Circuit group unblocking"),
    (0x1a, "Circuit group blocking acknowledgement"),
    (0x1b, "Circuit group unblocking acknowledgement"),
    (0x1f, "Facility request"),
    (0x20, "Facility accepted"),
    (0x21, "Facility reject"),
    (0x24, "Loop back acknowledgement"),
    (0x28, "Pass-along"),
    (0x29, "Circuit group reset acknowledgement"),
    (0x2a, "Circuit group query"),
    (0x2b, "Circuit group query response"),
    (0x2d, "User-to-user information"),
    (0x2e, "Unequipped CIC"),
    (0x2f, "Confusion"),
    (0x30, "Overload"),
    (0x31, "Charge information"),
    (0x32, "Network resource management"),
    (0x33, "Facility"),
    (0x34, "User part test"),
    (0x35, "User part available"),
    (0x36, "Identification request"),
    (0x37, "Identification response"),
    (0x38, "Segmentation"),
    (0x40, "Loop prevention"),
    (0x41, "Application transport"),
    (0x42, "Pre-release information"),
    (0x43, "Subsequent directory number"),
];

impl MessageType {
    /// The type a message type code names.
    #[must_use]
    pub const fn of(code: u8) -> Self {
        match code {
            0x01 => Self::InitialAddress,
            0x06 => Self::AddressComplete,
            0x2c => Self::CallProgress,
            0x09 => Self::Answer,
            0x07 => Self::Connect,
            0x0c => Self::Release,
            0x10 => Self::ReleaseComplete,
            other => Self::Other(other),
        }
    }

    /// The message type code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::InitialAddress => 0x01,
            Self::AddressComplete => 0x06,
            Self::CallProgress => 0x2c,
            Self::Answer => 0x09,
            Self::Connect => 0x07,
            Self::Release => 0x0c,
            Self::ReleaseComplete => 0x10,
            Self::Other(code) => code,
        }
    }

    /// The three-letter abbreviation of a named type: `IAM`, `ACM`, `CPG`,
    /// `ANM`, `CON`, `REL`, `RLC`.
    #[must_use]
    pub const fn abbreviation(self) -> Option<&'static str> {
        Some(match self {
            Self::InitialAddress => "IAM",
            Self::AddressComplete => "ACM",
            Self::CallProgress => "CPG",
            Self::Answer => "ANM",
            Self::Connect => "CON",
            Self::Release => "REL",
            Self::ReleaseComplete => "RLC",
            Self::Other(_) => return None,
        })
    }

    /// The name Table 4 gives the type; `None` for a code it does not
    /// allocate (a spare, reserved or national one).
    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::InitialAddress => "Initial address",
            Self::AddressComplete => "Address complete",
            Self::CallProgress => "Call progress",
            Self::Answer => "Answer",
            Self::Connect => "Connect",
            Self::Release => "Release",
            Self::ReleaseComplete => "Release complete",
            Self::Other(code) => {
                return OTHER_NAMES
                    .iter()
                    .find(|(known, _)| *known == code)
                    .map(|(_, name)| *name);
            }
        })
    }

    /// The shape of the message (Tables 21 to 34), for the seven read here.
    const fn layout(self) -> Option<Layout> {
        Some(match self {
            Self::InitialAddress => Layout {
                fixed: 5,
                variable: 1,
            },
            Self::AddressComplete | Self::Connect => Layout {
                fixed: 2,
                variable: 0,
            },
            Self::CallProgress => Layout {
                fixed: 1,
                variable: 0,
            },
            Self::Answer | Self::ReleaseComplete => Layout {
                fixed: 0,
                variable: 0,
            },
            Self::Release => Layout {
                fixed: 0,
                variable: 1,
            },
            Self::Other(_) => return None,
        })
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.abbreviation(), self.name()) {
            (Some(short), _) => f.write_str(short),
            (None, Some(name)) => f.write_str(name),
            (None, None) => write!(f, "message type {:#04x}", self.code()),
        }
    }
}

/// The parts of a message type: how many octets its mandatory fixed part
/// has, and how many mandatory variable parameters. Every type read here
/// allows an optional part.
#[derive(Clone, Copy, Debug)]
struct Layout {
    fixed: usize,
    variable: usize,
}

/// Why an ISUP message could not be read or written.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IsupError {
    /// No octet at all: not even a message type.
    Empty,
    /// The message ends inside the part named.
    Truncated(&'static str),
    /// A pointer of zero to a mandatory variable parameter, or one pointing
    /// past the end.
    BadPointer(&'static str),
    /// A parameter, a part or a number that cannot be written as asked:
    /// what, and why.
    Unwritable(&'static str),
}

impl fmt::Display for IsupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("an ISUP message with no message type"),
            Self::Truncated(part) => write!(f, "the ISUP message ends inside its {part}"),
            Self::BadPointer(part) => write!(f, "the ISUP pointer to its {part} points nowhere"),
            Self::Unwritable(why) => write!(f, "the ISUP message cannot be written: {why}"),
        }
    }
}

impl core::error::Error for IsupError {}

/// One ISUP message, read into its parts. Borrows the bytes it was read
/// from.
#[derive(Clone, Copy, Debug)]
pub struct Isup<'a> {
    bytes: &'a [u8],
    kind: MessageType,
    fixed: &'a [u8],
    variable: Option<&'a [u8]>,
    optional: &'a [u8],
}

/// Read one ISUP message (Q.763), starting at its message type code.
///
/// # Errors
/// [`IsupError::Empty`] for no bytes; [`IsupError::Truncated`] and
/// [`IsupError::BadPointer`] for a message whose parts do not fit in what
/// was given.
pub fn parse(bytes: &[u8]) -> Result<Isup<'_>, IsupError> {
    let (&first, rest) = bytes.split_first().ok_or(IsupError::Empty)?;
    let kind = MessageType::of(first);
    let Some(layout) = kind.layout() else {
        return Ok(Isup {
            bytes,
            kind,
            fixed: &[],
            variable: None,
            optional: &[],
        });
    };
    let fixed = rest
        .get(..layout.fixed)
        .ok_or(IsupError::Truncated("mandatory fixed part"))?;
    // offsets below are into `rest`, the octets after the message type
    let pointers = layout.fixed;
    let mut variable = None;
    for at in pointers..pointers + layout.variable {
        let pointer = usize::from(*rest.get(at).ok_or(IsupError::Truncated("pointers"))?);
        if pointer == 0 {
            return Err(IsupError::BadPointer("mandatory variable part"));
        }
        let start = at + pointer;
        let length = usize::from(
            *rest
                .get(start)
                .ok_or(IsupError::BadPointer("mandatory variable part"))?,
        );
        variable = Some(
            rest.get(start + 1..start + 1 + length)
                .ok_or(IsupError::Truncated("mandatory variable part"))?,
        );
    }
    let at = pointers + layout.variable;
    let optional = match rest.get(at) {
        // stopping where the pointer would be: no optional part
        None | Some(0) => &[][..],
        Some(&pointer) => rest
            .get(at + usize::from(pointer)..)
            .ok_or(IsupError::BadPointer("optional part"))?,
    };
    let message = Isup {
        bytes,
        kind,
        fixed,
        variable,
        optional,
    };
    // every optional parameter is checked once here, so the accessors only
    // ever walk a part known to fit
    let mut walk = Parameters { rest: optional };
    while walk.step()?.is_some() {}
    Ok(message)
}

impl<'a> Isup<'a> {
    /// The message, as it was given.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The message type.
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        self.kind
    }

    /// The mandatory fixed part, as carried. Empty for a type not read here.
    #[must_use]
    pub const fn fixed(&self) -> &'a [u8] {
        self.fixed
    }

    /// The content of the one mandatory variable parameter an IAM (the
    /// called party number) or a REL (the cause indicators) has.
    #[must_use]
    pub const fn variable(&self) -> Option<&'a [u8]> {
        self.variable
    }

    /// The optional parameters, name and content, in the order carried.
    #[must_use]
    pub const fn parameters(&self) -> Parameters<'a> {
        Parameters {
            rest: self.optional,
        }
    }

    /// The content of the first optional parameter with this name code.
    #[must_use]
    pub fn parameter(&self, code: u8) -> Option<&'a [u8]> {
        self.parameters()
            .find(|(name, _)| *name == code)
            .map(|(_, content)| content)
    }

    /// The nature of connection indicators of an IAM.
    #[must_use]
    pub fn nature_of_connection(&self) -> Option<NatureOfConnection> {
        match self.kind {
            MessageType::InitialAddress => self
                .fixed
                .first()
                .map(|&octet| NatureOfConnection::of(octet)),
            _ => None,
        }
    }

    /// The forward call indicators of an IAM.
    #[must_use]
    pub fn forward_call(&self) -> Option<ForwardCall> {
        match self.kind {
            MessageType::InitialAddress => ForwardCall::of(self.fixed.get(1..3)?),
            _ => None,
        }
    }

    /// The calling party's category of an IAM (§3.11): `0x0a` an ordinary
    /// subscriber, `0x0f` a payphone, `0x0d` a test call.
    #[must_use]
    pub fn calling_category(&self) -> Option<u8> {
        match self.kind {
            MessageType::InitialAddress => self.fixed.get(3).copied(),
            _ => None,
        }
    }

    /// The transmission medium requirement of an IAM (§3.54): 0 speech, 3
    /// 3.1 kHz audio, 2 64 kbit/s unrestricted.
    #[must_use]
    pub fn transmission_medium(&self) -> Option<u8> {
        match self.kind {
            MessageType::InitialAddress => self.fixed.get(4).copied(),
            _ => None,
        }
    }

    /// The backward call indicators: the fixed part of an ACM or a CON, an
    /// optional parameter of an ANM or a CPG.
    #[must_use]
    pub fn backward_call(&self) -> Option<BackwardCall> {
        match self.kind {
            MessageType::AddressComplete | MessageType::Connect => BackwardCall::of(self.fixed),
            _ => BackwardCall::of(self.parameter(code::BACKWARD_CALL)?),
        }
    }

    /// The event a CPG reports.
    #[must_use]
    pub fn event(&self) -> Option<CallEvent> {
        match self.kind {
            MessageType::CallProgress => self.fixed.first().map(|&octet| CallEvent::of(octet)),
            _ => None,
        }
    }

    /// The called party number of an IAM.
    #[must_use]
    pub fn called_party(&self) -> Option<Number> {
        match self.kind {
            MessageType::InitialAddress => Number::called(self.variable?),
            _ => None,
        }
    }

    /// The calling party number (§3.10).
    #[must_use]
    pub fn calling_party(&self) -> Option<Number> {
        Number::calling(self.parameter(code::CALLING_PARTY_NUMBER)?)
    }

    /// The original called number (§3.39): the number the call was first
    /// placed to, before any redirection.
    #[must_use]
    pub fn original_called(&self) -> Option<Number> {
        Number::redirecting(self.parameter(code::ORIGINAL_CALLED_NUMBER)?)
    }

    /// The redirecting number (§3.44): the number the call was last
    /// redirected from.
    #[must_use]
    pub fn redirecting(&self) -> Option<Number> {
        Number::redirecting(self.parameter(code::REDIRECTING_NUMBER)?)
    }

    /// The redirection number (§3.46): where an ACM, CPG, ANM or REL says the
    /// call is redirected to.
    #[must_use]
    pub fn redirection_number(&self) -> Option<Number> {
        Number::called(self.parameter(code::REDIRECTION_NUMBER)?)
    }

    /// The connected number (§3.16) an ANM, a CON or a CPG carries.
    #[must_use]
    pub fn connected(&self) -> Option<Number> {
        Number::connected(self.parameter(code::CONNECTED_NUMBER)?)
    }

    /// The redirection information (§3.45).
    #[must_use]
    pub fn redirection(&self) -> Option<Redirection> {
        Redirection::of(self.parameter(code::REDIRECTION_INFORMATION)?)
    }

    /// Every generic number (§3.26), in the order carried: the parameter
    /// may be repeated.
    pub fn generic_numbers(&self) -> impl Iterator<Item = GenericNumber> + 'a {
        self.parameters()
            .filter(|(name, _)| *name == code::GENERIC_NUMBER)
            .filter_map(|(_, content)| GenericNumber::of(content))
    }

    /// The cause indicators (§3.12): the mandatory variable part of a REL,
    /// an optional parameter of an ACM, a CPG or an RLC.
    #[must_use]
    pub fn cause(&self) -> Option<Cause> {
        match self.kind {
            MessageType::Release => Cause::of(self.variable?),
            _ => Cause::of(self.parameter(code::CAUSE)?),
        }
    }
}

/// The optional parameters of a message: `(name code, content)`.
#[derive(Clone, Debug)]
pub struct Parameters<'a> {
    rest: &'a [u8],
}

impl<'a> Parameters<'a> {
    /// One parameter, or the end: the zero octet, or no octet left.
    fn step(&mut self) -> Result<Option<(u8, &'a [u8])>, IsupError> {
        let Some((&name, after)) = self.rest.split_first() else {
            return Ok(None);
        };
        if name == code::END_OF_OPTIONAL {
            self.rest = &[];
            return Ok(None);
        }
        let (&length, after) = after
            .split_first()
            .ok_or(IsupError::Truncated("optional part"))?;
        let length = usize::from(length);
        let content = after
            .get(..length)
            .ok_or(IsupError::Truncated("optional part"))?;
        self.rest = after.get(length..).unwrap_or_default();
        Ok(Some((name, content)))
    }
}

impl<'a> Iterator for Parameters<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        self.step().ok().flatten()
    }
}
