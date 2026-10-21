// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The number parameters (Q.763 §3.9, §3.10, §3.16, §3.26, §3.39, §3.44,
//! §3.46).
//!
//! They share one layout and differ in the second octet:
//!
//! ```text
//!             8      7  6  5   4  3   2  1
//! octet 1     O/E    nature of address indicator
//! octet 2     X      numbering plan   Y      Z
//! octet 3     2nd address signal  1st address signal
//! ...
//! octet m     filler (0000) or    nth address signal
//!             the last signal
//! ```
//!
//! | parameter                  | X                 | Y                    | Z         |
//! |----------------------------|-------------------|----------------------|-----------|
//! | called party, redirection  | INN               | spare                | spare     |
//! | calling party, generic     | number incomplete | presentation         | screening |
//! | original called, redirecting | spare           | presentation         | spare     |
//! | connected                  | spare             | presentation         | screening |
//!
//! A generic number has one more octet in front, the number qualifier. An
//! address signal is four bits: 0 to 9 the digits, 11 and 12 the operator
//! codes "code 11" and "code 12", 15 the end-of-pulsing signal ST; the rest
//! are spare. They are written here as the hexadecimal digit of their
//! value, so a digit is itself and code 11 is `B`.

use super::IsupError;

/// The sixteen address signals, by value.
const SIGNALS: &[u8; 16] = b"0123456789ABCDEF";

/// The nature of address indicator (§3.9 b, §3.10 b).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Nature {
    /// Subscriber number, `000 0001`: local to the exchange.
    Subscriber,
    /// Unknown, `000 0010`.
    Unknown,
    /// National (significant) number, `000 0011`: without the country code.
    National,
    /// International number, `000 0100`: with the country code, the E.164
    /// number whole.
    International,
    /// Network-specific number, `000 0101`.
    NetworkSpecific,
    /// Any other value.
    Other(u8),
}

impl Nature {
    const fn of(value: u8) -> Self {
        match value {
            1 => Self::Subscriber,
            2 => Self::Unknown,
            3 => Self::National,
            4 => Self::International,
            5 => Self::NetworkSpecific,
            other => Self::Other(other),
        }
    }

    /// The seven-bit value.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Subscriber => 1,
            Self::Unknown => 2,
            Self::National => 3,
            Self::International => 4,
            Self::NetworkSpecific => 5,
            Self::Other(value) => value & 0x7f,
        }
    }
}

/// The numbering plan indicator (§3.9 d).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NumberingPlan {
    /// ISDN (telephony), E.164, `001`.
    Isdn,
    /// Data, X.121, `011`.
    Data,
    /// Telex, F.69, `100`.
    Telex,
    /// Private, `101` (in a generic number; national use elsewhere).
    Private,
    /// Any other value.
    Other(u8),
}

impl NumberingPlan {
    const fn of(value: u8) -> Self {
        match value {
            1 => Self::Isdn,
            3 => Self::Data,
            4 => Self::Telex,
            5 => Self::Private,
            other => Self::Other(other),
        }
    }

    /// The three-bit value.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Isdn => 1,
            Self::Data => 3,
            Self::Telex => 4,
            Self::Private => 5,
            Self::Other(value) => value & 0x07,
        }
    }
}

/// The address presentation restricted indicator (§3.10 e).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Presentation {
    /// `00`: the number may be shown.
    Allowed,
    /// `01`: the number is not to be shown to the called user.
    Restricted,
    /// `10`: there is no number to show; the address signals are left out.
    NotAvailable,
    /// `11`: reserved for restriction by the network.
    Reserved,
}

impl Presentation {
    const fn of(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::Allowed,
            1 => Self::Restricted,
            2 => Self::NotAvailable,
            _ => Self::Reserved,
        }
    }

    /// The two-bit value.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Allowed => 0,
            Self::Restricted => 1,
            Self::NotAvailable => 2,
            Self::Reserved => 3,
        }
    }

    /// Whether the number is to be kept from the called user: restricted,
    /// or restricted by the network.
    #[must_use]
    pub const fn withheld(self) -> bool {
        matches!(self, Self::Restricted | Self::Reserved)
    }
}

/// The screening indicator (§3.10 f, §3.26 g).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Screening {
    /// `00`: user provided, not verified (national use).
    UserNotVerified,
    /// `01`: user provided, verified and passed.
    UserVerified,
    /// `10`: user provided, verified and failed (national use).
    UserFailed,
    /// `11`: network provided.
    Network,
}

impl Screening {
    const fn of(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::UserNotVerified,
            1 => Self::UserVerified,
            2 => Self::UserFailed,
            _ => Self::Network,
        }
    }

    /// The two-bit value.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::UserNotVerified => 0,
            Self::UserVerified => 1,
            Self::UserFailed => 2,
            Self::Network => 3,
        }
    }

    /// Whether the network stands behind the number: it provided it, or
    /// verified the one the user gave.
    #[must_use]
    pub const fn vouched(self) -> bool {
        matches!(self, Self::UserVerified | Self::Network)
    }
}

/// The number qualifier indicator of a generic number (§3.26 a).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NumberQualifier {
    /// Additional called number, `0000 0001` (national use).
    AdditionalCalled,
    /// Additional connected number, `0000 0101`.
    AdditionalConnected,
    /// Additional calling party number, `0000 0110`: the number a caller
    /// with a special arrangement presents, beside the network's own
    /// calling party number.
    AdditionalCalling,
    /// Any other value.
    Other(u8),
}

impl NumberQualifier {
    const fn of(value: u8) -> Self {
        match value {
            1 => Self::AdditionalCalled,
            5 => Self::AdditionalConnected,
            6 => Self::AdditionalCalling,
            other => Self::Other(other),
        }
    }

    /// The octet.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::AdditionalCalled => 1,
            Self::AdditionalConnected => 5,
            Self::AdditionalCalling => 6,
            Self::Other(value) => value,
        }
    }
}

/// Which of the layouts above a number parameter has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    /// Called party, redirection number: INN, no presentation.
    Called,
    /// Calling party, generic: number incomplete, presentation, screening.
    Calling,
    /// Original called, redirecting: presentation only.
    Redirecting,
    /// Connected: presentation, screening.
    Connected,
}

/// A telephone number, as one of the number parameters carries it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Number {
    /// The nature of address.
    pub nature: Nature,
    /// The numbering plan.
    pub plan: NumberingPlan,
    /// Whether it may be shown. `None` for the parameters that do not say:
    /// the called party number and the redirection number.
    pub presentation: Option<Presentation>,
    /// Who provided it, and whether it was checked. `None` for the
    /// parameters that do not say.
    pub screening: Option<Screening>,
    /// The number incomplete indicator of a calling party or generic number.
    pub incomplete: bool,
    /// The called party and redirection numbers' internal network number
    /// indicator: routing to an internal network number is not allowed.
    pub inn_not_allowed: bool,
    /// The address signals, one character each (see the module's
    /// documentation): `441632960123`.
    pub digits: Box<str>,
}

impl Number {
    /// A number of this nature on the ISDN numbering plan, presentation
    /// allowed and network provided where the parameter says, complete.
    /// `digits` keeps only the characters that are address signals.
    #[must_use]
    pub fn new(nature: Nature, digits: &str) -> Self {
        Self {
            nature,
            plan: NumberingPlan::Isdn,
            presentation: Some(Presentation::Allowed),
            screening: Some(Screening::Network),
            incomplete: false,
            inn_not_allowed: false,
            digits: digits
                .chars()
                .filter(char::is_ascii_hexdigit)
                .map(|c| c.to_ascii_uppercase())
                .collect::<String>()
                .into_boxed_str(),
        }
    }

    /// The same, with this presentation.
    #[must_use]
    pub fn presented(mut self, presentation: Presentation) -> Self {
        self.presentation = Some(presentation);
        self
    }

    /// The same, with this screening.
    #[must_use]
    pub fn screened(mut self, screening: Screening) -> Self {
        self.screening = Some(screening);
        self
    }

    /// The number as it is written for a person: `+` and the digits for an
    /// international number, the digits alone for any other. Empty when the
    /// parameter carried no address signal.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = String::with_capacity(self.digits.len() + 1);
        if self.nature == Nature::International && !self.digits.is_empty() {
            out.push('+');
        }
        out.push_str(&self.digits);
        out
    }

    /// Whether every address signal is a decimal digit: a number a `tel:`
    /// URI can carry.
    #[must_use]
    pub fn is_dialable(&self) -> bool {
        !self.digits.is_empty() && self.digits.bytes().all(|byte| byte.is_ascii_digit())
    }

    /// A called party number (§3.9) or redirection number (§3.46).
    pub(super) fn called(content: &[u8]) -> Option<Self> {
        Self::read(content, Form::Called)
    }

    /// A calling party number (§3.10).
    pub(super) fn calling(content: &[u8]) -> Option<Self> {
        Self::read(content, Form::Calling)
    }

    /// An original called number (§3.39) or redirecting number (§3.44).
    pub(super) fn redirecting(content: &[u8]) -> Option<Self> {
        Self::read(content, Form::Redirecting)
    }

    /// A connected number (§3.16).
    pub(super) fn connected(content: &[u8]) -> Option<Self> {
        Self::read(content, Form::Connected)
    }

    fn read(content: &[u8], form: Form) -> Option<Self> {
        let (&first, rest) = content.split_first()?;
        let (&second, signals) = rest.split_first()?;
        let odd = first & 0x80 != 0;
        let mut digits = String::with_capacity(signals.len() * 2);
        for &octet in signals {
            digits.push(char::from(*SIGNALS.get(usize::from(octet & 0x0f))?));
            digits.push(char::from(*SIGNALS.get(usize::from(octet >> 4))?));
        }
        // the filler of an odd count is not a signal
        if odd && !signals.is_empty() {
            digits.pop();
        }
        let presentation = Presentation::of(second >> 2);
        let screening = Screening::of(second);
        let (presentation, screening) = match form {
            Form::Called => (None, None),
            Form::Calling | Form::Connected => (Some(presentation), Some(screening)),
            Form::Redirecting => (Some(presentation), None),
        };
        Some(Self {
            nature: Nature::of(first & 0x7f),
            plan: NumberingPlan::of((second >> 4) & 0x07),
            presentation,
            screening,
            incomplete: form == Form::Calling && second & 0x80 != 0,
            inn_not_allowed: form == Form::Called && second & 0x80 != 0,
            digits: digits.into_boxed_str(),
        })
    }

    /// The content of a called party number (§3.9) or redirection number
    /// (§3.46) parameter.
    ///
    /// # Errors
    /// [`IsupError::Unwritable`] for a character that is no address signal,
    /// or more than fit in one parameter.
    pub fn to_called_party(&self) -> Result<Vec<u8>, IsupError> {
        self.write(Form::Called)
    }

    /// The content of a calling party number parameter (§3.10).
    ///
    /// # Errors
    /// As [`Number::to_called_party`].
    pub fn to_calling_party(&self) -> Result<Vec<u8>, IsupError> {
        self.write(Form::Calling)
    }

    /// The content of an original called number (§3.39) or redirecting
    /// number (§3.44) parameter.
    ///
    /// # Errors
    /// As [`Number::to_called_party`].
    pub fn to_redirecting(&self) -> Result<Vec<u8>, IsupError> {
        self.write(Form::Redirecting)
    }

    /// The content of a connected number parameter (§3.16).
    ///
    /// # Errors
    /// As [`Number::to_called_party`].
    pub fn to_connected(&self) -> Result<Vec<u8>, IsupError> {
        self.write(Form::Connected)
    }

    fn write(&self, form: Form) -> Result<Vec<u8>, IsupError> {
        let presentation = self.presentation.unwrap_or(Presentation::Allowed);
        // §3.10 Note 1: no address to show, so no address signals
        let digits = if presentation == Presentation::NotAvailable && form != Form::Called {
            ""
        } else {
            &self.digits
        };
        let mut values = Vec::with_capacity(digits.len());
        for character in digits.bytes() {
            let value = SIGNALS
                .iter()
                .position(|signal| *signal == character.to_ascii_uppercase())
                .ok_or(IsupError::Unwritable(
                    "a character that is no address signal",
                ))?;
            values.push(u8::try_from(value).unwrap_or_default());
        }
        let odd = values.len() % 2 == 1;
        let mut out = Vec::with_capacity(2 + values.len().div_ceil(2));
        out.push(u8::from(odd) << 7 | self.nature.code());
        let top = match form {
            Form::Called => self.inn_not_allowed,
            Form::Calling => self.incomplete,
            Form::Redirecting | Form::Connected => false,
        };
        let presentation_bits = match form {
            Form::Called => 0,
            _ => presentation.code() << 2,
        };
        let screening_bits = match form {
            Form::Calling | Form::Connected => self.screening.unwrap_or(Screening::Network).code(),
            Form::Called | Form::Redirecting => 0,
        };
        out.push(u8::from(top) << 7 | self.plan.code() << 4 | presentation_bits | screening_bits);
        for pair in values.chunks(2) {
            let low = pair.first().copied().unwrap_or_default();
            let high = pair.get(1).copied().unwrap_or_default();
            out.push(high << 4 | low);
        }
        if out.len() > usize::from(u8::MAX) {
            return Err(IsupError::Unwritable(
                "more address signals than one parameter holds",
            ));
        }
        Ok(out)
    }
}

/// A generic number (§3.26): a number and what it is.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct GenericNumber {
    /// What the number is.
    pub qualifier: NumberQualifier,
    /// The number, laid out as a calling party number's.
    pub number: Number,
}

impl GenericNumber {
    /// A number with its qualifier.
    #[must_use]
    pub const fn new(qualifier: NumberQualifier, number: Number) -> Self {
        Self { qualifier, number }
    }

    pub(super) fn of(content: &[u8]) -> Option<Self> {
        let (&qualifier, rest) = content.split_first()?;
        Some(Self {
            qualifier: NumberQualifier::of(qualifier),
            number: Number::calling(rest)?,
        })
    }

    /// The content of the parameter.
    ///
    /// # Errors
    /// As [`Number::to_called_party`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, IsupError> {
        let number = self.number.to_calling_party()?;
        let mut out = Vec::with_capacity(number.len() + 1);
        out.push(self.qualifier.code());
        out.extend_from_slice(&number);
        if out.len() > usize::from(u8::MAX) {
            return Err(IsupError::Unwritable(
                "more address signals than one parameter holds",
            ));
        }
        Ok(out)
    }
}
