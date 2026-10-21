// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The indicator parameters an endpoint reads: nature of connection (Q.763
//! §3.35), forward and backward call indicators (§3.23, §3.5), event
//! information (§3.21) and redirection information (§3.45).
//!
//! Bits are named as Q.763 draws them, A the least significant bit of the
//! first octet and I that of the second. What an endpoint has no use for —
//! the end-to-end and SCCP methods, the national bits — is not decoded; the
//! octets are there to read.

/// The nature of connection indicators of an IAM (§3.35).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NatureOfConnection {
    /// Bits BA: how many satellite circuits the connection has, 0 to 2
    /// (3 is spare).
    pub satellites: u8,
    /// Bits DC: 0 no continuity check, 1 required on this circuit, 2
    /// performed on a previous one.
    pub continuity_check: u8,
    /// Bit E: an outgoing echo control device is included.
    pub echo_control: bool,
}

impl NatureOfConnection {
    pub(super) const fn of(octet: u8) -> Self {
        Self {
            satellites: octet & 0x03,
            continuity_check: (octet >> 2) & 0x03,
            echo_control: octet & 0x10 != 0,
        }
    }

    /// The octet.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        (self.satellites & 0x03)
            | (self.continuity_check & 0x03) << 2
            | (self.echo_control as u8) << 4
    }
}

/// The forward call indicators of an IAM (§3.23).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[allow(clippy::struct_excessive_bools)]
pub struct ForwardCall {
    /// Bit A: the call is to be treated as international.
    pub international: bool,
    /// Bit D: interworking was encountered on the way, so not all of it
    /// was Signalling System No. 7.
    pub interworking: bool,
    /// Bit F: ISUP was used all the way.
    pub isup_all_the_way: bool,
    /// Bits HG: 0 ISUP preferred all the way, 1 not required, 2 required.
    pub isup_preference: u8,
    /// Bit I: the originating access is ISDN.
    pub isdn_access: bool,
}

impl ForwardCall {
    pub(super) fn of(octets: &[u8]) -> Option<Self> {
        let (&first, rest) = octets.split_first()?;
        let &second = rest.first()?;
        Some(Self {
            international: first & 0x01 != 0,
            interworking: first & 0x08 != 0,
            isup_all_the_way: first & 0x20 != 0,
            isup_preference: (first >> 6) & 0x03,
            isdn_access: second & 0x01 != 0,
        })
    }

    /// The two octets.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 2] {
        [
            u8::from(self.international)
                | u8::from(self.interworking) << 3
                | u8::from(self.isup_all_the_way) << 5
                | (self.isup_preference & 0x03) << 6,
            u8::from(self.isdn_access),
        ]
    }
}

/// The called party's status in backward call indicators (§3.5, bits DC).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CalledStatus {
    /// `00`: no indication.
    #[default]
    NoIndication,
    /// `01`: the subscriber is free, and being alerted.
    SubscriberFree,
    /// `10`: connect when free (national use).
    ConnectWhenFree,
    /// `11`: spare.
    Spare,
}

impl CalledStatus {
    const fn of(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::NoIndication,
            1 => Self::SubscriberFree,
            2 => Self::ConnectWhenFree,
            _ => Self::Spare,
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::NoIndication => 0,
            Self::SubscriberFree => 1,
            Self::ConnectWhenFree => 2,
            Self::Spare => 3,
        }
    }
}

/// The backward call indicators (§3.5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[allow(clippy::struct_excessive_bools)]
pub struct BackwardCall {
    /// Bits BA: 0 no indication, 1 no charge, 2 charge.
    pub charge: u8,
    /// Bits DC.
    pub called_status: CalledStatus,
    /// Bits FE: 0 no indication, 1 ordinary subscriber, 2 payphone.
    pub called_category: u8,
    /// Bit I: interworking was encountered.
    pub interworking: bool,
    /// Bit K: ISUP was used all the way.
    pub isup_all_the_way: bool,
    /// Bit M: the terminating access is ISDN.
    pub isdn_access: bool,
    /// Bit N: an incoming echo control device is included.
    pub echo_control: bool,
}

impl BackwardCall {
    pub(super) fn of(octets: &[u8]) -> Option<Self> {
        let (&first, rest) = octets.split_first()?;
        let &second = rest.first()?;
        Some(Self {
            charge: first & 0x03,
            called_status: CalledStatus::of(first >> 2),
            called_category: (first >> 4) & 0x03,
            interworking: second & 0x01 != 0,
            isup_all_the_way: second & 0x04 != 0,
            isdn_access: second & 0x10 != 0,
            echo_control: second & 0x20 != 0,
        })
    }

    /// The two octets.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 2] {
        [
            (self.charge & 0x03)
                | self.called_status.code() << 2
                | (self.called_category & 0x03) << 4,
            u8::from(self.interworking)
                | u8::from(self.isup_all_the_way) << 2
                | u8::from(self.isdn_access) << 4
                | u8::from(self.echo_control) << 5,
        ]
    }
}

/// What a CPG reports (§3.21, bits G to A).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EventKind {
    /// `000 0001`: the called party is being alerted.
    Alerting,
    /// `000 0010`: progress.
    Progress,
    /// `000 0011`: in-band information or an appropriate pattern is now
    /// available.
    InBandInformation,
    /// `000 0100`: the call was forwarded on busy (national use).
    ForwardedOnBusy,
    /// `000 0101`: forwarded on no reply (national use).
    ForwardedOnNoReply,
    /// `000 0110`: forwarded unconditionally (national use).
    ForwardedUnconditional,
    /// Any other value.
    Other(u8),
}

impl EventKind {
    const fn of(value: u8) -> Self {
        match value {
            1 => Self::Alerting,
            2 => Self::Progress,
            3 => Self::InBandInformation,
            4 => Self::ForwardedOnBusy,
            5 => Self::ForwardedOnNoReply,
            6 => Self::ForwardedUnconditional,
            other => Self::Other(other),
        }
    }

    /// The seven-bit value.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Alerting => 1,
            Self::Progress => 2,
            Self::InBandInformation => 3,
            Self::ForwardedOnBusy => 4,
            Self::ForwardedOnNoReply => 5,
            Self::ForwardedUnconditional => 6,
            Self::Other(value) => value & 0x7f,
        }
    }

    /// Whether the event says the call was forwarded.
    #[must_use]
    pub const fn forwarded(self) -> bool {
        matches!(
            self,
            Self::ForwardedOnBusy | Self::ForwardedOnNoReply | Self::ForwardedUnconditional
        )
    }
}

/// The event information of a CPG (§3.21).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CallEvent {
    /// What happened.
    pub kind: EventKind,
    /// Bit H: the event is not to be presented (national use).
    pub presentation_restricted: bool,
}

impl CallEvent {
    /// An event, presentation not restricted.
    #[must_use]
    pub const fn new(kind: EventKind) -> Self {
        Self {
            kind,
            presentation_restricted: false,
        }
    }

    pub(super) const fn of(octet: u8) -> Self {
        Self {
            kind: EventKind::of(octet & 0x7f),
            presentation_restricted: octet & 0x80 != 0,
        }
    }

    /// The octet.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        self.kind.code() | (self.presentation_restricted as u8) << 7
    }
}

/// The redirecting indicator of redirection information (§3.45, bits CBA).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RedirectingIndicator {
    /// `000`: no redirection (national use).
    None,
    /// `001`: call rerouted (national use).
    Rerouted,
    /// `010`: call rerouted, all redirection information presentation
    /// restricted (national use).
    ReroutedAllRestricted,
    /// `011`: call diverted.
    Diverted,
    /// `100`: call diverted, all redirection information presentation
    /// restricted.
    DivertedAllRestricted,
    /// `101`: call rerouted, redirection number presentation restricted
    /// (national use).
    ReroutedNumberRestricted,
    /// `110`: call diversion, redirection number presentation restricted
    /// (national use).
    DivertedNumberRestricted,
    /// `111`: spare.
    Spare,
}

impl RedirectingIndicator {
    const fn of(bits: u8) -> Self {
        match bits & 0x07 {
            0 => Self::None,
            1 => Self::Rerouted,
            2 => Self::ReroutedAllRestricted,
            3 => Self::Diverted,
            4 => Self::DivertedAllRestricted,
            5 => Self::ReroutedNumberRestricted,
            6 => Self::DivertedNumberRestricted,
            _ => Self::Spare,
        }
    }

    /// The three-bit value.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Rerouted => 1,
            Self::ReroutedAllRestricted => 2,
            Self::Diverted => 3,
            Self::DivertedAllRestricted => 4,
            Self::ReroutedNumberRestricted => 5,
            Self::DivertedNumberRestricted => 6,
            Self::Spare => 7,
        }
    }

    /// Whether every piece of redirection information is to be kept from
    /// the called user.
    #[must_use]
    pub const fn all_restricted(self) -> bool {
        matches!(
            self,
            Self::ReroutedAllRestricted | Self::DivertedAllRestricted
        )
    }
}

/// Why a call was redirected (§3.45, bits HGFE and PONM; §3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RedirectReason {
    /// `0000`: unknown, or not available.
    Unknown,
    /// `0001`: user busy.
    UserBusy,
    /// `0010`: no reply.
    NoReply,
    /// `0011`: unconditional.
    Unconditional,
    /// `0100`: deflection during alerting.
    DeflectionDuringAlerting,
    /// `0101`: deflection, immediate response.
    DeflectionImmediate,
    /// `0110`: mobile subscriber not reachable.
    MobileNotReachable,
    /// Any other value.
    Other(u8),
}

impl RedirectReason {
    const fn of(bits: u8) -> Self {
        match bits & 0x0f {
            0 => Self::Unknown,
            1 => Self::UserBusy,
            2 => Self::NoReply,
            3 => Self::Unconditional,
            4 => Self::DeflectionDuringAlerting,
            5 => Self::DeflectionImmediate,
            6 => Self::MobileNotReachable,
            other => Self::Other(other),
        }
    }

    /// The four-bit value.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::UserBusy => 1,
            Self::NoReply => 2,
            Self::Unconditional => 3,
            Self::DeflectionDuringAlerting => 4,
            Self::DeflectionImmediate => 5,
            Self::MobileNotReachable => 6,
            Self::Other(value) => value & 0x0f,
        }
    }

    /// The `reason` a SIP `Diversion` gives the same thing (RFC 5806 §4):
    /// `user-busy`, `no-answer`, `unconditional`, `deflection`,
    /// `out-of-service`, or `unknown`.
    #[must_use]
    pub const fn diversion_reason(self) -> &'static str {
        match self {
            Self::UserBusy => "user-busy",
            Self::NoReply => "no-answer",
            Self::Unconditional => "unconditional",
            Self::DeflectionDuringAlerting | Self::DeflectionImmediate => "deflection",
            Self::MobileNotReachable => "out-of-service",
            Self::Unknown | Self::Other(_) => "unknown",
        }
    }
}

/// The redirection information (§3.45).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Redirection {
    /// Bits CBA: rerouted or diverted, and what may be shown.
    pub indicator: RedirectingIndicator,
    /// Bits HGFE: why the call was first redirected.
    pub original_reason: RedirectReason,
    /// Bits KJI: how many times the call has been redirected, 1 to 5.
    /// `None` when the second octet is not there (ISUP'88 sends one octet).
    pub counter: Option<u8>,
    /// Bits PONM: why it was last redirected. `None` without the second
    /// octet.
    pub reason: Option<RedirectReason>,
}

impl Redirection {
    /// A diversion: why it happened last, why first, and how many there
    /// have been.
    #[must_use]
    pub const fn diverted(
        reason: RedirectReason,
        original_reason: RedirectReason,
        counter: u8,
    ) -> Self {
        Self {
            indicator: RedirectingIndicator::Diverted,
            original_reason,
            counter: Some(counter),
            reason: Some(reason),
        }
    }

    pub(super) fn of(octets: &[u8]) -> Option<Self> {
        let (&first, rest) = octets.split_first()?;
        let second = rest.first().copied();
        Some(Self {
            indicator: RedirectingIndicator::of(first),
            original_reason: RedirectReason::of(first >> 4),
            counter: second.map(|octet| octet & 0x07),
            reason: second.map(|octet| RedirectReason::of(octet >> 4)),
        })
    }

    /// The octets: two, or one when neither `counter` nor `reason` is set.
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        let first = self.indicator.code() | self.original_reason.code() << 4;
        if self.counter.is_none() && self.reason.is_none() {
            return vec![first];
        }
        vec![
            first,
            (self.counter.unwrap_or(0) & 0x07)
                | self.reason.unwrap_or(RedirectReason::Unknown).code() << 4,
        ]
    }
}
