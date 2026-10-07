// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One entry: what was decided, when, about what.

use core::fmt;
use core::time::Duration;
use std::net::SocketAddr;
use std::sync::Arc;

use super::Reason;
use crate::endpoint::TransportProtocol;
use crate::msg::{Method, StatusCode};

/// Which way a message was travelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// It arrived here.
    Inbound,
    /// It left here.
    Outbound,
}

impl Direction {
    /// The wire form, under the stability rules of [`Reason`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "in",
            Self::Outbound => "out",
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A method, owned: [`Method`] borrows its start line, and a record outlives
/// the parse buffer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MethodName {
    /// One of the methods this stack knows, kept as the literal.
    Known(&'static str),
    /// One it does not, kept as the peer spelled it.
    Extension(Arc<str>),
}

/// The methods [`Method::as_str`] answers for with a literal.
const KNOWN: [Method<'static>; 14] = [
    Method::Invite,
    Method::Ack,
    Method::Bye,
    Method::Cancel,
    Method::Options,
    Method::Register,
    Method::Prack,
    Method::Subscribe,
    Method::Notify,
    Method::Refer,
    Method::Info,
    Method::Update,
    Method::Message,
    Method::Publish,
];

impl MethodName {
    /// Keep a method past the message it was read from. Known methods are
    /// literals and cost nothing; an extension token is copied.
    #[must_use]
    pub fn of(method: Method<'_>) -> Self {
        match KNOWN.into_iter().find(|known| *known == method) {
            Some(known) => Self::Known(known.as_str()),
            None => Self::Extension(Arc::from(method.as_str())),
        }
    }

    /// The wire form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match *self {
            Self::Known(name) => name,
            Self::Extension(ref name) => name,
        }
    }
}

impl fmt::Display for MethodName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which message a wire event was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Wire {
    /// A request, by its method.
    Request(MethodName),
    /// A response, by its status.
    Response(StatusCode),
}

/// The message that caused a decision.
///
/// The size is the message as on the wire, the one number a log line never
/// carries (B1 in `docs/13-client-requirements.md`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct WireEvent {
    /// A method or a status.
    pub message: Wire,
    /// Which way it was going.
    pub direction: Direction,
    /// How many bytes it measured.
    pub bytes: usize,
}

impl WireEvent {
    /// A request going out or arriving.
    #[must_use]
    pub fn request(method: Method<'_>, direction: Direction, bytes: usize) -> Self {
        Self {
            message: Wire::Request(MethodName::of(method)),
            direction,
            bytes,
        }
    }

    /// A response going out or arriving.
    #[must_use]
    pub const fn response(status: StatusCode, direction: Direction, bytes: usize) -> Self {
        Self {
            message: Wire::Response(status),
            direction,
            bytes,
        }
    }
}

/// A size and the limit it was measured against. Always both: a size alone
/// says nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Measure {
    /// What was measured.
    pub size: usize,
    /// What it had to fit in.
    pub limit: u32,
}

/// One decision, with what a bug report needs.
///
/// Built only by the stack. Fields are public so a binding can read them
/// without JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Decision {
    /// Which decision it was.
    pub reason: Reason,
    /// Offset from the record's first entry. Not an instant: nothing here
    /// reads a clock.
    pub at: Duration,
    /// The message that caused it, where there was one.
    pub wire: Option<WireEvent>,
    /// The far end it concerned.
    pub address: Option<SocketAddr>,
    /// What was going to carry it.
    pub protocol: Option<TransportProtocol>,
    /// The size that decided it, and what it was measured against.
    pub measure: Option<Measure>,
}

impl Decision {
    /// A decision with nothing on it yet. The time is stamped by the record.
    pub(crate) const fn of(reason: Reason) -> Self {
        Self {
            reason,
            at: Duration::ZERO,
            wire: None,
            address: None,
            protocol: None,
            measure: None,
        }
    }

    /// The message that caused it.
    pub(crate) fn caused_by(mut self, wire: WireEvent) -> Self {
        self.wire = Some(wire);
        self
    }

    /// The far end.
    pub(crate) const fn at_address(mut self, address: SocketAddr) -> Self {
        self.address = Some(address);
        self
    }

    /// What was going to carry it.
    pub(crate) const fn over(mut self, protocol: TransportProtocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// The size, and the limit it was weighed against.
    pub(crate) const fn measured(mut self, size: usize, limit: u32) -> Self {
        self.measure = Some(Measure { size, limit });
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{Decision, Direction, MethodName, Reason, Wire, WireEvent};
    use crate::msg::{Method, StatusCode};

    #[test]
    fn a_known_method_is_kept_as_a_literal_and_an_extension_is_copied() {
        // a record outlives the datagram; known methods must not allocate
        assert_eq!(
            MethodName::of(Method::Invite),
            MethodName::Known("INVITE"),
            "a method the stack knows"
        );
        let owned = String::from("SPIRAL");
        assert_eq!(
            MethodName::of(Method::Extension(&owned)).as_str(),
            "SPIRAL",
            "a method it does not"
        );
        assert!(matches!(
            MethodName::of(Method::Extension(&owned)),
            MethodName::Extension(_)
        ));
    }

    #[test]
    fn every_method_the_stack_knows_survives_the_message_it_came_from() {
        let methods = [
            "INVITE",
            "ACK",
            "BYE",
            "CANCEL",
            "OPTIONS",
            "REGISTER",
            "PRACK",
            "SUBSCRIBE",
            "NOTIFY",
            "REFER",
            "INFO",
            "UPDATE",
            "MESSAGE",
            "PUBLISH",
        ];
        for text in methods {
            let owned = String::from(text);
            let method = Method::from_bytes(owned.as_bytes()).expect("a token");
            assert_eq!(
                MethodName::of(method),
                MethodName::Known(text),
                "{text} should be kept as a literal"
            );
        }
    }

    #[test]
    fn a_wire_event_carries_the_size_that_went_on_the_wire() {
        let event = WireEvent::request(Method::Invite, Direction::Outbound, 1_785);
        assert_eq!(event.bytes, 1_785);
        assert_eq!(event.direction, Direction::Outbound);
        assert_eq!(event.message, Wire::Request(MethodName::Known("INVITE")));

        let refusal = WireEvent::response(StatusCode::UNAUTHORIZED, Direction::Inbound, 412);
        assert_eq!(refusal.message, Wire::Response(StatusCode::UNAUTHORIZED));
        assert_eq!(refusal.direction.as_str(), "in");
    }

    #[test]
    fn a_decision_carries_only_what_applies_to_it() {
        let bare = Decision::of(Reason::FlowDead);
        assert!(bare.wire.is_none());
        assert!(bare.address.is_none());
        assert!(bare.protocol.is_none());
        assert!(bare.measure.is_none());

        let sized = Decision::of(Reason::TransportPromotedBySize).measured(1_785, 1_299);
        let measure = sized.measure.expect("a size and a limit");
        assert_eq!(measure.size, 1_785);
        assert_eq!(measure.limit, 1_299);
        assert!(sized.wire.is_none());
    }
}
