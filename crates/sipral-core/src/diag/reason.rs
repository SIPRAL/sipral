// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The vocabulary: one code per decision this crate makes.

use core::fmt;

/// Why an entry is in the record.
///
/// # Stability
///
/// The wire form ([`Reason::as_str`]) leaves the process: JSON, bug reports,
/// greps, alerts. Two rules hold for the life of the crate, and breaking
/// either is a breaking change:
///
/// - **A wire form never changes.** Renaming the Rust variant is allowed;
///   changing its string is not.
/// - **A wire form is never reused.** A retired decision keeps its string
///   reserved, since a reader cannot tell which build wrote a record.
///
/// It is a dotted slug, not a number, because a number needs a table that
/// matches the build, and bug reports never say the build.
///
/// # Adding one
///
/// The enum is `#[non_exhaustive]`, so adding a variant is not breaking. Add
/// the variant, an arm in [`Reason::as_str`] with an unused string, and a line
/// in `docs/14-diagnostics.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Reason {
    /// The flow a request is about to leave on.
    TransportSelected,
    /// RFC 3261 §18.1.1: too large for a datagram, so moved to a stream
    /// transport. Carries the size and the limit.
    TransportPromotedBySize,
    /// Too large for a datagram and no stream open: the request was not sent
    /// and the caller was asked to open one.
    TransportRefusedBySize,
    /// Too large for a datagram, no stream available, and
    /// `DatagramLimit::without_stream_bytes` sent it over the datagram anyway.
    /// Carries the size and that limit.
    TransportKeptOnDatagram,
    /// Too large in full, so sent in RFC 3261 §7.3.3 compact form
    /// (`DatagramLimit::compaction`), and without `Allow` if that was not
    /// enough. Carries the final size and the limit. A promotion or refusal
    /// that still followed is a separate entry.
    TransportCompactedBySize,
    /// A transport closed or failed, and everything on it failed with it.
    TransportLost,
    /// RFC 5626 §4.4.1: ten seconds without a pong on a flow that answered
    /// before, so the flow was taken down.
    FlowDead,
    /// A request went on the wire. Carries its size in bytes (B1 in
    /// `docs/13-client-requirements.md`).
    RequestSent,
    /// A retransmission timer fired and the same bytes went again.
    RequestRetransmitted,
    /// A peer's request got a 503 because this endpoint holds as many
    /// transactions or dialogs as configured.
    RequestRefusedWhenFull,
    /// A framed request got a 400 before anything acted on it, because a
    /// field the message depends on could not be read (RFC 3261 §8.2.x). An
    /// ACK draws no answer, so it is dropped under the same reason.
    RequestRefusedAsMalformed,
    /// An in-dialog request got a 503 because that dialog already holds as
    /// many non-INVITE server transactions as it may. Separate from
    /// [`Self::RequestRefusedWhenFull`]: in-dialog requests are never refused
    /// for the endpoint-wide limit.
    RequestRefusedByDialog,
    /// A request the parser refused (past a `msg::Limits` bound, or
    /// unreadable) was answered from the fields still recoverable: 513 when
    /// over the message bound (RFC 3261 §21.5.14), else 400 with the reason in
    /// the phrase (§21.4.1). Carries size and limit when a byte bound refused
    /// it.
    RequestRefusedUnreadable,
    /// Unparseable bytes that could not be answered: a response, an ACK, or a
    /// request whose `Via`, `From`, `To`, `Call-ID` or `CSeq` was lost.
    /// Dropped.
    MessageDroppedUnreadable,
    /// A response went on the wire.
    ResponseSent,
    /// A retransmission timer fired and the same response went again: the
    /// acknowledgement is not arriving.
    ResponseRetransmitted,
    /// A final response was retransmitted for 64·T1 and never acknowledged
    /// (RFC 3261 §17.2.1, timer H).
    TransactionUnacknowledged,
    /// A non-INVITE server transaction got no final response from the
    /// application within 64·T1, so the endpoint answered 408 (RFC 3261
    /// §17.2.2 gives that state no timer of its own).
    RequestAnsweredByTimeout,
    /// A 2xx to a forked INVITE found no room under `max_dialogs`, so it was
    /// neither reported nor acknowledged (§13.3.1.4: the far end ends the call
    /// with its own BYE).
    ForkDroppedAtLimit,
    /// A refusal arrived carrying a challenge this stack can answer
    /// (§22, RFC 8760).
    ChallengeReceived,
    /// The request went again carrying credentials.
    ChallengeAnswered,
    /// A challenge was not answered because the password is not for whoever
    /// asked: another server than the account's, or another realm (RFC 3261
    /// §22.1). The refusal stands. Carries the challenger's address.
    ChallengeDeclined,
    /// A dialog was created (§12.1).
    DialogCreated,
    /// A dialog is over and its handle is stale.
    DialogDestroyed,
    /// A final response of 300 or above ended a request or a call.
    FailedRefused,
    /// Nothing came back within 64·T1.
    FailedTimeout,
    /// The transport could not deliver.
    FailedTransport,
    /// A registrar's 2xx carried an unreadable or too long `Service-Route`,
    /// so none was taken (RFC 3608 §6.1). Written by `sipral-ua`.
    ServiceRouteIgnored,
    /// A registrar's 2xx carried an unreadable `pub-gruu` or `temp-gruu` for
    /// this instance, so it was not used (RFC 5627 §4.2). Written by
    /// `sipral-ua`.
    GruuIgnored,
    /// A registrar's 2xx carried an unreadable `P-Associated-URI`, so no
    /// associated identity was reported (RFC 7315 §4.1). Written by
    /// `sipral-ua`.
    AssociatedUriIgnored,
}

impl Reason {
    /// The wire form, which never changes and is never reused.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TransportSelected => "transport.selected",
            Self::TransportPromotedBySize => "transport.promoted.size",
            Self::TransportRefusedBySize => "transport.refused.size",
            Self::TransportKeptOnDatagram => "transport.kept.datagram",
            Self::TransportCompactedBySize => "transport.compacted.size",
            Self::TransportLost => "transport.lost",
            Self::FlowDead => "transport.flow.dead",
            Self::RequestSent => "request.sent",
            Self::RequestRetransmitted => "request.retransmitted",
            Self::RequestRefusedWhenFull => "request.refused.overload",
            Self::RequestRefusedAsMalformed => "request.refused.malformed",
            Self::RequestRefusedByDialog => "request.refused.dialog",
            Self::RequestRefusedUnreadable => "request.refused.unreadable",
            Self::MessageDroppedUnreadable => "message.dropped.unreadable",
            Self::ResponseSent => "response.sent",
            Self::ResponseRetransmitted => "response.retransmitted",
            Self::TransactionUnacknowledged => "transaction.unacknowledged",
            Self::RequestAnsweredByTimeout => "request.answered.timeout",
            Self::ForkDroppedAtLimit => "dialog.fork.dropped",
            Self::ChallengeReceived => "auth.challenge.received",
            Self::ChallengeAnswered => "auth.challenge.answered",
            Self::ChallengeDeclined => "auth.challenge.declined",
            Self::DialogCreated => "dialog.created",
            Self::DialogDestroyed => "dialog.destroyed",
            Self::FailedRefused => "failure.refused",
            Self::FailedTimeout => "failure.timeout",
            Self::FailedTransport => "failure.transport",
            Self::ServiceRouteIgnored => "registration.service_route.ignored",
            Self::GruuIgnored => "registration.gruu.ignored",
            Self::AssociatedUriIgnored => "registration.associated_uri.ignored",
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::Reason;

    /// Every variant, so the tests cannot miss one added later.
    const ALL: [Reason; 30] = [
        Reason::TransportSelected,
        Reason::TransportPromotedBySize,
        Reason::TransportRefusedBySize,
        Reason::TransportKeptOnDatagram,
        Reason::TransportCompactedBySize,
        Reason::TransportLost,
        Reason::FlowDead,
        Reason::RequestSent,
        Reason::RequestRetransmitted,
        Reason::RequestRefusedWhenFull,
        Reason::RequestRefusedAsMalformed,
        Reason::RequestRefusedByDialog,
        Reason::RequestRefusedUnreadable,
        Reason::MessageDroppedUnreadable,
        Reason::ResponseSent,
        Reason::ResponseRetransmitted,
        Reason::TransactionUnacknowledged,
        Reason::RequestAnsweredByTimeout,
        Reason::ForkDroppedAtLimit,
        Reason::ChallengeReceived,
        Reason::ChallengeAnswered,
        Reason::ChallengeDeclined,
        Reason::DialogCreated,
        Reason::DialogDestroyed,
        Reason::FailedRefused,
        Reason::FailedTimeout,
        Reason::FailedTransport,
        Reason::ServiceRouteIgnored,
        Reason::GruuIgnored,
        Reason::AssociatedUriIgnored,
    ];

    #[test]
    fn no_two_decisions_share_a_wire_form() {
        // a string names one decision and keeps naming it
        for (at, one) in ALL.iter().enumerate() {
            for other in ALL.iter().skip(at + 1) {
                assert_ne!(one.as_str(), other.as_str(), "{one:?} and {other:?}");
            }
        }
    }

    #[test]
    fn a_wire_form_is_a_lowercase_dotted_slug() {
        for reason in ALL {
            let text = reason.as_str();
            assert!(!text.is_empty(), "{reason:?}");
            assert!(text.contains('.'), "{reason:?} is not dotted");
            assert!(
                text.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'.' || byte == b'_'),
                "{reason:?} is {text}"
            );
            assert!(!text.starts_with('.') && !text.ends_with('.'), "{reason:?}");
        }
    }

    #[test]
    fn the_wire_forms_are_the_ones_written_down() {
        // spelled out: deriving the expected string would prove nothing
        assert_eq!(
            Reason::TransportPromotedBySize.as_str(),
            "transport.promoted.size"
        );
        assert_eq!(
            Reason::ChallengeAnswered.as_str(),
            "auth.challenge.answered"
        );
        assert_eq!(Reason::RequestSent.to_string(), "request.sent");
        assert_eq!(
            Reason::TransportCompactedBySize.as_str(),
            "transport.compacted.size"
        );
        assert_eq!(
            Reason::ChallengeDeclined.as_str(),
            "auth.challenge.declined"
        );
        assert_eq!(
            Reason::RequestAnsweredByTimeout.as_str(),
            "request.answered.timeout"
        );
        assert_eq!(Reason::ForkDroppedAtLimit.as_str(), "dialog.fork.dropped");
        assert_eq!(Reason::FailedRefused.as_str(), "failure.refused");
        assert_eq!(
            Reason::ServiceRouteIgnored.as_str(),
            "registration.service_route.ignored"
        );
        assert_eq!(Reason::GruuIgnored.as_str(), "registration.gruu.ignored");
        assert_eq!(
            Reason::AssociatedUriIgnored.as_str(),
            "registration.associated_uri.ignored"
        );
    }
}
