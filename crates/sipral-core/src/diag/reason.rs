// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The vocabulary: one code per decision this crate makes.

use core::fmt;

/// Why an entry is in the record.
///
/// # What stability means here
///
/// The wire form of a variant — the string [`Reason::as_str`] answers with — is
/// the part that leaves this process. It goes into JSON, into a bug report,
/// into whatever a support engineer greps six months later, and into the
/// condition of somebody's alert. Two rules therefore hold for the life of the
/// crate, and breaking either of them is a breaking change of the same weight
/// as removing a public function:
///
/// - **A wire form never changes.** `transport.promoted.size` means what it
///   meant the day it was written. Renaming the Rust variant is allowed;
///   changing the string it answers with is not.
/// - **A wire form is never reused for a different meaning.** A decision that
///   is retired keeps its string reserved rather than handing it to the next
///   thing that looks similar, because a reader cannot tell which version
///   produced the record in front of them.
///
/// The form is a lower-case dotted slug rather than a number for the same
/// reason: a number has to be looked up in a table that matches the build, and
/// the build is the one thing a bug report never comes with.
///
/// # Adding one
///
/// The enum is `#[non_exhaustive]`, so a new variant is not a breaking change
/// for a caller that matches on it — which is what lets the layers above this
/// one add their own decisions as they are written. Adding one means: a new
/// variant, a new arm in [`Reason::as_str`] whose string is not already in the
/// list, and a line in `docs/14-diagnostics.md`. Nothing else moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Reason {
    /// The flow a request is about to leave on.
    TransportSelected,
    /// RFC 3261 §18.1.1: the request would not fit a datagram, so it was moved
    /// to a stream transport. Carries the size and the limit it was measured
    /// against.
    TransportPromotedBySize,
    /// The same rule with nowhere to go: too large for a datagram, no stream
    /// open, so the request was not emitted at all and the caller was asked to
    /// open one.
    TransportRefusedBySize,
    /// The same rule set aside: too large for a datagram, the caller said no
    /// stream could be had, and `DatagramLimit::without_stream_bytes` sent it
    /// over the datagram anyway. Carries the size and that limit.
    TransportKeptOnDatagram,
    /// The same rule met by writing the request smaller: too large for a
    /// datagram in full, so it went out in RFC 3261 §7.3.3's compact form
    /// (`DatagramLimit::compaction`), and without its `Allow` when that was
    /// not enough. Carries the size it went out at and the limit; the
    /// promotion or refusal that follows, when it still did not fit, is an
    /// entry of its own.
    TransportCompactedBySize,
    /// A transport closed or failed, and everything running on it was failed
    /// with it.
    TransportLost,
    /// RFC 5626 §4.4.1: ten seconds without a pong on a flow that has answered
    /// one before, so the flow is dead and was taken down.
    FlowDead,
    /// A request went on the wire. Carries its size as the bytes the caller
    /// writes, which is what B1 in `docs/13-client-requirements.md` asks to be
    /// readable without a capture.
    RequestSent,
    /// A retransmission timer fired and the same bytes went again.
    RequestRetransmitted,
    /// A peer's request was refused with a 503 because this endpoint is
    /// holding as many transactions or dialogs as it is configured to.
    RequestRefusedWhenFull,
    /// A request arrived framed and was refused with a 400 before anything
    /// acted on it, because a field that carries the message could not be
    /// read (RFC 3261 §8.2.x: a UAS that detects a syntax error answers 400
    /// and names the problem). An ACK draws no answer, so it is dropped here
    /// instead, under the same reason.
    RequestRefusedAsMalformed,
    /// A peer already inside a dialog was refused with a 503 because that one
    /// dialog is already holding as many non-INVITE server transactions as it
    /// may at once — a ceiling of its own, distinct from
    /// [`Self::RequestRefusedWhenFull`], because a request inside a dialog is
    /// never refused for the endpoint-wide one.
    RequestRefusedByDialog,
    /// A request the parser refused — past one of `msg::Limits`, or not
    /// well formed enough to be read at all — was answered from the fields
    /// that could still be recovered from it: 513 for one longer than the
    /// message bound (RFC 3261 §21.5.14), 400 with the reason in the phrase
    /// for anything else (§21.4.1). Carries the size and the limit when a
    /// bound on bytes was what refused it.
    RequestRefusedUnreadable,
    /// Bytes the parser refused that no answer could be written to: a
    /// response, an ACK, or a request whose `Via`, `From`, `To`, `Call-ID` or
    /// `CSeq` could not be recovered. Dropped, and this entry is the trace of
    /// it.
    MessageDroppedUnreadable,
    /// A response went on the wire.
    ResponseSent,
    /// A retransmission timer fired and the same response went again, which
    /// means the acknowledgement is not arriving.
    ResponseRetransmitted,
    /// A final response was retransmitted for 64·T1 and never acknowledged
    /// (RFC 3261 §17.2.1, timer H).
    TransactionUnacknowledged,
    /// A non-INVITE server transaction's application never sent a final
    /// response within 64·T1, so the endpoint answered 408 on its behalf
    /// (RFC 3261 §17.2.2 gives that state no timer of its own).
    RequestAnsweredByTimeout,
    /// A 2xx to a forked INVITE found no room under `max_dialogs` for the
    /// dialog it would have opened, so it was neither reported nor
    /// acknowledged (§13.3.1.4 has the far end give the call up with a BYE of
    /// its own).
    ForkDroppedAtLimit,
    /// A refusal arrived carrying a challenge this stack can answer
    /// (§22, RFC 8760).
    ChallengeReceived,
    /// The request went again carrying credentials.
    ChallengeAnswered,
    /// A challenge was not answered because the password is not for
    /// whoever asked: it came from somewhere other than the account's own
    /// server, or for a realm that is not the account's (RFC 3261 §22.1).
    /// The refusal stands. Carries the address the challenge came from.
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
    /// A registrar's 2xx carried a `Service-Route` that could not be read, or
    /// one longer than this stack puts on every request, so no service route
    /// was taken from it (RFC 3608 §6.1). Written by `sipral-ua`.
    ServiceRouteIgnored,
    /// A registrar's 2xx carried a `pub-gruu` or `temp-gruu` for this
    /// instance that could not be read, so that GRUU was not used (RFC 5627
    /// §4.2). Written by `sipral-ua`.
    GruuIgnored,
    /// A registrar's 2xx carried a `P-Associated-URI` that could not be read,
    /// so no associated identity was reported from it (RFC 7315 §4.1).
    /// Written by `sipral-ua`.
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

    /// Every variant this crate has, so that the tests below cannot silently
    /// stop covering one that was added afterwards.
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
        // the promise the type makes: a string names one decision and keeps
        // naming it, so a reader six months from now cannot be misled by a
        // code that was handed to something else
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
        // spelled out rather than derived, because a test that computes the
        // expected string from the variant proves nothing about stability
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
