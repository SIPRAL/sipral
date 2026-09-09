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
    /// A transport closed or failed, and everything running on it was failed
    /// with it.
    TransportLost,
    /// RFC 5626 §4.4.1: ten seconds without a pong, so the flow is dead and
    /// was taken down.
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
    /// A response went on the wire.
    ResponseSent,
    /// A retransmission timer fired and the same response went again, which
    /// means the acknowledgement is not arriving.
    ResponseRetransmitted,
    /// A final response was retransmitted for 64·T1 and never acknowledged
    /// (RFC 3261 §17.2.1, timer H).
    TransactionUnacknowledged,
    /// A refusal arrived carrying a challenge this stack can answer
    /// (§22, RFC 8760).
    ChallengeReceived,
    /// The request went again carrying credentials.
    ChallengeAnswered,
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
}

impl Reason {
    /// The wire form, which never changes and is never reused.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TransportSelected => "transport.selected",
            Self::TransportPromotedBySize => "transport.promoted.size",
            Self::TransportRefusedBySize => "transport.refused.size",
            Self::TransportLost => "transport.lost",
            Self::FlowDead => "transport.flow.dead",
            Self::RequestSent => "request.sent",
            Self::RequestRetransmitted => "request.retransmitted",
            Self::RequestRefusedWhenFull => "request.refused.overload",
            Self::ResponseSent => "response.sent",
            Self::ResponseRetransmitted => "response.retransmitted",
            Self::TransactionUnacknowledged => "transaction.unacknowledged",
            Self::ChallengeReceived => "auth.challenge.received",
            Self::ChallengeAnswered => "auth.challenge.answered",
            Self::DialogCreated => "dialog.created",
            Self::DialogDestroyed => "dialog.destroyed",
            Self::FailedRefused => "failure.refused",
            Self::FailedTimeout => "failure.timeout",
            Self::FailedTransport => "failure.transport",
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
    const ALL: [Reason; 18] = [
        Reason::TransportSelected,
        Reason::TransportPromotedBySize,
        Reason::TransportRefusedBySize,
        Reason::TransportLost,
        Reason::FlowDead,
        Reason::RequestSent,
        Reason::RequestRetransmitted,
        Reason::RequestRefusedWhenFull,
        Reason::ResponseSent,
        Reason::ResponseRetransmitted,
        Reason::TransactionUnacknowledged,
        Reason::ChallengeReceived,
        Reason::ChallengeAnswered,
        Reason::DialogCreated,
        Reason::DialogDestroyed,
        Reason::FailedRefused,
        Reason::FailedTimeout,
        Reason::FailedTransport,
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
        assert_eq!(Reason::FailedRefused.as_str(), "failure.refused");
    }
}
