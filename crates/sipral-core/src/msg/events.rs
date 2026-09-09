// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The fields the event framework adds: `Event` and `Subscription-State`
//! (RFC 6665 §8.2).
//!
//! ```text
//! Event              =  ( "Event" / "o" ) HCOLON event-type *( SEMI event-param )
//! event-type         =  event-package *( "." event-template )
//! token-nodot        =  1*( alphanum / "-" / "!" / "%" / "*"
//!                           / "_" / "+" / "`" / "'" / "~" )
//! Subscription-State =  "Subscription-State" HCOLON substate-value
//!                       *( SEMI subexp-params )
//! substate-value     =  "active" / "pending" / "terminated" / token
//! subexp-params      =  ("reason" EQUAL event-reason-value)
//!                     / ("expires" EQUAL delta-seconds)
//!                     / ("retry-after" EQUAL delta-seconds)
//!                     / generic-param
//! ```
//!
//! **`Event` is the one SIP token compared with case.** §8.2.1: "the
//! event-type portion of the `Event` header field is compared byte by byte,
//! and the `id` parameter token (if present) is compared byte by byte", and it
//! spells out the consequence — `Event: Foo; id=1234` does not match
//! `Event: foo; id=1234`. Everything else in this crate folds case on a token,
//! so [`EventRef::matches`] exists to keep that rule in one place instead of
//! letting it be forgotten at each call site.
//!
//! The other half of that rule is the one that bites: an `Event` with an `id`
//! never matches one without. Two subscriptions to the same package on one
//! dialog are told apart by nothing else, and a subscriber that ignores `id`
//! feeds one notifier's state into the other's machine.
//!
//! **A `Subscription-State` value is not read the same way in every state.**
//! §4.1.3 gives `expires` meaning only under `active` and `pending`, and
//! `reason` and `retry-after` meaning only under `terminated` — and it says a
//! subscriber "MUST ignore" an `expires` on a terminated one. This reads the
//! parameters as written and says which state they came with; refusing to act
//! on the wrong ones is the subscriber's, because it is behaviour rather than
//! syntax.

use std::borrow::Cow;

use super::error::HeaderError;
use super::lex::{Params, trim};
use super::scalar::{Digits, digits};

/// An `Event` value: which package, and which subscription to it.
#[derive(Clone, Copy, Debug)]
pub struct EventRef<'a> {
    package: &'a [u8],
    raw: &'a [u8],
}

impl<'a> EventRef<'a> {
    /// Read one `Event` value.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] when the event type is empty or holds a byte
    /// `token-nodot` does not allow. A package name is what decides which
    /// machine a NOTIFY is handed to, so one that is not a token is refused
    /// rather than matched loosely.
    pub fn parse(value: &'a [u8]) -> Result<Self, HeaderError> {
        let (package, _) = Params::split(value);
        if package.is_empty() {
            return Err(HeaderError::Malformed("Event names no package"));
        }
        // "." separates a package from its templates, and every other byte has
        // to be one token-nodot allows
        if !package.iter().all(|byte| is_nodot(*byte) || *byte == b'.') {
            return Err(HeaderError::Malformed("Event is not an event-type"));
        }
        Ok(Self {
            package,
            raw: value,
        })
    }

    /// The event type, as written: the package and any templates on it.
    #[must_use]
    pub const fn package(&self) -> &'a [u8] {
        self.package
    }

    /// The `id` parameter, when there is one.
    ///
    /// §8.4 calls its use deprecated and keeps it for compatibility, which is
    /// exactly why it has to be read: a notifier that sends one expects it
    /// back, and §8.2.1 makes its absence and its presence different values.
    #[must_use]
    pub fn id(&self) -> Option<Cow<'a, [u8]>> {
        self.params().get("id")
    }

    /// Everything after the event type.
    #[must_use]
    pub fn params(&self) -> Params<'a> {
        Params::split(self.raw).1
    }

    /// Whether two `Event` values name the same subscription (§8.2.1).
    ///
    /// Byte for byte on both halves, and no other parameter is looked at.
    #[must_use]
    pub fn matches(&self, other: &EventRef<'_>) -> bool {
        self.package == other.package
            && match (self.id(), other.id()) {
                (Some(ours), Some(theirs)) => ours == theirs,
                (None, None) => true,
                _ => false,
            }
    }
}

/// Where a subscription is, as the notifier reports it (§4.1.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Substate<'a> {
    /// Accepted, and in general authorised.
    Active,
    /// The notifier has it and has not decided yet.
    Pending,
    /// Over. `reason` says whether trying again is worth anything.
    Terminated,
    /// A value some other specification defined. §8.4's `extension-substate`
    /// is any token, so one that is not known is carried rather than refused.
    Other(&'a [u8]),
}

/// A `Subscription-State` value.
#[derive(Clone, Copy, Debug)]
pub struct SubscriptionStateRef<'a> {
    state: Substate<'a>,
    raw: &'a [u8],
}

impl<'a> SubscriptionStateRef<'a> {
    /// Read one `Subscription-State` value.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] when there is no substate value at all.
    /// Every NOTIFY has to carry one (§4.1.3), and a notification that does
    /// not say where the subscription is says nothing a subscriber can act on.
    pub fn parse(value: &'a [u8]) -> Result<Self, HeaderError> {
        let (head, _) = Params::split(value);
        let head = trim(head);
        if head.is_empty() {
            return Err(HeaderError::Malformed("Subscription-State names no state"));
        }
        // §8.4's substate-value is a token, and tokens fold case; only the
        // event-type of §8.2.1 is compared with case
        let state = if head.eq_ignore_ascii_case(b"active") {
            Substate::Active
        } else if head.eq_ignore_ascii_case(b"pending") {
            Substate::Pending
        } else if head.eq_ignore_ascii_case(b"terminated") {
            Substate::Terminated
        } else {
            Substate::Other(head)
        };
        Ok(Self { state, raw: value })
    }

    /// Which of the three states, or the token that was written instead.
    #[must_use]
    pub const fn state(&self) -> Substate<'a> {
        self.state
    }

    /// The `expires` parameter, in seconds.
    ///
    /// §4.1.3 makes this authoritative over what the SUBSCRIBE transaction
    /// negotiated, under `active` and `pending`. Under `terminated` it has no
    /// meaning and subscribers "MUST ignore any such parameter, if present" —
    /// which is the caller's to do, because this reads the field.
    #[must_use]
    pub fn expires(&self) -> Option<Digits> {
        self.number("expires")
    }

    /// The `retry-after` parameter, in seconds.
    #[must_use]
    pub fn retry_after(&self) -> Option<Digits> {
        self.number("retry-after")
    }

    /// The `reason` parameter, as written.
    #[must_use]
    pub fn reason(&self) -> Option<Cow<'a, [u8]>> {
        self.params().get("reason")
    }

    /// Everything after the substate value.
    #[must_use]
    pub fn params(&self) -> Params<'a> {
        Params::split(self.raw).1
    }

    fn number(&self, name: &str) -> Option<Digits> {
        digits(&self.params().get(name)?).ok()
    }
}

/// One byte of `token-nodot` (§8.4).
const fn is_nodot(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

#[cfg(test)]
mod tests {
    use super::{EventRef, SubscriptionStateRef, Substate};
    use crate::msg::HeaderError;

    fn event(value: &[u8]) -> EventRef<'_> {
        EventRef::parse(value).expect("an Event value")
    }

    fn substate(value: &[u8]) -> SubscriptionStateRef<'_> {
        SubscriptionStateRef::parse(value).expect("a Subscription-State value")
    }

    #[test]
    fn an_event_is_a_package_and_its_parameters() {
        let value = event(b"dialog;id=4321");
        assert_eq!(value.package(), b"dialog");
        assert_eq!(value.id().as_deref(), Some(&b"4321"[..]));

        let plain = event(b"message-summary");
        assert_eq!(plain.package(), b"message-summary");
        assert!(plain.id().is_none());
    }

    #[test]
    fn a_template_package_keeps_its_dot() {
        // 5.2's event template-packages: "presence.winfo"
        assert_eq!(event(b"presence.winfo").package(), b"presence.winfo");
    }

    #[test]
    fn matching_is_byte_for_byte_and_the_rfc_gives_the_examples() {
        // 8.2.1: "'Event: foo; id=1234' would match 'Event: foo; param=abcd;
        // id=1234', but not 'Event: foo' ('id' does not match) or 'Event: Foo;
        // id=1234' ('Event' portion does not match)"
        let ours = event(b"foo; id=1234");
        assert!(ours.matches(&event(b"foo; param=abcd; id=1234")));
        assert!(!ours.matches(&event(b"foo")));
        assert!(!ours.matches(&event(b"Foo; id=1234")));
        assert!(event(b"foo").matches(&event(b"foo;param=abcd")));
    }

    #[test]
    fn a_value_that_is_not_an_event_type_is_refused() {
        for value in [&b""[..], &b";id=1"[..], &b"two words"[..], &b"a@b"[..]] {
            assert!(
                matches!(EventRef::parse(value), Err(HeaderError::Malformed(_))),
                "{}",
                String::from_utf8_lossy(value)
            );
        }
    }

    #[test]
    fn the_three_states_fold_case_and_anything_else_is_carried() {
        assert_eq!(substate(b"active").state(), Substate::Active);
        assert_eq!(substate(b"Pending").state(), Substate::Pending);
        assert_eq!(substate(b"TERMINATED").state(), Substate::Terminated);
        assert_eq!(
            substate(b"waiting;retry-after=60").state(),
            Substate::Other(b"waiting")
        );
        assert!(matches!(
            SubscriptionStateRef::parse(b";expires=60"),
            Err(HeaderError::Malformed(_))
        ));
    }

    #[test]
    fn the_parameters_are_read_as_written() {
        let value = substate(b"terminated;reason=probation;retry-after=1800");
        assert_eq!(value.reason().as_deref(), Some(&b"probation"[..]));
        assert_eq!(
            value.retry_after().and_then(|d| d.require().ok()),
            Some(1800)
        );
        assert!(value.expires().is_none());

        let live = substate(b"active ; expires=3600");
        assert_eq!(live.expires().and_then(|d| d.require().ok()), Some(3600));
    }

    #[test]
    fn a_number_that_does_not_fit_says_so_rather_than_wrapping() {
        // scalar02 of RFC 4475 is the same shape one field along
        let value = substate(b"active;expires=100000000000");
        assert_eq!(
            value.expires().map(super::Digits::require),
            Some(Err(HeaderError::OutOfRange))
        );
        assert!(substate(b"active;expires=soon").expires().is_none());
    }
}
