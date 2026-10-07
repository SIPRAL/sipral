// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
//! `Event` is the one SIP token compared with case (§8.2.1): `Foo` does not
//! match `foo`, and an `Event` with an `id` never matches one without. Two
//! subscriptions to one package on a dialog differ only by `id`.
//! [`EventRef::matches`] keeps that rule in one place.
//!
//! In `Subscription-State`, `expires` means something only under `active`
//! and `pending`, `reason` and `retry-after` only under `terminated`
//! (§4.1.3). They are read as written; ignoring the wrong ones is the
//! subscriber's job.

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
    /// `token-nodot` does not allow.
    pub fn parse(value: &'a [u8]) -> Result<Self, HeaderError> {
        let (package, _) = Params::split(value);
        if package.is_empty() {
            return Err(HeaderError::Malformed("Event names no package"));
        }
        // "." separates package from templates
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

    /// The `id` parameter, when there is one. Deprecated by §8.4 but still
    /// sent, and its presence changes the value (§8.2.1).
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
    /// Byte for byte on type and `id`, nothing else.
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
    /// A value another specification defined (§8.4 `extension-substate`).
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
    /// [`HeaderError::Malformed`] when there is no substate value (§4.1.3).
    pub fn parse(value: &'a [u8]) -> Result<Self, HeaderError> {
        let (head, _) = Params::split(value);
        let head = trim(head);
        if head.is_empty() {
            return Err(HeaderError::Malformed("Subscription-State names no state"));
        }
        // substate-value is a token, so case folds here
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
    /// Authoritative under `active` and `pending` (§4.1.3). Under `terminated`
    /// the caller MUST ignore it.
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
        let value = substate(b"active;expires=100000000000");
        assert_eq!(
            value.expires().map(super::Digits::require),
            Some(Err(HeaderError::OutOfRange))
        );
        assert!(substate(b"active;expires=soon").expires().is_none());
    }
}
