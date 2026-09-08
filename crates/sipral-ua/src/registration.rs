// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Keeping a binding alive, and knowing when to stop trying.
//!
//! Registration is the one part of SIP that a user agent has to keep doing for
//! as long as it is switched on, and the two numbers that decide whether it
//! works are both policy rather than protocol: when to refresh, and how long to
//! wait after a failure.
//!
//! **When to refresh.** RFC 3261 §10.2.4 says only "before the expiration
//! interval has elapsed". Cutting it fine is how a phone stops receiving calls
//! for thirty seconds every hour: one lost datagram and the binding is gone
//! before the retransmission arrives. So the refresh goes at 0.85 of what the
//! registrar granted, and never later than thirty seconds before it lapses,
//! which leaves room for a lost REGISTER and a full retransmission round. Never
//! sooner than halfway either, so that a registrar handing out very short
//! bindings does not turn the client into a metronome.
//!
//! **How long to wait.** RFC 5626 §4.5 has the schedule, and it is used here
//! for the same reason it exists there: a thousand phones that lost the same
//! server must not come back in the same second. `W = min(max, base · 2^n)`,
//! and the actual wait is drawn uniformly between half of W and W.
//!
//! What is *not* retried is the other half of this. A registrar that says 403
//! will say 403 again, and a password that was refused will be refused again —
//! and re-sending it is how an account gets locked out. Those stop, and say so.

use std::time::{Duration, Instant};

use sipral_core::dialog::CallId;
use sipral_core::msg::{Contacts, HeaderError, OwnedMessage, RawMessage, Uri, digits};
use sipral_core::transaction::{NonInviteClient, TransactionId};

use crate::event::RegistrationState;

/// The fraction of the granted interval at which the refresh goes.
const REFRESH_FRACTION: u64 = 85;
/// And how long before the binding lapses it must go at the latest.
const REFRESH_MARGIN: u64 = 30;
/// RFC 5626 §4.5: "base-time (if all failed) with a default of 30 seconds".
const BACKOFF_BASE: u64 = 30;
/// "max-time with a default of 1800 seconds".
const BACKOFF_MAX: u64 = 1_800;
/// The doubling stops mattering here; going higher only risks the shift.
const BACKOFF_CEILING: u32 = 16;

/// Everything one account's registration is doing.
#[derive(Debug)]
pub(crate) struct Registration {
    pub(crate) state: RegistrationState,
    /// §10.2.4: "A UA SHOULD use the same Call-ID for all registrations during
    /// a single boot cycle."
    pub(crate) call_id: CallId,
    /// §10.2: the number grows across refreshes, so a registrar can tell a
    /// refresh from a replay.
    pub(crate) cseq: u32,
    /// The REGISTER in flight, when there is one.
    pub(crate) transaction: Option<TransactionId<NonInviteClient>>,
    /// The interval being asked for, which a 423 may raise once (§10.2.8).
    pub(crate) asking: Duration,
    /// Whether a 423 has already raised it. A second one is the registrar
    /// contradicting itself, and is not chased.
    pub(crate) raised: bool,
    /// When the next thing happens: a refresh, or a retry.
    pub(crate) due: Option<Instant>,
    /// Consecutive failures worth retrying, which is what the back-off counts.
    pub(crate) failures: u32,
    /// A de-registration is in flight, so its 200 is not read as a binding.
    pub(crate) unregistering: bool,
    /// A challenge came back and it is not yet known whether anything could
    /// read it. The refusal is kept for the event that says so.
    pub(crate) unanswered: Option<OwnedMessage>,
}

impl Registration {
    pub(crate) fn new(call_id: CallId, asking: Duration) -> Self {
        Self {
            state: RegistrationState::Idle,
            call_id,
            cseq: 0,
            transaction: None,
            asking,
            raised: false,
            due: None,
            failures: 0,
            unregistering: false,
            unanswered: None,
        }
    }

    /// Whether a binding is believed to be live, which is what a refresh has
    /// to protect and a first registration does not.
    pub(crate) const fn is_bound(&self) -> bool {
        matches!(
            self.state,
            RegistrationState::Registered | RegistrationState::Refreshing
        )
    }
}

/// When to send the next REGISTER for a binding granted for `granted`.
///
/// See the module note. Zero in means the registrar removed the binding, and
/// there is nothing to refresh.
pub(crate) fn refresh_after(granted: Duration) -> Duration {
    let seconds = granted.as_secs();
    if seconds == 0 {
        return Duration::ZERO;
    }
    let fraction = seconds.saturating_mul(REFRESH_FRACTION) / 100;
    let margin = seconds.saturating_sub(REFRESH_MARGIN);
    // never sooner than halfway, and never zero: a binding of a second or two
    // is a registrar being strange, and answering it with a spin is worse
    let floor = (seconds / 2).max(1);
    Duration::from_secs(fraction.min(margin).max(floor))
}

/// RFC 5626 §4.5's upper bound after `failures` consecutive failures.
///
/// `W = min(max-time, base-time · 2^consecutive-failures)`.
pub(crate) fn backoff_bound(failures: u32) -> Duration {
    let doublings = failures.min(BACKOFF_CEILING);
    let scaled = BACKOFF_BASE.saturating_mul(1_u64 << doublings);
    Duration::from_secs(scaled.min(BACKOFF_MAX))
}

/// "a uniform random time between 50 and 100% of the upper-bound wait time",
/// spread by `entropy`.
///
/// `entropy` is a token from the endpoint's own stream, which is hexadecimal;
/// its first eight characters are thirty-two bits drawn from that stream. The
/// modulo is biased by less than one part in a hundred million over these
/// ranges, which is far below the second this value is rounded to.
pub(crate) fn backoff_delay(failures: u32, entropy: &[u8]) -> Duration {
    let bound = backoff_bound(failures).as_secs();
    let half = bound / 2;
    let span = bound - half;
    if span == 0 {
        return Duration::from_secs(bound);
    }
    Duration::from_secs(half + u64::from(spread(entropy)) % (span + 1))
}

/// Thirty-two bits off the front of a hexadecimal token.
pub(crate) fn spread(entropy: &[u8]) -> u32 {
    let mut value = 0_u32;
    for byte in entropy.iter().take(8) {
        let digit = match *byte {
            b'0'..=b'9' => u32::from(*byte - b'0'),
            b'a'..=b'f' => u32::from(*byte - b'a') + 10,
            b'A'..=b'F' => u32::from(*byte - b'A') + 10,
            _ => 0,
        };
        value = (value << 4) | digit;
    }
    value
}

/// How long the registrar says the binding lasts (§10.2.4).
///
/// The `expires` parameter of the `Contact` it echoed back for us wins, then
/// the `Expires` header field, then what was asked for. Our own contact is
/// found by §19.1.4 equivalence rather than by byte comparison, because a
/// registrar is allowed to normalise what it stores.
///
/// A contact list that does not name us is not read as a removal. Registrars
/// rewrite addresses behind a NAT, and concluding "the binding was refused"
/// from an address that no longer matches would drop a working registration.
/// Only a stated zero means removed.
pub(crate) fn granted_expiry(
    response: &RawMessage<'_>,
    ours: &Uri,
    asked: Duration,
) -> Option<Duration> {
    if let Some(seconds) = ours_in(response, ours) {
        return Some(Duration::from_secs(u64::from(seconds)));
    }
    match response.expires() {
        Ok(value) => value
            .require()
            .ok()
            .map(|seconds| Duration::from_secs(u64::from(seconds))),
        Err(HeaderError::Missing) => Some(asked),
        Err(_) => None,
    }
}

/// The `expires` parameter on the contact the registrar echoed back for us.
fn ours_in(response: &RawMessage<'_>, ours: &Uri) -> Option<u32> {
    let Ok(Contacts::Addrs(addrs)) = response.contact() else {
        return None;
    };
    for addr in addrs {
        let Ok(addr) = addr else {
            continue;
        };
        let Ok(uri) = Uri::parse(addr.uri_bytes()) else {
            continue;
        };
        if !ours.equivalent(&uri) {
            continue;
        }
        return addr.expires().ok().flatten().and_then(|d| d.require().ok());
    }
    None
}

/// The `Min-Expires` of a 423, which §10.2.8 asks the next attempt to meet.
pub(crate) fn min_expires(response: &RawMessage<'_>) -> Option<Duration> {
    let value = response.header(sipral_core::msg::HeaderName::MinExpires)?;
    digits(value)
        .ok()?
        .require()
        .ok()
        .map(|seconds| Duration::from_secs(u64::from(seconds)))
}

/// A `Retry-After` in seconds, which RFC 5626 §4.5 lets extend the back-off.
///
/// Only the delta-seconds are read. The header can also carry a comment and
/// parameters, and neither changes when to come back.
pub(crate) fn retry_after(response: &RawMessage<'_>) -> Option<Duration> {
    let value = response.header(sipral_core::msg::HeaderName::RetryAfter)?;
    let seconds = value
        .iter()
        .copied()
        .skip_while(u8::is_ascii_whitespace)
        .take_while(u8::is_ascii_digit)
        .collect::<Vec<u8>>();
    digits(&seconds)
        .ok()?
        .require()
        .ok()
        .map(|seconds| Duration::from_secs(u64::from(seconds)))
}

#[cfg(test)]
mod tests {
    use super::{BACKOFF_MAX, backoff_bound, backoff_delay, refresh_after, spread};
    use std::time::Duration;

    #[test]
    fn a_refresh_leaves_room_for_a_lost_register_and_a_retransmission() {
        // an hour: 0.85 of it, well clear of the last thirty seconds
        assert_eq!(
            refresh_after(Duration::from_secs(3_600)),
            Duration::from_secs(3_060)
        );
        // two minutes: the thirty-second margin bites before the fraction does
        assert_eq!(
            refresh_after(Duration::from_secs(120)),
            Duration::from_secs(90)
        );
        // one minute: both agree
        assert_eq!(
            refresh_after(Duration::from_secs(60)),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn a_very_short_binding_does_not_turn_the_client_into_a_metronome() {
        // the margin would ask for a refresh at once, and the floor stops it
        for seconds in [1_u64, 5, 20, 30, 45] {
            let granted = Duration::from_secs(seconds);
            let after = refresh_after(granted);
            assert!(
                after.as_secs() >= seconds / 2 && !after.is_zero(),
                "{seconds}s granted refreshes after {after:?}"
            );
            assert!(after <= granted, "{seconds}s granted refreshes too late");
        }
    }

    #[test]
    fn a_removed_binding_has_nothing_to_refresh() {
        assert_eq!(refresh_after(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn the_backoff_doubles_and_then_stops() {
        // RFC 5626 4.5's worked example: base 30, three failures, 240 seconds
        assert_eq!(backoff_bound(0), Duration::from_secs(30));
        assert_eq!(backoff_bound(3), Duration::from_secs(240));
        assert_eq!(backoff_bound(6), Duration::from_secs(1_800));
        assert_eq!(
            backoff_bound(u32::MAX),
            Duration::from_secs(BACKOFF_MAX),
            "no shift overflow, however long the outage"
        );
    }

    #[test]
    fn the_wait_lands_between_half_the_bound_and_the_bound() {
        // "a uniform random time between 50 and 100% of the upper-bound"
        let mut seen = std::collections::HashSet::new();
        for nonce in 0_u32..500 {
            let token = format!("{nonce:08x}{nonce:08x}").into_bytes();
            let delay = backoff_delay(3, &token);
            assert!(delay >= Duration::from_secs(120), "{delay:?}");
            assert!(delay <= Duration::from_secs(240), "{delay:?}");
            seen.insert(delay);
        }
        assert!(seen.len() > 100, "the draw is barely moving");
    }

    #[test]
    fn the_first_retry_after_a_boot_failure_lands_where_the_rfc_says() {
        // "the first retry happens somewhere between 30 and 60 seconds after
        // the failure of the first registration request" - one failure, so the
        // bound has doubled once
        for nonce in 0_u32..200 {
            let token = format!("{nonce:016x}").into_bytes();
            let delay = backoff_delay(1, &token);
            assert!(delay >= Duration::from_secs(30), "{delay:?}");
            assert!(delay <= Duration::from_secs(60), "{delay:?}");
        }
    }

    #[test]
    fn a_token_that_is_not_hexadecimal_still_yields_a_number() {
        assert_eq!(spread(b"0000000f"), 15);
        assert_eq!(spread(b"ffffffff"), u32::MAX);
        assert_eq!(spread(b""), 0);
    }
}
