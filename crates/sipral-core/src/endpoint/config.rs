// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What an endpoint is told once, and then never asked again.
//!
//! Every value here has a default that works against a normal registrar on a
//! normal network. They are settable because the field is full of networks
//! that are not normal: carriers whose round trip is long enough that T1 at
//! 500 ms retransmits into its own echo, access networks whose real MTU is
//! nowhere near Ethernet's, and firewalls that drop an idle connection in
//! well under the two minutes RFC 5626 assumes.

use std::time::Duration;

use crate::diag::RecordLimits;
use crate::msg::{Limits, ParseMode};
use crate::transaction::TimerConfig;

/// The size rule of RFC 3261 §18.1.1, as two numbers.
///
/// "If a request is within 200 bytes of the path MTU, or if it is larger than
/// 1300 bytes and the path MTU is unknown, the request MUST be sent using an
/// RFC 2914 congestion controlled transport protocol, such as TCP."
///
/// The RFC explains both figures: the 200 bytes are headroom for a response
/// that is larger than its request, because a proxy adds `Record-Route` on
/// the way back, and 1300 is what is left of a 1500-byte Ethernet MTU once
/// that headroom is taken off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatagramLimit {
    /// The path MTU, when the caller knows it. Nothing here measures one.
    pub path_mtu: Option<u32>,
    /// How much of a known MTU to leave for the response. 200.
    pub headroom_bytes: u32,
    /// The largest request to put in a datagram when the MTU is unknown. 1300.
    pub max_datagram_bytes: u32,
    /// The largest request to send over the datagram anyway, once the caller
    /// has said the stream §18.1.1 asked for cannot be had
    /// ([`Endpoint::no_stream_coming`](super::Endpoint::no_stream_coming)).
    ///
    /// **A deliberate deviation from §18.1.1**, off (`None`) by default, for
    /// a server that takes SIP over UDP alone: a PBX with no TCP listener
    /// answers a request it cannot receive over a stream with nothing, while
    /// the same PBX takes a 1,444-byte INVITE over UDP from every other phone
    /// on its network. What the rule guards against is fragmentation on a
    /// path whose MTU nobody measured; a caller that knows its path is better
    /// served by [`DatagramLimit::path_mtu`], and this is for the one that
    /// has only the server's word. A request past this size is still not
    /// sent, and ends as it would without it. Each request that goes over
    /// the datagram this way is recorded as `transport.kept.datagram`, with
    /// its size and this limit.
    pub without_stream_bytes: Option<u32>,
    /// When a request bound for a datagram is written in its compact form
    /// ([`Compaction`]). Only when it would not fit otherwise, by default.
    pub compaction: Compaction,
}

/// When a request bound for a datagram is written small, before RFC 3261
/// §18.1.1 moves it to a stream.
///
/// Compact means what `msg::compact_request` writes: the one-letter names
/// §7.3.3 gives `Via`, `From`, `To`, `Call-ID`, `Contact`, `Supported`,
/// `Content-Type`, `Content-Length` and the rest of RFC 3261's own, no space
/// after a colon, and lists of tokens without spaces. That is about ninety
/// bytes off an INVITE, the same message to every parser §7.3.3 holds to
/// accepting both forms. A request still too large then goes without its
/// `Allow` (§20.5 lets it, §13.2.1 asks for it in an INVITE), which is eighty
/// more; one still too large after that goes to a stream as before, written
/// in full there, where size is not a question.
///
/// A stream transport is never written compact: the rule is for a datagram.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Compaction {
    /// Every request in full, and §18.1.1 decides on the full size.
    Never,
    /// A request too large for a datagram is written compact first, and only
    /// what is too large even so leaves the datagram. The default: a request
    /// that fits goes out as readable as it was built, and one that would
    /// have asked for a stream — which a server on UDP alone never answers —
    /// goes out over the datagram whenever being compact is enough.
    #[default]
    WhenOversize,
    /// Every request bound for a datagram is written compact, whatever its
    /// size, for a path known to be narrower than the limit says: a tunnel
    /// with a 1280-byte MTU fragments what §18.1.1's 1300 still lets
    /// through. `Allow` is still only left out of one that does not fit.
    Always,
}

impl DatagramLimit {
    /// The figures from §18.1.1.
    pub const DEFAULT: Self = Self {
        path_mtu: None,
        headroom_bytes: 200,
        max_datagram_bytes: 1_300,
        without_stream_bytes: None,
        compaction: Compaction::WhenOversize,
    };

    /// Whether a request of this size goes over the datagram once no stream
    /// is coming ([`DatagramLimit::without_stream_bytes`]).
    #[must_use]
    pub fn fits_without_stream(&self, request_bytes: usize) -> bool {
        self.without_stream_bytes
            .is_some_and(|largest| u32::try_from(request_bytes).is_ok_and(|size| size <= largest))
    }

    /// The largest request that still goes in a datagram, and `None` when the
    /// configured MTU leaves room for none at all.
    ///
    /// A size that did not fit says nothing on its own, so this is the other
    /// half of what a bug report needs: the number the request was measured
    /// against. It is carried by [`Event::TransportWanted`], which is where an
    /// application reads it.
    ///
    /// [`Event::TransportWanted`]: super::Event::TransportWanted
    #[must_use]
    pub const fn largest_datagram_request(&self) -> Option<u32> {
        match self.path_mtu {
            // "within 200 bytes of the path MTU" — at the boundary too, since
            // a request exactly 200 bytes short of the MTU leaves a response
            // no room at all, so the last size that fits is one below the
            // difference
            Some(mtu) => match mtu.checked_sub(self.headroom_bytes) {
                Some(room) => room.checked_sub(1),
                None => None,
            },
            None => Some(self.max_datagram_bytes),
        }
    }

    /// Whether a request of this size has to leave over something congestion
    /// controlled rather than over a datagram.
    #[must_use]
    pub fn too_big_for_a_datagram(&self, request_bytes: usize) -> bool {
        let Ok(size) = u32::try_from(request_bytes) else {
            // larger than four gigabytes is not a datagram by any reading
            return true;
        };
        self.largest_datagram_request()
            .is_none_or(|largest| size > largest)
    }
}

impl Default for DatagramLimit {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Everything an endpoint is configured with.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct EndpointConfig {
    /// T1, T2 and T4, from which every RFC 3261 §17 timer is derived.
    pub timers: TimerConfig,
    /// How strictly to read what arrives. Lenient by default: real
    /// deployments emit malformed messages daily, and a stack that refuses
    /// them loses calls a competitor completes.
    pub parse_mode: ParseMode,
    /// The parser's bounds, which are what stops a hostile peer from making
    /// it do unbounded work.
    pub limits: Limits,
    /// The same, one layer down, for the session description a message body
    /// carries (RFC 4566). The message is bounded before its body is even
    /// looked at; this is what bounds the body once it is.
    pub sdp_limits: crate::sdp::Limits,
    /// When a request is too large for a datagram (§18.1.1).
    pub datagram_limit: DatagramLimit,
    /// Whether to put `;rport` on every `Via` we write (RFC 3581 §3).
    ///
    /// The RFC makes this a MAY. It is on, because the alternative is not
    /// receiving responses from behind the NAT that nearly every softphone
    /// sits behind, and a server that does not implement RFC 3581 ignores an
    /// empty `rport` rather than failing on it.
    pub always_request_rport: bool,
    /// The longest a stream transport may sit idle before a double-CRLF goes
    /// out on it (RFC 5626 §4.4.1). `None` turns keepalives off.
    ///
    /// This is an upper bound, not a period: §4.4.1 requires the interval to
    /// be picked at random between it and 20% below it, so that a server does
    /// not get every client's ping at the same instant.
    pub keepalive_interval: Option<Duration>,
    /// The most server transactions a peer may have open here at once.
    ///
    /// Once the parser has refused what it can refuse, an arriving request is a
    /// well-formed request, and a peer that sends a thousand of them a second
    /// costs a transaction each. This is the ceiling on that: past it a request
    /// that would create a new server transaction is answered 503 rather than
    /// held, and the endpoint keeps answering the ones it already has.
    pub max_server_transactions: usize,
    /// The most dialogs that may be live at once, in either direction.
    ///
    /// A transaction lasts seconds and a dialog lasts as long as the call, so
    /// this is the one a slow flood reaches: a thousand INVITEs that are all
    /// answered leave a thousand calls standing.
    ///
    /// An incoming call counts from the moment its INVITE is let in, not from
    /// the 180 or 2xx of this end's that makes its dialog: counted any later,
    /// every INVITE that arrived before the first of them was answered would
    /// be let in, and answering them would pass the ceiling.
    ///
    /// A call this end places counts from its INVITE on, for the same reason:
    /// it is a dialog the moment anything answers it. One placed when the
    /// dialogs, the calls let in and the calls placed and not yet answered
    /// already come to this is refused with [`super::SendError::LimitReached`]
    /// before anything goes out, and a refusal from the far end gives its
    /// room back at once.
    ///
    /// A fork is held to it too. The first dialog of an INVITE this end sent
    /// always opens, and so does the first 2xx to it, since between them they
    /// are the call the application placed: a forking proxy can ring one
    /// phone and have another answer. Each further branch opens only while
    /// there is room. One that finds none is
    /// reported as a provisional without a dialog, or, when it is a 2xx, is
    /// not acknowledged here, and the far end gives it up with a BYE of its own
    /// (RFC 3261 §13.3.1.4).
    pub max_dialogs: usize,
    /// How much of what the endpoint decided it keeps
    /// ([`crate::diag`]).
    ///
    /// Another ceiling on what a peer can make this endpoint spend, and the
    /// only one whose cost is paid on calls that succeed as well as on the
    /// ones that do not.
    pub diagnostics: RecordLimits,
}

impl EndpointConfig {
    /// The defaults.
    ///
    /// `keepalive_interval` is 25 s rather than the 120 s RFC 5626 §4.4.1
    /// suggests. That figure assumes a network which leaves an idle TCP
    /// connection alone for longer than two minutes, and carrier-grade NATs
    /// routinely do not; a softphone that discovers a dead flow two minutes
    /// after it died has already missed the call it existed for. The cost is
    /// four bytes every 25 seconds per connection.
    ///
    /// The two ceilings are set where a softphone will never see them and a
    /// flood will: 256 concurrent server transactions is an order of magnitude
    /// more than a busy desk phone reaches, and 128 live dialogs is more calls
    /// than one person can hold. A media server built on this crate raises
    /// them; nothing here has to guess how far.
    pub const DEFAULT: Self = Self {
        timers: TimerConfig::DEFAULT,
        parse_mode: ParseMode::Lenient,
        limits: Limits::DEFAULT,
        sdp_limits: crate::sdp::Limits::DEFAULT,
        datagram_limit: DatagramLimit::DEFAULT,
        always_request_rport: true,
        keepalive_interval: Some(Duration::from_secs(25)),
        max_server_transactions: 256,
        max_dialogs: 128,
        diagnostics: RecordLimits::DEFAULT,
    };
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::{DatagramLimit, EndpointConfig};
    use std::time::Duration;

    #[test]
    fn with_no_known_mtu_the_line_is_1300() {
        let limit = DatagramLimit::DEFAULT;
        assert!(!limit.too_big_for_a_datagram(1_300));
        assert!(limit.too_big_for_a_datagram(1_301));
        assert!(!limit.too_big_for_a_datagram(0));
    }

    #[test]
    fn a_known_mtu_keeps_200_bytes_back_for_the_response() {
        // the headroom is there because a response can be larger than its
        // request: a proxy adds Record-Route on the way back
        let limit = DatagramLimit {
            path_mtu: Some(1_500),
            ..DatagramLimit::DEFAULT
        };
        assert!(!limit.too_big_for_a_datagram(1_299));
        assert!(limit.too_big_for_a_datagram(1_300));
        assert!(limit.too_big_for_a_datagram(1_400));
    }

    #[test]
    fn a_small_mtu_moves_the_line_with_it() {
        // access networks where the real MTU is nowhere near Ethernet's are
        // the reason this is configurable at all
        let limit = DatagramLimit {
            path_mtu: Some(576),
            ..DatagramLimit::DEFAULT
        };
        assert!(!limit.too_big_for_a_datagram(375));
        assert!(limit.too_big_for_a_datagram(376));
    }

    #[test]
    fn an_mtu_smaller_than_the_headroom_sends_nothing_by_datagram() {
        let limit = DatagramLimit {
            path_mtu: Some(100),
            ..DatagramLimit::DEFAULT
        };
        assert!(limit.too_big_for_a_datagram(0));
    }

    #[test]
    fn a_size_that_does_not_fit_in_the_arithmetic_is_too_big() {
        let limit = DatagramLimit::DEFAULT;
        assert!(limit.too_big_for_a_datagram(usize::MAX));
    }

    #[test]
    fn the_limit_reported_is_the_last_size_that_would_have_gone() {
        assert_eq!(
            DatagramLimit::DEFAULT.largest_datagram_request(),
            Some(1_300)
        );
        assert_eq!(
            DatagramLimit {
                path_mtu: Some(1_500),
                ..DatagramLimit::DEFAULT
            }
            .largest_datagram_request(),
            Some(1_299)
        );
        // no room for a request of any size, not even an empty one
        assert_eq!(
            DatagramLimit {
                path_mtu: Some(200),
                ..DatagramLimit::DEFAULT
            }
            .largest_datagram_request(),
            None
        );
    }

    #[test]
    fn the_limit_reported_is_the_one_the_switch_was_decided_on() {
        // the two are read side by side in a bug report — "1785 bytes, limit
        // 1299" — so a limit that disagreed with the decision would be worse
        // than none at all
        for mtu in [None, Some(200), Some(576), Some(1_500), Some(9_000)] {
            let limit = DatagramLimit {
                path_mtu: mtu,
                ..DatagramLimit::DEFAULT
            };
            let largest = limit
                .largest_datagram_request()
                .map(|largest| usize::try_from(largest).expect("a size that fits a pointer"));
            for size in 0..2_000_usize {
                assert_eq!(
                    limit.too_big_for_a_datagram(size),
                    largest.is_none_or(|largest| size > largest),
                    "{mtu:?} at {size}"
                );
            }
        }
    }

    #[test]
    fn the_defaults_are_the_ones_the_documents_promise() {
        let config = EndpointConfig::default();
        assert_eq!(config.timers.t1, Duration::from_millis(500));
        assert!(config.always_request_rport);
        assert_eq!(config.keepalive_interval, Some(Duration::from_secs(25)));
        assert_eq!(config.datagram_limit.max_datagram_bytes, 1_300);
        assert_eq!(config.datagram_limit.headroom_bytes, 200);
        assert_eq!(config.datagram_limit.path_mtu, None);
        // §18.1.1 is kept unless a deployment says otherwise
        assert_eq!(config.datagram_limit.without_stream_bytes, None);
        assert!(!config.datagram_limit.fits_without_stream(1));
        assert_eq!(config.max_server_transactions, 256);
        assert_eq!(config.max_dialogs, 128);
        assert_eq!(config.diagnostics.max_decisions, 64);
        assert_eq!(config.diagnostics.max_records, 32);
    }

    #[test]
    fn the_size_kept_on_the_datagram_without_a_stream_is_inclusive() {
        let limit = DatagramLimit {
            without_stream_bytes: Some(1_500),
            ..DatagramLimit::DEFAULT
        };
        assert!(limit.fits_without_stream(1_500));
        assert!(!limit.fits_without_stream(1_501));
        // and it moves nothing about §18.1.1's own line
        assert!(limit.too_big_for_a_datagram(1_301));
    }
}
