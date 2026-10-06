// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The record itself: ordered, bounded, and honest about what it dropped.

use core::fmt::Write as _;
use std::collections::VecDeque;
use std::time::Instant;

use super::json;
use super::{Decision, Wire};
use crate::dialog::CallId;

/// How much a record and a set of records may hold.
///
/// Both are ceilings on memory a peer can make this endpoint spend: a call
/// that runs for an hour keeps deciding things, and a flood arrives with a
/// fresh `Call-ID` every time. Neither may grow without end, and neither may
/// pretend it did not lose anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordLimits {
    /// The most decisions one record holds. Past it the oldest go and the
    /// count of them is kept.
    pub max_decisions: usize,
    /// The most calls that have a record at once. Past it the least recently
    /// written record goes, and the count of those is kept too.
    pub max_records: usize,
}

impl RecordLimits {
    /// The defaults.
    ///
    /// Sixty-four decisions is more than a call that connects and hangs up
    /// makes, and enough to hold a registration handshake, a fork of three and
    /// six retransmissions without losing the beginning. Thirty-two records is
    /// more calls, registrations and subscriptions than a softphone has in the
    /// air at once.
    ///
    /// Together they are the memory bound, and it is a quarter of a megabyte
    /// at the outside — a decision is under a hundred and twenty bytes, and
    /// nothing here holds a message. A caller on a device where that matters
    /// turns them down; a media server turns them up.
    pub const DEFAULT: Self = Self {
        max_decisions: 64,
        max_records: 32,
    };
}

impl Default for RecordLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What one call — or the endpoint itself — decided, in order.
#[derive(Clone, Debug)]
pub struct Record {
    call: Option<CallId>,
    /// The first moment anything was written here. Every entry's offset is
    /// measured from it, so a record read out of the endpoint means the same
    /// thing as one pasted into a bug report.
    epoch: Option<Instant>,
    limit: usize,
    entries: VecDeque<Decision>,
    dropped: u64,
}

impl Record {
    pub(crate) const fn new(call: Option<CallId>, limit: usize) -> Self {
        Self {
            call,
            epoch: None,
            limit,
            entries: VecDeque::new(),
            dropped: 0,
        }
    }

    /// Write a decision down, dropping the oldest if there is no room.
    pub(crate) fn push(&mut self, now: Instant, mut decision: Decision) {
        if self.limit == 0 {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        let epoch = *self.epoch.get_or_insert(now);
        // saturating, because a caller whose clock went backwards should get a
        // record with a flat spot in it rather than a panic
        decision.at = now.saturating_duration_since(epoch);
        while self.entries.len() >= self.limit {
            self.entries.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.entries.push_back(decision);
    }

    /// The call this is about, or `None` for the endpoint's own record.
    #[must_use]
    pub const fn call_id(&self) -> Option<&CallId> {
        self.call.as_ref()
    }

    /// The decisions, oldest first.
    pub fn decisions(&self) -> impl ExactSizeIterator<Item = &Decision> {
        self.entries.iter()
    }

    /// How many are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing has been decided yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many decisions were made and are no longer held.
    ///
    /// Never left out of the JSON. A record that quietly forgot its first
    /// twenty entries and says nothing is a record that answers "what happened
    /// first?" with a lie.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The record as JSON, ready to attach to a bug report.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out);
        out
    }

    pub(crate) fn write_json(&self, out: &mut String) {
        out.push_str("{\"call_id\":");
        match self.call {
            Some(ref call) => json::bytes(out, call.as_bytes()),
            None => out.push_str("null"),
        }
        let _ = write!(out, ",\"dropped\":{},\"decisions\":[", self.dropped);
        for (at, decision) in self.entries.iter().enumerate() {
            if at > 0 {
                out.push(',');
            }
            write_decision(out, decision);
        }
        out.push_str("]}");
    }
}

/// One entry, with only the fields that apply to it.
fn write_decision(out: &mut String, decision: &Decision) {
    let _ = write!(out, "{{\"at_us\":{},\"reason\":", decision.at.as_micros());
    json::string(out, decision.reason.as_str());
    if let Some(ref wire) = decision.wire {
        out.push_str(",\"direction\":");
        json::string(out, wire.direction.as_str());
        match wire.message {
            Wire::Request(ref method) => {
                out.push_str(",\"method\":");
                json::string(out, method.as_str());
            }
            Wire::Response(status) => {
                let _ = write!(out, ",\"status\":{}", status.get());
            }
        }
        let _ = write!(out, ",\"bytes\":{}", wire.bytes);
    }
    if let Some(address) = decision.address {
        out.push_str(",\"address\":");
        json::string(out, &address.to_string());
    }
    if let Some(protocol) = decision.protocol {
        out.push_str(",\"protocol\":");
        json::string(out, protocol.as_str());
    }
    if let Some(measure) = decision.measure {
        let _ = write!(
            out,
            ",\"size\":{},\"limit\":{}",
            measure.size, measure.limit
        );
    }
    out.push('}');
}

/// Every record one endpoint holds.
///
/// The endpoint's own record is separate rather than being one more entry,
/// because it must never be the one evicted: it is where a transport that
/// failed before any call existed is written down.
#[derive(Debug)]
pub(crate) struct Records {
    limits: RecordLimits,
    /// The time the caller last drove the endpoint at. A sans-I/O core has no
    /// other clock, and inside one call no time passes, so this is the instant
    /// every decision made during that call is stamped with.
    now: Option<Instant>,
    endpoint: Record,
    /// Least recently written first, so the one to evict is at the front.
    calls: Vec<Record>,
    dropped: u64,
}

impl Records {
    pub(crate) const fn new(limits: RecordLimits) -> Self {
        Self {
            limits,
            now: None,
            endpoint: Record::new(None, limits.max_decisions),
            calls: Vec::new(),
            dropped: 0,
        }
    }

    /// The time the caller is driving the endpoint at.
    pub(crate) const fn mark(&mut self, now: Instant) {
        self.now = Some(now);
    }

    /// Write a decision down against a call, or against the endpoint when it
    /// belongs to no call.
    ///
    /// Nothing is recorded before the caller has given the endpoint a time,
    /// which it does on the first call that takes one. There is no decision to
    /// make before then.
    pub(crate) fn note(&mut self, call: Option<&[u8]>, decision: Decision) {
        let Some(now) = self.now else {
            return;
        };
        match call {
            None => self.endpoint.push(now, decision),
            Some(call) => match self.for_call(call) {
                Some(record) => record.push(now, decision),
                None => self.dropped = self.dropped.saturating_add(1),
            },
        }
    }

    /// The record for a `Call-ID`, made if there is none and there is room.
    fn for_call(&mut self, call: &[u8]) -> Option<&mut Record> {
        if self.limits.max_records == 0 {
            return None;
        }
        if let Some(at) = self
            .calls
            .iter()
            .position(|record| record.call_id().is_some_and(|id| id.as_bytes() == call))
        {
            // the one written to most recently goes to the back, so a call
            // that has been quiet for an hour is the one evicted rather than
            // the one that merely started first
            let record = self.calls.remove(at);
            self.calls.push(record);
            return self.calls.last_mut();
        }
        while self.calls.len() >= self.limits.max_records {
            self.calls.remove(0);
            self.dropped = self.dropped.saturating_add(1);
        }
        self.calls.push(Record::new(
            Some(CallId::new(call)),
            self.limits.max_decisions,
        ));
        self.calls.last_mut()
    }

    /// What a call decided.
    pub(crate) fn record(&self, call: &CallId) -> Option<&Record> {
        self.calls
            .iter()
            .find(|record| record.call_id() == Some(call))
    }

    /// What the endpoint decided outside any call.
    pub(crate) const fn endpoint(&self) -> &Record {
        &self.endpoint
    }

    /// Every call with a record, least recently written first.
    pub(crate) fn calls(&self) -> impl Iterator<Item = &CallId> {
        self.calls.iter().filter_map(Record::call_id)
    }

    /// How many records were made and are no longer held.
    pub(crate) const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Everything, as one document.
    pub(crate) fn to_json(&self) -> String {
        let mut out = String::new();
        let _ = write!(out, "{{\"records_dropped\":{},\"records\":[", self.dropped);
        self.endpoint.write_json(&mut out);
        for record in &self.calls {
            out.push(',');
            record.write_json(&mut out);
        }
        out.push_str("]}");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{Record, RecordLimits, Records};
    use crate::diag::{Decision, Direction, Reason, WireEvent};
    use crate::dialog::CallId;
    use crate::endpoint::TransportProtocol;
    use crate::msg::{Method, StatusCode};
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    fn address() -> SocketAddr {
        "192.0.2.9:5060".parse().expect("a documentation address")
    }

    #[test]
    fn the_first_decision_is_the_epoch_and_the_rest_are_measured_from_it() {
        let start = Instant::now();
        let mut record = Record::new(None, 8);
        record.push(
            start + Duration::from_secs(5),
            Decision::of(Reason::FlowDead),
        );
        record.push(
            start + Duration::from_secs(7),
            Decision::of(Reason::TransportLost),
        );
        let offsets: Vec<Duration> = record.decisions().map(|entry| entry.at).collect();
        assert_eq!(offsets, vec![Duration::ZERO, Duration::from_secs(2)]);
    }

    #[test]
    fn a_clock_that_went_backwards_gives_a_flat_spot_rather_than_a_panic() {
        let start = Instant::now();
        let mut record = Record::new(None, 8);
        record.push(
            start + Duration::from_secs(5),
            Decision::of(Reason::FlowDead),
        );
        record.push(start, Decision::of(Reason::TransportLost));
        let last = record.decisions().last().expect("two entries");
        assert_eq!(last.at, Duration::ZERO);
    }

    #[test]
    fn a_record_that_overflows_says_how_much_it_lost() {
        let now = Instant::now();
        let mut record = Record::new(None, 3);
        for _ in 0..10 {
            record.push(now, Decision::of(Reason::RequestRetransmitted));
        }
        assert_eq!(record.len(), 3);
        assert_eq!(record.dropped(), 7);
        assert!(record.to_json().contains("\"dropped\":7"));
    }

    #[test]
    fn a_record_that_may_hold_nothing_still_counts_what_it_refused() {
        let now = Instant::now();
        let mut record = Record::new(None, 0);
        record.push(now, Decision::of(Reason::RequestSent));
        assert!(record.is_empty());
        assert_eq!(record.dropped(), 1);
    }

    #[test]
    fn a_flood_of_call_ids_cannot_grow_the_set() {
        let mut records = Records::new(RecordLimits {
            max_decisions: 4,
            max_records: 2,
        });
        records.mark(Instant::now());
        for call in 0..10_u32 {
            records.note(
                Some(call.to_string().as_bytes()),
                Decision::of(Reason::RequestRefusedWhenFull),
            );
        }
        assert_eq!(records.calls().count(), 2);
        assert_eq!(records.dropped(), 8);
        assert!(records.record(&CallId::new(b"0")).is_none());
        assert!(records.record(&CallId::new(b"9")).is_some());
    }

    #[test]
    fn the_call_evicted_is_the_one_nothing_has_been_written_to() {
        // an hour-long call must not be thrown away by two registrations that
        // happened to start after it
        let mut records = Records::new(RecordLimits {
            max_decisions: 4,
            max_records: 2,
        });
        records.mark(Instant::now());
        records.note(Some(b"call"), Decision::of(Reason::RequestSent));
        records.note(Some(b"other"), Decision::of(Reason::RequestSent));
        records.note(Some(b"call"), Decision::of(Reason::RequestRetransmitted));
        records.note(Some(b"third"), Decision::of(Reason::RequestSent));

        assert!(records.record(&CallId::new(b"call")).is_some());
        assert!(records.record(&CallId::new(b"other")).is_none());
        assert!(records.record(&CallId::new(b"third")).is_some());
    }

    #[test]
    fn the_endpoint_record_is_never_the_one_evicted() {
        let mut records = Records::new(RecordLimits {
            max_decisions: 4,
            max_records: 1,
        });
        records.mark(Instant::now());
        records.note(None, Decision::of(Reason::TransportLost));
        for call in 0..5_u32 {
            records.note(
                Some(call.to_string().as_bytes()),
                Decision::of(Reason::RequestSent),
            );
        }
        assert_eq!(records.endpoint().len(), 1);
    }

    #[test]
    fn nothing_is_written_before_the_caller_has_given_a_time() {
        let mut records = Records::new(RecordLimits::DEFAULT);
        records.note(None, Decision::of(Reason::TransportLost));
        assert!(records.endpoint().is_empty());
        records.mark(Instant::now());
        records.note(None, Decision::of(Reason::TransportLost));
        assert_eq!(records.endpoint().len(), 1);
    }

    #[test]
    fn the_json_holds_the_two_sizes_a_bug_report_needs() {
        let now = Instant::now();
        let mut record = Record::new(Some(CallId::new(b"a84b4c76e66710")), 8);
        record.push(
            now,
            Decision::of(Reason::TransportPromotedBySize)
                .measured(1_785, 1_299)
                .at_address(address()),
        );
        record.push(
            now + Duration::from_millis(2),
            Decision::of(Reason::RequestSent)
                .caused_by(WireEvent::request(
                    Method::Invite,
                    Direction::Outbound,
                    1_785,
                ))
                .at_address(address())
                .over(TransportProtocol::Tcp),
        );
        let json = record.to_json();
        assert_eq!(
            json,
            "{\"call_id\":\"a84b4c76e66710\",\"dropped\":0,\"decisions\":[\
{\"at_us\":0,\"reason\":\"transport.promoted.size\",\"address\":\"192.0.2.9:5060\",\
\"size\":1785,\"limit\":1299},\
{\"at_us\":2000,\"reason\":\"request.sent\",\"direction\":\"out\",\"method\":\"INVITE\",\
\"bytes\":1785,\"address\":\"192.0.2.9:5060\",\"protocol\":\"TCP\"}]}"
        );
    }

    #[test]
    fn a_response_is_written_by_its_status() {
        let now = Instant::now();
        let mut record = Record::new(None, 8);
        record.push(
            now,
            Decision::of(Reason::FailedRefused).caused_by(WireEvent::response(
                StatusCode::BUSY_HERE,
                Direction::Inbound,
                412,
            )),
        );
        let json = record.to_json();
        assert!(json.contains("\"status\":486"), "{json}");
        assert!(json.contains("\"direction\":\"in\""), "{json}");
        assert!(!json.contains("\"method\""), "{json}");
    }

    #[test]
    fn the_whole_set_is_one_document_with_the_endpoint_first() {
        let mut records = Records::new(RecordLimits {
            max_decisions: 4,
            max_records: 1,
        });
        records.mark(Instant::now());
        records.note(None, Decision::of(Reason::TransportLost));
        records.note(Some(b"one"), Decision::of(Reason::RequestSent));
        records.note(Some(b"two"), Decision::of(Reason::RequestSent));
        let json = records.to_json();
        assert!(
            json.starts_with("{\"records_dropped\":1,\"records\":["),
            "{json}"
        );
        assert!(json.contains("\"call_id\":null"), "{json}");
        assert!(json.contains("\"call_id\":\"two\""), "{json}");
        assert!(json.ends_with("]}"), "{json}");
    }
}
