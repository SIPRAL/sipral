// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Reliable provisional responses (RFC 3262), both ways round.
//!
//! A 180 Ringing is a datagram like any other, and on UDP it can be lost. That
//! matters more than it sounds: an offer or an answer can travel in a 1xx, and
//! a carrier that mandates `100rel` will not complete a call without one. So
//! the response is numbered, retransmitted until it is acknowledged, and the
//! acknowledgement is a request of its own — PRACK — because unlike an ACK it
//! has to be able to cross a proxy that predates this extension.
//!
//! Both ends keep a little state, and the two are not symmetric.
//!
//! The end that **sends** one holds the bytes and a doubling timer, and refuses
//! to send a second before the first is acknowledged: §3 gives the first
//! response special treatment because it carries the initial sequence number,
//! and without an acknowledgement there is no way to know the two arrived in
//! order.
//!
//! The end that **receives** one holds the highest number it has seen in
//! order. §4: a response whose `RSeq` is not exactly one higher "MUST NOT be
//! acknowledged with a PRACK, and MUST NOT be processed further", which is
//! what turns an unordered transport into an ordered stream of them.

use std::collections::HashMap;
use std::time::Instant;

use super::table::Flow;
use crate::msg::{Method, OwnedMessage, RAck};
use crate::transaction::{DialogId, InviteServer, Raw, TimerHandle, TransactionId, slab::Slab};

/// The option tag this whole file is about (RFC 3262 §8.1).
pub(super) const OPTION_100REL: &str = "100rel";

/// The largest `RSeq` a first reliable provisional response may carry.
///
/// §3: "The value of the header field for the first reliable provisional
/// response in a transaction MUST be between 1 and 2**31 - 1." The ceiling is
/// there so that the series can climb by one for the life of the transaction
/// without ever wrapping, which §3 forbids outright.
pub(super) const FIRST_RSEQ_CEILING: u32 = i32::MAX as u32;

/// What the end that sent a reliable provisional response has to remember.
#[derive(Debug)]
pub(super) struct Sent {
    /// The transaction it was sent on, so that giving up can refuse the call.
    pub(super) invite: TransactionId<InviteServer>,
    /// The bytes, retransmitted unchanged.
    pub(super) message: OwnedMessage,
    /// How many times it has gone out, which is what the doubling counts.
    pub(super) attempt: u32,
    /// 64·T1 after the first one: "the UAS SHOULD reject the original request
    /// with a 5xx response".
    pub(super) give_up_at: Instant,
    /// The scheduled retransmission, so that a PRACK can take it down.
    pub(super) timer: Option<TimerHandle>,
    /// Whether a PRACK matched it and was not refused: §3's "remove it from
    /// the list of unacknowledged provisional responses". Kept rather than
    /// forgotten until the INVITE or the dialog ends, because a PRACK the
    /// layer above refuses under RFC 3261 §8.2 — a `Require` it cannot
    /// honour, a body it cannot read, an offer it will not take — has
    /// acknowledged nothing, and the retry that follows has to find it again
    /// ([`super::Endpoint::refuse_prack`]).
    pub(super) acknowledged: bool,
    /// Whether the INVITE has had its final response, after which §3 has
    /// the retransmissions stop for good: "it SHOULD NOT continue to
    /// retransmit the unacknowledged reliable provisional responses".
    pub(super) quiet: bool,
}

/// One reliable provisional response, on whichever side of it we are.
#[derive(Debug)]
pub(super) struct Reliable {
    /// The dialog it belongs to. A fork numbers each branch separately, so the
    /// number alone does not identify one.
    pub(super) dialog: DialogId,
    /// Its `RSeq`.
    pub(super) rseq: u32,
    /// The `CSeq` number of the request it answers, which `RAck` copies.
    pub(super) cseq: u32,
    /// That request's method, which `RAck` copies too. §7.2: "The method name
    /// in the RAck header is case sensitive."
    pub(super) method: Box<[u8]>,
    /// Where its PRACK, or its retransmissions, go.
    pub(super) flow: Flow,
    /// Present on the end that sent it.
    pub(super) sent: Option<Sent>,
}

impl Reliable {
    /// Whether a PRACK's `RAck` names this response.
    ///
    /// §3: "A matching PRACK is defined as one within the same dialog as the
    /// response, and whose method, CSeq-num, and response-num in the RAck
    /// header field match, respectively, the method from the CSeq, the
    /// sequence number from the CSeq, and the sequence number from the RSeq of
    /// the reliable provisional response."
    fn answered_by(&self, dialog: DialogId, rack: &RAck<'_>) -> bool {
        self.sent.as_ref().is_none_or(|sent| !sent.acknowledged)
            && self.dialog == dialog
            && self.rseq == rack.response_num
            && self.cseq == rack.cseq_num
            && *self.method == *rack.method.as_str().as_bytes()
    }
}

/// Every reliable provisional response one endpoint is holding.
#[derive(Debug, Default)]
pub(super) struct Reliables {
    entries: Slab<Reliable>,
    /// Every entry, by the dialog it belongs to.
    ///
    /// Ending a dialog, matching a PRACK and refusing a call whose response
    /// went unacknowledged each ask about one dialog or one INVITE. Answered
    /// by visiting every entry, a burst of calls given up on at the same
    /// instant cost the square of their number.
    of_dialog: HashMap<DialogId, Vec<Raw>>,
    /// Every entry this end sent, by the INVITE it answers.
    of_invite: HashMap<TransactionId<InviteServer>, Vec<Raw>>,
    /// The highest `RSeq` received in order, per dialog.
    ///
    /// §4 keeps this "for the initial request", which predates a clean answer
    /// for forking: one INVITE that a proxy forks is answered by several user
    /// agents, each numbering its own series from its own transaction (§3:
    /// "The RSeq numbering space is within a single transaction"). Keyed on
    /// the request, two branches would look to each other like a series full
    /// of gaps, and every response after the first would be discarded. Keyed
    /// on the dialog, which is what tells the branches apart, both are read.
    heard: HashMap<DialogId, u32>,
    /// The next `RSeq` to write per INVITE we are answering (§3).
    series: HashMap<TransactionId<InviteServer>, u32>,
}

impl Reliables {
    /// An endpoint with nothing outstanding.
    pub(super) fn new() -> Self {
        Self {
            entries: Slab::new(),
            of_dialog: HashMap::new(),
            of_invite: HashMap::new(),
            heard: HashMap::new(),
            series: HashMap::new(),
        }
    }

    /// Keep one, and name it.
    pub(super) fn keep(&mut self, reliable: Reliable) -> Raw {
        let dialog = reliable.dialog;
        let invite = reliable.sent.as_ref().map(|sent| sent.invite);
        let raw = self.entries.insert(reliable);
        self.of_dialog.entry(dialog).or_default().push(raw);
        if let Some(invite) = invite {
            self.of_invite.entry(invite).or_default().push(raw);
        }
        raw
    }

    /// What is known about one.
    pub(super) fn get(&self, raw: Raw) -> Option<&Reliable> {
        self.entries.get(raw)
    }

    /// What is known about one, mutably.
    pub(super) fn get_mut(&mut self, raw: Raw) -> Option<&mut Reliable> {
        self.entries.get_mut(raw)
    }

    /// Forget one, acknowledged or given up on.
    pub(super) fn forget(&mut self, raw: Raw) -> Option<Reliable> {
        let reliable = self.entries.remove(raw)?;
        unlink(&mut self.of_dialog, &reliable.dialog, raw);
        if let Some(sent) = reliable.sent.as_ref() {
            unlink(&mut self.of_invite, &sent.invite, raw);
        }
        Some(reliable)
    }

    /// The response a PRACK acknowledges, if it is one we are still holding.
    ///
    /// §3: a PRACK that matches nothing "MUST be responded to with a 481", so
    /// `None` here is an answer rather than a shrug.
    pub(super) fn answered_by(&self, dialog: DialogId, rack: &RAck<'_>) -> Option<Raw> {
        self.of_dialog.get(&dialog)?.iter().copied().find(|raw| {
            self.entries
                .get(*raw)
                .is_some_and(|reliable| reliable.answered_by(dialog, rack))
        })
    }

    /// Whether this INVITE already has one waiting to be acknowledged.
    ///
    /// §3: "The UAS MUST NOT send a second reliable provisional response until
    /// the first is acknowledged."
    pub(super) fn outstanding_on(&self, invite: TransactionId<InviteServer>) -> bool {
        self.of_invite.get(&invite).is_some_and(|held| {
            held.iter().any(|raw| {
                self.entries
                    .get(*raw)
                    .and_then(|reliable| reliable.sent.as_ref())
                    .is_some_and(|sent| !sent.acknowledged)
            })
        })
    }

    /// The next number in this INVITE's series.
    ///
    /// The first is drawn from `first`, which the caller takes from its own
    /// entropy: §3 recommends choosing it uniformly in 1..2³¹-1, so that a
    /// number seen on the wire says nothing about how many calls this endpoint
    /// has taken. Every one after that is "greater by exactly one".
    pub(super) fn next_rseq(&mut self, invite: TransactionId<InviteServer>, first: u32) -> u32 {
        let rseq = *self.series.entry(invite).or_insert(first);
        self.series.insert(invite, rseq.saturating_add(1));
        rseq
    }

    /// Everything this INVITE is still holding, for when it ends.
    pub(super) fn on_invite(&self, invite: TransactionId<InviteServer>) -> Vec<Raw> {
        self.of_invite.get(&invite).cloned().unwrap_or_default()
    }

    /// This INVITE is over: forget its series.
    pub(super) fn forget_series(&mut self, invite: TransactionId<InviteServer>) {
        self.series.remove(&invite);
    }

    /// Whether a reliable provisional response is the next one in order (§4),
    /// and remember it if it is.
    ///
    /// The first for a transaction is accepted whatever its number, since that
    /// is the number the series starts from. After that only one higher is
    /// taken: a lower one is a retransmission, and a gap means one was lost
    /// and this one cannot be processed until it arrives.
    pub(super) fn in_order(&mut self, dialog: DialogId, rseq: u32) -> bool {
        match self.heard.get(&dialog) {
            None => {
                self.heard.insert(dialog, rseq);
                true
            }
            Some(&last) if rseq == last.wrapping_add(1) => {
                self.heard.insert(dialog, rseq);
                true
            }
            Some(_) => false,
        }
    }

    /// This dialog is over: forget its numbering.
    pub(super) fn forget_heard(&mut self, dialog: DialogId) {
        self.heard.remove(&dialog);
    }

    /// Everything held for a dialog, for when it ends.
    pub(super) fn on_dialog(&self, dialog: DialogId) -> Vec<Raw> {
        self.of_dialog.get(&dialog).cloned().unwrap_or_default()
    }
}

/// Take one entry out of an index, and its key with it once nothing is left.
fn unlink<K: Eq + core::hash::Hash>(index: &mut HashMap<K, Vec<Raw>>, key: &K, raw: Raw) {
    if let Some(held) = index.get_mut(key) {
        held.retain(|known| *known != raw);
        if held.is_empty() {
            index.remove(key);
        }
    }
}

/// The `RAck` value acknowledging a response (§7.2).
pub(super) fn rack_value(reliable: &Reliable) -> Box<[u8]> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(reliable.rseq.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(reliable.cseq.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(&reliable.method);
    out.into_boxed_slice()
}

/// Whether a message offers or demands `100rel`.
///
/// §3: a UAS may answer reliably only if the INVITE listed the option tag in
/// `Supported`, and must do so if it listed it in `Require`.
pub(super) fn offers_100rel(request: &crate::msg::RawMessage<'_>) -> bool {
    request.supported().has(OPTION_100REL) || request.require().has(OPTION_100REL)
}

/// Whether a message demands it.
pub(super) fn demands_100rel(request: &crate::msg::RawMessage<'_>) -> bool {
    request.require().has(OPTION_100REL)
}

/// Whether a provisional response says it was sent reliably.
///
/// §4: a 100 that carries the option tag anyway is ignored, because "100
/// (Trying) responses are hop-by-hop only" and the mechanism is end to end.
pub(super) fn is_reliable(response: &crate::msg::RawMessage<'_>) -> bool {
    response
        .status()
        .is_some_and(|status| status.get() >= 101 && status.is_provisional())
        && response.require().has(OPTION_100REL)
        && response.rseq().is_ok()
}

/// The method of the request a response answers, from its `CSeq`.
pub(super) fn answered_method(response: &crate::msg::RawMessage<'_>) -> Box<[u8]> {
    response.cseq().map_or_else(
        |_| Box::from(Method::Invite.as_str().as_bytes()),
        |cseq| Box::from(cseq.method.as_str().as_bytes()),
    )
}

#[cfg(test)]
mod tests {
    use super::{Reliable, Reliables, Sent, rack_value};
    use crate::endpoint::table::Flow;
    use crate::endpoint::{TransportId, TransportProtocol};
    use crate::msg::{ParseMode, ParseScratch, RAck, parse};
    use crate::transaction::{DialogId, InviteServer, Raw, TransactionId};
    use std::net::SocketAddr;

    fn flow() -> Flow {
        Flow {
            transport: TransportId(1),
            destination: "192.0.2.9:5060".parse::<SocketAddr>().unwrap(),
            source: None,
            protocol: TransportProtocol::Udp,
        }
    }

    const fn raw(slot: u32) -> Raw {
        Raw {
            slot,
            generation: 0,
        }
    }

    fn dialog(slot: u32) -> DialogId {
        DialogId::new(raw(slot))
    }

    fn invite_server(slot: u32) -> TransactionId<InviteServer> {
        TransactionId::new(raw(slot))
    }

    fn heard(dialog_slot: u32, rseq: u32) -> Reliable {
        Reliable {
            dialog: dialog(dialog_slot),
            rseq,
            cseq: 1,
            method: Box::from(&b"INVITE"[..]),
            flow: flow(),
            sent: None,
        }
    }

    fn rack(value: &str) -> RAck<'_> {
        RAck::parse(value.as_bytes()).unwrap()
    }

    #[test]
    fn a_prack_finds_the_response_whose_three_numbers_it_names() {
        let mut store = Reliables::new();
        let one = store.keep(heard(0, 700));
        store.keep(heard(1, 700));

        assert_eq!(
            store.answered_by(dialog(0), &rack("700 1 INVITE")),
            Some(one)
        );
        // the same numbers in another dialog are another call's
        assert_ne!(
            store.answered_by(dialog(1), &rack("700 1 INVITE")),
            Some(one)
        );
        assert_eq!(store.answered_by(dialog(0), &rack("701 1 INVITE")), None);
        assert_eq!(store.answered_by(dialog(0), &rack("700 2 INVITE")), None);
        assert_eq!(store.answered_by(dialog(0), &rack("700 1 UPDATE")), None);
    }

    #[test]
    fn a_rack_is_written_the_way_the_rfc_prints_it() {
        // "RAck: 776656 1 INVITE"
        let reliable = Reliable {
            rseq: 776_656,
            ..heard(0, 0)
        };
        assert_eq!(&*rack_value(&reliable), b"776656 1 INVITE");
    }

    #[test]
    fn the_numbering_of_a_series_climbs_by_exactly_one() {
        let mut store = Reliables::new();
        let invite = invite_server(0);
        assert_eq!(store.next_rseq(invite, 500), 500);
        assert_eq!(store.next_rseq(invite, 500), 501);
        assert_eq!(store.next_rseq(invite, 500), 502);
        // another transaction numbers its own, and may reuse the values
        assert_eq!(store.next_rseq(invite_server(1), 500), 500);
    }

    #[test]
    fn a_second_response_is_refused_until_the_first_is_acknowledged() {
        let mut store = Reliables::new();
        let invite = invite_server(0);
        assert!(!store.outstanding_on(invite));

        let held = store.keep(Reliable {
            sent: Some(Sent {
                invite,
                message: parse(RINGING, &mut ParseScratch::new(), ParseMode::Lenient)
                    .unwrap()
                    .to_owned(),
                attempt: 0,
                give_up_at: std::time::Instant::now(),
                timer: None,
                acknowledged: false,
                quiet: false,
            }),
            ..heard(0, 700)
        });
        assert!(store.outstanding_on(invite));
        assert!(!store.outstanding_on(invite_server(1)));

        // acknowledged, it no longer holds the next one back, and a refused
        // PRACK that takes the acknowledgement back holds it again
        let mark = |store: &mut Reliables, acknowledged: bool| {
            if let Some(sent) = store.get_mut(held).and_then(|held| held.sent.as_mut()) {
                sent.acknowledged = acknowledged;
            }
        };
        mark(&mut store, true);
        assert!(!store.outstanding_on(invite));
        assert_eq!(store.answered_by(dialog(0), &rack("700 1 INVITE")), None);
        mark(&mut store, false);
        assert!(store.outstanding_on(invite));
        assert_eq!(
            store.answered_by(dialog(0), &rack("700 1 INVITE")),
            Some(held)
        );

        store.forget(held);
        assert!(!store.outstanding_on(invite));
    }

    const RINGING: &[u8] = b"SIP/2.0 180 Ringing\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
From: <sip:alice@example.com>;tag=a\r\n\
To: <sip:bob@example.com>;tag=b\r\n\
Call-ID: c\r\n\
CSeq: 1 INVITE\r\n\
Require: 100rel\r\n\
RSeq: 700\r\n\
Content-Length: 0\r\n\
\r\n";

    #[test]
    fn the_first_response_heard_sets_the_series_and_the_rest_must_follow_it() {
        // §4: one that is not exactly one higher "MUST NOT be acknowledged
        // with a PRACK, and MUST NOT be processed further"
        let mut store = Reliables::new();
        let branch = dialog(0);
        assert!(store.in_order(branch, 900), "the first sets the series");
        assert!(!store.in_order(branch, 900), "a retransmission");
        assert!(!store.in_order(branch, 902), "a gap");
        assert!(store.in_order(branch, 901));
        assert!(store.in_order(branch, 902));

        // the other branch of a fork numbers its own, from its own transaction
        assert!(store.in_order(dialog(1), 5));
    }

    #[test]
    fn a_call_that_is_over_forgets_both_halves_of_its_numbering() {
        let mut store = Reliables::new();
        let branch = dialog(0);
        let server = invite_server(0);
        store.in_order(branch, 10);
        store.next_rseq(server, 10);

        store.forget_heard(branch);
        store.forget_series(server);
        assert!(store.in_order(branch, 77), "the series started again");
        assert_eq!(store.next_rseq(server, 42), 42);
    }

    #[test]
    fn everything_one_invite_is_holding_can_be_found_when_it_ends() {
        let mut store = Reliables::new();
        let invite = invite_server(3);
        let sent = || Sent {
            invite,
            message: parse(RINGING, &mut ParseScratch::new(), ParseMode::Lenient)
                .unwrap()
                .to_owned(),
            attempt: 0,
            give_up_at: std::time::Instant::now(),
            timer: None,
            acknowledged: false,
            quiet: false,
        };
        let first = store.keep(Reliable {
            sent: Some(sent()),
            ..heard(0, 700)
        });
        store.keep(heard(1, 900));
        assert_eq!(store.on_invite(invite), vec![first]);
        // the other one is on the receiving side, and belongs to its dialog
        assert_eq!(store.on_dialog(dialog(1)).len(), 1);
        assert!(store.on_dialog(dialog(0)).contains(&first));
    }
}
