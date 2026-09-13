// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Where the endpoint keeps dialogs, and why they are kept in two shapes.
//!
//! A dialog we opened by calling somebody is never alone. One INVITE can be
//! forked by a proxy to a desk phone, a mobile and a voicemail box, and each
//! branch that answers is a dialog of its own on the same request — so what
//! the endpoint holds is not a dialog but a [`DialogSet`], which knows how to
//! tell the branches apart and which of them a late 2xx belongs to.
//!
//! A dialog somebody opened by calling us has no such problem: we answered one
//! request once, and there is exactly one. It is held on its own.
//!
//! Both are reached by the same [`DialogId`], so nothing above here has to
//! know which shape a particular dialog is in.

use std::collections::HashMap;

use super::table::Flow;
use crate::dialog::{Dialog, DialogKey, DialogSet};
use crate::msg::OwnedMessage;
use crate::transaction::{DialogId, InviteClient, Raw, TransactionId, slab::Slab};

/// Which of the two shapes a dialog is in.
#[derive(Debug)]
enum Home {
    /// One branch of an INVITE we sent, held by the set that knows its
    /// siblings.
    Branch(Raw),
    /// A dialog we answered a request into.
    Answered(Box<Dialog>),
}

/// One dialog, and where its requests go.
#[derive(Debug)]
struct Entry {
    key: DialogKey,
    home: Home,
    /// Where in-dialog requests leave from. The route set says which hop
    /// first, but not which socket, and the socket is the caller's.
    flow: Flow,
    /// Where the ACK to the 2xx that confirmed this dialog left from, for a
    /// dialog of an INVITE we sent. Not always `flow`: §18.1.1 moves an ACK
    /// too large for a datagram onto a stream, and every retransmission of
    /// the 2xx has to be answered on that stream too.
    acked_on: Option<Flow>,
    /// How many non-INVITE server transactions this dialog has open right
    /// now — the budget `endpoint::inbound::MAX_DIALOG_NON_INVITE_TRANSACTIONS`
    /// counts against. A dialog is exempt from the endpoint-wide ceiling, but
    /// not from having a ceiling of its own: this is the count that ceiling
    /// reads, raised at every server transaction this dialog admits and
    /// lowered when it retires, on every transport and in an early dialog
    /// exactly as in a confirmed one.
    non_invite_transactions: usize,
    /// The `CSeq` number of the INVITE whose 2xx this end sent last in this
    /// dialog, which is the number the ACK it is owed carries (§13.2.2.4).
    /// Not the dialog's remote sequence number: a PRACK or an UPDATE the far
    /// end sends before its ACK moves that one on.
    answered_invite: Option<u32>,
    /// The `CSeq` number of the last ACK reported for such a 2xx, so that a
    /// repeat of it, sent for a retransmission of the 2xx, is not reported
    /// again.
    acknowledged_invite: Option<u32>,
}

/// The dialogs one INVITE produced, and the transaction that produced them.
#[derive(Debug)]
struct Branches {
    set: DialogSet,
    /// The transaction, until it terminates. A confirmed dialog outlives it
    /// by the length of the call.
    invite: Option<TransactionId<InviteClient>>,
    /// How many dialog entries still point here.
    live: usize,
}

/// Every dialog of one endpoint.
#[derive(Debug)]
pub(crate) struct Dialogs {
    entries: Slab<Entry>,
    sets: Slab<Branches>,
    by_key: HashMap<DialogKey, DialogId>,
    by_invite: HashMap<TransactionId<InviteClient>, Raw>,
}

impl Dialogs {
    /// An endpoint with no calls.
    pub(crate) fn new() -> Self {
        Self {
            entries: Slab::new(),
            sets: Slab::new(),
            by_key: HashMap::new(),
            by_invite: HashMap::new(),
        }
    }

    /// How many dialogs are live.
    pub(crate) const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Start following an INVITE we are about to send.
    pub(crate) fn watch(&mut self, set: DialogSet, invite: TransactionId<InviteClient>) -> Raw {
        let raw = self.sets.insert(Branches {
            set,
            invite: Some(invite),
            live: 0,
        });
        self.by_invite.insert(invite, raw);
        raw
    }

    /// The set an INVITE client transaction is producing dialogs into.
    pub(crate) fn set_for(&self, invite: TransactionId<InviteClient>) -> Option<Raw> {
        self.by_invite.get(&invite).copied()
    }

    /// The set an INVITE client transaction is producing dialogs into.
    pub(crate) fn set_mut(&mut self, set: Raw) -> Option<&mut DialogSet> {
        self.sets.get_mut(set).map(|branches| &mut branches.set)
    }

    /// The set, read only.
    pub(crate) fn set(&self, set: Raw) -> Option<&DialogSet> {
        self.sets.get(set).map(|branches| &branches.set)
    }

    /// Name a dialog a set has just opened, so the layer above can hold it.
    pub(crate) fn name_branch(&mut self, set: Raw, key: DialogKey, flow: Flow) -> DialogId {
        if let Some(known) = self.by_key.get(&key) {
            return *known;
        }
        if let Some(branches) = self.sets.get_mut(set) {
            branches.live += 1;
        }
        let raw = self.entries.insert(Entry {
            key: key.clone(),
            home: Home::Branch(set),
            flow,
            acked_on: None,
            non_invite_transactions: 0,
            answered_invite: None,
            acknowledged_invite: None,
        });
        let id = DialogId::new(raw);
        self.by_key.insert(key, id);
        id
    }

    /// Keep a dialog we opened by answering a request.
    pub(crate) fn answer(&mut self, dialog: Dialog, flow: Flow) -> DialogId {
        let key = dialog.key().clone();
        if let Some(known) = self.by_key.get(&key) {
            return *known;
        }
        let raw = self.entries.insert(Entry {
            key: key.clone(),
            home: Home::Answered(Box::new(dialog)),
            flow,
            acked_on: None,
            non_invite_transactions: 0,
            answered_invite: None,
            acknowledged_invite: None,
        });
        let id = DialogId::new(raw);
        self.by_key.insert(key, id);
        id
    }

    /// The dialog with this name, if it is still live.
    pub(crate) fn get(&self, id: DialogId) -> Option<&Dialog> {
        let entry = self.entries.get(id.raw)?;
        match entry.home {
            Home::Branch(set) => self.sets.get(set)?.set.get(&entry.key),
            Home::Answered(ref dialog) => Some(dialog),
        }
    }

    /// The dialog, mutably.
    pub(crate) fn get_mut(&mut self, id: DialogId) -> Option<&mut Dialog> {
        let entry = self.entries.get_mut(id.raw)?;
        match entry.home {
            // the key is cloned rather than borrowed because the borrow of
            // `entry` has to end before the set can be reached
            Home::Branch(set) => {
                let key = entry.key.clone();
                self.sets.get_mut(set)?.set.get_mut(&key)
            }
            Home::Answered(ref mut dialog) => Some(dialog),
        }
    }

    /// Where this dialog's requests go.
    pub(crate) fn flow(&self, id: DialogId) -> Option<Flow> {
        self.entries.get(id.raw).map(|entry| entry.flow)
    }

    /// Point this dialog's requests somewhere else, after the caller has
    /// resolved the next hop its route set names.
    pub(crate) fn set_flow(&mut self, id: DialogId, flow: Flow) {
        if let Some(entry) = self.entries.get_mut(id.raw) {
            entry.flow = flow;
        }
    }

    /// How many non-INVITE server transactions this dialog holds right now.
    pub(crate) fn non_invite_transactions(&self, id: DialogId) -> usize {
        self.entries
            .get(id.raw)
            .map_or(0, |entry| entry.non_invite_transactions)
    }

    /// A non-INVITE server transaction was admitted into this dialog: count
    /// it against the budget until it retires.
    pub(crate) fn reserve_non_invite_transaction(&mut self, id: DialogId) {
        if let Some(entry) = self.entries.get_mut(id.raw) {
            entry.non_invite_transactions += 1;
        }
    }

    /// The transaction [`Dialogs::reserve_non_invite_transaction`] counted has
    /// retired; give its place back. A no-op for a dialog already forgotten —
    /// nothing can match it any more either, so its budget stops mattering the
    /// same instant.
    pub(crate) fn release_non_invite_transaction(&mut self, id: DialogId) {
        if let Some(entry) = self.entries.get_mut(id.raw) {
            entry.non_invite_transactions = entry.non_invite_transactions.saturating_sub(1);
        }
    }

    /// A 2xx to the INVITE numbered `seq` has gone out in this dialog, so the
    /// ACK it is owed carries that number (§13.2.2.4).
    pub(crate) fn answer_invite(&mut self, id: DialogId, seq: u32) {
        if let Some(entry) = self.entries.get_mut(id.raw) {
            entry.answered_invite = Some(seq);
        }
    }

    /// Whether an ACK numbered `seq` is the one the last 2xx this end sent in
    /// the dialog is still owed, taking it when it is. An ACK for an earlier
    /// INVITE is stale, and one for an INVITE already acknowledged is a repeat
    /// (§17.1.1.3): neither is.
    pub(crate) fn take_ack(&mut self, id: DialogId, seq: u32) -> bool {
        let Some(entry) = self.entries.get_mut(id.raw) else {
            return false;
        };
        if entry.answered_invite != Some(seq) || entry.acknowledged_invite == Some(seq) {
            return false;
        }
        entry.acknowledged_invite = Some(seq);
        true
    }

    /// Keep the ACK to the 2xx that confirmed a dialog of ours, and the flow
    /// it left on, for every retransmission of that 2xx (§13.2.2.4).
    pub(crate) fn keep_ack(&mut self, id: DialogId, ack: OwnedMessage, flow: Flow) {
        let Some(entry) = self.entries.get_mut(id.raw) else {
            return;
        };
        let Home::Branch(set) = entry.home else {
            return;
        };
        let Some(branches) = self.sets.get_mut(set) else {
            return;
        };
        if branches.set.keep_ack(&entry.key, ack).is_ok() {
            entry.acked_on = Some(flow);
        }
    }

    /// That ACK and its flow, once both are kept.
    pub(crate) fn kept_ack(&self, id: DialogId) -> Option<(&OwnedMessage, Flow)> {
        let entry = self.entries.get(id.raw)?;
        let Home::Branch(set) = entry.home else {
            return None;
        };
        let ack = self.sets.get(set)?.set.ack_for(&entry.key)?;
        Some((ack, entry.acked_on?))
    }

    /// The dialog this message belongs to, by its identifier (§12.2).
    pub(crate) fn find(&self, key: &DialogKey) -> Option<DialogId> {
        self.by_key.get(key).copied()
    }

    /// The set a dialog belongs to, when it came from an INVITE we sent.
    pub(crate) fn branch_set(&self, id: DialogId) -> Option<Raw> {
        match self.entries.get(id.raw)?.home {
            Home::Branch(set) => Some(set),
            Home::Answered(_) => None,
        }
    }

    /// The INVITE that opened this dialog, while it is still running.
    ///
    /// §14.1 forbids a second INVITE transaction in a dialog while one is in
    /// progress, and the INVITE that opened an early dialog counts.
    pub(crate) fn opening_invite(&self, id: DialogId) -> Option<TransactionId<InviteClient>> {
        let set = self.branch_set(id)?;
        self.sets.get(set)?.invite
    }

    /// The INVITE transaction is over. The set stays for as long as it still
    /// has dialogs; without them it goes now.
    pub(crate) fn invite_done(&mut self, set: Raw) {
        let Some(branches) = self.sets.get_mut(set) else {
            return;
        };
        if let Some(invite) = branches.invite.take() {
            self.by_invite.remove(&invite);
        }
        if branches.live == 0 {
            self.sets.remove(set);
        }
    }

    /// Forget a dialog, and the set with it if that was the last one and its
    /// transaction has already finished.
    pub(crate) fn forget(&mut self, id: DialogId) -> Option<DialogKey> {
        let entry = self.entries.remove(id.raw)?;
        self.by_key.remove(&entry.key);
        if let Home::Branch(set) = entry.home
            && let Some(branches) = self.sets.get_mut(set)
        {
            branches.live = branches.live.saturating_sub(1);
            if branches.live == 0 && branches.invite.is_none() {
                self.sets.remove(set);
            }
        }
        Some(entry.key)
    }

    /// Every dialog a set has named, found through the set's own branches.
    ///
    /// Retiring an INVITE transaction ends what its set is still holding, and
    /// that happens on the timer path, for every call whose timer M fires at
    /// the same instant. Visiting every dialog the endpoint holds on each
    /// retirement made that quadratic in the number of calls; this visits the
    /// branches of one INVITE and nothing else.
    pub(crate) fn branches_of(&self, set: Raw) -> Vec<DialogId> {
        let Some(branches) = self.sets.get(set) else {
            return Vec::new();
        };
        branches
            .set
            .dialogs()
            .filter_map(|dialog| self.by_key.get(dialog.key()).copied())
            .filter(|id| {
                self.entries
                    .get(id.raw)
                    .is_some_and(|entry| matches!(entry.home, Home::Branch(home) if home == set))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::table::Flow;
    use super::Dialogs;
    use crate::dialog::{Dialog, DialogSet};
    use crate::endpoint::{TransportId, TransportProtocol};
    use crate::msg::{OwnedMessage, ParseMode, ParseScratch, RawMessage, StatusCode, parse};
    use crate::transaction::{InviteClient, TransactionId};
    use std::net::SocketAddr;

    const INVITE: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=alice\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.0.2.1>\r\n\
Content-Length: 0\r\n\
\r\n";

    fn ringing(tag: &str) -> Vec<u8> {
        format!(
            "SIP/2.0 180 Ringing\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
From: <sip:alice@example.com>;tag=alice\r\n\
To: <sip:bob@example.com>;tag={tag}\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@192.0.2.{}>\r\n\
Content-Length: 0\r\n\
\r\n",
            tag.len()
        )
        .into_bytes()
    }

    fn owned(bytes: &[u8]) -> OwnedMessage {
        let mut scratch = ParseScratch::new();
        parse(bytes, &mut scratch, ParseMode::Lenient)
            .unwrap()
            .to_owned()
    }

    fn with<T>(bytes: &[u8], f: impl FnOnce(&RawMessage<'_>) -> T) -> T {
        let mut scratch = ParseScratch::new();
        f(&parse(bytes, &mut scratch, ParseMode::Lenient).unwrap())
    }

    fn flow() -> Flow {
        Flow {
            transport: TransportId(1),
            destination: "192.0.2.9:5060".parse::<SocketAddr>().unwrap(),
            source: None,
            protocol: TransportProtocol::Udp,
        }
    }

    fn invite_id() -> TransactionId<InviteClient> {
        TransactionId::new(crate::transaction::Raw {
            slot: 0,
            generation: 0,
        })
    }

    #[test]
    fn a_fork_puts_two_dialogs_on_one_invite_and_both_are_reachable() {
        let mut dialogs = Dialogs::new();
        let set = dialogs.watch(DialogSet::new(owned(INVITE), false), invite_id());

        let mut named = Vec::new();
        for tag in ["desk", "mobile"] {
            let key = with(&ringing(tag), |response| {
                let fork = dialogs.set_mut(set).unwrap().on_response(response).unwrap();
                match fork {
                    crate::dialog::Fork::Opened(key) => key,
                    other => panic!("expected a new dialog, got {other:?}"),
                }
            });
            named.push(dialogs.name_branch(set, key, flow()));
        }

        assert_eq!(dialogs.len(), 2);
        assert_ne!(named.first(), named.get(1));
        for id in &named {
            assert!(dialogs.get(*id).is_some());
            assert_eq!(dialogs.branch_set(*id), Some(set));
        }
    }

    #[test]
    fn naming_the_same_branch_twice_gives_the_same_name() {
        let mut dialogs = Dialogs::new();
        let set = dialogs.watch(DialogSet::new(owned(INVITE), false), invite_id());
        let key = with(&ringing("desk"), |response| {
            dialogs.set_mut(set).unwrap().on_response(response).unwrap();
            crate::dialog::DialogKey::as_uac(response).unwrap()
        });
        let first = dialogs.name_branch(set, key.clone(), flow());
        let second = dialogs.name_branch(set, key, flow());
        assert_eq!(first, second);
        assert_eq!(dialogs.len(), 1);
    }

    #[test]
    fn a_dialog_we_answered_stands_on_its_own() {
        let mut dialogs = Dialogs::new();
        let dialog = with(INVITE, |request| {
            Dialog::from_request(request, b"ours", StatusCode::new(200).unwrap(), false).unwrap()
        });
        let key = dialog.key().clone();
        let id = dialogs.answer(dialog, flow());
        assert_eq!(dialogs.find(&key), Some(id));
        assert!(dialogs.get(id).is_some());
        assert_eq!(dialogs.branch_set(id), None);
    }

    #[test]
    fn a_forgotten_dialog_answers_to_nothing() {
        let mut dialogs = Dialogs::new();
        let dialog = with(INVITE, |request| {
            Dialog::from_request(request, b"ours", StatusCode::new(200).unwrap(), false).unwrap()
        });
        let key = dialog.key().clone();
        let id = dialogs.answer(dialog, flow());
        assert_eq!(dialogs.forget(id), Some(key.clone()));
        assert!(dialogs.get(id).is_none());
        assert_eq!(dialogs.find(&key), None);
        assert_eq!(dialogs.len(), 0);
    }

    #[test]
    fn a_set_outlives_its_transaction_but_not_its_last_dialog() {
        // the transaction ends 64*T1 after the answer; the call it opened can
        // last an hour
        let mut dialogs = Dialogs::new();
        let set = dialogs.watch(DialogSet::new(owned(INVITE), false), invite_id());
        let key = with(&ringing("desk"), |response| {
            dialogs.set_mut(set).unwrap().on_response(response).unwrap();
            crate::dialog::DialogKey::as_uac(response).unwrap()
        });
        let id = dialogs.name_branch(set, key, flow());

        assert_eq!(dialogs.set_for(invite_id()), Some(set));
        dialogs.invite_done(set);
        assert_eq!(dialogs.set_for(invite_id()), None);
        assert!(dialogs.set(set).is_some(), "the call is still up");
        assert!(dialogs.get(id).is_some());

        dialogs.forget(id);
        assert!(dialogs.set(set).is_none(), "nothing points at it any more");
    }

    #[test]
    fn a_set_whose_invite_failed_without_a_dialog_goes_at_once() {
        let mut dialogs = Dialogs::new();
        let set = dialogs.watch(DialogSet::new(owned(INVITE), false), invite_id());
        dialogs.invite_done(set);
        assert!(dialogs.set(set).is_none());
    }
}
