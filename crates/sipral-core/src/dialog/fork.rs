// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One INVITE and every dialog it turned into (RFC 3261 §13.2.2).
//!
//! A proxy may fork a call to the desk phone, the mobile and the voicemail at
//! once. All three ring, all three can answer, and "multiple 2xx responses may
//! arrive at the UAC for a single INVITE request ... each represents a distinct
//! dialog". They are told apart by the tag in `To`, and nothing here picks
//! between them: this records what came back and leaves the choice — take one,
//! take both, hang up on the loser — to the layer that knows what the call is
//! for.
//!
//! What it does insist on is that nothing is lost. Every 2xx gets its own
//! dialog and its own ACK, including one that arrives after another branch has
//! already been answered, because a 2xx nobody acknowledges is a call the far
//! end thinks is up.

use super::key::DialogKey;
use super::request::InDialogRequest;
use super::state::{Dialog, DialogState};
use super::{DialogError, Tag};
use crate::msg::{OwnedMessage, RawMessage};

/// What a response did to the set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fork {
    /// It opened a dialog: early if it was provisional, confirmed if 2xx.
    Opened(DialogKey),
    /// It belongs to a dialog the set already had, which has taken it.
    Advanced(DialogKey),
    /// A non-2xx final answered the INVITE, so "all early dialogs are
    /// considered terminated" (§13.2.2.3). Any dialog already confirmed by a
    /// 2xx from another branch is left alone — it is a call in progress, not
    /// an attempt that failed.
    Refused,
    /// Nothing: a 100, a response with no tag to name a dialog by, one that
    /// arrived after the set was finished with, or one that would have opened
    /// a branch when the caller had no room for another dialog.
    Ignored,
}

/// The dialogs one outgoing INVITE has produced.
pub struct DialogSet {
    invite: OwnedMessage,
    over_tls: bool,
    branches: Vec<Branch>,
    refused: bool,
    closed: bool,
}

struct Branch {
    dialog: Dialog,
    /// The ACK as it went out, kept because §13.2.2.4 makes retransmitting it
    /// our job: "The ACK MUST be passed to the client transport every time a
    /// retransmission of the 2xx final response that triggered the ACK
    /// arrives."
    ack: Option<OwnedMessage>,
}

impl DialogSet {
    /// Start from the INVITE that was sent.
    ///
    /// `over_tls` says how it left, which is half of what the `secure` flag
    /// of §12.1 needs; the other half is its Request-URI, read from the
    /// message.
    #[must_use]
    pub const fn new(invite: OwnedMessage, over_tls: bool) -> Self {
        Self {
            invite,
            over_tls,
            branches: Vec::new(),
            refused: false,
            closed: false,
        }
    }

    /// The INVITE these dialogs came from.
    #[must_use]
    pub fn invite(&self) -> RawMessage<'_> {
        self.invite.as_raw()
    }

    /// Every dialog, in the order the branches answered.
    pub fn dialogs(&self) -> impl Iterator<Item = &Dialog> {
        self.branches.iter().map(|branch| &branch.dialog)
    }

    /// How many branches answered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.branches.len()
    }

    /// Whether nothing has answered yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.branches.is_empty()
    }

    /// One dialog by name.
    #[must_use]
    pub fn get(&self, key: &DialogKey) -> Option<&Dialog> {
        self.branch(key).map(|branch| &branch.dialog)
    }

    /// One dialog by name, to send inside or to take a request to.
    pub fn get_mut(&mut self, key: &DialogKey) -> Option<&mut Dialog> {
        self.branches
            .iter_mut()
            .find(|branch| branch.dialog.key() == key)
            .map(|branch| &mut branch.dialog)
    }

    /// A response to the INVITE arrived.
    ///
    /// # Errors
    /// [`DialogError::WrongKind`] for a request, and [`DialogError::Field`]
    /// or [`DialogError::Uri`] for a field the dialog needs and cannot read.
    pub fn on_response(&mut self, response: &RawMessage<'_>) -> Result<Fork, DialogError> {
        self.on_response_with_room(response, true)
    }

    /// [`DialogSet::on_response`], for a caller that holds its dialogs to a
    /// ceiling.
    ///
    /// With `room` false, a response that would open a branch the set does
    /// not have yet opens nothing and is [`Fork::Ignored`]. Every branch that
    /// is already open goes on taking its own responses, and a refusal still
    /// ends the early ones, because neither makes anything new to hold.
    ///
    /// # Errors
    /// As [`DialogSet::on_response`].
    pub(crate) fn on_response_with_room(
        &mut self,
        response: &RawMessage<'_>,
        room: bool,
    ) -> Result<Fork, DialogError> {
        let status = response.status().ok_or(DialogError::WrongKind)?;
        // §13.2.2.4 gives the answer window an end: 64*T1 after the first 2xx
        // "no more new 2xx responses are expected to arrive"
        if self.closed {
            return Ok(Fork::Ignored);
        }
        // "only 2xx and 101-199 responses with a To tag ... will establish a
        // dialog": a 100 is hop by hop and names nothing
        if status.is_provisional() && status.get() < 101 {
            return Ok(Fork::Ignored);
        }

        if status.is_final() && !status.is_success() {
            if self.refused {
                // "Subsequent final responses (which would only arrive under
                // error conditions) MUST be ignored."
                return Ok(Fork::Ignored);
            }
            self.refused = true;
            for branch in &mut self.branches {
                if branch.dialog.state() == DialogState::Early {
                    branch.dialog.terminate();
                }
            }
            return Ok(Fork::Refused);
        }

        // A provisional after the INVITE has been refused says nothing worth
        // keeping. A 2xx still does: it is a dialog the far end believes in,
        // and one nobody acknowledges is a call left standing at that end.
        if self.refused && !status.is_success() {
            return Ok(Fork::Ignored);
        }
        // a dialog is named by a tag, and a response without one names none
        if response.to()?.tag().is_none() {
            return Ok(Fork::Ignored);
        }

        let key = DialogKey::as_uac(response)?;
        if let Some(branch) = self
            .branches
            .iter_mut()
            .find(|branch| branch.dialog.key() == &key)
        {
            branch.dialog.on_response(response)?;
            return Ok(Fork::Advanced(key));
        }
        if !room {
            return Ok(Fork::Ignored);
        }

        let dialog = {
            let invite = self.invite.as_raw();
            Dialog::from_response(&invite, response, self.over_tls)?
        };
        self.branches.push(Branch { dialog, ack: None });
        Ok(Fork::Opened(key))
    }

    /// The answer window is over: 64*T1 after the first 2xx, "all the early
    /// dialogs that have not transitioned to established dialogs are
    /// terminated" (§13.2.2.4), and nothing further is expected.
    ///
    /// The clock belongs to the caller, as everywhere here; this is the same
    /// instant the INVITE client transaction leaves `Accepted`.
    pub fn no_more_answers(&mut self) {
        self.closed = true;
        for branch in &mut self.branches {
            if branch.dialog.state() == DialogState::Early {
                branch.dialog.terminate();
            }
        }
    }

    /// Whether a non-2xx final has answered the INVITE.
    #[must_use]
    pub const fn is_refused(&self) -> bool {
        self.refused
    }

    /// Whether the answer window has closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// The ACK for the 2xx that confirmed one of these dialogs (§13.2.2.4).
    ///
    /// # Errors
    /// [`DialogError::Field`] when the INVITE has no readable `CSeq`, and
    /// [`DialogError::NoRemoteTarget`] when the name is not one of ours.
    pub fn ack_2xx(&self, key: &DialogKey) -> Result<InDialogRequest, DialogError> {
        let branch = self.branch(key).ok_or(DialogError::NoSuchDialog)?;
        let invite = self.invite.as_raw();
        branch.dialog.ack_2xx(&invite)
    }

    /// Keep the ACK that went out, so a retransmitted 2xx can be answered
    /// without asking the caller for it again — and with the same bytes,
    /// answer included.
    ///
    /// # Errors
    /// [`DialogError::NoSuchDialog`] when the name is not one of ours.
    pub fn keep_ack(&mut self, key: &DialogKey, ack: OwnedMessage) -> Result<(), DialogError> {
        let branch = self
            .branches
            .iter_mut()
            .find(|branch| branch.dialog.key() == key)
            .ok_or(DialogError::NoSuchDialog)?;
        branch.ack = Some(ack);
        Ok(())
    }

    /// The ACK to send again for a retransmitted 2xx, if one was kept.
    #[must_use]
    pub fn ack_for(&self, key: &DialogKey) -> Option<&OwnedMessage> {
        self.branch(key).and_then(|branch| branch.ack.as_ref())
    }

    /// The tags the branches answered with, which is what a fork looks like
    /// from here.
    pub fn remote_tags(&self) -> impl Iterator<Item = Option<&Tag>> {
        self.branches
            .iter()
            .map(|branch| branch.dialog.key().remote_tag())
    }

    fn branch(&self, key: &DialogKey) -> Option<&Branch> {
        self.branches
            .iter()
            .find(|branch| branch.dialog.key() == key)
    }
}

impl core::fmt::Debug for DialogSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DialogSet")
            .field("invite", &self.invite)
            .field("over_tls", &self.over_tls)
            .field("dialogs", &self.branches.len())
            .field("refused", &self.refused)
            .field("closed", &self.closed)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{DialogSet, Fork};
    use crate::dialog::{DialogKey, DialogState};
    use crate::msg::{OwnedMessage, ParseMode, ParseScratch, RawMessage, parse};

    const INVITE: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
Max-Forwards: 70\r\n\
From: Alice <sip:alice@example.com>;tag=alice1\r\n\
To: Bob <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Authorization: Digest username=\"alice\", realm=\"example.com\", nonce=\"abc\", uri=\"sip:bob@example.com\", response=\"6629fae49393a05397450978507c4ef1\"\r\n\
Contact: <sip:alice@192.0.2.1>\r\n\
Content-Length: 0\r\n\
\r\n";

    fn with<R>(bytes: &[u8], f: impl FnOnce(&RawMessage<'_>) -> R) -> R {
        let mut scratch = ParseScratch::new();
        let message = parse(bytes, &mut scratch, ParseMode::Strict).expect("a message");
        f(&message)
    }

    fn owned(bytes: &[u8]) -> OwnedMessage {
        let mut scratch = ParseScratch::new();
        parse(bytes, &mut scratch, ParseMode::Strict)
            .expect("a message")
            .to_owned()
    }

    /// A response from one branch of the fork, told apart by its `To` tag.
    fn from_branch(status: u16, tag: &str, record_route: &str) -> Vec<u8> {
        format!(
            "SIP/2.0 {status} Whatever\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
{record_route}\
From: Alice <sip:alice@example.com>;tag=alice1\r\n\
To: Bob <sip:bob@example.com>;tag={tag}\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:bob@192.0.2.{}>\r\n\
Content-Length: 0\r\n\
\r\n",
            if tag == "bob1" { 4 } else { 5 }
        )
        .into_bytes()
    }

    fn set() -> DialogSet {
        DialogSet::new(owned(INVITE), false)
    }

    fn feed(set: &mut DialogSet, response: &[u8]) -> Fork {
        with(response, |response| {
            set.on_response(response).expect("a response")
        })
    }

    fn key_of(response: &[u8]) -> DialogKey {
        with(response, |response| {
            DialogKey::as_uac(response).expect("a key")
        })
    }

    fn state_of(set: &DialogSet, response: &[u8]) -> DialogState {
        set.get(&key_of(response)).expect("a dialog").state()
    }

    #[test]
    fn every_branch_that_answers_gets_a_dialog_of_its_own() {
        let mut set = set();
        let (first, second) = (from_branch(180, "bob1", ""), from_branch(180, "bob2", ""));
        assert_eq!(feed(&mut set, &first), Fork::Opened(key_of(&first)));
        assert_eq!(feed(&mut set, &second), Fork::Opened(key_of(&second)));
        assert_eq!(set.len(), 2);
        assert_eq!(state_of(&set, &first), DialogState::Early);
        assert_eq!(state_of(&set, &second), DialogState::Early);

        // and a second provisional on one branch is that dialog again
        assert_eq!(feed(&mut set, &first), Fork::Advanced(key_of(&first)));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn two_answers_are_two_calls_and_the_core_picks_neither() {
        let mut set = set();
        let (first, second) = (from_branch(200, "bob1", ""), from_branch(200, "bob2", ""));
        feed(&mut set, &first);
        feed(&mut set, &second);
        assert_eq!(set.len(), 2);
        assert_eq!(state_of(&set, &first), DialogState::Confirmed);
        assert_eq!(state_of(&set, &second), DialogState::Confirmed);
        assert_eq!(
            set.dialogs()
                .filter(|d| d.state() == DialogState::Confirmed)
                .count(),
            2,
            "both are up; which one to keep is not a question for this layer"
        );
    }

    #[test]
    fn a_refusal_ends_the_branches_still_ringing_and_leaves_the_answered_one() {
        let mut set = set();
        let (ringing, answered) = (from_branch(180, "bob1", ""), from_branch(200, "bob2", ""));
        feed(&mut set, &ringing);
        feed(&mut set, &answered);
        assert_eq!(feed(&mut set, &from_branch(486, "bob3", "")), Fork::Refused);
        assert!(set.is_refused());
        assert_eq!(state_of(&set, &ringing), DialogState::Terminated);
        assert_eq!(state_of(&set, &answered), DialogState::Confirmed);
    }

    #[test]
    fn a_second_refusal_is_ignored_but_a_2xx_is_not() {
        let mut set = set();
        feed(&mut set, &from_branch(486, "bob1", ""));
        assert_eq!(feed(&mut set, &from_branch(603, "bob2", "")), Fork::Ignored);
        assert_eq!(feed(&mut set, &from_branch(180, "bob2", "")), Fork::Ignored);

        // a 2xx is a call the far end believes in, and one nobody
        // acknowledges is a call left standing there
        let late = from_branch(200, "bob2", "");
        assert_eq!(feed(&mut set, &late), Fork::Opened(key_of(&late)));
        assert_eq!(state_of(&set, &late), DialogState::Confirmed);
    }

    #[test]
    fn a_100_and_a_tagless_response_name_nothing() {
        let mut set = set();
        assert_eq!(feed(&mut set, &from_branch(100, "bob1", "")), Fork::Ignored);
        let tagless = b"SIP/2.0 180 Ringing\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
From: Alice <sip:alice@example.com>;tag=alice1\r\n\
To: Bob <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        assert_eq!(feed(&mut set, tagless), Fork::Ignored);
        assert!(set.is_empty());
    }

    #[test]
    fn the_answer_window_ends_the_branches_that_never_answered() {
        let mut set = set();
        let (ringing, answered) = (from_branch(180, "bob1", ""), from_branch(200, "bob2", ""));
        feed(&mut set, &ringing);
        feed(&mut set, &answered);

        set.no_more_answers();
        assert!(set.is_closed());
        assert_eq!(state_of(&set, &ringing), DialogState::Terminated);
        assert_eq!(state_of(&set, &answered), DialogState::Confirmed);
        assert_eq!(
            feed(&mut set, &from_branch(200, "bob3", "")),
            Fork::Ignored,
            "no more 2xx responses are expected after that"
        );
    }

    #[test]
    fn the_confirming_2xx_recomputes_the_route_set() {
        // RFC 2543 mirrored Record-Route in the 2xx but not in the
        // provisional, so an early dialog can have the wrong path
        let mut set = set();
        let ringing = from_branch(180, "bob1", "");
        feed(&mut set, &ringing);
        assert!(
            set.get(&key_of(&ringing))
                .expect("a dialog")
                .route_set()
                .is_empty()
        );

        let answered = from_branch(
            200,
            "bob1",
            "Record-Route: <sip:p2.example.net;lr>\r\nRecord-Route: <sip:p1.example.net;lr>\r\n",
        );
        assert_eq!(feed(&mut set, &answered), Fork::Advanced(key_of(&answered)));
        let dialog = set.get(&key_of(&answered)).expect("a dialog");
        assert_eq!(dialog.state(), DialogState::Confirmed);
        assert_eq!(
            dialog
                .route_set()
                .iter()
                .map(crate::msg::Uri::as_str)
                .collect::<Vec<_>>(),
            ["sip:p1.example.net;lr", "sip:p2.example.net;lr"]
        );
    }

    #[test]
    fn the_ack_repeats_the_invites_number_and_its_credentials() {
        let mut set = set();
        let answered = from_branch(200, "bob1", "Record-Route: <sip:p1.example.net;lr>\r\n");
        feed(&mut set, &answered);

        let ack = set.ack_2xx(&key_of(&answered)).expect("an ACK");
        let message = ack
            .builder()
            .via(b"SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK2")
            .max_forwards(70)
            .build()
            .expect("a message");
        let bytes = message.as_raw().as_bytes();

        assert!(bytes.starts_with(b"ACK sip:bob@192.0.2.4 SIP/2.0\r\n"));
        assert!(
            find(bytes, b"CSeq: 314159 ACK\r\n"),
            "the number is the INVITE's, only the method changes"
        );
        assert!(find(bytes, b"Route: <sip:p1.example.net;lr>\r\n"));
        assert!(find(bytes, b"To: <sip:bob@example.com>;tag=bob1\r\n"));
        assert!(
            find(bytes, b"Authorization: Digest username=\"alice\""),
            "the same credentials as the INVITE"
        );
    }

    #[test]
    fn the_kept_ack_answers_the_next_copy_of_the_2xx() {
        let mut set = set();
        let answered = from_branch(200, "bob1", "");
        feed(&mut set, &answered);
        let key = key_of(&answered);
        assert!(set.ack_for(&key).is_none());

        let ack = set
            .ack_2xx(&key)
            .expect("an ACK")
            .builder()
            .via(b"SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK2")
            .max_forwards(70)
            .build()
            .expect("a message");
        set.keep_ack(&key, ack.clone()).expect("kept");

        // the 2xx arrives again: the same bytes go out again, answer included
        assert_eq!(feed(&mut set, &answered), Fork::Advanced(key.clone()));
        assert_eq!(
            set.ack_for(&key)
                .expect("the ACK again")
                .as_raw()
                .as_bytes(),
            ack.as_raw().as_bytes()
        );
    }

    fn find(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
