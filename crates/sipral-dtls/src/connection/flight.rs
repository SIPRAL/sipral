// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a connection sends: flights cut into records and packed into
//! datagrams, and the timer that sends a flight again.

use std::collections::VecDeque;
use std::mem;
use std::time::{Duration, Instant};

use super::{Retransmission, epoch_of};
use crate::Error;
use crate::alert::Alert;
use crate::handshake::{self, ChangeCipherSpec, HandshakeType};
use crate::record::{self, ContentType, GcmProtection, ProtocolVersion, WriteEpoch};

/// One entry of a flight.
pub(super) enum Item {
    /// A handshake message, kept whole. It is cut into fragments each time it
    /// goes out, so a retransmission carries the same message under the same
    /// `message_seq` in records of its own.
    Handshake {
        msg_type: HandshakeType,
        message_seq: u16,
        body: Vec<u8>,
    },
    /// ChangeCipherSpec, which RFC 6347 §4.2.5 treats "as part of the same
    /// flight as the associated Finished message".
    ChangeCipherSpec,
}

/// The sending half of the record layer.
pub(super) struct Writer {
    max_datagram: usize,
    pub(super) epoch0: WriteEpoch,
    pub(super) epoch1: Option<(WriteEpoch, GcmProtection)>,
    /// Whether this end's ChangeCipherSpec has gone out, after which alerts
    /// are sent protected.
    changed_cipher_spec: bool,
    /// The datagram being filled.
    datagram: Vec<u8>,
    pub(super) outbox: VecDeque<Vec<u8>>,
}

impl Writer {
    pub(super) const fn new(max_datagram: usize) -> Self {
        Self {
            max_datagram,
            epoch0: WriteEpoch::initial(),
            epoch1: None,
            changed_cipher_spec: false,
            datagram: Vec::new(),
            outbox: VecDeque::new(),
        }
    }

    /// Write a flight, every message cut to the datagram size and as many
    /// records packed into each datagram as fit (RFC 6347 §4.1.1 lets a
    /// datagram carry several).
    pub(super) fn flight(&mut self, items: &[Item]) -> Result<(), Error> {
        let written = self.flight_records(items);
        if written.is_err() {
            self.datagram.clear();
        }
        self.flush();
        written
    }

    fn flight_records(&mut self, items: &[Item]) -> Result<(), Error> {
        for item in items {
            match item {
                Item::Handshake {
                    msg_type,
                    message_seq,
                    body,
                } => {
                    let epoch = epoch_of(*msg_type);
                    let overhead = if epoch == 0 { 0 } else { record::GCM_OVERHEAD };
                    let budget = handshake::record_payload_budget(self.max_datagram, overhead)?;
                    for fragment in
                        handshake::fragment_message(*msg_type, *message_seq, body, budget)?
                    {
                        self.record(epoch, ContentType::HANDSHAKE, &fragment)?;
                    }
                }
                Item::ChangeCipherSpec => {
                    self.record(
                        0,
                        ContentType::CHANGE_CIPHER_SPEC,
                        &ChangeCipherSpec.encode(),
                    )?;
                    self.changed_cipher_spec = true;
                }
            }
        }
        Ok(())
    }

    /// An alert, in a datagram of its own, in the epoch this end writes in.
    pub(super) fn alert(&mut self, alert: Alert) -> Result<(), Error> {
        let epoch = u16::from(self.changed_cipher_spec && self.epoch1.is_some());
        self.flush();
        let written = self.record(epoch, ContentType::ALERT, &alert.encode());
        self.flush();
        written
    }

    /// Application data, one record to a datagram as RFC 5764 §4.1 asks.
    pub(super) fn application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        self.flush();
        let written = self.record(1, ContentType::APPLICATION_DATA, data);
        self.flush();
        written
    }

    /// One unprotected handshake record under a record sequence number the
    /// caller chooses, outside the epoch's own count: a stateless server's
    /// HelloVerifyRequest, which RFC 6347 §4.2.1 sends under the sequence
    /// number of the ClientHello it answers.
    pub(super) fn stateless(&mut self, sequence: u64, fragment: &[u8]) -> Result<(), Error> {
        let mut out = Vec::new();
        record::encode_plaintext(
            ContentType::HANDSHAKE,
            ProtocolVersion::DTLS_1_2,
            0,
            sequence,
            fragment,
            &mut out,
        )?;
        self.flush();
        self.outbox.push_back(out);
        Ok(())
    }

    fn record(
        &mut self,
        epoch: u16,
        content_type: ContentType,
        payload: &[u8],
    ) -> Result<(), Error> {
        let mut out = Vec::with_capacity(record::HEADER_LEN + record::GCM_OVERHEAD + payload.len());
        if epoch == 0 {
            let sequence = self.epoch0.next_sequence()?;
            record::encode_plaintext(
                content_type,
                ProtocolVersion::DTLS_1_2,
                0,
                sequence,
                payload,
                &mut out,
            )?;
        } else {
            let (write, protection) = self.epoch1.as_mut().ok_or(Error::NotConnected)?;
            let sequence = write.next_sequence()?;
            protection.seal(
                content_type,
                ProtocolVersion::DTLS_1_2,
                write.epoch(),
                sequence,
                payload,
                &mut out,
            )?;
        }
        if !self.datagram.is_empty() && self.datagram.len() + out.len() > self.max_datagram {
            self.flush();
        }
        self.datagram.extend_from_slice(&out);
        Ok(())
    }

    fn flush(&mut self) {
        if !self.datagram.is_empty() {
            self.outbox.push_back(mem::take(&mut self.datagram));
        }
    }
}

/// What the timer found when it was asked.
pub(super) enum Expiry {
    /// Nothing is due.
    NotYet,
    /// Send the flight again.
    Retransmit,
    /// The attempts are spent.
    GiveUp,
}

/// The retransmission timer of RFC 6347 §4.2.4.1.
pub(super) struct Timer {
    settings: Retransmission,
    timeout: Duration,
    retransmissions: u32,
    deadline: Option<Instant>,
}

impl Timer {
    pub(super) const fn new(settings: Retransmission) -> Self {
        Self {
            settings,
            timeout: settings.initial,
            retransmissions: 0,
            deadline: None,
        }
    }

    pub(super) const fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// A new flight has gone out. It is timed only when it expects an answer.
    ///
    /// "Implementations SHOULD retain the current timer value until a
    /// transmission without loss occurs, at which time the value may be
    /// reset to the initial value": a flight that needed no retransmission
    /// was such a transmission, and the next one starts from the initial
    /// value again; after one that did, it starts from where that one left
    /// off.
    pub(super) fn start(&mut self, now: Instant, expects_reply: bool) {
        if self.retransmissions == 0 {
            self.timeout = self.settings.initial;
        }
        self.retransmissions = 0;
        self.deadline = if expects_reply {
            now.checked_add(self.timeout)
        } else {
            None
        };
    }

    /// Whether the flight is due to go out again, and if so, the timer
    /// doubled — "double the value at each retransmission, up to" the cap.
    pub(super) fn expire(&mut self, now: Instant) -> Expiry {
        match self.deadline {
            Some(deadline) if now >= deadline => {}
            _ => return Expiry::NotYet,
        }
        if self.retransmissions >= self.settings.attempts {
            self.deadline = None;
            return Expiry::GiveUp;
        }
        self.retransmissions += 1;
        self.timeout = self.timeout.saturating_mul(2).min(self.settings.max);
        self.deadline = now.checked_add(self.timeout);
        Expiry::Retransmit
    }

    /// The flight went out again on the peer's prompting: wait the current
    /// value from now, without doubling it or spending an attempt, since a
    /// peer that retransmits is a peer that is there.
    pub(super) fn restart(&mut self, now: Instant) {
        if self.deadline.is_some() {
            self.deadline = now.checked_add(self.timeout);
        }
    }

    pub(super) const fn stop(&mut self) {
        self.deadline = None;
    }
}
