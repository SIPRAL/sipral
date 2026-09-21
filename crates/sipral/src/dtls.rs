// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! DTLS-SRTP: the handshake that keys a call, on the call's own media path.
//!
//! `sipral-dtls` has RFC 5764's handshake and `sipral-rtp` has RFC 3711's
//! stream, and until this module neither had ever met the other: an offer
//! could carry `a=fingerprint`, a peer's could be read back, and a plan keyed
//! that way was then refused rather than opened, because nothing in the tree
//! could produce a key on the media path. This is the joint.
//!
//! # What crosses the boundary
//!
//! Three things, and they are the three the layers below cannot have:
//!
//! - **An identity.** A P-256 key and a self-signed certificate, made once per
//!   [`MediaEngine`](crate::MediaEngine) and named in every offer it writes by
//!   the fingerprint of that certificate. [`Identity`].
//! - **A role.** Which end sends the ClientHello, which RFC 5763 §5 takes from
//!   the `a=setup` of the offer and of the answer together — so the facade has
//!   to remember what it wrote as well as read what arrived. [`Role`].
//! - **A driver.** The connection is sans-I/O like everything else here: it
//!   takes datagrams, gives datagrams back, and asks to be woken. [`Handshake`]
//!   is what a [`MediaSession`](crate::MediaSession) drives it through.
//!
//! # Where the randomness comes from
//!
//! The media engine's own [`KeySource`], which is the stream every SRTP master
//! key is already drawn from and is deliberately not the endpoint's: the
//! endpoint's seed is written in clear into every replay recording, and a
//! recording that carried the means to derive a call's certificate key would
//! carry the means to impersonate the stack that made it.
//!
//! What a poor media seed costs here is the same thing it costs SDES — the
//! whole of the encryption — and it costs it just as quietly.
//!
//! # What this module refuses
//!
//! A handshake that cannot be authenticated. `peer_fingerprints` is required
//! to be non-empty by `sipral-dtls` itself, and a description that named
//! `UDP/TLS/RTP/SAVP` without an `a=fingerprint` never becomes a
//! [`Keying::Dtls`](sipral_core::sdp::Keying::Dtls) in the first place, so
//! there is no path here that opens a stream against a certificate nobody
//! vouched for.
//!
//! An SRTP profile there are no keys for. `sipral-dtls` offers only the two
//! AES-128 counter-mode profiles and refuses the NULL ones outright (RFC 8827
//! §6.5 forbids negotiating encryption away); [`suite_of`] is the other half
//! of that, and a profile it does not know stops the stream rather than
//! opening it on terms nobody agreed.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::auth::KeySource;
use sipral_core::sdp::Keying;
use sipral_dtls::handshake::SrtpProtectionProfile;
use sipral_dtls::keys::EcdsaKey;
use sipral_dtls::setup::{Party, Setup, dtls_role};
use sipral_dtls::x509::{Certificate, CertificateParams, Fingerprint};
use sipral_dtls::{Config, Connection, Event, Random, Retransmission, Role, SrtpKeying, State};
use sipral_rtp::srtp::{Master, Policy, Security, Suite};
use zeroize::Zeroizing;

use crate::error::MediaError;

/// How long a certificate this stack makes says it is good for, each way
/// from the moment it was made.
///
/// Thirty days, which is nothing to do with trust: a DTLS-SRTP certificate is
/// checked against the fingerprint in this very call's signalling and against
/// nothing else (RFC 8122 §5.1), so no clock anywhere decides whether it is
/// the right one. The period exists because RFC 5280 §4.1.2.5 requires one to
/// be written. It runs backwards as well as forwards because the two ends of
/// a call do not agree on the time, and a peer that does check the period —
/// Asterisk with `dtls_verify` set to more than the fingerprint is the one
/// that does — would otherwise refuse a certificate made a minute ago by a
/// stack whose clock is a minute behind its own.
const CERTIFICATE_LIFETIME: u64 = 30 * 24 * 60 * 60;

/// How long before a certificate runs out that a fresh one is made.
///
/// A day, which is longer than any call: a certificate minted at the start of
/// a call must still be good at the end of it, and re-minting mid-call would
/// change the fingerprint this stack already put in an offer.
const RENEW_WITHIN: u64 = 24 * 60 * 60;

/// The `a=setup` an offer from this stack carries.
///
/// `actpass` is what RFC 5763 §5 requires of an offerer — "The endpoint MUST
/// use the setup attribute defined in \[RFC4145\]. The endpoint that is the
/// offerer MUST use the setup attribute value of setup:actpass" — and it is
/// also the one that lets the answerer be the client, which saves the
/// handshake a round trip.
pub(crate) const OFFERED_SETUP: Setup = Setup::ActPass;

/// The most expensive policy a handshake here could settle on, for a stream
/// sizing its buffers before it knows which one it got.
///
/// Both profiles `sipral-dtls` will negotiate are AES-128 in counter mode and
/// differ only in the tag, so the longer tag is the upper bound. See
/// [`RtpSession::awaiting`](sipral_rtp::RtpSession::awaiting).
pub(crate) const MOST: Policy = Policy::new(Suite::AesCm80);

/// Random octets for the handshake, out of the media engine's key stream.
///
/// One 32-octet block at a time, handed out in order and never twice: the
/// counter behind [`KeySource`] does not repeat, so neither does anything
/// drawn here. A block is held only until it is spent.
struct Source<'a> {
    keys: &'a mut KeySource,
    block: [u8; 32],
    used: usize,
}

impl<'a> Source<'a> {
    fn new(keys: &'a mut KeySource) -> Self {
        // `used` at the width of a block means the first fill draws one,
        // rather than handing out a block of zeros nobody asked for
        Self {
            keys,
            block: [0; 32],
            used: 32,
        }
    }
}

impl Random for Source<'_> {
    fn fill(&mut self, dest: &mut [u8]) {
        for slot in dest {
            if self.used >= self.block.len() {
                self.block = self.keys.block();
                self.used = 0;
            }
            *slot = self.block.get(self.used).copied().unwrap_or(0);
            self.used += 1;
        }
    }
}

/// This stack's DTLS identity: one key, one certificate, one fingerprint.
///
/// One per [`MediaEngine`](crate::MediaEngine) and not one per call. A
/// certificate here authenticates nothing but "the far end of this handshake
/// is the end the signalling described", and the signalling is what carries
/// the fingerprint, so a fresh certificate per call would buy unlinkability
/// against an observer who is already watching the `a=fingerprint` go past in
/// the same SDP. What it would cost is a P-256 key pair and a signature on
/// every call setup, on a device whose battery the call is already the
/// expensive part of.
///
/// Neither `Clone` nor `Copy`: the private key is the whole of the identity.
#[derive(Debug)]
pub struct Identity {
    key: EcdsaKey,
    certificate: Certificate,
    /// The value of the `a=fingerprint` this end writes, kept rather than
    /// recomputed: it goes into every offer and every answer, and hashing a
    /// certificate that has not changed to get the same string back is work
    /// for nothing.
    fingerprint: String,
    /// When the certificate stops saying it is valid, in seconds since 1970.
    ///
    /// Kept so that a process which outlives its own certificate — a desk
    /// phone or an agent runs for months, and `MediaEngine` is made once —
    /// mints a fresh one rather than offering an expired one for ever. See
    /// [`Identity::is_stale`].
    not_after: u64,
}

impl Identity {
    /// Make one, drawing from the engine's key stream.
    ///
    /// `unix_seconds` is the wall clock, which the validity period needs and
    /// which nothing in this tree reads for itself.
    ///
    /// # Errors
    /// [`MediaError::DtlsIdentity`] when the key or the certificate cannot be
    /// made — which with a sound key source does not happen, and with an
    /// unsound one is exactly the failure worth reporting rather than
    /// papering over.
    pub(crate) fn new(keys: &mut KeySource, unix_seconds: u64) -> Result<Self, MediaError> {
        let mut source = Source::new(keys);
        let key = EcdsaKey::generate(&mut source).map_err(|_| MediaError::DtlsIdentity)?;
        // the common name identifies nobody and is checked by nobody (RFC
        // 8122 §5.1 puts the whole of the identity in the fingerprint), so it
        // says what the certificate is for and carries no name at all
        let not_after = unix_seconds.saturating_add(CERTIFICATE_LIFETIME);
        let params = CertificateParams {
            common_name: "Sipral DTLS-SRTP",
            not_before: unix_seconds.saturating_sub(CERTIFICATE_LIFETIME),
            not_after,
        };
        let certificate = Certificate::self_signed(&key, &params, &mut source)
            .map_err(|_| MediaError::DtlsIdentity)?;
        let fingerprint = certificate.fingerprint().to_string();
        Ok(Self {
            key,
            certificate,
            fingerprint,
            not_after,
        })
    }

    /// Whether this certificate is close enough to running out that the next
    /// call should be offered a fresh one.
    ///
    /// The wall clock comes from the caller here as it does everywhere else;
    /// nothing in this tree reads one for itself.
    pub(crate) const fn is_stale(&self, unix_seconds: u64) -> bool {
        unix_seconds.saturating_add(RENEW_WITHIN) >= self.not_after
    }

    /// The `a=fingerprint` value this end writes, as it goes into a
    /// description.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// How long a whole handshake is given before the call is told it will not
/// happen, given the retransmission schedule the client end runs.
///
/// DTLS's own limit is one-sided and this is why the facade needs one at all.
/// A client's flights are retransmitted on the schedule of RFC 6347 §4.2.4.1
/// and given up after `attempts` of them; a server that has received no
/// ClientHello has no flight to retransmit, so its timer is never armed and
/// `Connection::poll_timeout` answers `None` while the state is still
/// `Handshaking` — it would wait for the length of the call. Both ends of a
/// call have to reach the same answer in about the same time, so the budget
/// is the client's own schedule added up: every wait it would take, and then
/// the last one it would spend waiting for the answer that never came.
fn budget(schedule: Retransmission) -> Duration {
    let mut total = Duration::ZERO;
    let mut wait = schedule.initial;
    for _ in 0..schedule.attempts {
        total = total.saturating_add(wait);
        wait = wait.saturating_mul(2).min(schedule.max);
    }
    total.saturating_add(schedule.max)
}

/// One call's handshake, and the records it owes the far end.
#[derive(Debug)]
pub(crate) struct Handshake {
    connection: Connection,
    /// What `poll_transmit` has produced and the caller has not taken. Owned
    /// octets, because `sipral-dtls` allocates each datagram and there is no
    /// buffer of the session's to borrow one from.
    ///
    /// Where they go is not kept here. The session addresses each record: to
    /// the address the far end's own records came from while RTP has no latch
    /// of its own — which is the whole handshake, since RTP can only latch on
    /// a packet it has keys to authenticate — and to the signalled address
    /// before the far end has said anything. See
    /// [`MediaSession::poll_transmit`](crate::MediaSession::poll_transmit).
    outbound: VecDeque<Vec<u8>>,
    /// The keys, once the handshake exported them, waiting to be collected by
    /// the session that will install them.
    keyed: Option<Result<Exported, MediaError>>,
    /// Whether the handshake has already reported that it failed, so that a
    /// connection that keeps being driven does not report it again.
    reported: bool,
    /// When this handshake gives up, whatever the connection's own timer
    /// says. See [`budget`].
    expires: Instant,
    /// Whether the budget above has run out, which the connection itself has
    /// no way of knowing.
    expired: bool,
    /// What a new association on the same call is started with
    /// ([`Handshake::renewal`]): the certificate this end presents, the
    /// fingerprints the far end's has to match, and this handshake's own
    /// randomness.
    identity: Arc<Identity>,
    peers: Vec<Fingerprint>,
    keys: KeySource,
}

/// What a finished handshake exported, per direction, before it is made into
/// a stream's contexts.
///
/// Kept apart rather than made into a [`Security`] on the spot, because a
/// stream keyed once opens its contexts from it and a stream already running
/// replaces each direction's (RFC 6347 §4.2.8, a new association) the way a
/// re-key does, with the old receive context kept for the packets already in
/// flight under it.
pub(crate) struct Exported {
    pub(crate) suite: Suite,
    pub(crate) policy: Policy,
    /// What protects what this end sends.
    pub(crate) local: Master,
    /// What opens what arrives.
    pub(crate) remote: Master,
}

impl Exported {
    /// The contexts a stream that was waiting for its keys opens with.
    pub(crate) fn into_security(self) -> Security {
        Security::new(self.policy, self.local, self.policy, self.remote)
    }
}

impl core::fmt::Debug for Exported {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // two master keys and their salts: the suite is all a log may see
        f.debug_struct("Exported")
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

impl Handshake {
    /// Start the handshake a settled plan calls for, or `None` where the plan
    /// calls for none.
    ///
    /// `party` is which side of the offer/answer exchange this end was and
    /// `ours` is the `a=setup` it wrote; `keying` is what the negotiation read
    /// off the peer's description. `None` comes back for a peer that answered
    /// `holdconn` — "no connection for the time being" — which is a plan with
    /// no handshake in it rather than a failure.
    ///
    /// # Errors
    /// [`MediaError::DtlsRole`] for a pair of `a=setup` values RFC 4145 §4.1
    /// does not allow together, or a value that is not one of the four;
    /// [`MediaError::DtlsFingerprint`] for an `a=fingerprint` that cannot be
    /// read or names a hash this build does not have; and
    /// [`MediaError::DtlsHandshake`] for a configuration no handshake can
    /// come of.
    pub(crate) fn start(
        identity: &Arc<Identity>,
        keying: &Keying,
        party: Party,
        ours: Setup,
        keys: &mut KeySource,
        now: Instant,
    ) -> Result<Option<Self>, MediaError> {
        let Keying::Dtls {
            fingerprints,
            setup,
        } = keying
        else {
            return Ok(None);
        };
        let theirs = match setup {
            Some(written) => Some(Setup::parse(written).map_err(|_| MediaError::DtlsRole)?),
            None => None,
        };
        let (offer, answer) = match party {
            Party::Offerer => (Some(ours), theirs),
            Party::Answerer => (theirs, Some(ours)),
        };
        let Some(role) = dtls_role(party, offer, answer).map_err(|_| MediaError::DtlsRole)? else {
            return Ok(None);
        };
        // every line that parses, and a failure only when none does: a peer
        // that wrote one fingerprint under a hash this build has and one
        // under a hash it does not has still said something checkable, and
        // RFC 8122 §5 is why it wrote both
        let peers: Vec<Fingerprint> = fingerprints
            .iter()
            .filter_map(|written| Fingerprint::parse(written).ok())
            .collect();
        if peers.is_empty() {
            return Err(MediaError::DtlsFingerprint);
        }
        let seed = Zeroizing::new(keys.block());
        Self::begin(
            Arc::clone(identity),
            peers,
            role,
            KeySource::new(*seed),
            now,
        )
        .map(Some)
    }

    /// A handshake in `role`, presenting `identity` and requiring a peer
    /// certificate `peers` names, drawing its randomness from `keys`.
    ///
    /// The randomness is the handshake's own from here on: a stream seeded
    /// once from the engine's, so that a new association the session starts
    /// by itself (see [`Handshake::renewal`]) draws from somewhere that never
    /// hands out a block the engine does.
    fn begin(
        identity: Arc<Identity>,
        peers: Vec<Fingerprint>,
        role: Role,
        mut keys: KeySource,
        now: Instant,
    ) -> Result<Self, MediaError> {
        let schedule = Retransmission::default();
        let mut config = Config::new(
            role,
            identity.key.clone(),
            identity.certificate.clone(),
            peers.clone(),
        );
        config.retransmission = schedule;
        let mut source = Source::new(&mut keys);
        let connection =
            Connection::new(config, &mut source, now).map_err(|_| MediaError::DtlsHandshake)?;
        let mut handshake = Self {
            connection,
            outbound: VecDeque::new(),
            keyed: None,
            reported: false,
            expires: now
                .checked_add(budget(schedule))
                .ok_or(MediaError::DtlsHandshake)?,
            expired: false,
            identity,
            peers,
            keys,
        };
        // a client's ClientHello is already waiting, and a server's outbox is
        // empty; draining here means the caller never has to know which
        handshake.drain();
        Ok(handshake)
    }

    /// A new association on the same call, in the same role, with the same
    /// certificates on both sides: RFC 6347 §4.2.8.
    ///
    /// "In cases where a server believes it has an existing association on a
    /// given host/port quartet and it receives an epoch=0 ClientHello, it
    /// SHOULD proceed with a new handshake but MUST NOT destroy the existing
    /// association until the client has demonstrated reachability either by
    /// completing a cookie exchange or by completing a complete handshake
    /// including delivering a verifiable Finished message." Some peers start
    /// one on every re-negotiation — Asterisk does, on a hold and again on the
    /// resume — and a server that ignored the ClientHello left the far end
    /// waiting on a handshake that never came and the call silent. The session
    /// runs the two side by side and keeps the old keys until this one has
    /// produced new ones; see `MediaSession::receive`.
    ///
    /// # Errors
    /// [`MediaError::DtlsHandshake`] for a configuration no handshake can come
    /// of, which the one this was made from already came of.
    pub(crate) fn renewal(&mut self, now: Instant) -> Result<Self, MediaError> {
        let seed = Zeroizing::new(self.keys.block());
        Self::begin(
            Arc::clone(&self.identity),
            self.peers.clone(),
            self.role(),
            KeySource::new(*seed),
            now,
        )
    }

    /// Whether this handshake has finished and produced keys: the only state
    /// a new association can replace (RFC 6347 §4.2.8).
    pub(crate) fn is_keyed(&self) -> bool {
        matches!(self.connection.state(), State::Connected)
    }

    /// Take a datagram the demux said is a DTLS record.
    pub(crate) fn on_datagram(&mut self, datagram: &[u8], now: Instant) {
        self.connection.handle_datagram(datagram, now);
        self.drain();
    }

    /// When the handshake must be woken again: the connection's own
    /// retransmission deadline, or the budget, whichever comes first.
    ///
    /// Never `None` while the handshake is running, which is the point. A
    /// server waiting for a ClientHello has no retransmission deadline at
    /// all, and a caller that asked the connection directly would be told
    /// there is nothing to wake for.
    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        if self.finished() {
            return None;
        }
        Some(match self.connection.poll_timeout() {
            Some(deadline) => deadline.min(self.expires),
            None => self.expires,
        })
    }

    /// Let time pass.
    pub(crate) fn on_timeout(&mut self, now: Instant) {
        self.connection.handle_timeout(now);
        if now >= self.expires && !self.expired && !self.finished() {
            self.expired = true;
            if !self.reported {
                self.reported = true;
                self.keyed = Some(Err(MediaError::DtlsHandshake));
            }
        }
        self.drain();
    }

    /// The next record to put on the media socket. Where it goes is the
    /// session's to say; see [`Handshake::outbound`].
    pub(crate) fn take_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    /// The keys, once, or the reason there will not be any, once.
    ///
    /// `None` while the handshake is still running, and `None` for ever after
    /// either answer has been taken: a session installs keys once and reports
    /// a failure once.
    pub(crate) fn take_outcome(&mut self) -> Option<Result<Exported, MediaError>> {
        self.keyed.take()
    }

    /// Which end of the association this one is, fixed when the handshake
    /// was started and for as long as the association lasts.
    pub(crate) const fn role(&self) -> Role {
        self.connection.role()
    }

    /// Whether this handshake is done with, either way — including having
    /// spent its budget, which the connection itself has no way of knowing.
    pub(crate) fn finished(&self) -> bool {
        self.expired || !matches!(self.connection.state(), State::Handshaking)
    }

    /// Say goodbye on the way out.
    ///
    /// RFC 6347 §4.2.8 has `close_notify` end a connection properly, and a
    /// peer that gets one stops retransmitting a flight into a call that has
    /// already hung up. The records it produces are drained like any others;
    /// whether the caller gets to send them before the socket closes is the
    /// caller's affair, and nothing here waits for an answer.
    pub(crate) fn close(&mut self) {
        self.connection.close();
        self.drain();
    }

    /// Move everything the connection has produced into this type: the
    /// records to send, and the one outcome worth reporting upwards.
    fn drain(&mut self) {
        while let Some(record) = self.connection.poll_transmit() {
            self.outbound.push_back(record);
        }
        while let Some(event) = self.connection.poll_event() {
            match event {
                Event::Connected(keying) => {
                    if !self.reported {
                        self.reported = true;
                        self.keyed = Some(security_of(&keying));
                    }
                }
                Event::Failed(_) => {
                    if !self.reported {
                        self.reported = true;
                        self.keyed = Some(Err(MediaError::DtlsHandshake));
                    }
                }
                Event::Closed => {
                    if !self.reported {
                        self.reported = true;
                        self.keyed = Some(Err(MediaError::DtlsClosed));
                    }
                }
                // RFC 5764 §4.1 carries the media in SRTP, outside DTLS, so
                // this stack sends none and has nothing to do with any a peer
                // sends. Dropping it is not a refusal of the handshake: the
                // keys are what the connection is for, and they are unaffected
                Event::ApplicationData(_) => {}
            }
        }
    }
}

/// The pair of SRTP contexts a completed handshake opens the stream with.
///
/// RFC 5764 §4.2 exports one key and salt per direction and `sipral-dtls`
/// arranges them for the end that asked, so "local" protects what this end
/// sends and "remote" opens what arrives — the same split RFC 4568 §7.1.1
/// gives SDES, reached a different way.
///
/// # Errors
/// [`MediaError::DtlsProfile`] for a protection profile this build has no
/// transform for. `sipral-dtls` negotiates only the two it offers, so this is
/// the arm that a future profile added on one side of the boundary and not the
/// other would land in, loudly, rather than silently opening a stream with the
/// wrong transform.
fn security_of(keying: &SrtpKeying) -> Result<Exported, MediaError> {
    let suite = suite_of(keying.profile())?;
    // RFC 5764 §4.1.2 fixes the key derivation rate at zero and agrees no
    // MKI, which is what `Policy::new` already sets: a single derivation and
    // no identifier
    Ok(Exported {
        suite,
        policy: Policy::new(suite),
        local: Master::new(*keying.local_master_key(), *keying.local_master_salt()),
        remote: Master::new(*keying.remote_master_key(), *keying.remote_master_salt()),
    })
}

/// Whether a datagram is the first flight of a new association: a plaintext
/// epoch-0 handshake record whose message is a ClientHello with the first
/// message sequence number (RFC 6347 §4.1, §4.2.2).
///
/// Read off the header alone, because this is asked of a record the running
/// connection would otherwise take and ignore. The record header is thirteen
/// octets — type, version, a sixteen-bit epoch, a forty-eight-bit sequence,
/// a length — and the handshake header after it opens with the message type
/// and, four octets on, the message sequence.
pub(crate) fn begins_an_association(datagram: &[u8]) -> bool {
    const CLIENT_HELLO: u8 = 1;
    datagram.first() == Some(&22)
        && datagram.get(3..5) == Some(&[0, 0][..])
        && datagram.get(13) == Some(&CLIENT_HELLO)
        && datagram.get(17..19) == Some(&[0, 0][..])
}

/// The transform a DTLS-SRTP protection profile names, on the media side of
/// the boundary.
///
/// Two enumerations of the same transforms, for the same reason the SDES side
/// has two: the crate that runs a handshake and the crate that encrypts
/// packets do not depend on each other, and neither should have to learn the
/// other's spelling.
fn suite_of(profile: SrtpProtectionProfile) -> Result<Suite, MediaError> {
    match profile {
        SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80 => Ok(Suite::AesCm80),
        SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32 => Ok(Suite::AesCm32),
        _ => Err(MediaError::DtlsProfile),
    }
}

/// What this end writes for `a=setup`, given which party it is and, for an
/// answerer, what the offer said.
///
/// An offerer writes `actpass` (RFC 5763 §5). An answerer writes the value
/// RFC 4145 §4.1's table leaves it, which for the `actpass` every conforming
/// offer carries is `active` — the end that sends the ClientHello, so its
/// first flight can leave with the answer rather than wait for the answer to
/// arrive.
///
/// # Errors
/// [`MediaError::DtlsRole`] for an offer whose `a=setup` is not one of the
/// four values RFC 4145 §4 defines.
pub(crate) fn setup_to_write(party: Party, theirs: Option<&str>) -> Result<Setup, MediaError> {
    match party {
        Party::Offerer => Ok(OFFERED_SETUP),
        Party::Answerer => {
            // §4.1: "active" is the default in an offer that wrote no
            // attribute at all, and the answer follows from that the same way
            let offered = match theirs {
                Some(written) => Setup::parse(written).map_err(|_| MediaError::DtlsRole)?,
                None => Setup::Active,
            };
            Ok(Setup::answer_to(offered))
        }
    }
}

/// Whether two lists of `a=fingerprint` values name the same certificate.
///
/// Compared as sets. RFC 8842 §3.1 asks for a new association when
/// fingerprints are "modified, added, or removed", and a peer that writes its
/// lines — one per hash function, RFC 8122 §5 — in another order, or repeats
/// one, has done none of those. Without regard to case as well, because the
/// hexadecimal is the same number however it is written.
pub(crate) fn same_fingerprints(had: &[String], now: &[String]) -> bool {
    let set = |values: &[String]| {
        let mut normal: Vec<String> = values
            .iter()
            .map(|value| value.to_ascii_lowercase())
            .collect();
        normal.sort_unstable();
        normal.dedup();
        normal
    };
    set(had) == set(now)
}

/// What this end answers a re-offer with, on a call whose association has
/// already given it `role` (RFC 8842 §5.3).
///
/// "The answerer MUST insert an SDP 'setup' attribute with an attribute value
/// that does not change the previously negotiated DTLS roles." Against the
/// `actpass` §5.5 asks every subsequent offer for, that is simply the role in
/// force. Against the concrete value an older peer still writes (§5.3 asks
/// that it be understood), RFC 4145 §4.1 leaves one answer, and when that
/// answer is the other role the offer is asking for a new association.
///
/// # Errors
/// [`MediaError::DtlsRoleChanged`] for an offer whose value leaves this end
/// only the role it does not have — including one that wrote no value at
/// all, which §4.1 reads as `active` — and [`MediaError::DtlsRole`] for a
/// value that is not one of the four.
pub(crate) fn setup_to_keep(role: Role, theirs: Option<&str>) -> Result<Setup, MediaError> {
    let offered = match theirs {
        Some(written) => Setup::parse(written).map_err(|_| MediaError::DtlsRole)?,
        None => Setup::Active,
    };
    let ours = match role {
        Role::Client => Setup::Active,
        Role::Server => Setup::Passive,
    };
    match offered {
        // "no connection for the time being": nothing to take a role in, and
        // §4.1 has one answer to it
        Setup::HoldConn => Ok(Setup::HoldConn),
        Setup::ActPass => Ok(ours),
        concrete if Setup::answer_to(concrete) == ours => Ok(ours),
        _ => Err(MediaError::DtlsRoleChanged),
    }
}

/// The role a re-negotiation gives this end, from the `a=setup` it wrote and
/// the one the far end wrote, or `None` where it gives none to compare.
///
/// Read without asking which of the two was the offer, because this end's
/// own writing already says so: it writes `actpass` only into an offer (RFC
/// 8842 §5.5) and a concrete role only into an answer, or into an offer it is
/// repeating unchanged. A concrete value here is the role, whichever side it
/// was written on. `actpass` leaves the role to the answer — `active` there
/// makes this end the server, `passive` or nothing at all (RFC 4145 §4.1's
/// default for an answer) the client. `holdconn` on either side takes no
/// role, and there is nothing to compare.
///
/// # Errors
/// [`MediaError::DtlsRole`] for a pair §4.1 does not allow together: the
/// same concrete role on both sides, or `actpass` answered with `actpass`.
pub(crate) fn role_after(ours: Setup, theirs: Option<Setup>) -> Result<Option<Role>, MediaError> {
    match (ours, theirs) {
        (Setup::HoldConn, _) | (_, Some(Setup::HoldConn)) => Ok(None),
        (Setup::Active, Some(Setup::Active))
        | (Setup::Passive, Some(Setup::Passive))
        | (Setup::ActPass, Some(Setup::ActPass)) => Err(MediaError::DtlsRole),
        (Setup::Active, _) | (Setup::ActPass, Some(Setup::Passive) | None) => {
            Ok(Some(Role::Client))
        }
        (Setup::Passive, _) | (Setup::ActPass, Some(Setup::Active)) => Ok(Some(Role::Server)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Handshake, Identity, MOST, Source, budget, role_after, same_fingerprints, setup_to_keep,
        setup_to_write, suite_of,
    };
    use sipral_core::auth::KeySource;
    use sipral_core::sdp::Keying;
    use sipral_dtls::handshake::SrtpProtectionProfile;
    use sipral_dtls::setup::{Party, Setup};
    use sipral_dtls::{Random, Retransmission, Role};
    use sipral_rtp::srtp::Suite;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::error::MediaError;

    /// A wall clock in the middle of the period any certificate this module
    /// writes is good for; the number itself says nothing, because nothing
    /// checks it.
    const NOW_UNIX: u64 = 1_790_000_000;

    fn identity(seed: u8) -> (Arc<Identity>, KeySource) {
        let mut keys = KeySource::new([seed; 32]);
        let identity = Identity::new(&mut keys, NOW_UNIX).expect("an identity");
        (Arc::new(identity), keys)
    }

    #[test]
    fn the_key_stream_hands_out_every_octet_once_and_in_order() {
        // the same seed, drawn in one go and drawn in pieces, is the same
        // stream: a handshake that drew a key and then a serial number must
        // not have been handed the same block twice
        let mut whole = KeySource::new([9; 32]);
        let mut in_pieces = KeySource::new([9; 32]);
        let mut all = [0_u8; 96];
        Source::new(&mut whole).fill(&mut all);

        let mut rebuilt = [0_u8; 96];
        {
            let mut source = Source::new(&mut in_pieces);
            for chunk in rebuilt.chunks_mut(7) {
                source.fill(chunk);
            }
        }
        assert_eq!(all, rebuilt);
        assert_ne!(all, [0; 96], "the stream handed out nothing at all");
    }

    #[test]
    fn two_stacks_on_different_seeds_do_not_share_a_fingerprint() {
        let (one, _) = identity(1);
        let (other, _) = identity(2);
        assert_ne!(one.fingerprint(), other.fingerprint());
        assert!(
            one.fingerprint().starts_with("sha-256 "),
            "{}",
            one.fingerprint()
        );
    }

    #[test]
    fn the_same_seed_makes_the_same_certificate_every_time() {
        // which is what makes a handshake reproducible in a test, and is also
        // the exact reason the media seed must be real entropy in production
        let (one, _) = identity(7);
        let (again, _) = identity(7);
        assert_eq!(one.fingerprint(), again.fingerprint());
    }

    #[test]
    fn an_offerer_writes_actpass_and_an_answerer_writes_active() {
        assert_eq!(
            setup_to_write(Party::Offerer, None).expect("a value"),
            Setup::ActPass
        );
        assert_eq!(
            setup_to_write(Party::Offerer, Some("passive")).expect("a value"),
            Setup::ActPass,
            "an offerer read the peer's last answer"
        );
        assert_eq!(
            setup_to_write(Party::Answerer, Some("actpass")).expect("a value"),
            Setup::Active
        );
        assert_eq!(
            setup_to_write(Party::Answerer, Some("active")).expect("a value"),
            Setup::Passive
        );
        // RFC 4145 §4.1: an offer with no attribute means "active"
        assert_eq!(
            setup_to_write(Party::Answerer, None).expect("a value"),
            Setup::Passive
        );
    }

    #[test]
    fn a_setup_value_that_is_not_one_of_the_four_is_refused() {
        assert_eq!(
            setup_to_write(Party::Answerer, Some("whenever")),
            Err(MediaError::DtlsRole)
        );
        assert_eq!(
            setup_to_keep(Role::Client, Some("whenever")),
            Err(MediaError::DtlsRole)
        );
    }

    #[test]
    fn fingerprints_are_compared_as_the_set_of_certificates_they_name() {
        let owned = |values: &[&str]| -> Vec<String> {
            values.iter().map(|value| (*value).to_owned()).collect()
        };
        let had = owned(&["sha-256 AB:CD", "sha-1 01:02"]);
        for same in [
            owned(&["sha-1 01:02", "sha-256 AB:CD"]),
            owned(&["SHA-256 ab:cd", "sha-1 01:02"]),
            owned(&["sha-256 AB:CD", "sha-1 01:02", "sha-256 AB:CD"]),
        ] {
            assert!(same_fingerprints(&had, &same), "{same:?}");
        }
        for moved in [
            owned(&["sha-256 AB:CE", "sha-1 01:02"]),
            owned(&["sha-256 AB:CD"]),
            owned(&["sha-256 AB:CD", "sha-1 01:02", "sha-512 FF"]),
        ] {
            assert!(!same_fingerprints(&had, &moved), "{moved:?}");
        }
    }

    #[test]
    fn a_re_offer_is_answered_with_the_role_the_association_already_has() {
        // RFC 8842 §5.3, against the actpass §5.5 asks every re-offer for:
        // the role in force, which a fresh answer to actpass would not be for
        // a server — `setup_to_write` answers it `active` every time
        for (role, kept) in [
            (Role::Client, Setup::Active),
            (Role::Server, Setup::Passive),
        ] {
            assert_eq!(setup_to_keep(role, Some("actpass")), Ok(kept), "{role:?}");
        }
        // an older peer's concrete value, where RFC 4145 §4.1 leaves exactly
        // the role in force
        assert_eq!(
            setup_to_keep(Role::Client, Some("passive")),
            Ok(Setup::Active)
        );
        assert_eq!(
            setup_to_keep(Role::Server, Some("active")),
            Ok(Setup::Passive)
        );
        // and no value at all, which §4.1 reads as active
        assert_eq!(setup_to_keep(Role::Server, None), Ok(Setup::Passive));
        assert_eq!(
            setup_to_keep(Role::Client, Some("holdconn")),
            Ok(Setup::HoldConn)
        );
    }

    #[test]
    fn a_re_offer_that_leaves_only_the_other_role_is_asking_for_a_new_association() {
        assert_eq!(
            setup_to_keep(Role::Client, Some("active")),
            Err(MediaError::DtlsRoleChanged)
        );
        assert_eq!(
            setup_to_keep(Role::Client, None),
            Err(MediaError::DtlsRoleChanged)
        );
        assert_eq!(
            setup_to_keep(Role::Server, Some("passive")),
            Err(MediaError::DtlsRoleChanged)
        );
    }

    #[test]
    fn the_role_a_re_negotiation_gives_is_read_off_the_two_values() {
        use Setup::{ActPass, Active, HoldConn, Passive};
        for (ours, theirs, role) in [
            // this end offered actpass: the answer decides
            (ActPass, Some(Active), Some(Role::Server)),
            (ActPass, Some(Passive), Some(Role::Client)),
            // RFC 4145 §4.1: an answer that says nothing says passive
            (ActPass, None, Some(Role::Client)),
            // a concrete value is the role, whichever side it was written on
            (Active, Some(ActPass), Some(Role::Client)),
            (Active, Some(Passive), Some(Role::Client)),
            (Active, None, Some(Role::Client)),
            (Passive, Some(ActPass), Some(Role::Server)),
            (Passive, Some(Active), Some(Role::Server)),
            (HoldConn, Some(Active), None),
            (ActPass, Some(HoldConn), None),
        ] {
            assert_eq!(
                role_after(ours, theirs),
                Ok(role),
                "{ours:?} against {theirs:?}"
            );
        }
        for (ours, theirs) in [(Active, Active), (Passive, Passive), (ActPass, ActPass)] {
            assert_eq!(
                role_after(ours, Some(theirs)),
                Err(MediaError::DtlsRole),
                "{ours:?} against {theirs:?}"
            );
        }
    }

    #[test]
    fn the_two_profiles_that_can_be_negotiated_both_have_a_transform() {
        assert_eq!(
            suite_of(SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80),
            Ok(Suite::AesCm80)
        );
        assert_eq!(
            suite_of(SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32),
            Ok(Suite::AesCm32)
        );
        assert_eq!(MOST.suite, Suite::AesCm80);
    }

    #[test]
    fn a_profile_with_no_keys_stops_the_stream_rather_than_opening_it() {
        // RFC 8827 §6.5 forbids negotiating encryption away, and sipral-dtls
        // refuses the NULL profiles before they ever get here; this is the
        // arm that catches a profile added on one side of the boundary only
        assert_eq!(
            suite_of(SrtpProtectionProfile::NULL_HMAC_SHA1_80),
            Err(MediaError::DtlsProfile)
        );
    }

    /// The two ends of one call, driven against each other with nothing but
    /// the datagrams they produce — which is the whole of what a socket would
    /// have carried.
    ///
    /// Named `dialling`/`answering` rather than `caller`/`callee` for the
    /// reason `interop/harness/src/local.rs` gives: the two read too much
    /// alike for `clippy::similar_names`, which this workspace denies.
    fn shake_hands(
        dialling: &mut Handshake,
        answering: &mut Handshake,
        now: Instant,
    ) -> (bool, bool) {
        let mut at = now;
        for _ in 0..64 {
            let mut moved = false;
            while let Some(record) = dialling.take_outbound() {
                answering.on_datagram(&record, at);
                moved = true;
            }
            while let Some(record) = answering.take_outbound() {
                dialling.on_datagram(&record, at);
                moved = true;
            }
            if dialling.finished() && answering.finished() {
                break;
            }
            if !moved {
                // nothing crossed, so the only thing that can move either end
                // is the retransmission timer
                at += Duration::from_millis(1100);
                dialling.on_timeout(at);
                answering.on_timeout(at);
            }
        }
        (dialling.finished(), answering.finished())
    }

    #[test]
    fn two_ends_that_named_each_others_fingerprints_agree_on_keys() {
        let now = Instant::now();
        let (dialling_identity, mut dialling_keys) = identity(11);
        let (answering_identity, mut answering_keys) = identity(12);

        // what each end read off the other's description
        let dialling_sees = Keying::Dtls {
            fingerprints: vec![answering_identity.fingerprint().to_owned()],
            setup: Some("active".to_owned()),
        };
        let answering_sees = Keying::Dtls {
            fingerprints: vec![dialling_identity.fingerprint().to_owned()],
            setup: Some("actpass".to_owned()),
        };

        let mut dialling = Handshake::start(
            &dialling_identity,
            &dialling_sees,
            Party::Offerer,
            Setup::ActPass,
            &mut dialling_keys,
            now,
        )
        .expect("a handshake")
        .expect("one that runs");
        let mut answering = Handshake::start(
            &answering_identity,
            &answering_sees,
            Party::Answerer,
            Setup::Active,
            &mut answering_keys,
            now,
        )
        .expect("a handshake")
        .expect("one that runs");

        assert_eq!(
            dialling.connection.role(),
            Role::Server,
            "the offerer wrote actpass and the answer said active, so it listens"
        );
        assert_eq!(answering.connection.role(), Role::Client);

        let (dialled, answered) = shake_hands(&mut dialling, &mut answering, now);
        assert!(dialled && answered, "the handshake never finished");

        assert!(
            dialling.take_outcome().expect("an outcome").is_ok(),
            "the offerer got no keys"
        );
        assert!(
            answering.take_outcome().expect("an outcome").is_ok(),
            "the answerer got no keys"
        );
    }

    #[test]
    fn a_peer_whose_certificate_is_not_the_one_the_signalling_named_gets_no_keys() {
        // RFC 8122 §5.1: "if the fingerprint does not match ... the endpoint
        // MUST NOT establish the TLS connection". This is the whole of the
        // authentication, so it is the whole of what a man in the middle has
        // to beat
        let now = Instant::now();
        let (dialling_identity, mut dialling_keys) = identity(21);
        let (answering_identity, mut answering_keys) = identity(22);
        let (impostor, _) = identity(23);

        let dialling_sees = Keying::Dtls {
            fingerprints: vec![impostor.fingerprint().to_owned()],
            setup: Some("active".to_owned()),
        };
        let answering_sees = Keying::Dtls {
            fingerprints: vec![dialling_identity.fingerprint().to_owned()],
            setup: Some("actpass".to_owned()),
        };

        let mut dialling = Handshake::start(
            &dialling_identity,
            &dialling_sees,
            Party::Offerer,
            Setup::ActPass,
            &mut dialling_keys,
            now,
        )
        .expect("a handshake")
        .expect("one that runs");
        let mut answering = Handshake::start(
            &answering_identity,
            &answering_sees,
            Party::Answerer,
            Setup::Active,
            &mut answering_keys,
            now,
        )
        .expect("a handshake")
        .expect("one that runs");

        shake_hands(&mut dialling, &mut answering, now);
        assert_eq!(
            dialling.take_outcome().expect("an outcome").err(),
            Some(MediaError::DtlsHandshake),
            "a certificate nobody vouched for opened a stream"
        );
    }

    #[test]
    fn a_peer_that_answered_holdconn_leaves_no_handshake_to_run() {
        let now = Instant::now();
        let (own, mut keys) = identity(31);
        let seen = Keying::Dtls {
            fingerprints: vec![own.fingerprint().to_owned()],
            setup: Some("holdconn".to_owned()),
        };
        let handshake =
            Handshake::start(&own, &seen, Party::Offerer, Setup::ActPass, &mut keys, now)
                .expect("no error");
        assert!(handshake.is_none());
    }

    #[test]
    fn two_ends_that_both_claim_the_same_role_are_refused_rather_than_left_waiting() {
        // RFC 4145 §4.1 has no row for an answer of actpass, and the failure
        // it would otherwise cause is the quiet one: two servers waiting for
        // a ClientHello neither will send, for the whole of the handshake
        // timeout
        let now = Instant::now();
        let (own, mut keys) = identity(41);
        let seen = Keying::Dtls {
            fingerprints: vec![own.fingerprint().to_owned()],
            setup: Some("actpass".to_owned()),
        };
        assert_eq!(
            Handshake::start(&own, &seen, Party::Offerer, Setup::ActPass, &mut keys, now).err(),
            Some(MediaError::DtlsRole)
        );
    }

    #[test]
    fn a_fingerprint_that_cannot_be_read_stops_the_call_before_the_handshake() {
        let now = Instant::now();
        let (own, mut keys) = identity(51);
        for written in [
            "sha-256 not-hexadecimal",
            "md5 AA:BB",
            "",
            "sha-256 AA:BB:CC",
        ] {
            let seen = Keying::Dtls {
                fingerprints: vec![written.to_owned()],
                setup: Some("active".to_owned()),
            };
            assert_eq!(
                Handshake::start(&own, &seen, Party::Offerer, Setup::ActPass, &mut keys, now).err(),
                Some(MediaError::DtlsFingerprint),
                "{written}"
            );
        }
    }

    #[test]
    fn a_plan_keyed_by_sdes_is_not_a_handshake() {
        let now = Instant::now();
        let (own, mut keys) = identity(61);
        let sdes = Keying::Sdes {
            local: sipral_core::sdp::CryptoPolicy::new(
                1,
                sipral_core::sdp::CryptoSuite::AesCm80,
                sipral_core::sdp::KeySalt::new([1; 16], [2; 14]),
            ),
            remote: sipral_core::sdp::CryptoPolicy::new(
                1,
                sipral_core::sdp::CryptoSuite::AesCm80,
                sipral_core::sdp::KeySalt::new([3; 16], [4; 14]),
            ),
        };
        assert!(
            Handshake::start(&own, &sdes, Party::Offerer, Setup::ActPass, &mut keys, now,)
                .expect("no error")
                .is_none()
        );
    }

    #[test]
    fn a_handshake_that_finished_reports_its_outcome_once() {
        let now = Instant::now();
        let (dialling_identity, mut dialling_keys) = identity(71);
        let (answering_identity, mut answering_keys) = identity(72);
        let dialling_sees = Keying::Dtls {
            fingerprints: vec![answering_identity.fingerprint().to_owned()],
            setup: Some("active".to_owned()),
        };
        let answering_sees = Keying::Dtls {
            fingerprints: vec![dialling_identity.fingerprint().to_owned()],
            setup: Some("actpass".to_owned()),
        };
        let mut dialling = Handshake::start(
            &dialling_identity,
            &dialling_sees,
            Party::Offerer,
            Setup::ActPass,
            &mut dialling_keys,
            now,
        )
        .expect("a handshake")
        .expect("one that runs");
        let mut answering = Handshake::start(
            &answering_identity,
            &answering_sees,
            Party::Answerer,
            Setup::Active,
            &mut answering_keys,
            now,
        )
        .expect("a handshake")
        .expect("one that runs");
        shake_hands(&mut dialling, &mut answering, now);

        assert!(dialling.take_outcome().is_some());
        assert!(
            dialling.take_outcome().is_none(),
            "a session would have installed the same keys twice"
        );
    }

    #[test]
    fn a_server_that_is_never_spoken_to_gives_up_when_a_client_would_have() {
        // the failure this budget exists for. A DTLS server has no flight to
        // retransmit, so `Connection::poll_timeout` answers `None` for ever
        // while the state is still `Handshaking`, and a call driven by that
        // alone would wait for as long as somebody stayed on the line
        let now = Instant::now();
        let (own, mut keys) = identity(81);
        let seen = Keying::Dtls {
            fingerprints: vec![own.fingerprint().to_owned()],
            // the peer answered `active`, so this end listens
            setup: Some("active".to_owned()),
        };
        let mut handshake =
            Handshake::start(&own, &seen, Party::Offerer, Setup::ActPass, &mut keys, now)
                .expect("a handshake")
                .expect("one that runs");
        assert!(
            handshake.take_outbound().is_none(),
            "a server sent a flight"
        );
        let deadline = handshake.poll_timeout().expect("a deadline");
        assert!(deadline > now);

        handshake.on_timeout(
            deadline
                .checked_sub(Duration::from_millis(1))
                .expect("a moment before the deadline"),
        );
        assert!(
            handshake.take_outcome().is_none(),
            "it gave up before its budget was spent"
        );

        handshake.on_timeout(deadline);
        assert_eq!(
            handshake.take_outcome().expect("an outcome").err(),
            Some(MediaError::DtlsHandshake)
        );
        assert!(handshake.finished());
        assert!(
            handshake.poll_timeout().is_none(),
            "it is still asking to be woken"
        );
    }

    #[test]
    fn the_budget_is_the_schedule_a_client_would_have_spent() {
        // 1 + 2 + 4 + 8 + 16 + 32 seconds of retransmissions and a last wait
        // of sixty, which is what RFC 6347 §4.2.4.1's defaults add up to
        assert_eq!(
            budget(Retransmission::default()),
            Duration::from_secs(1 + 2 + 4 + 8 + 16 + 32 + 60)
        );
        // and it follows the settings rather than being written down twice
        let brisk = Retransmission {
            initial: Duration::from_millis(500),
            max: Duration::from_secs(4),
            attempts: 3,
        };
        assert_eq!(
            budget(brisk),
            Duration::from_millis(500 + 1000 + 2000) + Duration::from_secs(4)
        );
    }
}
