// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! DTLS-SRTP: the handshake that keys a call, run on the call's own media path.
//!
//! `sipral-dtls` has the RFC 5764 handshake and `sipral-rtp` the RFC 3711 stream; this module
//! connects them.
//!
//! # What crosses the boundary
//!
//! - **An identity** ([`Identity`]): a P-256 key and self-signed certificate, one per
//!   [`MediaEngine`](crate::MediaEngine), named in every offer by its fingerprint.
//! - **A role** ([`Role`]): which end sends the ClientHello. RFC 5763 §5 derives it from the
//!   `a=setup` of both offer and answer, so the facade remembers what it wrote.
//! - **A driver** ([`Handshake`]): sans-I/O, driven by a [`MediaSession`](crate::MediaSession).
//!
//! # Where the randomness comes from
//!
//! The media engine's [`KeySource`], which also produces the SRTP keys, and not the endpoint's: the
//! endpoint seed is written in clear into replay recordings, and a recording must not carry the
//! means to rebuild the certificate key. A poor media seed silently costs all of the encryption, as
//! with SDES.
//!
//! # What this module refuses
//!
//! An unauthenticated handshake: `sipral-dtls` requires peer fingerprints, and `UDP/TLS/RTP/SAVP`
//! without `a=fingerprint` never becomes [`Keying::Dtls`](sipral_core::sdp::Keying::Dtls).
//!
//! An SRTP profile without keys. `sipral-dtls` refuses the NULL profiles (RFC 8827 §6.5 forbids
//! negotiating encryption away), and [`suite_of`] stops the stream on any profile it does not know.

use std::collections::VecDeque;
use std::mem;
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

/// Validity of a certificate this stack makes, each way from its creation.
///
/// Not about trust: the certificate is checked only against the fingerprint in the signalling (RFC
/// 8122 §5.1). RFC 5280 §4.1.2.5 requires a period. It also runs backwards because clocks differ,
/// and a peer that checks the period (Asterisk with a strict `dtls_verify`) would otherwise refuse
/// a certificate from a stack whose clock is behind.
const CERTIFICATE_LIFETIME: u64 = 30 * 24 * 60 * 60;

/// How long before expiry a fresh certificate is made. A day, longer than any call, so the
/// fingerprint in an offer never changes mid-call.
const RENEW_WITHIN: u64 = 24 * 60 * 60;

/// The `a=setup` in our offers. RFC 5763 §5 requires `actpass` from an offerer ("The endpoint that
/// is the offerer MUST use the setup attribute value of setup:actpass"); it also lets the answerer
/// be the client, saving a round trip.
pub(crate) const OFFERED_SETUP: Setup = Setup::ActPass;

/// The most expensive policy a handshake can settle on, for sizing buffers before the result is
/// known.
///
/// Of the four keyable profiles (`connection::KEYABLE`), the AEAD ones have the widest tag (16
/// octets, same for both). See [`RtpSession::awaiting`](sipral_rtp::RtpSession::awaiting).
pub(crate) const MOST: Policy = Policy::new(Suite::AeadAes256Gcm);

/// Random octets for the handshake from the engine's key stream.
///
/// One 32-octet block at a time, never repeated. Each octet is wiped as it is handed out and the
/// rest when the source drops, since these become the private key and signature nonces.
struct Source<'a> {
    keys: &'a mut KeySource,
    block: Zeroizing<[u8; 32]>,
    used: usize,
}

impl<'a> Source<'a> {
    fn new(keys: &'a mut KeySource) -> Self {
        // a full `used` makes the first fill draw a block instead of handing out zeros
        Self {
            keys,
            block: Zeroizing::new([0; 32]),
            used: 32,
        }
    }
}

impl Random for Source<'_> {
    fn fill(&mut self, dest: &mut [u8]) {
        for slot in dest {
            if self.used >= self.block.len() {
                *self.block = self.keys.block();
                self.used = 0;
            }
            *slot = self.block.get_mut(self.used).map_or(0, mem::take);
            self.used += 1;
        }
    }
}

/// This stack's DTLS identity: one key, one certificate, one fingerprint.
///
/// One per [`MediaEngine`](crate::MediaEngine), not per call. The certificate only proves "this is
/// the end the signalling described", and an observer already sees the fingerprint in the SDP, so
/// per-call certificates would cost a P-256 key and signature per call for nothing.
///
/// Neither `Clone` nor `Copy`: the private key is the identity.
#[derive(Debug)]
pub struct Identity {
    key: EcdsaKey,
    certificate: Certificate,
    /// The `a=fingerprint` value, cached for every offer and answer.
    fingerprint: String,
    /// Expiry, in Unix seconds. A desk phone or agent runs for months with one `MediaEngine`, so it
    /// must renew instead of offering an expired certificate; see [`Identity::is_stale`].
    not_after: u64,
}

impl Identity {
    /// Make one from the engine's key stream. `unix_seconds` is the wall clock for the validity
    /// period.
    ///
    /// # Errors
    ///
    /// [`MediaError::DtlsIdentity`] when the key or certificate cannot be made, which does not
    /// happen with a sound key source.
    pub(crate) fn new(keys: &mut KeySource, unix_seconds: u64) -> Result<Self, MediaError> {
        let mut source = Source::new(keys);
        let key = EcdsaKey::generate(&mut source).map_err(|_| MediaError::DtlsIdentity)?;
        // nobody checks the common name (RFC 8122 §5.1 puts identity in the fingerprint), so it
        // names the purpose, not a party
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

    /// Whether this certificate is close enough to expiry that the next call should get a fresh
    /// one.
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

/// How long a whole handshake may take before the call is told it failed.
///
/// DTLS's own limit is one-sided: a client retransmits on the RFC 6347 §4.2.4.1 schedule and gives
/// up after `attempts`, but a server that never got a ClientHello has no timer at all, and
/// `Connection::poll_timeout` returns `None` while still `Handshaking`. So both ends use the
/// client's schedule added up: every wait, plus the final wait for an answer.
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
    /// Records produced and not yet taken. Owned, since `sipral-dtls` allocates each.
    ///
    /// The session addresses them: to where the far end's records came from while RTP has no latch
    /// (the whole handshake), else to the signalled address. See
    /// [`MediaSession::poll_transmit`](crate::MediaSession::poll_transmit).
    outbound: VecDeque<Vec<u8>>,
    /// The exported keys, waiting for the session to install them.
    keyed: Option<Result<Exported, MediaError>>,
    /// Whether failure was already reported, so it is reported once.
    reported: bool,
    /// When this handshake gives up regardless of the connection's timer; see [`budget`].
    expires: Instant,
    /// Whether the budget ran out, which the connection cannot know.
    expired: bool,
    /// What a new association on the same call starts with ([`Handshake::renewal`]): our
    /// certificate, the far end's fingerprints, and this handshake's randomness.
    identity: Arc<Identity>,
    peers: Vec<Fingerprint>,
    /// The protection profiles this call offers or accepts, best first ([`profiles`]), kept so a
    /// new association uses the same.
    profiles: Vec<SrtpProtectionProfile>,
    keys: KeySource,
}

/// What a finished handshake exported, per direction.
///
/// Not turned into a [`Security`] immediately: a first keying opens contexts from it, while a
/// running stream replaces each direction like a re-key (RFC 6347 §4.2.8), keeping the old receive
/// context for packets in flight.
pub(crate) struct Exported {
    pub(crate) suite: Suite,
    pub(crate) policy: Policy,
    /// Protects what this end sends.
    pub(crate) local: Master,
    /// Opens what arrives.
    pub(crate) remote: Master,
}

impl Exported {
    /// The contexts for a stream that was waiting for its keys.
    pub(crate) fn into_security(self) -> Security {
        Security::new(self.policy, self.local, self.policy, self.remote)
    }
}

impl core::fmt::Debug for Exported {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // master keys and salts stay out of logs; only the suite is shown
        f.debug_struct("Exported")
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

impl Handshake {
    /// Start the handshake a settled plan calls for, or `None` if it calls for none.
    ///
    /// `party` is our side of the offer/answer, `ours` the `a=setup` we wrote, `keying` what the
    /// peer's description said. `None` also for a peer that answered `holdconn` ("no connection for
    /// the time being"), which is not a failure.
    ///
    /// # Errors
    ///
    /// [`MediaError::DtlsRole`] for an `a=setup` pair RFC 4145 §4.1 does not allow or an unknown
    /// value; [`MediaError::DtlsFingerprint`] for an unreadable fingerprint or unknown hash;
    /// [`MediaError::DtlsHandshake`] for a configuration no handshake can come of.
    pub(crate) fn start(
        identity: &Arc<Identity>,
        keying: &Keying,
        party: Party,
        ours: Setup,
        profiles: Vec<SrtpProtectionProfile>,
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
        // keep every line that parses and fail only if none does: RFC 8122 §5 has peers write
        // several hashes, and one we know is enough
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
            profiles,
            KeySource::new(*seed),
            now,
        )
        .map(Some)
    }

    /// A handshake in `role`, presenting `identity` and requiring a peer certificate listed in
    /// `peers`, with randomness from `keys`.
    ///
    /// The randomness becomes the handshake's own stream, so a renewal the session starts (see
    /// [`Handshake::renewal`]) never reuses an engine block.
    fn begin(
        identity: Arc<Identity>,
        peers: Vec<Fingerprint>,
        role: Role,
        profiles: Vec<SrtpProtectionProfile>,
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
        config.srtp_profiles.clone_from(&profiles);
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
            profiles,
            keys,
        };
        // a client's ClientHello is ready and a server has nothing; draining hides the difference
        // from the caller
        handshake.drain();
        Ok(handshake)
    }

    /// A new association on the same call, same role and certificates (RFC 6347 §4.2.8).
    ///
    /// The server "SHOULD proceed with a new handshake but MUST NOT destroy the existing
    /// association" until the client completes it. Asterisk starts one on every hold and resume;
    /// ignoring it leaves the call silent. The session runs both and keeps the old keys until this
    /// one produces new ones; see `MediaSession::receive`.
    ///
    /// # Errors
    ///
    /// [`MediaError::DtlsHandshake`] for a configuration no handshake can come of, which cannot
    /// happen for one the original already used.
    pub(crate) fn renewal(&mut self, now: Instant) -> Result<Self, MediaError> {
        let seed = Zeroizing::new(self.keys.block());
        Self::begin(
            Arc::clone(&self.identity),
            self.peers.clone(),
            self.role(),
            self.profiles.clone(),
            KeySource::new(*seed),
            now,
        )
    }

    /// Whether this handshake produced keys, the only state a new association can replace (RFC 6347
    /// §4.2.8).
    pub(crate) fn is_keyed(&self) -> bool {
        matches!(self.connection.state(), State::Connected)
    }

    /// Take a datagram the demux said is a DTLS record.
    pub(crate) fn on_datagram(&mut self, datagram: &[u8], now: Instant) {
        self.connection.handle_datagram(datagram, now);
        self.drain();
    }

    /// When to wake the handshake: the connection's retransmission deadline or the budget,
    /// whichever is first.
    ///
    /// Never `None` while running. A server waiting for a ClientHello has no deadline of its own.
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

    /// The next record to send. The session picks the destination; see [`Handshake::outbound`].
    pub(crate) fn take_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    /// The keys, or the reason there are none, each returned once. `None` while running and after
    /// it was taken.
    pub(crate) fn take_outcome(&mut self) -> Option<Result<Exported, MediaError>> {
        self.keyed.take()
    }

    /// This end's role in the association, fixed for its lifetime.
    pub(crate) const fn role(&self) -> Role {
        self.connection.role()
    }

    /// Whether the handshake is over either way, including a spent budget.
    pub(crate) fn finished(&self) -> bool {
        self.expired || !matches!(self.connection.state(), State::Handshaking)
    }

    /// Send `close_notify` (RFC 6347 §4.2.8) so the peer stops retransmitting into a call that has
    /// hung up. The records are drained as usual; nothing waits for an answer.
    pub(crate) fn close(&mut self) {
        self.connection.close();
        self.drain();
    }

    /// Move the connection's output here: records to send and the one outcome to report.
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
                // media travels as SRTP outside DTLS (RFC 5764 §4.1), so application data is
                // ignored; it does not affect the keys
                Event::ApplicationData(_) => {}
            }
        }
    }
}

/// The SRTP contexts a completed handshake opens the stream with.
///
/// RFC 5764 §4.2 exports a key and salt per direction; `sipral-dtls` orders them so "local"
/// protects what we send and "remote" opens what arrives, as RFC 4568 §7.1.1 does for SDES.
///
/// # Errors
///
/// [`MediaError::DtlsProfile`] for a profile this build has no transform for. Only reachable if a
/// profile is added on one side of the boundary and not the other, and then it fails loudly.
fn security_of(keying: &SrtpKeying) -> Result<Exported, MediaError> {
    let suite = suite_of(keying.profile())?;
    // RFC 5764 §4.1.2: key derivation rate zero and no MKI, which `Policy::new` already sets
    Ok(Exported {
        suite,
        policy: Policy::new(suite),
        local: Master::new(keying.local_master_key(), keying.local_master_salt()),
        remote: Master::new(keying.remote_master_key(), keying.remote_master_salt()),
    })
}

/// Whether a datagram is the first flight of a new association: a plaintext epoch-0 handshake
/// record holding a ClientHello with message sequence zero (RFC 6347 §4.1, §4.2.2).
///
/// Read from the headers only, because the running connection would otherwise swallow it. The
/// record header is 13 octets (type, version, 16-bit epoch, 48-bit sequence, length); the handshake
/// header starts with the message type and has the message sequence four octets later.
pub(crate) fn begins_an_association(datagram: &[u8]) -> bool {
    const CLIENT_HELLO: u8 = 1;
    datagram.first() == Some(&22)
        && datagram.get(3..5) == Some(&[0, 0][..])
        && datagram.get(13) == Some(&CLIENT_HELLO)
        && datagram.get(17..19) == Some(&[0, 0][..])
}

/// The protection profiles a call with `suites` offers and accepts, in order. With no suites named:
/// the four keyable ones, strongest first (the two AEAD profiles of RFC 7714 §14.2, then the two
/// AES-CM of RFC 5764 §4.1.2). Otherwise those of its suites that have a profile, in its order.
///
/// # Errors
///
/// [`MediaError::DtlsProfile`] when `suites` has none of the four, so only SDES could carry them.
pub(crate) fn profiles(suites: Option<&[Suite]>) -> Result<Vec<SrtpProtectionProfile>, MediaError> {
    const STRONGEST_FIRST: [Suite; 4] = [
        Suite::AeadAes256Gcm,
        Suite::AeadAes128Gcm,
        Suite::AesCm80,
        Suite::AesCm32,
    ];
    let named = suites.unwrap_or(&STRONGEST_FIRST);
    let profiles: Vec<SrtpProtectionProfile> = named
        .iter()
        .filter_map(|suite| match suite {
            Suite::AesCm80 => Some(SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80),
            Suite::AesCm32 => Some(SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32),
            Suite::AeadAes128Gcm => Some(SrtpProtectionProfile::AEAD_AES_128_GCM),
            Suite::AeadAes256Gcm => Some(SrtpProtectionProfile::AEAD_AES_256_GCM),
            Suite::AesF8 | Suite::Aes256Cm80 | Suite::Aes256Cm32 => None,
        })
        .collect();
    if profiles.is_empty() {
        return Err(MediaError::DtlsProfile);
    }
    Ok(profiles)
}

/// The media-side suite for a DTLS-SRTP protection profile. Two enumerations exist because the
/// handshake crate and the SRTP crate do not depend on each other.
fn suite_of(profile: SrtpProtectionProfile) -> Result<Suite, MediaError> {
    match profile {
        SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80 => Ok(Suite::AesCm80),
        SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32 => Ok(Suite::AesCm32),
        SrtpProtectionProfile::AEAD_AES_128_GCM => Ok(Suite::AeadAes128Gcm),
        SrtpProtectionProfile::AEAD_AES_256_GCM => Ok(Suite::AeadAes256Gcm),
        _ => Err(MediaError::DtlsProfile),
    }
}

/// Our `a=setup` given our party and, for an answerer, the offer's value.
///
/// An offerer writes `actpass` (RFC 5763 §5). An answerer writes what RFC 4145 §4.1 leaves it:
/// `active` against `actpass`, so its ClientHello can leave with the answer.
///
/// # Errors
///
/// [`MediaError::DtlsRole`] for an offer value outside the four of RFC 4145 §4.
pub(crate) fn setup_to_write(party: Party, theirs: Option<&str>) -> Result<Setup, MediaError> {
    match party {
        Party::Offerer => Ok(OFFERED_SETUP),
        Party::Answerer => {
            // §4.1: an offer without the attribute means "active"
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
/// Compared as sets, case-insensitively. RFC 8842 §3.1 wants a new association when fingerprints
/// are "modified, added, or removed"; reordering or repeating lines (one per hash, RFC 8122 §5) is
/// none of those.
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

/// Our answer to a re-offer on a call whose association gave us `role` (RFC 8842 §5.3: the answer
/// "does not change the previously negotiated DTLS roles").
///
/// Against `actpass` (§5.5) that is simply the current role. Against a concrete value from an older
/// peer, RFC 4145 §4.1 allows one answer; if that is the other role, the offer asks for a new
/// association.
///
/// # Errors
///
/// [`MediaError::DtlsRoleChanged`] when the offer leaves us only the other role, including no value
/// at all (§4.1 reads it as `active`); [`MediaError::DtlsRole`] for an unknown value.
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
        // "no connection for the time being": no role to take
        Setup::HoldConn => Ok(Setup::HoldConn),
        Setup::ActPass => Ok(ours),
        concrete if Setup::answer_to(concrete) == ours => Ok(ours),
        _ => Err(MediaError::DtlsRoleChanged),
    }
}

/// The role a renegotiation gives this end, from the `a=setup` we wrote and theirs, or `None` when
/// there is nothing to compare.
///
/// No need to know which was the offer: we write `actpass` only in offers (RFC 8842 §5.5) and a
/// concrete role only in answers or unchanged repeats. A concrete value of ours is the role. With
/// our `actpass`, their `active` makes us server, `passive` or nothing (RFC 4145 §4.1's answer
/// default) makes us client. `holdconn` on either side gives no role.
///
/// # Errors
///
/// [`MediaError::DtlsRole`] for a pair §4.1 forbids: the same concrete role on both sides, or
/// `actpass` answered with `actpass`.
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
        Handshake, Identity, MOST, Source, budget, profiles, role_after, same_fingerprints,
        setup_to_keep, setup_to_write, suite_of,
    };
    use sipral_core::auth::KeySource;
    use sipral_core::sdp::Keying;
    use sipral_dtls::handshake::SrtpProtectionProfile;
    use sipral_dtls::setup::{Party, Setup};
    use sipral_dtls::x509::{Fingerprint, HashFunction};
    use sipral_dtls::{Random, Retransmission, Role};
    use sipral_rtp::srtp::Suite;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    use crate::error::MediaError;

    /// A wall clock inside every test certificate's validity period; nothing checks it.
    const NOW_UNIX: u64 = 1_790_000_000;

    fn identity(seed: u8) -> (Arc<Identity>, KeySource) {
        let mut keys = KeySource::new([seed; 32]);
        let identity = Identity::new(&mut keys, NOW_UNIX).expect("an identity");
        (Arc::new(identity), keys)
    }

    #[test]
    fn the_key_stream_hands_out_every_octet_once_and_in_order() {
        // the same seed drawn at once or in pieces must give the same stream, never the same block
        // twice
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
    fn an_octet_handed_out_is_wiped_from_the_block_it_came_from() {
        let mut keys = KeySource::new([9; 32]);
        let mut source = Source::new(&mut keys);
        let mut drawn = [0_u8; 40];
        source.fill(&mut drawn[..10]);
        assert!(source.block[..10].iter().all(|&octet| octet == 0));
        assert!(
            source.block[10..].iter().any(|&octet| octet != 0),
            "what is not drawn yet is still there to be drawn"
        );
        source.fill(&mut drawn[10..]);
        assert!(source.block[..8].iter().all(|&octet| octet == 0));
        assert!(drawn.iter().any(|&octet| octet != 0));
        // and the remainder is wiped with the source
        let _: &Zeroizing<[u8; 32]> = &source.block;
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
        // reproducible in tests, which is exactly why production needs real entropy
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
        // RFC 8842 §5.3 against the actpass of §5.5: keep the current role, which `setup_to_write`
        // would not do for a server (it always answers `active`)
        for (role, kept) in [
            (Role::Client, Setup::Active),
            (Role::Server, Setup::Passive),
        ] {
            assert_eq!(setup_to_keep(role, Some("actpass")), Ok(kept), "{role:?}");
        }
        // an older peer's concrete value, where §4.1 leaves exactly the current role
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
    fn every_keyable_profile_has_a_transform() {
        assert_eq!(
            suite_of(SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80),
            Ok(Suite::AesCm80)
        );
        assert_eq!(
            suite_of(SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32),
            Ok(Suite::AesCm32)
        );
        assert_eq!(
            suite_of(SrtpProtectionProfile::AEAD_AES_128_GCM),
            Ok(Suite::AeadAes128Gcm)
        );
        assert_eq!(
            suite_of(SrtpProtectionProfile::AEAD_AES_256_GCM),
            Ok(Suite::AeadAes256Gcm)
        );
        assert!(suite_of(SrtpProtectionProfile::NULL_HMAC_SHA1_80).is_err());
        // an AEAD suite's tag is wider than either AES-CM suite's, so it is
        // the upper bound `MOST` sizes buffers to
        assert_eq!(MOST.suite, Suite::AeadAes256Gcm);
        assert!(MOST.suite.tag() >= Suite::AesCm80.tag());
        assert!(MOST.suite.tag() >= Suite::AesCm32.tag());
        assert!(MOST.suite.tag() >= Suite::AeadAes128Gcm.tag());
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

    /// Drive both ends of a call against each other with only their datagrams.
    ///
    /// Named `dialling`/`answering` because `caller`/`callee` trips `clippy::similar_names` (see
    /// `interop/harness/src/local.rs`).
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
                // nothing crossed, so only the retransmission timer can move either end
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
            every(),
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
            every(),
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

    /// Every profile there are keys for, strongest first: what a call that
    /// named no suites of its own offers and accepts.
    fn every() -> Vec<SrtpProtectionProfile> {
        profiles(None).expect("four profiles")
    }

    /// The suite a handshake settles on between an offerer with `dialling` and an answerer with
    /// `answering`. The answerer is the client and offers its order; the server chooses in its own
    /// (RFC 5764 §4.1.1).
    fn settled_on(
        dialling: Vec<SrtpProtectionProfile>,
        answering: Vec<SrtpProtectionProfile>,
    ) -> Suite {
        let now = Instant::now();
        let (dialling_identity, mut dialling_keys) = identity(41);
        let (answering_identity, mut answering_keys) = identity(42);
        let dialling_sees = Keying::Dtls {
            fingerprints: vec![answering_identity.fingerprint().to_owned()],
            setup: Some("active".to_owned()),
        };
        let answering_sees = Keying::Dtls {
            fingerprints: vec![dialling_identity.fingerprint().to_owned()],
            setup: Some("actpass".to_owned()),
        };
        let mut server = Handshake::start(
            &dialling_identity,
            &dialling_sees,
            Party::Offerer,
            Setup::ActPass,
            dialling,
            &mut dialling_keys,
            now,
        )
        .expect("a handshake")
        .expect("one that runs");
        let mut client = Handshake::start(
            &answering_identity,
            &answering_sees,
            Party::Answerer,
            Setup::Active,
            answering,
            &mut answering_keys,
            now,
        )
        .expect("a handshake")
        .expect("one that runs");
        let (finished, answered) = shake_hands(&mut server, &mut client, now);
        assert!(finished && answered, "the handshake never finished");
        let suite = server
            .take_outcome()
            .expect("an outcome")
            .expect("keys")
            .suite;
        assert_eq!(
            client
                .take_outcome()
                .expect("an outcome")
                .expect("keys")
                .suite,
            suite
        );
        suite
    }

    /// 8.10: the account allows and orders the GCM profiles. They come first by default; a call
    /// naming only AES-CM gets AES-CM, and the server's order decides among what the client
    /// offered.
    #[test]
    fn the_profiles_a_call_names_are_the_ones_its_handshake_offers_in_its_order() {
        assert_eq!(settled_on(every(), every()), Suite::AeadAes256Gcm);
        let aes_cm = profiles(Some(&[Suite::AesCm80])).expect("one profile");
        assert_eq!(settled_on(every(), aes_cm.clone()), Suite::AesCm80);
        assert_eq!(settled_on(aes_cm, every()), Suite::AesCm80);
        let gcm_128_first =
            profiles(Some(&[Suite::AeadAes128Gcm, Suite::AeadAes256Gcm])).expect("two");
        assert_eq!(
            settled_on(gcm_128_first.clone(), every()),
            Suite::AeadAes128Gcm,
            "the server's own preference among what was offered"
        );
        assert_eq!(
            settled_on(every(), gcm_128_first),
            Suite::AeadAes256Gcm,
            "the client's order is its offer, and the server still chooses"
        );
        assert_eq!(
            profiles(Some(&[Suite::AesF8, Suite::Aes256Cm80])),
            Err(MediaError::DtlsProfile),
            "suites no DTLS-SRTP profile names leave a handshake nothing to offer"
        );
    }

    #[test]
    fn a_peer_that_signalled_sha_384_or_sha_512_is_held_to_it() {
        // RFC 8122 §5.1: only the most preferred hash is checked, SHA-512 over SHA-256, so a wrong
        // SHA-256 line beside a right SHA-512 one is ignored
        let now = Instant::now();
        let (dialling_identity, mut dialling_keys) = identity(31);
        let (answering_identity, mut answering_keys) = identity(32);
        let (impostor, _) = identity(33);
        let under = |hash, identity: &Identity| {
            Fingerprint::of(hash, identity.certificate.der()).to_string()
        };

        let dialling_sees = Keying::Dtls {
            fingerprints: vec![
                impostor.fingerprint().to_owned(),
                under(HashFunction::Sha512, &answering_identity),
            ],
            setup: Some("active".to_owned()),
        };
        let answering_sees = Keying::Dtls {
            fingerprints: vec![under(HashFunction::Sha384, &dialling_identity)],
            setup: Some("actpass".to_owned()),
        };

        let mut dialling = Handshake::start(
            &dialling_identity,
            &dialling_sees,
            Party::Offerer,
            Setup::ActPass,
            every(),
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
            every(),
            &mut answering_keys,
            now,
        )
        .expect("a SHA-384 fingerprint is one this build reads")
        .expect("one that runs");

        let (dialled, answered) = shake_hands(&mut dialling, &mut answering, now);
        assert!(dialled && answered, "the handshake never finished");
        assert!(dialling.take_outcome().expect("an outcome").is_ok());
        assert!(answering.take_outcome().expect("an outcome").is_ok());
    }

    #[test]
    fn a_peer_whose_certificate_is_not_the_one_the_signalling_named_gets_no_keys() {
        // RFC 8122 §5.1: a fingerprint mismatch "MUST NOT establish the TLS connection". This is
        // the whole authentication
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
            every(),
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
            every(),
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
        let handshake = Handshake::start(
            &own,
            &seen,
            Party::Offerer,
            Setup::ActPass,
            every(),
            &mut keys,
            now,
        )
        .expect("no error");
        assert!(handshake.is_none());
    }

    #[test]
    fn two_ends_that_both_claim_the_same_role_are_refused_rather_than_left_waiting() {
        // RFC 4145 §4.1 has no row for an actpass answer; otherwise two servers would wait silently
        // for the whole timeout
        let now = Instant::now();
        let (own, mut keys) = identity(41);
        let seen = Keying::Dtls {
            fingerprints: vec![own.fingerprint().to_owned()],
            setup: Some("actpass".to_owned()),
        };
        assert_eq!(
            Handshake::start(
                &own,
                &seen,
                Party::Offerer,
                Setup::ActPass,
                every(),
                &mut keys,
                now
            )
            .err(),
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
                Handshake::start(
                    &own,
                    &seen,
                    Party::Offerer,
                    Setup::ActPass,
                    every(),
                    &mut keys,
                    now
                )
                .err(),
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
                sipral_core::sdp::KeySalt::new(&[1; 16], &[2; 14]),
            ),
            remote: sipral_core::sdp::CryptoPolicy::new(
                1,
                sipral_core::sdp::CryptoSuite::AesCm80,
                sipral_core::sdp::KeySalt::new(&[3; 16], &[4; 14]),
            ),
        };
        assert!(
            Handshake::start(
                &own,
                &sdes,
                Party::Offerer,
                Setup::ActPass,
                every(),
                &mut keys,
                now,
            )
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
            every(),
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
            every(),
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
        // what the budget is for: a DTLS server has no flight to retransmit, so
        // `Connection::poll_timeout` would return `None` forever
        let now = Instant::now();
        let (own, mut keys) = identity(81);
        let seen = Keying::Dtls {
            fingerprints: vec![own.fingerprint().to_owned()],
            // the peer answered `active`, so this end listens
            setup: Some("active".to_owned()),
        };
        let mut handshake = Handshake::start(
            &own,
            &seen,
            Party::Offerer,
            Setup::ActPass,
            every(),
            &mut keys,
            now,
        )
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
        // 1+2+4+8+16+32 s of retransmissions plus a final 60 s wait, the RFC 6347 §4.2.4.1 defaults
        assert_eq!(
            budget(Retransmission::default()),
            Duration::from_secs(1 + 2 + 4 + 8 + 16 + 32 + 60)
        );
        // and it follows the settings
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
